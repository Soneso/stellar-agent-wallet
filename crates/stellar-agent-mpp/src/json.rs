//! Duplicate-safe, depth-bounded JSON helpers.

use std::collections::BTreeMap;

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Number, Value};

use crate::{
    error::{MppError, MppErrorCode},
    limits::MAX_JSON_DEPTH,
};

struct StrictValueSeed {
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for StrictValueSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if self.depth > MAX_JSON_DEPTH {
            return Err(de::Error::custom("JSON nesting depth exceeded"));
        }
        deserializer.deserialize_any(StrictValueVisitor { depth: self.depth })
    }
}

struct StrictValueVisitor {
    depth: usize,
}

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a valid JSON value without duplicate object members")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(256));
        while let Some(value) = sequence.next_element_seed(StrictValueSeed {
            depth: self.depth + 1,
        })? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = BTreeMap::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom("duplicate JSON object member"));
            }
            let value = map.next_value_seed(StrictValueSeed {
                depth: self.depth + 1,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values.into_iter().collect()))
    }
}

/// Parses one JSON value while rejecting duplicate object members, excessive
/// nesting, invalid UTF-8, and trailing data.
///
/// # Errors
///
/// Returns `mpp.challenge_invalid` for malformed input.
pub fn parse_strict_json(input: &[u8]) -> Result<Value, MppError> {
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    let value = StrictValueSeed { depth: 1 }
        .deserialize(&mut deserializer)
        .map_err(|_error| {
            MppError::new(MppErrorCode::ChallengeInvalid, "invalid canonical JSON")
        })?;
    deserializer.end().map_err(|_error| {
        MppError::new(MppErrorCode::ChallengeInvalid, "invalid canonical JSON")
    })?;
    Ok(value)
}

/// Encodes a JSON value using RFC 8785 JSON Canonicalization Scheme.
///
/// # Errors
///
/// Returns a redacted protocol error if the value cannot be serialized.
pub fn canonical_json(value: &Value) -> Result<Vec<u8>, MppError> {
    serde_json_canonicalizer::to_vec(value).map_err(|_error| {
        MppError::new(
            MppErrorCode::ChallengeInvalid,
            "JSON canonicalization failed",
        )
    })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        reason = "test fixtures use expect for concise assertions"
    )]

    use super::*;
    use proptest::prelude::*;

    #[test]
    fn rejects_duplicate_members() {
        let error = parse_strict_json(br#"{"a":1,"a":2}"#).expect_err("duplicate must fail");
        assert_eq!(error.code(), "mpp.challenge_invalid");
    }

    #[test]
    fn rejects_trailing_data() {
        assert!(parse_strict_json(br#"{} []"#).is_err());
    }

    #[test]
    fn parses_every_json_primitive_and_nested_collections() {
        let value = parse_strict_json(
            br#"{"array":[true,false,null,-1,2,3.5,"text"],"object":{"ok":true}}"#,
        )
        .expect("valid JSON kinds");
        assert_eq!(value["array"][0], true);
        assert_eq!(value["array"][3], -1);
        assert_eq!(value["array"][4], 2_u64);
        assert_eq!(value["array"][5], 3.5);
        assert_eq!(value["array"][6], "text");
        assert_eq!(value["object"]["ok"], true);
    }

    #[test]
    fn rejects_invalid_utf8_and_excessive_nesting() {
        assert!(parse_strict_json(&[0xff]).is_err());
        let nested = format!(
            "{}0{}",
            "[".repeat(MAX_JSON_DEPTH + 1),
            "]".repeat(MAX_JSON_DEPTH + 1)
        );
        assert!(parse_strict_json(nested.as_bytes()).is_err());
    }

    #[test]
    fn canonicalizes_member_order() {
        let value = parse_strict_json(br#"{"z":1,"a":2}"#).expect("valid JSON");
        assert_eq!(
            canonical_json(&value).expect("canonical JSON"),
            br#"{"a":2,"z":1}"#
        );
    }

    proptest! {
        #[test]
        fn canonical_digest_input_is_independent_of_object_insertion_order(
            first_key in "[a-z]{1,12}",
            second_key in "[a-z]{1,12}",
            first_value in any::<i64>(),
            second_value in any::<i64>(),
        ) {
            prop_assume!(first_key != second_key);
            let mut left = serde_json::Map::new();
            left.insert(first_key.clone(), Value::from(first_value));
            left.insert(second_key.clone(), Value::from(second_value));
            let mut right = serde_json::Map::new();
            right.insert(second_key, Value::from(second_value));
            right.insert(first_key, Value::from(first_value));
            prop_assert_eq!(
                canonical_json(&Value::Object(left)).expect("left canonical JSON"),
                canonical_json(&Value::Object(right)).expect("right canonical JSON")
            );
        }
    }
}
