//! Strict Payment receipt parsing.

use std::{collections::BTreeMap, fmt};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{
    STELLAR_METHOD,
    error::{MppError, MppErrorCode},
    json::{canonical_json, parse_strict_json},
    limits::{MAX_FIELD_BYTES, MAX_LONG_FIELD_BYTES, MAX_RECEIPT_BYTES},
};

/// Transport-tagged receipt input from a trusted host.
#[derive(Clone, Debug, Deserialize, schemars::JsonSchema, Serialize)]
#[serde(tag = "transport", rename_all = "snake_case")]
pub enum ReceiptInput {
    /// Raw base64url `Payment-Receipt` field value.
    Http {
        /// Field value without the `Payment-Receipt:` field name.
        value: String,
    },
    /// Native `org.paymentauth/receipt` object.
    Mcp {
        /// Receipt object extracted from response metadata.
        receipt: Value,
    },
}

/// Validated Stellar receipt and its correlation digest.
#[derive(Clone, Deserialize, Serialize)]
pub struct PaymentReceipt {
    method: String,
    reference: String,
    status: String,
    timestamp: String,
    #[serde(rename = "externalId", skip_serializing_if = "Option::is_none")]
    external_id: Option<String>,
    #[serde(rename = "challengeId", skip_serializing_if = "Option::is_none")]
    challenge_id: Option<String>,
    #[serde(flatten)]
    extensions: BTreeMap<String, Value>,
    #[serde(skip)]
    digest: [u8; 32],
}

impl PaymentReceipt {
    /// Returns the lowercase Stellar transaction hash.
    #[must_use]
    pub fn reference(&self) -> &str {
        &self.reference
    }

    /// Returns the RFC 3339 receipt timestamp.
    #[must_use]
    pub fn timestamp(&self) -> &str {
        &self.timestamp
    }

    /// Returns the validated receipt status. The wire contract admits only
    /// `"success"`; this accessor exists so audit rows record the validated
    /// value rather than a literal.
    #[must_use]
    pub fn status(&self) -> &str {
        &self.status
    }

    /// Returns the optional challenge correlation identifier.
    #[must_use]
    pub fn challenge_id(&self) -> Option<&str> {
        self.challenge_id.as_deref()
    }

    /// Returns the canonical receipt SHA-256 digest.
    #[must_use]
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

impl fmt::Debug for PaymentReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PaymentReceipt")
            .field("method", &self.method)
            .field("reference", &"[redacted]")
            .field("status", &self.status)
            .field("timestamp", &self.timestamp)
            .field(
                "external_id",
                &self.external_id.as_ref().map(|_| "[redacted]"),
            )
            .field(
                "challenge_id",
                &self.challenge_id.as_ref().map(|_| "[redacted]"),
            )
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
struct ReceiptWire {
    method: String,
    reference: String,
    status: String,
    timestamp: String,
    #[serde(rename = "externalId")]
    external_id: Option<String>,
    #[serde(rename = "challengeId")]
    challenge_id: Option<String>,
    #[serde(flatten)]
    extensions: BTreeMap<String, Value>,
}

/// Parses and validates an HTTP or native MCP Stellar receipt.
///
/// # Errors
///
/// Returns `mpp.receipt_invalid` or `mpp.input_too_large` for malformed or
/// oversized receipt data.
pub fn parse_receipt(input: &ReceiptInput) -> Result<PaymentReceipt, MppError> {
    let value = match input {
        ReceiptInput::Http { value } => {
            if value.is_empty() || value.contains('=') || value.len() > MAX_RECEIPT_BYTES * 2 {
                return Err(receipt_error());
            }
            let decoded = URL_SAFE_NO_PAD
                .decode(value)
                .map_err(|_error| receipt_error())?;
            if decoded.len() > MAX_RECEIPT_BYTES {
                return Err(input_too_large());
            }
            parse_strict_json(&decoded).map_err(|_error| receipt_error())?
        }
        ReceiptInput::Mcp { receipt } => {
            if canonical_json(receipt)
                .map_err(|_error| receipt_error())?
                .len()
                > MAX_RECEIPT_BYTES
            {
                return Err(input_too_large());
            }
            receipt.clone()
        }
    };
    let canonical = canonical_json(&value).map_err(|_error| receipt_error())?;
    let wire: ReceiptWire = serde_json::from_value(value).map_err(|_error| receipt_error())?;
    validate_wire(&wire)?;
    Ok(PaymentReceipt {
        method: wire.method,
        reference: wire.reference,
        status: wire.status,
        timestamp: wire.timestamp,
        external_id: wire.external_id,
        challenge_id: wire.challenge_id,
        extensions: wire.extensions,
        digest: Sha256::digest(canonical).into(),
    })
}

fn validate_wire(wire: &ReceiptWire) -> Result<(), MppError> {
    if wire.method != STELLAR_METHOD || wire.status != "success" {
        return Err(receipt_error());
    }
    if wire.reference.len() != 64
        || !wire
            .reference
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(receipt_error());
    }
    OffsetDateTime::parse(&wire.timestamp, &Rfc3339).map_err(|_error| receipt_error())?;
    if wire.timestamp.len() > MAX_FIELD_BYTES {
        return Err(receipt_error());
    }
    for field in [wire.external_id.as_deref(), wire.challenge_id.as_deref()]
        .into_iter()
        .flatten()
    {
        if field.is_empty()
            || field.len() > MAX_LONG_FIELD_BYTES
            || field.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(receipt_error());
        }
    }
    Ok(())
}

const fn receipt_error() -> MppError {
    MppError::new(
        MppErrorCode::ReceiptInvalid,
        "invalid Stellar payment receipt",
    )
}

const fn input_too_large() -> MppError {
    MppError::new(
        MppErrorCode::InputTooLarge,
        "MPP input exceeds a named limit",
    )
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        reason = "test fixtures use expect for concise setup"
    )]

    use super::*;

    fn receipt() -> Value {
        serde_json::json!({
            "method": "stellar",
            "reference": "a".repeat(64),
            "status": "success",
            "timestamp": "2026-07-16T12:00:00Z"
        })
    }

    #[test]
    fn parses_native_receipt() {
        let parsed =
            parse_receipt(&ReceiptInput::Mcp { receipt: receipt() }).expect("valid receipt");
        assert_eq!(parsed.reference(), "a".repeat(64));
    }

    #[test]
    fn parses_http_receipt() {
        let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&receipt()).expect("valid JSON"));
        let parsed = parse_receipt(&ReceiptInput::Http { value: encoded }).expect("valid receipt");
        assert_eq!(parsed.timestamp(), "2026-07-16T12:00:00Z");
    }

    #[test]
    fn rejects_uppercase_reference() {
        let mut invalid = receipt();
        invalid["reference"] = Value::String("A".repeat(64));
        assert!(parse_receipt(&ReceiptInput::Mcp { receipt: invalid }).is_err());
    }

    #[test]
    fn debug_redacts_reference() {
        let parsed =
            parse_receipt(&ReceiptInput::Mcp { receipt: receipt() }).expect("valid receipt");
        assert!(!format!("{parsed:?}").contains(&"a".repeat(64)));
    }

    #[test]
    fn retains_correlations_extensions_and_a_stable_canonical_digest() {
        let mut first = receipt();
        first["externalId"] = Value::String("invoice-7".to_owned());
        first["challengeId"] = Value::String("challenge-1".to_owned());
        first["providerData"] = serde_json::json!({"sequence": 3});
        let parsed = parse_receipt(&ReceiptInput::Mcp {
            receipt: first.clone(),
        })
        .expect("extended receipt");
        assert_eq!(parsed.challenge_id(), Some("challenge-1"));
        assert_ne!(parsed.digest(), &[0; 32]);

        let reordered: Value = serde_json::from_str(
            r#"{"providerData":{"sequence":3},"timestamp":"2026-07-16T12:00:00Z","status":"success","reference":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","method":"stellar","externalId":"invoice-7","challengeId":"challenge-1"}"#,
        )
        .expect("reordered receipt");
        let second =
            parse_receipt(&ReceiptInput::Mcp { receipt: reordered }).expect("canonical receipt");
        assert_eq!(parsed.digest(), second.digest());
    }

    #[test]
    fn rejects_malformed_and_oversized_http_receipts() {
        for value in [
            String::new(),
            "e30=".to_owned(),
            "!!!!".to_owned(),
            "x".repeat(MAX_RECEIPT_BYTES * 2 + 1),
            URL_SAFE_NO_PAD.encode(b"not JSON"),
            URL_SAFE_NO_PAD.encode(br#"{} {}"#),
        ] {
            assert!(parse_receipt(&ReceiptInput::Http { value }).is_err());
        }
        let oversized = URL_SAFE_NO_PAD.encode(vec![b'x'; MAX_RECEIPT_BYTES + 1]);
        assert_eq!(
            parse_receipt(&ReceiptInput::Http { value: oversized })
                .expect_err("decoded receipt bound")
                .code(),
            "mpp.input_too_large"
        );
    }

    #[test]
    fn rejects_invalid_native_receipt_fields() {
        let mut cases = Vec::new();
        for (field, value) in [
            ("method", Value::String("evm".to_owned())),
            ("status", Value::String("failed".to_owned())),
            ("reference", Value::String("a".repeat(63))),
            ("reference", Value::String("g".repeat(64))),
            ("timestamp", Value::String("not-a-time".to_owned())),
            ("externalId", Value::String(String::new())),
            (
                "challengeId",
                Value::String("x".repeat(MAX_LONG_FIELD_BYTES + 1)),
            ),
            ("externalId", Value::String("bad\nidentifier".to_owned())),
        ] {
            let mut invalid = receipt();
            invalid[field] = value;
            cases.push(invalid);
        }
        cases.push(Value::String("not-an-object".to_owned()));
        for receipt in cases {
            assert_eq!(
                parse_receipt(&ReceiptInput::Mcp { receipt })
                    .expect_err("invalid receipt")
                    .code(),
                "mpp.receipt_invalid"
            );
        }

        let huge = serde_json::json!({"extension": "x".repeat(MAX_RECEIPT_BYTES)});
        assert_eq!(
            parse_receipt(&ReceiptInput::Mcp { receipt: huge })
                .expect_err("native receipt bound")
                .code(),
            "mpp.input_too_large"
        );
    }

    #[test]
    fn rejects_parseable_but_oversized_timestamp() {
        let timestamp = format!("2026-07-16T12:00:00.{}Z", "0".repeat(MAX_FIELD_BYTES));
        let wire = ReceiptWire {
            method: STELLAR_METHOD.to_owned(),
            reference: "a".repeat(64),
            status: "success".to_owned(),
            timestamp,
            external_id: None,
            challenge_id: None,
            extensions: BTreeMap::new(),
        };
        assert!(validate_wire(&wire).is_err());
    }
}
