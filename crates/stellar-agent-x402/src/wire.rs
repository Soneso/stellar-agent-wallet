//! x402 v2 wire types with camelCase serde and standard-base64 codecs.
//!
//! All types in this module are wire-compatible with `@x402/stellar`.
//!
//! # Encoding
//!
//! `encode_payment_signature` / `decode_payment_required` /
//! `decode_payment_response` use **standard base64** (RFC 4648 standard
//! alphabet, NOT url-safe) of `JSON.stringify(obj)`.
//!
//! # Field names
//!
//! All structs use `#[serde(rename_all = "camelCase")]`.  Field types and
//! names are verified against the @x402/stellar reference implementation:
//! `PaymentRequirements`, `PaymentPayload`, `SettleResponse`,
//! `ExactStellarPayloadV2`, and `ResourceInfo`.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use serde::{Deserialize, Serialize};

use crate::X402Error;

// ─────────────────────────────────────────────────────────────────────────────
// Wire types
// ─────────────────────────────────────────────────────────────────────────────

/// Metadata about the resource protected by an x402 paywall.
///
/// Part of the x402 v2 wire type set (matching the `@x402/stellar` package) so a
/// host integration can deserialize a full payment payload; the payer-only flow
/// here never populates it (`PaymentPayload.resource` stays `None`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceInfo {
    /// URL of the protected resource.
    pub url: String,
    /// Human-readable description of the resource.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// MIME type of the resource content.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    /// Service name offering the resource.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_name: Option<String>,
    /// Categorisation tags.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    /// URL of a service icon.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon_url: Option<String>,
}

/// The `accepts[]` element from a 402 `PAYMENT-REQUIRED` header.
///
/// Carries all parameters the payer needs to construct a valid payment.
/// `extra` is modelled as an **open map** (`serde_json::Value`) because the
/// upstream type is `Record<string, unknown>` — closed-struct modelling would
/// drop unrecognised fields on round-trip.
///
/// # Validation
///
/// `extra["areFeesSponsored"] == true` is a hard precondition for the `exact`
/// scheme and is validated by [`crate::exact::create_payment`] before any
/// network round-trip.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequirements {
    /// Payment scheme identifier.  Must be `"exact"` for this crate.
    pub scheme: String,
    /// x402 Stellar CAIP-2 network identifier.  Valid values:
    /// `"stellar:pubnet"` or `"stellar:testnet"`.
    pub network: String,
    /// SAC contract address (C-strkey) of the token to transfer.
    pub asset: String,
    /// Payment amount in atomic token units (e.g. for USDC: 1 USDC = 10_000_000).
    pub amount: String,
    /// Recipient address (G-, C-, or M-strkey; muxed recipients are accepted).
    pub pay_to: String,
    /// Maximum ledger window in seconds for payment validity.
    pub max_timeout_seconds: u32,
    /// Scheme-specific extension map.  MUST include `areFeesSponsored: true`
    /// for the `exact` scheme.
    #[serde(default)]
    pub extra: serde_json::Value,
}

/// The x402 `PAYMENT-SIGNATURE` body sent by the payer to the facilitator.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentPayload {
    /// x402 protocol version.  Always `2` for x402 v2.
    pub x402_version: u32,
    /// Optional resource metadata from the original 402 response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<ResourceInfo>,
    /// The payment requirements this payload satisfies.
    pub accepted: PaymentRequirements,
    /// Scheme-specific payload carrying the signed transaction.
    pub payload: ExactStellarPayloadV2,
    /// Reserved for future protocol extensions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Value>,
}

/// Stellar-specific inner payload inside a [`PaymentPayload`].
///
/// Contains a base64-encoded Stellar `TransactionEnvelope` XDR with a signed
/// `SorobanAuthorizationEntry` for the SAC `transfer` invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExactStellarPayloadV2 {
    /// Base64-encoded Stellar `TransactionEnvelope` XDR.
    pub transaction: String,
}

/// Settlement receipt returned by the facilitator in the `PAYMENT-RESPONSE`
/// header.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettleResponse {
    /// Whether settlement succeeded.
    pub success: bool,
    /// Typed reason code for failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_reason: Option<String>,
    /// Human-readable failure message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    /// Payer strkey (G-, C-, or M-strkey) when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payer: Option<String>,
    /// Transaction hash (hex) or empty string when not yet settled.
    pub transaction: String,
    /// x402 CAIP-2 network string (e.g. `"stellar:pubnet"`).
    pub network: String,
    /// Actual amount settled in atomic token units.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<String>,
    /// Reserved for future protocol extensions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Value>,
    /// Scheme-specific extra data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<serde_json::Value>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Codec helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Encodes a [`PaymentPayload`] as a standard base64 string for the
/// `PAYMENT-SIGNATURE` HTTP header.
///
/// Encoding: `base64(JSON.stringify(paymentPayload))` using the RFC 4648
/// standard alphabet (NOT url-safe).
///
/// # Errors
///
/// - [`X402Error::TransactionBuildFailed`] if JSON serialisation fails
///   (unreachable for well-formed types, but handled for correctness).
pub fn encode_payment_signature(payload: &PaymentPayload) -> Result<String, X402Error> {
    let json_bytes =
        serde_json::to_vec(payload).map_err(|e| X402Error::TransactionBuildFailed {
            detail: format!("PaymentPayload JSON serialisation failed: {e}"),
        })?;
    Ok(BASE64_STANDARD.encode(&json_bytes))
}

/// Decodes a `PAYMENT-REQUIRED` header value into a [`PaymentRequirements`].
///
/// Decoding: `JSON.parse(base64_decode(header))` using the RFC 4648 standard
/// alphabet.
///
/// # Errors
///
/// - [`X402Error::InvalidPaymentRequired`] if base64 decoding or JSON
///   deserialisation fails.
pub fn decode_payment_required(header: &str) -> Result<PaymentRequirements, X402Error> {
    let bytes =
        BASE64_STANDARD
            .decode(header.trim())
            .map_err(|e| X402Error::InvalidPaymentRequired {
                detail: format!("base64 decode failed: {e}"),
            })?;
    serde_json::from_slice(&bytes).map_err(|e| X402Error::InvalidPaymentRequired {
        detail: format!("JSON deserialise failed: {e}"),
    })
}

/// Decodes a `PAYMENT-RESPONSE` header value into a [`SettleResponse`].
///
/// Decoding: `JSON.parse(base64_decode(header))` using the RFC 4648 standard
/// alphabet.
///
/// # Errors
///
/// - [`X402Error::ReceiptParseFailed`] if base64 decoding or JSON
///   deserialisation fails.
pub fn decode_payment_response(header: &str) -> Result<SettleResponse, X402Error> {
    let bytes =
        BASE64_STANDARD
            .decode(header.trim())
            .map_err(|e| X402Error::ReceiptParseFailed {
                detail: format!("base64 decode failed: {e}"),
            })?;
    serde_json::from_slice(&bytes).map_err(|e| X402Error::ReceiptParseFailed {
        detail: format!("JSON deserialise failed: {e}"),
    })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics and unwraps acceptable in unit tests"
    )]

    use super::*;

    fn sample_requirements() -> PaymentRequirements {
        PaymentRequirements {
            scheme: "exact".to_owned(),
            network: "stellar:testnet".to_owned(),
            asset: "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA".to_owned(),
            amount: "1000000".to_owned(),
            pay_to: "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            max_timeout_seconds: 300,
            extra: serde_json::json!({ "areFeesSponsored": true }),
        }
    }

    fn sample_payload(req: PaymentRequirements) -> PaymentPayload {
        PaymentPayload {
            x402_version: 2,
            resource: None,
            accepted: req,
            payload: ExactStellarPayloadV2 {
                transaction: "AAAA".to_owned(),
            },
            extensions: None,
        }
    }

    // ── encode / decode round-trip ─────────────────────────────────────────────

    #[test]
    fn encode_payment_signature_round_trips() {
        let payload = sample_payload(sample_requirements());
        let encoded = encode_payment_signature(&payload).unwrap();
        // Must be valid standard base64
        let decoded_bytes = BASE64_STANDARD.decode(&encoded).unwrap();
        let json_str = std::str::from_utf8(&decoded_bytes).unwrap();
        // Must contain camelCase field names
        assert!(json_str.contains("x402Version"));
        assert!(json_str.contains("accepted"));
        assert!(json_str.contains("payTo"));
        assert!(json_str.contains("maxTimeoutSeconds"));
        assert!(json_str.contains("areFeesSponsored"));
    }

    #[test]
    fn decode_payment_required_round_trips() {
        let req = sample_requirements();
        // Manually encode the requirements
        let json = serde_json::to_vec(&req).unwrap();
        let encoded = BASE64_STANDARD.encode(&json);
        let decoded = decode_payment_required(&encoded).unwrap();
        assert_eq!(decoded.scheme, "exact");
        assert_eq!(decoded.network, "stellar:testnet");
        assert_eq!(decoded.amount, "1000000");
    }

    #[test]
    fn decode_payment_required_invalid_base64_returns_error() {
        let result = decode_payment_required("not-valid-base64!!!");
        assert!(matches!(
            result,
            Err(X402Error::InvalidPaymentRequired { .. })
        ));
    }

    #[test]
    fn decode_payment_required_invalid_json_returns_error() {
        let encoded = BASE64_STANDARD.encode(b"{ not valid json }");
        let result = decode_payment_required(&encoded);
        assert!(matches!(
            result,
            Err(X402Error::InvalidPaymentRequired { .. })
        ));
    }

    #[test]
    fn decode_payment_response_round_trips() {
        let resp = SettleResponse {
            success: true,
            error_reason: None,
            error_message: None,
            payer: Some("GAABC".to_owned()),
            transaction: "abcdef01".to_owned(),
            network: "stellar:testnet".to_owned(),
            amount: Some("1000000".to_owned()),
            extensions: None,
            extra: None,
        };
        let json = serde_json::to_vec(&resp).unwrap();
        let encoded = BASE64_STANDARD.encode(&json);
        let decoded = decode_payment_response(&encoded).unwrap();
        assert!(decoded.success);
        assert_eq!(decoded.network, "stellar:testnet");
    }

    #[test]
    fn decode_payment_response_invalid_returns_error() {
        let result = decode_payment_response("notbase64!!!");
        assert!(matches!(result, Err(X402Error::ReceiptParseFailed { .. })));
    }

    // ── camelCase field-name verification ─────────────────────────────────────

    #[test]
    fn payment_requirements_serialises_to_camel_case() {
        let req = sample_requirements();
        let json = serde_json::to_value(&req).unwrap();
        // Check camelCase field names in the serialised JSON
        assert!(json.get("payTo").is_some(), "payTo must be camelCase");
        assert!(
            json.get("maxTimeoutSeconds").is_some(),
            "maxTimeoutSeconds must be camelCase"
        );
        assert!(json.get("pay_to").is_none(), "snake_case must not appear");
    }

    #[test]
    fn payment_payload_serialises_to_camel_case() {
        let payload = sample_payload(sample_requirements());
        let json = serde_json::to_value(&payload).unwrap();
        assert!(json.get("x402Version").is_some());
        assert!(json.get("x402_version").is_none());
    }

    #[test]
    fn settle_response_serialises_to_camel_case() {
        let resp = SettleResponse {
            success: false,
            error_reason: Some("insufficient_funds".to_owned()),
            error_message: Some("Not enough USDC".to_owned()),
            payer: None,
            transaction: "".to_owned(),
            network: "stellar:testnet".to_owned(),
            amount: None,
            extensions: None,
            extra: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json.get("errorReason").is_some());
        assert!(json.get("errorMessage").is_some());
        assert!(json.get("error_reason").is_none());
    }

    // ── extra is an open map ───────────────────────────────────────────────────

    #[test]
    fn extra_preserves_unknown_fields_on_round_trip() {
        let json_str = r#"{
            "scheme": "exact",
            "network": "stellar:testnet",
            "asset": "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA",
            "amount": "100",
            "payTo": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "maxTimeoutSeconds": 300,
            "extra": {
                "areFeesSponsored": true,
                "unknownField": "someValue"
            }
        }"#;
        let req: PaymentRequirements = serde_json::from_str(json_str).unwrap();
        // Unknown fields in extra are preserved as-is
        assert_eq!(req.extra["areFeesSponsored"], serde_json::Value::Bool(true));
        assert_eq!(
            req.extra["unknownField"],
            serde_json::Value::String("someValue".to_owned())
        );
    }
}
