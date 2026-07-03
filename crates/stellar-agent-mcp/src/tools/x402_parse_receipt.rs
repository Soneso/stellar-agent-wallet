//! `stellar_x402_parse_receipt` MCP tool — x402 `PAYMENT-RESPONSE` receipt decode.
//!
//! Decodes a base64-encoded `PAYMENT-RESPONSE` header (or raw JSON) into a
//! [`SettleResponse`] and returns a structured receipt object.  This tool is
//! **read-only** — it does not interact with the keyring or the network.
//!
//! # Input
//!
//! `payment_response` may be supplied in two forms:
//!
//! 1. **Base64-encoded JSON** — standard-base64 (RFC 4648 §4) encoded
//!    `SettleResponse` JSON, as it appears in the raw `PAYMENT-RESPONSE`
//!    HTTP header value.
//! 2. **Raw JSON string** — the `SettleResponse` JSON object directly.
//!
//! # Output
//!
//! Returns `{ success, transaction, payer, network, errorReason }` on success.
//! `payer` and `errorReason` are `null` when absent.

use rmcp::{
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Content},
    schemars, serde, tool, tool_router,
};
use serde_json::json;
use stellar_agent_mcp_macros::mcp_tool_router;

use crate::server::WalletServer;
use crate::tools::common::x402_error_to_tool_result;

// ─────────────────────────────────────────────────────────────────────────────
// Argument type
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for the `stellar_x402_parse_receipt` MCP tool.
///
/// # Schema
///
/// - `payment_response` — base64-encoded `PAYMENT-RESPONSE` header value OR
///   raw JSON `SettleResponse` object.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(crate = "rmcp::serde")]
pub struct X402ParseReceiptArgs {
    /// Base64-encoded `PAYMENT-RESPONSE` header value OR raw JSON
    /// `SettleResponse` object.
    ///
    /// The tool tries base64-decode + JSON-parse first; falls back to direct
    /// JSON-parse when base64 decoding fails or yields non-JSON bytes.
    pub payment_response: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Input-decode helper
// ─────────────────────────────────────────────────────────────────────────────

/// Decodes the `payment_response` input to a `SettleResponse`.
///
/// Tries the crate's canonical base64 decode path first
/// ([`stellar_agent_x402::wire::decode_payment_response`]; RFC 4648 §4 standard
/// alphabet, `JSON.parse`); on error falls back to direct raw-JSON parse.
/// Returns an x402 error if both paths fail.
///
/// # Errors
///
/// - [`stellar_agent_x402::X402Error::ReceiptParseFailed`] when both paths fail.
fn decode_payment_response_input(
    input: &str,
) -> Result<stellar_agent_x402::wire::SettleResponse, stellar_agent_x402::X402Error> {
    use stellar_agent_x402::wire::decode_payment_response;

    // Try the crate's canonical base64 decode (RFC 4648 §4 standard alphabet).
    if let Ok(parsed) = decode_payment_response(input) {
        return Ok(parsed);
    }

    // Fall back: parse as raw JSON string (caller-supplied unencoded JSON).
    serde_json::from_str::<stellar_agent_x402::wire::SettleResponse>(input).map_err(|e| {
        stellar_agent_x402::X402Error::ReceiptParseFailed {
            detail: format!("not valid base64+JSON or raw JSON SettleResponse: {e}"),
        }
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool router impl block
// ─────────────────────────────────────────────────────────────────────────────

/// Decodes an x402 v2 `PAYMENT-RESPONSE` header value into a structured receipt.
///
/// Accepts a `SettleResponse` object (as the base64-encoded `PAYMENT-RESPONSE`
/// header value OR raw JSON).  This tool is read-only — it only parses the
/// response, it does not sign or submit anything.
///
/// Returns `{ success, transaction, payer, network, errorReason }` on success.
/// Errors return `{ "code": "x402.error", "message": "..." }` with
/// `isError = true`.
///
/// # Tool annotations
///
/// - `readOnlyHint = true` — pure decode; does not access keyring or network.
/// - `destructiveHint = false` — safe to call without user confirmation.
///
/// # Errors
///
/// Returns `isError = true` with `{ "code": "x402.error", "message": "..." }` when:
/// - `payment_response` is not valid base64+JSON or raw JSON `SettleResponse`.
///
/// # Examples
///
/// ```json
/// { "payment_response": "<base64-encoded SettleResponse>" }
/// ```
#[mcp_tool_router]
#[tool_router(router = x402_parse_receipt_tool_router, vis = "pub(crate)")]
impl WalletServer {
    #[mcp_tool_item(
        name = "stellar_x402_parse_receipt",
        destructive_hint = false,
        read_only_hint = true,
        chain_id_required = false
    )]
    #[tool(
        name = "stellar_x402_parse_receipt",
        description = "Decode an x402 v2 PAYMENT-RESPONSE header value into a structured settlement receipt. \
                       Accepts base64-encoded PAYMENT-RESPONSE header or raw JSON SettleResponse. \
                       Returns { success: bool, transaction: string, payer: string|null, network: string, errorReason: string|null }. \
                       Read-only; does not access keyring or network. \
                       read_only_hint=true; destructive_hint=false.",
        annotations(read_only_hint = true, destructive_hint = false)
    )]
    async fn stellar_x402_parse_receipt(
        &self,
        Parameters(args): Parameters<X402ParseReceiptArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        // ── No dispatch_gate call — deliberate exemption ──────────────────────
        //
        // This tool is a PURE OFFLINE DECODE: it deserialises a caller-supplied
        // string and does not access the keyring, the active profile, or the
        // network.  There is no operator-controlled resource for the policy
        // chokepoint to gate.
        //
        // Context: `sep43_get_network` calls `dispatch_gate` because it reads
        // the profile passphrase, which IS a profile-level resource requiring
        // policy evaluation. `stellar_x402_parse_receipt` has no such
        // dependency — it only parses the bytes provided by the caller. A
        // `dispatch_gate` call here would require inventing a spurious
        // `chain_id` argument and a profile lookup for a tool that has zero
        // network/profile semantics.
        //
        // `chain_id_required = false` in the `mcp_tool_item` annotation records
        // this decision at the tool-registry level; the inline comment above
        // documents the architectural rationale.
        tracing::debug!(
            payment_response_len = args.payment_response.len(),
            "x402_parse_receipt: decode request",
        );

        // ── Decode ────────────────────────────────────────────────────────────
        let receipt = match decode_payment_response_input(&args.payment_response) {
            Ok(r) => r,
            Err(ref err) => return Ok(x402_error_to_tool_result(err)),
        };

        tracing::debug!(
            success = receipt.success,
            network = %receipt.network,
            "x402_parse_receipt: decoded",
        );

        // ── Build response ────────────────────────────────────────────────────
        // `payer` and `errorReason` may be null when absent.
        let response = json!({
            "success": receipt.success,
            "transaction": receipt.transaction,
            "payer": receipt.payer,
            "network": receipt.network,
            "errorReason": receipt.error_reason,
        });
        let json_str = serde_json::to_string_pretty(&response).unwrap_or_else(|_| "{}".to_owned());
        Ok(CallToolResult::success(vec![Content::text(json_str)]))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test helpers
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(any(test, feature = "test-helpers"))]
impl WalletServer {
    /// Calls `stellar_x402_parse_receipt` with the given args, bypassing the
    /// rmcp transport.
    ///
    /// # Errors
    ///
    /// Propagates `rmcp::ErrorData` (JSON-RPC level) if raised by the handler.
    /// Receipt-decode failures are returned as `Ok(CallToolResult)` with
    /// `is_error = Some(true)`.
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Feature gate
    ///
    /// Gated on the `test-helpers` feature or `#[cfg(test)]`.
    #[doc(hidden)]
    pub async fn call_stellar_x402_parse_receipt(
        &self,
        args: X402ParseReceiptArgs,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.stellar_x402_parse_receipt(Parameters(args)).await
    }
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
    use stellar_agent_x402::wire::SettleResponse;

    fn sample_settle_response() -> SettleResponse {
        SettleResponse {
            success: true,
            error_reason: None,
            error_message: None,
            payer: Some("GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned()),
            transaction: "abcdef0123456789".to_owned(),
            network: "stellar:testnet".to_owned(),
            amount: Some("1000000".to_owned()),
            extensions: None,
            extra: None,
        }
    }

    #[test]
    fn decode_raw_json_settle_response() {
        let json_str = serde_json::to_string(&sample_settle_response()).unwrap();
        let result = decode_payment_response_input(&json_str);
        assert!(
            result.is_ok(),
            "raw JSON SettleResponse must be accepted; got {result:?}"
        );
        let resp = result.unwrap();
        assert!(resp.success);
        assert_eq!(resp.network, "stellar:testnet");
    }

    #[test]
    fn decode_base64_encoded_settle_response() {
        use base64::Engine as _;
        let json_str = serde_json::to_string(&sample_settle_response()).unwrap();
        let encoded = base64::engine::general_purpose::STANDARD.encode(json_str.as_bytes());
        let result = decode_payment_response_input(&encoded);
        assert!(
            result.is_ok(),
            "base64-encoded SettleResponse must be accepted; got {result:?}"
        );
        let resp = result.unwrap();
        assert!(resp.success);
    }

    #[test]
    fn decode_invalid_input_returns_error() {
        let result = decode_payment_response_input("not_json_or_base64!!!");
        assert!(
            matches!(
                result,
                Err(stellar_agent_x402::X402Error::ReceiptParseFailed { .. })
            ),
            "invalid input must return ReceiptParseFailed; got {result:?}"
        );
    }

    #[test]
    fn failed_receipt_has_error_reason() {
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
        let json_str = serde_json::to_string(&resp).unwrap();
        let decoded = decode_payment_response_input(&json_str).unwrap();
        assert!(!decoded.success);
        assert_eq!(decoded.error_reason, Some("insufficient_funds".to_owned()));
    }
}
