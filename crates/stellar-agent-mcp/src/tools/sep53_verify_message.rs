//! `stellar_sep53_verify_message` MCP tool — SEP-53 message verification.
//!
//! Verifies a SEP-53 message signature by recomputing
//! `SHA-256("Stellar Signed Message:\n" ‖ message)` and ed25519-verifying
//! against the supplied public key and base64 signature.
//!
//! Per `sep-0053.md` lines :106-115.
//!
//! This is a pure verification tool: it does NOT access the keyring, sign
//! anything, or interact with the Stellar network.

use base64::Engine as _;
use rmcp::{
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Content},
    schemars, serde, tool, tool_router,
};
use serde_json::json;
use stellar_agent_mcp_macros::mcp_tool_router;

use crate::server::WalletServer;

// ─────────────────────────────────────────────────────────────────────────────
// Argument type
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for the `stellar_sep53_verify_message` MCP tool.
///
/// # Schema
///
/// - `message` — the original message, same encoding as when it was signed.
/// - `message_encoding` — optional; `"utf8"` (default) or `"base64"`. Must
///   match what was used during signing.
/// - `signature` — base64-standard-encoded 64-byte ed25519 signature.
/// - `public_key` — G-strkey of the signer to verify against.
/// - `chain_id` — optional CAIP-2 chain identifier (not required; verification
///   is chain-agnostic, but passed for dispatch-gate compatibility).
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(crate = "rmcp::serde")]
pub struct Sep53VerifyMessageArgs {
    /// CAIP-2 chain identifier (e.g. `"stellar:testnet"`).
    ///
    /// Required for dispatch-gate compatibility even though SEP-53 message
    /// verification is chain-agnostic.
    pub chain_id: String,

    /// The original message in the same encoding used when signing.
    pub message: String,

    /// Message encoding: `"utf8"` (default) or `"base64"`.
    ///
    /// Must match the encoding used when calling `stellar_sep53_sign_message`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_encoding: Option<String>,

    /// Standard base64-encoded 64-byte ed25519 signature to verify.
    pub signature: String,

    /// G-strkey of the public key to verify the signature against.
    pub public_key: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool router impl block
// ─────────────────────────────────────────────────────────────────────────────

/// Verifies a SEP-53 message signature.
///
/// Implements `stellar_sep53_verify_message`. Pure verification — no keyring
/// access, no network calls, no state mutation.
///
/// Recomputes `SHA-256("Stellar Signed Message:\n" ‖ message_bytes)` and
/// ed25519-verifies the 64-byte signature against the supplied G-strkey.
///
/// Returns:
/// - `{ "valid": true }` on successful verification.
/// - An error envelope on failure (invalid key, invalid signature bytes,
///   wrong key/message, or oversized message).
///
/// # Tool annotations
///
/// - `readOnlyHint = true` — pure verification; no keyring access or state change.
/// - `destructiveHint = false` — does not modify any state.
///
/// # SEP-53 reference
///
/// `sep-0053.md` lines :106-115.
///
/// # Errors
///
/// Returns a tool-level error when:
/// - `chain_id` does not match the profile (dispatch-gate check).
/// - `public_key` is not a valid G-strkey.
/// - `signature` is not valid base64 or not exactly 64 bytes.
/// - The message is too large.
/// - Signature verification fails.
///
/// # Examples
///
/// ```json
/// {
///   "chain_id": "stellar:testnet",
///   "message": "Hello, World!",
///   "signature": "fO5dbYhXUhBM...",
///   "public_key": "GBXFXNDLV4LSWA4VB7YIL5GBD7BVNR22SGBTDKMO2SBZZHDXSKZYCP7L"
/// }
/// ```
#[mcp_tool_router]
#[tool_router(router = sep53_verify_message_tool_router, vis = "pub(crate)")]
impl WalletServer {
    #[mcp_tool_item(
        name = "stellar_sep53_verify_message",
        destructive_hint = false,
        read_only_hint = true,
        chain_id_required = true
    )]
    #[tool(
        name = "stellar_sep53_verify_message",
        description = "Verify a SEP-53 message signature (SHA-256('Stellar Signed Message:\\n' + message) → ed25519 verify). \
                       Inputs: message, signature (base64), public_key (G-strkey), chain_id, message_encoding ('utf8'|'base64'). \
                       Returns { valid: true } on success or an error envelope on failure. \
                       read_only_hint=true; destructive_hint=false (pure verification, no keyring access).",
        annotations(read_only_hint = true, destructive_hint = false)
    )]
    async fn stellar_sep53_verify_message(
        &self,
        Parameters(args): Parameters<Sep53VerifyMessageArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let args_value = json!({
            "chain_id": &args.chain_id,
            "message_len": args.message.len(),
            "message_encoding": args.message_encoding.as_deref().unwrap_or("utf8"),
            "public_key_len": args.public_key.len(),
        });
        // Read-only tool: RequireApproval produces no signing material; proceed.
        if let Err(e) = self
            .dispatch_gate("stellar_sep53_verify_message", &args_value, &args.chain_id)
            .await
        {
            return e.into_result();
        }

        // Decode the message bytes (same logic as sign tool).
        let encoding = args.message_encoding.as_deref().unwrap_or("utf8");
        let message_bytes: Vec<u8> = match encoding {
            "base64" => base64::engine::general_purpose::STANDARD
                .decode(&args.message)
                .map_err(|e| {
                    rmcp::ErrorData::invalid_params(
                        "sep53_verify_message_invalid_message_base64",
                        Some(json!({ "detail": format!("message base64 decode failed: {e}") })),
                    )
                })?,
            "utf8" => args.message.as_bytes().to_vec(),
            other => {
                return Err(rmcp::ErrorData::invalid_params(
                    "sep53_verify_message_invalid_encoding",
                    Some(json!({
                        "detail": format!("unsupported message_encoding: {other:?}; use 'utf8' or 'base64'")
                    })),
                ));
            }
        };

        // Parse the G-strkey public key.
        let public_key = stellar_strkey::ed25519::PublicKey::from_string(&args.public_key)
            .map_err(|e| {
                rmcp::ErrorData::invalid_params(
                    "sep53_verify_message_invalid_public_key",
                    Some(json!({ "detail": format!("public_key is not a valid G-strkey: {e}") })),
                )
            })?;

        // Decode the base64 signature.
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(&args.signature)
            .map_err(|e| {
                rmcp::ErrorData::invalid_params(
                    "sep53_verify_message_invalid_signature_base64",
                    Some(json!({ "detail": format!("signature base64 decode failed: {e}") })),
                )
            })?;

        // Validate the signature is exactly 64 bytes.
        let sig_arr: [u8; 64] = sig_bytes.try_into().map_err(|_| {
            rmcp::ErrorData::invalid_params(
                "sep53_verify_message_signature_wrong_length",
                Some(json!({ "detail": "signature must be exactly 64 bytes after base64 decode" })),
            )
        })?;

        // Perform SEP-53 verification.
        match stellar_agent_sep53::verify_message(&message_bytes, &sig_arr, &public_key) {
            Ok(()) => {
                let json_str = serde_json::to_string_pretty(&json!({ "valid": true }))
                    .unwrap_or_else(|_| r#"{"valid":true}"#.to_owned());
                Ok(CallToolResult::success(vec![Content::text(json_str)]))
            }
            Err(err) => Ok(crate::tools::common::business_error_result(
                "sep53.verify_failed",
                err.to_string(),
            )),
        }
    }
}
