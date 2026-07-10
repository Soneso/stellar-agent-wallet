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

        // Decode the message bytes (same logic as sign tool). Every failure
        // below is a business refusal on caller-supplied input, not a
        // JSON-RPC protocol fault, so it surfaces via the documented result
        // envelope with a `sep53.*` wire code.
        let encoding = args.message_encoding.as_deref().unwrap_or("utf8");
        let message_bytes: Vec<u8> = match encoding {
            "base64" => match base64::engine::general_purpose::STANDARD.decode(&args.message) {
                Ok(bytes) => bytes,
                Err(e) => {
                    return Ok(crate::tools::common::business_error_result(
                        "sep53.invalid_message_base64",
                        format!("message base64 decode failed: {e}"),
                    ));
                }
            },
            "utf8" => args.message.as_bytes().to_vec(),
            other => {
                return Ok(crate::tools::common::business_error_result(
                    "sep53.invalid_encoding",
                    format!("unsupported message_encoding: {other:?}; use 'utf8' or 'base64'"),
                ));
            }
        };

        // Parse the G-strkey public key.
        let public_key = match stellar_strkey::ed25519::PublicKey::from_string(&args.public_key) {
            Ok(pk) => pk,
            Err(e) => {
                return Ok(crate::tools::common::business_error_result(
                    "sep53.invalid_public_key",
                    format!("public_key is not a valid G-strkey: {e}"),
                ));
            }
        };

        // Decode the base64 signature.
        let sig_bytes = match base64::engine::general_purpose::STANDARD.decode(&args.signature) {
            Ok(bytes) => bytes,
            Err(e) => {
                return Ok(crate::tools::common::business_error_result(
                    "sep53.invalid_signature_base64",
                    format!("signature base64 decode failed: {e}"),
                ));
            }
        };

        // Validate the signature is exactly 64 bytes.
        let sig_arr: [u8; 64] = match sig_bytes.try_into() {
            Ok(arr) => arr,
            Err(_) => {
                return Ok(crate::tools::common::business_error_result(
                    "sep53.signature_wrong_length",
                    "signature must be exactly 64 bytes after base64 decode",
                ));
            }
        };

        // Perform SEP-53 verification.
        match stellar_agent_sep53::verify_message(&message_bytes, &sig_arr, &public_key) {
            Ok(()) => {
                let envelope = stellar_agent_core::envelope::Envelope::ok(json!({ "valid": true }));
                let json_str = envelope
                    .to_json_pretty()
                    .unwrap_or_else(|_| String::from("{}"));
                Ok(CallToolResult::success(vec![Content::text(json_str)]))
            }
            Err(err) => Ok(crate::tools::common::business_error_result(
                "sep53.verify_failed",
                err.to_string(),
            )),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test helpers
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(any(test, feature = "test-helpers"))]
impl WalletServer {
    /// Calls `stellar_sep53_verify_message` with the given args, bypassing the
    /// rmcp transport.
    ///
    /// # Errors
    ///
    /// Propagates `rmcp::ErrorData` from the `dispatch_gate` preamble.
    /// Verification failures are returned as `Ok(CallToolResult)` with the
    /// normalised business-error envelope.
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Feature gate
    ///
    /// Gated on the `test-helpers` feature or `#[cfg(test)]`.
    #[doc(hidden)]
    pub async fn call_stellar_sep53_verify_message(
        &self,
        args: Sep53VerifyMessageArgs,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.stellar_sep53_verify_message(rmcp::handler::server::wrapper::Parameters(args))
            .await
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;
    use stellar_agent_core::profile::schema::Profile;

    fn make_server() -> crate::server::WalletServer {
        crate::server::WalletServer::new(
            Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
                .with_noop_engine()
                .build(),
        )
        .expect("WalletServer::new must not fail in tests")
    }

    /// A valid ed25519 signature over the SEP-53 prefixed digest verifies
    /// successfully, and the result carries the documented `{ ok: true,
    /// data: { valid: true }, request_id }` envelope.
    #[tokio::test]
    async fn valid_signature_verifies_under_normalised_envelope() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let message = b"hello stellar";
        let digest = stellar_agent_sep53::message_digest(message);
        let signature: ed25519_dalek::Signature =
            ed25519_dalek::Signer::sign(&signing_key, &digest);
        let public_key = stellar_strkey::ed25519::PublicKey(verifying_key.to_bytes()).to_string();

        let server = make_server();
        let args = Sep53VerifyMessageArgs {
            chain_id: "stellar:testnet".to_owned(),
            message: "hello stellar".to_owned(),
            message_encoding: None,
            signature: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
            public_key: public_key.as_str().to_owned(),
        };
        let result = server
            .call_stellar_sep53_verify_message(args)
            .await
            .expect("verification must not be a protocol error");
        assert_ne!(
            result.is_error,
            Some(true),
            "success must not set is_error = true"
        );
        let text = result
            .content
            .first()
            .and_then(|c| c.as_text())
            .map(|t| t.text.clone())
            .expect("result must carry a text content block");
        let value: serde_json::Value = serde_json::from_str(&text).expect("must be JSON");
        assert_eq!(value["ok"], serde_json::json!(true));
        assert_eq!(value["data"]["valid"], serde_json::json!(true));
        assert!(
            value["request_id"].as_str().is_some_and(|s| !s.is_empty()),
            "envelope must carry a non-empty request_id: {value}"
        );
    }

    /// A malformed G-strkey public key is a business refusal
    /// (`sep53.invalid_public_key`), not a JSON-RPC protocol error.
    #[tokio::test]
    async fn invalid_public_key_is_business_error() {
        let server = make_server();
        let args = Sep53VerifyMessageArgs {
            chain_id: "stellar:testnet".to_owned(),
            message: "hello stellar".to_owned(),
            message_encoding: None,
            signature: base64::engine::general_purpose::STANDARD.encode([0u8; 64]),
            public_key: "not-a-strkey".to_owned(),
        };
        let result = server
            .call_stellar_sep53_verify_message(args)
            .await
            .expect("invalid input must surface as a business-error envelope, not Err");
        let (code, _message, _text) = crate::tools::common::assert_business_envelope(&result);
        assert_eq!(code, "sep53.invalid_public_key");
    }

    /// A signature that fails ed25519 verification against the supplied
    /// public key is `sep53.verify_failed`, not a JSON-RPC protocol error.
    #[tokio::test]
    async fn wrong_signature_is_verify_failed_business_error() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let public_key = stellar_strkey::ed25519::PublicKey(verifying_key.to_bytes()).to_string();

        let server = make_server();
        let args = Sep53VerifyMessageArgs {
            chain_id: "stellar:testnet".to_owned(),
            message: "hello stellar".to_owned(),
            message_encoding: None,
            // 64 zero bytes: well-formed length, wrong signature.
            signature: base64::engine::general_purpose::STANDARD.encode([0u8; 64]),
            public_key: public_key.as_str().to_owned(),
        };
        let result = server
            .call_stellar_sep53_verify_message(args)
            .await
            .expect("a failed verification must surface as a business-error envelope, not Err");
        let (code, _message, _text) = crate::tools::common::assert_business_envelope(&result);
        assert_eq!(code, "sep53.verify_failed");
    }
}
