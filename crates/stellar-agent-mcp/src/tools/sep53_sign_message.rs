//! `stellar_sep53_sign_message` MCP tool — SEP-53 prefixed message signing.
//!
//! Signs an arbitrary message using the SEP-53 canonical scheme:
//! `SHA-256("Stellar Signed Message:\n" ‖ message)` → ed25519 sign.
//!
//! Per `sep-0053.md` lines :55-104.
//!
//! # Distinction from SEP-43 signMessage
//!
//! `stellar_sep43_sign_message` computes `sha256(message_bytes)` with NO prefix
//! (SEP-43 `signMessage` semantics). This tool uses the SEP-53 24-byte prefix
//! scheme and produces an incompatible, non-interchangeable signature. The two
//! tools serve different SEPs and MUST NOT be confused.

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

/// Arguments for the `stellar_sep53_sign_message` MCP tool.
///
/// # Schema
///
/// - `message` — UTF-8 string OR base64-encoded binary (see `message_encoding`).
/// - `message_encoding` — optional; `"utf8"` (default) or `"base64"`. When
///   `"base64"`, `message` is decoded as standard base64 before signing.
/// - `chain_id` — CAIP-2 chain identifier.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(crate = "rmcp::serde")]
pub struct Sep53SignMessageArgs {
    /// CAIP-2 chain identifier (e.g. `"stellar:testnet"`).
    pub chain_id: String,

    /// Message to sign.
    ///
    /// When `message_encoding` is `"utf8"` (the default), this is a UTF-8
    /// string and will be signed as its UTF-8 byte representation.
    ///
    /// When `message_encoding` is `"base64"`, this field must be a valid
    /// standard base64-encoded string; the raw bytes after decoding are signed.
    pub message: String,

    /// Message encoding: `"utf8"` (default) or `"base64"`.
    ///
    /// Use `"base64"` to sign arbitrary binary data that cannot be represented
    /// as a UTF-8 string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_encoding: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool router impl block
// ─────────────────────────────────────────────────────────────────────────────

/// Signs a message using the SEP-53 canonical scheme (prefixed SHA-256 → ed25519).
///
/// Implements `stellar_sep53_sign_message`. Loads the wallet signer from the
/// platform keyring, constructs the SEP-53 preimage
/// `"Stellar Signed Message:\n" ‖ message_bytes`, computes `SHA-256`, and
/// signs the 32-byte digest with ed25519.
///
/// Returns:
/// ```json
/// {
///   "signature": "<base64-standard>",
///   "signer_public_key": "G...",
///   "message_encoding": "utf8" | "base64"
/// }
/// ```
///
/// # Tool annotations
///
/// - `readOnlyHint = false` — accesses the keyring to produce a signature.
/// - `destructiveHint = false` — signing does not submit a transaction.
///
/// # SEP-53 reference
///
/// `sep-0053.md` lines :55-104.
///
/// # Distinction from SEP-43
///
/// Uses `stellar_agent_sep53::sign_message`, NOT `stellar_agent_sep43::signing::sign_message_bytes`.
/// The sep43 path computes `sha256(message_bytes)` with NO prefix and is
/// incompatible with the SEP-53 scheme.
///
/// # Errors
///
/// Returns a tool-level error when:
/// - `chain_id` does not match the profile.
/// - `message` exceeds the maximum allowed size.
/// - `message_encoding` is `"base64"` but `message` is not valid base64.
/// - The keyring entry for the signer cannot be loaded.
///
/// # Examples
///
/// ```json
/// { "chain_id": "stellar:testnet", "message": "Hello, World!" }
/// ```
#[mcp_tool_router]
#[tool_router(router = sep53_sign_message_tool_router, vis = "pub(crate)")]
impl WalletServer {
    #[mcp_tool_item(
        name = "stellar_sep53_sign_message",
        destructive_hint = false,
        read_only_hint = false,
        chain_id_required = true
    )]
    #[tool(
        name = "stellar_sep53_sign_message",
        description = "Sign an arbitrary message using SEP-53 (SHA-256('Stellar Signed Message:\\n' + message) → ed25519). \
                       message_encoding: 'utf8' (default) or 'base64' for binary messages. \
                       Returns { signature: string (base64), signer_public_key: string (G-strkey), message_encoding: string }. \
                       read_only_hint=false; destructive_hint=false. \
                       NOT compatible with stellar_sep43_sign_message (different prefix scheme).",
        annotations(read_only_hint = false, destructive_hint = false)
    )]
    async fn stellar_sep53_sign_message(
        &self,
        Parameters(args): Parameters<Sep53SignMessageArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let args_value = json!({
            "chain_id": &args.chain_id,
            "message_len": args.message.len(),
            "message_encoding": args.message_encoding.as_deref().unwrap_or("utf8"),
        });
        // Single-shot sign tool: a RequireApproval verdict is fail-closed.
        // The two-phase approval flow is not supported on this path.
        match self
            .dispatch_gate("stellar_sep53_sign_message", &args_value, &args.chain_id)
            .await?
        {
            crate::tools::common::DispatchOutcome::Allow => {}
            crate::tools::common::DispatchOutcome::RequireApproval(_) => {
                return Err(crate::tools::common::single_shot_require_approval_error());
            }
        }

        // Decode the message bytes.
        let encoding = args.message_encoding.as_deref().unwrap_or("utf8");
        let message_bytes: Vec<u8> = match encoding {
            "base64" => base64::engine::general_purpose::STANDARD
                .decode(&args.message)
                .map_err(|e| {
                    rmcp::ErrorData::invalid_params(
                        "sep53_sign_message_invalid_base64",
                        Some(json!({ "detail": format!("message base64 decode failed: {e}") })),
                    )
                })?,
            "utf8" => args.message.as_bytes().to_vec(),
            other => {
                return Err(rmcp::ErrorData::invalid_params(
                    "sep53_sign_message_invalid_encoding",
                    Some(json!({
                        "detail": format!("unsupported message_encoding: {other:?}; use 'utf8' or 'base64'")
                    })),
                ));
            }
        };

        use std::sync::Arc;
        use stellar_agent_network::keyring::signer_from_keyring;

        let account = self.profile.mcp_signer_default.account.as_str();
        let signer_handle =
            match signer_from_keyring(&self.profile.mcp_signer_default, account).await {
                Ok(h) => h,
                Err(err) => {
                    let json_str = serde_json::to_string_pretty(&json!({
                        "error": "keyring_load_failed",
                        "detail": format!("keyring load failed: {err}")
                    }))
                    .unwrap_or_else(|_| "{}".to_owned());
                    let mut result = CallToolResult::success(vec![Content::text(json_str)]);
                    result.is_error = Some(true);
                    return Ok(result);
                }
            };

        let signer: Arc<dyn stellar_agent_network::signing::Signer + Send + Sync> =
            Arc::new(signer_handle);

        match stellar_agent_sep53::sign_message(&message_bytes, signer.as_ref()).await {
            Ok(sig_bytes) => {
                // Get the signer's public key for the response.
                // The response MAY include the full public key (it is not secret).
                let pk = signer.public_key().await.map_err(|e| {
                    rmcp::ErrorData::internal_error(
                        "sep53_sign_message_pubkey_read_failed",
                        Some(json!({ "detail": format!("{e}") })),
                    )
                })?;
                // `stellar_strkey::ed25519::PublicKey` has an INHERENT `to_string()`
                // returning `heapless::String<56>` (shadows the `ToString` trait);
                // borrow as `&str` and own it for serde serialisation.
                let signer_public_key: std::string::String =
                    stellar_strkey::ed25519::PublicKey(pk.0)
                        .to_string()
                        .as_str()
                        .to_owned();

                // Encode signature as standard base64.
                let signature_b64 = base64::engine::general_purpose::STANDARD.encode(sig_bytes);

                // Log the signing event at info level with redacted public key
                // (first-5-last-5).
                let pk_redacted = if signer_public_key.len() > 10 {
                    format!(
                        "{}...{}",
                        &signer_public_key[..5],
                        &signer_public_key[signer_public_key.len() - 5..]
                    )
                } else {
                    signer_public_key.clone()
                };
                tracing::info!(
                    signer = %pk_redacted,
                    message_len = message_bytes.len(),
                    encoding = encoding,
                    "sep53 message signed"
                );

                let json_str = serde_json::to_string_pretty(&json!({
                    "signature": signature_b64,
                    "signer_public_key": signer_public_key,
                    "message_encoding": encoding,
                }))
                .unwrap_or_else(|_| "{}".to_owned());
                Ok(CallToolResult::success(vec![Content::text(json_str)]))
            }
            Err(err) => {
                let json_str = serde_json::to_string_pretty(&json!({
                    "error": "sep53_sign_failed",
                    "detail": err.to_string(),
                }))
                .unwrap_or_else(|_| "{}".to_owned());
                let mut result = CallToolResult::success(vec![Content::text(json_str)]);
                result.is_error = Some(true);
                Ok(result)
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test helpers
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(any(test, feature = "test-helpers"))]
impl WalletServer {
    /// Calls `stellar_sep53_sign_message` with the given args, bypassing the
    /// rmcp transport.
    ///
    /// # Errors
    ///
    /// Propagates `rmcp::ErrorData` from the `dispatch_gate` preamble (e.g.
    /// chain_id mismatch, policy deny, `RequireApproval` fail-closed).
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Feature gate
    ///
    /// Gated on the `test-helpers` feature or `#[cfg(test)]`.
    #[doc(hidden)]
    pub async fn call_stellar_sep53_sign_message(
        &self,
        args: Sep53SignMessageArgs,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.stellar_sep53_sign_message(rmcp::handler::server::wrapper::Parameters(args))
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
    use stellar_agent_core::policy::ToolDescriptor;
    use stellar_agent_core::policy::v1::{
        AccountIdentityView, AccountReservesView, CounterpartyCacheView, Sep10SessionView,
        Sep45SessionView,
    };
    use stellar_agent_core::policy::{ApprovalRequest, Decision, PolicyEngine, PolicyError};
    use stellar_agent_core::profile::schema::Profile;

    struct RequireApprovalEngine;

    impl PolicyEngine for RequireApprovalEngine {
        fn evaluate(
            &self,
            _tool: &ToolDescriptor,
            _args: &serde_json::Value,
            _profile: &Profile,
            _account_view: Option<&dyn AccountReservesView>,
            _identity_view: Option<&dyn AccountIdentityView>,
            _counterparty_cache: Option<&dyn CounterpartyCacheView>,
            _sep10_sessions: Option<&dyn Sep10SessionView>,
            _sep45_sessions: Option<&dyn Sep45SessionView>,
        ) -> Result<Decision, PolicyError> {
            Ok(Decision::RequireApproval(ApprovalRequest::new(
                "test-nonce".into(),
                120,
            )))
        }
    }

    fn make_require_approval_server() -> crate::server::WalletServer {
        use std::sync::Arc;
        let mut server = crate::server::WalletServer::new(
            Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
                .with_noop_engine()
                .build(),
        )
        .expect("WalletServer::new must not fail in tests");
        server.policy_engine = Arc::new(RequireApprovalEngine);
        server
    }

    /// A `RequireApproval` policy verdict on `stellar_sep53_sign_message` must
    /// return fail-closed `ErrorData` with wire code
    /// `policy.approval_required_unsupported` and MUST NOT produce a signature.
    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn require_approval_verdict_is_fail_closed_no_signature_produced() {
        stellar_agent_test_support::keyring_mock::install().ok();
        let server = make_require_approval_server();
        let args = Sep53SignMessageArgs {
            chain_id: "stellar:testnet".to_owned(),
            message: "hello stellar".to_owned(),
            message_encoding: None,
        };
        let result = server.call_stellar_sep53_sign_message(args).await;
        let err = result.expect_err(
            "RequireApproval must return Err(ErrorData), not Ok (which would mean signing proceeded)",
        );
        assert!(
            err.message.contains("policy.approval_required_unsupported"),
            "wire code must be policy.approval_required_unsupported; got: {}",
            err.message
        );
        assert!(
            err.message.contains("single-shot"),
            "error message must mention single-shot; got: {}",
            err.message
        );
    }
}
