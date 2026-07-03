//! `stellar_sep43_sign_message` MCP tool — SEP-43 `signMessage`.
//!
//! Signs an arbitrary UTF-8 message string and returns the signature as
//! lowercase hex with the signer's address.
//!
//! Per `sep-0043.md` lines :90-100.

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

/// Arguments for the `stellar_sep43_sign_message` MCP tool.
///
/// # Schema
///
/// - `chain_id` — CAIP-2 chain identifier.
/// - `message` — UTF-8 message to sign (must be non-empty).
/// - `network_passphrase` — optional network passphrase; if provided, must match the active profile.
/// - `address` — optional signer address; if provided must match active signer.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(crate = "rmcp::serde")]
pub struct Sep43SignMessageArgs {
    /// CAIP-2 chain identifier (e.g. `"stellar:testnet"`).
    pub chain_id: String,

    /// UTF-8 message string to sign.
    ///
    /// Must be non-empty. The message is hashed via `sha256(message.as_bytes())`
    /// before signing.
    pub message: String,

    /// Optional network passphrase; if provided, must match the active profile.
    ///
    /// Acts as a caller-intent validation gate. The passphrase is not mixed into
    /// the signed bytes; message signing is network-independent per SEP-43 v1.2.1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_passphrase: Option<String>,

    /// Optional signer address (G-strkey).
    ///
    /// If provided, must match the active signer enrolled in the profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool router impl block
// ─────────────────────────────────────────────────────────────────────────────

/// Signs an arbitrary message string (SEP-43 `signMessage`).
///
/// Hashes the message via `sha256(message.as_bytes())` and signs with the
/// active signer.
///
/// Returns `{ "signedMessage": "<hex>", "signerAddress": "G..." }` on success.
///
/// # Tool annotations
///
/// - `readOnlyHint = false` — creates a signature over the message.
/// - `destructiveHint = false` — signing does not submit a transaction.
///
/// # SEP-43 reference
///
/// `sep-0043.md` lines :90-100 — `signMessage(message, opts?)`.
///
/// # Errors
///
/// Returns a tool-level error when:
/// - `chain_id` does not match the profile.
/// - `message` is empty.
/// - The keyring entry for the signer cannot be loaded.
///
/// # Examples
///
/// ```json
/// { "chain_id": "stellar:testnet", "message": "hello stellar" }
/// ```
#[mcp_tool_router]
#[tool_router(router = sep43_sign_message_tool_router, vis = "pub(crate)")]
impl WalletServer {
    #[mcp_tool_item(
        name = "stellar_sep43_sign_message",
        destructive_hint = false,
        read_only_hint = false,
        chain_id_required = true
    )]
    #[tool(
        name = "stellar_sep43_sign_message",
        description = "Sign an arbitrary UTF-8 message (SEP-43 signMessage). \
                       Hashes message via sha256 before signing. \
                       Returns { signedMessage: string (hex), signerAddress: string }. \
                       read_only_hint=false; destructive_hint=false.",
        annotations(read_only_hint = false, destructive_hint = false)
    )]
    async fn stellar_sep43_sign_message(
        &self,
        Parameters(args): Parameters<Sep43SignMessageArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let args_value = json!({
            "chain_id": &args.chain_id,
            "message_len": args.message.len(),
        });
        // Single-shot sign tool: a RequireApproval verdict is fail-closed.
        // The two-phase approval flow is not supported on this path.
        match self
            .dispatch_gate("stellar_sep43_sign_message", &args_value, &args.chain_id)
            .await?
        {
            crate::tools::common::DispatchOutcome::Allow => {}
            crate::tools::common::DispatchOutcome::RequireApproval(_) => {
                return Err(crate::tools::common::single_shot_require_approval_error());
            }
        }

        use std::sync::Arc;
        use stellar_agent_network::keyring::signer_from_keyring;
        use stellar_agent_sep43::StellarAgentModule;
        use stellar_agent_sep43::module::ModuleAdapter;

        let account = self.profile.mcp_signer_default.account.as_str();

        let signer_handle =
            match signer_from_keyring(&self.profile.mcp_signer_default, account).await {
                Ok(h) => h,
                Err(err) => {
                    let resp = stellar_agent_sep43::Sep43Error::WalletUnlockFailed {
                        detail: format!("keyring load failed: {err}"),
                    }
                    .to_sep43_response();
                    let json_str =
                        serde_json::to_string_pretty(&resp).unwrap_or_else(|_| "{}".to_owned());
                    let mut result = CallToolResult::success(vec![Content::text(json_str)]);
                    result.is_error = Some(true);
                    return Ok(result);
                }
            };

        let profile = Arc::clone(&self.profile);
        let signer: Arc<dyn stellar_agent_network::signing::Signer + Send + Sync> =
            Arc::new(signer_handle);
        let module = StellarAgentModule::new(profile, signer);

        match module
            .sign_message(
                &args.message,
                args.network_passphrase.as_deref(),
                args.address.as_deref(),
            )
            .await
        {
            Ok(value) => {
                let json_str =
                    serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".to_owned());
                Ok(CallToolResult::success(vec![Content::text(json_str)]))
            }
            Err(err) => {
                let resp = err.to_sep43_response();
                let json_str =
                    serde_json::to_string_pretty(&resp).unwrap_or_else(|_| "{}".to_owned());
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
    /// Calls `stellar_sep43_sign_message` with the given args, bypassing the
    /// rmcp transport.
    ///
    /// Integration-test entry point for handler-level checks.
    ///
    /// # Errors
    ///
    /// Propagates `rmcp::ErrorData` from the `dispatch_gate` preamble (e.g.
    /// chain_id mismatch, policy deny, `RequireApproval` fail-closed).
    /// Signing errors are returned as `Ok(CallToolResult)` with
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
    pub async fn call_stellar_sep43_sign_message(
        &self,
        args: Sep43SignMessageArgs,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.stellar_sep43_sign_message(rmcp::handler::server::wrapper::Parameters(args))
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

    /// A `RequireApproval` policy verdict on `stellar_sep43_sign_message` must
    /// return fail-closed `ErrorData` with wire code
    /// `policy.approval_required_unsupported` and MUST NOT produce a signature.
    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn require_approval_verdict_is_fail_closed_no_signature_produced() {
        stellar_agent_test_support::keyring_mock::install().ok();
        let server = make_require_approval_server();
        let args = Sep43SignMessageArgs {
            chain_id: "stellar:testnet".to_owned(),
            message: "hello stellar".to_owned(),
            network_passphrase: None,
            address: None,
        };
        let result = server.call_stellar_sep43_sign_message(args).await;
        let err = result.expect_err(
            "RequireApproval must return Err(ErrorData), not Ok (which would mean signing proceeded)",
        );
        assert!(
            err.message.contains("policy.approval_required_unsupported"),
            "wire code must be policy.approval_required_unsupported; got: {}",
            err.message
        );
        // Confirm the message explains the single-shot limitation.
        assert!(
            err.message.contains("single-shot"),
            "error message must mention single-shot; got: {}",
            err.message
        );
    }
}
