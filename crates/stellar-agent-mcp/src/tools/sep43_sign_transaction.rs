//! `stellar_sep43_sign_transaction` MCP tool — SEP-43 `signTransaction`.
//!
//! Signs a base64-encoded `TransactionEnvelope` XDR and returns the signed
//! envelope with the signer's address.
//!
//! Per `sep-0043.md` lines :62-76.
//!
//! # Signing path
//!
//! Loads the signer from `profile.mcp_signer_default` via
//! `stellar_agent_network::keyring::signer_from_keyring`, then dispatches to
//! `stellar_agent_sep43::StellarAgentModule::sign_transaction`.

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

/// Arguments for the `stellar_sep43_sign_transaction` MCP tool.
///
/// # Schema
///
/// - `chain_id` — CAIP-2 chain identifier; validated against the active profile.
/// - `transaction_xdr` — base64-encoded `TransactionEnvelope` XDR.
/// - `network_passphrase` — optional; if provided must match profile passphrase.
/// - `address` — optional signer address (G-strkey); if provided must match
///   the active signer.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(crate = "rmcp::serde")]
pub struct Sep43SignTransactionArgs {
    /// CAIP-2 chain identifier (e.g. `"stellar:testnet"`).
    pub chain_id: String,

    /// Base64-encoded `TransactionEnvelope` XDR to sign.
    pub transaction_xdr: String,

    /// Optional Stellar network passphrase override.
    ///
    /// If provided, must equal the profile's `network_passphrase` exactly.
    /// Mismatch → error code -3.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_passphrase: Option<String>,

    /// Optional signer address (G-strkey).
    ///
    /// If provided, must match the active signer enrolled in the profile.
    /// Mismatch → error code -3.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool router impl block
// ─────────────────────────────────────────────────────────────────────────────

/// Signs a `TransactionEnvelope` XDR (SEP-43 `signTransaction`).
///
/// Loads the signer from the profile's default keyring entry and signs the
/// provided transaction XDR.  Returns
/// `{ "signedTxXdr": "...", "signerAddress": "G..." }` on success or a
/// SEP-43 spec-compliant `{ "code": N, "message": "..." }` error object.
///
/// # Tool annotations
///
/// - `readOnlyHint = false` — creates a signature over the transaction.
/// - `destructiveHint = false` — `signTransaction` per SEP-43 does NOT submit;
///   the `submit?` opt defaults to `false`. Submission is a separate step.
///
/// # SEP-43 reference
///
/// `sep-0043.md` lines :62-76 — `signTransaction(xdr, opts?)`.
///
/// # Errors
///
/// Returns a tool-level error (not a JSON-RPC error) when:
/// - `chain_id` does not match the active profile.
/// - `transaction_xdr` is not valid base64 `TransactionEnvelope`.
/// - `network_passphrase` is provided but does not match the profile.
/// - `address` is provided but does not match the active signer.
/// - The keyring entry for the signer cannot be loaded.
///
/// # Examples
///
/// ```json
/// {
///   "chain_id": "stellar:testnet",
///   "transaction_xdr": "AAAAAQAA..."
/// }
/// ```
#[mcp_tool_router]
#[tool_router(router = sep43_sign_transaction_tool_router, vis = "pub(crate)")]
impl WalletServer {
    #[mcp_tool_item(
        name = "stellar_sep43_sign_transaction",
        destructive_hint = false,
        read_only_hint = false,
        chain_id_required = true
    )]
    #[tool(
        name = "stellar_sep43_sign_transaction",
        description = "Sign a TransactionEnvelope XDR (SEP-43 signTransaction). \
                       Does NOT submit — signing only. \
                       Returns { signedTxXdr: string, signerAddress: string }. \
                       read_only_hint=false; destructive_hint=false.",
        annotations(read_only_hint = false, destructive_hint = false)
    )]
    async fn stellar_sep43_sign_transaction(
        &self,
        Parameters(args): Parameters<Sep43SignTransactionArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        // Mainnet structural refusal — before any key access or signing.
        // This tool returns a signature the caller broadcasts externally; the
        // submit-layer mainnet gate never fires because the wallet does not
        // submit. Refuse on a mainnet profile so no valid mainnet signature is
        // ever produced. Wire code: network.mainnet_write_forbidden.
        if self.profile.chain_id.is_mainnet() {
            return Ok(crate::tools::common::mainnet_signing_forbidden_result());
        }

        let args_value = json!({
            "chain_id": &args.chain_id,
            "transaction_xdr_len": args.transaction_xdr.len(),
        });
        // Single-shot sign tool: a RequireApproval verdict is fail-closed.
        // The two-phase approval flow is not supported on this path.
        match self
            .dispatch_gate(
                "stellar_sep43_sign_transaction",
                &args_value,
                &args.chain_id,
            )
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

        // Load the signer from the keyring.
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
            .sign_transaction(
                &args.transaction_xdr,
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
    /// Calls `stellar_sep43_sign_transaction` with the given args, bypassing the
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
    pub async fn call_stellar_sep43_sign_transaction(
        &self,
        args: Sep43SignTransactionArgs,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.stellar_sep43_sign_transaction(rmcp::handler::server::wrapper::Parameters(args))
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

    fn make_mainnet_server() -> crate::server::WalletServer {
        crate::server::WalletServer::new(
            Profile::builder_mainnet("svc", "acct", "n-svc", "n-acct")
                .with_noop_engine()
                .build(),
        )
        .expect("WalletServer::new must not fail in tests")
    }

    /// A mainnet profile MUST refuse `stellar_sep43_sign_transaction`
    /// structurally before any key access: the result is an `is_error` SEP-43
    /// object carrying the canonical `network.mainnet_write_forbidden` wire code
    /// (SEP-43 code -3), and it MUST NOT contain a signed transaction.
    ///
    /// The keyring mock is intentionally NOT installed: reaching the keyring
    /// would surface a `wallet_unlock_failed` message instead, so this test also
    /// proves the refusal fires before key access.
    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn mainnet_profile_refuses_before_signing_no_signature_produced() {
        let server = make_mainnet_server();
        let args = Sep43SignTransactionArgs {
            chain_id: "stellar:mainnet".to_owned(),
            transaction_xdr: "AAAAAQAA".to_owned(),
            network_passphrase: None,
            address: None,
        };
        let result = server
            .call_stellar_sep43_sign_transaction(args)
            .await
            .expect("structural mainnet refusal is surfaced as Ok(is_error), not Err");
        assert_eq!(
            result.is_error,
            Some(true),
            "mainnet refusal must set is_error = true"
        );
        let text = result
            .content
            .first()
            .and_then(|c| c.as_text())
            .map(|t| t.text.as_str())
            .expect("refusal result must carry a text content block");
        let value: serde_json::Value =
            serde_json::from_str(text).expect("refusal content must be a SEP-43 JSON object");
        assert_eq!(value["code"], -3_i32, "mainnet refusal is SEP-43 code -3");
        let message = value["message"].as_str().unwrap_or_default();
        assert!(
            message.contains("network.mainnet_write_forbidden"),
            "message must carry the canonical wire code; got: {value}"
        );
        assert!(
            !message.contains("keyring") && !message.contains("unlock"),
            "refusal must fire before key access — message must not mention keyring/unlock: {value}"
        );
        assert!(
            value.get("signedTxXdr").is_none(),
            "no signature must be produced on mainnet; got: {value}"
        );
    }

    /// A `RequireApproval` policy verdict on `stellar_sep43_sign_transaction`
    /// must return fail-closed `ErrorData` with wire code
    /// `policy.approval_required_unsupported` and MUST NOT sign the transaction.
    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn require_approval_verdict_is_fail_closed_no_signature_produced() {
        stellar_agent_test_support::keyring_mock::install().ok();
        let server = make_require_approval_server();
        let args = Sep43SignTransactionArgs {
            chain_id: "stellar:testnet".to_owned(),
            transaction_xdr: "AAAAAQAA".to_owned(),
            network_passphrase: None,
            address: None,
        };
        let result = server.call_stellar_sep43_sign_transaction(args).await;
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
