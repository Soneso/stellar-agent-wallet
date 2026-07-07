//! `stellar_sep43_sign_and_submit_transaction` MCP tool — SEP-43 sign-and-submit.
//!
//! Signs a base64-encoded `TransactionEnvelope` XDR, submits it via the Stellar
//! RPC, and returns `{ signedTxXdr, txHash, status }`.
//!
//! # SEP-43 spec reference
//!
//! Per `sep-0043.md` lines :62-76 — `signTransaction(xdr, opts?)` where the
//! optional `submit` flag requests the wallet to sign AND submit. This tool
//! implements the submit variant as a dedicated method per the WalletConnect v2
//! `stellar_signAndSubmitXDR` method.
//!
//! # WalletConnect response shape
//!
//! The WalletConnect v2 `stellar_signAndSubmitXDR` method has the shape:
//!
//! ```text
//! async signAndSubmitTransaction(xdr, opts?) → { status: "success" | "pending" }
//! ```
//!
//! The method REQUIRES wallet-side submit-to-RPC; the response status is
//! `"success"` or `"pending"`.
//!
//! This MCP tool extends that shape with `signedTxXdr` and `txHash` in the
//! success response so agent consumers can observe the signed envelope and the
//! on-chain transaction hash without an extra RPC call.
//!
//! # Signing path
//!
//! 1. Loads the signer from `profile.mcp_signer_default` via
//!    `stellar_agent_network::keyring::signer_from_keyring`.
//! 2. Dispatches to `stellar_agent_sep43::StellarAgentModule::sign_transaction`.
//! 3. Submits the signed envelope via
//!    `stellar_agent_network::submit::submit_transaction_and_wait`.
//!
//! # Result status mapping
//!
//! [`stellar_agent_network::submit::SubmissionResult`] is returned by
//! `submit_transaction_and_wait` only after the transaction has been confirmed
//! in a ledger (status `"SUCCESS"` from `getTransaction`). There is no separate
//! `Pending` variant — the function polls until `SUCCESS` or returns a
//! `WalletError::Submission(TxTimeout)` if the timeout elapses.
//!
//! Therefore: `Ok(result)` → `status: "success"`;
//! `Err(WalletError::Submission(TxTimeout))` → `status: "pending"` (the
//! transaction may still confirm; the wallet's polling window expired).
//! `RpcUnreachable` and `RpcTimeout` → explicit arms strip the URL from
//! the Display string before surfacing `Sep43Error::RpcError` so the endpoint
//! never bleeds to the dapp caller.  All other errors → SEP-43 code -3.
//!
//! # Chain-not-supported mapping
//!
//! `chain_id` mismatches are caught by the `dispatch_gate` preamble and surface
//! as JSON-RPC-level `ErrorData` (consistent with `sep43_sign_transaction.rs`).
//! Passphrase mismatches after the `dispatch_gate` surface as SEP-43 code -3
//! (`InvalidNetworkPassphrase`) via the sep43 module's `sign_transaction`
//! validation path.

use rmcp::{
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Content},
    schemars, serde, tool, tool_router,
};
use serde_json::json;
use stellar_agent_core::error::NetworkError;
use stellar_agent_mcp_macros::mcp_tool_router;

use crate::server::WalletServer;
use crate::tools::common::redact_rpc_error_detail;

// Re-export the args type at the crate root (via server.rs) for test use.
// The server.rs re-export is the canonical public surface.

// ─────────────────────────────────────────────────────────────────────────────
// Argument type
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for the `stellar_sep43_sign_and_submit_transaction` MCP tool.
///
/// # Schema
///
/// - `chain_id` — CAIP-2 chain identifier (`"stellar:pubnet"` or
///   `"stellar:testnet"`); validated against the active profile.
/// - `transaction_xdr` — base64-encoded `TransactionEnvelope` XDR to sign and
///   submit.
/// - `network_passphrase` — optional; if provided must equal the profile's
///   configured passphrase.
/// - `address` — optional signer address (G-strkey); if provided must match
///   the active signer enrolled in the profile.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(crate = "rmcp::serde")]
pub struct Sep43SignAndSubmitTransactionArgs {
    /// CAIP-2 chain identifier (`"stellar:pubnet"` or `"stellar:testnet"`).
    ///
    /// Validated against the active profile. Mismatch returns JSON-RPC
    /// `ErrorData` from the `dispatch_gate` preamble.
    pub chain_id: String,

    /// Base64-encoded `TransactionEnvelope` XDR to sign and submit.
    pub transaction_xdr: String,

    /// Optional Stellar network passphrase override.
    ///
    /// When provided must equal `profile.network_passphrase` exactly.
    /// Mismatch causes the signing step to return SEP-43 error code -3
    /// (`InvalidNetworkPassphrase`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_passphrase: Option<String>,

    /// Optional signer address (G-strkey).
    ///
    /// When provided must match the active signer enrolled in the profile.
    /// Mismatch causes the signing step to return SEP-43 error code -3
    /// (`InvalidAddress`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool router impl block
// ─────────────────────────────────────────────────────────────────────────────

/// Signs and submits a `TransactionEnvelope` XDR.
///
/// Implements the SEP-43 sign-and-submit flow corresponding to the WalletConnect
/// v2 `stellar_signAndSubmitXDR` method.
///
/// Returns `{ "signedTxXdr": "<base64>", "txHash": "<hex64>", "status": "success" }`
/// on confirmed submission, or `{ "signedTxXdr": "<base64>", "txHash": "", "status": "pending" }`
/// when the polling window expired before ledger confirmation.
///
/// Errors return a SEP-43 spec-compliant `{ "code": N, "message": "..." }` object.
///
/// # Tool annotations
///
/// - `readOnlyHint = false` — creates a signed transaction and submits it.
/// - `destructiveHint = true` — this tool DOES submit to the network, unlike
///   `stellar_sep43_sign_transaction` which is sign-only.
///
/// # SEP-43 reference
///
/// `sep-0043.md` lines :62-76 — `signTransaction` with `submit?` option.
/// Implements the WalletConnect v2 `stellar_signAndSubmitXDR` submit-and-status
/// response shape.
///
/// # Errors
///
/// Returns a tool-level error (not a JSON-RPC error) when:
/// - `chain_id` does not match the active profile (`dispatch_gate` preamble).
/// - `transaction_xdr` is not valid base64 `TransactionEnvelope` XDR.
/// - `network_passphrase` is provided but does not match the profile passphrase.
/// - `address` is provided but does not match the active signer.
/// - The keyring entry for the signer cannot be loaded.
/// - The RPC client cannot be constructed from `profile.rpc_url`.
/// - Submission is rejected on-chain or times out.
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
#[tool_router(
    router = sep43_sign_and_submit_transaction_tool_router,
    vis = "pub(crate)"
)]
impl WalletServer {
    #[mcp_tool_item(
        name = "stellar_sep43_sign_and_submit_transaction",
        destructive_hint = true,
        read_only_hint = false,
        chain_id_required = true,
        value_kind = "opaque_sign"
    )]
    #[tool(
        name = "stellar_sep43_sign_and_submit_transaction",
        description = "Sign and submit a TransactionEnvelope XDR (SEP-43 signAndSubmit / \
                       WC v2 stellar_signAndSubmitXDR). Signs with the active profile signer, \
                       submits via RPC, polls until confirmed. \
                       Returns { signedTxXdr: string, txHash: string, status: \"success\" | \"pending\" }. \
                       read_only_hint=false; destructive_hint=true.",
        annotations(read_only_hint = false, destructive_hint = true)
    )]
    async fn stellar_sep43_sign_and_submit_transaction(
        &self,
        Parameters(args): Parameters<Sep43SignAndSubmitTransactionArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        use std::sync::Arc;

        use stellar_agent_network::StellarRpcClient;
        use stellar_agent_network::keyring::signer_from_keyring;
        use stellar_agent_network::submit::submit_transaction_and_wait;
        use stellar_agent_sep43::StellarAgentModule;
        use stellar_agent_sep43::module::ModuleAdapter;

        // ── Telemetry preamble ────────────────────────────────────────────────
        // Redact account IDs to first-5-last-5; tx XDR length only (no content).
        let args_value = json!({
            "chain_id": &args.chain_id,
            "transaction_xdr_len": args.transaction_xdr.len(),
        });

        // ── dispatch_gate: registry lookup + policy evaluation + chain_id ─────
        // Single-shot sign tool: a RequireApproval verdict is fail-closed.
        // The two-phase approval flow is not supported on this path.
        let dispatch_outcome = match self
            .dispatch_gate(
                "stellar_sep43_sign_and_submit_transaction",
                &args_value,
                &args.chain_id,
            )
            .await
        {
            Ok(o) => o,
            Err(e) => return e.into_result(),
        };
        match dispatch_outcome {
            crate::tools::common::DispatchOutcome::Allow => {}
            crate::tools::common::DispatchOutcome::RequireApproval(_) => {
                return Ok(crate::tools::common::single_shot_require_approval_error());
            }
        }

        tracing::debug!(
            chain_id = %args.chain_id,
            xdr_len = args.transaction_xdr.len(),
            "sep43_sign_and_submit: dispatch gate passed",
        );

        let account = self.profile.mcp_signer_default.account.as_str();

        // ── Load signer from keyring ──────────────────────────────────────────
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

        // ── Sign the transaction via the SEP-43 module ───────────────────────
        // Dispatches to `stellar_agent_sep43::StellarAgentModule::sign_transaction`.
        let profile = Arc::clone(&self.profile);
        let signer: Arc<dyn stellar_agent_network::signing::Signer + Send + Sync> =
            Arc::new(signer_handle);
        let module = StellarAgentModule::new(profile, signer);

        let signed_value = match module
            .sign_transaction(
                &args.transaction_xdr,
                args.network_passphrase.as_deref(),
                args.address.as_deref(),
            )
            .await
        {
            Ok(v) => v,
            Err(err) => {
                let resp = err.to_sep43_response();
                let json_str =
                    serde_json::to_string_pretty(&resp).unwrap_or_else(|_| "{}".to_owned());
                let mut result = CallToolResult::success(vec![Content::text(json_str)]);
                result.is_error = Some(true);
                return Ok(result);
            }
        };

        // Extract the signed XDR from the module response.
        // `sign_transaction` returns `{ "signedTxXdr": "...", "signerAddress": "..." }`.
        let signed_xdr = match signed_value
            .get("signedTxXdr")
            .and_then(serde_json::Value::as_str)
        {
            Some(xdr) => xdr.to_owned(),
            None => {
                let resp = stellar_agent_sep43::Sep43Error::XdrSerializationFailed {
                    detail: "sign_transaction response missing signedTxXdr field".to_owned(),
                }
                .to_sep43_response();
                let json_str =
                    serde_json::to_string_pretty(&resp).unwrap_or_else(|_| "{}".to_owned());
                let mut result = CallToolResult::success(vec![Content::text(json_str)]);
                result.is_error = Some(true);
                return Ok(result);
            }
        };

        // ── Construct RPC client from active profile ──────────────────────────
        let rpc_url = self.profile.rpc_url.as_str();
        let client = match StellarRpcClient::new(rpc_url) {
            Ok(c) => c,
            Err(err) => {
                let resp = stellar_agent_sep43::Sep43Error::RpcError {
                    detail: redact_rpc_error_detail("rpc_client_construction_failed", &err),
                }
                .to_sep43_response();
                let json_str =
                    serde_json::to_string_pretty(&resp).unwrap_or_else(|_| "{}".to_owned());
                let mut result = CallToolResult::success(vec![Content::text(json_str)]);
                result.is_error = Some(true);
                return Ok(result);
            }
        };

        // ── Submit via submit_transaction_and_wait ────────────────────────────
        // Reuses `stellar_agent_network::submit::submit_transaction_and_wait`.
        // Timeout from profile or default (60 s).
        let timeout = crate::tools::common::submit_timeout(&self.profile);
        let network_passphrase = self.profile.network_passphrase.as_str();

        match submit_transaction_and_wait(
            &client,
            &signed_xdr,
            timeout,
            network_passphrase,
            Some(stellar_agent_network::SubmissionSignerKind::Keyring),
        )
        .await
        {
            Ok(result) => {
                // `SubmissionResult` carries `tx_hash: String` (64-char lowercase
                // hex) and `ledger: u32`.  `Ok(_)` here means the RPC confirmed
                // STATUS = "SUCCESS"; map to `status: "success"`.
                // SAFETY: `result.tx_hash` is the raw 64-char hex hash.
                // MUST be redacted before passing to any telemetry sink.
                // `response` is the MCP tool output — sent to callers, NOT to
                // tracing — so the full hash appears only in the response object,
                // never in a `tracing::info!` call.  All telemetry below uses
                // `redact_tx_hash`.
                let redacted = stellar_agent_network::submit::redact_tx_hash(&result.tx_hash);
                tracing::info!(
                    tx_hash = %redacted,
                    ledger = result.ledger,
                    "sep43_sign_and_submit: transaction confirmed",
                );
                let response = json!({
                    "signedTxXdr": signed_xdr,
                    "txHash": result.tx_hash,
                    "status": "success",
                });
                let json_str =
                    serde_json::to_string_pretty(&response).unwrap_or_else(|_| "{}".to_owned());
                Ok(CallToolResult::success(vec![Content::text(json_str)]))
            }

            Err(stellar_agent_core::WalletError::Submission(
                stellar_agent_core::error::SubmissionError::TxTimeout { ref tx_hash, .. },
            )) => {
                // The transaction was submitted but not confirmed within the
                // polling window. The transaction MAY still be accepted in a
                // future ledger. Map to `status: "pending"`. `tx_hash` may be
                // empty-string if timeout fired before the hash was retrieved;
                // use what we have.
                let redacted = stellar_agent_network::submit::redact_tx_hash(tx_hash);
                tracing::info!(
                    tx_hash = %redacted,
                    "sep43_sign_and_submit: submit timeout; status pending",
                );
                let response = json!({
                    "signedTxXdr": signed_xdr,
                    "txHash": tx_hash,
                    "status": "pending",
                });
                let json_str =
                    serde_json::to_string_pretty(&response).unwrap_or_else(|_| "{}".to_owned());
                Ok(CallToolResult::success(vec![Content::text(json_str)]))
            }

            Err(stellar_agent_core::WalletError::Network(
                stellar_agent_core::error::NetworkError::MainnetWriteForbidden,
            )) => {
                // Mainnet-write guard — surface as MainnetSigningForbidden (-3),
                // the same SEP-43 code the sign-only tools use for the structural
                // mainnet refusal, rather than the external-service RpcError (-2).
                // Same refusal class, one code group across the sep43 family.
                let resp = stellar_agent_sep43::Sep43Error::MainnetSigningForbidden {
                    detail: crate::tools::common::mainnet_signing_refusal_detail(),
                }
                .to_sep43_response();
                let json_str =
                    serde_json::to_string_pretty(&resp).unwrap_or_else(|_| "{}".to_owned());
                let mut result = CallToolResult::success(vec![Content::text(json_str)]);
                result.is_error = Some(true);
                Ok(result)
            }

            Err(stellar_agent_core::WalletError::Network(
                stellar_agent_core::error::NetworkError::RpcUnreachable { .. },
            )) => {
                // URL is in the RpcUnreachable struct; strip it to prevent credential
                // or endpoint leak to the dapp caller.
                tracing::warn!("sep43_sign_and_submit: rpc_unreachable");
                let resp = stellar_agent_sep43::Sep43Error::RpcError {
                    detail: "rpc_unreachable".to_owned(),
                }
                .to_sep43_response();
                let json_str =
                    serde_json::to_string_pretty(&resp).unwrap_or_else(|_| "{}".to_owned());
                let mut result = CallToolResult::success(vec![Content::text(json_str)]);
                result.is_error = Some(true);
                Ok(result)
            }

            Err(stellar_agent_core::WalletError::Network(
                stellar_agent_core::error::NetworkError::RpcTimeout { .. },
            )) => {
                // RpcTimeout Display is `"RPC endpoint '{url}' timed out after
                // {timeout_secs}s"`.  URL is embedded in the Display string; strip
                // it to prevent endpoint leak to the dapp caller, mirroring the
                // RpcUnreachable arm above.
                tracing::warn!("sep43_sign_and_submit: rpc_timeout");
                let resp = stellar_agent_sep43::Sep43Error::RpcError {
                    detail: "rpc_timeout".to_owned(),
                }
                .to_sep43_response();
                let json_str =
                    serde_json::to_string_pretty(&resp).unwrap_or_else(|_| "{}".to_owned());
                let mut result = CallToolResult::success(vec![Content::text(json_str)]);
                result.is_error = Some(true);
                Ok(result)
            }

            Err(err) => {
                // All other errors (XDR decode failure, on-chain FAILED, bad auth,
                // etc.) map to SEP-43 code -1.
                // `stellar_agent_network::submit` error taxonomy:
                // WalletError::Protocol → XdrCodecFailed (code -1 per "internal")
                // WalletError::Submission → TxMalformed (code -1)
                // WalletError::Ledger   → on-chain failure (code -1)
                //
                // NOTE: WalletError::Network variants RpcUnreachable and RpcTimeout
                // are handled in explicit arms above to strip URL from Display.
                // AccountNotFound carries a G-strkey and is redacted in the
                // shared formatter below before crossing the dapp wire boundary.
                tracing::warn!(
                    error = %err,
                    "sep43_sign_and_submit: submission failed",
                );
                let resp = stellar_agent_sep43::Sep43Error::RpcError {
                    detail: submission_failed_detail(&err),
                }
                .to_sep43_response();
                let json_str =
                    serde_json::to_string_pretty(&resp).unwrap_or_else(|_| "{}".to_owned());
                let mut result = CallToolResult::success(vec![Content::text(json_str)]);
                result.is_error = Some(true);
                Ok(result)
            }
        }
    }
}

fn submission_failed_detail(err: &stellar_agent_core::WalletError) -> String {
    match err {
        stellar_agent_core::WalletError::Network(NetworkError::AccountNotFound { account_id }) => {
            format!(
                "submission_failed: account not found: {}",
                stellar_agent_core::observability::redact_strkey_first5_last5(account_id)
            )
        }
        _ => format!("submission_failed: {err}"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test helpers
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(any(test, feature = "test-helpers"))]
impl WalletServer {
    /// Calls `stellar_sep43_sign_and_submit_transaction` with the given args,
    /// bypassing the rmcp transport.
    ///
    /// Integration-test and testnet-acceptance entry point for handler-level
    /// checks.  The method wraps the private handler in a `Parameters` envelope
    /// so test code does not need to import rmcp internals directly.
    ///
    /// # Errors
    ///
    /// Propagates `rmcp::ErrorData` from the `dispatch_gate` preamble (e.g.
    /// chain_id mismatch, policy deny).  SEP-43 semantic errors (signing
    /// failures, submission failures) are returned as `Ok(CallToolResult)` with
    /// `is_error = Some(true)` per the SEP-43 error-object contract.
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Feature gate
    ///
    /// Gated on the `test-helpers` feature or `#[cfg(test)]`.
    #[doc(hidden)]
    pub async fn call_stellar_sep43_sign_and_submit_transaction(
        &self,
        args: Sep43SignAndSubmitTransactionArgs,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.stellar_sep43_sign_and_submit_transaction(Parameters(args))
            .await
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;
    use stellar_agent_core::WalletError;
    use stellar_agent_core::error::NetworkError;
    use stellar_agent_core::policy::ToolDescriptor;
    use stellar_agent_core::policy::v1::{
        AccountIdentityView, AccountReservesView, CounterpartyCacheView, Sep10SessionView,
        Sep45SessionView,
    };
    use stellar_agent_core::policy::{ApprovalRequest, Decision, PolicyEngine, PolicyError};
    use stellar_agent_core::profile::schema::Profile;

    #[test]
    fn account_not_found_wire_detail_redacts_strkey() {
        let account_id = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY".to_owned();
        let err = WalletError::Network(NetworkError::AccountNotFound {
            account_id: account_id.clone(),
        });
        let detail = submission_failed_detail(&err);

        assert!(
            !detail.contains(&account_id),
            "full strkey leaked: {detail}"
        );
        assert!(
            detail.contains("GAQAA...QSTVY"),
            "redacted strkey missing: {detail}"
        );
    }

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

    /// A `RequireApproval` policy verdict on
    /// `stellar_sep43_sign_and_submit_transaction` must return fail-closed
    /// `ErrorData` with wire code `policy.approval_required_unsupported` and
    /// MUST NOT sign or submit the transaction.
    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn require_approval_verdict_is_fail_closed_no_signature_produced() {
        stellar_agent_test_support::keyring_mock::install().ok();
        let server = make_require_approval_server();
        let args = Sep43SignAndSubmitTransactionArgs {
            chain_id: "stellar:testnet".to_owned(),
            transaction_xdr: "AAAAAQAA".to_owned(),
            network_passphrase: None,
            address: None,
        };
        let result = server
            .call_stellar_sep43_sign_and_submit_transaction(args)
            .await;
        let result = result.expect(
            "RequireApproval must return Ok(is_error) envelope, not a protocol error or a signature",
        );
        let (code, message, text) = crate::tools::common::assert_business_envelope(&result);
        assert_eq!(
            code, "policy.approval_required_unsupported",
            "wire code must be policy.approval_required_unsupported"
        );
        assert!(
            message.contains("single-shot"),
            "error message must mention single-shot; got: {message}"
        );
        assert!(
            !text.contains("\"signature\""),
            "fail-closed approval refusal must not produce a signature; got: {text}"
        );
    }
}
