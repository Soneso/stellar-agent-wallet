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
/// Returns `{ ok: true, data: { "signedTxXdr": "<base64>", "txHash": "<hex64>",
/// "status": "success" }, request_id }` on confirmed submission, or the same
/// shape with `"txHash": ""` and `"status": "pending"` when the polling window
/// expired before ledger confirmation (`ok: true` in both cases — pending is
/// not a failure).
///
/// Errors return `{ ok: false, error: { code, message }, request_id }` with a
/// `sep43.*` wire code (or `network.mainnet_write_forbidden` for the mainnet
/// guard, shared with the sign-only tools).
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

        use stellar_agent_core::audit_log::{AuditEntry, PolicyDecision};
        use stellar_agent_core::policy::v1::OpaqueReason;
        use stellar_agent_network::StellarRpcClient;
        use stellar_agent_network::keyring::signer_from_keyring;
        use stellar_agent_network::submit::submit_transaction_and_wait;
        use stellar_agent_sep43::StellarAgentModule;
        use stellar_agent_sep43::module::ModuleAdapter;

        use crate::tools::value_audit::emit_value_audit_row_with_writer;

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
            crate::tools::common::DispatchOutcome::Allow(_) => {}
            crate::tools::common::DispatchOutcome::RequireApproval(_) => {
                return Ok(crate::tools::common::single_shot_require_approval_error());
            }
        }

        // ── Audit pre-flight (fail-closed) ────────────────────────────────────
        // Runs AFTER the dispatch gate: a policy denial or approval escalation
        // signs and submits nothing and needs no audit setup, so it must
        // surface its own code rather than audit.chain_key_unavailable. The
        // pre-flight still precedes the signer load, the signature, and the
        // submit — the transaction must not exist unless the row recording its
        // production can be written. Reused (not re-acquired) for the
        // post-confirm `opaque_action_submitted` row.
        let audit_writer = match crate::tools::value_audit::require_value_audit_writer(
            &self.profile,
            &self.profile_name_for_approval(),
        ) {
            Ok(w) => w,
            Err(err) => {
                return Ok(crate::tools::common::business_error_result(
                    err.code(),
                    err.to_string(),
                ));
            }
        };

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
                    let sep43_err = stellar_agent_sep43::Sep43Error::WalletUnlockFailed {
                        detail: format!("keyring load failed: {err}"),
                    };
                    return Ok(crate::tools::common::business_error_result(
                        sep43_err.wire_code(),
                        sep43_err.to_string(),
                    ));
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
                return Ok(crate::tools::common::business_error_result(
                    err.wire_code(),
                    err.to_string(),
                ));
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
                let sep43_err = stellar_agent_sep43::Sep43Error::XdrSerializationFailed {
                    detail: "sign_transaction response missing signedTxXdr field".to_owned(),
                };
                return Ok(crate::tools::common::business_error_result(
                    sep43_err.wire_code(),
                    sep43_err.to_string(),
                ));
            }
        };

        // ── Construct RPC client from active profile ──────────────────────────
        let rpc_url = self.profile.rpc_url.as_str();
        let client = match StellarRpcClient::new(rpc_url) {
            Ok(c) => c,
            Err(err) => {
                let sep43_err = stellar_agent_sep43::Sep43Error::RpcError {
                    detail: redact_rpc_error_detail("rpc_client_construction_failed", &err),
                };
                return Ok(crate::tools::common::business_error_result(
                    sep43_err.wire_code(),
                    sep43_err.to_string(),
                ));
            }
        };

        // ── Submit via submit_transaction_and_wait ────────────────────────────
        // Reuses `stellar_agent_network::submit::submit_transaction_and_wait`.
        // Timeout from profile or default (60 s).
        let timeout = crate::tools::common::submit_timeout(&self.profile);
        let network_passphrase = self.profile.network_passphrase.as_str();

        // Record the submission before the bytes leave. The envelope is the
        // caller's, so the policy engine sized no value for it and no
        // spending-window reservation is possible — but the receipt, the
        // pending row and the duplicate suppression are, and they are what
        // make a timeout here reconcilable and the sequence protected.
        let profile_name = self.profile_name_for_approval();
        let now_ms = match stellar_agent_core::timefmt::now_unix_ms() {
            Ok(v) => v,
            Err(e) => {
                return Ok(crate::tools::common::business_error_result(
                    "wallet.clock_error",
                    e.to_string(),
                ));
            }
        };
        let recorder = match crate::tools::submission_record::build_recorder(
            crate::tools::submission_record::CommitRecord {
                profile: &self.profile,
                profile_name: profile_name.clone(),
                tool: "stellar_sep43_sign_and_submit_transaction",
                chain_id: self.profile.chain_id.caip2_str().to_owned(),
                legs: Vec::new(),
                engine: self.policy_engine.as_ref(),
                descriptor: None,
                value_class: stellar_agent_core::policy::v1::ValueClass::Opaque(
                    OpaqueReason::RawTransactionSignature,
                ),
                audit: std::sync::Arc::clone(&audit_writer),
                nonce_id: None,
                approval_nonce: None,
                approval_dir: None,
                now_ms,
            },
            None,
        ) {
            // The tool writes the row that carries its own contract, so the
            // recorder leaves the confirmed arm to it: one settled row per
            // confirmed send.
            Ok(r) => r.with_caller_written_confirmed_row(),
            Err(err) => {
                return Ok(crate::tools::submission_record::submission_error_result(
                    &err,
                    &signed_xdr,
                ));
            }
        };

        match submit_transaction_and_wait(
            &client,
            &signed_xdr,
            timeout,
            network_passphrase,
            Some(stellar_agent_network::SubmissionSignerKind::Keyring),
            Some(&recorder),
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

                // Non-fatal allow-path audit row. This is an opaque submit: the
                // wallet did not decode the caller-supplied envelope's value, so
                // legs are empty and the opaque reason is the tool's fixed
                // classification (name-derived, not argument-derived). The on-chain
                // tx is identified by the redacted hash.
                //
                // The row names the submission it settles. It is the only
                // settled row this send writes, so without the envelope hash
                // the pending row written before the send stays owed for good
                // and a later reconciliation of the same transaction appends a
                // second one.
                let request_id = uuid::Uuid::new_v4().to_string();
                let audit_entry = AuditEntry::new_opaque_action_submitted(
                    "stellar_sep43_sign_and_submit_transaction",
                    args.chain_id.as_str(),
                    OpaqueReason::RawTransactionSignature.as_str(),
                    redacted.as_str(),
                    result.ledger,
                    PolicyDecision::Allow,
                    Some(stellar_agent_network::envelope_hash_hex(&signed_xdr)),
                    None,
                    &request_id,
                );
                emit_value_audit_row_with_writer(
                    &audit_writer,
                    &self.profile_name_for_approval(),
                    audit_entry,
                );

                let response = json!({
                    "signedTxXdr": signed_xdr,
                    "txHash": result.tx_hash,
                    "status": "success",
                });
                let envelope = stellar_agent_core::envelope::Envelope::ok(response);
                let json_str = envelope
                    .to_json_pretty()
                    .unwrap_or_else(|_| String::from("{}"));
                Ok(CallToolResult::success(vec![Content::text(json_str)]))
            }

            Err(stellar_agent_core::WalletError::Submission(
                stellar_agent_core::error::SubmissionError::TxTimeout { ref tx_hash, .. },
            )) => {
                // The transaction was submitted but not confirmed within the
                // polling window. It MAY still be accepted in a future ledger,
                // so the response is `status: "pending"` carrying the full
                // transaction hash: the hash is computed from the envelope
                // before the send, so it is always populated, and it is what
                // `stellar_transaction_status` reconciles against.
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
                let envelope = stellar_agent_core::envelope::Envelope::ok(response);
                let json_str = envelope
                    .to_json_pretty()
                    .unwrap_or_else(|_| String::from("{}"));
                Ok(CallToolResult::success(vec![Content::text(json_str)]))
            }

            Err(stellar_agent_core::WalletError::Network(
                stellar_agent_core::error::NetworkError::MainnetWriteForbidden,
            )) => {
                // Mainnet-write guard — surface under the SAME canonical
                // `network.mainnet_write_forbidden` code the sign-only tools use
                // for the structural mainnet refusal (mirrors
                // `mainnet_signing_forbidden_result`), rather than a SEP-43
                // RpcError code. Same refusal class, one code across the sep43
                // family.
                Ok(crate::tools::common::business_error_result(
                    stellar_agent_core::error::NetworkError::MainnetWriteForbidden.code(),
                    stellar_agent_sep43::Sep43Error::MainnetSigningForbidden {
                        detail: crate::tools::common::mainnet_signing_refusal_detail(),
                    }
                    .to_string(),
                ))
            }

            Err(stellar_agent_core::WalletError::Network(
                stellar_agent_core::error::NetworkError::RpcUnreachable { .. },
            )) => {
                // URL is in the RpcUnreachable struct; strip it to prevent credential
                // or endpoint leak to the dapp caller.
                tracing::warn!("sep43_sign_and_submit: rpc_unreachable");
                let sep43_err = stellar_agent_sep43::Sep43Error::RpcError {
                    detail: "rpc_unreachable".to_owned(),
                };
                Ok(crate::tools::common::business_error_result(
                    sep43_err.wire_code(),
                    sep43_err.to_string(),
                ))
            }

            Err(stellar_agent_core::WalletError::Network(
                stellar_agent_core::error::NetworkError::RpcTimeout { .. },
            )) => {
                // RpcTimeout Display is `"RPC endpoint '{url}' timed out after
                // {timeout_secs}s"`.  URL is embedded in the Display string; strip
                // it to prevent endpoint leak to the dapp caller, mirroring the
                // RpcUnreachable arm above.
                tracing::warn!("sep43_sign_and_submit: rpc_timeout");
                let sep43_err = stellar_agent_sep43::Sep43Error::RpcError {
                    detail: "rpc_timeout".to_owned(),
                };
                Ok(crate::tools::common::business_error_result(
                    sep43_err.wire_code(),
                    sep43_err.to_string(),
                ))
            }

            Err(err) => Ok(submit_failure_result(&err, &signed_xdr)),
        }
    }
}

/// Reports a submit-path failure this tool did not answer with a status of its
/// own.
///
/// Three routes, in order:
///
/// - A refusal operator policy decided reports the criterion's own code, the
///   way this server reports the same decision made at the dispatch gate. A
///   dapp told the endpoint failed would re-submit against a cap that has
///   already refused it.
/// - A submission whose outcome only reconciliation can settle keeps its own
///   code and carries the transaction to reconcile. The tool records its
///   submissions like any other, so a dapp that re-submits the same sequence
///   after a timeout gets the hash it needs rather than a generic transport
///   failure.
/// - Everything else (XDR decode failure, on-chain FAILED, bad auth) maps to
///   the SEP-43 `RpcError` wire code. `AccountNotFound` carries a G-strkey and
///   is redacted by the shared formatter before crossing the dapp wire
///   boundary; the `RpcUnreachable` and `RpcTimeout` arms at the call site
///   strip the endpoint URL from their own `Display` before reaching here.
fn submit_failure_result(
    err: &stellar_agent_core::WalletError,
    signed_xdr: &str,
) -> CallToolResult {
    if let stellar_agent_core::WalletError::PolicyDenied { reason } = err {
        return crate::tools::common::policy_denial_error_result(reason.as_ref());
    }
    if matches!(
        err,
        stellar_agent_core::WalletError::Submission(
            stellar_agent_core::error::SubmissionError::TxAlreadySubmitted { .. }
                | stellar_agent_core::error::SubmissionError::HashMismatch { .. }
                | stellar_agent_core::error::SubmissionError::RecordUnavailable { .. }
        )
    ) {
        return crate::tools::submission_record::submission_error_result(err, signed_xdr);
    }
    tracing::warn!(
        error = %err,
        "sep43_sign_and_submit: submission failed",
    );
    let sep43_err = stellar_agent_sep43::Sep43Error::RpcError {
        detail: submission_failed_detail(err),
    };
    crate::tools::common::business_error_result(sep43_err.wire_code(), sep43_err.to_string())
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
    /// the normalised business-error envelope (`is_error = Some(true)`).
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

    /// The error code a tool result reports.
    fn result_code(result: &CallToolResult) -> String {
        let text = match &result.content[0].raw {
            rmcp::model::RawContent::Text(t) => t.text.clone(),
            other => panic!("expected text content; got {other:?}"),
        };
        let json: serde_json::Value = serde_json::from_str(&text).unwrap();
        json["error"]["code"].as_str().unwrap().to_owned()
    }

    /// A refusal operator policy decided keeps the criterion's own code here
    /// too: a dapp told the endpoint failed would rebuild and re-submit
    /// against a cap that has already refused it.
    #[test]
    fn a_policy_refusal_is_not_reported_as_an_rpc_error() {
        let err = WalletError::PolicyDenied {
            reason: Box::new(
                stellar_agent_core::policy::DenyReason::PerPeriodCapExceeded {
                    asset: "native".to_owned(),
                    window: "1d".to_owned(),
                    max_stroops: 1_000,
                    attempted_stroops: 600,
                    period_used_stroops: 600,
                },
            ),
        };
        assert_eq!(
            result_code(&submit_failure_result(&err, "AAAAAgAAAAA=")),
            "policy.deny.per_period_cap_exceeded"
        );
    }

    /// A submission whose outcome is unknown still keeps its own code.
    #[test]
    fn an_unresolved_submission_keeps_its_submission_code() {
        let err = WalletError::Submission(
            stellar_agent_core::error::SubmissionError::TxAlreadySubmitted {
                hash: "ab".repeat(32),
            },
        );
        assert_eq!(
            result_code(&submit_failure_result(&err, "AAAAAgAAAAA=")),
            "submission.tx_already_submitted"
        );
    }

    /// Every other submit failure still reports the SEP-43 RPC-error code.
    #[test]
    fn every_other_submit_failure_is_still_an_rpc_error() {
        let err =
            WalletError::Submission(stellar_agent_core::error::SubmissionError::TxMalformed {
                detail: "txINSUFFICIENT_FEE".to_owned(),
            });
        assert_eq!(
            result_code(&submit_failure_result(&err, "AAAAAgAAAAA=")),
            "sep43.rpc_error"
        );
    }
    use stellar_agent_core::policy::ToolDescriptor;
    use stellar_agent_core::policy::v1::{
        AccountIdentityView, AccountReservesView, CounterpartyCacheView, Sep10SessionView,
        Sep45SessionView,
    };
    use stellar_agent_core::policy::{
        ApprovalRequest, Decision, DenyReason, PolicyEngine, PolicyError,
    };
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

    struct DenyEngine;

    impl PolicyEngine for DenyEngine {
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
            Ok(Decision::Deny(DenyReason::NoMatchingRule))
        }
    }

    fn make_require_approval_server() -> crate::server::WalletServer {
        use std::sync::Arc;
        let profile = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
            .with_noop_engine()
            .build();
        // No audit chain key is seeded at this profile's coordinate: gate
        // verdicts (RequireApproval here) precede the audit pre-flight, so
        // this scenario must complete without one — the test's assertion on
        // the fail-closed approval error doubles as the ordering pin.
        let mut server = crate::server::WalletServer::new(profile)
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

    /// A policy denial precedes the audit pre-flight: with a denying engine
    /// AND an unminted audit chain key, the surfaced wire code is the policy
    /// denial — a denial signs and submits nothing and needs no audit setup, so
    /// it must never be masked by `audit.chain_key_unavailable`.
    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn policy_denial_precedes_the_audit_preflight() {
        use std::sync::Arc;
        stellar_agent_test_support::keyring_mock::install().ok();
        let profile = Profile::builder_testnet(
            "svc-s43sas-denyfirst",
            "acct-s43sas-denyfirst",
            "n-svc",
            "n-acct",
        )
        .with_noop_engine()
        .build();
        let mut server =
            crate::server::WalletServer::new(profile).expect("WalletServer::new in tests");
        server.policy_engine = Arc::new(DenyEngine);
        let args = Sep43SignAndSubmitTransactionArgs {
            chain_id: "stellar:testnet".to_owned(),
            transaction_xdr: "AAAAAQAA".to_owned(),
            network_passphrase: None,
            address: None,
        };
        let result = server
            .call_stellar_sep43_sign_and_submit_transaction(args)
            .await
            .expect("denial must be a business envelope, not a protocol error");
        let (code, _message, text) = crate::tools::common::assert_business_envelope(&result);
        assert_eq!(code, "policy.deny.no_matching_rule");
        assert!(
            !text.contains("signedTxXdr"),
            "no signature may be produced on a policy denial; got: {text}"
        );
    }
}
