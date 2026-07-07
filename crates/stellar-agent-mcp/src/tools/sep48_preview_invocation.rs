//! `stellar_sep48_preview_invocation` MCP tool — SEP-48 typed-arg preview.
//!
//! Given a base64 `TransactionEnvelope` or a direct `(contract_id, function)`
//! pair, fetches the on-chain SEP-48 spec for the target contract and renders
//! typed argument names and JSON values.
//!
//! # SEP-48 reference
//!
//! `sep-0048.md`: "Contract Interface Specification" — the `contractspecv0`
//! WASM custom section carries `SCSpecEntry` XDR entries describing each
//! exported function's parameter names and types.

use rmcp::{
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Content},
    schemars, serde, tool, tool_router,
};
use serde_json::json;
use stellar_agent_mcp_macros::mcp_tool_router;

use stellar_agent_sep48::{decode_invoke_host_function, fetch_contract_spec, render_typed_args};

use crate::server::WalletServer;

// ─────────────────────────────────────────────────────────────────────────────
// Argument type
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for the `stellar_sep48_preview_invocation` MCP tool.
///
/// # Input shape
///
/// Two modes:
///
/// **Mode A** — supply a base64 `transaction_xdr` containing an
/// `InvokeHostFunction`/`InvokeContract` operation.  The tool decodes the XDR
/// to extract `(contract_id, function_name, args)` automatically.
///
/// **Mode B** — supply `contract_id` + `function` directly.  Useful when the
/// caller knows the invocation parameters but does not have an encoded
/// `TransactionEnvelope`.
///
/// At least one of `transaction_xdr` or `contract_id` + `function` MUST be
/// provided.  If both are provided, `transaction_xdr` takes precedence.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(crate = "rmcp::serde")]
pub struct Sep48PreviewInvocationArgs {
    /// Base64-encoded `TransactionEnvelope` XDR containing an
    /// `InvokeHostFunction`/`InvokeContract` operation.
    ///
    /// When present, the contract address, function name, and arguments are
    /// decoded automatically from the XDR.
    #[serde(default)]
    pub transaction_xdr: Option<String>,

    /// The C-strkey of the contract to preview (Mode B, used when
    /// `transaction_xdr` is absent).
    #[serde(default)]
    pub contract_id: Option<String>,

    /// The name of the contract function to preview (Mode B).
    #[serde(default)]
    pub function: Option<String>,

    /// CAIP-2 chain identifier (e.g. `"stellar:testnet"`).
    ///
    /// Required to resolve the active RPC endpoint from the profile.
    pub chain_id: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool router impl block
// ─────────────────────────────────────────────────────────────────────────────

/// Returns a typed JSON preview of a contract function invocation by fetching
/// the on-chain SEP-48 spec and mapping each positional `ScVal` argument to its
/// declared parameter name and type.
///
/// # Tool annotations
///
/// - `readOnlyHint = true` — fetches spec from chain; does NOT sign or submit.
/// - `destructiveHint = false` — safe to call without user confirmation.
///
/// # SEP-48 reference
///
/// `sep-0048.md` — "Contract Interface Specification".
///
/// # Errors
///
/// Returns a tool-level error when:
/// - Neither `transaction_xdr` nor (`contract_id` + `function`) are supplied.
/// - XDR decoding fails.
/// - The RPC is unreachable.
/// - The contract has no SEP-48 spec section.
/// - The requested function is absent from the spec.
///
/// # Examples
///
/// ```json
/// {
///   "transaction_xdr": "AAAAAgAAAAA...",
///   "chain_id": "stellar:testnet"
/// }
/// ```
#[mcp_tool_router]
#[tool_router(router = sep48_preview_invocation_tool_router, vis = "pub(crate)")]
impl WalletServer {
    #[mcp_tool_item(
        name = "stellar_sep48_preview_invocation",
        destructive_hint = false,
        read_only_hint = true,
        chain_id_required = true
    )]
    #[tool(
        name = "stellar_sep48_preview_invocation",
        description = "Returns a typed JSON preview of a Soroban contract function invocation \
                       by fetching the on-chain SEP-48 spec. Supply either transaction_xdr \
                       (base64 TransactionEnvelope) or (contract_id + function). \
                       read_only_hint=true; destructive_hint=false.",
        annotations(read_only_hint = true, destructive_hint = false)
    )]
    async fn stellar_sep48_preview_invocation(
        &self,
        Parameters(args): Parameters<Sep48PreviewInvocationArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        // Validate chain_id via dispatch_gate.
        let args_value = json!({ "chain_id": args.chain_id });
        // Read-only tool: RequireApproval produces no signing material; proceed.
        if let Err(e) = self
            .dispatch_gate(
                "stellar_sep48_preview_invocation",
                &args_value,
                &args.chain_id,
            )
            .await
        {
            return e.into_result();
        }

        // Resolve the RPC URL from the active profile.
        let rpc_url = self.profile.rpc_url.as_str();

        // ── Decode invocation (Mode A: from XDR; Mode B: from explicit fields) ──
        let (contract_strkey, function_name, arg_vals) = if let Some(xdr) = &args.transaction_xdr {
            match decode_invoke_host_function(xdr) {
                Ok(decoded) => (decoded.contract_strkey, decoded.function_name, decoded.args),
                Err(e) => {
                    return Ok(crate::tools::common::business_error_result(
                        "sep48.invoke_decode_failed",
                        e.to_string(),
                    ));
                }
            }
        } else {
            match (&args.contract_id, &args.function) {
                (Some(cid), Some(func)) => (cid.clone(), func.clone(), vec![]),
                _ => {
                    return Ok(crate::tools::common::business_error_result(
                        "sep48.missing_required_args",
                        "either transaction_xdr or (contract_id + function) must be provided",
                    ));
                }
            }
        };

        // ── Fetch spec ─────────────────────────────────────────────────────────
        let entries = match fetch_contract_spec(rpc_url, &contract_strkey).await {
            Ok(e) => e,
            Err(e) => {
                return Ok(crate::tools::common::business_error_result(
                    "sep48.spec_fetch_failed",
                    e.to_string(),
                ));
            }
        };

        // ── Render typed args ──────────────────────────────────────────────────
        match render_typed_args(&entries, &contract_strkey, &function_name, &arg_vals) {
            Ok(preview) => {
                let json_str =
                    serde_json::to_string_pretty(&preview).unwrap_or_else(|_| "{}".to_owned());
                Ok(CallToolResult::success(vec![Content::text(json_str)]))
            }
            Err(e) => Ok(crate::tools::common::business_error_result(
                "sep48.render_failed",
                e.to_string(),
            )),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Toolset-dispatch helper
// ─────────────────────────────────────────────────────────────────────────────

impl WalletServer {
    /// Invoke `stellar_sep48_preview_invocation` by value, bypassing the rmcp transport.
    ///
    /// Used by the toolset-invocation routing path (`tools/toolsets.rs`).
    ///
    /// # Errors
    ///
    /// Same as [`WalletServer::stellar_sep48_preview_invocation`].
    pub(crate) async fn invoke_stellar_sep48_preview_invocation(
        &self,
        args: Sep48PreviewInvocationArgs,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.stellar_sep48_preview_invocation(Parameters(args))
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
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;
    use stellar_agent_core::profile::schema::Profile;

    fn make_testnet_server() -> crate::server::WalletServer {
        crate::server::WalletServer::new(
            Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
                .with_noop_engine()
                .build(),
        )
        .expect("WalletServer::new must not fail in tests")
    }

    /// Neither `transaction_xdr` nor `contract_id` + `function` supplied: the
    /// tool refuses through the normalised business-error envelope carrying wire
    /// code `sep48.missing_required_args` (never the legacy `{error, code}`
    /// top-level shape).
    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn missing_required_args_returns_business_envelope() {
        let server = make_testnet_server();
        let args = Sep48PreviewInvocationArgs {
            transaction_xdr: None,
            contract_id: None,
            function: None,
            chain_id: "stellar:testnet".to_owned(),
        };
        let result = server
            .invoke_stellar_sep48_preview_invocation(args)
            .await
            .expect("missing-args refusal is surfaced as Ok(is_error) envelope");
        let (code, _message, _text) = crate::tools::common::assert_business_envelope(&result);
        assert_eq!(code, "sep48.missing_required_args");
    }

    /// A malformed `transaction_xdr` fails invocation decode before any RPC call:
    /// business-error envelope with wire code `sep48.invoke_decode_failed`.
    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn malformed_transaction_xdr_returns_invoke_decode_failed() {
        let server = make_testnet_server();
        let args = Sep48PreviewInvocationArgs {
            transaction_xdr: Some("!!! not valid xdr !!!".to_owned()),
            contract_id: None,
            function: None,
            chain_id: "stellar:testnet".to_owned(),
        };
        let result = server
            .invoke_stellar_sep48_preview_invocation(args)
            .await
            .expect("decode failure is surfaced as Ok(is_error) envelope");
        let (code, _message, _text) = crate::tools::common::assert_business_envelope(&result);
        assert_eq!(code, "sep48.invoke_decode_failed");
    }
}
