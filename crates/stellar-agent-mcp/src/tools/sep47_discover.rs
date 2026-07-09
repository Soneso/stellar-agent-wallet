//! `stellar_sep47_discover` MCP tool — SEP-47 Contract Interface Discovery.
//!
//! Returns the list of SEPs a contract claims to implement by reading the
//! SEP-46 `Contract Meta` `sep` entry from the WASM's `contractmetav0` custom
//! section.
//!
//! # SEP-47 reference
//!
//! `sep-0047.md` — "Contract Interface Discovery".  The `sep` meta entry value
//! is a comma-separated list of SEP identifiers with leading zeros stripped
//! (e.g. `"41,40"`).

use rmcp::{
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Content},
    schemars, serde, tool, tool_router,
};
use serde_json::json;
use stellar_agent_mcp_macros::mcp_tool_router;

use stellar_agent_sep48::discover_claimed_seps;

use crate::server::WalletServer;

// ─────────────────────────────────────────────────────────────────────────────
// Argument type
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for the `stellar_sep47_discover` MCP tool.
///
/// # Schema
///
/// - `contract_id` — C-strkey of the contract to inspect.
/// - `chain_id` — CAIP-2 chain identifier used to resolve the RPC endpoint.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(crate = "rmcp::serde")]
pub struct Sep47DiscoverArgs {
    /// The C-strkey of the contract to inspect (e.g.
    /// `"CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA"`).
    pub contract_id: String,

    /// CAIP-2 chain identifier (e.g. `"stellar:testnet"`).
    ///
    /// Used to resolve the active RPC endpoint from the profile.
    pub chain_id: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool router impl block
// ─────────────────────────────────────────────────────────────────────────────

/// Returns `{ "supported_seps": [...] }` — the list of SEPs the contract claims
/// to implement per the SEP-47 `Contract Meta` `sep` entry.
///
/// # Tool annotations
///
/// - `readOnlyHint = true` — fetches WASM; does NOT sign or submit.
/// - `destructiveHint = false` — safe to call without user confirmation.
///
/// # SEP-47 reference
///
/// `sep-0047.md` — "Contract Interface Discovery".
///
/// # Errors
///
/// Returns a tool-level error when:
/// - `contract_id` is not a valid C-strkey.
/// - The RPC endpoint is unreachable.
/// - The WASM cannot be fetched.
///
/// Returns `{ "supported_seps": [] }` (not an error) when the contract has no
/// `contractmetav0` section or no `sep` meta entry.
///
/// # Examples
///
/// ```json
/// {
///   "contract_id": "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA",
///   "chain_id": "stellar:testnet"
/// }
/// ```
#[mcp_tool_router]
#[tool_router(router = sep47_discover_tool_router, vis = "pub(crate)")]
impl WalletServer {
    #[mcp_tool_item(
        name = "stellar_sep47_discover",
        destructive_hint = false,
        read_only_hint = true,
        chain_id_required = true
    )]
    #[tool(
        name = "stellar_sep47_discover",
        description = "Returns the SEPs a contract claims to implement per SEP-47 Contract \
                       Interface Discovery (reads the contractmetav0 'sep' meta entry). \
                       Returns { supported_seps: [\"41\", \"40\"] }. \
                       read_only_hint=true; destructive_hint=false.",
        annotations(read_only_hint = true, destructive_hint = false)
    )]
    async fn stellar_sep47_discover(
        &self,
        Parameters(args): Parameters<Sep47DiscoverArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        // Validate chain_id via dispatch_gate.
        let args_value = json!({ "chain_id": args.chain_id });
        // Read-only tool: RequireApproval produces no signing material; proceed.
        if let Err(e) = self
            .dispatch_gate("stellar_sep47_discover", &args_value, &args.chain_id)
            .await
        {
            return e.into_result();
        }

        // Resolve the RPC URL from the active profile.
        let rpc_url = self.profile.rpc_url.as_str();

        match discover_claimed_seps(rpc_url, &args.contract_id).await {
            Ok(seps) => {
                let resp = json!({ "supported_seps": seps });
                let json_str =
                    serde_json::to_string_pretty(&resp).unwrap_or_else(|_| "{}".to_owned());
                Ok(CallToolResult::success(vec![Content::text(json_str)]))
            }
            Err(e) => Ok(crate::tools::common::business_error_result(
                "sep47.discovery_failed",
                e.to_string(),
            )),
        }
    }
}

#[cfg(any(test, feature = "test-helpers"))]
impl WalletServer {
    /// Calls `stellar_sep47_discover` with the given args, bypassing the rmcp
    /// transport.
    ///
    /// Integration-test entry point for handler-level checks.
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Feature gate
    ///
    /// Gated on the `test-helpers` feature or `#[cfg(test)]`.
    #[doc(hidden)]
    pub async fn call_stellar_sep47_discover(
        &self,
        args: Sep47DiscoverArgs,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.stellar_sep47_discover(Parameters(args)).await
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Toolset-dispatch helper
// ─────────────────────────────────────────────────────────────────────────────

impl WalletServer {
    /// Invoke `stellar_sep47_discover` by value, bypassing the rmcp transport.
    ///
    /// Used by the toolset-invocation routing path (`tools/toolsets.rs`).
    ///
    /// # Errors
    ///
    /// Same as [`WalletServer::stellar_sep47_discover`].
    pub(crate) async fn invoke_stellar_sep47_discover(
        &self,
        args: Sep47DiscoverArgs,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.stellar_sep47_discover(Parameters(args)).await
    }
}
