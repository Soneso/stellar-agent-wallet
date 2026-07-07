//! `stellar_fee_stats` MCP tool: fetches Stellar RPC fee statistics.

use rmcp::{
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Content},
    schemars, serde, tool, tool_router,
};
use serde_json::json;
use stellar_agent_mcp_macros::mcp_tool_router;

use crate::server::WalletServer;
use crate::tools::common::redact_rpc_error_detail;
use stellar_agent_network::{StellarRpcClient, fetch_fee_stats};

/// Arguments for the `stellar_fee_stats` MCP tool.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(crate = "rmcp::serde")]
pub struct StellarFeeStatsArgs {
    /// CAIP-2 chain identifier: `stellar:testnet` or `stellar:mainnet`.
    pub chain_id: String,

    /// Optional allow-listed Stellar RPC URL override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rpc_url: Option<String>,
}

#[mcp_tool_router]
#[tool_router(router = fee_stats_tool_router, vis = "pub(crate)")]
impl WalletServer {
    /// Fetches Stellar RPC `getFeeStats`.
    #[mcp_tool_item(
        name = "stellar_fee_stats",
        destructive_hint = false,
        read_only_hint = true,
        chain_id_required = true
    )]
    #[tool(
        name = "stellar_fee_stats",
        description = "Fetch Stellar RPC getFeeStats. Returns classic inclusion_fee and \
                       soroban_inclusion_fee percentile distributions. read_only_hint=true; \
                       destructive_hint=false.",
        annotations(read_only_hint = true, destructive_hint = false)
    )]
    async fn stellar_fee_stats(
        &self,
        Parameters(args): Parameters<StellarFeeStatsArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let args_value = json!({
            "chain_id": &args.chain_id,
            "rpc_url_override": args.rpc_url.is_some(),
        });
        // Read-only tool: RequireApproval produces no signing material; proceed.
        if let Err(e) = self
            .dispatch_gate("stellar_fee_stats", &args_value, &args.chain_id)
            .await
        {
            return e.into_result();
        }

        let rpc_url = match args.rpc_url.as_deref() {
            Some(url) => {
                validate_rpc_url_for_mcp(url)?;
                url
            }
            None => self.profile.rpc_url.as_str(),
        };

        let client = StellarRpcClient::new(rpc_url).map_err(|err| {
            rmcp::ErrorData::internal_error(redact_rpc_error_detail("rpc_client_error", &err), None)
        })?;

        match fetch_fee_stats(&client).await {
            Ok(view) => {
                let envelope = stellar_agent_core::envelope::Envelope::ok(view);
                let json = envelope
                    .to_json_pretty()
                    .unwrap_or_else(|_| String::from("{}"));
                Ok(CallToolResult::success(vec![Content::text(json)]))
            }
            Err(err) => {
                let wallet_err = stellar_agent_core::WalletError::Network(err);
                let envelope = stellar_agent_core::envelope::Envelope::<()>::err(&wallet_err);
                let json = envelope
                    .to_json_pretty()
                    .unwrap_or_else(|_| String::from("{}"));
                let mut result = CallToolResult::success(vec![Content::text(json)]);
                result.is_error = Some(true);
                Ok(result)
            }
        }
    }
}

#[cfg(any(test, feature = "test-helpers"))]
impl WalletServer {
    /// Calls `stellar_fee_stats` directly for integration tests.
    #[doc(hidden)]
    pub async fn call_stellar_fee_stats(
        &self,
        args: StellarFeeStatsArgs,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.stellar_fee_stats(Parameters(args)).await
    }
}

fn validate_rpc_url_for_mcp(url: &str) -> Result<(), rmcp::ErrorData> {
    stellar_agent_network::validate_rpc_url(url)
        .map_err(|err| rmcp::ErrorData::invalid_params(format!("invalid rpc_url: {err}"), None))
}
