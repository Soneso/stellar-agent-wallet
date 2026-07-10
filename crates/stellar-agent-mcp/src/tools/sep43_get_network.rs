//! `stellar_sep43_get_network` MCP tool — SEP-43 `getNetwork`.
//!
//! Returns the active network name and passphrase from the loaded profile.
//! Per `sep-0043.md` lines :101-104.

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

/// Arguments for the `stellar_sep43_get_network` MCP tool.
///
/// # Schema
///
/// - `chain_id` — Optional CAIP-2 chain identifier.  If `None`, defaults to
///   the active profile's chain (CAIP-2 derived from `network_passphrase`).
///   If `Some`, validated against the profile per the existing `dispatch_gate`
///   logic.
///
/// The Optional shape supports SEP-43 spec `getNetwork`'s chain-agnostic
/// semantics (`sep-0043.md:101-104`) while preserving chain-ID validation for
/// callers that explicitly supply a chain hint.  Mirrors the empty-args
/// handling in `sep43_get_address`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(crate = "rmcp::serde")]
pub struct Sep43GetNetworkArgs {
    /// CAIP-2 chain identifier (e.g. `"stellar:testnet"`).
    ///
    /// Optional per SEP-43 `getNetwork` chain-agnostic semantics
    /// (`sep-0043.md:101-104`).  When `None`, the active profile's chain is
    /// used.  When `Some`, must match the chain configured in the active
    /// profile.
    #[serde(default)]
    pub chain_id: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool router impl block
// ─────────────────────────────────────────────────────────────────────────────

/// Returns `{ "network": "...", "networkPassphrase": "..." }` from the
/// active profile configuration.
///
/// # Tool annotations
///
/// - `readOnlyHint = true` — does not modify chain state.
/// - `destructiveHint = false` — safe to call without user confirmation.
///
/// # SEP-43 reference
///
/// `sep-0043.md` lines :101-104 — `getNetwork()`.
///
/// # Errors
///
/// Returns a tool-level error when `chain_id` is `Some` and does not match the
/// active profile.
///
/// # Examples
///
/// ```json
/// {}
/// ```
///
/// ```json
/// { "chain_id": "stellar:testnet" }
/// ```
#[mcp_tool_router]
#[tool_router(router = sep43_get_network_tool_router, vis = "pub(crate)")]
impl WalletServer {
    #[mcp_tool_item(
        name = "stellar_sep43_get_network",
        destructive_hint = false,
        read_only_hint = true,
        chain_id_required = true
    )]
    #[tool(
        name = "stellar_sep43_get_network",
        description = "Returns the active network name and passphrase (SEP-43 getNetwork). \
                       Returns { network: string, networkPassphrase: string }. \
                       read_only_hint=true; destructive_hint=false.",
        annotations(read_only_hint = true, destructive_hint = false)
    )]
    async fn stellar_sep43_get_network(
        &self,
        Parameters(args): Parameters<Sep43GetNetworkArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        // Resolve the effective chain_id: caller-supplied (Some) or profile default (None).
        // SEP-43 `getNetwork` is chain-agnostic per `sep-0043.md:101-104`; callers may omit
        // `chain_id` entirely.  When omitted, fall back to the profile's CAIP-2 chain so
        // `dispatch_gate`'s chain-ID validation step always receives a non-empty string.
        // Mirrors the empty-args handling in sep43_get_address.
        let profile_chain = self.profile.chain_id.caip2_str();
        let effective_chain: &str = args.chain_id.as_deref().unwrap_or(profile_chain);
        let args_value = json!({ "chain_id": effective_chain });
        // Read-only tool: RequireApproval produces no signing material; proceed.
        if let Err(e) = self
            .dispatch_gate("stellar_sep43_get_network", &args_value, effective_chain)
            .await
        {
            return e.into_result();
        }

        use std::sync::Arc;
        use stellar_agent_sep43::StellarAgentModule;
        use stellar_agent_sep43::module::ModuleAdapter;

        let profile = Arc::clone(&self.profile);
        let dummy_key =
            Arc::new(stellar_agent_network::signing::SoftwareSigningKey::new_from_bytes([0u8; 32]));
        let module = StellarAgentModule::new(profile, dummy_key);

        match module.get_network().await {
            Ok(value) => {
                let envelope = stellar_agent_core::envelope::Envelope::ok(value);
                let json_str = envelope
                    .to_json_pretty()
                    .unwrap_or_else(|_| String::from("{}"));
                Ok(CallToolResult::success(vec![Content::text(json_str)]))
            }
            Err(err) => Ok(crate::tools::common::business_error_result(
                err.wire_code(),
                err.to_string(),
            )),
        }
    }
}
