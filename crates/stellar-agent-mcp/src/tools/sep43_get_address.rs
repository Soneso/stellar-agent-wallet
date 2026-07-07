//! `stellar_sep43_get_address` MCP tool — SEP-43 `getAddress`.
//!
//! Returns the active wallet address from the loaded profile.
//! Per `sep-0043.md` lines :57-61.

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

/// Arguments for the `stellar_sep43_get_address` MCP tool.
///
/// # Schema
///
/// - `chain_id` — Optional CAIP-2 chain identifier.  If `None`, defaults to
///   the active profile's chain (CAIP-2 derived from `network_passphrase`).
///   If `Some`, validated against the profile per the existing `dispatch_gate`
///   logic.
///
/// The Optional shape supports SEP-43 spec `getAddress`'s chain-agnostic
/// semantics (`sep-0043.md:57-61`) while preserving chain-ID validation for
/// callers that explicitly supply a chain hint.  The WalletConnect host passes
/// `{}` (no `chain_id`) per SEP-43 spec; `chain_id: Option<String>` allows rmcp
/// to deserialise that correctly.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(crate = "rmcp::serde")]
pub struct Sep43GetAddressArgs {
    /// CAIP-2 chain identifier (e.g. `"stellar:testnet"`).
    ///
    /// Optional per SEP-43 `getAddress` chain-agnostic semantics
    /// (`sep-0043.md:57-61`).  When `None`, the active profile's chain is
    /// used.  When `Some`, must match the chain configured in the active
    /// profile.
    #[serde(default)]
    pub chain_id: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool router impl block
// ─────────────────────────────────────────────────────────────────────────────

/// Returns `{ "address": "G..." }` for the active wallet from the loaded
/// profile. Read-only; does not access the keyring or sign anything.
///
/// # Tool annotations
///
/// - `readOnlyHint = true` — does not modify chain state.
/// - `destructiveHint = false` — safe to call without user confirmation.
///
/// # SEP-43 reference
///
/// `sep-0043.md` lines :57-61 — `getAddress({ path?, skipRequestAccess? })`.
///
/// # Errors
///
/// Returns a tool-level error (not a JSON-RPC error) when:
/// - `chain_id` is `Some` and does not match the active profile.
/// - The active profile has no enrolled address.
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
#[tool_router(router = sep43_get_address_tool_router, vis = "pub(crate)")]
impl WalletServer {
    #[mcp_tool_item(
        name = "stellar_sep43_get_address",
        destructive_hint = false,
        read_only_hint = true,
        chain_id_required = true
    )]
    #[tool(
        name = "stellar_sep43_get_address",
        description = "Returns the active wallet address (SEP-43 getAddress). \
                       Returns { address: string }. \
                       read_only_hint=true; destructive_hint=false.",
        annotations(read_only_hint = true, destructive_hint = false)
    )]
    async fn stellar_sep43_get_address(
        &self,
        Parameters(args): Parameters<Sep43GetAddressArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        // Resolve the effective chain_id: caller-supplied (Some) or profile default (None).
        // SEP-43 `getAddress` is chain-agnostic per `sep-0043.md:57-61`; callers may omit
        // `chain_id` entirely.  When omitted, fall back to the profile's CAIP-2 chain so
        // `dispatch_gate`'s chain-ID validation step always receives a non-empty string.
        // The WalletConnect host passes `{}` (no chain_id).
        let profile_chain = self.profile.chain_id.caip2_str();
        let effective_chain: &str = args.chain_id.as_deref().unwrap_or(profile_chain);
        let args_value = json!({ "chain_id": effective_chain });
        // Read-only tool: RequireApproval produces no signing material; proceed.
        if let Err(e) = self
            .dispatch_gate("stellar_sep43_get_address", &args_value, effective_chain)
            .await
        {
            return e.into_result();
        }

        use std::sync::Arc;
        use stellar_agent_sep43::StellarAgentModule;
        use stellar_agent_sep43::module::ModuleAdapter;

        // Construct an ephemeral module for address lookup (no signer needed
        // for getAddress — the getAddress path only reads profile fields).
        let profile = Arc::clone(&self.profile);

        // For getAddress we do not need a real signer — construct a no-op
        // software key. The getAddress path only reads profile fields.
        let dummy_key =
            Arc::new(stellar_agent_network::signing::SoftwareSigningKey::new_from_bytes([0u8; 32]));
        let module = StellarAgentModule::new(profile, dummy_key);

        match module.get_address().await {
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
