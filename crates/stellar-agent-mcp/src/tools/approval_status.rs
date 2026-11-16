//! Non-consuming approval status for the active profile.

use rmcp::{
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Content},
    schemars, serde, tool, tool_router,
};
use stellar_agent_core::{
    envelope::Envelope,
    error::{WalletError, WalletStateError},
};
use stellar_agent_mcp_macros::mcp_tool_router;
use stellar_agent_network::policy_state::approvals::status::{
    ApprovalStatusSnapshot, status_read_error,
};

use super::common::business_error_result;
use crate::server::WalletServer;

/// Selects the existing public approval nonce in the active profile.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(crate = "rmcp::serde", deny_unknown_fields)]
pub struct ApprovalStatusArgs {
    /// The approval nonce returned during preparation.
    pub approval_id: String,
}

#[mcp_tool_router]
#[tool_router(router = approval_status_tool_router, vis = "pub(crate)")]
impl WalletServer {
    /// Inspects retained consent without consuming it or granting reuse.
    #[mcp_tool_item(
        name = "stellar_approval_status",
        destructive_hint = false,
        read_only_hint = true,
        chain_id_required = false,
        value_kind = "read_only"
    )]
    #[tool(
        name = "stellar_approval_status",
        description = "Inspect an approval by its public nonce in the active profile. Returns retained state and consent verification without consuming approval or granting signing or retry authority.",
        annotations(read_only_hint = true, destructive_hint = false)
    )]
    async fn stellar_approval_status(
        &self,
        Parameters(args): Parameters<ApprovalStatusArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let now = match self.clock.now_unix_ms() {
            Ok(now) => now,
            Err(error) => {
                let error = WalletError::WalletState(WalletStateError::clock_error(&error));
                return Ok(business_error_result(error.code(), error.to_string()));
            }
        };
        let name = self.profile_name_for_approval();
        let snapshot =
            ApprovalStatusSnapshot::read(&self.window_store, self.security_profile(), &name, now);
        let args_value = serde_json::json!({"approval_id": args.approval_id});
        if let Err(error) = self
            .dispatch_approval_status(&args_value, &snapshot, now)
            .await
        {
            return error.into_result();
        }
        let view = snapshot
            .map_err(|error| status_read_error(&error))
            .and_then(|snapshot| {
                let dir = self.resolve_approval_dir().map_err(|_| {
                    stellar_agent_core::error::ApprovalFailure::StoreDirError {
                        detail: "could not determine approval store directory".to_owned(),
                    }
                })?;
                snapshot.inspect(&args.approval_id, &dir.join(format!("{name}.toml")))
            });
        match view {
            Ok(view) => {
                let json = Envelope::ok(view).to_json_pretty().map_err(|_| {
                    rmcp::ErrorData::internal_error("approval status serialization failed", None)
                })?;
                Ok(CallToolResult::success(vec![Content::text(json)]))
            }
            Err(error) => Ok(business_error_result(error.code(), error.to_string())),
        }
    }
}

#[cfg(any(test, feature = "test-helpers"))]
impl WalletServer {
    /// Calls the production status handler with isolated test state.
    ///
    /// # Errors
    /// Returns the handler's protocol or serialization failure.
    pub async fn approval_status_for_test(
        &self,
        approval_id: String,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.stellar_approval_status(Parameters(ApprovalStatusArgs { approval_id }))
            .await
    }
}

#[cfg(test)]
mod tests;
