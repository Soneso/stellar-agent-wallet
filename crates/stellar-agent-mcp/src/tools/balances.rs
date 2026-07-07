//! `stellar_balances` MCP tool: fetches native XLM balance and trustlines.
//!
//! Contains the argument type, the `#[tool_router]` impl block for the
//! `balances_tool_router`, and the test-helper for integration tests.

use rmcp::{
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Content},
    schemars, serde, tool, tool_router,
};
use serde_json::json;
use stellar_agent_mcp_macros::mcp_tool_router;

use crate::server::WalletServer;
use crate::tools::common::{redact_rpc_error_detail, redacted_wallet_error_envelope};
use stellar_agent_network::{Asset, fetch_account};

// ─────────────────────────────────────────────────────────────────────────────
// Argument types
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum number of trustline assets that can be queried in a single
/// `stellar_balances` call.
///
/// Conservative cap chosen as half the typical `getLedgerEntries` per-call key
/// budget.  Stellar RPC servers vary: `protocols.stellar.org/api/methods/getLedgerEntries`
/// describes the limit, and large nodes typically allow ≥200 keys per call, but
/// the exact limit is server-policy.  This cap reserves headroom for the
/// account key, future per-call additions, and an operator safety margin.
///
/// Requests exceeding this limit are rejected with `invalid_params` before
/// any network call is made.
pub const MAX_TRUSTLINE_ASSETS_PER_CALL: usize = 100;

/// A non-native asset to query a trustline for.
///
/// Fields must pass validation before the network call:
/// - `code` must be 1-12 ASCII alphanumeric characters.  The `:` character
///   is not allowed (it is the `CODE:ISSUER` separator in Stellar asset notation).
/// - `issuer` must be a valid G-strkey (ed25519 public key).
///
/// Invalid inputs return `invalid_params` before any network call is made.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(crate = "rmcp::serde")]
pub struct TrustlineAssetArg {
    /// Asset code: 1-12 ASCII alphanumeric characters (e.g. `"USDC"`).
    ///
    /// Must not contain `:` (the character is the `CODE:ISSUER` separator).
    pub code: String,
    /// Issuer G-strkey (ed25519 public key, 56 characters).
    ///
    /// Example: `"GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"`
    pub issuer: String,
}

/// Arguments for the `stellar_balances` MCP tool.
///
/// # Schema
///
/// The `chain_id` field is a CAIP-2 chain identifier (`stellar:testnet` or
/// `stellar:mainnet`).  The wallet resolves it against the loaded profile to
/// obtain the RPC URL and network passphrase.
///
/// The `account_id` field is a Stellar G-strkey (ed25519 public key, 56 chars).
///
/// The optional `assets` field lists non-native assets to query trustlines for.
/// When absent or empty, only the native XLM balance is returned.  When present,
/// each entry is validated (code 1-12 alphanumeric, issuer G-strkey) before the
/// network call; assets the account does not currently trust are omitted from the
/// response.
///
/// # Example
///
/// ```json
/// {
///   "chain_id": "stellar:testnet",
///   "account_id": "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN",
///   "assets": [
///     { "code": "USDC", "issuer": "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN" }
///   ]
/// }
/// ```
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(crate = "rmcp::serde")]
pub struct StellarBalancesArgs {
    /// CAIP-2 chain identifier: `stellar:testnet` or `stellar:mainnet`.
    ///
    /// Resolved against the loaded profile to determine the RPC endpoint.
    pub chain_id: String,

    /// Stellar account G-strkey (ed25519 public key, 56 characters).
    ///
    /// Example: `GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN`
    pub account_id: String,

    /// Optional list of non-native assets to query trustlines for.
    ///
    /// Each entry is `{ code: "USDC", issuer: "GA5Z..." }`.  Empty or absent
    /// returns native XLM only.  Invalid entries return `invalid_params`
    /// before any network call.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assets: Vec<TrustlineAssetArg>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool router impl block
// ─────────────────────────────────────────────────────────────────────────────

// Attribute order: #[tool_router] is innermost (listed last) and runs FIRST.
// #[mcp_tool_router] is outermost (listed first) and runs SECOND.
// `router = balances_tool_router` names the generated method so it can be
// merged into the master router in `WalletServer::new`.
#[mcp_tool_router]
#[tool_router(router = balances_tool_router, vis = "pub(crate)")]
impl WalletServer {
    /// Fetches the native XLM balance and trustlines for a Stellar account.
    ///
    /// Returns the same JSON envelope as `stellar-agent balances <G>`.
    ///
    /// # Tool annotations
    ///
    /// - `readOnlyHint = true` — does not modify chain state.
    /// - `destructiveHint = false` — safe to call without user confirmation.
    ///
    /// # Trustline enumeration
    ///
    /// The optional `assets` argument lists non-native assets to query trustlines
    /// for alongside the native XLM balance.  Each asset is validated (code 1-12
    /// alphanumeric, issuer G-strkey) before the network call; assets the account
    /// does not trust are omitted from the response.  When `assets` is absent or
    /// empty, only the native XLM balance is returned.
    ///
    /// All keys (1 account + N trustlines) are fetched in a single batched
    /// `getLedgerEntries` RPC call.
    ///
    /// # CAIP-2 validation
    ///
    /// The `chain_id` argument is parsed and validated against the loaded
    /// profile's `chain_id` field via
    /// [`stellar_agent_core::profile::caip2::validate_chain_id_matches_profile`].
    /// A mismatch returns `invalid_params` before any network call is made.
    ///
    /// # Errors
    ///
    /// Returns a tool-level error (not a JSON-RPC error) when:
    /// - `account_id` is not a valid G-strkey.
    /// - An entry in `assets` has an invalid code or issuer.
    /// - The RPC call fails (network error, account not found).
    /// - The policy engine denies the call (not currently possible for a
    ///   read-only tool, but the call site is maintained for parity with the
    ///   signing tools).
    ///
    /// # Examples
    ///
    /// Native XLM only:
    ///
    /// ```json
    /// {
    ///   "chain_id": "stellar:testnet",
    ///   "account_id": "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN"
    /// }
    /// ```
    ///
    /// With trustline:
    ///
    /// ```json
    /// {
    ///   "chain_id": "stellar:testnet",
    ///   "account_id": "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN",
    ///   "assets": [
    ///     { "code": "USDC", "issuer": "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN" }
    ///   ]
    /// }
    /// ```
    #[mcp_tool_item(
        name = "stellar_balances",
        destructive_hint = false,
        read_only_hint = true,
        chain_id_required = true
    )]
    #[tool(
        name = "stellar_balances",
        description = "Fetch the native XLM balance and trustlines for a Stellar account. \
                       Optional `assets` array specifies non-native trustlines to include. \
                       Returns the same JSON envelope as `stellar-agent balances <G>`. \
                       read_only_hint=true; destructive_hint=false.",
        annotations(read_only_hint = true, destructive_hint = false)
    )]
    async fn stellar_balances(
        &self,
        Parameters(args): Parameters<StellarBalancesArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        // ── Dispatch gate ─────────────────────────────────────────────────────
        // Called unconditionally on every tools/call.  The descriptor is sourced
        // from the registry built at WalletServer::new from the #[mcp_tool_item]
        // attribute — single source of truth.
        // If the tool is not in the registry (authoring error), fail closed.
        let args_value = json!({
            "chain_id": &args.chain_id,
            "account_id": &args.account_id,
            "assets_count": args.assets.len(),
        });
        // Read-only tool: RequireApproval produces no signing material; proceed
        // regardless of verdict (only Deny and engine errors are fail-closed via ?).
        if let Err(e) = self
            .dispatch_gate("stellar_balances", &args_value, &args.chain_id)
            .await
        {
            return e.into_result();
        }

        // ── Validate G-strkey (strict G-only ed25519 public key) ────────────
        // Uses ed25519::PublicKey::from_string (not the permissive Strkey::from_string
        // which accepts S/M/C strkeys) so only G-strkeys are accepted.
        if let Err(err) = stellar_strkey::ed25519::PublicKey::from_string(&args.account_id) {
            return Err(rmcp::ErrorData::invalid_params(
                format!("invalid account_id (expected G-strkey): {err}"),
                None,
            ));
        }

        // ── DoS guard: asset count cap ───────────────────────────────────────
        // Stellar RPC getLedgerEntries max is 200 entries; we reserve headroom
        // for the account key + safety buffer.  Reject before any allocation.
        if args.assets.len() > MAX_TRUSTLINE_ASSETS_PER_CALL {
            return Err(rmcp::ErrorData::invalid_params(
                format!(
                    "too many trustline assets requested: {}; maximum is {}",
                    args.assets.len(),
                    MAX_TRUSTLINE_ASSETS_PER_CALL
                ),
                None,
            ));
        }

        // ── Validate and convert trustline assets ────────────────────────────
        // Trust boundary: code + issuer validated via Asset::from_code_and_issuer
        // BEFORE network call.  Error messages do not echo asset code or issuer
        // back into the error string (error variant carries the input internally
        // but WalletError::code() is what flows to the client).
        let mut trustline_assets: Vec<Asset> = Vec::with_capacity(args.assets.len());
        for arg in &args.assets {
            match Asset::from_code_and_issuer(&arg.code, &arg.issuer) {
                Ok(a) => trustline_assets.push(a),
                Err(err) => {
                    return Err(rmcp::ErrorData::invalid_params(
                        format!("invalid trustline asset: {}", err.code()),
                        None,
                    ));
                }
            }
        }

        // ── Resolve RPC URL from profile ─────────────────────────────────────
        // The profile's rpc_url takes precedence over the chain_id argument's
        // default RPC.  The chain_id was validated above.
        let rpc_url = self.profile.rpc_url.as_str();

        // ── Fetch account state ──────────────────────────────────────────────
        let client = match stellar_agent_network::StellarRpcClient::new(rpc_url) {
            Ok(c) => c,
            Err(err) => {
                return Err(rmcp::ErrorData::internal_error(
                    redact_rpc_error_detail("rpc_client_error", &err),
                    None,
                ));
            }
        };

        match fetch_account(&client, &args.account_id, &trustline_assets).await {
            Ok(view) => {
                let envelope = stellar_agent_core::envelope::Envelope::ok(view);
                let json = envelope
                    .to_json_pretty()
                    .unwrap_or_else(|_| String::from("{}"));
                Ok(CallToolResult::success(vec![Content::text(json)]))
            }
            Err(err) => {
                let envelope = redacted_wallet_error_envelope(&err);
                let json = envelope
                    .to_json_pretty()
                    .unwrap_or_else(|_| String::from("{}"));
                // Tool-level error: is_error = true but JSON-RPC level succeeds.
                let mut result = CallToolResult::success(vec![Content::text(json)]);
                result.is_error = Some(true);
                Ok(result)
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Toolset-dispatch helper
// ─────────────────────────────────────────────────────────────────────────────

impl WalletServer {
    /// Invoke `stellar_balances` by value, bypassing the rmcp transport layer.
    ///
    /// Used by the toolset-invocation routing path (`tools/toolsets.rs`) to call
    /// this handler with deserialized args from `stellar_toolset_invoke`.
    /// This is the production dispatch path, not a test helper.
    ///
    /// # Errors
    ///
    /// Same as `WalletServer::stellar_balances`.
    pub(crate) async fn invoke_stellar_balances(
        &self,
        args: StellarBalancesArgs,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.stellar_balances(Parameters(args)).await
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test helpers
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(any(test, feature = "test-helpers"))]
impl WalletServer {
    /// Calls `stellar_balances` with the given args, bypassing the rmcp transport.
    ///
    /// This method is the integration-test entry point for the cap guard and other
    /// handler-level checks.  It is equivalent to calling the handler via the MCP
    /// transport but without the stdio framing overhead.  It exposes the handler
    /// for cap-guard testing from integration test crates without requiring a full
    /// client-server transport setup.
    ///
    /// # Errors
    ///
    /// Returns the same `rmcp::ErrorData` as `WalletServer::stellar_balances`
    /// for invalid arguments, RPC failures, or handler-level tool errors.
    ///
    /// # Feature gate
    ///
    /// Gated on the `test-helpers` feature or `#[cfg(test)]`.
    pub async fn call_stellar_balances(
        &self,
        args: StellarBalancesArgs,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.stellar_balances(Parameters(args)).await
    }
}
