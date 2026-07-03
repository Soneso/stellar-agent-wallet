//! `stellar_friendbot` MCP tool: funds a testnet account via Friendbot.
//!
//! Contains the argument type and the `#[tool_router]` impl block for the
//! `friendbot_tool_router`.

use rmcp::{
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Content},
    schemars, serde, tool, tool_router,
};
use serde_json::json;
use stellar_agent_mcp_macros::mcp_tool_router;

use crate::server::WalletServer;
use stellar_agent_network::friendbot::{default_friendbot_url, validate_friendbot_url};

// ─────────────────────────────────────────────────────────────────────────────
// Argument type
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for the `stellar_friendbot` MCP tool.
///
/// # Schema
///
/// - `chain_id` — CAIP-2 chain identifier (`stellar:testnet`).  Mainnet is
///   rejected at the policy gate (destructive tool, mainnet profile →
///   `NoopPolicyEngine` returns `Err(NotImplemented)`).
/// - `account_id` — Stellar G-strkey (ed25519 public key, 56 chars).
/// - `friendbot_url` — optional override URL.  When supplied it is validated
///   against the allow-list in `stellar-agent-network::friendbot`.  When
///   omitted the profile's default Friendbot URL for the resolved chain is used.
///   The MCP tool exposes **no** `--friendbot-url-unchecked` escape; any
///   supplied URL is unconditionally validated against the allow-list.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(crate = "rmcp::serde")]
pub struct StellarFriendbotArgs {
    /// CAIP-2 chain identifier.
    ///
    /// Only `stellar:testnet` succeeds — mainnet profiles with a destructive
    /// tool return `policy.engine_required`.
    pub chain_id: String,

    /// Stellar account G-strkey (ed25519 public key, 56 characters).
    ///
    /// Example: `GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN`
    pub account_id: String,

    /// Optional override for the Friendbot endpoint URL.
    ///
    /// When `None`, the default URL for the resolved chain is used
    /// (`https://friendbot.stellar.org` for testnet).
    /// When `Some`, the URL is validated against the production allow-list
    /// (`ALLOWED_FRIENDBOT_HOSTS`).  Non-allowlisted URLs are rejected with
    /// `invalid_params`.
    pub friendbot_url: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool router impl block
// ─────────────────────────────────────────────────────────────────────────────

#[mcp_tool_router]
#[tool_router(router = friendbot_tool_router, vis = "pub(crate)")]
impl WalletServer {
    /// Funds a testnet account via the Stellar Friendbot HTTP endpoint.
    ///
    /// Returns the same JSON envelope as `stellar-agent friendbot --account <G>`.
    ///
    /// # Tool annotations
    ///
    /// - `readOnlyHint = false` — this tool creates on-chain state.
    /// - `destructiveHint = true` — mainnet profiles are rejected at the policy
    ///   gate (`NoopPolicyEngine` returns `Err(NotImplemented)` for destructive
    ///   tools on mainnet).
    ///
    /// # URL allow-listing
    ///
    /// When `friendbot_url` is `None`, the default Friendbot URL for the
    /// resolved chain is used (`https://friendbot.stellar.org` for testnet).
    /// When `Some`, the URL is validated against the production allow-list via
    /// [`validate_friendbot_url`].  Non-allowlisted URLs are rejected with
    /// `invalid_params`.  The MCP tool exposes **no** unchecked escape;
    /// every supplied URL is validated unconditionally.
    ///
    /// # CAIP-2 validation
    ///
    /// The `chain_id` argument is parsed and validated against the profile's
    /// `chain_id` field via
    /// [`stellar_agent_core::profile::caip2::validate_chain_id_matches_profile`].
    /// A mismatch returns `invalid_params`.
    ///
    /// # Errors
    ///
    /// Returns a tool-level error (not a JSON-RPC error) when:
    /// - The policy engine denies the call (mainnet + destructive →
    ///   `policy.engine_required`).
    /// - `chain_id` does not match the profile's configured chain.
    /// - `account_id` is not a valid G-strkey.
    /// - `friendbot_url` is not in the allow-list (when supplied).
    /// - The Friendbot HTTP call fails.
    ///
    /// # Examples
    ///
    /// Agent input JSON:
    ///
    /// ```json
    /// {
    ///   "chain_id": "stellar:testnet",
    ///   "account_id": "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN"
    /// }
    /// ```
    #[mcp_tool_item(
        name = "stellar_friendbot",
        destructive_hint = true,
        read_only_hint = false,
        chain_id_required = true
    )]
    #[tool(
        name = "stellar_friendbot",
        description = "Fund a testnet account via the Stellar Friendbot HTTP endpoint. \
                       Only available on testnet profiles — mainnet is rejected by the \
                       policy gate. Returns the same JSON envelope as \
                       `stellar-agent friendbot --account <G>`. \
                       read_only_hint=false; destructive_hint=true.",
        annotations(read_only_hint = false, destructive_hint = true)
    )]
    async fn stellar_friendbot(
        &self,
        Parameters(args): Parameters<StellarFriendbotArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        // ── dispatch gate ─────────────────────────────────────────────────────
        // Called unconditionally on every tools/call.
        // NoopPolicyEngine rejects mainnet + destructive with NotImplemented.
        let args_value = json!({
            "chain_id": &args.chain_id,
            "account_id": &args.account_id,
        });
        // Non-signing tool: RequireApproval produces no signing material; proceed.
        let _ = self
            .dispatch_gate("stellar_friendbot", &args_value, &args.chain_id)
            .await?;

        // ── Validate G-strkey (strict G-only ed25519 public key) ────────────
        // Uses ed25519::PublicKey::from_string (not the permissive Strkey::from_string
        // which accepts S/M/C strkeys) so only G-strkeys are accepted.
        if let Err(err) = stellar_strkey::ed25519::PublicKey::from_string(&args.account_id) {
            return Err(rmcp::ErrorData::invalid_params(
                format!("invalid account_id (expected G-strkey): {err}"),
                None,
            ));
        }

        // ── Resolve and validate Friendbot URL ───────────────────────────────
        // When the caller supplies a URL, validate it against the allow-list.
        // When None, use the profile's default Friendbot URL for the chain.
        // The default is the CAIP-2-derived default; currently testnet maps
        // to https://friendbot.stellar.org (the only allowed testnet host).
        let friendbot_url: String = args
            .friendbot_url
            .clone()
            .or_else(|| default_friendbot_url(self.profile.chain_id).map(str::to_owned))
            .ok_or_else(|| {
                rmcp::ErrorData::invalid_params("no default friendbot URL for this chain", None)
            })?;
        if let Err(err) = validate_friendbot_url(&friendbot_url) {
            return Err(rmcp::ErrorData::invalid_params(
                format!("friendbot_url not allowed: {err}"),
                None,
            ));
        }

        // ── Call the Friendbot network layer ─────────────────────────────────
        // Pass the profile's network passphrase (not the chain_id string) to
        // fund_with_friendbot so the mainnet-passphrase gate fires even if
        // the policy gate were somehow bypassed.
        let network_passphrase = self.profile.network_passphrase.as_str();

        match stellar_agent_network::fund_with_friendbot(
            &friendbot_url,
            &args.account_id,
            network_passphrase,
        )
        .await
        {
            Ok(result) => {
                let envelope = stellar_agent_core::envelope::Envelope::ok(result);
                let json = envelope
                    .to_json_pretty()
                    .unwrap_or_else(|_| String::from("{}"));
                Ok(CallToolResult::success(vec![Content::text(json)]))
            }
            Err(err) => {
                let envelope = stellar_agent_core::envelope::Envelope::<()>::err(&err);
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

// ─────────────────────────────────────────────────────────────────────────────
// Test helpers
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(any(test, feature = "test-helpers"))]
impl WalletServer {
    /// Calls `stellar_friendbot` with the given args, bypassing the rmcp transport.
    ///
    /// This mirrors `call_stellar_balances` and exists only for integration
    /// tests that need to exercise handler-level validation without stdio
    /// framing.
    #[doc(hidden)]
    pub async fn call_stellar_friendbot(
        &self,
        args: StellarFriendbotArgs,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.stellar_friendbot(Parameters(args)).await
    }
}
