//! `stellar_sep6_deposit_info` MCP tool — SEP-6 anchor capability discovery.
//!
//! Calls ONLY `GET {transfer_server}/info` (the public, non-authenticated SEP-6
//! discovery endpoint).  Returns the decoded anchor capabilities including the
//! `authentication_required` flag per asset.
//!
//! # Positive capability bound
//!
//! This tool NEVER calls `/deposit`, `/withdraw`, `/deposit-exchange`,
//! `/withdraw-exchange`, `/customer` (SEP-12), `/fee`, or `/transaction(s)`.
//! It NEVER transmits any KYC field.  The bound is structural — see
//! `stellar-agent-anchor/src/sep6.rs` module docs.
//!
//! # SEP-6 reference
//!
//! `sep-0006.md:1241-1248`.

use rmcp::{
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Content},
    schemars, serde, tool, tool_router,
};
use serde_json::json;
use stellar_agent_mcp_macros::mcp_tool_router;

use stellar_agent_anchor::{Sep6Info, get_sep6_info};
use stellar_agent_network::counterparty::{fetch::fetch_stellar_toml, parser::parse_minimal_sep1};

use crate::server::WalletServer;

// ─────────────────────────────────────────────────────────────────────────────
// Argument type
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for the `stellar_sep6_deposit_info` MCP tool.
///
/// # POSITIVE CAPABILITY BOUND
///
/// This tool arg struct intentionally has NO KYC field.  Adding any SEP-9
/// KYC field (`email_address`, `first_name`, `dest`, etc.) is FORBIDDEN
/// without a dedicated security re-review.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(crate = "rmcp::serde")]
pub struct Sep6DepositInfoArgs {
    /// CAIP-2 chain identifier (e.g. `"stellar:testnet"`).
    pub chain_id: String,

    /// The anchor domain to resolve `TRANSFER_SERVER` from (e.g.
    /// `"testanchor.stellar.org"`).
    ///
    /// Mutually exclusive with `transfer_server`.  If both are provided,
    /// `anchor_domain` takes precedence.
    #[serde(default)]
    pub anchor_domain: Option<String>,

    /// A directly-supplied `TRANSFER_SERVER` URL (HTTPS required).
    ///
    /// Use when you already know the transfer-server URL and do not want to
    /// resolve it from stellar.toml.  The URL must use HTTPS and have a
    /// public FQDN (≥2 labels, not an IP address).
    ///
    /// Mutually exclusive with `anchor_domain`.
    #[serde(default)]
    pub transfer_server: Option<String>,

    /// Optional asset code filter.  If supplied, passed as `?asset_code=` to
    /// the anchor's `/info` endpoint.
    #[serde(default)]
    pub asset_code: Option<String>,

    /// Optional language code (RFC 4646).  Defaults to `"en"` if absent.
    #[serde(default)]
    pub lang: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool router impl block
// ─────────────────────────────────────────────────────────────────────────────

/// SEP-6 anchor capability discovery tool.
///
/// Implements `stellar_sep6_deposit_info`.  Calls ONLY `GET /info`; NEVER
/// initiates a deposit/withdraw or transmits KYC data.
#[mcp_tool_router]
#[tool_router(router = sep6_deposit_info_tool_router, vis = "pub(crate)")]
impl WalletServer {
    #[mcp_tool_item(
        name = "stellar_sep6_deposit_info",
        destructive_hint = false,
        read_only_hint = true,
        chain_id_required = true
    )]
    #[tool(
        name = "stellar_sep6_deposit_info",
        description = "Discover SEP-6 anchor capabilities via GET /info (public, no JWT). \
                       Inputs: chain_id, anchor_domain OR transfer_server (direct URL), \
                       asset_code? (filter), lang?. \
                       Returns decoded anchor capabilities (deposit/withdraw assets, \
                       authentication_required per asset, fee info). \
                       This wallet NEVER initiates a deposit/withdraw, NEVER calls \
                       /deposit, /withdraw, /customer, /fee, or /transaction(s), and \
                       NEVER transmits any KYC field. /info ONLY. \
                       read_only_hint=true; destructive_hint=false.",
        annotations(read_only_hint = true, destructive_hint = false)
    )]
    async fn stellar_sep6_deposit_info(
        &self,
        Parameters(args): Parameters<Sep6DepositInfoArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let args_value = json!({
            "chain_id": &args.chain_id,
            "has_anchor_domain": args.anchor_domain.is_some(),
            "has_transfer_server": args.transfer_server.is_some(),
        });
        // Non-signing tool: RequireApproval produces no signing material; proceed.
        if let Err(e) = self
            .dispatch_gate("stellar_sep6_deposit_info", &args_value, &args.chain_id)
            .await
        {
            return e.into_result();
        }

        // Resolve transfer_server URL. A resolution failure is a business
        // refusal on caller-supplied input (bad domain, unreachable anchor,
        // malformed stellar.toml), not a JSON-RPC protocol fault.
        let (transfer_server, anchor_domain_str) = match resolve_transfer_server(
            args.anchor_domain.as_deref(),
            args.transfer_server.as_deref(),
        )
        .await
        {
            Ok(resolved) => resolved,
            Err(e) => {
                let (code, detail) = anchor_error_to_wire(&e);
                return Ok(crate::tools::common::business_error_result(code, detail));
            }
        };

        // Fetch and decode /info.
        let info = match get_sep6_info(
            &transfer_server,
            anchor_domain_str.as_deref(),
            args.asset_code.as_deref(),
            args.lang.as_deref(),
        )
        .await
        {
            Ok(info) => info,
            Err(e) => {
                let (code, detail) = anchor_error_to_wire(&e);
                return Ok(crate::tools::common::business_error_result(code, detail));
            }
        };

        let output = build_sep6_output(&info);
        let envelope = stellar_agent_core::envelope::Envelope::ok(output);
        let json_str = envelope
            .to_json_pretty()
            .unwrap_or_else(|_| String::from("{}"));
        Ok(CallToolResult::success(vec![Content::text(json_str)]))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Resolves the transfer-server URL from either an anchor domain (stellar.toml
/// lookup) or a direct URL.
///
/// Returns `(transfer_server_url, anchor_domain_for_ssrf_bind)`.
async fn resolve_transfer_server(
    anchor_domain: Option<&str>,
    direct_transfer_server: Option<&str>,
) -> Result<(String, Option<String>), stellar_agent_anchor::AnchorError> {
    use stellar_agent_anchor::AnchorError;

    if let Some(domain) = anchor_domain {
        let authority_hint = format!("{domain}/.well-known/stellar.toml");
        let toml_body =
            fetch_stellar_toml(domain)
                .await
                .map_err(|_| AnchorError::AnchorFetchFailed {
                    authority_hint: authority_hint.clone(),
                    detail: "stellar.toml fetch failed".to_owned(),
                })?;
        let sep1 = parse_minimal_sep1(&toml_body).map_err(|_| {
            AnchorError::AnchorResponseDecodeFailed {
                authority_hint: authority_hint.clone(),
                detail: "stellar.toml parse failed".to_owned(),
            }
        })?;
        let ts = sep1
            .transfer_server
            .ok_or(AnchorError::AnchorResponseDecodeFailed {
                authority_hint,
                detail: "stellar.toml does not declare TRANSFER_SERVER".to_owned(),
            })?;
        Ok((ts, Some(domain.to_owned())))
    } else if let Some(direct) = direct_transfer_server {
        Ok((direct.to_owned(), None))
    } else {
        Err(AnchorError::InvalidAnchorDomain {
            detail: "either anchor_domain or transfer_server must be provided".to_owned(),
        })
    }
}

/// Builds the JSON output for the SEP-6 /info response.
///
/// Surfaces `authentication_required` prominently.
fn build_sep6_output(info: &Sep6Info) -> serde_json::Value {
    let deposit: serde_json::Map<String, serde_json::Value> = info
        .deposit
        .iter()
        .map(|(asset, ai)| {
            (
                asset.clone(),
                json!({
                    "enabled": ai.enabled,
                    "authentication_required": ai.authentication_required,
                    "fee_fixed": ai.fee_fixed,
                    "fee_percent": ai.fee_percent,
                    "min_amount": ai.min_amount,
                    "max_amount": ai.max_amount,
                }),
            )
        })
        .collect();

    let withdraw: serde_json::Map<String, serde_json::Value> = info
        .withdraw
        .iter()
        .map(|(asset, ai)| {
            (
                asset.clone(),
                json!({
                    "enabled": ai.enabled,
                    "authentication_required": ai.authentication_required,
                    "fee_fixed": ai.fee_fixed,
                    "fee_percent": ai.fee_percent,
                    "min_amount": ai.min_amount,
                    "max_amount": ai.max_amount,
                }),
            )
        })
        .collect();

    json!({
        "deposit": deposit,
        "withdraw": withdraw,
        "deposit_exchange": info.deposit_exchange.keys().collect::<Vec<_>>(),
        "withdraw_exchange": info.withdraw_exchange.keys().collect::<Vec<_>>(),
        "features": {
            "account_creation": info.features.account_creation,
            "claimable_balances": info.features.claimable_balances,
        },
        "wallet_note": "This wallet calls ONLY GET /info. \
                        It never initiates a deposit/withdraw or transmits KYC data \
                        (positive capability bound).",
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Error mapping (pub(crate) for reuse by sep24_interactive_url)
// ─────────────────────────────────────────────────────────────────────────────

/// Maps [`AnchorError`] to a wire-safe (dotted code, detail) pair.
///
/// The code is in the `anchor.*` namespace, matching the dotted wire-code
/// taxonomy every other normalised tool uses. URLs are redacted to
/// authority-only.
pub(crate) fn anchor_error_to_wire(
    err: &stellar_agent_anchor::AnchorError,
) -> (&'static str, String) {
    use stellar_agent_anchor::AnchorError;
    match err {
        AnchorError::InvalidAnchorDomain { detail } => ("anchor.invalid_domain", detail.clone()),
        AnchorError::TransferServerHostMismatch {
            anchor_domain,
            resolved_host,
        } => (
            "anchor.transfer_server_host_mismatch",
            format!(
                "SSRF bind rejected: resolved host {resolved_host:?} does not match \
                 anchor domain {anchor_domain:?}"
            ),
        ),
        AnchorError::AnchorFetchFailed {
            authority_hint,
            detail,
        } => (
            "anchor.fetch_failed",
            format!("fetch failed at {authority_hint}: {detail}"),
        ),
        AnchorError::AnchorResponseDecodeFailed {
            authority_hint,
            detail,
        } => (
            "anchor.response_decode_failed",
            format!("decode failed at {authority_hint}: {detail}"),
        ),
        AnchorError::HttpStatusError {
            authority_hint,
            status,
        } => (
            "anchor.http_status_error",
            format!("HTTP {status} at {authority_hint}"),
        ),
        AnchorError::Sep24UnexpectedResponseType { response_type } => (
            "anchor.sep24_unexpected_response_type",
            format!("unexpected response type: {response_type:?}"),
        ),
        AnchorError::InvalidDirectUrl { detail } => ("anchor.invalid_direct_url", detail.clone()),
        // Non-exhaustive: catch-all for future variants.
        _ => ("anchor.error", format!("{err}")),
    }
}
