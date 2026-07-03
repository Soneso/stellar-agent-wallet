//! `stellar_sep7_parse_uri` MCP tool — SEP-7 inbound URI parse and verify.
//!
//! Parses a `web+stellar:tx/pay?<params>` URI into a structured preview and,
//! when `origin_domain` and `signature` are present, performs a **fresh**
//! (non-cached) stellar.toml fetch + ed25519 signature verification.
//!
//! # Parse-and-verify-only guarantee
//!
//! This tool NEVER signs a URI, NEVER auto-POSTs to a `callback` endpoint,
//! and NEVER submits a transaction.  The `will_auto_submit` and
//! `will_auto_post_callback` fields in the preview are always `false`.
//!
//! # SEP-7 reference
//!
//! `sep-0007.md`.

use rmcp::{
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Content},
    schemars, serde, tool, tool_router,
};
use serde_json::json;
use stellar_agent_mcp_macros::mcp_tool_router;

use stellar_agent_sep7::{parse_and_verify_uri, parse_uri, preview::build_preview};

use crate::server::WalletServer;

// ─────────────────────────────────────────────────────────────────────────────
// Argument type
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for the `stellar_sep7_parse_uri` MCP tool.
///
/// # Schema
///
/// - `uri` — the `web+stellar:` URI to parse (required).
/// - `chain_id` — CAIP-2 chain identifier (required for dispatch-gate; SEP-7
///   parsing itself is chain-agnostic but the preview may carry a
///   `network_passphrase` from the URI).
/// - `verify_origin` — if `true` (default), performs the fresh stellar.toml
///   fetch and signature verification when `origin_domain` + `signature` are
///   present.  Set to `false` to parse without network I/O (the
///   `signature_status` will be `absent` or `missing_required` based on
///   parameter presence alone).
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(crate = "rmcp::serde")]
pub struct Sep7ParseUriArgs {
    /// CAIP-2 chain identifier (e.g. `"stellar:testnet"`).
    pub chain_id: String,

    /// The `web+stellar:` URI to parse.
    pub uri: String,

    /// Whether to perform live origin_domain signature verification.
    ///
    /// When `true` (default), a fresh stellar.toml fetch + ed25519 verification
    /// is performed if both `origin_domain` and `signature` are present.
    ///
    /// When `false`, only structural parsing is performed (no network I/O).
    #[serde(default = "default_verify_origin")]
    pub verify_origin: bool,
}

fn default_verify_origin() -> bool {
    true
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool router impl block
// ─────────────────────────────────────────────────────────────────────────────

/// Parses a `web+stellar:` URI and returns a structured preview.
///
/// Implements `stellar_sep7_parse_uri`. Parse-and-verify-only; no signing,
/// no callback POST, no transaction submission.
///
/// Returns a JSON object with:
/// - `operation` — `"tx"` or `"pay"`.
/// - Parsed fields for the operation.
/// - `callback` — authority host for SSRF inspection (never auto-posted).
/// - `origin_domain` — if declared.
/// - `origin_verified` — `true` only when verification passed.
/// - `signature_status` — one of `verified`, `failed`, `missing_required`, `absent`.
/// - `will_auto_submit` — always `false`.
/// - `will_auto_post_callback` — always `false`.
///
/// # Tool annotations
///
/// - `readOnlyHint = true` — no keyring access; signature verification is
///   read-only (stellar.toml fetch is the only I/O, and it is a GET).
/// - `destructiveHint = false` — does not modify any state.
///
/// # SEP-7 reference
///
/// `sep-0007.md`.
///
/// # Errors
///
/// Returns a tool-level error when:
/// - `chain_id` does not match the profile (dispatch-gate check).
/// - The URI is not a valid `web+stellar:` URI.
/// - Required parameters are missing (`xdr` for `tx`, `destination` for `pay`).
/// - Parameter values are invalid (bad XDR, bad G-strkey, oversized `msg`, etc.).
/// - `verify_origin=true` and the stellar.toml fetch fails (TOML URL redacted).
///
/// # Examples
///
/// ```json
/// {
///   "chain_id": "stellar:testnet",
///   "uri": "web+stellar:pay?destination=GCALNQ...&amount=100",
///   "verify_origin": false
/// }
/// ```
#[mcp_tool_router]
#[tool_router(router = sep7_parse_uri_tool_router, vis = "pub(crate)")]
impl WalletServer {
    #[mcp_tool_item(
        name = "stellar_sep7_parse_uri",
        destructive_hint = false,
        read_only_hint = true,
        chain_id_required = true
    )]
    #[tool(
        name = "stellar_sep7_parse_uri",
        description = "Parse a web+stellar: SEP-7 URI into a structured preview. \
                       Inputs: uri (web+stellar:tx/pay?...), chain_id, verify_origin (bool, default true). \
                       Performs fresh stellar.toml fetch + ed25519 signature verification when \
                       origin_domain+signature are present and verify_origin=true. \
                       Returns structured JSON: operation, fields, callback authority (for SSRF inspection), \
                       signature_status (verified/failed/missing_required/absent), origin_verified. \
                       NEVER auto-signs, NEVER auto-POSTs callback, NEVER submits a transaction. \
                       read_only_hint=true; destructive_hint=false.",
        annotations(read_only_hint = true, destructive_hint = false)
    )]
    async fn stellar_sep7_parse_uri(
        &self,
        Parameters(args): Parameters<Sep7ParseUriArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        // Log structured (no URI content at info level — may carry sensitive paths).
        let args_value = json!({
            "chain_id": &args.chain_id,
            "uri_len": args.uri.len(),
            "verify_origin": args.verify_origin,
        });
        // Read-only tool: RequireApproval produces no signing material; proceed.
        let _ = self
            .dispatch_gate("stellar_sep7_parse_uri", &args_value, &args.chain_id)
            .await?;

        // Parse the URI and determine signature status.
        let (request, status) = if args.verify_origin {
            // `parse_and_verify_uri` performs its own bounded HTTPS fetch of
            // `stellar.toml` for the origin domain (HTTPS-only, no-redirect).
            parse_and_verify_uri(&args.uri).await.map_err(|e| {
                let (code, detail) = sep7_error_to_wire(&e);
                rmcp::ErrorData::invalid_params(code, Some(json!({ "detail": detail })))
            })?
        } else {
            parse_uri(&args.uri).map_err(|e| {
                let (code, detail) = sep7_error_to_wire(&e);
                rmcp::ErrorData::invalid_params(code, Some(json!({ "detail": detail })))
            })?
        };

        let preview = build_preview(&request, &status);

        let json_str = serde_json::to_string_pretty(&preview).unwrap_or_else(|_| "{}".to_owned());
        Ok(CallToolResult::success(vec![Content::text(json_str)]))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Error mapping
// ─────────────────────────────────────────────────────────────────────────────

/// Maps a [`Sep7Error`] to a wire-safe (machine_code, detail) pair.
///
/// The `detail` field never leaks the full fetch URL.
fn sep7_error_to_wire(err: &stellar_agent_sep7::Sep7Error) -> (&'static str, String) {
    use stellar_agent_sep7::Sep7Error;
    match err {
        Sep7Error::MalformedUri { detail } => ("sep7_malformed_uri", detail.clone()),
        Sep7Error::UnknownOperation { operation } => (
            "sep7_unknown_operation",
            format!("unknown operation: {operation:?}"),
        ),
        Sep7Error::MissingRequiredParam { param } => (
            "sep7_missing_required_param",
            format!("missing required parameter: {param}"),
        ),
        Sep7Error::InvalidParamValue { param, detail } => (
            "sep7_invalid_param_value",
            format!("invalid '{param}': {detail}"),
        ),
        Sep7Error::MsgTooLong { len } => (
            "sep7_msg_too_long",
            format!("msg is {len} chars; maximum is 300"),
        ),
        Sep7Error::TooManyChainLevels { depth } => (
            "sep7_too_many_chain_levels",
            format!("chain depth {depth} exceeds maximum of 7"),
        ),
        Sep7Error::InvalidOriginDomain { detail } => ("sep7_invalid_origin_domain", detail.clone()),
        Sep7Error::TomlFetchFailed { authority_hint } => (
            "sep7_toml_fetch_failed",
            // Redacted — only the authority hint, not the full URL.
            format!("stellar.toml fetch failed: {authority_hint}"),
        ),
        Sep7Error::SigningKeyNotInToml => (
            "sep7_signing_key_not_in_toml",
            "origin_domain stellar.toml does not contain URI_REQUEST_SIGNING_KEY".to_owned(),
        ),
        Sep7Error::SignatureVerificationFailed { detail } => {
            ("sep7_signature_verification_failed", detail.clone())
        }
        Sep7Error::SignatureMissingWithOriginDomain => (
            "sep7_signature_missing_with_origin_domain",
            "origin_domain is present but signature is absent; request is untrusted".to_owned(),
        ),
        // Non-exhaustive match arm for future variants.
        _ => ("sep7_error", err.to_string()),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Toolset-dispatch helper
// ─────────────────────────────────────────────────────────────────────────────

impl WalletServer {
    /// Invoke `stellar_sep7_parse_uri` by value, bypassing the rmcp transport.
    ///
    /// Used by the toolset-invocation routing path (`tools/toolsets.rs`).
    ///
    /// # Errors
    ///
    /// Same as [`WalletServer::stellar_sep7_parse_uri`].
    pub(crate) async fn invoke_stellar_sep7_parse_uri(
        &self,
        args: Sep7ParseUriArgs,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.stellar_sep7_parse_uri(Parameters(args)).await
    }
}
