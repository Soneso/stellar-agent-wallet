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
        if let Err(e) = self
            .dispatch_gate("stellar_sep7_parse_uri", &args_value, &args.chain_id)
            .await
        {
            return e.into_result();
        }

        // Parse the URI and determine signature status. A parse/verify failure
        // is a business refusal on the caller-supplied URI content, not a
        // JSON-RPC protocol fault — it surfaces through the documented result
        // envelope with a `sep7.*` wire code, matching every other normalised
        // tool.
        let (request, status) = if args.verify_origin {
            // `parse_and_verify_uri` performs its own bounded HTTPS fetch of
            // `stellar.toml` for the origin domain (HTTPS-only, no-redirect).
            match parse_and_verify_uri(&args.uri).await {
                Ok(parsed) => parsed,
                Err(e) => {
                    let (code, detail) = sep7_error_to_wire(&e);
                    return Ok(crate::tools::common::business_error_result(code, detail));
                }
            }
        } else {
            match parse_uri(&args.uri) {
                Ok(parsed) => parsed,
                Err(e) => {
                    let (code, detail) = sep7_error_to_wire(&e);
                    return Ok(crate::tools::common::business_error_result(code, detail));
                }
            }
        };

        let preview = build_preview(&request, &status);

        let envelope = stellar_agent_core::envelope::Envelope::ok(preview);
        let json_str = envelope
            .to_json_pretty()
            .unwrap_or_else(|_| String::from("{}"));
        Ok(CallToolResult::success(vec![Content::text(json_str)]))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Error mapping
// ─────────────────────────────────────────────────────────────────────────────

/// Maps a [`Sep7Error`] to a wire-safe (dotted code, detail) pair.
///
/// The code is in the `sep7.*` namespace, matching the dotted wire-code
/// taxonomy every other normalised tool uses. The `detail` field never leaks
/// the full fetch URL.
fn sep7_error_to_wire(err: &stellar_agent_sep7::Sep7Error) -> (&'static str, String) {
    use stellar_agent_sep7::Sep7Error;
    match err {
        Sep7Error::MalformedUri { detail } => ("sep7.malformed_uri", detail.clone()),
        Sep7Error::UnknownOperation { operation } => (
            "sep7.unknown_operation",
            format!("unknown operation: {operation:?}"),
        ),
        Sep7Error::MissingRequiredParam { param } => (
            "sep7.missing_required_param",
            format!("missing required parameter: {param}"),
        ),
        Sep7Error::InvalidParamValue { param, detail } => (
            "sep7.invalid_param_value",
            format!("invalid '{param}': {detail}"),
        ),
        Sep7Error::MsgTooLong { len } => (
            "sep7.msg_too_long",
            format!("msg is {len} chars; maximum is 300"),
        ),
        Sep7Error::TooManyChainLevels { depth } => (
            "sep7.too_many_chain_levels",
            format!("chain depth {depth} exceeds maximum of 7"),
        ),
        Sep7Error::InvalidOriginDomain { detail } => ("sep7.invalid_origin_domain", detail.clone()),
        Sep7Error::TomlFetchFailed { authority_hint } => (
            "sep7.toml_fetch_failed",
            // Redacted — only the authority hint, not the full URL.
            format!("stellar.toml fetch failed: {authority_hint}"),
        ),
        Sep7Error::SigningKeyNotInToml => (
            "sep7.signing_key_not_in_toml",
            "origin_domain stellar.toml does not contain URI_REQUEST_SIGNING_KEY".to_owned(),
        ),
        Sep7Error::SignatureVerificationFailed { detail } => {
            ("sep7.signature_verification_failed", detail.clone())
        }
        Sep7Error::SignatureMissingWithOriginDomain => (
            "sep7.signature_missing_with_origin_domain",
            "origin_domain is present but signature is absent; request is untrusted".to_owned(),
        ),
        // Non-exhaustive match arm for future variants.
        _ => ("sep7.error", err.to_string()),
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

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;
    use stellar_agent_core::profile::schema::Profile;

    fn make_server() -> crate::server::WalletServer {
        crate::server::WalletServer::new(
            Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
                .with_noop_engine()
                .build(),
        )
        .expect("WalletServer::new must not fail in tests")
    }

    /// A well-formed `pay` URI with no `origin_domain` parses successfully
    /// under the documented `{ ok: true, data: {...}, request_id }` envelope.
    #[tokio::test]
    async fn valid_pay_uri_parses_under_normalised_envelope() {
        let server = make_server();
        let args = Sep7ParseUriArgs {
            chain_id: "stellar:testnet".to_owned(),
            uri: "web+stellar:pay?destination=\
                  GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO"
                .to_owned(),
            verify_origin: false,
        };
        let result = server
            .invoke_stellar_sep7_parse_uri(args)
            .await
            .expect("a well-formed URI must not be a protocol error");
        assert_ne!(
            result.is_error,
            Some(true),
            "success must not set is_error = true"
        );
        let text = result
            .content
            .first()
            .and_then(|c| c.as_text())
            .map(|t| t.text.clone())
            .expect("result must carry a text content block");
        let value: serde_json::Value = serde_json::from_str(&text).expect("must be JSON");
        assert_eq!(value["ok"], serde_json::json!(true));
        assert_eq!(value["data"]["operation"], serde_json::json!("pay"));
        assert!(
            value["request_id"].as_str().is_some_and(|s| !s.is_empty()),
            "envelope must carry a non-empty request_id: {value}"
        );
    }

    /// A malformed `web+stellar:` URI is a business refusal
    /// (`sep7.malformed_uri`), not a JSON-RPC protocol error.
    #[tokio::test]
    async fn malformed_uri_is_business_error() {
        let server = make_server();
        let args = Sep7ParseUriArgs {
            chain_id: "stellar:testnet".to_owned(),
            uri: "not-a-stellar-uri".to_owned(),
            verify_origin: false,
        };
        let result = server
            .invoke_stellar_sep7_parse_uri(args)
            .await
            .expect("a malformed URI must surface as a business-error envelope, not Err");
        let (code, _message, _text) = crate::tools::common::assert_business_envelope(&result);
        assert_eq!(code, "sep7.malformed_uri");
    }

    /// An unsupported operation in the URI path is `sep7.unknown_operation`,
    /// not a JSON-RPC protocol error.
    #[tokio::test]
    async fn unknown_operation_is_business_error() {
        let server = make_server();
        let args = Sep7ParseUriArgs {
            chain_id: "stellar:testnet".to_owned(),
            uri: "web+stellar:swap?foo=bar".to_owned(),
            verify_origin: false,
        };
        let result = server
            .invoke_stellar_sep7_parse_uri(args)
            .await
            .expect("an unknown operation must surface as a business-error envelope, not Err");
        let (code, _message, _text) = crate::tools::common::assert_business_envelope(&result);
        assert_eq!(code, "sep7.unknown_operation");
    }
}
