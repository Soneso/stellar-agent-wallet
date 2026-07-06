//! `stellar_dex_trade` and `stellar_dex_quote` MCP tools — Soroswap swap adapter.
//!
//! # What these tools do
//!
//! `stellar_dex_trade` submits a `swap_exact_tokens_for_tokens` transaction to
//! the Soroswap ROUTER-DIRECT path.  It delegates the full ordered trust gate to
//! `DexSwapAdapter::submit`:
//!
//! 1. Venue allowlist — Soroswap router address for the network.
//! 2. Router WASM-hash pin — two-RPC check against pinned value.
//! 3. Slippage re-verify — on-chain `router_get_amounts_out` re-fetch.
//! 4. Swap submission via `submit_signed_invoke`.
//!
//! `stellar_dex_quote` fetches the on-chain `router_get_amounts_out` quote in
//! read-only mode (no signing, no state mutation).
//!
//! # No inline duplication
//!
//! There is NO duplicated `HostFunction` build or `submit_signed_invoke` call
//! in this file.  All execution logic lives exclusively in `DexSwapAdapter`.
//!
//! # Policy evaluation
//!
//! `stellar_dex_trade` runs `WalletServer::dispatch_gate` before signing.
//! `stellar_dex_quote` is read-only; it does NOT call `dispatch_gate`.
//!
//! # Behaviour
//!
//! - Slippage floor is an absolute `qty_out_min` value.
//! - Slippage is re-verified on-chain before submission.
//! - Tokens are canonicalised to their SAC addresses.
//! - The swap deadline is bounded.
//! - The venue allowlist is fail-closed.
//! - The router WASM-hash pin is verified before any quote read.
//! - The trade tool exposes a typed preview.

use rmcp::{
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Content},
    schemars, serde, tool, tool_router,
};
use serde_json::json;
use stellar_agent_mcp_macros::mcp_tool_router;

use stellar_agent_core::observability::redact_strkey_first5_last5;
use stellar_agent_defi::adapter::{DefiAdapter, DefiAdapterCtx};
use stellar_agent_defi::dispatch::{GateOutcome, dispatch_gate, require_approval_error};
use stellar_agent_defi::pins::DefiContractPin;
use stellar_agent_dex::{
    abi::TradeArgs, adapter::DexSwapAdapter, pins::pinned_router_for_network, quote::fetch_quote,
    sac::canonicalise_path,
};
use stellar_agent_network::{StellarRpcClient, signer_from_keyring};

use crate::server::WalletServer;
use crate::tools::common::DispatchOutcome;

// ─────────────────────────────────────────────────────────────────────────────
// Argument types
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for the `stellar_dex_trade` MCP tool.
///
/// Submits a `swap_exact_tokens_for_tokens` call to the Soroswap
/// ROUTER-DIRECT path.  The ordered trust gate (venue-check, pin-verify,
/// slippage-reverify) runs inside `DexSwapAdapter::submit` before signing.
///
/// The slippage floor is an absolute `qty_out_min` value, and the arguments
/// are surfaced as a typed schema.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(crate = "rmcp::serde")]
pub struct DexTradeArgs {
    /// CAIP-2 chain identifier: `stellar:testnet` or `stellar:mainnet`.
    pub chain_id: String,
    /// Wallet smart-account address submitting the swap (C-strkey).
    pub from_address: String,
    /// Exact input token amount in native base units (7-decimal i128), as a
    /// decimal string (e.g. `"250000000"`). A raw JSON number is rejected —
    /// `serde_json::from_value` backs numbers with `f64`, which cannot
    /// represent an i128 exactly above `2^53`.
    ///
    /// Named `qty_in` so raw on-chain integer fields use `qty_*` rather than
    /// `amount_*`, avoiding conflation with the `McpAmountArgument` dual-unit
    /// schema.
    pub qty_in: String,
    /// Minimum output token amount (absolute floor, required), as a decimal
    /// string. A raw JSON number is rejected (see `qty_in`).
    ///
    /// MUST be a non-negative integer (not a percent string).
    /// Named `qty_out_min` for the same naming reason as `qty_in`. The
    /// slippage floor is explicit and absolute.
    pub qty_out_min: String,
    /// Swap path: first element is the input token, last is the output token.
    ///
    /// Each element is a C-strkey, `"native"`, or `"CODE:ISSUER"` classic asset.
    /// The path must be specified explicitly.
    pub path: Vec<String>,
    /// Swap deadline as a Unix timestamp (seconds).
    ///
    /// When absent, defaults to `now + 300s`. The deadline is bounded.
    #[serde(default)]
    pub deadline: Option<u64>,
    /// Optional secondary RPC URL for the two-RPC WASM-hash cross-check.
    ///
    /// When absent, the primary RPC is used for both checks (degraded security).
    /// A distinct secondary RPC is strongly recommended for mainnet.
    #[serde(default)]
    pub secondary_rpc_url: Option<String>,
}

/// Arguments for the `stellar_dex_quote` MCP tool.
///
/// Fetches the on-chain `router_get_amounts_out` quote in read-only mode.
/// No signing; no state mutation.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(crate = "rmcp::serde")]
pub struct DexQuoteArgs {
    /// CAIP-2 chain identifier: `stellar:testnet` or `stellar:mainnet`.
    pub chain_id: String,
    /// Exact input token amount in native base units, as a decimal string
    /// (e.g. `"250000000"`). A raw JSON number is rejected (see
    /// `DexTradeArgs.qty_in`).
    ///
    /// Named `qty_in` so raw on-chain integer fields use `qty_*`, avoiding
    /// conflation with the `McpAmountArgument` dual-unit schema.
    pub qty_in: String,
    /// Swap path (same format as `stellar_dex_trade.path`).
    pub path: Vec<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool router impl block
// ─────────────────────────────────────────────────────────────────────────────

/// Submits a Soroswap swap via the ROUTER-DIRECT path.
///
/// # Ordered trust gate (LOAD-BEARING)
///
/// Delegated to `DexSwapAdapter::submit`:
/// 1. Venue allowlist check (Soroswap-only; fail-closed).
/// 2. Router WASM-hash pin-verify (two-RPC; FIRST, before any quote read).
/// 3. Slippage re-verify (`router_get_amounts_out` re-fetch; age-bounded).
///
/// Only after all three pass does the swap execute via `submit_signed_invoke`.
///
/// # Tool annotations
///
/// - `destructive_hint = true` — signs and submits a transaction.
/// - `read_only_hint = false` — modifies on-chain state.
///
/// # Errors
///
/// Returns a tool-level error when:
/// - `qty_out_min < 0`.
/// - Path length is outside `[2, 5]`.
/// - Token canonicalisation fails (ambiguous bare code, percent string, etc.).
/// - Venue allowlist refuses the router address.
/// - Router WASM-hash pin does not match.
/// - On-chain slippage re-verify shows expected output < `qty_out_min`.
/// - Policy engine returns `Deny`.
/// - The smart-account submit fails.
#[mcp_tool_router]
#[tool_router(router = dex_trade_tool_router, vis = "pub(crate)")]
impl WalletServer {
    #[mcp_tool_item(
        name = "stellar_dex_trade",
        destructive_hint = true,
        read_only_hint = false,
        chain_id_required = true
    )]
    #[tool(
        name = "stellar_dex_trade",
        description = "Swap tokens via Soroswap ROUTER-DIRECT path. Enforces ordered trust gate: \
                       venue allowlist, router WASM-hash pin, on-chain slippage re-verify. \
                       Requires absolute qty_out_min floor (not a percent). Signs and submits \
                       via smart-account. destructive_hint=true, read_only_hint=false.",
        annotations(destructive_hint = true, read_only_hint = false)
    )]
    async fn stellar_dex_trade(
        &self,
        Parameters(args): Parameters<DexTradeArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        // ── Policy gate ───────────────────────────────────────────────────────
        // qty_in rides through the policy gate as a decimal STRING
        // (wire-faithful — deliberate). No criterion reads a decimal-string
        // amount field numerically; a future amount criterion must parse this
        // value string-tolerantly rather than assuming a JSON number.
        let args_value = json!({
            "chain_id": args.chain_id,
            "from_address": args.from_address,
            "qty_in": args.qty_in,
        });
        let dispatch_outcome = self
            .dispatch_gate("stellar_dex_trade", &args_value, &args.chain_id)
            .await?;

        // Single-shot DeFi tool: RequireApproval is not supported (no two-phase split).
        if matches!(dispatch_outcome, DispatchOutcome::RequireApproval(_)) {
            return Err(crate::tools::common::single_shot_require_approval_error());
        }

        // ── Parse the decimal-string amount fields ────────────────────────────
        let qty_in = crate::tools::amount_wire::parse_i128_field("qty_in", &args.qty_in)?;
        let qty_out_min =
            crate::tools::amount_wire::parse_i128_field("qty_out_min", &args.qty_out_min)?;

        // ── Resolve network settings ──────────────────────────────────────────
        let network_passphrase = self.profile.network_passphrase.as_str();
        let rpc_url = self.profile.rpc_url.as_str();

        // ── Build RPCs ────────────────────────────────────────────────────────
        let primary_rpc = StellarRpcClient::new(rpc_url).map_err(|e| {
            rmcp::ErrorData::internal_error(format!("dex.rpc_init_failed: {e}"), None)
        })?;
        let secondary_rpc: Option<StellarRpcClient> = args
            .secondary_rpc_url
            .as_deref()
            .map(|url| {
                StellarRpcClient::new(url).map_err(|e| {
                    rmcp::ErrorData::internal_error(
                        format!("dex.secondary_rpc_init_failed: {e}"),
                        None,
                    )
                })
            })
            .transpose()?;

        // ── Resolve pinned router address and WASM hash for network ──────────
        let (router_address, router_wasm_hash) = pinned_router_for_network(&args.chain_id)
            .map_err(|e| {
                rmcp::ErrorData::invalid_params(format!("dex.unrecognised_network: {e}"), None)
            })?;

        // ── Canonicalise path for display and TradeArgs ───────────────────────
        // Surface canonicalisation errors (not swallowed): an unresolvable token
        // address is a structural refusal, not a warning to ignore.
        let canonical_path = canonicalise_path(&args.path, network_passphrase).map_err(|e| {
            rmcp::ErrorData::invalid_params(format!("dex.canonicalisation_failed: {e}"), None)
        })?;

        // ── Build TradeArgs for the adapter ──────────────────────────────────
        let trade_args = TradeArgs {
            from_address: args.from_address.clone(),
            amount_in: qty_in,
            amount_out_min: qty_out_min,
            path: canonical_path.clone(),
            deadline: args.deadline,
        };

        let from_redacted = redact_strkey_first5_last5(&args.from_address);
        let router_redacted = redact_strkey_first5_last5(router_address);
        let path_redacted: Vec<String> = canonical_path
            .iter()
            .map(|a| redact_strkey_first5_last5(a))
            .collect();

        // ── DeFi dispatch gate (capability-witness seam) ──────────────────────
        let gate_result = dispatch_gate("trade", router_address);
        let witness = match gate_result {
            Ok(GateOutcome::Allow(w)) => w,
            Ok(GateOutcome::RequireApproval) => {
                return Err(rmcp::ErrorData::internal_error(
                    require_approval_error(),
                    None,
                ));
            }
            Err(e) => {
                return Err(rmcp::ErrorData::internal_error(
                    format!("dex.gate_error: {e}"),
                    None,
                ));
            }
        };

        tracing::info!(
            verb = "trade",
            router_redacted = %router_redacted,
            from_redacted = %from_redacted,
            qty_in,
            qty_out_min,
            request_id = witness.request_id(),
            "Soroswap trade: policy gate passed, submitting via adapter"
        );

        // ── Load signer from keyring ──────────────────────────────────────────
        let signer_entry_ref = &self.profile.mcp_signer_default;
        let expected_g_strkey = signer_entry_ref.account.as_str();
        let signer_handle = signer_from_keyring(signer_entry_ref, expected_g_strkey)
            .await
            .map_err(|_| {
                rmcp::ErrorData::internal_error(
                    "dex.signer_load_failed: could not load signer from keyring",
                    None,
                )
            })?;

        let timeout = crate::tools::common::submit_timeout(&self.profile);

        // ── Construct DefiAdapterCtx with full submit context ─────────────────
        // The pin is a synthetic DefiContractPin carrying the router address and
        // network; the actual WASM-hash pin is verified inside DexSwapAdapter::submit
        // by `verify_soroswap_router_wasm`.  The hash is resolved from the pinned
        // value for the network via `pinned_router_for_network` — not hardcoded.
        let router_pin = DefiContractPin::new(
            "soroswap",
            "router-direct",
            "default",
            &args.chain_id,
            router_address,
            router_wasm_hash, // resolved per-network from pinned_router_for_network
            "soroswap-core",  // abi_source_provenance
        );

        let ctx = DefiAdapterCtx::new_with_submit_ctx(
            "default",
            &router_pin,
            &primary_rpc,
            Some(&signer_handle as &(dyn stellar_agent_network::Signer + Send + Sync)),
            Some(network_passphrase),
            Some(args.chain_id.as_str()),
            secondary_rpc.as_ref(),
            Some(timeout),
        );

        // ── Delegate to DexSwapAdapter::submit (witness consumed inside) ──────
        // NO inline HostFunction build or submit_signed_invoke call here. All
        // execution logic lives in DexSwapAdapter::submit.
        let adapter = DexSwapAdapter::new();
        let submit_result = adapter
            .submit(
                &trade_args as &(dyn std::any::Any + Send + Sync),
                &ctx,
                witness,
            )
            .await;

        match submit_result {
            Ok(()) => {
                let resp = json!({
                    "status": "submitted",
                    "preview": {
                        "router_address_redacted": router_redacted,
                        "from_address_redacted": from_redacted,
                        "qty_in": args.qty_in,
                        "qty_out_min": args.qty_out_min,
                        "path_redacted": path_redacted,
                        "deadline": args.deadline,
                    },
                    "summary": format!(
                        "Swap {} (min out: {}) via Soroswap ({}-hop) on {}",
                        args.qty_in,
                        args.qty_out_min,
                        canonical_path.len().saturating_sub(1),
                        args.chain_id,
                    ),
                });
                let json_str =
                    serde_json::to_string_pretty(&resp).unwrap_or_else(|_| "{}".to_owned());
                Ok(CallToolResult::success(vec![Content::text(json_str)]))
            }
            Err(e) => {
                let resp = json!({
                    "code": "dex.submit_failed",
                    "message": e.to_string(),
                });
                let json_str =
                    serde_json::to_string_pretty(&resp).unwrap_or_else(|_| "{}".to_owned());
                let mut result = CallToolResult::success(vec![Content::text(json_str)]);
                result.is_error = Some(true);
                Ok(result)
            }
        }
    }

    #[mcp_tool_item(
        name = "stellar_dex_quote",
        destructive_hint = false,
        read_only_hint = true,
        chain_id_required = true
    )]
    #[tool(
        name = "stellar_dex_quote",
        description = "Fetch an on-chain Soroswap swap quote via router_get_amounts_out (read-only). \
                       Returns the expected output amounts for the given path. \
                       destructive_hint=false, read_only_hint=true.",
        annotations(destructive_hint = false, read_only_hint = true)
    )]
    async fn stellar_dex_quote(
        &self,
        Parameters(args): Parameters<DexQuoteArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        // ── Parse and validate basic input ────────────────────────────────────
        let qty_in = crate::tools::amount_wire::parse_i128_field("qty_in", &args.qty_in)?;
        if qty_in <= 0 {
            return Err(rmcp::ErrorData::invalid_params(
                "dex.quote.invalid_qty_in: qty_in must be positive",
                None,
            ));
        }
        if args.path.len() < 2 {
            return Err(rmcp::ErrorData::invalid_params(
                "dex.quote.path_too_short: path must have at least 2 tokens",
                None,
            ));
        }

        // ── Resolve network settings ──────────────────────────────────────────
        let network_passphrase = self.profile.network_passphrase.as_str();
        let rpc_url = self.profile.rpc_url.as_str();

        // ── Resolve pinned router address ─────────────────────────────────────
        let (router_address, _) = pinned_router_for_network(&args.chain_id).map_err(|e| {
            rmcp::ErrorData::invalid_params(format!("dex.quote.unrecognised_network: {e}"), None)
        })?;

        // ── Canonicalise path ─────────────────────────────────────────────────
        let canonical_path = canonicalise_path(&args.path, network_passphrase).map_err(|e| {
            rmcp::ErrorData::invalid_params(format!("dex.quote.canonicalisation_failed: {e}"), None)
        })?;

        // ── Fetch on-chain quote ──────────────────────────────────────────────
        let quote = fetch_quote(
            router_address,
            qty_in,
            &canonical_path,
            rpc_url,
            network_passphrase,
        )
        .await
        .map_err(|e| {
            rmcp::ErrorData::internal_error(format!("dex.quote.fetch_failed: {e}"), None)
        })?;

        // expected_out and amounts are core i128 values returned by the dex
        // crate; they are stringified AT THIS MCP BOUNDARY (the core
        // QuoteResult type itself stays i128).
        let expected_out = quote.expected_out().unwrap_or(0);
        let amounts_wire: Vec<String> = quote.amounts.iter().map(ToString::to_string).collect();
        let path_redacted: Vec<String> = canonical_path
            .iter()
            .map(|a| redact_strkey_first5_last5(a))
            .collect();

        let resp = json!({
            "status": "ok",
            "qty_in": args.qty_in,
            "expected_out": expected_out.to_string(),
            "amounts": amounts_wire,
            "path_redacted": path_redacted,
            "router_redacted": redact_strkey_first5_last5(router_address),
        });
        let json_str = serde_json::to_string_pretty(&resp).unwrap_or_else(|_| "{}".to_owned());
        Ok(CallToolResult::success(vec![Content::text(json_str)]))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test helpers
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(any(test, feature = "test-helpers"))]
impl WalletServer {
    /// Calls `stellar_dex_quote` with the given args, bypassing the rmcp
    /// transport.
    ///
    /// Integration-test entry point for handler-level checks, including the
    /// MCP-tool-layer decimal-string wire acceptance test.
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Feature gate
    ///
    /// Gated on the `test-helpers` feature or `#[cfg(test)]`.
    #[doc(hidden)]
    pub async fn call_stellar_dex_quote(
        &self,
        args: DexQuoteArgs,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.stellar_dex_quote(Parameters(args)).await
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
        reason = "test-only fixture construction"
    )]
    use super::{DexQuoteArgs, DexTradeArgs};

    #[test]
    fn router_redaction_format() {
        let addr = "CCJUD55AG6W5HAI5LRVNKAE5WDP5XGZBUDS5WNTIVDU7O264UZZE7BRD";
        let redacted = stellar_agent_core::observability::redact_strkey_first5_last5(addr);
        assert!(redacted.starts_with("CCJUD"), "must start with first 5");
        assert!(redacted.contains("7BRD"), "must contain last chars");
        assert!(!redacted.contains(addr), "full addr must not appear");
    }

    // ── DexTradeArgs: decimal-string wire ─────────────────────────────────────

    #[test]
    fn dex_trade_args_deserialises_string_amounts_above_2_pow_53() {
        let json = serde_json::json!({
            "chain_id": "stellar:testnet",
            "from_address": "CAJJZSGMMM3PD7N33TAPHGBUGTB43OC73HVIK2L2G6BNGGGYOSSYBXBD",
            "qty_in": "9007199254740993",
            "qty_out_min": "1",
            "path": ["native", "native"],
        });
        let args: DexTradeArgs = serde_json::from_value(json).expect("deserialise");
        assert_eq!(args.qty_in, "9007199254740993");
        let parsed: i128 = args.qty_in.parse().expect("parse");
        assert_eq!(parsed, 9_007_199_254_740_993_i128);
    }

    #[test]
    fn dex_trade_args_rejects_raw_json_number_for_qty_in() {
        let json = serde_json::json!({
            "chain_id": "stellar:testnet",
            "from_address": "CAJJZSGMMM3PD7N33TAPHGBUGTB43OC73HVIK2L2G6BNGGGYOSSYBXBD",
            "qty_in": 250_000_000,
            "qty_out_min": "1",
            "path": ["native", "native"],
        });
        let result: Result<DexTradeArgs, _> = serde_json::from_value(json);
        assert!(
            result.is_err(),
            "a raw JSON number for qty_in must be rejected (String-typed field)"
        );
    }

    #[test]
    fn dex_trade_args_rejects_raw_json_number_for_qty_out_min() {
        let json = serde_json::json!({
            "chain_id": "stellar:testnet",
            "from_address": "CAJJZSGMMM3PD7N33TAPHGBUGTB43OC73HVIK2L2G6BNGGGYOSSYBXBD",
            "qty_in": "250000000",
            "qty_out_min": 1,
            "path": ["native", "native"],
        });
        let result: Result<DexTradeArgs, _> = serde_json::from_value(json);
        assert!(
            result.is_err(),
            "a raw JSON number for qty_out_min must be rejected (String-typed field)"
        );
    }

    /// Pins toolset-dispatch eligibility: the args struct must round-trip
    /// through `serde_json::from_value`, the mechanism the toolset matrix
    /// dispatcher uses. String-typed amount fields round-trip
    /// unconditionally; a raw i128 field fails for values beyond the range
    /// `serde_json::Number` can hold.
    #[test]
    fn dex_trade_args_round_trips_through_serde_json_from_value() {
        let value = serde_json::json!({
            "chain_id": "stellar:testnet",
            "from_address": "CAJJZSGMMM3PD7N33TAPHGBUGTB43OC73HVIK2L2G6BNGGGYOSSYBXBD",
            "qty_in": "170141183460469231731687303715884105727",
            "qty_out_min": "0",
            "path": ["native", "native"],
        });
        let args: DexTradeArgs = serde_json::from_value(value).expect("from_value must succeed");
        assert_eq!(args.qty_in.parse::<i128>().expect("parse"), i128::MAX);
    }

    // ── DexQuoteArgs: decimal-string wire ─────────────────────────────────────

    #[test]
    fn dex_quote_args_deserialises_string_qty_in() {
        let json = serde_json::json!({
            "chain_id": "stellar:testnet",
            "qty_in": "9007199254740993",
            "path": ["native", "native"],
        });
        let args: DexQuoteArgs = serde_json::from_value(json).expect("deserialise");
        assert_eq!(args.qty_in, "9007199254740993");
    }

    #[test]
    fn dex_quote_args_rejects_raw_json_number() {
        let json = serde_json::json!({
            "chain_id": "stellar:testnet",
            "qty_in": 250_000_000,
            "path": ["native", "native"],
        });
        let result: Result<DexQuoteArgs, _> = serde_json::from_value(json);
        assert!(
            result.is_err(),
            "a raw JSON number for qty_in must be rejected (String-typed field)"
        );
    }

    #[test]
    fn dex_quote_args_round_trips_through_serde_json_from_value() {
        let value = serde_json::json!({
            "chain_id": "stellar:testnet",
            "qty_in": "170141183460469231731687303715884105727",
            "path": ["native", "native"],
        });
        let args: DexQuoteArgs = serde_json::from_value(value).expect("from_value must succeed");
        assert_eq!(args.qty_in.parse::<i128>().expect("parse"), i128::MAX);
    }

    // ── Output-shape: expected_out / amounts stringify exactly at the boundary ─

    /// Mirrors the exact `expected_out.to_string()` / `amounts.iter().map(...)`
    /// projection used in `stellar_dex_quote`'s success response, proving the
    /// values above `2^53` round-trip byte-for-byte and serialise as JSON
    /// strings rather than JSON numbers.
    #[test]
    fn dex_quote_output_amounts_stringify_exactly_above_2_pow_53() {
        let expected_out: i128 = 9_007_199_254_740_993_i128;
        let amounts: Vec<i128> = vec![250_000_000_i128, expected_out, i128::MAX];
        let amounts_wire: Vec<String> = amounts.iter().map(ToString::to_string).collect();

        assert_eq!(amounts_wire[1], "9007199254740993");
        assert_eq!(amounts_wire[2], i128::MAX.to_string());

        let expected_out_wire = expected_out.to_string();
        let value = serde_json::json!({
            "expected_out": expected_out_wire,
            "amounts": amounts_wire,
        });
        assert!(
            value["expected_out"].is_string(),
            "expected_out must serialise as a JSON string: {value}"
        );
        assert!(
            value["amounts"][1].is_string(),
            "each amounts element must serialise as a JSON string: {value}"
        );
        assert_eq!(
            value["expected_out"].as_str().expect("string"),
            "9007199254740993"
        );
    }
}
