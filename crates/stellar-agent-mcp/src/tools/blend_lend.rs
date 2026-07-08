//! `stellar_blend_lend` MCP tool — Blend protocol supply/borrow/repay/withdraw.
//!
//! # What this tool does
//!
//! Implements the `lend` verb for the Blend lending protocol.  The tool runs
//! the **ORDERED TRUST GATE**:
//!
//! 1. `verify_blend_pool_wasm` — two-RPC pin check against the pinned v1/v2
//!    pool WASM hash set.
//! 2. Oracle-allowlist check — read `PoolConfig.oracle`, refuse unless the
//!    oracle address is in the Reflector allowlist.
//! 3. Oracle staleness — construct `OracleStalenessSnapshot` from oracle
//!    `lastprice` timestamps; evaluate `OracleStalenessEvalExt`.
//!
//! After all three gate steps pass, calls `dispatch_gate("lend", ...)` to
//! obtain a `SubmitWitness`, constructs a `DefiAdapterCtx` with full submit
//! context, and delegates to `BlendLendAdapter::submit(args, ctx, witness)`.
//! There is NO duplicated `HostFunction` build or `submit_signed_invoke` call
//! in this file; that logic lives exclusively in the adapter.
//!
//! # Simulate-authoritative health-factor guard
//!
//! The Blend pool's on-chain `submit` enforces the health-factor check. A
//! successful simulate of the actual `submit` IS the fail-closed health gate.
//! The predicted post-op HF is rendered in the typed preview for display only —
//! it NEVER gates signing.
//!
//! # Policy evaluation
//!
//! The MCP tool runs `WalletServer::dispatch_gate_with_value` (which evaluates
//! the operator `PolicyEngineV1` document: Deny / RequireApproval / chain_id /
//! counterparty / value effects) before signing.  The typed
//! [`stellar_agent_core::policy::v1::ValueLeg`]s sized from `blend_requests`
//! (via `blend_value_legs`) are the SAME requests later placed into `LendArgs`
//! — the single-decode invariant.  The CLI `lend` subcommand mirrors this by
//! loading the profile's signed policy engine and evaluating it before submit.
//! Both routes delegate submit to `BlendLendAdapter::submit`.
//!
//! # Liquidation guard
//!
//! Liquidation request types (discriminants 6-9) are rejected by the `lend`
//! verb with a typed error pointing to the dedicated `liquidate` verb.  The
//! `lend` verb permits only lending operations (0-5).

use rmcp::{
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Content},
    schemars, serde, tool, tool_router,
};
use serde_json::json;
use stellar_agent_mcp_macros::mcp_tool_router;

use stellar_agent_blend::{
    abi::{BlendRequest, LendArgs, RequestType},
    adapter::BlendLendAdapter,
    oracle::{OracleStalenessEvalExt, OracleStalenessSnapshot},
    oracle_fetch::{
        PoolOracleFetchError, query_oracle_lastprice_timestamps, read_pool_oracle_address,
    },
    pins::{
        BlendPoolWasmSet, blend_pool_wasm_set_pubnet, blend_pool_wasm_set_testnet,
        is_oracle_in_allowlist, verify_blend_pool_wasm,
    },
    preview::{build_blend_lend_preview, preview_summary},
    value::blend_value_legs,
};
use stellar_agent_core::policy::v1::{ValueClass, ValueEffects};
use stellar_agent_defi::adapter::{DefiAdapter, DefiAdapterCtx};
use stellar_agent_defi::dispatch::{GateOutcome, dispatch_gate, require_approval_error};
use stellar_agent_defi::pins::DefiContractPin;
use stellar_agent_network::{StellarRpcClient, signer_from_keyring};

use crate::server::WalletServer;
use crate::tools::common::DispatchOutcome;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Default oracle staleness threshold in seconds.
///
/// Tighter than the Blend pool's on-chain 24h threshold.
const DEFAULT_MAX_STALENESS_SECS: u64 = stellar_agent_blend::oracle::DEFAULT_MAX_STALENESS_SECS;

// ─────────────────────────────────────────────────────────────────────────────
// Argument types
// ─────────────────────────────────────────────────────────────────────────────

/// Request entry for the `stellar_blend_lend` MCP tool.
///
/// Each entry describes one Blend pool operation.
#[derive(Debug, Clone, serde::Deserialize, schemars::JsonSchema)]
#[serde(crate = "rmcp::serde")]
pub struct BlendLendRequest {
    /// Request type discriminant (0-9). See `RequestType` variants.
    ///
    /// | Value | Operation |
    /// |---|---|
    /// | 0 | Supply |
    /// | 1 | Withdraw |
    /// | 2 | SupplyCollateral |
    /// | 3 | WithdrawCollateral |
    /// | 4 | Borrow |
    /// | 5 | Repay |
    pub request_type: u32,
    /// Asset contract address (C-strkey) or liquidatee address for liquidation ops.
    pub address: String,
    /// Raw token quantity in the asset's native base unit (7-decimal i128),
    /// as a decimal string (e.g. `"250000000"`). A raw JSON number is
    /// rejected — `serde_json::from_value` backs numbers with `f64`, which
    /// cannot represent an i128 exactly above `2^53`.
    ///
    /// This is the direct `Request.amount` field sent to the Blend `submit`
    /// function on-chain. It carries no unit label (not "N XLM" format).
    /// Named `qty` so the dual-unit trigger tokens `amount/fee/balance/charge`
    /// do not apply to this raw on-chain integer.
    pub qty: String,
}

/// Arguments for the `stellar_blend_lend` MCP tool.
///
/// Submits one or more requests to a Blend v1/v2 pool.  The tool validates the
/// pool's WASM hash, oracle allowlist, and oracle staleness before signing.
///
/// # Behaviour
///
/// - Exposes a typed `Vec<Request>` preview; no raw-vector or opaque-calldata
///   signing.
/// - Verifies the pool WASM hash before the oracle read.
/// - The health-factor guard is simulate-authoritative.
/// - Oracle staleness is an ordered gate step with an opt-in override.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(crate = "rmcp::serde")]
pub struct BlendLendArgs {
    /// CAIP-2 chain identifier: `stellar:testnet` or `stellar:mainnet`.
    pub chain_id: String,
    /// The Blend pool contract address (C-strkey).
    pub pool_address: String,
    /// The wallet smart-account address submitting the operation (C-strkey).
    pub from_address: String,
    /// The list of requests to submit.
    pub requests: Vec<BlendLendRequest>,
    /// Override oracle staleness check (default `false`).
    ///
    /// When `true`, the operation proceeds even if the Reflector timestamp
    /// exceeds the 600s threshold; a distinct `oracle.staleness_overridden`
    /// audit event is emitted unconditionally.  The pin-verify and
    /// oracle-allowlist refusals are NON-overridable regardless.
    #[serde(default)]
    pub override_oracle_staleness: bool,
    /// Optional secondary RPC URL for the two-RPC pool WASM-hash cross-check.
    ///
    /// When absent, the primary RPC is used for both checks (degraded security).
    /// Configuring a distinct secondary RPC is strongly recommended for mainnet.
    #[serde(default)]
    pub secondary_rpc_url: Option<String>,
    /// Custom maximum staleness threshold in seconds (default 600).
    ///
    /// Set to a very small value (e.g. `0`) to force a staleness block.
    #[serde(default)]
    pub max_staleness_secs: Option<u64>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool router impl block
// ─────────────────────────────────────────────────────────────────────────────

/// Submits one or more supply/borrow/repay/withdraw requests to a Blend lending
/// pool.
///
/// # Ordered trust gate (LOAD-BEARING)
///
/// The gate runs as `?`-early-return SEQUENCING before any signing:
///
/// 1. `verify_blend_pool_wasm` — two-RPC pin check.
/// 2. `read_pool_oracle_address` + oracle-allowlist check.
/// 3. `query_oracle_lastprice_timestamps` + `OracleStalenessEvalExt::evaluate`.
///
/// Only after all three pass, `dispatch_gate("lend", ...)` is called and the
/// `SubmitWitness` is passed to `BlendLendAdapter::submit`.
///
/// # Tool annotations
///
/// - `destructive_hint = true` — signs and submits a transaction.
/// - `read_only_hint = false` — modifies on-chain state.
///
/// # Errors
///
/// Returns a tool-level error when:
/// - The pool WASM hash does not match the pinned v1/v2 set.
/// - The pool's oracle is not in the Reflector allowlist.
/// - Oracle price data is stale and no override is set.
/// - Oracle price data is unavailable.
/// - A request type is a liquidation discriminant (6-9); use the
///   `liquidate` verb.
/// - `dispatch_gate` returns `UnknownVerb`.
/// - The policy engine returns `Deny`.
/// - The smart-account submit fails.
#[mcp_tool_router]
#[tool_router(router = blend_lend_tool_router, vis = "pub(crate)")]
impl WalletServer {
    #[mcp_tool_item(
        name = "stellar_blend_lend",
        destructive_hint = true,
        read_only_hint = false,
        chain_id_required = true,
        value_kind = "moves_value"
    )]
    #[tool(
        name = "stellar_blend_lend",
        description = "Submit supply/borrow/repay/withdraw requests to a Blend v1/v2 \
                       lending pool. Enforces ordered trust gate: pool WASM-hash pin, \
                       Reflector oracle allowlist, oracle staleness. Signs and submits \
                       via smart-account. destructive_hint=true, read_only_hint=false.",
        annotations(destructive_hint = true, read_only_hint = false)
    )]
    async fn stellar_blend_lend(
        &self,
        Parameters(args): Parameters<BlendLendArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        // ── Parse and validate requests (single decode; feeds BOTH the
        // value-carrying policy gate below and `LendArgs` handed to the
        // adapter further down — see the single-decode invariant) ────────────
        let mut blend_requests: Vec<BlendRequest> = Vec::with_capacity(args.requests.len());
        for (idx, req) in args.requests.iter().enumerate() {
            let rt = RequestType::try_from_u32(req.request_type).map_err(|e| {
                rmcp::ErrorData::invalid_params(format!("blend.invalid_request_type: {e}"), None)
            })?;
            // The `lend` verb permits only lending operations (0-5).
            // Liquidation discriminants 6-9 require the dedicated `liquidate`
            // verb.
            if let Err(e) = rt.assert_lend_verb_allowed() {
                return Ok(crate::tools::common::business_error_result(
                    "blend.liquidation_not_permitted_on_lend_verb",
                    e.to_string(),
                ));
            }
            let qty = crate::tools::amount_wire::parse_i128_field(
                &format!("requests[{idx}].qty"),
                &req.qty,
            )?;
            blend_requests.push(BlendRequest::new(rt, req.address.clone(), qty));
        }
        if blend_requests.is_empty() {
            return Err(rmcp::ErrorData::invalid_params(
                "blend.empty_requests: at least one request is required",
                None,
            ));
        }

        // ── Policy gate (value-carrying; dispatch_gate prerequisite) ──────────
        // `value_legs` is built from the SAME `blend_requests` vector passed to
        // `LendArgs` below, satisfying the single-decode invariant: the effect
        // sized by policy is exactly the effect signed. `account_view` /
        // `identity_view` are `None` — the `minimum_reserve` / `home_domain`
        // criteria fail closed on this tool pending account-view wiring, which
        // is acceptable for this step (Blend legs are token debits, not native
        // reserve debits, in the common case).
        let value_legs = blend_value_legs(&blend_requests, &args.pool_address);
        let args_value = json!({
            "chain_id": args.chain_id,
            "pool_address": args.pool_address,
            "from_address": args.from_address,
        });
        let dispatch_outcome = match self
            .dispatch_gate_with_value(
                "stellar_blend_lend",
                &args_value,
                &args.chain_id,
                ValueClass::Value(ValueEffects::new(value_legs)),
                None,
                None,
            )
            .await
        {
            Ok(o) => o,
            Err(e) => return e.into_result(),
        };

        // Single-shot DeFi tool: RequireApproval is not supported (no two-phase
        // split). Return fail-closed error rather than silently proceeding.
        if matches!(dispatch_outcome, DispatchOutcome::RequireApproval(_)) {
            return Ok(crate::tools::common::single_shot_require_approval_error());
        }

        // ── Resolve network ───────────────────────────────────────────────────
        let network = self.profile.network_passphrase.as_str();
        let is_testnet = self.profile.chain_id.caip2_str().contains("testnet");

        // ── ORDERED TRUST GATE ────────────────────────────────────────────────
        // Step 1: verify pool WASM hash (two-RPC cross-check).
        // The secondary RPC is threaded at this gate site, not via
        // DefiAdapterCtx.
        let rpc_url = self.profile.rpc_url.as_str();
        let primary_rpc = StellarRpcClient::new(rpc_url).map_err(|e| {
            rmcp::ErrorData::internal_error(format!("blend.rpc_init_failed: {e}"), None)
        })?;
        let secondary_rpc: Option<StellarRpcClient> = args
            .secondary_rpc_url
            .as_deref()
            .map(|url| {
                StellarRpcClient::new(url).map_err(|e| {
                    rmcp::ErrorData::internal_error(
                        format!("blend.secondary_rpc_init_failed: {e}"),
                        None,
                    )
                })
            })
            .transpose()?;

        let wasm_set: BlendPoolWasmSet = if is_testnet {
            blend_pool_wasm_set_testnet()
        } else {
            blend_pool_wasm_set_pubnet()
        };

        if let Err(e) = verify_blend_pool_wasm(
            &args.pool_address,
            &wasm_set,
            &primary_rpc,
            secondary_rpc.as_ref(),
        )
        .await
        {
            tracing::warn!(
                event = "blend.pool_wasm_pin_failed",
                pool_redacted = stellar_agent_core::observability::redact_strkey_first5_last5(
                    &args.pool_address
                ),
                error = %e,
            );
            return Ok(crate::tools::common::business_error_result(
                "blend.pool_wasm_pin_failed",
                "pool WASM hash mismatch",
            ));
        }

        // Step 2: read pool oracle, check allowlist.
        let oracle_address = match read_pool_oracle_address(&args.pool_address, &primary_rpc).await
        {
            Ok(addr) => addr,
            Err(e) => {
                tracing::warn!(
                    event = "blend.oracle_fetch_failed",
                    pool_redacted = stellar_agent_core::observability::redact_strkey_first5_last5(
                        &args.pool_address
                    ),
                    error = %e,
                );
                return Ok(crate::tools::common::business_error_result(
                    "blend.oracle_fetch_failed",
                    "could not read pool oracle address",
                ));
            }
        };

        let network_label = if is_testnet { "testnet" } else { "pubnet" };
        if !is_oracle_in_allowlist(&oracle_address, network_label) {
            tracing::warn!(
                event = "blend.oracle_not_allowlisted",
                oracle_redacted =
                    stellar_agent_core::observability::redact_strkey_first5_last5(&oracle_address),
                pool_redacted = stellar_agent_core::observability::redact_strkey_first5_last5(
                    &args.pool_address
                ),
            );
            return Ok(crate::tools::common::business_error_result(
                "blend.oracle_not_allowlisted",
                "pool oracle is not in the Reflector allowlist",
            ));
        }

        // Step 3: query oracle lastprice timestamps + evaluate staleness.
        // Collect the distinct asset addresses from the requests.
        let asset_addresses: Vec<String> = blend_requests
            .iter()
            .filter(|r| r.is_asset_address())
            .map(|r| r.address.clone())
            .collect::<std::collections::HashSet<String>>()
            .into_iter()
            .collect();

        let max_staleness = args
            .max_staleness_secs
            .unwrap_or(DEFAULT_MAX_STALENESS_SECS);

        let timestamps_result =
            query_oracle_lastprice_timestamps(&oracle_address, &asset_addresses, rpc_url, network)
                .await;

        let staleness_view: Option<OracleStalenessSnapshot> = match timestamps_result {
            Ok(ts) if !ts.is_empty() => {
                OracleStalenessSnapshot::new(&oracle_address, &ts, max_staleness)
            }
            Ok(_) => Some(OracleStalenessSnapshot::unavailable(
                &oracle_address,
                max_staleness,
            )),
            Err(PoolOracleFetchError::OraclePriceAbsent) => Some(
                OracleStalenessSnapshot::unavailable(&oracle_address, max_staleness),
            ),
            Err(e) => {
                tracing::warn!(
                    event = "blend.oracle_price_fetch_failed",
                    error = %e,
                );
                Some(OracleStalenessSnapshot::unavailable(
                    &oracle_address,
                    max_staleness,
                ))
            }
        };

        // Evaluate staleness — INDEPENDENT of simulate success.
        let staleness_eval = OracleStalenessEvalExt::evaluate(
            staleness_view
                .as_ref()
                .map(|v| v as &dyn stellar_agent_blend::oracle::OracleStalenessView),
            args.override_oracle_staleness,
        );
        if let Err(staleness_reason) = staleness_eval {
            tracing::warn!(
                event = "oracle.staleness_exceeded",
                reason = %staleness_reason,
            );
            return Ok(crate::tools::common::business_error_result(
                "oracle.staleness_exceeded",
                staleness_reason.to_string(),
            ));
        }

        // ── DeFi dispatch gate ────────────────────────────────────────────────
        // The dispatch_gate call proves the lend verb is registered and produces
        // the SubmitWitness that is the only valid input to submit.
        let gate_result = dispatch_gate("lend", &args.pool_address);
        let witness = match gate_result {
            Ok(GateOutcome::Allow(w)) => w,
            Ok(GateOutcome::RequireApproval) => {
                return Ok(crate::tools::common::business_error_result(
                    "policy.approval_required",
                    require_approval_error(),
                ));
            }
            Err(e) => {
                return Err(rmcp::ErrorData::internal_error(
                    format!("blend.gate_error: {e}"),
                    None,
                ));
            }
        };

        // ── Build typed preview for the response ──────────────────────────────
        let oracle_staleness_secs = staleness_view.as_ref().and_then(|v| {
            use stellar_agent_blend::oracle::OracleStalenessView;
            v.worst_case_age_secs()
        });

        let blend_preview = build_blend_lend_preview(
            &args.pool_address,
            &args.from_address,
            &blend_requests,
            stellar_agent_blend::preview::HfStatus::Unavailable,
            oracle_staleness_secs,
        );
        let preview_text = preview_summary(&blend_preview);

        tracing::info!(
            verb = "lend",
            pool_redacted = stellar_agent_core::observability::redact_strkey_first5_last5(
                &args.pool_address
            ),
            from_redacted = stellar_agent_core::observability::redact_strkey_first5_last5(
                &args.from_address
            ),
            preview = %preview_text,
            request_id = witness.request_id(),
            "Blend lend: ordered gate passed, submitting via adapter"
        );

        // ── Load signer from keyring ──────────────────────────────────────────
        // The profile's default signer is used; the MCP tool's signing key is
        // the G-strkey of the wallet's registered default signer.  Multi-signer
        // profile selection is out of scope for this tool.
        let signer_entry_ref = &self.profile.mcp_signer_default;
        let expected_g_strkey = signer_entry_ref.account.as_str();
        let signer_handle = match signer_from_keyring(signer_entry_ref, expected_g_strkey).await {
            Ok(h) => h,
            Err(_) => {
                return Ok(crate::tools::common::business_error_result(
                    "blend.signer_load_failed",
                    "could not load signer from keyring",
                ));
            }
        };

        let timeout = crate::tools::common::submit_timeout(&self.profile);

        // ── Construct the DefiAdapterCtx with full submit context ─────────────
        // The pin is a synthetic DefiContractPin carrying just the pool address
        // and network; the actual WASM-hash pin has already been verified by
        // verify_blend_pool_wasm above.
        let pool_pin = DefiContractPin::new(
            "blend",
            "v2",
            "default",
            &args.chain_id,
            &args.pool_address,
            [0u8; 32],         // hash already verified above; not re-checked in adapter
            "blend-contracts", // abi_source_provenance
        );

        let ctx = DefiAdapterCtx::new_with_submit_ctx(
            "default",
            &pool_pin,
            &primary_rpc,
            Some(&signer_handle as &(dyn stellar_agent_network::Signer + Send + Sync)),
            Some(network),
            Some(args.chain_id.as_str()),
            secondary_rpc.as_ref(),
            Some(timeout),
        );

        // ── Build LendArgs for the adapter ────────────────────────────────────
        let lend_args = LendArgs {
            pool_address: args.pool_address.clone(),
            from_address: args.from_address.clone(),
            requests: blend_requests,
            override_oracle_staleness: args.override_oracle_staleness,
        };

        // ── Delegate to BlendLendAdapter::submit (witness consumed inside) ────
        let adapter = BlendLendAdapter::new();
        let submit_result = adapter
            .submit(
                &lend_args as &(dyn std::any::Any + Send + Sync),
                &ctx,
                witness,
            )
            .await;

        match submit_result {
            Ok(()) => {
                // blend_preview.requests carries BlendRequestEntry.amount as a
                // core i128; the field is projected to a decimal string AT
                // THIS MCP BOUNDARY (the stellar-agent-blend core type itself
                // stays i128).
                let requests_wire: Vec<serde_json::Value> = blend_preview
                    .requests
                    .iter()
                    .map(|r| {
                        json!({
                            "verb": r.verb,
                            "address_redacted": r.address_redacted,
                            "address_label": r.address_label,
                            "amount": r.amount.to_string(),
                        })
                    })
                    .collect();
                let resp = json!({
                    "status": "submitted",
                    "preview": {
                        "pool_address_redacted": blend_preview.pool_address_redacted,
                        "from_address_redacted": blend_preview.from_address_redacted,
                        "requests": requests_wire,
                        "health_factor": "simulate_authoritative",
                        "oracle_staleness_secs": oracle_staleness_secs,
                    },
                    "summary": preview_text,
                });
                let json_str =
                    serde_json::to_string_pretty(&resp).unwrap_or_else(|_| "{}".to_owned());
                Ok(CallToolResult::success(vec![Content::text(json_str)]))
            }
            Err(e) => Ok(crate::tools::common::business_error_result(
                "blend.submit_failed",
                e.to_string(),
            )),
        }
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
    use super::{BlendLendArgs, BlendLendRequest};

    #[test]
    fn redact_strkey_format() {
        let addr = "CCEBVDYM32YNYCVNRXQKDFFPISJJCV557CDZEIRBEE4NCV4KHPQ44HGF";
        let redacted = stellar_agent_core::observability::redact_strkey_first5_last5(addr);
        assert!(redacted.starts_with("CCEBV"), "must start with first 5");
        assert!(redacted.contains("4HGF"), "must contain last chars");
        assert!(!redacted.contains(addr), "full addr must not appear");
    }

    // ── BlendLendRequest.qty: decimal-string wire ─────────────────────────────

    #[test]
    fn blend_lend_request_deserialises_string_qty_above_2_pow_53() {
        let json = serde_json::json!({
            "request_type": 0,
            "address": "CAQCFVLOBK5GIULPNZRGATJJMIZL5BSP7X5YJVMGCPTUEPFM4AVSRCJU",
            "qty": "9007199254740993",
        });
        let req: BlendLendRequest = serde_json::from_value(json).expect("deserialise");
        assert_eq!(req.qty, "9007199254740993");
        assert_eq!(
            req.qty.parse::<i128>().expect("parse"),
            9_007_199_254_740_993_i128
        );
    }

    #[test]
    fn blend_lend_request_rejects_raw_json_number_for_qty() {
        let json = serde_json::json!({
            "request_type": 0,
            "address": "CAQCFVLOBK5GIULPNZRGATJJMIZL5BSP7X5YJVMGCPTUEPFM4AVSRCJU",
            "qty": 500_000_000,
        });
        let result: Result<BlendLendRequest, _> = serde_json::from_value(json);
        assert!(
            result.is_err(),
            "a raw JSON number for qty must be rejected (String-typed field)"
        );
    }

    /// Pins toolset-dispatch eligibility for the enclosing `BlendLendArgs`
    /// (the toolset matrix dispatcher deserialises via
    /// `serde_json::from_value`, which cannot decode an i128 field).
    #[test]
    fn blend_lend_args_round_trips_through_serde_json_from_value() {
        let value = serde_json::json!({
            "chain_id": "stellar:testnet",
            "pool_address": "CCEBVDYM32YNYCVNRXQKDFFPISJJCV557CDZEIRBEE4NCV4KHPQ44HGF",
            "from_address": "CAJJZSGMMM3PD7N33TAPHGBUGTB43OC73HVIK2L2G6BNGGGYOSSYBXBD",
            "requests": [
                {
                    "request_type": 0,
                    "address": "CAQCFVLOBK5GIULPNZRGATJJMIZL5BSP7X5YJVMGCPTUEPFM4AVSRCJU",
                    "qty": "170141183460469231731687303715884105727",
                }
            ],
        });
        let args: BlendLendArgs = serde_json::from_value(value).expect("from_value must succeed");
        assert_eq!(
            args.requests[0].qty.parse::<i128>().expect("parse"),
            i128::MAX
        );
    }

    /// Mirrors the exact `requests_wire` projection built in
    /// `stellar_blend_lend`'s success response, proving `BlendRequestEntry.amount`
    /// (a core i128) stringifies exactly above `2^53` and serialises as a JSON
    /// string at the MCP boundary — the core `stellar-agent-blend` type
    /// remains i128.
    #[test]
    fn blend_lend_output_requests_amount_stringifies_exactly_above_2_pow_53() {
        use stellar_agent_blend::abi::{BlendRequest, RequestType};
        use stellar_agent_blend::preview::{HfStatus, build_blend_lend_preview};

        const POOL: &str = "CCEBVDYM32YNYCVNRXQKDFFPISJJCV557CDZEIRBEE4NCV4KHPQ44HGF";
        const FROM: &str = "CAJJZSGMMM3PD7N33TAPHGBUGTB43OC73HVIK2L2G6BNGGGYOSSYBXBD";
        const ASSET: &str = "CAQCFVLOBK5GIULPNZRGATJJMIZL5BSP7X5YJVMGCPTUEPFM4AVSRCJU";

        let request = BlendRequest::new(RequestType::Supply, ASSET, 9_007_199_254_740_993_i128);
        let preview = build_blend_lend_preview(POOL, FROM, &[request], HfStatus::NotArmed, None);

        let requests_wire: Vec<serde_json::Value> = preview
            .requests
            .iter()
            .map(|r| {
                serde_json::json!({
                    "verb": r.verb,
                    "address_redacted": r.address_redacted,
                    "address_label": r.address_label,
                    "amount": r.amount.to_string(),
                })
            })
            .collect();

        assert!(
            requests_wire[0]["amount"].is_string(),
            "amount must serialise as a JSON string: {:?}",
            requests_wire[0]
        );
        assert_eq!(
            requests_wire[0]["amount"].as_str().expect("string"),
            "9007199254740993"
        );
    }

    #[test]
    fn blend_lend_request_vec_index_error_names_the_failing_entry() {
        // Exercises parse_i128_field's per-request naming convention as used
        // by the handler's `requests[{idx}].qty` error format.
        let err = crate::tools::amount_wire::parse_i128_field("requests[2].qty", "not-a-number")
            .unwrap_err();
        let msg = err.message.to_string();
        assert!(
            msg.contains("requests[2].qty"),
            "error must name the failing request index: {msg}"
        );
    }
}
