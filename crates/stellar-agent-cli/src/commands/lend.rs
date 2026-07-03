//! `stellar-agent lend` subcommand — Blend protocol supply/borrow/repay/withdraw.
//!
//! # What this command does
//!
//! Submits one or more supply/borrow/repay/withdraw requests to a Blend v1/v2
//! pool through the wallet's smart-account.  Enforces the ordered trust gate:
//! pool WASM-hash pin, Reflector oracle allowlist, oracle staleness.
//!
//! # Ordered trust gate (LOAD-BEARING)
//!
//! 1. `verify_blend_pool_wasm` — two-RPC pin check against v1/v2 pool WASM set.
//! 2. `read_pool_oracle_address` + oracle-allowlist check.
//! 3. `query_oracle_lastprice_timestamps` + staleness evaluation.
//!
//! Only after all three steps pass, the `lend` verb is dispatched via
//! `dispatch_gate` and `BlendLendAdapter::submit` is called.
//!
//! # Operator policy evaluation
//!
//! The CLI loads the operator-signed `PolicyEngineV1` from the profile (if
//! `policy.engine = "v1"`) or falls back to `NoopPolicyEngine` (if `"noop"`).
//! A `ToolDescriptor` for `stellar_blend_lend` (destructive, not read-only) is
//! evaluated BEFORE submit, honouring Deny / RequireApproval exactly as the MCP
//! tool does via `WalletServer::dispatch_gate`.  The verb-registry
//! `dispatch_gate` call remains (capability-witness seam); the policy evaluation
//! runs alongside it.  Both paths enforce the operator policy document.
//!
//! # Output
//!
//! JSON by default.  Returns `0` on success, `1` on error.

use clap::{Args, ValueEnum};
use serde_json::json;
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::policy::{Decision, McpToolRegistration, ToolDescriptor};
use stellar_agent_core::profile::loader as profile_loader;

use crate::commands::policy_engine::build_v1_policy_engine;

use stellar_agent_blend::{
    abi::{BlendRequest, LendArgs as BlendLendArgs, RequestType},
    adapter::BlendLendAdapter,
    oracle::OracleStalenessEvalExt,
    oracle::OracleStalenessSnapshot,
    oracle_fetch::{
        PoolOracleFetchError, query_oracle_lastprice_timestamps, read_pool_oracle_address,
    },
    pins::{
        BlendPoolWasmSet, blend_pool_wasm_set_pubnet, blend_pool_wasm_set_testnet,
        is_oracle_in_allowlist, verify_blend_pool_wasm,
    },
};
use stellar_agent_defi::adapter::{DefiAdapter, DefiAdapterCtx};
use stellar_agent_defi::dispatch::{GateOutcome, dispatch_gate, require_approval_error};
use stellar_agent_defi::pins::DefiContractPin;
use stellar_agent_network::{StellarRpcClient, signer_from_keyring};

use crate::common::render::render_json;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Default oracle staleness threshold in seconds.
const DEFAULT_MAX_STALENESS_SECS: u64 = stellar_agent_blend::oracle::DEFAULT_MAX_STALENESS_SECS;

// ─────────────────────────────────────────────────────────────────────────────
// Argument types
// ─────────────────────────────────────────────────────────────────────────────

/// The operation type for a single Blend request.
#[derive(Debug, Clone, ValueEnum)]
pub enum LendOp {
    /// Supply tokens to the pool's reserve (RequestType 0).
    Supply,
    /// Withdraw tokens from the pool's reserve (RequestType 1).
    Withdraw,
    /// Supply tokens as collateral (RequestType 2).
    #[value(name = "supply-collateral")]
    SupplyCollateral,
    /// Withdraw tokens from collateral (RequestType 3).
    #[value(name = "withdraw-collateral")]
    WithdrawCollateral,
    /// Borrow tokens from the pool's reserve (RequestType 4).
    Borrow,
    /// Repay a borrow (RequestType 5).
    Repay,
}

impl LendOp {
    fn to_request_type(&self) -> RequestType {
        match self {
            LendOp::Supply => RequestType::Supply,
            LendOp::Withdraw => RequestType::Withdraw,
            LendOp::SupplyCollateral => RequestType::SupplyCollateral,
            LendOp::WithdrawCollateral => RequestType::WithdrawCollateral,
            LendOp::Borrow => RequestType::Borrow,
            LendOp::Repay => RequestType::Repay,
        }
    }
}

/// Successful `lend` operation result.
#[derive(Debug, serde::Serialize)]
pub struct LendResult {
    /// Summary of the lend operation.
    pub summary: String,
    /// Oracle staleness age in seconds (display only).
    pub oracle_staleness_secs: Option<u64>,
}

/// Arguments for the `stellar-agent lend` subcommand.
///
/// # Examples
///
/// ```text
/// stellar-agent lend \
///   --pool CCEBVDYM32YNYCVNRXQKDFFPISJJCV557CDZEIRBEE4NCV4KHPQ44HGF \
///   --from CAJJZSGMMM3PD7N33TAPHGBUGTB43OC73HVIK2L2G6BNGGGYOSSYBXBD \
///   --op supply \
///   --asset CAQCFVLOBK5GIULPNZRGATJJMIZL5BSP7X5YJVMGCPTUEPFM4AVSRCJU \
///   --amount 500000000 \
///   --profile default
/// ```
#[derive(Debug, Args)]
pub struct LendArgs {
    /// Profile name to load (default: "default").
    #[arg(long, default_value = "default")]
    pub profile: String,

    /// The Blend pool contract address (C-strkey).
    #[arg(long)]
    pub pool: String,

    /// The wallet smart-account address (C-strkey).
    #[arg(long)]
    pub from: String,

    /// The operation type.
    #[arg(long, value_enum)]
    pub op: LendOp,

    /// The asset contract address (C-strkey).
    #[arg(long)]
    pub asset: String,

    /// Amount in the asset's native base unit (integer, no decimals).
    #[arg(long)]
    pub amount: i128,

    /// Override oracle staleness check (default false).
    #[arg(long, default_value_t = false)]
    pub override_oracle_staleness: bool,

    /// Secondary RPC URL for two-RPC pool WASM-hash cross-check.
    #[arg(long)]
    pub secondary_rpc_url: Option<String>,

    /// Custom maximum staleness threshold in seconds (default 600).
    ///
    /// Set to `0` to force a staleness block.
    #[arg(long)]
    pub max_staleness_secs: Option<u64>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Run
// ─────────────────────────────────────────────────────────────────────────────

/// Dispatches the `lend` subcommand.
///
/// Returns `0` on success, `1` on error.
pub async fn run(args: &LendArgs) -> i32 {
    // ── Load profile ──────────────────────────────────────────────────────────
    let profile = match profile_loader::load(&args.profile, None) {
        Ok(p) => p,
        Err(e) => {
            render_json(&Envelope::<()>::err_raw(
                "profile.load_failed",
                format!("{e}"),
            ));
            return 1;
        }
    };

    // ── Resolve network settings ──────────────────────────────────────────────
    let rpc_url = profile.rpc_url.as_str();
    let network_passphrase = profile.network_passphrase.as_str();
    let chain_id = profile.chain_id.caip2_str();
    let is_testnet = chain_id.contains("testnet");

    // ── Construct the BlendRequest ────────────────────────────────────────────
    let request_type = args.op.to_request_type();
    let blend_requests = vec![BlendRequest::new(
        request_type,
        args.asset.clone(),
        args.amount,
    )];

    // ── Build RPCs ────────────────────────────────────────────────────────────
    let primary_rpc = match StellarRpcClient::new(rpc_url) {
        Ok(r) => r,
        Err(e) => {
            render_json(&Envelope::<()>::err_raw("rpc.init_failed", format!("{e}")));
            return 1;
        }
    };
    let secondary_rpc: Option<StellarRpcClient> = match args
        .secondary_rpc_url
        .as_deref()
        .map(StellarRpcClient::new)
        .transpose()
    {
        Ok(s) => s,
        Err(e) => {
            render_json(&Envelope::<()>::err_raw(
                "rpc.secondary_init_failed",
                format!("{e}"),
            ));
            return 1;
        }
    };

    let wasm_set: BlendPoolWasmSet = if is_testnet {
        blend_pool_wasm_set_testnet()
    } else {
        blend_pool_wasm_set_pubnet()
    };

    // ── ORDERED TRUST GATE step 1: verify pool WASM hash ─────────────────────
    if let Err(e) =
        verify_blend_pool_wasm(&args.pool, &wasm_set, &primary_rpc, secondary_rpc.as_ref()).await
    {
        render_json(&Envelope::<()>::err_raw(
            "blend.pool_wasm_pin_failed",
            format!("pool WASM hash mismatch: {e}"),
        ));
        return 1;
    }

    // ── ORDERED TRUST GATE step 2: read pool oracle, check allowlist ──────────
    let oracle_address = match read_pool_oracle_address(&args.pool, &primary_rpc).await {
        Ok(addr) => addr,
        Err(e) => {
            render_json(&Envelope::<()>::err_raw(
                "blend.oracle_fetch_failed",
                format!("could not read pool oracle: {e}"),
            ));
            return 1;
        }
    };

    let network_label = if is_testnet { "testnet" } else { "pubnet" };
    if !is_oracle_in_allowlist(&oracle_address, network_label) {
        render_json(&Envelope::<()>::err_raw(
            "blend.oracle_not_allowlisted",
            "pool oracle is not in the Reflector allowlist".to_owned(),
        ));
        return 1;
    }

    // ── ORDERED TRUST GATE step 3: oracle staleness ───────────────────────────
    let max_staleness = args
        .max_staleness_secs
        .unwrap_or(DEFAULT_MAX_STALENESS_SECS);

    let timestamps_result = query_oracle_lastprice_timestamps(
        &oracle_address,
        std::slice::from_ref(&args.asset),
        rpc_url,
        network_passphrase,
    )
    .await;

    let staleness_view = match timestamps_result {
        Ok(ts) if !ts.is_empty() => {
            OracleStalenessSnapshot::new(&oracle_address, &ts, max_staleness)
        }
        Ok(_) => Some(OracleStalenessSnapshot::unavailable(
            &oracle_address,
            max_staleness,
        )),
        Err(PoolOracleFetchError::OraclePriceAbsent) => Some(OracleStalenessSnapshot::unavailable(
            &oracle_address,
            max_staleness,
        )),
        Err(e) => {
            render_json(&Envelope::<()>::err_raw(
                "blend.oracle_price_fetch_failed",
                format!("{e}"),
            ));
            return 1;
        }
    };

    let staleness_eval = OracleStalenessEvalExt::evaluate(
        staleness_view
            .as_ref()
            .map(|v| v as &dyn stellar_agent_blend::oracle::OracleStalenessView),
        args.override_oracle_staleness,
    );
    if let Err(reason) = staleness_eval {
        render_json(&Envelope::<()>::err_raw(
            "oracle.staleness_exceeded",
            reason.to_string(),
        ));
        return 1;
    }

    // ── Operator policy evaluation (mirrors MCP dispatch_gate) ───────────────
    // Load the operator-signed PolicyEngineV1 (if profile.policy.engine == V1)
    // or a permissive NoopPolicyEngine (if Noop), then evaluate before submit.
    // This mirrors WalletServer::dispatch_gate.
    //
    // The ToolDescriptor matches the `stellar_blend_lend` MCP tool registration:
    // destructive_hint=true, read_only_hint=false, chain_id_required=true.
    let policy_engine = match build_v1_policy_engine("lend", &profile.policy.engine, &profile) {
        Ok(pe) => pe,
        Err(msg) => {
            // Fail-closed: a configured-but-unbuildable policy refuses the
            // value-moving lend op rather than silently running permissive.
            render_json(&Envelope::<()>::err_raw("policy.engine_unavailable", msg));
            return 1;
        }
    };
    // Construct the ToolDescriptor from its static registration record (the
    // preferred constructor per ToolDescriptor::from_registration rustdoc).
    // chain_id is set after construction as it is resolved at dispatch time.
    let blend_lend_reg = McpToolRegistration {
        name: "stellar_blend_lend",
        destructive_hint: true,
        read_only_hint: false,
        chain_id_required: true,
    };
    let mut tool_descriptor = ToolDescriptor::from_registration(&blend_lend_reg);
    tool_descriptor.chain_id = chain_id.to_owned();
    let policy_args = json!({
        "chain_id": chain_id,
        "pool_address": args.pool,
        "from_address": args.from,
    });
    match policy_engine.evaluate(
        &tool_descriptor,
        &policy_args,
        &profile,
        None,
        None,
        None,
        None,
        None,
    ) {
        Ok(Decision::Allow) => {}
        Ok(Decision::Deny(reason)) => {
            render_json(&Envelope::<()>::err_raw(
                format!("policy.deny.{}", reason.code()),
                "lend operation denied by operator policy".to_owned(),
            ));
            return 1;
        }
        Ok(Decision::RequireApproval(_)) => {
            render_json(&Envelope::<()>::err_raw(
                "policy.approval_required",
                "lend operation requires approval; use the MCP server for two-phase approval"
                    .to_owned(),
            ));
            return 1;
        }
        Ok(_) => {
            render_json(&Envelope::<()>::err_raw(
                "policy.unexpected_decision",
                "unexpected policy decision — operation refused (fail-closed)".to_owned(),
            ));
            return 1;
        }
        Err(e) => {
            render_json(&Envelope::<()>::err_raw(
                "policy.engine_required",
                format!("{e}"),
            ));
            return 1;
        }
    }

    // ── DeFi dispatch gate (capability-witness seam) ──────────────────────────
    // The verb-registry dispatch_gate produces the SubmitWitness that is the
    // only valid input to BlendLendAdapter::submit.
    let witness = match dispatch_gate("lend", &args.pool) {
        Ok(GateOutcome::Allow(w)) => w,
        Ok(GateOutcome::RequireApproval) => {
            render_json(&Envelope::<()>::err_raw(
                "policy.approval_required",
                require_approval_error(),
            ));
            return 1;
        }
        Err(e) => {
            render_json(&Envelope::<()>::err_raw("blend.gate_error", format!("{e}")));
            return 1;
        }
    };

    // ── Build preview summary (for the result envelope) ───────────────────────
    let oracle_staleness_secs = staleness_view.as_ref().and_then(|v| {
        use stellar_agent_blend::oracle::OracleStalenessView;
        v.worst_case_age_secs()
    });

    let blend_preview = stellar_agent_blend::preview::build_blend_lend_preview(
        &args.pool,
        &args.from,
        &blend_requests,
        stellar_agent_blend::preview::HfStatus::Unavailable,
        oracle_staleness_secs,
    );
    let preview_text = stellar_agent_blend::preview::preview_summary(&blend_preview);

    // ── Load signer ───────────────────────────────────────────────────────────
    let signer_entry_ref = &profile.mcp_signer_default;
    let expected_g = signer_entry_ref.account.as_str();
    let signer_handle = match signer_from_keyring(signer_entry_ref, expected_g).await {
        Ok(s) => s,
        Err(e) => {
            render_json(&Envelope::<()>::err(&e));
            return 1;
        }
    };

    // ── Construct DefiAdapterCtx with full submit context ─────────────────────
    let pool_pin = DefiContractPin::new(
        "blend", "v2", "default", chain_id, &args.pool,
        [0u8; 32], // hash already verified above by verify_blend_pool_wasm
        "ba22b48",
    );

    let timeout = std::time::Duration::from_secs(60);
    let ctx = DefiAdapterCtx::new_with_submit_ctx(
        "default",
        &pool_pin,
        &primary_rpc,
        Some(&signer_handle as &(dyn stellar_agent_network::Signer + Send + Sync)),
        Some(network_passphrase),
        Some(chain_id),
        secondary_rpc.as_ref(),
        Some(timeout),
    );

    // ── Build BlendLendArgs for the adapter ───────────────────────────────────
    let lend_args = BlendLendArgs {
        pool_address: args.pool.clone(),
        from_address: args.from.clone(),
        requests: blend_requests,
        override_oracle_staleness: args.override_oracle_staleness,
    };

    // ── Delegate to BlendLendAdapter::submit (witness consumed inside) ────────
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
            render_json(&Envelope::ok(LendResult {
                summary: preview_text,
                oracle_staleness_secs,
            }));
            0
        }
        Err(e) => {
            render_json(&Envelope::<()>::err_raw(
                "blend.submit_failed",
                e.to_string(),
            ));
            1
        }
    }
}
