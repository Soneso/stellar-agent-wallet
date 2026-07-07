//! `stellar-agent trade` subcommand — Soroswap swap adapter.
//!
//! # What this command does
//!
//! Submits a `swap_exact_tokens_for_tokens` call to the Soroswap ROUTER-DIRECT
//! path through the wallet's smart-account.  Enforces the ordered trust gate:
//!
//! 1. Venue allowlist — Soroswap router for the network (fail-closed).
//! 2. Router WASM-hash pin — two-RPC check against pinned value.
//! 3. Slippage re-verify — on-chain `router_get_amounts_out` re-fetch
//!    immediately before signing.
//!
//! All gate steps run inside `DexSwapAdapter::submit` (no inline duplication).
//!
//! # Operator policy evaluation
//!
//! Loads the operator-signed `PolicyEngineV1` (if `profile.policy.engine == V1`)
//! or a permissive `NoopPolicyEngine` (if `Noop`) and evaluates before submit.
//! Mirrors the MCP `dispatch_gate` pattern.  Fail-closed on build failures.
//!
//! # Output
//!
//! JSON by default.  Returns `0` on success, `1` on error.

use clap::Args;
use serde_json::json;
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::WalletError;
use stellar_agent_core::policy::{Decision, McpToolRegistration, ToolDescriptor};
use stellar_agent_core::profile::loader as profile_loader;
use stellar_agent_core::profile::schema::Profile;

use crate::commands::policy_engine::build_v1_policy_engine;

use stellar_agent_defi::adapter::{DefiAdapter, DefiAdapterCtx};
use stellar_agent_defi::dispatch::{GateOutcome, dispatch_gate, require_approval_error};
use stellar_agent_defi::pins::DefiContractPin;
use stellar_agent_dex::{
    abi::TradeArgs as DexTradeArgs, adapter::DexSwapAdapter, pins::pinned_router_for_network,
};
use stellar_agent_network::{StellarRpcClient, init_platform_keyring_store, signer_from_keyring};

use crate::common::render::render_json;

// ─────────────────────────────────────────────────────────────────────────────
// Argument types
// ─────────────────────────────────────────────────────────────────────────────

/// Successful `trade` operation result.
#[derive(Debug, serde::Serialize)]
pub struct TradeResult {
    /// Human-readable summary of the swap.
    pub summary: String,
    /// Redacted router address (first-5-last-5).
    pub router_address_redacted: String,
}

/// Arguments for the `stellar-agent trade` subcommand.
///
/// # Examples
///
/// ```text
/// stellar-agent trade \
///   --from CAJJZSGMMM3PD7N33TAPHGBUGTB43OC73HVIK2L2G6BNGGGYOSSYBXBD \
///   --amount-in 10000000 \
///   --amount-out-min 9800000 \
///   --path CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC \
///   --path CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA \
///   --profile default
/// ```
#[derive(Debug, Args)]
pub struct TradeArgs {
    /// Profile name to load (default: "default").
    #[arg(long, default_value = "default")]
    pub profile: String,

    /// Wallet smart-account address submitting the swap (C-strkey).
    #[arg(long)]
    pub from: String,

    /// Exact input token amount in the asset's native base unit (7-decimal i128).
    #[arg(long)]
    pub amount_in: i128,

    /// Minimum output token amount (absolute floor; NOT a percent).
    #[arg(long)]
    pub amount_out_min: i128,

    /// Swap path (repeatable): first is the input token, last is the output token.
    ///
    /// Each value is a C-strkey, `native`, or `CODE:ISSUER` classic asset.
    /// Must have at least 2 elements.
    #[arg(long = "path", num_args = 1)]
    pub path: Vec<String>,

    /// Swap deadline as a Unix timestamp (seconds).
    ///
    /// When absent, defaults to `now + 300s`.
    #[arg(long)]
    pub deadline: Option<u64>,

    /// Secondary RPC URL for the two-RPC router WASM-hash cross-check.
    #[arg(long)]
    pub secondary_rpc_url: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Run
// ─────────────────────────────────────────────────────────────────────────────

/// Dispatches the `trade` subcommand.
///
/// Returns `0` on success, `1` on error.
pub async fn run(args: &TradeArgs) -> i32 {
    run_with_dependencies(
        args,
        |name| profile_loader::load(name, None),
        init_platform_keyring_store,
    )
    .await
}

/// Testable core of [`run`] with the profile loader and the platform-keyring
/// initialiser injected.
///
/// Production callers use [`run`], which supplies the real profile loader and
/// [`init_platform_keyring_store`]. Tests substitute an in-memory profile and a
/// spy initialiser to assert the keyring store is registered before signer
/// resolution without touching the OS keychain.
async fn run_with_dependencies<LoadProfile, InitKeyring>(
    args: &TradeArgs,
    load_profile: LoadProfile,
    init_keyring: InitKeyring,
) -> i32
where
    LoadProfile: Fn(&str) -> Result<Profile, profile_loader::ProfileLoadError>,
    InitKeyring: Fn() -> Result<(), WalletError>,
{
    // ── Load profile ──────────────────────────────────────────────────────────
    let profile = match load_profile(&args.profile) {
        Ok(p) => p,
        Err(e) => {
            render_json(&Envelope::<()>::err_raw(
                "profile.load_failed",
                format!("{e}"),
            ));
            return 1;
        }
    };

    // ── Initialise platform keyring store ─────────────────────────────────────
    // The keyring signer loaded before signing requires the process-global
    // default store.  Ordered after the profile load so a missing profile never
    // triggers the store registration.
    if let Err(e) = init_keyring() {
        render_json(&Envelope::<()>::err(&e));
        return 1;
    }

    // ── Resolve network settings ──────────────────────────────────────────────
    let rpc_url = profile.rpc_url.as_str();
    let network_passphrase = profile.network_passphrase.as_str();
    let chain_id = profile.chain_id.caip2_str();

    // ── Resolve pinned router address and WASM hash ───────────────────────────
    let (router_address, router_wasm_hash) = match pinned_router_for_network(chain_id) {
        Ok(r) => r,
        Err(e) => {
            render_json(&Envelope::<()>::err_raw(
                "dex.unrecognised_network",
                format!("{e}"),
            ));
            return 1;
        }
    };

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

    // ── Operator policy evaluation ────────────────────────────────────────────
    let policy_engine = match build_v1_policy_engine("trade", &profile.policy.engine, &profile) {
        Ok(pe) => pe,
        Err(msg) => {
            render_json(&Envelope::<()>::err_raw("policy.engine_unavailable", msg));
            return 1;
        }
    };
    let dex_trade_reg = McpToolRegistration {
        name: "stellar_dex_trade",
        destructive_hint: true,
        read_only_hint: false,
        chain_id_required: true,
    };
    let mut tool_descriptor = ToolDescriptor::from_registration(&dex_trade_reg);
    tool_descriptor.chain_id = chain_id.to_owned();
    let policy_args = json!({
        "chain_id": chain_id,
        "from_address": args.from,
        "amount_in": args.amount_in,
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
                "trade operation denied by operator policy".to_owned(),
            ));
            return 1;
        }
        Ok(Decision::RequireApproval(_)) => {
            render_json(&Envelope::<()>::err_raw(
                "policy.approval_required",
                "trade operation requires approval; use the MCP server for two-phase approval"
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
    let witness = match dispatch_gate("trade", router_address) {
        Ok(GateOutcome::Allow(w)) => w,
        Ok(GateOutcome::RequireApproval) => {
            render_json(&Envelope::<()>::err_raw(
                "policy.approval_required",
                require_approval_error(),
            ));
            return 1;
        }
        Err(e) => {
            render_json(&Envelope::<()>::err_raw("dex.gate_error", format!("{e}")));
            return 1;
        }
    };

    // ── Build DexTradeArgs for the adapter ───────────────────────────────────
    let trade_args = DexTradeArgs {
        from_address: args.from.clone(),
        amount_in: args.amount_in,
        amount_out_min: args.amount_out_min,
        path: args.path.clone(),
        deadline: args.deadline,
    };

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
    // The synthetic DefiContractPin carries the router address and network;
    // the actual WASM-hash pin is verified inside DexSwapAdapter::submit.
    // Hash resolved per-network from pinned_router_for_network — not hardcoded.
    let router_pin = DefiContractPin::new(
        "soroswap",
        "router-direct",
        "default",
        chain_id,
        router_address,
        router_wasm_hash,
        "bb90a65",
    );

    let timeout = std::time::Duration::from_secs(60);
    let ctx = DefiAdapterCtx::new_with_submit_ctx(
        "default",
        &router_pin,
        &primary_rpc,
        Some(&signer_handle as &(dyn stellar_agent_network::Signer + Send + Sync)),
        Some(network_passphrase),
        Some(chain_id),
        secondary_rpc.as_ref(),
        Some(timeout),
    );

    // ── Delegate to DexSwapAdapter::submit (witness consumed inside) ──────────
    // NO inline HostFunction build or submit_signed_invoke here. All execution
    // logic lives in DexSwapAdapter::submit.
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
            let router_redacted =
                stellar_agent_core::observability::redact_strkey_first5_last5(router_address);
            render_json(&Envelope::ok(TradeResult {
                summary: format!(
                    "Swap {} (min out: {}) via Soroswap ({}-hop) on {}",
                    args.amount_in,
                    args.amount_out_min,
                    args.path.len().saturating_sub(1),
                    chain_id,
                ),
                router_address_redacted: router_redacted,
            }));
            0
        }
        Err(e) => {
            render_json(&Envelope::<()>::err_raw("dex.submit_failed", e.to_string()));
            1
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
        reason = "test-only assertions"
    )]

    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use stellar_agent_core::error::AuthError;

    use super::*;

    // ── keyring store initialisation ordering ─────────────────────────────────

    #[tokio::test]
    async fn run_initialises_keyring_store_before_signer_resolution() {
        // The keyring initialiser must be invoked on the run() path, after the
        // profile load and before the signer is resolved from the keyring.
        // Both dependencies are injected, so no OS keychain or on-disk profile
        // is touched and no process-global keyring store is registered — hence
        // this test needs no `#[serial]`.  The injected initialiser returns an
        // error so the run bails at that step, which proves the store
        // initialisation gates the path ahead of signer resolution.
        let profile_loaded = Arc::new(AtomicBool::new(false));
        let init_invoked = Arc::new(AtomicBool::new(false));

        let loaded_writer = Arc::clone(&profile_loaded);
        let loaded_reader = Arc::clone(&profile_loaded);
        let init_writer = Arc::clone(&init_invoked);

        let args = TradeArgs {
            profile: "keyring-order-test".to_owned(),
            from: String::new(),
            amount_in: 0,
            amount_out_min: 0,
            path: Vec::new(),
            deadline: None,
            secondary_rpc_url: None,
        };

        let code = run_with_dependencies(
            &args,
            move |_name| {
                loaded_writer.store(true, Ordering::SeqCst);
                Ok(Profile::builder_testnet_named(
                    "keyring-order-test",
                    "stellar-agent-signer",
                    "keyring-order-test",
                    "stellar-agent-nonce",
                    "keyring-order-test",
                )
                .build())
            },
            move || {
                assert!(
                    loaded_reader.load(Ordering::SeqCst),
                    "profile must be loaded before the keyring store is initialised"
                );
                init_writer.store(true, Ordering::SeqCst);
                Err(WalletError::Auth(AuthError::KeyringNotFound {
                    name: "keyring-order-test-sentinel".to_owned(),
                }))
            },
        )
        .await;

        assert!(
            init_invoked.load(Ordering::SeqCst),
            "run must initialise the keyring store before resolving the signer"
        );
        assert_eq!(
            code, 1,
            "run must surface the keyring init failure instead of reaching signer resolution"
        );
    }
}
