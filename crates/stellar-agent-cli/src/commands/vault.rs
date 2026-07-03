//! `stellar-agent vault` subcommand — DeFindex vault deposit and withdraw.
//!
//! # What this command does
//!
//! Submits a deposit or withdraw operation to a DeFindex vault through the
//! wallet's smart-account.  Enforces the ordered trust gate: vault WASM-hash
//! pin, upgradable-flag check, role disclosure.
//!
//! # Ordered trust gate (LOAD-BEARING)
//!
//! 1. `verify_defindex_vault_wasm` — two-RPC pin check against the pinned
//!    DeFindex vault WASM hash (same hash for testnet and pubnet).
//! 2. `read_vault_upgradable_flag` — refuse if `upgradable:true`.
//! 3. `read_vault_roles` — read the four role addresses; compute
//!    self-managed vs delegated management mode.
//!
//! Only after all three steps pass, the `vault` verb is dispatched via
//! `dispatch_gate` and `DefindexVaultAdapter::submit` is called.
//!
//! # Upgradable posture
//!
//! Default: refuse `upgradable:true` vaults.  Use `--override-upgradable` to
//! proceed; a distinct `vault.upgradable_override` audit event is emitted
//! unconditionally (EMIT-THEN-RETURN).
//!
//! # min_out requirement
//!
//! `--amounts-min` (deposit) and `--min-amounts-out` (withdraw) are REQUIRED
//! arguments.  Absent = structural pre-sign refuse.
//!
//! # Operator policy evaluation
//!
//! Mirrors the MCP `dispatch_gate` policy path: loads the operator-signed
//! `PolicyEngineV1` (if `policy.engine = "v1"`) or `NoopPolicyEngine` (if
//! `"noop"`).  Fail-closed: a configured-but-unbuildable policy refuses the
//! value-moving vault op.
//!
//! # Output
//!
//! JSON by default.  Returns `0` on success, `1` on error.

use clap::{Args, Subcommand};
use serde_json::json;
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::policy::{Decision, McpToolRegistration, ToolDescriptor};
use stellar_agent_core::profile::loader as profile_loader;

use crate::commands::policy_engine::build_v1_policy_engine;

use stellar_agent_defi::adapter::{DefiAdapter, DefiAdapterCtx};
use stellar_agent_defi::dispatch::{GateOutcome, dispatch_gate, require_approval_error};
use stellar_agent_defi::pins::DefiContractPin;
use stellar_agent_defindex::{
    abi::{VaultDepositArgs, VaultWithdrawArgs},
    adapter::DefindexVaultAdapter,
    criteria::upgradable::UpgradableEvalExt,
    pins::{DEFINDEX_VAULT_WASM_HASH, is_blend_strategy, verify_defindex_vault_wasm},
    preview::VaultOperationPreview,
    roles::read_vault_roles,
    storage::{read_vault_assets, read_vault_upgradable_flag},
};
use stellar_agent_network::{
    StellarRpcClient, WasmHashFetch, fetch_contract_wasm_hash, signer_from_keyring,
};

use crate::common::render::render_json;

// ─────────────────────────────────────────────────────────────────────────────
// Argument types
// ─────────────────────────────────────────────────────────────────────────────

/// Top-level arguments for the `stellar-agent vault` subcommand.
#[derive(Debug, Args)]
pub struct VaultArgs {
    /// Sub-action: deposit or withdraw.
    #[command(subcommand)]
    pub action: VaultAction,
}

/// Sub-actions under `stellar-agent vault`.
#[derive(Debug, Subcommand)]
pub enum VaultAction {
    /// Deposit assets into a DeFindex vault.
    Deposit(VaultDepositCliArgs),
    /// Withdraw assets from a DeFindex vault by redeeming shares.
    Withdraw(VaultWithdrawCliArgs),
}

/// Arguments for `stellar-agent vault deposit`.
///
/// # Examples
///
/// ```text
/// stellar-agent vault deposit \
///   --vault CBMVK2JK6NTOT2O4HNQAIQFJY232BHKGLIMXDVQVHIIZKDACXDFZDWHN \
///   --from  CAJJZSGMMM3PD7N33TAPHGBUGTB43OC73HVIK2L2G6BNGGGYOSSYBXBD \
///   --amounts-desired 1000000000 \
///   --amounts-min     900000000 \
///   --profile default
/// ```
#[derive(Debug, Args)]
pub struct VaultDepositCliArgs {
    /// Profile name to load (default: "default").
    #[arg(long, default_value = "default")]
    pub profile: String,

    /// The DeFindex vault contract address (C-strkey).
    #[arg(long)]
    pub vault: String,

    /// The wallet smart-account address submitting the deposit (C-strkey).
    #[arg(long)]
    pub from: String,

    /// Desired deposit amounts per asset in declaration order (i128, one per
    /// asset).  Pass multiple values: `--amounts-desired 100 200`.
    #[arg(long, num_args = 1..)]
    pub amounts_desired: Vec<i128>,

    /// Minimum accepted amounts per asset (i128, same length as
    /// `amounts_desired`).  Absence = structural pre-sign refuse.  Zero floor =
    /// no slippage protection.
    #[arg(long, num_args = 1..)]
    pub amounts_min: Vec<i128>,

    /// Auto-invest immediately after deposit.
    #[arg(long, default_value_t = false)]
    pub invest: bool,

    /// Override the upgradable-vault refusal.
    ///
    /// When set, the operation proceeds on an `upgradable:true` vault; a
    /// distinct `vault.upgradable_override` audit event is emitted.
    #[arg(long, default_value_t = false)]
    pub override_upgradable: bool,

    /// Secondary RPC URL for the two-RPC WASM-hash cross-check.
    #[arg(long)]
    pub secondary_rpc_url: Option<String>,
}

/// Arguments for `stellar-agent vault withdraw`.
///
/// # Examples
///
/// ```text
/// stellar-agent vault withdraw \
///   --vault  CBMVK2JK6NTOT2O4HNQAIQFJY232BHKGLIMXDVQVHIIZKDACXDFZDWHN \
///   --from   CAJJZSGMMM3PD7N33TAPHGBUGTB43OC73HVIK2L2G6BNGGGYOSSYBXBD \
///   --shares 5000000 \
///   --min-amounts-out 4500000 \
///   --profile default
/// ```
#[derive(Debug, Args)]
pub struct VaultWithdrawCliArgs {
    /// Profile name to load (default: "default").
    #[arg(long, default_value = "default")]
    pub profile: String,

    /// The DeFindex vault contract address (C-strkey).
    #[arg(long)]
    pub vault: String,

    /// The wallet smart-account address submitting the withdrawal (C-strkey).
    #[arg(long)]
    pub from: String,

    /// Number of vault shares to redeem (i128 raw on-chain value).
    #[arg(long)]
    pub shares: i128,

    /// Minimum amounts to receive per asset (i128, one per asset).
    /// Absence = structural pre-sign refuse.
    #[arg(long, num_args = 1..)]
    pub min_amounts_out: Vec<i128>,

    /// Override the upgradable-vault refusal.
    #[arg(long, default_value_t = false)]
    pub override_upgradable: bool,

    /// Secondary RPC URL for the two-RPC WASM-hash cross-check.
    #[arg(long)]
    pub secondary_rpc_url: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Run
// ─────────────────────────────────────────────────────────────────────────────

/// Dispatches the `vault` subcommand.
///
/// Returns `0` on success, `1` on error.
pub async fn run(args: &VaultArgs) -> i32 {
    match &args.action {
        VaultAction::Deposit(deposit_args) => run_deposit(deposit_args).await,
        VaultAction::Withdraw(withdraw_args) => run_withdraw(withdraw_args).await,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Deposit path
// ─────────────────────────────────────────────────────────────────────────────

async fn run_deposit(args: &VaultDepositCliArgs) -> i32 {
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

    let rpc_url = profile.rpc_url.as_str();
    let network_passphrase = profile.network_passphrase.as_str();
    let chain_id = profile.chain_id.caip2_str();

    // ── Structural validation ─────────────────────────────────────────────────
    let vault_args = VaultDepositArgs {
        vault_address: args.vault.clone(),
        amounts_desired: args.amounts_desired.clone(),
        amounts_min: args.amounts_min.clone(),
        from_address: args.from.clone(),
        invest: args.invest,
        override_upgradable: args.override_upgradable,
    };
    if let Err(e) = vault_args.validate_structure() {
        render_json(&Envelope::<()>::err_raw(
            "vault.invalid_args",
            format!("{e}"),
        ));
        return 1;
    }

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

    // ── ORDERED TRUST GATE step 1: verify vault WASM hash ────────────────────
    // The vault WASM hash is identical on testnet and pubnet.
    if let Err(e) =
        verify_defindex_vault_wasm(&args.vault, &primary_rpc, secondary_rpc.as_ref()).await
    {
        render_json(&Envelope::<()>::err_raw(
            "vault.wasm_pin_failed",
            format!("vault WASM hash mismatch: {e}"),
        ));
        return 1;
    }

    // ── ORDERED TRUST GATE step 2: read upgradable flag ──────────────────────
    let is_upgradable = match read_vault_upgradable_flag(&args.vault, &primary_rpc).await {
        Ok(v) => v,
        Err(e) => {
            render_json(&Envelope::<()>::err_raw(
                "vault.upgradable_read_failed",
                format!("could not read upgradable flag: {e}"),
            ));
            return 1;
        }
    };

    // ── ORDERED TRUST GATE step 3: read roles ────────────────────────────────
    let roles = match read_vault_roles(&args.vault, &primary_rpc).await {
        Ok(r) => r,
        Err(e) => {
            render_json(&Envelope::<()>::err_raw(
                "vault.roles_read_failed",
                format!("could not read vault roles: {e}"),
            ));
            return 1;
        }
    };

    let management_mode = roles.management_mode(&args.from);
    let roles_summary = roles.disclosure_summary();

    // ── ORDERED TRUST GATE step 4: read assets + validate count + strategy ───
    let mut assets = match read_vault_assets(&args.vault, &primary_rpc).await {
        Ok(a) => a,
        Err(e) => {
            render_json(&Envelope::<()>::err_raw(
                "vault.assets_read_failed",
                format!("could not read vault assets: {e}"),
            ));
            return 1;
        }
    };

    // Validate amounts_min length against the PIN-VERIFIED on-chain asset count.
    if let Err(e) = vault_args.validate_against_asset_count(assets.len()) {
        render_json(&Envelope::<()>::err_raw(
            "vault.asset_count_mismatch",
            e.to_string(),
        ));
        return 1;
    }

    // Blend-strategy detection via WASM-hash match.
    for asset in &mut assets {
        for strategy in &mut asset.strategies {
            match fetch_contract_wasm_hash(&primary_rpc, secondary_rpc.as_ref(), &strategy.address)
                .await
            {
                Ok(WasmHashFetch::Wasm(hash)) => {
                    strategy.is_blend_strategy = is_blend_strategy(&hash, chain_id);
                }
                Ok(_) | Err(_) => {
                    strategy.is_blend_strategy = false;
                }
            }
        }
    }

    // ── ORDERED TRUST GATE step 5: mode-aware upgradable evaluation ──────────
    if let Err(reason) =
        UpgradableEvalExt::evaluate(is_upgradable, args.override_upgradable, &management_mode)
    {
        render_json(&Envelope::<()>::err_raw(
            "vault.upgradable_refused",
            reason.to_string(),
        ));
        return 1;
    }

    // ── Operator policy evaluation (mirrors MCP dispatch_gate) ───────────────
    let policy_engine = match build_v1_policy_engine("vault", &profile.policy.engine, &profile) {
        Ok(pe) => pe,
        Err(msg) => {
            render_json(&Envelope::<()>::err_raw("policy.engine_unavailable", msg));
            return 1;
        }
    };
    let vault_deposit_reg = McpToolRegistration {
        name: "stellar_defindex_vault_deposit",
        destructive_hint: true,
        read_only_hint: false,
        chain_id_required: true,
    };
    let mut tool_descriptor = ToolDescriptor::from_registration(&vault_deposit_reg);
    tool_descriptor.chain_id = chain_id.to_owned();
    let policy_args = json!({
        "chain_id": chain_id,
        "vault_address": args.vault,
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
                "vault deposit denied by operator policy".to_owned(),
            ));
            return 1;
        }
        Ok(Decision::RequireApproval(_)) => {
            render_json(&Envelope::<()>::err_raw(
                "policy.approval_required",
                "vault deposit requires approval; use the MCP server for two-phase approval"
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
    let witness = match dispatch_gate("vault", &args.vault) {
        Ok(GateOutcome::Allow(w)) => w,
        Ok(GateOutcome::RequireApproval) => {
            render_json(&Envelope::<()>::err_raw(
                "policy.approval_required",
                require_approval_error(),
            ));
            return 1;
        }
        Err(e) => {
            render_json(&Envelope::<()>::err_raw("vault.gate_error", format!("{e}")));
            return 1;
        }
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

    // ── Build VaultOperationPreview ───────────────────────────────────────────
    let preview = VaultOperationPreview::from_deposit(
        &vault_args,
        chain_id,
        is_upgradable,
        roles.clone(),
        assets,
    );
    let preview_summary = preview.summary();

    // ── Build submit context ──────────────────────────────────────────────────
    let vault_pin = DefiContractPin::new(
        "defindex",
        "v1",
        "default",
        chain_id,
        &args.vault,
        DEFINDEX_VAULT_WASM_HASH,
        "f8b5c61",
    );
    let timeout = std::time::Duration::from_secs(60);
    let ctx = DefiAdapterCtx::new_with_submit_ctx(
        "default",
        &vault_pin,
        &primary_rpc,
        Some(&signer_handle as &(dyn stellar_agent_network::Signer + Send + Sync)),
        Some(network_passphrase),
        Some(chain_id),
        secondary_rpc.as_ref(),
        Some(timeout),
    );

    // ── Delegate to DefindexVaultAdapter::submit ──────────────────────────────
    let adapter = DefindexVaultAdapter::new();
    let submit_result = adapter
        .submit(
            &vault_args as &(dyn std::any::Any + Send + Sync),
            &ctx,
            witness,
        )
        .await;

    match submit_result {
        Ok(()) => {
            render_json(&Envelope::ok(json!({
                "status": "submitted",
                "action": "deposit",
                "vault_address_redacted": stellar_agent_core::observability::redact_strkey_first5_last5(&args.vault),
                "from_address_redacted": stellar_agent_core::observability::redact_strkey_first5_last5(&args.from),
                "preview": preview_summary,
                "roles": roles_summary,
                "management_mode": format!("{management_mode:?}"),
                "upgradable": is_upgradable,
            })));
            0
        }
        Err(e) => {
            render_json(&Envelope::<()>::err_raw(
                "vault.submit_failed",
                format!("{e}"),
            ));
            1
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Withdraw path
// ─────────────────────────────────────────────────────────────────────────────

async fn run_withdraw(args: &VaultWithdrawCliArgs) -> i32 {
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

    let rpc_url = profile.rpc_url.as_str();
    let network_passphrase = profile.network_passphrase.as_str();
    let chain_id = profile.chain_id.caip2_str();

    // ── Structural validation ─────────────────────────────────────────────────
    let vault_args = VaultWithdrawArgs {
        vault_address: args.vault.clone(),
        withdraw_shares: args.shares,
        min_amounts_out: args.min_amounts_out.clone(),
        from_address: args.from.clone(),
        override_upgradable: args.override_upgradable,
    };
    if let Err(e) = vault_args.validate_structure() {
        render_json(&Envelope::<()>::err_raw(
            "vault.invalid_args",
            format!("{e}"),
        ));
        return 1;
    }

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

    // ── ORDERED TRUST GATE step 1: verify vault WASM hash ────────────────────
    if let Err(e) =
        verify_defindex_vault_wasm(&args.vault, &primary_rpc, secondary_rpc.as_ref()).await
    {
        render_json(&Envelope::<()>::err_raw(
            "vault.wasm_pin_failed",
            format!("vault WASM hash mismatch: {e}"),
        ));
        return 1;
    }

    // ── ORDERED TRUST GATE step 2: read upgradable flag ──────────────────────
    let is_upgradable = match read_vault_upgradable_flag(&args.vault, &primary_rpc).await {
        Ok(v) => v,
        Err(e) => {
            render_json(&Envelope::<()>::err_raw(
                "vault.upgradable_read_failed",
                format!("could not read upgradable flag: {e}"),
            ));
            return 1;
        }
    };

    // ── ORDERED TRUST GATE step 3: read roles ────────────────────────────────
    let roles = match read_vault_roles(&args.vault, &primary_rpc).await {
        Ok(r) => r,
        Err(e) => {
            render_json(&Envelope::<()>::err_raw(
                "vault.roles_read_failed",
                format!("could not read vault roles: {e}"),
            ));
            return 1;
        }
    };

    let management_mode = roles.management_mode(&args.from);
    let roles_summary = roles.disclosure_summary();

    // ── ORDERED TRUST GATE step 4: read assets + validate count + strategy ───
    let mut assets = match read_vault_assets(&args.vault, &primary_rpc).await {
        Ok(a) => a,
        Err(e) => {
            render_json(&Envelope::<()>::err_raw(
                "vault.assets_read_failed",
                format!("could not read vault assets: {e}"),
            ));
            return 1;
        }
    };

    // Validate min_amounts_out length against the PIN-VERIFIED on-chain asset count.
    if let Err(e) = vault_args.validate_against_asset_count(assets.len()) {
        render_json(&Envelope::<()>::err_raw(
            "vault.asset_count_mismatch",
            e.to_string(),
        ));
        return 1;
    }

    // Blend-strategy detection via WASM-hash match.
    for asset in &mut assets {
        for strategy in &mut asset.strategies {
            match fetch_contract_wasm_hash(&primary_rpc, secondary_rpc.as_ref(), &strategy.address)
                .await
            {
                Ok(WasmHashFetch::Wasm(hash)) => {
                    strategy.is_blend_strategy = is_blend_strategy(&hash, chain_id);
                }
                Ok(_) | Err(_) => {
                    strategy.is_blend_strategy = false;
                }
            }
        }
    }

    // ── ORDERED TRUST GATE step 5: mode-aware upgradable evaluation ──────────
    if let Err(reason) =
        UpgradableEvalExt::evaluate(is_upgradable, args.override_upgradable, &management_mode)
    {
        render_json(&Envelope::<()>::err_raw(
            "vault.upgradable_refused",
            reason.to_string(),
        ));
        return 1;
    }

    // ── Operator policy evaluation ────────────────────────────────────────────
    let policy_engine = match build_v1_policy_engine("vault", &profile.policy.engine, &profile) {
        Ok(pe) => pe,
        Err(msg) => {
            render_json(&Envelope::<()>::err_raw("policy.engine_unavailable", msg));
            return 1;
        }
    };
    let vault_withdraw_reg = McpToolRegistration {
        name: "stellar_defindex_vault_withdraw",
        destructive_hint: true,
        read_only_hint: false,
        chain_id_required: true,
    };
    let mut tool_descriptor = ToolDescriptor::from_registration(&vault_withdraw_reg);
    tool_descriptor.chain_id = chain_id.to_owned();
    let policy_args = json!({
        "chain_id": chain_id,
        "vault_address": args.vault,
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
                "vault withdraw denied by operator policy".to_owned(),
            ));
            return 1;
        }
        Ok(Decision::RequireApproval(_)) => {
            render_json(&Envelope::<()>::err_raw(
                "policy.approval_required",
                "vault withdraw requires approval; use the MCP server for two-phase approval"
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

    // ── DeFi dispatch gate ────────────────────────────────────────────────────
    let witness = match dispatch_gate("vault", &args.vault) {
        Ok(GateOutcome::Allow(w)) => w,
        Ok(GateOutcome::RequireApproval) => {
            render_json(&Envelope::<()>::err_raw(
                "policy.approval_required",
                require_approval_error(),
            ));
            return 1;
        }
        Err(e) => {
            render_json(&Envelope::<()>::err_raw("vault.gate_error", format!("{e}")));
            return 1;
        }
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

    // ── Build VaultOperationPreview ───────────────────────────────────────────
    let preview = VaultOperationPreview::from_withdraw(
        &vault_args,
        chain_id,
        is_upgradable,
        roles.clone(),
        assets,
    );
    let preview_summary = preview.summary();

    // ── Build submit context ──────────────────────────────────────────────────
    let vault_pin = DefiContractPin::new(
        "defindex",
        "v1",
        "default",
        chain_id,
        &args.vault,
        DEFINDEX_VAULT_WASM_HASH,
        "f8b5c61",
    );
    let timeout = std::time::Duration::from_secs(60);
    let ctx = DefiAdapterCtx::new_with_submit_ctx(
        "default",
        &vault_pin,
        &primary_rpc,
        Some(&signer_handle as &(dyn stellar_agent_network::Signer + Send + Sync)),
        Some(network_passphrase),
        Some(chain_id),
        secondary_rpc.as_ref(),
        Some(timeout),
    );

    // ── Delegate to DefindexVaultAdapter::submit ──────────────────────────────
    let adapter = DefindexVaultAdapter::new();
    let submit_result = adapter
        .submit(
            &vault_args as &(dyn std::any::Any + Send + Sync),
            &ctx,
            witness,
        )
        .await;

    match submit_result {
        Ok(()) => {
            render_json(&Envelope::ok(json!({
                "status": "submitted",
                "action": "withdraw",
                "vault_address_redacted": stellar_agent_core::observability::redact_strkey_first5_last5(&args.vault),
                "from_address_redacted": stellar_agent_core::observability::redact_strkey_first5_last5(&args.from),
                "preview": preview_summary,
                "roles": roles_summary,
                "management_mode": format!("{management_mode:?}"),
                "upgradable": is_upgradable,
            })));
            0
        }
        Err(e) => {
            render_json(&Envelope::<()>::err_raw(
                "vault.submit_failed",
                format!("{e}"),
            ));
            1
        }
    }
}
