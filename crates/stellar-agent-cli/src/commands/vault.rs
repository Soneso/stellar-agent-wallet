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
//! Mirrors the MCP `dispatch_gate_with_value` policy path: loads the
//! operator-signed `PolicyEngineV1` (if `policy.engine = "v1"`) or
//! `NoopPolicyEngine` (if `"noop"`), then evaluates value-carrying via
//! `evaluate_with_value` with legs built from the relocated
//! `vault_deposit_value_legs` / `vault_withdraw_value_leg` builders (the SAME
//! ones the MCP twins use).  Fail-closed: a configured-but-unbuildable policy
//! refuses the value-moving vault op.
//!
//! # Audit pre-flight (fail-closed)
//!
//! Before the signer is loaded or the deposit/withdraw is submitted, both
//! actions require the profile's audit chain-root HMAC key to be acquirable
//! via [`crate::commands::value_audit::require_value_audit_writer`], refusing
//! with `audit.chain_key_unavailable` if not — `vault` always loads a
//! persisted `<name>.toml` profile (no zero-config synthesis), so the
//! pre-flight fails closed unconditionally, unlike `pay` / `claim` /
//! `accounts create`. The acquired writer is reused (not re-acquired) for
//! `DefiAdapterCtx::audit_writer`.
//!
//! # Output
//!
//! JSON by default.  Returns `0` on success, `1` on error.

use clap::{Args, Subcommand};
use serde_json::json;
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::WalletError;
use stellar_agent_core::policy::v1::{ValueClass, ValueEffects};
use stellar_agent_core::profile::loader as profile_loader;
use stellar_agent_core::profile::schema::Profile;

use crate::commands::policy_engine::{
    build_v1_policy_engine, evaluate_value_moving_policy_with_value,
};

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
    value::{vault_deposit_value_legs, vault_withdraw_value_leg},
};
use stellar_agent_network::{
    StellarRpcClient, WasmHashFetch, fetch_contract_wasm_hash, init_platform_keyring_store,
    signer_from_keyring,
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
    run_deposit_with_dependencies(
        args,
        |name| profile_loader::load(name, None),
        init_platform_keyring_store,
    )
    .await
}

/// Testable core of [`run_deposit`] with the profile loader and the
/// platform-keyring initialiser injected.
///
/// Production callers use [`run_deposit`], which supplies the real profile
/// loader and [`init_platform_keyring_store`]. Tests substitute an in-memory
/// profile and a spy initialiser to assert the keyring store is registered
/// before signer resolution without touching the OS keychain.
async fn run_deposit_with_dependencies<LoadProfile, InitKeyring>(
    args: &VaultDepositCliArgs,
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

    // ── Operator policy evaluation (value-carrying; mirrors the MCP
    // `stellar_defindex_vault_deposit` twin's `dispatch_gate_with_value`
    // mechanism) ──────────────────────────────────────────────────────────
    // `asset_addresses` is derived from the SAME PIN-VERIFIED `assets` result
    // used to validate the amounts length above, and zips 1:1 against the
    // SAME `vault_args.amounts_desired` vector later placed into
    // `VaultDepositArgs` (single-decode invariant).
    let policy_engine = match build_v1_policy_engine("vault", &profile.policy.engine, &profile) {
        Ok(pe) => pe,
        Err(msg) => {
            render_json(&Envelope::<()>::err_raw("policy.engine_unavailable", msg));
            return 1;
        }
    };
    let asset_addresses: Vec<String> = assets.iter().map(|a| a.address.clone()).collect();
    let value_legs =
        vault_deposit_value_legs(&vault_args.amounts_desired, &asset_addresses, &args.vault);
    // Capture the gate-derived legs as audit records before the descriptor
    // moves into the gate, so the emitted row carries exactly what the gate
    // sized (single-derivation invariant).
    let audit_legs: Vec<stellar_agent_core::audit_log::ValueLegRecord> =
        value_legs.iter().map(Into::into).collect();
    let policy_args = json!({
        "vault_address": args.vault,
        "from_address": args.from,
    });
    if let Err(envelope) = evaluate_value_moving_policy_with_value(
        policy_engine.as_ref(),
        &profile,
        "stellar_defindex_vault_deposit",
        chain_id,
        &policy_args,
        ValueClass::Value(ValueEffects::new(value_legs)),
        "vault_deposit",
    ) {
        render_json(&envelope);
        return 1;
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

    // ── Audit pre-flight (fail-closed) ────────────────────────────────────────
    // Proves the profile's audit chain-root key is acquirable BEFORE the
    // signer is loaded (below) or the deposit is submitted. Reused (not
    // re-acquired) for `DefiAdapterCtx::audit_writer`.
    let audit_writer =
        match crate::commands::value_audit::require_value_audit_writer(&profile, &args.profile) {
            Ok(w) => w,
            Err(e) => {
                render_json(&Envelope::<()>::err(&e));
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
    let mut ctx = DefiAdapterCtx::new_with_submit_ctx(
        "default",
        &vault_pin,
        &primary_rpc,
        Some(&signer_handle as &(dyn stellar_agent_network::Signer + Send + Sync)),
        Some(network_passphrase),
        Some(chain_id),
        secondary_rpc.as_ref(),
        Some(timeout),
    );
    // Thread the pre-flight-acquired audit writer + gate-derived legs so the
    // adapter emits the ValueActionSubmitted row after a confirmed submit
    // (non-fatal past this point — the pre-flight above is what fails closed).
    ctx.audit_writer = Some(std::sync::Arc::clone(&audit_writer));
    ctx.audit_legs = Some(&audit_legs);
    ctx.audit_tool = Some("stellar_defindex_vault_deposit");

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
    run_withdraw_with_dependencies(
        args,
        |name| profile_loader::load(name, None),
        init_platform_keyring_store,
    )
    .await
}

/// Testable core of [`run_withdraw`] with the profile loader and the
/// platform-keyring initialiser injected.
///
/// Production callers use [`run_withdraw`], which supplies the real profile
/// loader and [`init_platform_keyring_store`]. Tests substitute an in-memory
/// profile and a spy initialiser to assert the keyring store is registered
/// before signer resolution without touching the OS keychain.
async fn run_withdraw_with_dependencies<LoadProfile, InitKeyring>(
    args: &VaultWithdrawCliArgs,
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

    // ── Operator policy evaluation (value-carrying; mirrors the MCP
    // `stellar_defindex_vault_withdraw` twin's `dispatch_gate_with_value`
    // mechanism) ──────────────────────────────────────────────────────────
    let policy_engine = match build_v1_policy_engine("vault", &profile.policy.engine, &profile) {
        Ok(pe) => pe,
        Err(msg) => {
            render_json(&Envelope::<()>::err_raw("policy.engine_unavailable", msg));
            return 1;
        }
    };
    let value_leg = vault_withdraw_value_leg(vault_args.withdraw_shares, &args.vault);
    // Capture the gate-derived leg as an audit record before the descriptor
    // moves into the gate, so the emitted row carries exactly what the gate
    // sized (single-derivation invariant).
    let audit_legs = vec![stellar_agent_core::audit_log::ValueLegRecord::from(
        &value_leg,
    )];
    let policy_args = json!({
        "vault_address": args.vault,
        "from_address": args.from,
    });
    if let Err(envelope) = evaluate_value_moving_policy_with_value(
        policy_engine.as_ref(),
        &profile,
        "stellar_defindex_vault_withdraw",
        chain_id,
        &policy_args,
        ValueClass::Value(ValueEffects::new(vec![value_leg])),
        "vault_withdraw",
    ) {
        render_json(&envelope);
        return 1;
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

    // ── Audit pre-flight (fail-closed) ────────────────────────────────────────
    // Proves the profile's audit chain-root key is acquirable BEFORE the
    // signer is loaded (below) or the withdrawal is submitted. Reused (not
    // re-acquired) for `DefiAdapterCtx::audit_writer`.
    let audit_writer =
        match crate::commands::value_audit::require_value_audit_writer(&profile, &args.profile) {
            Ok(w) => w,
            Err(e) => {
                render_json(&Envelope::<()>::err(&e));
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
    let mut ctx = DefiAdapterCtx::new_with_submit_ctx(
        "default",
        &vault_pin,
        &primary_rpc,
        Some(&signer_handle as &(dyn stellar_agent_network::Signer + Send + Sync)),
        Some(network_passphrase),
        Some(chain_id),
        secondary_rpc.as_ref(),
        Some(timeout),
    );
    // Thread the pre-flight-acquired audit writer + gate-derived leg so the
    // adapter emits the ValueActionSubmitted row after a confirmed submit
    // (non-fatal past this point — the pre-flight above is what fails closed).
    ctx.audit_writer = Some(std::sync::Arc::clone(&audit_writer));
    ctx.audit_legs = Some(&audit_legs);
    ctx.audit_tool = Some("stellar_defindex_vault_withdraw");

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
    use stellar_agent_core::profile::schema::PolicyEngineKind;

    use super::*;
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate, matchers::method};

    fn test_profile() -> Profile {
        Profile::builder_testnet_named(
            "keyring-order-test",
            "stellar-agent-signer",
            "keyring-order-test",
            "stellar-agent-nonce",
            "keyring-order-test",
        )
        .build()
    }

    // ── keyring store initialisation ordering (deposit) ───────────────────────

    #[tokio::test]
    async fn run_deposit_initialises_keyring_store_before_signer_resolution() {
        // The keyring initialiser must be invoked on the deposit path, after
        // the profile load and before the signer is resolved from the keyring.
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

        let args = VaultDepositCliArgs {
            profile: "keyring-order-test".to_owned(),
            vault: String::new(),
            from: String::new(),
            amounts_desired: Vec::new(),
            amounts_min: Vec::new(),
            invest: false,
            override_upgradable: false,
            secondary_rpc_url: None,
        };

        let code = run_deposit_with_dependencies(
            &args,
            move |_name| {
                loaded_writer.store(true, Ordering::SeqCst);
                Ok(test_profile())
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
            "deposit must initialise the keyring store before resolving the signer"
        );
        assert_eq!(
            code, 1,
            "deposit must surface the keyring init failure instead of reaching signer resolution"
        );
    }

    // ── keyring store initialisation ordering (withdraw) ──────────────────────

    #[tokio::test]
    async fn run_withdraw_initialises_keyring_store_before_signer_resolution() {
        let profile_loaded = Arc::new(AtomicBool::new(false));
        let init_invoked = Arc::new(AtomicBool::new(false));

        let loaded_writer = Arc::clone(&profile_loaded);
        let loaded_reader = Arc::clone(&profile_loaded);
        let init_writer = Arc::clone(&init_invoked);

        let args = VaultWithdrawCliArgs {
            profile: "keyring-order-test".to_owned(),
            vault: String::new(),
            from: String::new(),
            shares: 0,
            min_amounts_out: Vec::new(),
            override_upgradable: false,
            secondary_rpc_url: None,
        };

        let code = run_withdraw_with_dependencies(
            &args,
            move |_name| {
                loaded_writer.store(true, Ordering::SeqCst);
                Ok(test_profile())
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
            "withdraw must initialise the keyring store before resolving the signer"
        );
        assert_eq!(
            code, 1,
            "withdraw must surface the keyring init failure instead of reaching signer resolution"
        );
    }

    // ── Audit pre-flight (fail-closed) after the ordered trust gate ──────────
    //
    // `vault`'s audit pre-flight (module doc: "Audit pre-flight (fail-closed)")
    // runs AFTER the ordered trust gate's four `getLedgerEntries` round trips
    // (vault WASM-hash pin, upgradable-flag read, roles read, assets read —
    // see the module doc's "Ordered trust gate" section and the call sequence
    // in `run_deposit_with_dependencies` / `run_withdraw_with_dependencies`
    // above), so a `server.received_requests().is_empty()` assertion would be
    // structurally wrong here (see cycle-2 brief item B). These helpers mock
    // the ordered trust gate to a genuine PASS — a matching pinned WASM hash,
    // `upgradable:false` (never refused regardless of role data), and a single
    // well-formed asset with no strategies — so deposit and withdraw both
    // reach the real production pre-flight call site instead of refusing
    // earlier for an unrelated reason. Both `read_vault_roles` calls resolve
    // every role to absent (`None`); this is harmless because
    // `UpgradableEvalExt::evaluate` short-circuits on `is_upgradable == false`
    // before ever consulting the management mode derived from those roles.

    /// Builds the base64 XDR `(key, entry)` pair for a DeFindex vault's
    /// contract instance ledger entry, carrying a pinned WASM executable hash
    /// and instance-storage entries for `Upgradable`, `TotalAssets`, and a
    /// single `AssetStrategySet(0)` with no strategies — the SAME single
    /// instance entry `verify_defindex_vault_wasm`, `read_vault_upgradable_flag`,
    /// `read_vault_roles`, and `read_vault_assets` each independently decode via
    /// their own `getLedgerEntries` call against `LedgerKeyContractInstance`.
    ///
    /// # ABI provenance
    ///
    /// - `DataKey::Upgradable` / `DataKey::TotalAssets`: unit-variant keys built
    ///   via [`stellar_agent_defindex::storage::build_unit_variant_scval_key`]
    ///   (the SAME production builder, imported directly to avoid ABI drift).
    /// - `DataKey::AssetStrategySet(0)`: `ScVal::Vec([Symbol("AssetStrategySet"),
    ///   U32(0)])` per `stellar_agent_defindex::storage::build_asset_strategy_set_key`'s
    ///   ABI-provenance rustdoc (that builder is private to its crate; the shape
    ///   is reproduced here byte-for-byte from the cited rustdoc).
    /// - `AssetStrategySet { address, strategies: [] }`: fields sorted
    ///   alphabetically (`address` < `strategies`) per
    ///   `stellar_agent_defindex::storage::decode_asset_strategy_set_scval`'s
    ///   ABI-layout rustdoc; `ScVal::Vec(None)` for an empty `strategies` list
    ///   per that same function's explicit empty-vector arm.
    fn defindex_vault_instance_key_and_entry_xdr(
        vault_address: &str,
        wasm_hash: [u8; 32],
        asset_address: &str,
    ) -> (String, String) {
        use stellar_agent_defindex::storage::build_unit_variant_scval_key;
        use stellar_xdr::{
            ContractDataDurability, ContractDataEntry, ContractExecutable, ContractId,
            ExtensionPoint, Hash, LedgerEntryData, LedgerKey, LedgerKeyContractData, Limits,
            ScAddress, ScContractInstance, ScMap, ScMapEntry, ScSymbol, ScVal, ScVec, StringM,
            WriteXdr,
        };

        let vault =
            stellar_strkey::Contract::from_string(vault_address).expect("valid vault C-strkey");
        let sc_addr = ScAddress::Contract(ContractId(Hash(vault.0)));

        let asset =
            stellar_strkey::Contract::from_string(asset_address).expect("valid asset C-strkey");
        let asset_sc_addr = ScAddress::Contract(ContractId(Hash(asset.0)));

        let upgradable_key =
            build_unit_variant_scval_key("Upgradable").expect("'Upgradable' fits ScSymbol");
        let total_assets_key =
            build_unit_variant_scval_key("TotalAssets").expect("'TotalAssets' fits ScSymbol");

        let asset_strategy_set_sym: StringM<32> =
            "AssetStrategySet".try_into().expect("fits ScSymbol");
        let asset_strategy_set_key = ScVal::Vec(Some(ScVec(
            vec![
                ScVal::Symbol(ScSymbol(asset_strategy_set_sym)),
                ScVal::U32(0),
            ]
            .try_into()
            .expect("two-element ScVec fits VecM"),
        )));

        let address_sym: StringM<32> = "address".try_into().expect("fits ScSymbol");
        let strategies_sym: StringM<32> = "strategies".try_into().expect("fits ScSymbol");
        let asset_strategy_set_val = ScVal::Map(Some(ScMap(
            vec![
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol(address_sym)),
                    val: ScVal::Address(asset_sc_addr),
                },
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol(strategies_sym)),
                    val: ScVal::Vec(None),
                },
            ]
            .try_into()
            .expect("two-entry ScMap fits VecM"),
        )));

        let storage = ScMap(
            vec![
                ScMapEntry {
                    key: upgradable_key,
                    val: ScVal::Bool(false),
                },
                ScMapEntry {
                    key: total_assets_key,
                    val: ScVal::U32(1),
                },
                ScMapEntry {
                    key: asset_strategy_set_key,
                    val: asset_strategy_set_val,
                },
            ]
            .try_into()
            .expect("three-entry ScMap fits VecM"),
        );

        let instance = ScContractInstance {
            executable: ContractExecutable::Wasm(Hash(wasm_hash)),
            storage: Some(storage),
        };

        let key = LedgerKey::ContractData(LedgerKeyContractData {
            contract: sc_addr.clone(),
            key: ScVal::LedgerKeyContractInstance,
            durability: ContractDataDurability::Persistent,
        });
        let entry_data = LedgerEntryData::ContractData(ContractDataEntry {
            ext: ExtensionPoint::V0,
            contract: sc_addr,
            key: ScVal::LedgerKeyContractInstance,
            durability: ContractDataDurability::Persistent,
            val: ScVal::ContractInstance(instance),
        });

        let key_b64 = key.to_xdr_base64(Limits::none()).expect("key XDR encode");
        let val_b64 = entry_data
            .to_xdr_base64(Limits::none())
            .expect("entry XDR encode");
        (key_b64, val_b64)
    }

    /// Answers every `getLedgerEntries` request with the same fixed vault
    /// instance entry, so the ordered trust gate's four independent reads
    /// (WASM-pin, upgradable-flag, roles, assets — all against the SAME
    /// `LedgerKeyContractInstance`) all resolve successfully.
    struct VaultInstanceResponder {
        entry_xdr: String,
    }

    #[async_trait::async_trait]
    impl Respond for VaultInstanceResponder {
        fn respond(&self, request: &Request) -> ResponseTemplate {
            let request_value = serde_json::from_slice::<serde_json::Value>(&request.body)
                .unwrap_or_else(|_| serde_json::json!({}));
            let req_id = request_value
                .get("id")
                .cloned()
                .unwrap_or_else(|| serde_json::json!(1));
            let method = request_value
                .get("method")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");

            let result = match method {
                "getLedgerEntries" => serde_json::json!({
                    "entries": [{
                        "key": "unused-by-the-decoder",
                        "xdr": self.entry_xdr,
                        "lastModifiedLedgerSeq": 1000
                    }],
                    "latestLedger": 1001
                }),
                _ => serde_json::json!({}),
            };

            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": result,
                }))
                .insert_header("content-type", "application/json")
        }
    }

    /// Proves the deposit audit pre-flight is still wired into
    /// `run_deposit_with_dependencies`'s production path AFTER the ordered
    /// trust gate — not merely unit-tested in isolation. Mocks the ordered
    /// gate to a genuine PASS so the run reaches the real pre-flight call site
    /// and refuses there (`audit.chain_key_unavailable`) because the profile's
    /// audit chain-root key was never minted at its unique keyring coordinate.
    /// The exact `received_requests` count of 4 (one `getLedgerEntries` per
    /// gate step) is what makes this discriminating: fewer requests would mean
    /// the gate was short-circuited or bypassed before completing; more would
    /// mean an unexpected extra round trip (e.g. the empty-strategies asset
    /// unexpectedly triggering a Blend-strategy WASM-hash lookup) crept in.
    #[tokio::test]
    #[serial_test::serial]
    async fn run_deposit_refuses_after_ordered_trust_gate_when_audit_key_unminted() {
        stellar_agent_test_support::keyring_mock::install().expect("mock keyring store");

        let vault_c = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";
        let asset_c = "CBMVK2JK6NTOT2O4HNQAIQFJY232BHKGLIMXDVQVHIIZKDACXDFZDWHN";
        let (_key_xdr, entry_xdr) =
            defindex_vault_instance_key_and_entry_xdr(vault_c, DEFINDEX_VAULT_WASM_HASH, asset_c);

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(VaultInstanceResponder { entry_xdr })
            .mount(&server)
            .await;
        let rpc_url = server.uri();

        let args = VaultDepositCliArgs {
            profile: "vault-deposit-audit-preflight-test".to_owned(),
            vault: vault_c.to_owned(),
            from: asset_c.to_owned(),
            amounts_desired: vec![1_000_000],
            amounts_min: vec![900_000],
            invest: false,
            override_upgradable: false,
            secondary_rpc_url: None,
        };

        let code = run_deposit_with_dependencies(
            &args,
            move |_name| {
                let mut profile = Profile::builder_testnet_named(
                    "vault-deposit-audit-preflight-test",
                    "stellar-agent-signer",
                    "vault-deposit-audit-preflight-test",
                    "stellar-agent-nonce",
                    "vault-deposit-audit-preflight-test",
                )
                .policy_engine(PolicyEngineKind::Noop)
                .build();
                profile.rpc_url = rpc_url.clone();
                Ok(profile)
            },
            || Ok(()),
        )
        .await;

        assert_eq!(
            code, 1,
            "deposit must refuse when the audit chain-root key is unminted, even \
             after the ordered trust gate passes"
        );
        let requests = server
            .received_requests()
            .await
            .expect("request recording is enabled by default");
        assert_eq!(
            requests.len(),
            4,
            "the ordered trust gate must complete (WASM-pin + upgradable-flag + \
             roles + assets, each one getLedgerEntries call) BEFORE the audit \
             pre-flight refuses — a different count means the gate was \
             bypassed, short-circuited, or the pre-flight fired at the wrong \
             point"
        );
    }

    /// Withdraw counterpart of
    /// `run_deposit_refuses_after_ordered_trust_gate_when_audit_key_unminted`;
    /// see that test's doc comment for the full rationale. Proves
    /// `run_withdraw_with_dependencies`'s own audit pre-flight call site is
    /// independently wired — the deposit and withdraw paths are separate
    /// functions with separate `require_value_audit_writer` call sites, so
    /// proving one wired does not prove the other.
    #[tokio::test]
    #[serial_test::serial]
    async fn run_withdraw_refuses_after_ordered_trust_gate_when_audit_key_unminted() {
        stellar_agent_test_support::keyring_mock::install().expect("mock keyring store");

        let vault_c = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";
        let asset_c = "CBMVK2JK6NTOT2O4HNQAIQFJY232BHKGLIMXDVQVHIIZKDACXDFZDWHN";
        let (_key_xdr, entry_xdr) =
            defindex_vault_instance_key_and_entry_xdr(vault_c, DEFINDEX_VAULT_WASM_HASH, asset_c);

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(VaultInstanceResponder { entry_xdr })
            .mount(&server)
            .await;
        let rpc_url = server.uri();

        let args = VaultWithdrawCliArgs {
            profile: "vault-withdraw-audit-preflight-test".to_owned(),
            vault: vault_c.to_owned(),
            from: asset_c.to_owned(),
            shares: 1_000_000,
            min_amounts_out: vec![900_000],
            override_upgradable: false,
            secondary_rpc_url: None,
        };

        let code = run_withdraw_with_dependencies(
            &args,
            move |_name| {
                let mut profile = Profile::builder_testnet_named(
                    "vault-withdraw-audit-preflight-test",
                    "stellar-agent-signer",
                    "vault-withdraw-audit-preflight-test",
                    "stellar-agent-nonce",
                    "vault-withdraw-audit-preflight-test",
                )
                .policy_engine(PolicyEngineKind::Noop)
                .build();
                profile.rpc_url = rpc_url.clone();
                Ok(profile)
            },
            || Ok(()),
        )
        .await;

        assert_eq!(
            code, 1,
            "withdraw must refuse when the audit chain-root key is unminted, even \
             after the ordered trust gate passes"
        );
        let requests = server
            .received_requests()
            .await
            .expect("request recording is enabled by default");
        assert_eq!(
            requests.len(),
            4,
            "the ordered trust gate must complete (WASM-pin + upgradable-flag + \
             roles + assets, each one getLedgerEntries call) BEFORE the audit \
             pre-flight refuses — a different count means the gate was \
             bypassed, short-circuited, or the pre-flight fired at the wrong \
             point"
        );
    }
}
