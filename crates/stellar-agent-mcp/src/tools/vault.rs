//! `stellar_defindex_vault_deposit` and `stellar_defindex_vault_withdraw` MCP tools.
//!
//! # What these tools do
//!
//! Implement the `vault` verb for DeFindex vaults, exposing typed `deposit` and
//! `withdraw` operations.  Both tools enforce the **ORDERED TRUST GATE**:
//!
//! 1. `verify_defindex_vault_wasm` — two-RPC WASM-hash pin check against the
//!    pinned DeFindex vault hash set.
//! 2. `read_vault_upgradable_flag` — read `DataKey::Upgradable` from instance
//!    storage.
//! 3. `read_vault_roles` — read the four role addresses and compute management
//!    mode (self-managed vs delegated).
//! 4. `read_vault_assets` — read vault asset+strategy set; validate arg lengths;
//!    run Blend-strategy WASM-hash detection per strategy.
//! 5. `UpgradableEvalExt::evaluate` — refuse if `upgradable:true` for delegated
//!    or not-manager vaults (self-managed exempt; opt-in override).
//!
//! Only after all gate steps pass, `dispatch_gate("vault", ...)` produces a
//! `SubmitWitness`; the `DefindexVaultAdapter::submit` is called with it.
//! There is NO duplicated `HostFunction` build or `submit_signed_invoke` call in
//! this file — that logic lives exclusively in the adapter.
//!
//! # Upgradable posture
//!
//! Default: refuse `upgradable:true` vaults for delegated and not-manager modes.
//! Self-managed vaults (depositor == Manager, no third-party EM/RM) are EXEMPT.
//! Set `override_upgradable = true` to bypass for non-self-managed vaults; a
//! distinct `vault.upgradable_override` audit event is emitted unconditionally
//! (EMIT-THEN-RETURN pattern).  The WASM-pin refusal is NON-overridable.
//!
//! # min_out requirement
//!
//! `amounts_min` (deposit) and `min_amounts_out` (withdraw) are REQUIRED typed
//! fields.  A missing or length-mismatched field is a structural error pre-sign.
//! Length is ALSO validated against the PIN-VERIFIED on-chain asset count from
//! `read_vault_assets`.
//!
//! # Policy evaluation
//!
//! Both tools run `WalletServer::dispatch_gate_with_value` before signing,
//! carrying typed [`stellar_agent_core::policy::v1::ValueLeg`]s
//! (`vault_deposit_value_legs` / `vault_withdraw_value_leg`).  The withdraw
//! gate runs immediately after decode (no vault-asset addresses are needed for
//! its single non-debit leg).  The deposit gate runs AFTER ordered-trust-gate
//! step 4 (`read_vault_assets`): a `VaultDeposit` leg's `asset` is the
//! deposited token's on-chain address, which is not present in the wire args
//! and can only be resolved from that read — the legs still zip 1:1 against
//! the SAME `amounts_desired` vector later signed inside `VaultDepositArgs`
//! (single-decode invariant).
//!
//! # Behaviour
//!
//! - Typed preview plus submit for deposit and withdraw.
//! - Role disclosure for the vault's management roles.
//! - Upgradable posture enforced per management mode.
//! - `min_out` fields are required.
//! - Both tools expose a typed argument surface.

use rmcp::{
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Content},
    schemars, serde, tool, tool_router,
};
use serde_json::json;
use stellar_agent_mcp_macros::mcp_tool_router;

use stellar_agent_core::policy::v1::{ValueClass, ValueEffects};
use stellar_agent_defi::adapter::{DefiAdapter, DefiAdapterCtx};
use stellar_agent_defi::dispatch::{GateOutcome, dispatch_gate, require_approval_error};
use stellar_agent_defi::pins::DefiContractPin;
use stellar_agent_defindex::{
    abi::{VaultDepositArgs, VaultWithdrawArgs},
    adapter::DefindexVaultAdapter,
    criteria::upgradable::UpgradableEvalExt,
    pins::{DEFINDEX_VAULT_WASM_HASH, is_blend_strategy, verify_defindex_vault_wasm},
    preview::VaultOperationPreview,
    roles::{VaultManagementMode, read_vault_roles},
    storage::{read_vault_assets, read_vault_upgradable_flag},
    value::{vault_deposit_value_legs, vault_withdraw_value_leg},
};
use stellar_agent_network::{
    StellarRpcClient, WasmHashFetch, fetch_contract_wasm_hash, signer_from_keyring,
};

use crate::server::WalletServer;
use crate::tools::common::DispatchOutcome;

// ─────────────────────────────────────────────────────────────────────────────
// Argument types — deposit
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for the `stellar_defindex_vault_deposit` MCP tool.
///
/// Exposes typed arguments; `amounts_min` is a required field.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(crate = "rmcp::serde")]
pub struct VaultDepositMcpArgs {
    /// CAIP-2 chain identifier: `stellar:testnet` or `stellar:mainnet`.
    pub chain_id: String,
    /// The DeFindex vault contract address (C-strkey).
    pub vault_address: String,
    /// The wallet smart-account address submitting the deposit (C-strkey).
    pub from_address: String,
    /// Desired deposit amounts per asset (i128), in declaration order, each
    /// as a decimal string (e.g. `"250000000"`). A raw JSON number is
    /// rejected — `serde_json::from_value` backs numbers with `f64`, which
    /// cannot represent an i128 exactly above `2^53`.
    ///
    /// Length must match the number of assets in the vault (`get_assets().len()`).
    /// Absence is a structural pre-sign refuse.
    pub amounts_desired: Vec<String>,
    /// Minimum accepted deposit amounts per asset (i128), same length as
    /// `amounts_desired`, each as a decimal string. Zero floor = no slippage
    /// protection; the wallet does NOT default this to zero.
    pub amounts_min: Vec<String>,
    /// Whether to auto-invest immediately after deposit (`invest` arg in ABI).
    #[serde(default)]
    pub invest: bool,
    /// Override the upgradable-vault refusal.
    ///
    /// When `true`, the operation proceeds on an `upgradable:true` vault;
    /// a distinct `vault.upgradable_override` audit event is emitted
    /// unconditionally.  The WASM-pin refusal is NON-overridable.
    #[serde(default)]
    pub override_upgradable: bool,
    /// Optional secondary RPC URL for the two-RPC WASM-hash cross-check.
    #[serde(default)]
    pub secondary_rpc_url: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Argument types — withdraw
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for the `stellar_defindex_vault_withdraw` MCP tool.
///
/// Exposes typed arguments; `min_amounts_out` is a required field.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(crate = "rmcp::serde")]
pub struct VaultWithdrawMcpArgs {
    /// CAIP-2 chain identifier: `stellar:testnet` or `stellar:mainnet`.
    pub chain_id: String,
    /// The DeFindex vault contract address (C-strkey).
    pub vault_address: String,
    /// The wallet smart-account address submitting the withdrawal (C-strkey).
    pub from_address: String,
    /// Number of vault shares to redeem (i128 raw on-chain value), as a
    /// decimal string. A raw JSON number is rejected (see
    /// `VaultDepositMcpArgs.amounts_desired`).
    ///
    /// This is the `df_amount` / `withdraw_shares` first arg of the vault
    /// `withdraw` function.
    pub withdraw_shares: String,
    /// Minimum amounts to receive per asset (i128), in `total_managed_funds`
    /// order, each as a decimal string. Absence is a structural pre-sign
    /// refuse. Zero floor = no slippage protection; the wallet does NOT
    /// default to zero.
    pub min_amounts_out: Vec<String>,
    /// Override the upgradable-vault refusal.
    #[serde(default)]
    pub override_upgradable: bool,
    /// Optional secondary RPC URL for the two-RPC WASM-hash cross-check.
    #[serde(default)]
    pub secondary_rpc_url: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool router impl block
// ─────────────────────────────────────────────────────────────────────────────

/// Deposit assets into a DeFindex vault.
///
/// Runs the full ordered trust gate before signing.  Refuses `upgradable:true`
/// vaults for delegated and not-manager modes by default; self-managed vaults
/// are exempt.
///
/// # Ordered trust gate
///
/// 1. `verify_defindex_vault_wasm` — two-RPC pin check.
/// 2. `read_vault_upgradable_flag` — read the flag.
/// 3. `read_vault_roles` — read roles, compute self-managed/delegated mode.
/// 4. `read_vault_assets` — read assets+strategies; validate `amounts_min`
///    length against on-chain asset count; detect Blend strategies by
///    WASM-hash match.
/// 5. `UpgradableEvalExt::evaluate` — refuse if `upgradable:true`
///    (self-managed exempt).
///
/// Only after all steps pass, `dispatch_gate("vault", ...)` is called and the
/// `SubmitWitness` is passed to `DefindexVaultAdapter::submit`.
///
/// # Tool annotations
///
/// - `destructive_hint = true` — signs and submits a transaction.
/// - `read_only_hint = false` — modifies on-chain state.
///
/// # Errors
///
/// Returns a tool-level error when:
/// - The vault WASM hash does not match the pinned DeFindex set.
/// - The vault is `upgradable:true` and `override_upgradable = false`.
/// - `amounts_desired` / `amounts_min` are absent or length-mismatched.
/// - The policy engine returns `Deny`.
/// - The smart-account submit fails.
#[mcp_tool_router]
#[tool_router(router = vault_tool_router, vis = "pub(crate)")]
impl WalletServer {
    #[mcp_tool_item(
        name = "stellar_defindex_vault_deposit",
        destructive_hint = true,
        read_only_hint = false,
        chain_id_required = true,
        value_kind = "moves_value"
    )]
    #[tool(
        name = "stellar_defindex_vault_deposit",
        description = "Deposit assets into a DeFindex vault. Enforces ordered trust gate: vault \
                       WASM-hash pin (two-RPC), upgradable-flag check (self-managed exempt), \
                       role disclosure, asset-count validation, Blend-strategy detection. \
                       Refuses upgradable=true non-self-managed vaults by default \
                       (override_upgradable opt-in). amounts_min required (no default-zero). \
                       destructive_hint=true, read_only_hint=false.",
        annotations(destructive_hint = true, read_only_hint = false)
    )]
    async fn stellar_defindex_vault_deposit(
        &self,
        Parameters(args): Parameters<VaultDepositMcpArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        // ── Parse decimal-string amount fields (single decode; feeds BOTH the
        // value-carrying policy gate below and `VaultDepositArgs` handed to
        // the adapter further down) ───────────────────────────────────────────
        let amounts_desired = crate::tools::amount_wire::parse_i128_vec_field(
            "amounts_desired",
            &args.amounts_desired,
        )?;
        let amounts_min =
            crate::tools::amount_wire::parse_i128_vec_field("amounts_min", &args.amounts_min)?;

        // ── Structural validation ────────────────────────────────────────────
        let vault_args = VaultDepositArgs {
            vault_address: args.vault_address.clone(),
            amounts_desired,
            amounts_min,
            from_address: args.from_address.clone(),
            invest: args.invest,
            override_upgradable: args.override_upgradable,
        };
        if let Err(e) = vault_args.validate_structure() {
            return Ok(tool_error_result("vault.invalid_args", &e.to_string()));
        }

        // ── Build RPCs ────────────────────────────────────────────────────────
        let rpc_url = self.profile.rpc_url.as_str();
        let primary_rpc = StellarRpcClient::new(rpc_url).map_err(|e| {
            rmcp::ErrorData::internal_error(format!("vault.rpc_init_failed: {e}"), None)
        })?;
        let secondary_rpc: Option<StellarRpcClient> = args
            .secondary_rpc_url
            .as_deref()
            .map(|url| {
                StellarRpcClient::new(url).map_err(|e| {
                    rmcp::ErrorData::internal_error(
                        format!("vault.secondary_rpc_init_failed: {e}"),
                        None,
                    )
                })
            })
            .transpose()?;

        // ── ORDERED TRUST GATE step 1: verify vault WASM hash ───────────────
        // The vault WASM hash is identical on testnet and pubnet.
        if let Err(e) =
            verify_defindex_vault_wasm(&args.vault_address, &primary_rpc, secondary_rpc.as_ref())
                .await
        {
            tracing::warn!(
                event = "vault.wasm_pin_failed",
                vault_redacted =
                    stellar_agent_core::observability::redact_strkey_first5_last5(&args.vault_address),
                error = %e,
            );
            return Ok(tool_error_result(
                "vault.wasm_pin_failed",
                "vault WASM hash does not match the pinned DeFindex set",
            ));
        }

        // ── ORDERED TRUST GATE step 2: read upgradable flag ─────────────────
        let is_upgradable = match read_vault_upgradable_flag(&args.vault_address, &primary_rpc)
            .await
        {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    event = "vault.upgradable_read_failed",
                    vault_redacted = stellar_agent_core::observability::redact_strkey_first5_last5(
                        &args.vault_address
                    ),
                    error = %e,
                );
                return Ok(tool_error_result(
                    "vault.upgradable_read_failed",
                    "could not read vault upgradable flag (fail-safe: treating as upgradable=true)",
                ));
            }
        };

        // ── ORDERED TRUST GATE step 3: read roles ────────────────────────────
        let roles = match read_vault_roles(&args.vault_address, &primary_rpc).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(
                    event = "vault.roles_read_failed",
                    vault_redacted = stellar_agent_core::observability::redact_strkey_first5_last5(
                        &args.vault_address
                    ),
                    error = %e,
                );
                return Ok(tool_error_result(
                    "vault.roles_read_failed",
                    "could not read vault roles",
                ));
            }
        };

        let management_mode = roles.management_mode(&args.from_address);
        let roles_summary = roles.disclosure_summary();

        // Emit management-mode disclosure warnings.
        match &management_mode {
            VaultManagementMode::SelfManaged => {
                tracing::info!(
                    event = "vault.self_managed",
                    vault_redacted = stellar_agent_core::observability::redact_strkey_first5_last5(
                        &args.vault_address
                    ),
                    roles = %roles_summary,
                );
            }
            VaultManagementMode::Delegated {
                third_party_emergency_manager,
                third_party_rebalance_manager,
            } => {
                tracing::warn!(
                    event = "vault.delegated_roles_present",
                    vault_redacted = stellar_agent_core::observability::redact_strkey_first5_last5(
                        &args.vault_address
                    ),
                    third_party_emergency_manager = third_party_emergency_manager,
                    third_party_rebalance_manager = third_party_rebalance_manager,
                    roles = %roles_summary,
                );
            }
            VaultManagementMode::NotManager => {
                tracing::info!(
                    event = "vault.not_manager",
                    vault_redacted = stellar_agent_core::observability::redact_strkey_first5_last5(
                        &args.vault_address
                    ),
                );
            }
        }

        // ── ORDERED TRUST GATE step 4: read assets + validate + detect ──────
        let mut assets = match read_vault_assets(&args.vault_address, &primary_rpc).await {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!(
                    event = "vault.assets_read_failed",
                    vault_redacted = stellar_agent_core::observability::redact_strkey_first5_last5(
                        &args.vault_address
                    ),
                    error = %e,
                );
                return Ok(tool_error_result(
                    "vault.assets_read_failed",
                    "could not read vault assets (ordered gate step 4 failed)",
                ));
            }
        };

        // Validate amounts_min length against the PIN-VERIFIED on-chain asset count.
        if let Err(e) = vault_args.validate_against_asset_count(assets.len()) {
            return Ok(tool_error_result(
                "vault.asset_count_mismatch",
                &e.to_string(),
            ));
        }

        // Blend-strategy detection via WASM-hash match (per strategy address).
        for asset in &mut assets {
            for strategy in &mut asset.strategies {
                match fetch_contract_wasm_hash(
                    &primary_rpc,
                    secondary_rpc.as_ref(),
                    &strategy.address,
                )
                .await
                {
                    Ok(WasmHashFetch::Wasm(hash)) => {
                        strategy.is_blend_strategy = is_blend_strategy(&hash, &args.chain_id);
                    }
                    Ok(_) | Err(_) => {
                        // SAC, absent, or fetch failure → not a Blend strategy.
                        strategy.is_blend_strategy = false;
                    }
                }
            }
        }

        // ── Policy gate (value-carrying; MCP server dispatch_gate
        // prerequisite) ───────────────────────────────────────────────────────
        // Deferred until AFTER ordered-trust-gate step 4: the per-asset
        // addresses a `VaultDeposit` leg needs are read on-chain by
        // `read_vault_assets`, not present in the wire args, so they cannot be
        // resolved from `args` alone. `asset_addresses` zips 1:1 against
        // `vault_args.amounts_desired` — the SAME vector `validate_against_asset_count`
        // just confirmed is equal length, and the SAME vector later placed into
        // the `VaultDepositArgs` signed by the adapter (single-decode
        // invariant: no second amounts/asset parse). `account_view` /
        // `identity_view` are `None`: the `minimum_reserve` / `home_domain`
        // criteria fail closed on this tool pending account-view wiring,
        // acceptable for this step.
        let asset_addresses: Vec<String> = assets.iter().map(|a| a.address.clone()).collect();
        let value_legs = vault_deposit_value_legs(
            &vault_args.amounts_desired,
            &asset_addresses,
            &args.vault_address,
        );
        // Capture the gate-derived legs as audit records before the descriptor
        // moves into the gate (single-derivation invariant).
        let audit_legs: Vec<stellar_agent_core::audit_log::ValueLegRecord> =
            value_legs.iter().map(Into::into).collect();
        let args_value = json!({
            "chain_id": args.chain_id,
            "vault_address": args.vault_address,
            "from_address": args.from_address,
        });
        let dispatch_outcome = match self
            .dispatch_gate_with_value(
                "stellar_defindex_vault_deposit",
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

        if matches!(dispatch_outcome, DispatchOutcome::RequireApproval(_)) {
            return Ok(crate::tools::common::single_shot_require_approval_error());
        }

        // ── ORDERED TRUST GATE step 5: mode-aware upgradable evaluation ──────
        if let Err(reason) =
            UpgradableEvalExt::evaluate(is_upgradable, args.override_upgradable, &management_mode)
        {
            tracing::warn!(
                event = "vault.upgradable_refused",
                vault_redacted =
                    stellar_agent_core::observability::redact_strkey_first5_last5(&args.vault_address),
                reason = %reason,
            );
            return Ok(tool_error_result(
                "vault.upgradable_refused",
                &reason.to_string(),
            ));
        }

        // ── Build VaultOperationPreview for rich gate-passed summary ─────────
        let preview = VaultOperationPreview::from_deposit(
            &vault_args,
            &args.chain_id,
            is_upgradable,
            roles.clone(),
            assets,
        );
        let preview_summary = preview.summary();

        // ── DeFi dispatch gate ────────────────────────────────────────────────
        let gate_result = dispatch_gate("vault", &args.vault_address);
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
                    format!("vault.gate_error: {e}"),
                    None,
                ));
            }
        };

        // ── Load signer ───────────────────────────────────────────────────────
        let signer_entry_ref = &self.profile.mcp_signer_default;
        let expected_g_strkey = signer_entry_ref.account.as_str();
        let signer_handle = match signer_from_keyring(signer_entry_ref, expected_g_strkey).await {
            Ok(h) => h,
            Err(_) => {
                return Ok(crate::tools::common::business_error_result(
                    "vault.signer_load_failed",
                    "could not load signer from keyring",
                ));
            }
        };

        let timeout = crate::tools::common::submit_timeout(&self.profile);
        let network = self.profile.network_passphrase.as_str();

        // WASM hash already verified at step 1; use the real hash so the pin
        // carries a meaningful value for audit and downstream checks.
        let vault_pin = DefiContractPin::new(
            "defindex",
            "v1",
            "default",
            &args.chain_id,
            &args.vault_address,
            DEFINDEX_VAULT_WASM_HASH,
            "defindex-vault", // abi_source_provenance
        );

        let mut ctx = DefiAdapterCtx::new_with_submit_ctx(
            "default",
            &vault_pin,
            &primary_rpc,
            Some(&signer_handle as &(dyn stellar_agent_network::Signer + Send + Sync)),
            Some(network),
            Some(args.chain_id.as_str()),
            secondary_rpc.as_ref(),
            Some(timeout),
        );
        // Thread the audit writer + gate-derived legs so the adapter emits the
        // ValueActionSubmitted row after a confirmed submit (non-fatal).
        let audit_profile_name = self.profile_name_for_approval();
        ctx.audit_writer = crate::tools::value_audit::acquire_value_audit_writer(
            &self.profile,
            &audit_profile_name,
        );
        ctx.audit_legs = Some(&audit_legs);
        ctx.audit_tool = Some("stellar_defindex_vault_deposit");

        tracing::info!(
            verb = "vault",
            action = "deposit",
            vault_redacted = stellar_agent_core::observability::redact_strkey_first5_last5(
                &args.vault_address
            ),
            from_redacted = stellar_agent_core::observability::redact_strkey_first5_last5(
                &args.from_address
            ),
            management_mode = ?management_mode,
            roles = %roles_summary,
            upgradable = is_upgradable,
            preview = %preview_summary,
            request_id = witness.request_id(),
            "DeFindex vault: ordered gate passed, submitting deposit via adapter"
        );

        // ── Delegate to DefindexVaultAdapter::submit ──────────────────────────
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
                let resp = json!({
                    "status": "submitted",
                    "action": "deposit",
                    "vault_address_redacted": stellar_agent_core::observability::redact_strkey_first5_last5(&args.vault_address),
                    "from_address_redacted": stellar_agent_core::observability::redact_strkey_first5_last5(&args.from_address),
                    "preview": preview_summary,
                    "roles": roles_summary,
                    "management_mode": format!("{management_mode:?}"),
                    "upgradable": is_upgradable,
                });
                let json_str =
                    serde_json::to_string_pretty(&resp).unwrap_or_else(|_| "{}".to_owned());
                Ok(CallToolResult::success(vec![Content::text(json_str)]))
            }
            Err(e) => Ok(crate::tools::common::business_error_result(
                "vault.submit_failed",
                e.to_string(),
            )),
        }
    }

    #[mcp_tool_item(
        name = "stellar_defindex_vault_withdraw",
        destructive_hint = true,
        read_only_hint = false,
        chain_id_required = true,
        value_kind = "moves_value"
    )]
    #[tool(
        name = "stellar_defindex_vault_withdraw",
        description = "Withdraw assets from a DeFindex vault by redeeming shares. Enforces \
                       ordered trust gate: vault WASM-hash pin (two-RPC), upgradable-flag check \
                       (self-managed exempt), role disclosure, asset-count validation, \
                       Blend-strategy detection. Refuses upgradable=true non-self-managed \
                       vaults by default (override_upgradable opt-in). min_amounts_out required \
                       (no default-zero). destructive_hint=true, read_only_hint=false.",
        annotations(destructive_hint = true, read_only_hint = false)
    )]
    async fn stellar_defindex_vault_withdraw(
        &self,
        Parameters(args): Parameters<VaultWithdrawMcpArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        // ── Parse decimal-string amount fields (single decode; feeds BOTH the
        // value-carrying policy gate below and `VaultWithdrawArgs` handed to
        // the adapter further down) ───────────────────────────────────────────
        let withdraw_shares =
            crate::tools::amount_wire::parse_i128_field("withdraw_shares", &args.withdraw_shares)?;
        let min_amounts_out = crate::tools::amount_wire::parse_i128_vec_field(
            "min_amounts_out",
            &args.min_amounts_out,
        )?;

        // ── Structural validation ────────────────────────────────────────────
        let vault_args = VaultWithdrawArgs {
            vault_address: args.vault_address.clone(),
            withdraw_shares,
            min_amounts_out,
            from_address: args.from_address.clone(),
            override_upgradable: args.override_upgradable,
        };
        if let Err(e) = vault_args.validate_structure() {
            return Ok(tool_error_result("vault.invalid_args", &e.to_string()));
        }

        // ── Policy gate (value-carrying; MCP server dispatch_gate
        // prerequisite) ───────────────────────────────────────────────────────
        // A withdrawal redeems shares for a basket of underlying assets
        // (`min_amounts_out` spans the vault's whole asset set), so no single
        // token id is the leg's `asset`; the vault-share token id itself is out
        // of scope for this step, so `asset` is `None` (see
        // `vault_withdraw_value_leg`). `VaultWithdraw` is a non-debit
        // `ActionKind` (a redemption returns funds), so leaving `asset` unset
        // does not affect `minimum_reserve` sizing. `account_view` /
        // `identity_view` are `None`: the `minimum_reserve` / `home_domain`
        // criteria fail closed on this tool pending account-view wiring,
        // acceptable for this step.
        let value_leg = vault_withdraw_value_leg(vault_args.withdraw_shares, &args.vault_address);
        // Capture the gate-derived leg as an audit record before the descriptor
        // moves into the gate (single-derivation invariant).
        let audit_legs = vec![stellar_agent_core::audit_log::ValueLegRecord::from(
            &value_leg,
        )];
        let args_value = json!({
            "chain_id": args.chain_id,
            "vault_address": args.vault_address,
            "from_address": args.from_address,
        });
        let dispatch_outcome = match self
            .dispatch_gate_with_value(
                "stellar_defindex_vault_withdraw",
                &args_value,
                &args.chain_id,
                ValueClass::single(value_leg),
                None,
                None,
            )
            .await
        {
            Ok(o) => o,
            Err(e) => return e.into_result(),
        };

        if matches!(dispatch_outcome, DispatchOutcome::RequireApproval(_)) {
            return Ok(crate::tools::common::single_shot_require_approval_error());
        }

        // ── Build RPCs ────────────────────────────────────────────────────────
        let rpc_url = self.profile.rpc_url.as_str();
        let primary_rpc = StellarRpcClient::new(rpc_url).map_err(|e| {
            rmcp::ErrorData::internal_error(format!("vault.rpc_init_failed: {e}"), None)
        })?;
        let secondary_rpc: Option<StellarRpcClient> = args
            .secondary_rpc_url
            .as_deref()
            .map(|url| {
                StellarRpcClient::new(url).map_err(|e| {
                    rmcp::ErrorData::internal_error(
                        format!("vault.secondary_rpc_init_failed: {e}"),
                        None,
                    )
                })
            })
            .transpose()?;

        // ── ORDERED TRUST GATE step 1: verify vault WASM hash ───────────────
        // The vault WASM hash is identical on testnet and pubnet.
        if let Err(e) =
            verify_defindex_vault_wasm(&args.vault_address, &primary_rpc, secondary_rpc.as_ref())
                .await
        {
            tracing::warn!(
                event = "vault.wasm_pin_failed",
                vault_redacted =
                    stellar_agent_core::observability::redact_strkey_first5_last5(&args.vault_address),
                error = %e,
            );
            return Ok(tool_error_result(
                "vault.wasm_pin_failed",
                "vault WASM hash does not match the pinned DeFindex set",
            ));
        }

        // ── ORDERED TRUST GATE step 2: read upgradable flag ─────────────────
        let is_upgradable = match read_vault_upgradable_flag(&args.vault_address, &primary_rpc)
            .await
        {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    event = "vault.upgradable_read_failed",
                    vault_redacted = stellar_agent_core::observability::redact_strkey_first5_last5(
                        &args.vault_address
                    ),
                    error = %e,
                );
                return Ok(tool_error_result(
                    "vault.upgradable_read_failed",
                    "could not read vault upgradable flag (fail-safe: treating as upgradable=true)",
                ));
            }
        };

        // ── ORDERED TRUST GATE step 3: read roles ────────────────────────────
        let roles = match read_vault_roles(&args.vault_address, &primary_rpc).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(
                    event = "vault.roles_read_failed",
                    vault_redacted = stellar_agent_core::observability::redact_strkey_first5_last5(
                        &args.vault_address
                    ),
                    error = %e,
                );
                return Ok(tool_error_result(
                    "vault.roles_read_failed",
                    "could not read vault roles",
                ));
            }
        };

        let management_mode = roles.management_mode(&args.from_address);
        let roles_summary = roles.disclosure_summary();

        match &management_mode {
            VaultManagementMode::SelfManaged => {
                tracing::info!(
                    event = "vault.self_managed",
                    vault_redacted = stellar_agent_core::observability::redact_strkey_first5_last5(
                        &args.vault_address
                    ),
                    roles = %roles_summary,
                );
            }
            VaultManagementMode::Delegated {
                third_party_emergency_manager,
                third_party_rebalance_manager,
            } => {
                tracing::warn!(
                    event = "vault.delegated_roles_present",
                    vault_redacted = stellar_agent_core::observability::redact_strkey_first5_last5(
                        &args.vault_address
                    ),
                    third_party_emergency_manager = third_party_emergency_manager,
                    third_party_rebalance_manager = third_party_rebalance_manager,
                    roles = %roles_summary,
                );
            }
            VaultManagementMode::NotManager => {
                tracing::info!(
                    event = "vault.not_manager",
                    vault_redacted = stellar_agent_core::observability::redact_strkey_first5_last5(
                        &args.vault_address
                    ),
                );
            }
        }

        // ── ORDERED TRUST GATE step 4: read assets + validate + detect ──────
        let mut assets = match read_vault_assets(&args.vault_address, &primary_rpc).await {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!(
                    event = "vault.assets_read_failed",
                    vault_redacted = stellar_agent_core::observability::redact_strkey_first5_last5(
                        &args.vault_address
                    ),
                    error = %e,
                );
                return Ok(tool_error_result(
                    "vault.assets_read_failed",
                    "could not read vault assets (ordered gate step 4 failed)",
                ));
            }
        };

        // Validate min_amounts_out length against the PIN-VERIFIED on-chain asset count.
        if let Err(e) = vault_args.validate_against_asset_count(assets.len()) {
            return Ok(tool_error_result(
                "vault.asset_count_mismatch",
                &e.to_string(),
            ));
        }

        // Blend-strategy detection via WASM-hash match (per strategy address).
        for asset in &mut assets {
            for strategy in &mut asset.strategies {
                match fetch_contract_wasm_hash(
                    &primary_rpc,
                    secondary_rpc.as_ref(),
                    &strategy.address,
                )
                .await
                {
                    Ok(WasmHashFetch::Wasm(hash)) => {
                        strategy.is_blend_strategy = is_blend_strategy(&hash, &args.chain_id);
                    }
                    Ok(_) | Err(_) => {
                        strategy.is_blend_strategy = false;
                    }
                }
            }
        }

        // ── ORDERED TRUST GATE step 5: mode-aware upgradable evaluation ──────
        if let Err(reason) =
            UpgradableEvalExt::evaluate(is_upgradable, args.override_upgradable, &management_mode)
        {
            tracing::warn!(
                event = "vault.upgradable_refused",
                vault_redacted =
                    stellar_agent_core::observability::redact_strkey_first5_last5(&args.vault_address),
                reason = %reason,
            );
            return Ok(tool_error_result(
                "vault.upgradable_refused",
                &reason.to_string(),
            ));
        }

        // ── Build VaultOperationPreview for rich gate-passed summary ─────────
        let preview = VaultOperationPreview::from_withdraw(
            &vault_args,
            &args.chain_id,
            is_upgradable,
            roles.clone(),
            assets,
        );
        let preview_summary = preview.summary();

        // ── DeFi dispatch gate ────────────────────────────────────────────────
        let gate_result = dispatch_gate("vault", &args.vault_address);
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
                    format!("vault.gate_error: {e}"),
                    None,
                ));
            }
        };

        // ── Load signer ───────────────────────────────────────────────────────
        let signer_entry_ref = &self.profile.mcp_signer_default;
        let expected_g_strkey = signer_entry_ref.account.as_str();
        let signer_handle = match signer_from_keyring(signer_entry_ref, expected_g_strkey).await {
            Ok(h) => h,
            Err(_) => {
                return Ok(crate::tools::common::business_error_result(
                    "vault.signer_load_failed",
                    "could not load signer from keyring",
                ));
            }
        };

        let timeout = crate::tools::common::submit_timeout(&self.profile);
        let network = self.profile.network_passphrase.as_str();

        // WASM hash already verified at step 1; use the real hash for audit.
        let vault_pin = DefiContractPin::new(
            "defindex",
            "v1",
            "default",
            &args.chain_id,
            &args.vault_address,
            DEFINDEX_VAULT_WASM_HASH,
            "defindex-vault", // abi_source_provenance
        );

        let mut ctx = DefiAdapterCtx::new_with_submit_ctx(
            "default",
            &vault_pin,
            &primary_rpc,
            Some(&signer_handle as &(dyn stellar_agent_network::Signer + Send + Sync)),
            Some(network),
            Some(args.chain_id.as_str()),
            secondary_rpc.as_ref(),
            Some(timeout),
        );
        // Thread the audit writer + gate-derived leg so the adapter emits the
        // ValueActionSubmitted row after a confirmed submit (non-fatal).
        let audit_profile_name = self.profile_name_for_approval();
        ctx.audit_writer = crate::tools::value_audit::acquire_value_audit_writer(
            &self.profile,
            &audit_profile_name,
        );
        ctx.audit_legs = Some(&audit_legs);
        ctx.audit_tool = Some("stellar_defindex_vault_withdraw");

        tracing::info!(
            verb = "vault",
            action = "withdraw",
            vault_redacted = stellar_agent_core::observability::redact_strkey_first5_last5(
                &args.vault_address
            ),
            from_redacted = stellar_agent_core::observability::redact_strkey_first5_last5(
                &args.from_address
            ),
            management_mode = ?management_mode,
            roles = %roles_summary,
            upgradable = is_upgradable,
            preview = %preview_summary,
            request_id = witness.request_id(),
            "DeFindex vault: ordered gate passed, submitting withdraw via adapter"
        );

        // ── Delegate to DefindexVaultAdapter::submit ──────────────────────────
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
                let resp = json!({
                    "status": "submitted",
                    "action": "withdraw",
                    "vault_address_redacted": stellar_agent_core::observability::redact_strkey_first5_last5(&args.vault_address),
                    "from_address_redacted": stellar_agent_core::observability::redact_strkey_first5_last5(&args.from_address),
                    "preview": preview_summary,
                    "roles": roles_summary,
                    "management_mode": format!("{management_mode:?}"),
                    "upgradable": is_upgradable,
                });
                let json_str =
                    serde_json::to_string_pretty(&resp).unwrap_or_else(|_| "{}".to_owned());
                Ok(CallToolResult::success(vec![Content::text(json_str)]))
            }
            Err(e) => Ok(crate::tools::common::business_error_result(
                "vault.submit_failed",
                e.to_string(),
            )),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper
// ─────────────────────────────────────────────────────────────────────────────

/// Builds the documented business-error result envelope (`is_error = true`,
/// `ok: false`, `error.code`) from a code + message. The `code` string is
/// preserved verbatim as `error.code`.
fn tool_error_result(code: &str, message: &str) -> CallToolResult {
    crate::tools::common::business_error_result(code.to_owned(), message.to_owned())
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
    use super::{VaultDepositMcpArgs, VaultWithdrawMcpArgs};

    // ── VaultDepositMcpArgs: decimal-string wire ──────────────────────────────

    #[test]
    fn vault_deposit_args_deserialises_string_amounts_above_2_pow_53() {
        let json = serde_json::json!({
            "chain_id": "stellar:testnet",
            "vault_address": "CBMVK2JK6NTOT2O4HNQAIQFJY232BHKGLIMXDVQVHIIZKDACXDFZDWHN",
            "from_address": "CAJJZSGMMM3PD7N33TAPHGBUGTB43OC73HVIK2L2G6BNGGGYOSSYBXBD",
            "amounts_desired": ["9007199254740993"],
            "amounts_min": ["1"],
        });
        let args: VaultDepositMcpArgs = serde_json::from_value(json).expect("deserialise");
        assert_eq!(
            args.amounts_desired[0].parse::<i128>().expect("parse"),
            9_007_199_254_740_993_i128
        );
    }

    #[test]
    fn vault_deposit_args_rejects_raw_json_number_in_amounts_desired() {
        let json = serde_json::json!({
            "chain_id": "stellar:testnet",
            "vault_address": "CBMVK2JK6NTOT2O4HNQAIQFJY232BHKGLIMXDVQVHIIZKDACXDFZDWHN",
            "from_address": "CAJJZSGMMM3PD7N33TAPHGBUGTB43OC73HVIK2L2G6BNGGGYOSSYBXBD",
            "amounts_desired": [1_000_000_000],
            "amounts_min": ["1"],
        });
        let result: Result<VaultDepositMcpArgs, _> = serde_json::from_value(json);
        assert!(
            result.is_err(),
            "a raw JSON number inside amounts_desired must be rejected (String-typed field)"
        );
    }

    #[test]
    fn vault_deposit_args_round_trips_through_serde_json_from_value() {
        let value = serde_json::json!({
            "chain_id": "stellar:testnet",
            "vault_address": "CBMVK2JK6NTOT2O4HNQAIQFJY232BHKGLIMXDVQVHIIZKDACXDFZDWHN",
            "from_address": "CAJJZSGMMM3PD7N33TAPHGBUGTB43OC73HVIK2L2G6BNGGGYOSSYBXBD",
            "amounts_desired": ["170141183460469231731687303715884105727"],
            "amounts_min": ["0"],
        });
        let args: VaultDepositMcpArgs =
            serde_json::from_value(value).expect("from_value must succeed");
        assert_eq!(
            args.amounts_desired[0].parse::<i128>().expect("parse"),
            i128::MAX
        );
    }

    #[test]
    fn vault_deposit_amounts_vec_index_error_names_the_failing_entry() {
        let v = vec!["1".to_owned(), "not-a-number".to_owned()];
        let err = crate::tools::amount_wire::parse_i128_vec_field("amounts_min", &v).unwrap_err();
        let msg = err.message.to_string();
        assert!(
            msg.contains("amounts_min[1]"),
            "error must name the failing index: {msg}"
        );
    }

    // ── VaultWithdrawMcpArgs: decimal-string wire ─────────────────────────────

    #[test]
    fn vault_withdraw_args_deserialises_string_shares_above_2_pow_53() {
        let json = serde_json::json!({
            "chain_id": "stellar:testnet",
            "vault_address": "CBMVK2JK6NTOT2O4HNQAIQFJY232BHKGLIMXDVQVHIIZKDACXDFZDWHN",
            "from_address": "CAJJZSGMMM3PD7N33TAPHGBUGTB43OC73HVIK2L2G6BNGGGYOSSYBXBD",
            "withdraw_shares": "9007199254740993",
            "min_amounts_out": ["1"],
        });
        let args: VaultWithdrawMcpArgs = serde_json::from_value(json).expect("deserialise");
        assert_eq!(
            args.withdraw_shares.parse::<i128>().expect("parse"),
            9_007_199_254_740_993_i128
        );
    }

    #[test]
    fn vault_withdraw_args_rejects_raw_json_number_for_withdraw_shares() {
        let json = serde_json::json!({
            "chain_id": "stellar:testnet",
            "vault_address": "CBMVK2JK6NTOT2O4HNQAIQFJY232BHKGLIMXDVQVHIIZKDACXDFZDWHN",
            "from_address": "CAJJZSGMMM3PD7N33TAPHGBUGTB43OC73HVIK2L2G6BNGGGYOSSYBXBD",
            "withdraw_shares": 5_000_000,
            "min_amounts_out": ["1"],
        });
        let result: Result<VaultWithdrawMcpArgs, _> = serde_json::from_value(json);
        assert!(
            result.is_err(),
            "a raw JSON number for withdraw_shares must be rejected (String-typed field)"
        );
    }

    #[test]
    fn vault_withdraw_args_round_trips_through_serde_json_from_value() {
        let value = serde_json::json!({
            "chain_id": "stellar:testnet",
            "vault_address": "CBMVK2JK6NTOT2O4HNQAIQFJY232BHKGLIMXDVQVHIIZKDACXDFZDWHN",
            "from_address": "CAJJZSGMMM3PD7N33TAPHGBUGTB43OC73HVIK2L2G6BNGGGYOSSYBXBD",
            "withdraw_shares": "170141183460469231731687303715884105727",
            "min_amounts_out": ["0"],
        });
        let args: VaultWithdrawMcpArgs =
            serde_json::from_value(value).expect("from_value must succeed");
        assert_eq!(
            args.withdraw_shares.parse::<i128>().expect("parse"),
            i128::MAX
        );
    }

    #[test]
    fn redact_strkey_format() {
        use stellar_agent_core::observability::redact_strkey_first5_last5;
        // Vault address redaction: first-5-last-5.
        let vault = "CBMVK2JK6NTOT2O4HNQAIQFJY232BHKGLIMXDVQVHIIZKDACXDFZDWHN";
        let redacted = redact_strkey_first5_last5(vault);
        assert!(
            redacted.contains("CBMVK"),
            "redacted must contain first-5: {redacted}"
        );
        assert!(
            redacted.contains("ZDWHN"),
            "redacted must contain last-5: {redacted}"
        );
        assert!(
            !redacted.contains("JK6NTOT2O4"),
            "redacted must not contain middle: {redacted}"
        );
    }
}
