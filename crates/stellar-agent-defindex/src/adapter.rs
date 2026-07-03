//! DeFindex `DefiAdapter` implementation — the `vault` verb.
//!
//! # What this module does
//!
//! Implements `stellar_agent_defi::adapter::DefiAdapter` for the DeFindex
//! vault protocol, exposing the `vault` verb through the dispatch seam.
//!
//! The adapter handles both `deposit` and `withdraw` sub-actions, dispatched
//! by the presence of `VaultDepositArgs` vs `VaultWithdrawArgs` at downcast time.
//!
//! # Ordered trust gate enforcement (inline in submit)
//!
//! The ordered trust gate runs INLINE inside `submit_deposit` and
//! `submit_withdraw`, AFTER structural validation and BEFORE ScVal encoding.
//! The gate steps are enforced in order via `?`-early-return (fail-closed):
//!
//! 1. **PIN-VERIFY** — `verify_defindex_vault_wasm` confirms the vault's
//!    on-chain WASM hash matches the pinned DeFindex vault hash (two-RPC check).
//! 2. **Upgradable flag** — `read_vault_upgradable_flag` reads the
//!    `DataKey::Upgradable` value from instance storage.
//! 3. **Roles + management mode** — `read_vault_roles` reads all four role
//!    addresses; `management_mode` is computed from the on-chain snapshot.
//! 4. **Upgradable refusal** — `UpgradableEvalExt::evaluate` refuses when
//!    the vault is upgradable and the management mode is not self-managed,
//!    unless `override_upgradable = true`.
//! 5. **Asset-count validation** — `read_vault_assets` reads the on-chain
//!    asset count (bounded by `MAX_VAULT_ASSETS`); `validate_against_asset_count`
//!    confirms the caller's amounts vectors match.
//!
//! The dispatch site (MCP/CLI) builds the RICH `VaultOperationPreview` (role
//! disclosure, Blend-strategy detection) from its own gate run, which may
//! happen before `submit` is called.  The REFUSALS (upgradable, pin, counts)
//! are enforced here in submit — not delegated to the dispatch site.
//!
//! # Witness consumption
//!
//! [`DefindexVaultAdapter::submit`] consumes the [`SubmitWitness`] by logging,
//! then drops it.  The witness is held until after `submit_signed_invoke`
//! returns; a submit that errors still consumed a witness (the gate ran).
//!
//! # Fail-closed `Any` downcast
//!
//! The `args: &dyn Any` downcast is fail-closed: a cast miss returns
//! `DefiAdapterError::InvalidArguments`, never `.unwrap()` or panic.

use std::any::Any;

use async_trait::async_trait;

use stellar_agent_core::ContextRuleId;
use stellar_agent_defi::adapter::{DefiAdapter, DefiAdapterCtx, DefiAdapterError, DefiPreview};
use stellar_agent_defi::dispatch::SubmitWitness;
use stellar_agent_smart_account::submit::{SubmitInvokeArgs, submit_signed_invoke};

use crate::abi::{VaultDepositArgs, VaultWithdrawArgs};
use crate::scval::{args_to_vecm, encode_vault_deposit_args, encode_vault_withdraw_args};

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// DeFindex vault `deposit` function name.
///
/// Matches the DeFindex vault contract interface.
const DEFINDEX_DEPOSIT_FN: &str = "deposit";

/// DeFindex vault `withdraw` function name.
///
/// Matches the DeFindex vault contract interface.
const DEFINDEX_WITHDRAW_FN: &str = "withdraw";

/// Operation label for `submit_signed_invoke` observability logs.
const DEFINDEX_SUBMIT_OP_LABEL: &str = "defindex_vault";

/// Default submit timeout when none is provided in the context.
const DEFAULT_SUBMIT_TIMEOUT_SECS: u64 = 60;

// ─────────────────────────────────────────────────────────────────────────────
// DefindexVaultAdapter
// ─────────────────────────────────────────────────────────────────────────────

/// DeFindex vault adapter implementing [`DefiAdapter`].
///
/// Exposes the `"vault"` verb through the DeFi dispatch seam.
/// Handles both deposit and withdraw sub-actions, dispatching on arg type
/// at downcast time.
#[derive(Debug)]
pub struct DefindexVaultAdapter;

impl DefindexVaultAdapter {
    /// Constructs a new `DefindexVaultAdapter`.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for DefindexVaultAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl DefiAdapter for DefindexVaultAdapter {
    fn verb(&self) -> &'static str {
        "vault"
    }

    fn criterion_kinds(&self) -> &'static [&'static str] {
        &["vault_upgradable"]
    }

    /// Produces a minimal [`DefiPreview`] from `VaultDepositArgs` or `VaultWithdrawArgs`.
    ///
    /// This is a structural-validation-only preview; it does NOT fetch on-chain
    /// data (roles, assets, Blend detection).  The rich `VaultOperationPreview`
    /// with roles, Blend-strategy disclosure, and management mode is built at
    /// the dispatch site (MCP/CLI) and its `summary()` is included in the submit
    /// response.  The REFUSALS (pin, upgradable, asset-count) are enforced
    /// inline in `submit`, not in `preview`.
    ///
    /// # Errors
    ///
    /// Returns [`DefiAdapterError::InvalidArguments`] when:
    /// - `args` cannot be downcast to `VaultDepositArgs` or `VaultWithdrawArgs`.
    /// - Structural validation of the args fails.
    async fn preview(
        &self,
        args: &(dyn Any + Send + Sync),
        ctx: &DefiAdapterCtx<'_>,
    ) -> Result<DefiPreview, DefiAdapterError> {
        // Try deposit first, then withdraw.  Fail-closed on miss.
        if let Some(deposit_args) = args.downcast_ref::<VaultDepositArgs>() {
            return self.preview_deposit(deposit_args, ctx).await;
        }
        if let Some(withdraw_args) = args.downcast_ref::<VaultWithdrawArgs>() {
            return self.preview_withdraw(withdraw_args, ctx).await;
        }
        Err(DefiAdapterError::InvalidArguments {
            reason:
                "expected VaultDepositArgs or VaultWithdrawArgs; downcast failed (programmer error)"
                    .to_owned(),
        })
    }

    /// Executes the DeFindex vault `deposit` or `withdraw` call via
    /// `submit_signed_invoke`, consuming the [`SubmitWitness`].
    ///
    /// # Submit flow
    ///
    /// 1. Downcast `args` to `VaultDepositArgs` or `VaultWithdrawArgs`.
    /// 2. Validate structural constraints.
    /// 3. Run the ordered trust gate (fail-closed, in order):
    ///    a. PIN-VERIFY vault WASM hash.
    ///    b. Read `DataKey::Upgradable` flag.
    ///    c. Read roles + compute management mode.
    ///    d. Evaluate upgradable refusal (exempt for self-managed, refused for
    ///       delegated/not-manager unless `override_upgradable = true`).
    ///    e. Read on-chain asset list and validate amounts-vector lengths.
    /// 4. Encode args as `ScVal` argument vector (positional, per ABI).
    /// 5. Build `HostFunction::InvokeContract`.
    /// 6. Call `submit_signed_invoke`.
    /// 7. Drop witness after submit completes.
    ///
    /// # Errors
    ///
    /// Returns [`DefiAdapterError`] when:
    /// - Downcast fails.
    /// - Submit context fields absent.
    /// - Any ordered-gate step fails (pin, upgradable refusal, asset count mismatch).
    /// - ScVal encoding fails.
    /// - `submit_signed_invoke` returns an error.
    async fn submit(
        &self,
        args: &(dyn Any + Send + Sync),
        ctx: &DefiAdapterCtx<'_>,
        witness: SubmitWitness,
    ) -> Result<(), DefiAdapterError> {
        // Try deposit first, then withdraw.
        if let Some(deposit_args) = args.downcast_ref::<VaultDepositArgs>() {
            let deposit_args = deposit_args.clone();
            return self.submit_deposit(&deposit_args, ctx, witness).await;
        }
        if let Some(withdraw_args) = args.downcast_ref::<VaultWithdrawArgs>() {
            let withdraw_args = withdraw_args.clone();
            return self.submit_withdraw(&withdraw_args, ctx, witness).await;
        }
        // Witness is consumed here (drop) even on type mismatch — the gate ran.
        drop(witness);
        Err(DefiAdapterError::InvalidArguments {
            reason: "expected VaultDepositArgs or VaultWithdrawArgs in submit; downcast failed"
                .to_owned(),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Private preview helpers
// ─────────────────────────────────────────────────────────────────────────────

impl DefindexVaultAdapter {
    async fn preview_deposit(
        &self,
        deposit_args: &VaultDepositArgs,
        ctx: &DefiAdapterCtx<'_>,
    ) -> Result<DefiPreview, DefiAdapterError> {
        // Structural validation.
        deposit_args
            .validate_structure()
            .map_err(|e| DefiAdapterError::InvalidArguments {
                reason: format!("deposit args invalid: {e}"),
            })?;

        // Build a minimal preview using the contract pin's network + redacted address.
        // On-chain role/assets data is injected by the dispatch site; at preview-only
        // time we use placeholder text (ordered gate result not yet available).
        let network = ctx.pin.network.clone();
        let vault_redacted = ctx.pin.redacted_address();
        let summary = format!(
            "vault=deposit vault={vault_redacted} network={network} amounts={:?} min={:?} invest={}",
            deposit_args.amounts_desired, deposit_args.amounts_min, deposit_args.invest
        );

        Ok(DefiPreview::new(
            "defindex",
            self.verb(),
            network.as_str(),
            vault_redacted,
            summary,
        ))
    }

    async fn preview_withdraw(
        &self,
        withdraw_args: &VaultWithdrawArgs,
        ctx: &DefiAdapterCtx<'_>,
    ) -> Result<DefiPreview, DefiAdapterError> {
        withdraw_args
            .validate_structure()
            .map_err(|e| DefiAdapterError::InvalidArguments {
                reason: format!("withdraw args invalid: {e}"),
            })?;

        let network = ctx.pin.network.clone();
        let vault_redacted = ctx.pin.redacted_address();
        let summary = format!(
            "vault=withdraw vault={vault_redacted} network={network} shares={} min_out={:?}",
            withdraw_args.withdraw_shares, withdraw_args.min_amounts_out
        );

        Ok(DefiPreview::new(
            "defindex",
            self.verb(),
            network.as_str(),
            vault_redacted,
            summary,
        ))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Private submit helpers
// ─────────────────────────────────────────────────────────────────────────────

impl DefindexVaultAdapter {
    async fn submit_deposit(
        &self,
        deposit_args: &VaultDepositArgs,
        ctx: &DefiAdapterCtx<'_>,
        witness: SubmitWitness,
    ) -> Result<(), DefiAdapterError> {
        // ── Step 1: Structural validation ────────────────────────────────────
        deposit_args
            .validate_structure()
            .map_err(|e| DefiAdapterError::InvalidArguments {
                reason: format!("deposit args invalid at submit: {e}"),
            })?;

        // ── Step 2: Extract submit context ───────────────────────────────────
        let (signer, network_passphrase, chain_id, timeout) = extract_submit_ctx(ctx)?;

        // ── Steps 3a-3e: Ordered trust gate (fail-closed, in order) ─────────

        // 3a. PIN-VERIFY: confirm vault WASM hash against the pinned DeFindex hash.
        crate::pins::verify_defindex_vault_wasm(
            &deposit_args.vault_address,
            ctx.primary_rpc,
            ctx.secondary_rpc,
        )
        .await
        .map_err(|e| DefiAdapterError::PinFailed {
            reason: format!("vault WASM pin-verify failed: {e}"),
        })?;

        // 3b. Read the upgradable flag from instance storage.
        let is_upgradable = crate::storage::read_vault_upgradable_flag(
            &deposit_args.vault_address,
            ctx.primary_rpc,
        )
        .await
        .map_err(|e| DefiAdapterError::Network {
            reason: format!("vault upgradable-flag read failed: {e}"),
        })?;

        // 3c. Read roles and compute management mode.
        let roles = crate::roles::read_vault_roles(&deposit_args.vault_address, ctx.primary_rpc)
            .await
            .map_err(|e| DefiAdapterError::Network {
                reason: format!("vault roles read failed: {e}"),
            })?;
        let mode = roles.management_mode(&deposit_args.from_address);

        // 3d. Upgradable refusal (self-managed exempt; delegated/not-manager refused
        //     unless override_upgradable = true).
        crate::criteria::upgradable::UpgradableEvalExt::evaluate(
            is_upgradable,
            deposit_args.override_upgradable,
            &mode,
        )
        .map_err(|denial| DefiAdapterError::InvalidArguments {
            reason: denial.to_string(),
        })?;

        // 3e. Read on-chain asset list (bounded by MAX_VAULT_ASSETS) and validate
        //     that both amounts_desired and amounts_min lengths match the vault.
        let vault_assets =
            crate::storage::read_vault_assets(&deposit_args.vault_address, ctx.primary_rpc)
                .await
                .map_err(|e| DefiAdapterError::Network {
                    reason: format!("vault assets read failed: {e}"),
                })?;
        deposit_args
            .validate_against_asset_count(vault_assets.len())
            .map_err(|e| DefiAdapterError::InvalidArguments {
                reason: format!("amounts length mismatch: {e}"),
            })?;

        tracing::debug!(
            verb = "vault",
            action = "deposit",
            vault_redacted = ctx.pin.redacted_address(),
            "DeFindex vault: ordered trust gate passed (pin/upgradable/roles/asset-count)"
        );

        // ── Step 4: Encode vault address as ScAddress ────────────────────────
        let vault_sc_addr = crate::scval::encode_c_strkey_address(&deposit_args.vault_address)
            .map_err(|e| DefiAdapterError::InvalidArguments {
                reason: format!("invalid vault_address: {e}"),
            })?;

        // Encode deposit args as ScVal vector.
        let deposit_scvals = encode_vault_deposit_args(deposit_args).map_err(|e| {
            DefiAdapterError::InvalidArguments {
                reason: format!("ScVal encoding failed: {e}"),
            }
        })?;

        // Build InvokeContractArgs. Both vault_sc_addr and deposit_scvals are
        // stellar_xdr types; no round-trip needed.
        let invoke_args =
            build_invoke_contract_args(&vault_sc_addr, DEFINDEX_DEPOSIT_FN, deposit_scvals)?;
        let host_function = stellar_xdr::HostFunction::InvokeContract(invoke_args);

        let secondary_rpc_url = ctx
            .secondary_rpc
            .map(stellar_agent_network::StellarRpcClient::url);

        tracing::info!(
            verb = self.verb(),
            action = "deposit",
            vault_redacted = ctx.pin.redacted_address(),
            from_redacted = stellar_agent_core::observability::redact_strkey_first5_last5(
                &deposit_args.from_address
            ),
            request_id = witness.request_id(),
            "DeFindex vault: submitting deposit via smart-account submit path"
        );

        let submit_result = submit_signed_invoke(
            SubmitInvokeArgs::builder()
                .target_contract(&deposit_args.vault_address)
                .auth_address(&deposit_args.from_address)
                .auth_rule_ids(&[ContextRuleId::new(0)])
                .host_function(host_function)
                .signer(signer)
                .primary_rpc_url(ctx.primary_rpc.url())
                .maybe_secondary_rpc_url(secondary_rpc_url)
                .network_passphrase(network_passphrase)
                .chain_id(chain_id)
                .timeout(timeout)
                .op_label(DEFINDEX_SUBMIT_OP_LABEL)
                .emit_observability_logs(true)
                .build(),
        )
        .await;

        let request_id = witness.request_id().to_owned();
        drop(witness);

        match submit_result {
            Ok(result) => {
                tracing::info!(
                    verb = self.verb(),
                    action = "deposit",
                    request_id = %request_id,
                    tx_hash_redacted = stellar_agent_network::redact_tx_hash(&result.tx_hash),
                    "DeFindex vault deposit: submit succeeded"
                );
                Ok(())
            }
            Err(e) => Err(DefiAdapterError::Network {
                reason: format!("submit_signed_invoke failed: {e}"),
            }),
        }
    }

    async fn submit_withdraw(
        &self,
        withdraw_args: &VaultWithdrawArgs,
        ctx: &DefiAdapterCtx<'_>,
        witness: SubmitWitness,
    ) -> Result<(), DefiAdapterError> {
        // ── Step 1: Structural validation ────────────────────────────────────
        withdraw_args
            .validate_structure()
            .map_err(|e| DefiAdapterError::InvalidArguments {
                reason: format!("withdraw args invalid at submit: {e}"),
            })?;

        // ── Step 2: Extract submit context ───────────────────────────────────
        let (signer, network_passphrase, chain_id, timeout) = extract_submit_ctx(ctx)?;

        // ── Steps 3a-3e: Ordered trust gate (fail-closed, in order) ─────────

        // 3a. PIN-VERIFY: confirm vault WASM hash against the pinned DeFindex hash.
        crate::pins::verify_defindex_vault_wasm(
            &withdraw_args.vault_address,
            ctx.primary_rpc,
            ctx.secondary_rpc,
        )
        .await
        .map_err(|e| DefiAdapterError::PinFailed {
            reason: format!("vault WASM pin-verify failed: {e}"),
        })?;

        // 3b. Read the upgradable flag from instance storage.
        let is_upgradable = crate::storage::read_vault_upgradable_flag(
            &withdraw_args.vault_address,
            ctx.primary_rpc,
        )
        .await
        .map_err(|e| DefiAdapterError::Network {
            reason: format!("vault upgradable-flag read failed: {e}"),
        })?;

        // 3c. Read roles and compute management mode.
        let roles = crate::roles::read_vault_roles(&withdraw_args.vault_address, ctx.primary_rpc)
            .await
            .map_err(|e| DefiAdapterError::Network {
                reason: format!("vault roles read failed: {e}"),
            })?;
        let mode = roles.management_mode(&withdraw_args.from_address);

        // 3d. Upgradable refusal (self-managed exempt; delegated/not-manager refused
        //     unless override_upgradable = true).
        crate::criteria::upgradable::UpgradableEvalExt::evaluate(
            is_upgradable,
            withdraw_args.override_upgradable,
            &mode,
        )
        .map_err(|denial| DefiAdapterError::InvalidArguments {
            reason: denial.to_string(),
        })?;

        // 3e. Read on-chain asset list (bounded by MAX_VAULT_ASSETS) and validate
        //     that min_amounts_out length matches the vault asset count.
        let vault_assets =
            crate::storage::read_vault_assets(&withdraw_args.vault_address, ctx.primary_rpc)
                .await
                .map_err(|e| DefiAdapterError::Network {
                    reason: format!("vault assets read failed: {e}"),
                })?;
        withdraw_args
            .validate_against_asset_count(vault_assets.len())
            .map_err(|e| DefiAdapterError::InvalidArguments {
                reason: format!("amounts length mismatch: {e}"),
            })?;

        tracing::debug!(
            verb = "vault",
            action = "withdraw",
            vault_redacted = ctx.pin.redacted_address(),
            "DeFindex vault: ordered trust gate passed (pin/upgradable/roles/asset-count)"
        );

        // ── Step 4: Encode vault address as ScAddress ────────────────────────
        let vault_sc_addr = crate::scval::encode_c_strkey_address(&withdraw_args.vault_address)
            .map_err(|e| DefiAdapterError::InvalidArguments {
                reason: format!("invalid vault_address: {e}"),
            })?;

        let withdraw_scvals = encode_vault_withdraw_args(withdraw_args).map_err(|e| {
            DefiAdapterError::InvalidArguments {
                reason: format!("ScVal encoding failed: {e}"),
            }
        })?;

        let invoke_args =
            build_invoke_contract_args(&vault_sc_addr, DEFINDEX_WITHDRAW_FN, withdraw_scvals)?;
        let host_function = stellar_xdr::HostFunction::InvokeContract(invoke_args);

        let secondary_rpc_url = ctx
            .secondary_rpc
            .map(stellar_agent_network::StellarRpcClient::url);

        tracing::info!(
            verb = self.verb(),
            action = "withdraw",
            vault_redacted = ctx.pin.redacted_address(),
            from_redacted = stellar_agent_core::observability::redact_strkey_first5_last5(
                &withdraw_args.from_address
            ),
            request_id = witness.request_id(),
            "DeFindex vault: submitting withdraw via smart-account submit path"
        );

        let submit_result = submit_signed_invoke(
            SubmitInvokeArgs::builder()
                .target_contract(&withdraw_args.vault_address)
                .auth_address(&withdraw_args.from_address)
                .auth_rule_ids(&[ContextRuleId::new(0)])
                .host_function(host_function)
                .signer(signer)
                .primary_rpc_url(ctx.primary_rpc.url())
                .maybe_secondary_rpc_url(secondary_rpc_url)
                .network_passphrase(network_passphrase)
                .chain_id(chain_id)
                .timeout(timeout)
                .op_label(DEFINDEX_SUBMIT_OP_LABEL)
                .emit_observability_logs(true)
                .build(),
        )
        .await;

        let request_id = witness.request_id().to_owned();
        drop(witness);

        match submit_result {
            Ok(result) => {
                tracing::info!(
                    verb = self.verb(),
                    action = "withdraw",
                    request_id = %request_id,
                    tx_hash_redacted = stellar_agent_network::redact_tx_hash(&result.tx_hash),
                    "DeFindex vault withdraw: submit succeeded"
                );
                Ok(())
            }
            Err(e) => Err(DefiAdapterError::Network {
                reason: format!("submit_signed_invoke failed: {e}"),
            }),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// submit helper functions
// ─────────────────────────────────────────────────────────────────────────────

fn extract_submit_ctx<'a>(
    ctx: &'a DefiAdapterCtx<'_>,
) -> Result<
    (
        &'a (dyn stellar_agent_network::Signer + Send + Sync),
        &'a str,
        &'a str,
        std::time::Duration,
    ),
    DefiAdapterError,
> {
    let signer = ctx
        .signer
        .ok_or_else(|| DefiAdapterError::InvalidArguments {
            reason: "submit ctx missing signer (use DefiAdapterCtx::new_with_submit_ctx)"
                .to_owned(),
        })?;
    let network_passphrase =
        ctx.network_passphrase
            .ok_or_else(|| DefiAdapterError::InvalidArguments {
                reason: "submit ctx missing network_passphrase".to_owned(),
            })?;
    let chain_id = ctx
        .chain_id
        .ok_or_else(|| DefiAdapterError::InvalidArguments {
            reason: "submit ctx missing chain_id".to_owned(),
        })?;
    let timeout = ctx
        .timeout
        .unwrap_or_else(|| std::time::Duration::from_secs(DEFAULT_SUBMIT_TIMEOUT_SECS));
    Ok((signer, network_passphrase, chain_id, timeout))
}

fn build_invoke_contract_args(
    contract_sc_addr: &stellar_xdr::ScVal,
    fn_name: &str,
    scval_args: Vec<stellar_xdr::ScVal>,
) -> Result<stellar_xdr::InvokeContractArgs, DefiAdapterError> {
    // Extract the ScAddress directly from the ScVal::Address variant — no XDR
    // round-trip needed since both the caller and InvokeContractArgs use
    // stellar_xdr types.
    let sc_address = match contract_sc_addr {
        stellar_xdr::ScVal::Address(a) => a.clone(),
        _ => {
            return Err(DefiAdapterError::InvalidArguments {
                reason: "contract_sc_addr is not ScVal::Address".to_owned(),
            });
        }
    };

    let fn_sym: stellar_xdr::StringM<32> =
        fn_name
            .try_into()
            .map_err(|_| DefiAdapterError::InvalidArguments {
                reason: format!("function name '{fn_name}' too long for ScSymbol"),
            })?;

    let args_vecm = args_to_vecm(scval_args).map_err(|e| DefiAdapterError::InvalidArguments {
        reason: format!("args VecM conversion: {e}"),
    })?;

    Ok(stellar_xdr::InvokeContractArgs {
        contract_address: sc_address,
        function_name: stellar_xdr::ScSymbol(fn_sym),
        args: args_vecm,
    })
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

    use super::*;
    use crate::abi::{VaultDepositArgs, VaultWithdrawArgs};
    use stellar_agent_defi::pins::DefiContractPin;
    use stellar_agent_network::StellarRpcClient;

    fn test_pin() -> DefiContractPin {
        DefiContractPin::new(
            "defindex",
            "v1",
            "default",
            "stellar:testnet",
            "CBMVK2JK6NTOT2O4HNQAIQFJY232BHKGLIMXDVQVHIIZKDACXDFZDWHN",
            crate::pins::DEFINDEX_VAULT_WASM_HASH,
            "defindex-vault",
        )
    }

    fn test_rpc() -> StellarRpcClient {
        StellarRpcClient::new("https://soroban-testnet.stellar.org").expect("valid URL")
    }

    fn deposit_args() -> VaultDepositArgs {
        VaultDepositArgs {
            vault_address: "CBMVK2JK6NTOT2O4HNQAIQFJY232BHKGLIMXDVQVHIIZKDACXDFZDWHN".to_owned(),
            amounts_desired: vec![1_000_000_000i128],
            amounts_min: vec![900_000_000i128],
            from_address: "CAJJZSGMMM3PD7N33TAPHGBUGTB43OC73HVIK2L2G6BNGGGYOSSYBXBD".to_owned(),
            invest: false,
            override_upgradable: false,
        }
    }

    fn withdraw_args() -> VaultWithdrawArgs {
        VaultWithdrawArgs {
            vault_address: "CBMVK2JK6NTOT2O4HNQAIQFJY232BHKGLIMXDVQVHIIZKDACXDFZDWHN".to_owned(),
            withdraw_shares: 5_000_000i128,
            min_amounts_out: vec![4_500_000i128],
            from_address: "CAJJZSGMMM3PD7N33TAPHGBUGTB43OC73HVIK2L2G6BNGGGYOSSYBXBD".to_owned(),
            override_upgradable: false,
        }
    }

    // ── Verb identity ────────────────────────────────────────────────────────

    #[test]
    fn verb_is_vault() {
        let adapter = DefindexVaultAdapter::new();
        assert_eq!(adapter.verb(), "vault");
    }

    // ── Criterion kinds ──────────────────────────────────────────────────────

    #[test]
    fn criterion_kinds_includes_vault_upgradable() {
        let adapter = DefindexVaultAdapter::new();
        assert!(
            adapter.criterion_kinds().contains(&"vault_upgradable"),
            "must include vault_upgradable criterion"
        );
    }

    // ── Preview with valid deposit args ─────────────────────────────────────

    #[tokio::test]
    async fn preview_deposit_with_valid_args_succeeds() {
        let adapter = DefindexVaultAdapter::new();
        let pin = test_pin();
        let rpc = test_rpc();
        let ctx = DefiAdapterCtx::new("default", &pin, &rpc);
        let args = deposit_args();

        let result = adapter
            .preview(&args as &(dyn Any + Send + Sync), &ctx)
            .await;
        assert!(result.is_ok(), "preview must succeed: {result:?}");
        let preview = result.unwrap();
        assert_eq!(preview.protocol, "defindex");
        assert_eq!(preview.verb, "vault");
    }

    // ── Preview with valid withdraw args ─────────────────────────────────────

    #[tokio::test]
    async fn preview_withdraw_with_valid_args_succeeds() {
        let adapter = DefindexVaultAdapter::new();
        let pin = test_pin();
        let rpc = test_rpc();
        let ctx = DefiAdapterCtx::new("default", &pin, &rpc);
        let args = withdraw_args();

        let result = adapter
            .preview(&args as &(dyn Any + Send + Sync), &ctx)
            .await;
        assert!(result.is_ok(), "preview must succeed: {result:?}");
    }

    // ── Fail-closed downcast ──────────────────────────────────────────────────

    #[tokio::test]
    async fn preview_wrong_args_type_returns_invalid_arguments() {
        let adapter = DefindexVaultAdapter::new();
        let pin = test_pin();
        let rpc = test_rpc();
        let ctx = DefiAdapterCtx::new("default", &pin, &rpc);

        let wrong_args = String::from("not vault args");
        let result = adapter
            .preview(&wrong_args as &(dyn Any + Send + Sync), &ctx)
            .await;
        assert!(
            matches!(result, Err(DefiAdapterError::InvalidArguments { .. })),
            "wrong type must return InvalidArguments; got {result:?}"
        );
    }

    // ── Submit returns InvalidArguments when signer absent ───────────────────

    #[tokio::test]
    async fn submit_deposit_without_signer_returns_invalid_arguments() {
        use stellar_agent_defi::dispatch::{GateOutcome, dispatch_gate};

        let adapter = DefindexVaultAdapter::new();
        let pin = test_pin();
        let rpc = test_rpc();
        let ctx = DefiAdapterCtx::new("default", &pin, &rpc);
        let args = deposit_args();

        // Use the registered "lend" verb to obtain a valid SubmitWitness.
        // These tests exercise the adapter's submit error-path logic (missing
        // signer / wrong arg type) — the witness verb does not affect that path.
        let gate_result = dispatch_gate("lend", "test-req-1");
        let witness = match gate_result {
            Ok(GateOutcome::Allow(w)) => w,
            other => panic!("expected Allow; got {other:?}"),
        };

        let result = adapter
            .submit(&args as &(dyn Any + Send + Sync), &ctx, witness)
            .await;
        assert!(
            matches!(result, Err(DefiAdapterError::InvalidArguments { .. })),
            "missing signer must return InvalidArguments; got {result:?}"
        );
    }

    // ── Submit wrong type drops witness correctly ─────────────────────────────

    #[tokio::test]
    async fn submit_wrong_args_type_drops_witness_and_returns_error() {
        use stellar_agent_defi::dispatch::{GateOutcome, dispatch_gate};

        let adapter = DefindexVaultAdapter::new();
        let pin = test_pin();
        let rpc = test_rpc();
        let ctx = DefiAdapterCtx::new("default", &pin, &rpc);

        // Use "lend" (registered verb) to get a valid SubmitWitness.
        let gate_result = dispatch_gate("lend", "test-req-2");
        let witness = match gate_result {
            Ok(GateOutcome::Allow(w)) => w,
            other => panic!("expected Allow; got {other:?}"),
        };

        let wrong_args = 42u32;
        let result = adapter
            .submit(&wrong_args as &(dyn Any + Send + Sync), &ctx, witness)
            .await;
        assert!(
            matches!(result, Err(DefiAdapterError::InvalidArguments { .. })),
            "wrong type must return InvalidArguments on submit; got {result:?}"
        );
    }
}
