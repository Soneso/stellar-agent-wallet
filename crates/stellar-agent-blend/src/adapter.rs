//! Blend `DefiAdapter` implementation — the `lend` verb.
//!
//! # What this module does
//!
//! Implements `stellar_agent_defi::adapter::DefiAdapter` for the Blend
//! lending protocol, exposing the `lend` verb through the dispatch seam.
//!
//! The adapter:
//! 1. Validates all [`LendArgs`] requests via
//!    [`BlendRequest::validate`](crate::abi::BlendRequest::validate) (refuses
//!    liquidation discriminants 6-9 and invalid fields, fail-closed).
//! 2. Produces a typed [`BlendLendPreview`](crate::preview::BlendLendPreview) via [`build_blend_lend_preview`].
//! 3. On submit, builds the `HostFunction::InvokeContract` for the Blend
//!    `submit(from, spender, to, requests)` call and routes through
//!    `submit_signed_invoke` (the shared submit path is called, never
//!    modified).
//!
//! The **ordered trust gate** (pin-verify → oracle-allowlist → oracle-read)
//! is enforced by `?`-early-return SEQUENCING at the dispatch site
//! (`stellar-agent-mcp` or `stellar-agent-cli`), NOT inside this adapter.
//! The adapter receives an already-verified context and a [`SubmitWitness`]
//! that structurally proves the gate ran.
//!
//! # Witness consumption
//!
//! [`BlendLendAdapter::submit`] consumes the [`SubmitWitness`] by passing it
//! to a logging call, then drops it.  Because `SubmitWitness` is only
//! constructible by `dispatch_gate` (the `pub(crate)` invariant), consuming
//! it here — AFTER the actual `submit_signed_invoke` completes — is the
//! structural guarantee that no submit path bypasses the gate.
//!
//! The witness is held until after `submit_signed_invoke` returns; a submit
//! that returns an error still consumed a witness (i.e. the gate ran), which
//! is the correct semantic.
//!
//! # Single home for the submit build
//!
//! The `HostFunction` build and `submit_signed_invoke` call live exclusively
//! here rather than being duplicated in the MCP tool and CLI.  The MCP tool
//! and CLI each call `adapter.submit(args, ctx, witness)` after passing the
//! gate.
//!
//! # Fail-closed `Any` downcast
//!
//! The `args: &dyn Any` downcast is fail-closed: a cast miss returns
//! `DefiAdapterError::InvalidArguments`, never `.unwrap()` or panic.
//!
//! # Behavior
//!
//! Exposes the typed preview with fail-closed downcast, a
//! simulate-authoritative health guard, and the declared oracle-staleness
//! criteria.

use std::any::Any;

use async_trait::async_trait;

use stellar_agent_core::ContextRuleId;
use stellar_agent_defi::adapter::{DefiAdapter, DefiAdapterCtx, DefiAdapterError, DefiPreview};
use stellar_agent_defi::dispatch::SubmitWitness;
use stellar_agent_smart_account::submit::{SubmitInvokeArgs, submit_signed_invoke};

use crate::abi::LendArgs;
use crate::preview::{HfStatus, build_blend_lend_preview, preview_summary};
use crate::scval::{c_strkey_to_sc_address, encode_blend_requests};

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Blend `submit` function name on the pool contract.
///
/// Cited from `blend-contracts-v2 pool/src/contract.rs`.
const BLEND_SUBMIT_FN: &str = "submit";

/// Operation label for `submit_signed_invoke` observability logs.
const BLEND_SUBMIT_OP_LABEL: &str = "blend_submit";

/// Default submit timeout when none is provided in the context.
const DEFAULT_SUBMIT_TIMEOUT_SECS: u64 = 60;

// ─────────────────────────────────────────────────────────────────────────────
// BlendLendAdapter
// ─────────────────────────────────────────────────────────────────────────────

/// Blend `lend` verb adapter implementing [`DefiAdapter`].
///
/// Exposes the `"lend"` verb through the DeFi dispatch seam.  The first live
/// verb in the stellar-agent-wallet.
///
/// # Behavior
///
/// Provides a typed `Vec<Request>` preview, a simulate-authoritative health
/// guard, and the declared oracle-staleness criteria.
#[derive(Debug)]
pub struct BlendLendAdapter;

impl BlendLendAdapter {
    /// Constructs a new `BlendLendAdapter`.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for BlendLendAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl DefiAdapter for BlendLendAdapter {
    fn verb(&self) -> &'static str {
        "lend"
    }

    fn criterion_kinds(&self) -> &'static [&'static str] {
        &["blend_oracle_staleness"]
    }

    async fn preview(
        &self,
        args: &(dyn Any + Send + Sync),
        ctx: &DefiAdapterCtx<'_>,
    ) -> Result<DefiPreview, DefiAdapterError> {
        // ── Fail-closed downcast ─────────────────────────────────────────
        // Clone immediately to avoid holding &dyn Any across the async boundary.
        let lend_args = args
            .downcast_ref::<LendArgs>()
            .ok_or_else(|| DefiAdapterError::InvalidArguments {
                reason: "expected LendArgs; downcast failed (programmer error)".to_owned(),
            })?
            .clone();

        // ── Fail-closed request validation (lend verb + field checks) ─────
        // Refuses liquidation discriminants 6-9 (they require the `liquidate`
        // verb) and rejects empty addresses / non-positive amounts BEFORE any
        // preview is built.
        for req in &lend_args.requests {
            req.validate()
                .map_err(|e| DefiAdapterError::InvalidArguments {
                    reason: format!("invalid Blend request: {e}"),
                })?;
        }

        // ── Build typed preview ───────────────────────────────────────────
        // HF is Unavailable at preview time: the preview never runs simulate.
        // The fail-closed health gate is the on-chain simulate inside
        // submit_signed_invoke; the adapter never populates ArmedAndPassed.
        let blend_preview = build_blend_lend_preview(
            &lend_args.pool_address,
            &lend_args.from_address,
            &lend_args.requests,
            HfStatus::Unavailable, // preview is display-only; no simulate here
            None,                  // oracle staleness filled by criteria
        );

        let summary = preview_summary(&blend_preview);
        let contract_address_redacted = ctx.pin.redacted_address();
        let network = ctx.pin.network.clone();

        // ── Wrap in DefiPreview (the typed no-escape-hatch surface) ───────
        Ok(DefiPreview::new(
            "blend",
            self.verb(),
            network.as_str(),
            contract_address_redacted,
            summary,
        ))
    }

    /// Executes the Blend `submit(from, spender, to, requests)` call via
    /// `submit_signed_invoke`, consuming the [`SubmitWitness`].
    ///
    /// # Submit flow
    ///
    /// 1. Downcast `args` to [`LendArgs`] (fail-closed).
    /// 2. Encode `Vec<BlendRequest>` as `ScVal::Vec<Map>` per `blend-contracts-v2`
    ///    ABI (`blend-contracts-v2 pool/src/pool/actions.rs`).
    /// 3. Build `HostFunction::InvokeContract` for `submit(from, spender, to, requests)`.
    ///    Cited: `blend-contracts-v2 pool/src/contract.rs`.
    ///    For supply/borrow/repay: `from == spender == to == wallet smart-account`.
    /// 4. Call `submit_signed_invoke` (calls, does NOT modify it).
    /// 5. Drop the witness after submit completes — structural proof that the
    ///    gate ran before this submit occurred.
    ///
    /// # Context requirements
    ///
    /// The [`DefiAdapterCtx`] MUST be constructed via
    /// [`DefiAdapterCtx::new_with_submit_ctx`] with `signer`, `network_passphrase`,
    /// and `chain_id` set to `Some`.  Returns `InvalidArguments` otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`DefiAdapterError`] when:
    /// - Downcast to `LendArgs` fails.
    /// - Required submit context fields (`signer`, `network_passphrase`,
    ///   `chain_id`) are absent from `ctx`.
    /// - `ScVal` encoding fails.
    /// - `submit_signed_invoke` returns an error.
    ///
    /// # Behavior
    ///
    /// Provides the typed submit surface and a simulate-authoritative health
    /// guard.
    async fn submit(
        &self,
        args: &(dyn Any + Send + Sync),
        ctx: &DefiAdapterCtx<'_>,
        witness: SubmitWitness,
    ) -> Result<(), DefiAdapterError> {
        // ── Fail-closed downcast ──────────────────────────────────────────
        let lend_args = args
            .downcast_ref::<LendArgs>()
            .ok_or_else(|| DefiAdapterError::InvalidArguments {
                reason: "expected LendArgs in submit; downcast failed".to_owned(),
            })?
            .clone();

        // ── Fail-closed request validation (lend verb + field checks) ─────
        // MUST run before any encoding or signing: refuses liquidation
        // discriminants 6-9 and rejects empty addresses / non-positive amounts.
        for req in &lend_args.requests {
            req.validate()
                .map_err(|e| DefiAdapterError::InvalidArguments {
                    reason: format!("invalid Blend request: {e}"),
                })?;
        }

        // ── Extract required submit-context fields ────────────────────────
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

        // ── Encode from address as ScVal ──────────────────────────────────
        let from_sc_addr = c_strkey_to_sc_address(&lend_args.from_address).map_err(|e| {
            DefiAdapterError::InvalidArguments {
                reason: format!("invalid from_address: {e}"),
            }
        })?;
        let from_sc_val = stellar_xdr::ScVal::Address(from_sc_addr);

        // ── Encode pool address as ScAddress ─────────────────────────────
        let pool_sc_addr = c_strkey_to_sc_address(&lend_args.pool_address).map_err(|e| {
            DefiAdapterError::InvalidArguments {
                reason: format!("invalid pool_address: {e}"),
            }
        })?;

        // ── Encode Vec<BlendRequest> as ScVal ─────────────────────────────
        let requests_scval = encode_blend_requests(&lend_args.requests).map_err(|e| {
            DefiAdapterError::InvalidArguments {
                reason: format!("ScVal encoding failed: {e}"),
            }
        })?;

        // ── Build InvokeContractArgs for `submit(from, spender, to, requests)` ──
        // Cited from `blend-contracts-v2 pool/src/contract.rs`.
        // For supply/borrow/repay: from == spender == to == wallet smart-account.
        let fn_sym: stellar_xdr::StringM<32> =
            BLEND_SUBMIT_FN
                .try_into()
                .map_err(|_| DefiAdapterError::InvalidArguments {
                    reason: "BLEND_SUBMIT_FN symbol too long (should never happen)".to_owned(),
                })?;
        let submit_args: stellar_xdr::VecM<stellar_xdr::ScVal> = vec![
            from_sc_val.clone(), // from
            from_sc_val.clone(), // spender (same as from for normal ops)
            from_sc_val,         // to (same as from for normal ops)
            requests_scval,
        ]
        .try_into()
        .map_err(|_| DefiAdapterError::InvalidArguments {
            reason: "submit args VecM overflow (too many args)".to_owned(),
        })?;

        let invoke_args = stellar_xdr::InvokeContractArgs {
            contract_address: pool_sc_addr,
            function_name: stellar_xdr::ScSymbol(fn_sym),
            args: submit_args,
        };
        let host_function = stellar_xdr::HostFunction::InvokeContract(invoke_args);

        // ── Determine secondary RPC URL ───────────────────────────────────
        let secondary_rpc_url = ctx
            .secondary_rpc
            .map(stellar_agent_network::StellarRpcClient::url);

        // ── Log intent before submit ──────────────────────────────────────
        tracing::info!(
            verb = self.verb(),
            pool_redacted = ctx.pin.redacted_address(),
            from_redacted = stellar_agent_core::observability::redact_strkey_first5_last5(
                &lend_args.from_address
            ),
            request_id = witness.request_id(),
            "Blend lend: submitting via smart-account submit path"
        );

        // ── Submit via smart-account submit_signed_invoke ─────────────────
        // CALL submit_signed_invoke, do NOT modify it.
        let submit_result = submit_signed_invoke(
            SubmitInvokeArgs::builder()
                .target_contract(&lend_args.pool_address)
                .auth_address(&lend_args.from_address)
                .auth_rule_ids(&[ContextRuleId::new(0)])
                .host_function(host_function)
                .signer(signer)
                .primary_rpc_url(ctx.primary_rpc.url())
                .maybe_secondary_rpc_url(secondary_rpc_url)
                .network_passphrase(network_passphrase)
                .chain_id(chain_id)
                .timeout(timeout)
                .op_label(BLEND_SUBMIT_OP_LABEL)
                .emit_observability_logs(true)
                .maybe_sequence_floor(ctx.sequence_floor)
                .build(),
        )
        .await;

        // ── Consume the witness after submit completes ────────────────────
        // The witness is consumed here — AFTER submit_signed_invoke — to prove
        // that the gate ran before this submit path was entered.  A submit that
        // errors also consumed a witness (gate ran; tx failed on chain), which
        // is the correct semantic.
        let request_id = witness.request_id().to_owned();
        drop(witness);

        match submit_result {
            Ok(result) => {
                let tx_hash_redacted = stellar_agent_network::redact_tx_hash(&result.tx_hash);
                tracing::info!(
                    verb = self.verb(),
                    request_id = %request_id,
                    tx_hash_redacted = %tx_hash_redacted,
                    "Blend lend: submit succeeded"
                );
                // Non-fatal allow-path value-audit row (no-op unless the caller
                // threaded a writer + gate-derived legs into the context).
                ctx.emit_value_action_submitted(&tx_hash_redacted, result.ledger, &request_id);
                Ok(())
            }
            Err(e) => {
                // Caller-side Err-arm discipline: record the failure as a
                // SaRawInvocation row (non-fatal, no-op unless a writer was
                // threaded in) so failed value operations are not audit-silent.
                if let Some(writer) = ctx.audit_writer.as_ref() {
                    let smart_account_redacted =
                        stellar_agent_core::observability::redact_strkey_first5_last5(
                            &lend_args.from_address,
                        );
                    stellar_agent_smart_account::submit::emit_sa_raw_invocation_failure(
                        writer,
                        &smart_account_redacted,
                        &e,
                        ctx.auth_rule_ids.map_or(1, |ids| ids.len() as u32),
                        ctx.chain_id,
                        &request_id,
                    );
                }
                Err(DefiAdapterError::Network {
                    reason: format!("submit_signed_invoke failed: {e}"),
                })
            }
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

    use super::*;
    use crate::abi::{BlendRequest, RequestType};
    use stellar_agent_defi::pins::DefiContractPin;
    use stellar_agent_network::StellarRpcClient;

    fn test_pin() -> DefiContractPin {
        DefiContractPin::new(
            "blend",
            "v2",
            "default",
            "stellar:testnet",
            "CCEBVDYM32YNYCVNRXQKDFFPISJJCV557CDZEIRBEE4NCV4KHPQ44HGF",
            [0u8; 32],
            "blend-contracts-v2",
        )
    }

    fn test_rpc() -> StellarRpcClient {
        StellarRpcClient::new("https://soroban-testnet.stellar.org").expect("valid URL")
    }

    fn make_lend_args() -> LendArgs {
        LendArgs {
            pool_address: "CCEBVDYM32YNYCVNRXQKDFFPISJJCV557CDZEIRBEE4NCV4KHPQ44HGF".to_owned(),
            from_address: "CAJJZSGMMM3PD7N33TAPHGBUGTB43OC73HVIK2L2G6BNGGGYOSSYBXBD".to_owned(),
            requests: vec![BlendRequest::new(
                RequestType::Supply,
                "CAQCFVLOBK5GIULPNZRGATJJMIZL5BSP7X5YJVMGCPTUEPFM4AVSRCJU",
                5_000_000_000,
            )],
            override_oracle_staleness: false,
        }
    }

    // ── Verb identity ────────────────────────────────────────────────────────

    #[test]
    fn verb_is_lend() {
        let adapter = BlendLendAdapter::new();
        assert_eq!(adapter.verb(), "lend");
    }

    // ── Criterion kinds ──────────────────────────────────────────────────────

    #[test]
    fn criterion_kinds_includes_oracle_staleness() {
        let adapter = BlendLendAdapter::new();
        assert!(
            adapter
                .criterion_kinds()
                .contains(&"blend_oracle_staleness")
        );
    }

    // ── Preview with valid args ───────────────────────────────────────────────

    #[tokio::test]
    async fn preview_with_valid_lend_args_succeeds() {
        let adapter = BlendLendAdapter::new();
        let pin = test_pin();
        let rpc = test_rpc();
        let ctx = DefiAdapterCtx::new("default", &pin, &rpc);
        let lend_args = make_lend_args();

        let result = adapter
            .preview(&lend_args as &(dyn Any + Send + Sync), &ctx)
            .await;
        assert!(
            result.is_ok(),
            "preview must succeed for valid lend args: {result:?}"
        );
        let preview = result.unwrap();
        assert_eq!(preview.protocol, "blend");
        assert_eq!(preview.verb, "lend");
    }

    // ── Preview refuses a liquidation request on the lend verb ────────────────

    #[tokio::test]
    async fn preview_refuses_liquidation_request() {
        let adapter = BlendLendAdapter::new();
        let pin = test_pin();
        let rpc = test_rpc();
        let ctx = DefiAdapterCtx::new("default", &pin, &rpc);
        let lend_args = LendArgs {
            pool_address: "CCEBVDYM32YNYCVNRXQKDFFPISJJCV557CDZEIRBEE4NCV4KHPQ44HGF".to_owned(),
            from_address: "CAJJZSGMMM3PD7N33TAPHGBUGTB43OC73HVIK2L2G6BNGGGYOSSYBXBD".to_owned(),
            // Discriminant 6 (liquidation) must be refused on `lend`.
            requests: vec![BlendRequest::new(
                RequestType::FillUserLiquidationAuction,
                "CAQCFVLOBK5GIULPNZRGATJJMIZL5BSP7X5YJVMGCPTUEPFM4AVSRCJU",
                5_000_000_000,
            )],
            override_oracle_staleness: false,
        };

        let result = adapter
            .preview(&lend_args as &(dyn Any + Send + Sync), &ctx)
            .await;
        assert!(
            matches!(result, Err(DefiAdapterError::InvalidArguments { .. })),
            "preview must refuse a liquidation discriminant on the lend verb; got {result:?}"
        );
    }

    // ── Fail-closed downcast ─────────────────────────────────────────────────

    #[tokio::test]
    async fn preview_wrong_args_type_returns_error() {
        let adapter = BlendLendAdapter::new();
        let pin = test_pin();
        let rpc = test_rpc();
        let ctx = DefiAdapterCtx::new("default", &pin, &rpc);

        // Pass a String where LendArgs is expected — downcast must fail cleanly.
        let wrong_args = String::from("not lend args");
        let result = adapter
            .preview(&wrong_args as &(dyn Any + Send + Sync), &ctx)
            .await;
        assert!(
            matches!(result, Err(DefiAdapterError::InvalidArguments { .. })),
            "wrong type must return InvalidArguments; got {result:?}"
        );
    }

    // ── Submit returns InvalidArguments when signer absent ───────────────────

    /// Verifies that `submit` returns `InvalidArguments` when the context
    /// was constructed without submit fields (preview-only context).
    ///
    /// The full submit path (gate → witness → submit) is tested via the
    /// testnet acceptance tests in `blend_lend_testnet_acceptance.rs`.
    #[tokio::test]
    async fn submit_without_signer_returns_invalid_arguments() {
        use stellar_agent_defi::dispatch::{GateOutcome, dispatch_gate};

        let adapter = BlendLendAdapter::new();
        let pin = test_pin();
        let rpc = test_rpc();
        // Preview-only context — no signer.
        let ctx = DefiAdapterCtx::new("default", &pin, &rpc);
        let lend_args = make_lend_args();

        let gate_result = dispatch_gate("lend", "test-req-1");
        let witness = match gate_result {
            Ok(GateOutcome::Allow(w)) => w,
            other => panic!("expected Allow; got {other:?}"),
        };

        let result = adapter
            .submit(&lend_args as &(dyn Any + Send + Sync), &ctx, witness)
            .await;
        assert!(
            matches!(result, Err(DefiAdapterError::InvalidArguments { .. })),
            "missing signer must return InvalidArguments; got {result:?}"
        );
    }

    // ── Submit downcast fail-closed ──────────────────────────────────────────

    #[tokio::test]
    async fn submit_wrong_args_type_returns_invalid_arguments() {
        use stellar_agent_defi::dispatch::{GateOutcome, dispatch_gate};

        let adapter = BlendLendAdapter::new();
        let pin = test_pin();
        let rpc = test_rpc();
        let ctx = DefiAdapterCtx::new("default", &pin, &rpc);

        let gate_result = dispatch_gate("lend", "test-req-2");
        let witness = match gate_result {
            Ok(GateOutcome::Allow(w)) => w,
            other => panic!("expected Allow; got {other:?}"),
        };

        // Pass wrong type — downcast must fail cleanly.
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
