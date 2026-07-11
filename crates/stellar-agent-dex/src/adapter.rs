//! Soroswap `trade` verb adapter implementing [`DefiAdapter`].
//!
//! # What this module does
//!
//! Implements `stellar_agent_defi::adapter::DefiAdapter` for the Soroswap
//! ROUTER-DIRECT swap path, exposing the `trade` verb through the dispatch seam.
//!
//! The adapter:
//!
//! 1. Validates [`TradeArgs`] (fail-closed percent-string, deadline, path-length,
//!    amount-positive checks).
//! 2. Canonicalises token addresses to SEP-41/SAC C-strkeys (BEFORE all policy
//!    checks).
//! 3. Checks the venue allowlist (Soroswap-only; fail-closed).
//! 4. Pin-verifies the router WASM FIRST, before any on-chain state read
//!    (ordered trust gate).
//! 5. Fetches the on-chain quote via `router_get_amounts_out` and builds a typed
//!    [`SwapPreview`](crate::preview::SwapPreview).
//! 6. On submit, re-verifies the slippage immediately before signing,
//!    then executes the swap via
//!    `submit_signed_invoke` (ROUTER-DIRECT, single-auth-context path).
//! 7. Applies the multi-auth-entry guard: after simulate and before
//!    signing, counts wallet-credentialled root auth entries; refuses unless
//!    count == 1.
//!
//! # ROUTER-DIRECT submit pattern
//!
//! The swap is invoked as `InvokeContract(router,
//! "swap_exact_tokens_for_tokens", [amount_in, amount_out_min, path,
//! to=wallet, deadline])`.  The router calls `to.require_auth()` directly
//! (`soroswap-core contracts/router/src/lib.rs`), producing
//! exactly 1 wallet-credentialled root auth context in simulate.  The SAC
//! `transfer(from=wallet)` is a sub-invocation COVERED by that
//! single root entry.  Because the router creates a
//! `SorobanCredentials::Address` entry for the wallet C-address,
//! `submit_signed_invoke` requires exactly 1 rule ID:
//! `.auth_rule_ids(&[ContextRuleId::new(0)])`, where `0` is the OZ bootstrap
//! rule installed at deploy time.
//!
//! # Ordered trust gate (load-bearing invariant)
//!
//! ```text
//! 1. check_venue_allowed(router, network)?         // venue allowlist
//! 2. verify_soroswap_router_wasm(router, ...)?     // pin-verify FIRST
//! 3. reverify_slippage(...)?                       // on-chain re-fetch
//! 4. submit_signed_invoke(router, fn, args)        // swap execution (ROUTER-DIRECT)
//! ```
//!
//! Enforced by `?`-early-return sequencing.
//!
//! # Behavior summary
//!
//! Slippage is explicit (absolute `amount_out_min`) and re-verified on-chain
//! before signing; token paths are canonicalised; deadlines are bounded; the
//! swap path is explicit; the venue is allowlisted; the router WASM is
//! pin-verified; and the `trade` verb is exposed through the dispatch seam.

use std::any::Any;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use tracing::info;

use stellar_agent_core::ContextRuleId;
use stellar_agent_core::observability::redact_strkey_first5_last5;
use stellar_agent_defi::adapter::{DefiAdapter, DefiAdapterCtx, DefiAdapterError, DefiPreview};

use stellar_agent_defi::dispatch::SubmitWitness;
use stellar_agent_smart_account::submit::{SubmitInvokeArgs, submit_signed_invoke};

use crate::abi::{
    DEFAULT_DEADLINE_OFFSET_SECS, MAX_DEADLINE_OFFSET_SECS, MAX_PATH_LEN, MIN_PATH_LEN, TradeArgs,
};
use crate::auth_guard::count_wallet_auth_entries;
use crate::pins::{passphrase_for_network, pinned_router_for_network, verify_soroswap_router_wasm};
use crate::preview::build_swap_preview;
use crate::quote::{fetch_quote, reverify_slippage};
use crate::sac::canonicalise_path;
use crate::scval::encode_swap_args;
use crate::venue::check_venue_allowed;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Soroswap router function name for `swap_exact_tokens_for_tokens`.
///
/// Cited from `soroswap-core contracts/router/src/lib.rs`.
const SWAP_FN: &str = "swap_exact_tokens_for_tokens";

/// Operation label for `submit_signed_invoke` observability logs.
const DEX_SUBMIT_OP_LABEL: &str = "dex_swap";

/// Default submit timeout when none is provided in the context.
const DEFAULT_SUBMIT_TIMEOUT_SECS: u64 = 60;

// ─────────────────────────────────────────────────────────────────────────────
// DexSwapAdapter
// ─────────────────────────────────────────────────────────────────────────────

/// Soroswap `trade` verb adapter implementing [`DefiAdapter`].
///
/// Exposes the `"trade"` verb through the DeFi dispatch seam.
///
/// # Behavior summary
///
/// Slippage is explicit (absolute `amount_out_min`) and re-verified on-chain
/// before signing; token paths are canonicalised; deadlines are bounded; the
/// swap path is explicit; the venue is allowlisted; the router WASM is
/// pin-verified; and the `trade` verb is exposed through the dispatch seam.
#[derive(Debug)]
pub struct DexSwapAdapter;

impl DexSwapAdapter {
    /// Constructs a new `DexSwapAdapter`.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for DexSwapAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl DefiAdapter for DexSwapAdapter {
    fn verb(&self) -> &'static str {
        "trade"
    }

    /// Returns the criterion `kind` strings this adapter contributes.
    ///
    /// `"dex_slippage_reverify"` is the kind for the pre-sign on-chain quote
    /// re-verify guard.
    ///
    /// # Informational — not a handler registration
    ///
    /// The current dispatch seam (`dispatch_gate`) does NOT resolve criterion
    /// handlers by kind; it only checks verb registration in
    /// `live_verb_registry`.  `criterion_kinds()` is a declaration for external
    /// enumeration and documentation tooling only.  The reverify guard is
    /// enforced imperatively in `submit()` via `reverify_slippage(...)`.
    /// There is no runtime criterion-handler lookup that would leave this
    /// declaration unhandled (the declared-but-unhandled fail-open class
    /// does not apply here).
    fn criterion_kinds(&self) -> &'static [&'static str] {
        &["dex_slippage_reverify"]
    }

    /// Produces a typed [`DefiPreview`] for a Soroswap swap.
    ///
    /// # Preview flow
    ///
    /// 1. Fail-closed downcast to [`TradeArgs`].
    /// 2. Validate `amount_in > 0`, `amount_out_min >= 0`, path length, deadline.
    /// 3. Canonicalise token path to SEP-41/SAC addresses.
    /// 4. Check venue allowlist (Soroswap router for network).
    /// 5. Resolve deadline (default `now + DEFAULT_DEADLINE_OFFSET_SECS`).
    /// 6. Fetch on-chain quote via `router_get_amounts_out` to populate
    ///    `expected_out` in the preview (route + expected-output disclosure).
    /// 7. Build preview with the fetched `expected_out`.
    ///
    /// # Errors
    ///
    /// Returns [`DefiAdapterError`] on validation or canonicalisation failure.
    /// A quote-fetch failure is non-fatal at preview time (the preview is
    /// returned with `expected_out: None`); the pre-sign re-verify gate in
    /// `submit` is the fail-closed enforcement point.
    async fn preview(
        &self,
        args: &(dyn Any + Send + Sync),
        ctx: &DefiAdapterCtx<'_>,
    ) -> Result<DefiPreview, DefiAdapterError> {
        let trade_args = args
            .downcast_ref::<TradeArgs>()
            .ok_or_else(|| DefiAdapterError::InvalidArguments {
                reason: "expected TradeArgs; downcast failed (programmer error)".to_owned(),
            })?
            .clone();

        // ── Validate args ───────────────────────────────────────────────────
        validate_trade_args(&trade_args)?;

        // ── Resolve network + passphrase ─────────────────────────────────────
        // SAC canonicalisation derives contract ids from the network PASSPHRASE
        // (not the CAIP-2 id); prefer the submit-context passphrase and otherwise
        // map the CAIP-2 chain id to its canonical passphrase.  Using the CAIP-2
        // id here would derive a different SAC than submit() does.
        let chain_id = ctx.chain_id.unwrap_or(&ctx.pin.network);
        let network_passphrase = match ctx.network_passphrase {
            Some(p) => p,
            None => passphrase_for_network(chain_id).map_err(|e| {
                DefiAdapterError::InvalidArguments {
                    reason: format!("network not recognised for Soroswap: {e}"),
                }
            })?,
        };

        // ── Canonicalise path (runs BEFORE any policy/allowlist/path-build) ─
        let canonical_path =
            canonicalise_path(&trade_args.path, network_passphrase).map_err(|e| {
                DefiAdapterError::InvalidArguments {
                    reason: format!("token canonicalisation failed: {e}"),
                }
            })?;

        // ── Venue allowlist check ────────────────────────────────────────────
        let (router_address, _) = pinned_router_for_network(chain_id).map_err(|e| {
            DefiAdapterError::InvalidArguments {
                reason: format!("network not recognised for Soroswap: {e}"),
            }
        })?;
        check_venue_allowed(router_address, chain_id).map_err(|e| {
            DefiAdapterError::InvalidArguments {
                reason: format!("venue allowlist check failed: {e}"),
            }
        })?;

        // ── Resolve deadline ─────────────────────────────────────────────────
        let resolved_deadline = resolve_deadline(&trade_args)?;

        // ── Fetch on-chain quote for expected-output disclosure ──────────────
        // Non-fatal at preview time: a quote failure is surfaced as
        // `expected_out: None` so the agent can see the route.  The fail-closed
        // re-verify gate in `submit` is the enforcement point.
        // Pin-verify is intentionally skipped at preview time (submit-only).
        let expected_out = fetch_quote(
            router_address,
            trade_args.amount_in,
            &canonical_path,
            ctx.primary_rpc.url(),
            network_passphrase,
        )
        .await
        .ok()
        .and_then(|q| q.expected_out());

        // ── Build preview ────────────────────────────────────────────────────
        let (_, defi_preview) = build_swap_preview(
            &trade_args,
            router_address,
            &canonical_path,
            resolved_deadline,
            chain_id,
            expected_out,
        );

        Ok(defi_preview)
    }

    /// Executes the Soroswap `swap_exact_tokens_for_tokens` call via
    /// `submit_signed_invoke` (ROUTER-DIRECT), consuming the [`SubmitWitness`].
    ///
    /// # Submit flow
    ///
    /// 1. Fail-closed downcast to [`TradeArgs`].
    /// 2. Validate args + canonicalise path.
    /// 3. Venue-allowlist check.
    /// 4. **Pin-verify router WASM FIRST** (ordered trust gate).
    /// 5. **Slippage re-verify**: re-fetch on-chain quote.
    /// 6. Resolve deadline.
    /// 7. Encode `ScVal` args for `swap_exact_tokens_for_tokens`.
    /// 8. **Multi-auth-entry guard**: simulate and
    ///    count wallet-credentialled root auth entries — must be exactly 1.
    /// 9. Build `HostFunction::InvokeContract(router, fn, args)` (ROUTER-DIRECT).
    /// 10. Call `submit_signed_invoke` with `.target_contract(router)`,
    ///     `.auth_address(wallet)`, and `.auth_rule_ids(&[ContextRuleId::new(0)])`.
    /// 11. Drop witness after submit completes.
    ///
    /// # ROUTER-DIRECT auth model
    ///
    /// The router calls `to.require_auth()` at
    /// `soroswap-core contracts/router/src/lib.rs`.
    /// The SAC `transfer(from=wallet, to=pair, amount_in)` is
    /// a sub-invocation COVERED by that single root auth entry — confirmed
    /// empirically: exactly 1 wallet-credentialled root auth
    /// context is produced in simulate.
    ///
    /// The `submit_signed_invoke` call convention for external contracts:
    /// - `.target_contract(router)` — the contract to invoke; the auth digest
    ///   is computed over `router.swap_exact_tokens_for_tokens(...)`, matching
    ///   what on-chain `__check_auth` expects.
    /// - `.auth_address(wallet)` — the credential address; used by
    ///   `locate_smart_account_auth_entry` to find the wallet's auth entry.
    /// - `.auth_rule_ids(&[ContextRuleId::new(0)])` — the OZ bootstrap rule
    ///   (installed at deploy) that authorises all operations.
    ///
    /// # Errors
    ///
    /// Returns [`DefiAdapterError`] on any failure.
    ///
    /// # Behavior summary
    ///
    /// Encodes an absolute `amount_out_min` (explicit slippage), re-fetches the
    /// on-chain quote before signing, uses a canonicalised path, encodes a
    /// bounded deadline, checks the venue allowlist before pin-verify, and
    /// pin-verifies the router WASM FIRST before any state read.
    ///
    /// # Note — tx `timeBounds.maxTime`
    ///
    /// `submit_signed_invoke` does NOT currently set `timeBounds.maxTime`.
    /// For Soroswap, the on-chain `ensure_deadline` in
    /// `soroswap-core contracts/router/src/lib.rs` enforces the deadline.
    /// The tx-`timeBounds` backstop is deferred until a
    /// no-contract-deadline venue (Aquarius) is wired.
    async fn submit(
        &self,
        args: &(dyn Any + Send + Sync),
        ctx: &DefiAdapterCtx<'_>,
        witness: SubmitWitness,
    ) -> Result<(), DefiAdapterError> {
        // ── Fail-closed downcast ──────────────────────────────────────────
        let trade_args = args
            .downcast_ref::<TradeArgs>()
            .ok_or_else(|| DefiAdapterError::InvalidArguments {
                reason: "expected TradeArgs in submit; downcast failed".to_owned(),
            })?
            .clone();

        // ── Validate args ─────────────────────────────────────────────────
        validate_trade_args(&trade_args)?;

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

        // ── Canonicalise path (BEFORE allowlist / pin / state read) ──────
        let canonical_path =
            canonicalise_path(&trade_args.path, network_passphrase).map_err(|e| {
                DefiAdapterError::InvalidArguments {
                    reason: format!("token canonicalisation failed: {e}"),
                }
            })?;

        // ── Venue allowlist ───────────────────────────────────────────────
        let (router_address, _) = pinned_router_for_network(chain_id).map_err(|e| {
            DefiAdapterError::InvalidArguments {
                reason: format!("network not recognised for Soroswap: {e}"),
            }
        })?;
        check_venue_allowed(router_address, chain_id).map_err(|e| {
            DefiAdapterError::InvalidArguments {
                reason: format!("venue allowlist check failed: {e}"),
            }
        })?;

        // ── Pin-verify router WASM FIRST (ordered trust gate) ───────────
        // `?`-early-return: nothing is read from the router until pin passes.
        verify_soroswap_router_wasm(router_address, chain_id, ctx.primary_rpc, ctx.secondary_rpc)
            .await
            .map_err(|e| DefiAdapterError::PinFailed {
                reason: format!("router WASM pin-verify failed: {e}"),
            })?;

        // ── Slippage re-verify (pre-sign on-chain quote re-fetch) ─────────
        let quote = reverify_slippage(
            router_address,
            trade_args.amount_in,
            trade_args.amount_out_min,
            &canonical_path,
            ctx.primary_rpc.url(),
            network_passphrase,
        )
        .await
        .map_err(|e| DefiAdapterError::InvalidArguments {
            reason: format!("slippage re-verify failed: {e}"),
        })?;

        // ── Resolve deadline ──────────────────────────────────────────────
        let resolved_deadline = resolve_deadline(&trade_args)?;

        // ── Encode ScVal args for swap_exact_tokens_for_tokens ────────────
        // Arg order: [amount_in, amount_out_min, path, to, deadline].
        // Cited: soroswap-core contracts/router/src/lib.rs.
        //
        // NOTE: tx `timeBounds.maxTime` is NOT
        // set by `submit_signed_invoke`.  For Soroswap, the on-chain
        // `ensure_deadline` in `soroswap-core contracts/router/src/lib.rs` is the
        // enforcement point.  The tx-`timeBounds` backstop is deferred until
        // a no-contract-deadline venue (Aquarius) is wired.
        let scval_args = encode_swap_args(
            trade_args.amount_in,
            trade_args.amount_out_min,
            &canonical_path,
            &trade_args.from_address, // to = from_address (wallet smart-account)
            resolved_deadline,
        )
        .map_err(|e| DefiAdapterError::InvalidArguments {
            reason: format!("ScVal encoding failed: {e}"),
        })?;

        // ── Multi-auth-entry guard ───────────────────────────────────────
        // Simulate the ROUTER-DIRECT swap and count wallet-credentialled root
        // auth entries.  The Soroswap router calls `to.require_auth()` in
        // `soroswap-core contracts/router/src/lib.rs`; the SAC
        // `transfer(from=wallet)` is a sub-invocation covered by
        // that single root entry.  Count must be exactly 1.
        count_wallet_auth_entries(
            &trade_args.from_address,
            router_address,
            &scval_args,
            ctx.primary_rpc.url(),
        )
        .await
        .map_err(|e| DefiAdapterError::InvalidArguments {
            reason: format!("multi-auth-entry guard failed: {e}"),
        })?;

        // ── Log intent before submit ──────────────────────────────────────
        info!(
            verb = self.verb(),
            router_redacted = redact_strkey_first5_last5(router_address),
            from_redacted = redact_strkey_first5_last5(&trade_args.from_address),
            amount_in = trade_args.amount_in,
            amount_out_min = trade_args.amount_out_min,
            expected_out = quote.expected_out().unwrap_or(0),
            request_id = witness.request_id(),
            "Soroswap trade: submitting ROUTER-DIRECT via submit_signed_invoke"
        );

        // ── Build HostFunction::InvokeContract(router, fn, args) ──────────
        //
        // ROUTER-DIRECT pattern: call the router contract directly with
        // `to = wallet_c`.  The router calls `to.require_auth()`,
        // producing exactly 1 wallet-credentialled root auth entry.  The SAC
        // `transfer(from=wallet)` is a sub-invocation covered by
        // that single root entry.  This mirrors the Blend adapter
        // pattern exactly.
        //
        // Cited: soroswap-core contracts/router/src/lib.rs.
        use stellar_xdr::{
            ContractId, Hash, HostFunction, InvokeContractArgs, ScAddress, ScSymbol, StringM, VecM,
        };

        let router_sc_addr =
            stellar_strkey::Contract::from_string(router_address).map_err(|e| {
                DefiAdapterError::InvalidArguments {
                    reason: format!("router address invalid: {e}"),
                }
            })?;
        let router_xdr_addr = ScAddress::Contract(ContractId(Hash(router_sc_addr.0)));

        let swap_fn_sym: StringM<32> =
            SWAP_FN
                .try_into()
                .map_err(|_| DefiAdapterError::InvalidArguments {
                    reason: "SWAP_FN symbol too long (should never happen)".to_owned(),
                })?;

        let swap_args_vecm: VecM<stellar_xdr::ScVal> =
            scval_args
                .try_into()
                .map_err(|_| DefiAdapterError::InvalidArguments {
                    reason: "swap args VecM overflow (too many args)".to_owned(),
                })?;

        let host_function = HostFunction::InvokeContract(InvokeContractArgs {
            contract_address: router_xdr_addr,
            function_name: ScSymbol(swap_fn_sym),
            args: swap_args_vecm,
        });

        // ── Determine secondary RPC URL ────────────────────────────────────
        let secondary_rpc_url = ctx
            .secondary_rpc
            .map(stellar_agent_network::StellarRpcClient::url);

        // ── Submit via submit_signed_invoke (ROUTER-DIRECT) ───────────────
        //
        // ROUTER-DIRECT invocation produces exactly 1 wallet-credentialled
        // root auth entry, confirmed by on-chain simulate via
        // count_wallet_auth_entries above.
        //
        // The Soroswap router calls `to.require_auth()` in
        // `soroswap-core contracts/router/src/lib.rs`,
        // creating a SorobanCredentials::Address entry for the wallet.
        // the smart-account submit path locates this entry
        // by scanning for `SorobanCredentials::Address` matching the wallet.
        //
        // CALLER CONVENTION for external-contract calls:
        // - `smart_account = router_address` — the contract being invoked;
        //   used for re-simulate + envelope build (invoke.contract_address).
        // - `auth_address = wallet_address` — the credential address that
        //   needs to sign; used by `locate_smart_account_auth_entry` to find
        //   the auth entry.
        //
        // `submit_signed_invoke` computes the auth digest over
        // `router.swap_exact_tokens_for_tokens(...)`, which matches what the
        // on-chain `__check_auth` expects (the invocation that called
        // `to.require_auth()` is the router, not the wallet).
        //
        // `ContextRuleId::new(0)` is the OZ bootstrap rule installed at
        // smart-account deploy time that authorises all operations.
        let submit_result = submit_signed_invoke(
            SubmitInvokeArgs::builder()
                .target_contract(router_address)
                .auth_address(&trade_args.from_address)
                .auth_rule_ids(&[ContextRuleId::new(0)])
                .host_function(host_function)
                .signer(signer)
                .primary_rpc_url(ctx.primary_rpc.url())
                .maybe_secondary_rpc_url(secondary_rpc_url)
                .network_passphrase(network_passphrase)
                .chain_id(chain_id)
                .timeout(timeout)
                .op_label(DEX_SUBMIT_OP_LABEL)
                .emit_observability_logs(true)
                .maybe_sequence_floor(ctx.sequence_floor)
                .build(),
        )
        .await;

        // ── Consume witness AFTER submit completes ────────────────────────
        let request_id = witness.request_id().to_owned();
        drop(witness); // consumed here — gate ran before this point

        let result = match submit_result {
            Ok(r) => r,
            Err(e) => {
                // Caller-side Err-arm discipline: record the failure as a
                // SaRawInvocation row (non-fatal, no-op unless a writer was
                // threaded in).
                if let Some(writer) = ctx.audit_writer.as_ref() {
                    let smart_account_redacted =
                        stellar_agent_core::observability::redact_strkey_first5_last5(
                            &trade_args.from_address,
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
                return Err(DefiAdapterError::Network {
                    reason: format!("submit_signed_invoke failed: {e}"),
                });
            }
        };

        // Non-fatal allow-path value-audit row (no-op unless the caller threaded
        // a writer + gate-derived legs into the context).
        let tx_hash_redacted = stellar_agent_network::redact_tx_hash(&result.tx_hash);
        ctx.emit_value_action_submitted(&tx_hash_redacted, result.ledger, &request_id);

        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Validation helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Validates [`TradeArgs`] fields.
///
/// Checks:
/// - `from_address` is a valid C-strkey (the wallet smart-account is always a
///   contract address; G-strkeys are rejected early).
/// - `amount_in > 0`
/// - `amount_out_min >= 0` (zero is valid: accept any output)
/// - path length in `[MIN_PATH_LEN, MAX_PATH_LEN]`
/// - deadline not in the past and not excessively far
///
/// Returns `Err(DefiAdapterError::InvalidArguments)` on any violation.
fn validate_trade_args(args: &TradeArgs) -> Result<(), DefiAdapterError> {
    // from_address must be a C-strkey; G-strkeys are not contract addresses.
    stellar_strkey::Contract::from_string(&args.from_address).map_err(|_| {
        DefiAdapterError::InvalidArguments {
            reason:
                "from_address must be a C-strkey (contract address); G-strkeys are not supported"
                    .to_owned(),
        }
    })?;
    if args.amount_in <= 0 {
        return Err(DefiAdapterError::InvalidArguments {
            reason: "amount_in must be positive".to_owned(),
        });
    }
    if args.amount_out_min < 0 {
        return Err(DefiAdapterError::InvalidArguments {
            reason: "amount_out_min must be >= 0".to_owned(),
        });
    }
    if args.path.len() < MIN_PATH_LEN || args.path.len() > MAX_PATH_LEN {
        return Err(DefiAdapterError::InvalidArguments {
            reason: format!(
                "path length {} is out of range [{}, {}]",
                args.path.len(),
                MIN_PATH_LEN,
                MAX_PATH_LEN
            ),
        });
    }
    // Deadline validation (when provided).
    if let Some(deadline) = args.deadline {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if deadline <= now {
            return Err(DefiAdapterError::InvalidArguments {
                reason: "deadline is in the past or at current time".to_owned(),
            });
        }
        if deadline > now + MAX_DEADLINE_OFFSET_SECS {
            return Err(DefiAdapterError::InvalidArguments {
                reason: format!(
                    "deadline is too far in the future (max +{}s)",
                    MAX_DEADLINE_OFFSET_SECS
                ),
            });
        }
    }
    Ok(())
}

/// Resolves the deadline from [`TradeArgs`].
///
/// Returns the caller-supplied deadline if present, or `now + DEFAULT_DEADLINE_OFFSET_SECS`.
fn resolve_deadline(args: &TradeArgs) -> Result<u64, DefiAdapterError> {
    if let Some(deadline) = args.deadline {
        Ok(deadline)
    } else {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Ok(now + DEFAULT_DEADLINE_OFFSET_SECS)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Re-export of `validate_trade_args` for acceptance tests and cross-crate
/// test inspection.
///
/// Gated by the `test-helpers` feature so it is never compiled into production
/// binaries.
///
/// # Errors
///
/// Returns the same [`DefiAdapterError`] as `validate_trade_args` when the trade
/// arguments are invalid.
#[cfg(any(test, feature = "test-helpers"))]
pub fn validate_trade_args_pub(args: &TradeArgs) -> Result<(), DefiAdapterError> {
    validate_trade_args(args)
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

    fn make_valid_trade_args() -> TradeArgs {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        TradeArgs {
            from_address: "CCJUD55AG6W5HAI5LRVNKAE5WDP5XGZBUDS5WNTIVDU7O264UZZE7BRD".to_owned(),
            amount_in: 1_000_000_000,
            amount_out_min: 990_000_000,
            path: vec![
                "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC".to_owned(),
                "CB3TLW74NBIOT3BUWOZ3TUM6RFDF6A4GVIRUQRQZABG5KPOUL4JJOV2F".to_owned(),
            ],
            deadline: Some(now + 300),
        }
    }

    #[test]
    fn validate_trade_args_valid() {
        let args = make_valid_trade_args();
        assert!(validate_trade_args(&args).is_ok());
    }

    #[test]
    fn validate_trade_args_zero_amount_in_refused() {
        let mut args = make_valid_trade_args();
        args.amount_in = 0;
        assert!(
            matches!(
                validate_trade_args(&args),
                Err(DefiAdapterError::InvalidArguments { .. })
            ),
            "zero amount_in must be refused"
        );
    }

    #[test]
    fn validate_trade_args_negative_amount_in_refused() {
        let mut args = make_valid_trade_args();
        args.amount_in = -1;
        assert!(
            matches!(
                validate_trade_args(&args),
                Err(DefiAdapterError::InvalidArguments { .. })
            ),
            "negative amount_in must be refused"
        );
    }

    #[test]
    fn validate_trade_args_negative_amount_out_min_refused() {
        let mut args = make_valid_trade_args();
        args.amount_out_min = -1;
        assert!(
            matches!(
                validate_trade_args(&args),
                Err(DefiAdapterError::InvalidArguments { .. })
            ),
            "negative amount_out_min must be refused"
        );
    }

    #[test]
    fn validate_trade_args_zero_amount_out_min_allowed() {
        let mut args = make_valid_trade_args();
        args.amount_out_min = 0; // zero is allowed (accept any output)
        assert!(validate_trade_args(&args).is_ok());
    }

    #[test]
    fn validate_trade_args_path_too_short_refused() {
        let mut args = make_valid_trade_args();
        args.path = vec!["CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC".to_owned()];
        assert!(
            matches!(
                validate_trade_args(&args),
                Err(DefiAdapterError::InvalidArguments { .. })
            ),
            "path with < 2 elements must be refused"
        );
    }

    #[test]
    fn validate_trade_args_past_deadline_refused() {
        let mut args = make_valid_trade_args();
        args.deadline = Some(1_000_000); // far in the past
        assert!(
            matches!(
                validate_trade_args(&args),
                Err(DefiAdapterError::InvalidArguments { .. })
            ),
            "past deadline must be refused"
        );
    }

    #[test]
    fn validate_trade_args_none_deadline_allowed() {
        let mut args = make_valid_trade_args();
        args.deadline = None;
        assert!(
            validate_trade_args(&args).is_ok(),
            "None deadline must be allowed"
        );
    }

    #[test]
    fn validate_trade_args_deadline_too_far_refused() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut args = make_valid_trade_args();
        args.deadline = Some(now + MAX_DEADLINE_OFFSET_SECS + 1_000);
        assert!(
            matches!(
                validate_trade_args(&args),
                Err(DefiAdapterError::InvalidArguments { .. })
            ),
            "deadline beyond MAX_DEADLINE_OFFSET_SECS must be refused"
        );
    }

    #[test]
    fn validate_trade_args_path_too_long_refused() {
        let mut args = make_valid_trade_args();
        args.path = vec![
            "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC".to_owned();
            MAX_PATH_LEN + 1
        ];
        assert!(
            matches!(
                validate_trade_args(&args),
                Err(DefiAdapterError::InvalidArguments { .. })
            ),
            "path longer than MAX_PATH_LEN must be refused"
        );
    }

    #[test]
    fn resolve_deadline_some_passthrough() {
        let mut args = make_valid_trade_args();
        args.deadline = Some(4_102_444_800); // explicit far-future value, passed through verbatim
        assert_eq!(resolve_deadline(&args).unwrap(), 4_102_444_800);
    }

    #[test]
    fn resolve_deadline_none_defaults_to_now_plus_offset() {
        let before = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut args = make_valid_trade_args();
        args.deadline = None;
        let resolved = resolve_deadline(&args).unwrap();
        let after = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        assert!(
            resolved >= before + DEFAULT_DEADLINE_OFFSET_SECS
                && resolved <= after + DEFAULT_DEADLINE_OFFSET_SECS,
            "None deadline must default to now + DEFAULT_DEADLINE_OFFSET_SECS"
        );
    }

    #[test]
    fn dex_swap_adapter_verb_is_trade() {
        assert_eq!(DexSwapAdapter::new().verb(), "trade");
    }

    #[test]
    fn dex_swap_adapter_criterion_kinds_contains_reverify() {
        let kinds = DexSwapAdapter::new().criterion_kinds();
        assert!(
            kinds.contains(&"dex_slippage_reverify"),
            "criterion_kinds must include dex_slippage_reverify"
        );
        assert!(
            !kinds.contains(&"dex_oracle_sanity"),
            "dex_oracle_sanity must NOT be in criterion_kinds (oracle-sanity criterion deferred)"
        );
    }

    #[test]
    fn from_address_must_be_c_strkey() {
        let mut args = make_valid_trade_args();
        // A G-strkey should fail validation.
        args.from_address = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF".to_owned();
        assert!(
            matches!(
                validate_trade_args(&args),
                Err(DefiAdapterError::InvalidArguments { .. })
            ),
            "G-strkey from_address must be refused"
        );
    }
}
