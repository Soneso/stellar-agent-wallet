//! `stellar_claim` and `stellar_claim_commit` MCP tools.
//!
//! Simulate-then-commit pair for a Stellar `ClaimClaimableBalance` operation.
//! `stellar_claim` fetches the on-chain entry, runs the claim guards, builds an
//! unsigned envelope, and mints a single-use nonce. `stellar_claim_commit`
//! re-derives the authoritative args from the HMAC-bound envelope, re-fetches
//! and re-checks the entry, rebuilds and byte-compares the envelope, verifies
//! the nonce, signs via the keyring, and submits.

use rmcp::{
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Content},
    schemars, serde, tool, tool_router,
};
use serde_json::json;
use stellar_agent_mcp_macros::mcp_tool_router;

use crate::server::WalletServer;
use crate::tools::common::{
    APPROVAL_TTL_MS, CLASSIC_SINGLE_OPERATION_COUNT, DEFAULT_NONCE_TTL_MS, DispatchOutcome,
    commit_envelope_and_verify_nonce, commit_path_error_result, enforce_classic_fee_cap,
    ledger_err_result, nonce_id_prefix, redact_rpc_error_detail, redacted_wallet_error_envelope,
    resolve_classic_fee_per_op_stroops, submit_timeout, total_classic_fee_stroops,
    verify_attestation_gate,
};
use stellar_agent_claimable::entry::{fetch_claimable_balance_entry, fetch_trustline_state};
use stellar_agent_claimable::error::ClaimError;
use stellar_agent_claimable::id::BalanceId;
use stellar_agent_claimable::preview::{
    ClaimPreview, check_trustline, require_claimant, require_predicate_satisfied,
};
use stellar_agent_core::approval::store::PendingApproval;
use stellar_agent_core::approval::user_id::process_uid_for_attestation;
use stellar_agent_core::approval::{
    DEFAULT_RETRY_ATTEMPTS, DEFAULT_RETRY_BACKOFF, open_with_retry,
};
use stellar_agent_core::envelope_decode::decode_authoritative_args;
use stellar_agent_core::timefmt::now_unix_ms;
use stellar_agent_network::{
    BASE_RESERVE_STROOPS, BalanceView, ClassicOpBuilder, StellarRpcClient, fetch_account,
    keyring::signer_from_keyring,
    parse_classic_fee_choice, resolve_classic_fee_selection,
    signing::envelope_signing::attach_signature,
    submit::{SubmissionResult, SubmissionSignerKind, submit_transaction_and_wait},
};

// ─────────────────────────────────────────────────────────────────────────────
// Argument types
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for the `stellar_claim` (simulate) MCP tool.
///
/// Simulate step of the simulate-then-commit pattern for a Stellar
/// `ClaimClaimableBalance` operation. On success the tool returns
/// `{envelope_xdr, nonce, expires_at_unix_ms, preview}` for the agent to pass
/// unmodified to `stellar_claim_commit`.
///
/// # Balance-id grammar
///
/// `balance_id` accepts a `B...` strkey, a canonical 72-hex id, or a bare
/// 64-hex hash.
///
/// # Examples
///
/// ```json
/// {
///   "chain_id": "stellar:testnet",
///   "balance_id": "BAAD...",
///   "source_account": "GABC...SRC"
/// }
/// ```
#[derive(Debug, Clone, serde::Deserialize, schemars::JsonSchema)]
#[serde(crate = "rmcp::serde")]
pub struct StellarClaimArgs {
    /// CAIP-2 chain identifier: `stellar:testnet` or `stellar:mainnet`.
    ///
    /// Must match the loaded profile's `chain_id`.
    pub chain_id: String,

    /// Claimable-balance id: a `B...` strkey, canonical 72-hex id, or bare
    /// 64-hex hash.
    pub balance_id: String,

    /// G-strkey of the claiming (source) account.
    ///
    /// When absent, the profile's default MCP signer account is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_account: Option<String>,
}

/// Arguments for the `stellar_claim_commit` (commit) MCP tool.
///
/// Commit step of the simulate-then-commit pattern. The agent supplies the
/// `(nonce, expires_at_unix_ms, envelope_xdr)` triple returned by
/// `stellar_claim`, plus the original call arguments.
#[derive(Debug, Clone, serde::Deserialize, schemars::JsonSchema)]
#[serde(crate = "rmcp::serde")]
pub struct StellarClaimCommitArgs {
    /// CAIP-2 chain identifier: `stellar:testnet` or `stellar:mainnet`.
    pub chain_id: String,

    /// Claimable-balance id (same as the simulate step).
    pub balance_id: String,

    /// G-strkey of the claiming (source) account (same as the simulate step).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_account: Option<String>,

    /// Base64-url-no-pad nonce returned by the simulate step.
    pub nonce: String,

    /// Unix timestamp (milliseconds) at which the nonce expires.
    pub expires_at_unix_ms: u64,

    /// Base64 XDR envelope returned by the simulate step.
    ///
    /// Compared byte-for-byte to a freshly re-built envelope; mismatch returns
    /// `simulation.divergence`. Passed verbatim to HMAC verification.
    pub envelope_xdr: String,

    /// Wallet-issued approval nonce from the simulate-step `approval` block.
    ///
    /// Required only when the simulate step returned a `policy.approval_required`
    /// outcome.
    #[serde(default)]
    pub approval_nonce: Option<String>,

    /// HMAC-SHA256 attestation blob, URL-safe base64 no-pad encoded (32 bytes).
    ///
    /// Required alongside `approval_nonce` when the policy engine requires
    /// approval.
    #[serde(default)]
    pub approval_attestation: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Free helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Builds an `is_error` [`CallToolResult`] from a [`ClaimError`].
///
/// `ClaimError`'s `Display` carries only public claim data (balance ids,
/// amounts, source accounts) — no secret material — so it is surfaced verbatim
/// alongside its stable wire code. See `stellar-agent-claimable`'s
/// `error::ClaimError` docs for the redaction posture.
fn claim_error_result(err: &ClaimError) -> CallToolResult {
    let envelope =
        stellar_agent_core::envelope::Envelope::<()>::err_raw(err.code(), err.to_string());
    let json = envelope
        .to_json_pretty()
        .unwrap_or_else(|_| String::from("{}"));
    let mut result = CallToolResult::success(vec![Content::text(json)]);
    result.is_error = Some(true);
    result
}

/// Derives the summary asset string (`"XLM"` or `"<code>:<G-strkey>"`) from a
/// [`ClaimPreview`].
fn preview_asset_string(preview: &ClaimPreview) -> String {
    match (&preview.asset_code, &preview.asset_issuer) {
        (Some(code), Some(issuer)) => format!("{code}:{issuer}"),
        _ => "XLM".to_owned(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WalletServer — approval-spine helpers
// ─────────────────────────────────────────────────────────────────────────────

impl WalletServer {
    /// Persists a [`PendingApproval`] entry for a `stellar_claim` simulate call.
    ///
    /// Opens (or creates) the profile-scoped approval store, constructs an
    /// unattested `ClaimSimulated` entry from the claim summary, inserts it, and
    /// returns the entry for nonce / expiry extraction by the caller.
    ///
    /// # Errors
    ///
    /// Returns a string error description on any I/O, store-lock, validation, or
    /// clock failure. The caller maps this to an `internal_error` MCP response.
    ///
    /// # Feature gate
    ///
    /// Exposed as `pub(crate)`; `dead_code`-allowed in non-test builds because
    /// the approval path is exercised only when the policy engine requires
    /// approval.
    #[allow(clippy::too_many_arguments)]
    #[cfg_attr(not(any(test, feature = "test-helpers")), allow(dead_code))]
    pub(crate) fn persist_claim_pending_approval(
        &self,
        envelope_xdr: &str,
        balance_id_hex72: &str,
        balance_id_strkey: &str,
        asset: &str,
        amount_stroops: i64,
        source: &str,
        simulated_fee_stroops: u32,
        simulated_seq_num: i64,
        profile_name: &str,
    ) -> Result<PendingApproval, String> {
        let approvals_dir = self
            .resolve_approval_dir()
            .map_err(|e| format!("approval dir resolution failed: {e}"))?;
        std::fs::create_dir_all(&approvals_dir)
            .map_err(|e| format!("approval dir create_all failed: {e}"))?;
        let store_path = approvals_dir.join(format!("{profile_name}.toml"));
        let mut store = open_with_retry(&store_path, DEFAULT_RETRY_ATTEMPTS, DEFAULT_RETRY_BACKOFF)
            .map_err(|e| format!("approval store open failed: {e}"))?;

        let uid =
            process_uid_for_attestation().map_err(|e| format!("process UID unavailable: {e}"))?;
        let entry = PendingApproval::new_claim_pending(
            envelope_xdr.to_owned(),
            envelope_xdr.as_bytes(),
            balance_id_hex72.to_owned(),
            balance_id_strkey.to_owned(),
            asset.to_owned(),
            amount_stroops,
            source.to_owned(),
            simulated_fee_stroops,
            simulated_seq_num,
            uid,
            APPROVAL_TTL_MS,
        )
        .map_err(|e| format!("PendingApproval::new_claim_pending failed: {e}"))?;

        let now_ms = now_unix_ms()
            .map_err(|e| format!("approval store insert: current time unavailable: {e}"))?;
        store
            .insert(entry.clone(), now_ms)
            .map_err(|e| format!("approval store insert failed: {e}"))?;

        Ok(entry)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool router impl block
// ─────────────────────────────────────────────────────────────────────────────

#[mcp_tool_router]
#[tool_router(router = claim_tool_router, vis = "pub(crate)")]
impl WalletServer {
    /// Builds a `ClaimClaimableBalance` transaction envelope and mints a
    /// single-use nonce.
    ///
    /// This is the **simulate step** of the simulate-then-commit pattern for a
    /// Stellar `ClaimClaimableBalance` operation. It fetches the on-chain
    /// `ClaimableBalanceEntry`, renders a typed preview, and enforces the claim
    /// guards (claimant membership, predicate satisfaction, non-native
    /// trustline state, and native-XLM fee affordability) before minting a
    /// nonce.
    ///
    /// # Tool annotations
    ///
    /// - `readOnlyHint = false` — mints a nonce (wallet state mutation).
    /// - `destructiveHint = false` — does NOT submit a transaction.
    ///
    /// # Nonce binding
    ///
    /// The nonce is bound to `"stellar_claim_commit"`, the envelope XDR bytes,
    /// the expiry, and the chain_id.
    ///
    /// # Errors
    ///
    /// Returns a tool-level error when `source` or `balance_id` are invalid,
    /// the entry does not exist (`claim.balance_not_found`), a claim guard
    /// refuses (`claim.not_claimant` / `claim.predicate_not_satisfied` /
    /// `claim.trustline_*`), the source cannot afford the fee
    /// (`ledger.insufficient_balance`), or the nonce mint fails.
    #[mcp_tool_item(
        name = "stellar_claim",
        destructive_hint = false,
        read_only_hint = false,
        chain_id_required = true,
        value_kind = "moves_value"
    )]
    #[tool(
        name = "stellar_claim",
        description = "Build a ClaimClaimableBalance transaction envelope and mint a single-use \
                       nonce (simulate step). Fetches the on-chain claimable-balance entry, \
                       renders a typed preview, and enforces the claim guards (claimant, \
                       predicate, trustline, fee affordability). Returns \
                       {envelope_xdr, nonce, expires_at_unix_ms, preview}. Pass all three to \
                       stellar_claim_commit to sign and submit. \
                       destructive_hint=false; read_only_hint=false.",
        annotations(read_only_hint = false, destructive_hint = false)
    )]
    async fn stellar_claim(
        &self,
        Parameters(args): Parameters<StellarClaimArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        // ── Resolve source ────────────────────────────────────────────────────
        let source = args
            .source_account
            .clone()
            .unwrap_or_else(|| self.profile.mcp_signer_default.account.clone());

        if let Err(err) = stellar_strkey::ed25519::PublicKey::from_string(&source) {
            return Err(rmcp::ErrorData::invalid_params(
                format!("invalid source (expected G-strkey): {err}"),
                None,
            ));
        }

        // ── Parse balance id ──────────────────────────────────────────────────
        let id = match BalanceId::parse(&args.balance_id) {
            Ok(id) => id,
            Err(err) => {
                return Err(rmcp::ErrorData::invalid_params(
                    format!("invalid balance_id: {}", err.code()),
                    None,
                ));
            }
        };

        // ── RPC client ────────────────────────────────────────────────────────
        let rpc_url = self.profile.rpc_url.as_str();
        let client = match StellarRpcClient::new(rpc_url) {
            Ok(c) => c,
            Err(err) => {
                return Err(rmcp::ErrorData::internal_error(
                    redact_rpc_error_detail("rpc_client_error", &err),
                    None,
                ));
            }
        };

        // ── Fetch the claimable-balance entry ─────────────────────────────────
        let entry = match fetch_claimable_balance_entry(&client, &id).await {
            Ok(e) => e,
            Err(err) => return Ok(claim_error_result(&err)),
        };

        // ── Fetch source account (sequence number + native balance) ───────────
        let account_view = match fetch_account(&client, &source, &[]).await {
            Ok(v) => v,
            Err(err) => {
                let envelope = redacted_wallet_error_envelope(&err);
                let json = envelope
                    .to_json_pretty()
                    .unwrap_or_else(|_| String::from("{}"));
                let mut result = CallToolResult::success(vec![Content::text(json)]);
                result.is_error = Some(true);
                return Ok(result);
            }
        };
        let source_sequence = account_view.sequence_number;

        // ── Dispatch gate (with source reserves view) ─────────────────────────
        let args_value = json!({
            "chain_id": &args.chain_id,
            "balance_id": &args.balance_id,
            "source": &source,
        });
        let source_adapter = crate::policy_adapter::AccountViewAdapter::new(&account_view);
        let dispatch_outcome = match self
            .dispatch_gate_with_views(
                "stellar_claim",
                &args_value,
                &args.chain_id,
                Some(&source_adapter),
                None,
            )
            .await
        {
            Ok(o) => o,
            Err(e) => return e.into_result(),
        };

        // ── Build the preview + run the guards ────────────────────────────────
        let now_ms = now_unix_ms()
            .map_err(|e| rmcp::ErrorData::internal_error(format!("clock_error: {e}"), None))?;
        let now_secs = now_ms / 1000;
        let preview = match ClaimPreview::build(&entry, &source, now_secs) {
            Ok(p) => p,
            Err(err) => return Ok(claim_error_result(&err)),
        };

        if let Err(err) = require_claimant(&preview, &source) {
            return Ok(claim_error_result(&err));
        }
        if let Err(err) = require_predicate_satisfied(&preview) {
            return Ok(claim_error_result(&err));
        }
        if preview.asset_code.is_some() {
            let code = preview.asset_code.as_deref().unwrap_or_default();
            let issuer = preview.asset_issuer.as_deref().unwrap_or_default();
            let state = match fetch_trustline_state(&client, &source, code, issuer).await {
                Ok(s) => s,
                Err(err) => return Ok(claim_error_result(&err)),
            };
            if let Err(err) = check_trustline(
                &state,
                preview.asset_code.as_deref(),
                preview.asset_issuer.as_deref(),
                preview.amount_stroops,
            ) {
                return Ok(claim_error_result(&err));
            }
        }

        // ── Fee resolution + affordability ────────────────────────────────────
        let fee_choice = parse_classic_fee_choice(None).map_err(|err| {
            rmcp::ErrorData::invalid_params(format!("invalid fee: {}", err.code()), None)
        })?;
        let fee_selection = match resolve_classic_fee_selection(
            &client,
            resolve_classic_fee_per_op_stroops(&self.profile),
            fee_choice,
        )
        .await
        {
            Ok(selection) => selection,
            Err(err @ stellar_agent_core::WalletError::Network(_)) => {
                return Ok(ledger_err_result(&err));
            }
            Err(err) => {
                return Err(rmcp::ErrorData::invalid_params(
                    format!("invalid fee: {}", err.code()),
                    None,
                ));
            }
        };
        if let Err(r) = enforce_classic_fee_cap(
            fee_selection.per_op_stroops,
            &fee_selection.selected_fee_percentile,
            &self.profile,
        ) {
            return Ok(r);
        }
        let fee_per_op_stroops = fee_selection.per_op_stroops;
        let total_fee_stroops =
            total_classic_fee_stroops(fee_per_op_stroops, CLASSIC_SINGLE_OPERATION_COUNT)?;
        let fee_stroops = i64::from(total_fee_stroops);

        // Claiming credits the account; only the fee is debited. The
        // affordability check is therefore fee-only.
        let native_balance_stroops = account_view
            .balances
            .first()
            .filter(|b| b.asset.asset_type == "native")
            .map(BalanceView::balance_stroops)
            .transpose()
            .map_err(|e| {
                rmcp::ErrorData::internal_error(format!("balance_parse_error: {e}"), None)
            })?
            .unwrap_or(0_i64);
        let source_reserves = account_view.reserves_stroops(BASE_RESERVE_STROOPS);
        let available_native = native_balance_stroops.saturating_sub(source_reserves);
        if available_native < fee_stroops {
            return Ok(ledger_err_result(&stellar_agent_core::WalletError::Ledger(
                stellar_agent_core::LedgerError::InsufficientBalance {
                    asset: "XLM".to_owned(),
                    have: available_native.to_string(),
                    need: fee_stroops.to_string(),
                },
            )));
        }

        // ── Build the unsigned envelope ───────────────────────────────────────
        let mut builder = ClassicOpBuilder::new(
            &source,
            source_sequence,
            &self.profile.network_passphrase,
            fee_per_op_stroops,
        );
        if let Err(err) = builder.claim_claimable_balance(&id.to_hex64()) {
            return Err(rmcp::ErrorData::internal_error(
                format!("envelope_build_error: {err}"),
                None,
            ));
        }
        let envelope_xdr = match builder.build() {
            Ok(xdr) => xdr,
            Err(err) => {
                return Err(rmcp::ErrorData::internal_error(
                    format!("envelope_build_error: {err}"),
                    None,
                ));
            }
        };

        // ── Mint nonce ────────────────────────────────────────────────────────
        let expiry_unix_ms = now_ms.saturating_add(DEFAULT_NONCE_TTL_MS);
        let nonce = match self.nonce_mint.mint(
            self.tool_catalogue.as_ref(),
            envelope_xdr.as_bytes(),
            now_ms,
            expiry_unix_ms,
            "stellar_claim_commit",
            &args.chain_id,
        ) {
            Ok(n) => n,
            Err(err) => {
                return Ok(crate::tools::common::business_error_result(
                    "nonce.mint_failed",
                    err.to_string(),
                ));
            }
        };
        let nonce_b64 = nonce.to_base64();
        tracing::info!(
            tool = "stellar_claim",
            chain = %args.chain_id,
            nonce_id = %nonce_id_prefix(&nonce),
            decision = "simulated",
            "Claim simulation complete; nonce minted"
        );

        // ── Persist pending approval if policy requires it ────────────────────
        let asset_str = preview_asset_string(&preview);
        let approval_block = if let DispatchOutcome::RequireApproval(ref _req) = dispatch_outcome {
            let profile_name = self.profile_name_for_approval();
            match self.persist_claim_pending_approval(
                &envelope_xdr,
                &preview.balance_id_hex72,
                &preview.balance_id_strkey,
                &asset_str,
                preview.amount_stroops,
                &source,
                total_fee_stroops,
                source_sequence.saturating_add(1),
                &profile_name,
            ) {
                Ok(entry) => Some(json!({
                    "approval_nonce": entry.approval_nonce,
                    "expires_at_unix_ms": entry.expires_at_unix_ms,
                    "summary": {
                        "balance_id_hex72": &preview.balance_id_hex72,
                        "balance_id_strkey": &preview.balance_id_strkey,
                        "asset": &asset_str,
                        "amount_stroops": preview.amount_stroops.to_string(),
                        "source": &source,
                        "simulated_fee_stroops": total_fee_stroops.to_string(),
                        "simulated_seq_num": source_sequence.saturating_add(1),
                    }
                })),
                Err(e) => {
                    return Err(rmcp::ErrorData::internal_error(
                        format!("approval.store_error: {e}"),
                        None,
                    ));
                }
            }
        } else {
            None
        };

        // ── Build response ────────────────────────────────────────────────────
        let preview_json = serde_json::to_value(&preview).unwrap_or(serde_json::Value::Null);
        let mut view = json!({
            "envelope_xdr": &envelope_xdr,
            "nonce": &nonce_b64,
            "expires_at_unix_ms": expiry_unix_ms,
            "preview": preview_json,
        });
        if let Some(approval) = approval_block {
            view["approval"] = approval;
        }
        let envelope = stellar_agent_core::envelope::Envelope::ok(view);
        let json_out = envelope
            .to_json_pretty()
            .unwrap_or_else(|_| String::from("{}"));
        Ok(CallToolResult::success(vec![Content::text(json_out)]))
    }

    /// Signs and submits a `ClaimClaimableBalance` transaction (commit step).
    ///
    /// The agent supplies the `(nonce, expires_at_unix_ms, envelope_xdr)` triple
    /// returned by `stellar_claim`, plus the original call arguments.
    ///
    /// # Security invariants
    ///
    /// 1. Policy re-evaluation on authoritative args re-derived from the
    ///    HMAC-bound `envelope_xdr` (not caller args).
    /// 2. Attestation-verification gate (when policy required approval).
    /// 3. Nonce HMAC + replay-window verification.
    /// 4. Entry re-fetch: existence, claimant, and predicate are re-checked
    ///    against fresh on-chain state.
    /// 5. Envelope divergence check: the rebuilt envelope must byte-equal the
    ///    presented `envelope_xdr`, else `simulation.divergence`.
    ///
    /// # Tool annotations
    ///
    /// - `readOnlyHint = false` — signs and submits.
    /// - `destructiveHint = true` — submits a transaction on-chain.
    ///
    /// # Errors
    ///
    /// Returns a tool-level error on envelope re-derivation failure
    /// (`simulation.divergence`), policy denial, an invalid source, an
    /// expired/replayed nonce, a failed attestation, an entry that no longer
    /// exists or no longer satisfies the claim guards, envelope divergence, or
    /// an RPC submission failure.
    #[mcp_tool_item(
        name = "stellar_claim_commit",
        destructive_hint = true,
        read_only_hint = false,
        chain_id_required = true,
        value_kind = "moves_value"
    )]
    #[tool(
        name = "stellar_claim_commit",
        description = "Sign and submit a ClaimClaimableBalance transaction (commit step). \
                       Requires the nonce, expires_at_unix_ms, and envelope_xdr returned by \
                       stellar_claim. Re-derives authoritative args from the envelope, \
                       re-fetches and re-checks the entry, verifies the nonce, re-builds the \
                       envelope, signs via keyring, and submits. Returns {tx_hash, ledger}. \
                       destructive_hint=true; read_only_hint=false.",
        annotations(read_only_hint = false, destructive_hint = true)
    )]
    async fn stellar_claim_commit(
        &self,
        Parameters(args): Parameters<StellarClaimCommitArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.stellar_claim_commit_impl(args).await
    }

    /// Inner implementation of `stellar_claim_commit`.
    ///
    /// Separated from the public tool handler for testability via the
    /// `call_stellar_claim_commit` test helper. Unlike `stellar_pay_commit`,
    /// there is no `forced_dispatch_outcome` override: `stellar_claim_commit`
    /// has no toolset-gated tier (it is denylist-only), so the policy-engine
    /// outcome drives the attestation gate directly.
    #[allow(clippy::too_many_lines)]
    pub(crate) async fn stellar_claim_commit_impl(
        &self,
        args: StellarClaimCommitArgs,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        // ── Re-derive authoritative args from the HMAC-bound envelope_xdr ─────
        let mut authoritative_args =
            match decode_authoritative_args(&args.envelope_xdr, "stellar_claim_commit") {
                Ok(a) => a,
                Err(e) => {
                    tracing::debug!(
                        error = %e,
                        tool = "stellar_claim_commit",
                        "envelope_xdr re-derivation failed; returning simulation.divergence"
                    );
                    return Ok(crate::tools::common::business_error_result(
                        "simulation.divergence",
                        format!("envelope_xdr re-derivation failed: {e}"),
                    ));
                }
            };
        authoritative_args["chain_id"] = serde_json::Value::String(args.chain_id.clone());

        // ── Dispatch gate (uses authoritative args) ──────────────────────────
        let dispatch_outcome = match self
            .dispatch_gate("stellar_claim_commit", &authoritative_args, &args.chain_id)
            .await
        {
            Ok(o) => o,
            Err(e) => return e.into_result(),
        };

        // ── Resolve the authoritative source (from the signed envelope) ──────
        // The source used for RPC fetch, signing, and submission MUST come from
        // the HMAC-bound envelope decode, never from caller-supplied args.
        let source = match authoritative_args
            .get("source")
            .and_then(serde_json::Value::as_str)
        {
            Some(s) => s.to_owned(),
            None => {
                return Ok(crate::tools::common::business_error_result(
                    "simulation.divergence",
                    "envelope_xdr did not decode a source account",
                ));
            }
        };
        if let Err(err) = stellar_strkey::ed25519::PublicKey::from_string(&source) {
            return Err(rmcp::ErrorData::invalid_params(
                format!("invalid source (expected G-strkey): {err}"),
                None,
            ));
        }

        // ── Attestation verification gate ────────────────────────────────────
        if let Err(result) = verify_attestation_gate(
            self,
            &dispatch_outcome,
            &args.envelope_xdr,
            args.approval_nonce.as_deref(),
            args.approval_attestation.as_deref(),
            "stellar_claim_commit",
        )
        .await
        {
            return Ok(result);
        }

        // ── Decode nonce ─────────────────────────────────────────────────────
        let nonce = match stellar_agent_nonce::Nonce::from_base64(&args.nonce) {
            Ok(n) => n,
            Err(_) => return Ok(commit_path_error_result("nonce parse failed")),
        };

        // ── Parse the authoritative balance id ───────────────────────────────
        let balance_id_hex72 = match authoritative_args
            .get("balance_id_hex72")
            .and_then(serde_json::Value::as_str)
        {
            Some(s) => s,
            None => {
                return Ok(crate::tools::common::business_error_result(
                    "simulation.divergence",
                    "envelope_xdr did not decode a balance id",
                ));
            }
        };
        let id = match BalanceId::parse(balance_id_hex72) {
            Ok(id) => id,
            Err(err) => return Ok(claim_error_result(&err)),
        };

        // ── RPC client ───────────────────────────────────────────────────────
        let rpc_url = self.profile.rpc_url.as_str();
        let client = match StellarRpcClient::new(rpc_url) {
            Ok(c) => c,
            Err(err) => {
                return Err(rmcp::ErrorData::internal_error(
                    redact_rpc_error_detail("rpc_client_error", &err),
                    None,
                ));
            }
        };

        // ── Re-fetch the entry and re-check the claim guards ─────────────────
        // Per commit-phase parity with pay: the ENTRY (existence, claimant,
        // predicate) is re-fetched, but the account/trustline are not — a
        // between-phase trustline change fails cleanly on-chain.
        let entry = match fetch_claimable_balance_entry(&client, &id).await {
            Ok(e) => e,
            Err(err) => return Ok(claim_error_result(&err)),
        };
        let now_ms = now_unix_ms()
            .map_err(|e| rmcp::ErrorData::internal_error(format!("clock_error: {e}"), None))?;
        let now_secs = now_ms / 1000;
        let preview = match ClaimPreview::build(&entry, &source, now_secs) {
            Ok(p) => p,
            Err(err) => return Ok(claim_error_result(&err)),
        };
        if let Err(err) = require_claimant(&preview, &source) {
            return Ok(claim_error_result(&err));
        }
        if let Err(err) = require_predicate_satisfied(&preview) {
            return Ok(claim_error_result(&err));
        }

        // ── Re-fetch source account and re-build the envelope ────────────────
        let account_view = match fetch_account(&client, &source, &[]).await {
            Ok(v) => v,
            Err(err) => {
                let envelope = redacted_wallet_error_envelope(&err);
                let json = envelope
                    .to_json_pretty()
                    .unwrap_or_else(|_| String::from("{}"));
                let mut result = CallToolResult::success(vec![Content::text(json)]);
                result.is_error = Some(true);
                return Ok(result);
            }
        };
        let source_sequence = account_view.sequence_number;

        let total_fee_from_envelope = match authoritative_args
            .get("total_fee_stroops")
            .and_then(serde_json::Value::as_u64)
            .and_then(|fee| u32::try_from(fee).ok())
        {
            Some(f) => f,
            None => {
                return Ok(crate::tools::common::business_error_result(
                    "simulation.divergence",
                    "envelope_xdr did not contain a valid fee",
                ));
            }
        };
        let fee_per_op_stroops = total_fee_from_envelope
            .checked_div(CLASSIC_SINGLE_OPERATION_COUNT)
            .ok_or_else(|| {
                rmcp::ErrorData::internal_error("internal_error: operation count is zero", None)
            })?;

        let mut builder = ClassicOpBuilder::new(
            &source,
            source_sequence,
            &self.profile.network_passphrase,
            fee_per_op_stroops,
        );
        if let Err(err) = builder.claim_claimable_balance(&id.to_hex64()) {
            return Err(rmcp::ErrorData::internal_error(
                format!("envelope_build_error: {err}"),
                None,
            ));
        }
        let rebuilt_envelope_xdr = match builder.build() {
            Ok(xdr) => xdr,
            Err(err) => {
                return Err(rmcp::ErrorData::internal_error(
                    format!("envelope_build_error: {err}"),
                    None,
                ));
            }
        };

        // ── Envelope divergence check ────────────────────────────────────────
        if rebuilt_envelope_xdr != args.envelope_xdr {
            return Ok(crate::tools::common::business_error_result(
                "simulation.divergence",
                "re-built envelope does not match presented envelope_xdr; \
                 re-simulate to obtain a fresh envelope",
            ));
        }

        // ── Fee cap ──────────────────────────────────────────────────────────
        if let Err(r) = enforce_classic_fee_cap(fee_per_op_stroops, "envelope", &self.profile) {
            return Ok(r);
        }

        // ── Nonce verification + replay window ───────────────────────────────
        if let Err(e) = commit_envelope_and_verify_nonce(
            &self.nonce_mint,
            &self.replay_window,
            &nonce,
            &args.envelope_xdr,
            args.expires_at_unix_ms,
            &args.chain_id,
            "stellar_claim_commit",
            now_ms,
        )
        .await
        {
            return e.into_result();
        }

        // ── Load signer handle from keyring ──────────────────────────────────
        let handle = match signer_from_keyring(&self.profile.mcp_signer_default, &source).await {
            Ok(h) => h,
            Err(err) => {
                let envelope = stellar_agent_core::envelope::Envelope::<()>::err(&err);
                let json = envelope
                    .to_json_pretty()
                    .unwrap_or_else(|_| String::from("{}"));
                let mut result = CallToolResult::success(vec![Content::text(json)]);
                result.is_error = Some(true);
                return Ok(result);
            }
        };

        // ── Sign envelope ────────────────────────────────────────────────────
        let signed_xdr = match attach_signature(
            &args.envelope_xdr,
            &handle,
            &self.profile.network_passphrase,
        )
        .await
        {
            Ok(s) => s,
            Err(err) => {
                let envelope = stellar_agent_core::envelope::Envelope::<()>::err(&err);
                let json = envelope
                    .to_json_pretty()
                    .unwrap_or_else(|_| String::from("{}"));
                let mut result = CallToolResult::success(vec![Content::text(json)]);
                result.is_error = Some(true);
                return Ok(result);
            }
        };

        let nonce_id_prefix = nonce_id_prefix(&nonce);

        // ── Submit ───────────────────────────────────────────────────────────
        match submit_transaction_and_wait(
            &client,
            &signed_xdr,
            submit_timeout(&self.profile),
            &self.profile.network_passphrase,
            Some(SubmissionSignerKind::Keyring),
        )
        .await
        {
            Ok(SubmissionResult {
                tx_hash, ledger, ..
            }) => {
                tracing::info!(
                    tool = "stellar_claim_commit",
                    chain = %args.chain_id,
                    nonce_id = %nonce_id_prefix,
                    decision = "committed",
                    "stellar_claim_commit: tx submitted"
                );

                // Best-effort removal of the consumed approval entry so it
                // cannot be replayed. Failure does not abort the response —
                // the transaction is already on-chain.
                if let Some(ref approval_nonce_str) = args.approval_nonce
                    && let Ok(approvals_dir) = self.resolve_approval_dir()
                {
                    let profile_name = self.profile_name_for_approval();
                    let store_path = approvals_dir.join(format!("{profile_name}.toml"));
                    match open_with_retry(
                        &store_path,
                        DEFAULT_RETRY_ATTEMPTS,
                        DEFAULT_RETRY_BACKOFF,
                    ) {
                        Ok(mut store) => {
                            if let Err(e) = store.remove(approval_nonce_str) {
                                tracing::warn!(
                                    nonce = %approval_nonce_str,
                                    error = %e,
                                    "stellar_claim_commit: approval entry remove failed after \
                                     successful submit; entry will expire via gc"
                                );
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                "stellar_claim_commit: approval store open failed during \
                                 post-commit cleanup; entry will expire via gc"
                            );
                        }
                    }
                }

                let view = json!({
                    "tx_hash": tx_hash,
                    "ledger": ledger,
                });
                let envelope = stellar_agent_core::envelope::Envelope::ok(view);
                let json_out = envelope
                    .to_json_pretty()
                    .unwrap_or_else(|_| String::from("{}"));
                Ok(CallToolResult::success(vec![Content::text(json_out)]))
            }
            Err(err) => {
                let envelope = stellar_agent_core::envelope::Envelope::<()>::err(&err);
                let json = envelope
                    .to_json_pretty()
                    .unwrap_or_else(|_| String::from("{}"));
                let mut result = CallToolResult::success(vec![Content::text(json)]);
                result.is_error = Some(true);
                Ok(result)
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Toolset-dispatch helper
// ─────────────────────────────────────────────────────────────────────────────

impl WalletServer {
    /// Invoke `stellar_claim` (simulate step) by value, bypassing the rmcp
    /// transport layer.
    ///
    /// Used by the toolset-invocation routing path (`tools/toolsets.rs`).
    ///
    /// # Errors
    ///
    /// Same as [`WalletServer::stellar_claim`].
    pub(crate) async fn invoke_stellar_claim(
        &self,
        args: StellarClaimArgs,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.stellar_claim(Parameters(args)).await
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test helpers
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(any(test, feature = "test-helpers"))]
impl WalletServer {
    /// Calls `stellar_claim` (simulate step) with the given args, bypassing the
    /// rmcp transport.
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Feature gate
    ///
    /// Gated on the `test-helpers` feature or `#[cfg(test)]`.
    #[doc(hidden)]
    pub async fn call_stellar_claim(
        &self,
        args: StellarClaimArgs,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.stellar_claim(Parameters(args)).await
    }

    /// Calls `stellar_claim_commit` (commit step) with the given args,
    /// bypassing the rmcp transport.
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Feature gate
    ///
    /// Gated on the `test-helpers` feature or `#[cfg(test)]`.
    #[doc(hidden)]
    pub async fn call_stellar_claim_commit(
        &self,
        args: StellarClaimCommitArgs,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.stellar_claim_commit(Parameters(args)).await
    }
}
