//! `stellar_trustline` and `stellar_trustline_commit` MCP tools.
//!
//! Implements the two-phase simulate-then-commit pattern for the Stellar
//! `ChangeTrust` classic operation.  The two phases mirror the `stellar_pay` /
//! `stellar_pay_commit` split:
//!
//! - `stellar_trustline` (simulate) — resolves the denomination, fetches live
//!   issuer flags, runs the clawback gate, builds the unsigned
//!   `ChangeTrust` envelope, mints a nonce, and returns the preview.
//! - `stellar_trustline_commit` (commit) — re-derives authoritative args from
//!   the nonce-bound XDR, verifies the nonce + attestation, signs, and submits.
//!
//! # Gate order on the live path (fail-closed at every step)
//!
//! 1. `resolve_denomination` — USDT hard-refusal + lookalike denylist +
//!    pinned-issuer-mismatch + unpinned-bare-code.
//! 2. Live issuer account fetch via `fetch_account` → `AccountFlagsView`
//!    (for the clawback gate).
//! 3. Source account fetch via `fetch_account` (for the policy gate's
//!    `account_view`; sequence number consumed at envelope-build time).
//! 4. `dispatch_gate_with_views` — policy engine evaluation (chain_id, rate
//!    limits, and `minimum_reserve` against the step-3 `account_view`;
//!    `identity_view` stays `None`, so identity-class criteria fail closed).
//! 5. `clawback_gate(flags, opt_in_present)` where `opt_in_present` is
//!    derived from the wallet-controlled approval store ONLY — NOT an
//!    agent-suppliable bool.
//! 6. `TrustlinePreview::build` — typed JSON preview for the operator.
//! 7. `RefuseWithWarning` / `Refuse` gate decisions return early.
//! 8. Fee resolution.
//! 9. Build `ChangeTrust` envelope via `ClassicOpBuilder::change_trust`.
//! 10. Mint nonce bound to `"stellar_trustline_commit"`.
//!
//! # Behavior
//!
//! - Denomination resolver + USDT refusal: bare codes resolve via the pin table;
//!   USDT is refused unconditionally.
//! - Live issuer-flag fetch + named clawback gate disclosure.
//! - `identity_view` is `None` on both phases: `ChangeTrust`'s only
//!   counterparty account is the asset issuer, whose on-chain `home_domain`
//!   is self-asserted — feeding it to `counterparty_allowlist` HOME_DOMAIN
//!   matching would let an issuer alias an allowlisted domain. Identity-class
//!   criteria configured on this verb fail closed. See the Step 2 comment in
//!   `stellar_trustline`.
//! - Nonce binding: simulate mints a nonce; commit verifies and consumes it.

use rmcp::{
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Content},
    schemars, serde, tool, tool_router,
};
use serde_json::json;
use stellar_agent_mcp_macros::mcp_tool_router;

use stellar_agent_core::approval::retry::{
    DEFAULT_RETRY_ATTEMPTS, DEFAULT_RETRY_BACKOFF, open_with_retry,
};
use stellar_agent_core::approval::store::PendingApproval;
use stellar_agent_core::approval::user_id::process_uid_for_attestation;
use stellar_agent_core::envelope_decode::decode_authoritative_args;
use stellar_agent_core::observability::redact_strkey_first5_last5;
use stellar_agent_core::profile::schema::default_approval_dir;
use stellar_agent_core::timefmt::now_unix_ms;
use stellar_agent_network::{
    AccountView, Asset, ClassicOpBuilder, StellarRpcClient,
    account::AccountFlagsView,
    fetch_account,
    keyring::signer_from_keyring,
    parse_classic_fee_choice, resolve_classic_fee_selection,
    signing::envelope_signing::attach_signature,
    submit::{SubmissionResult, SubmissionSignerKind, submit_transaction_and_wait},
};

use crate::policy_adapter::AccountViewAdapter;
use stellar_agent_stablecoin::{
    preview::{GateDecisionView, TrustlinePreview},
    resolve::{DenominationInput, ResolvedAsset, resolve_denomination},
};
use zeroize::Zeroizing;

use crate::server::WalletServer;
use crate::tools::common::{
    APPROVAL_TTL_MS, CLASSIC_SINGLE_OPERATION_COUNT, DEFAULT_NONCE_TTL_MS, DispatchOutcome,
    commit_path_error_result, enforce_classic_fee_cap, ledger_err_result, nonce_id_prefix,
    redact_rpc_error_detail, redacted_wallet_error_envelope, resolve_classic_fee_per_op_stroops,
    submit_timeout, total_classic_fee_stroops, verify_attestation_gate,
};

/// Redacts an asset input string (`CODE:ISSUER`, or `native`/`XLM`) for logging:
/// the asset code is public; the issuer G-strkey is reduced to first-5-last-5.
fn redact_asset_for_log(asset: &str) -> String {
    match asset.split_once(':') {
        Some((code, issuer)) => format!("{code}:{}", redact_strkey_first5_last5(issuer)),
        None => asset.to_owned(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Argument types
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for the `stellar_trustline` (simulate) MCP tool.
///
/// Simulate step of the simulate-then-commit pattern for a Stellar
/// `ChangeTrust` operation.  On success the tool returns
/// `{envelope_xdr, nonce, expires_at_unix_ms, preview}` for the agent to
/// pass unmodified to `stellar_trustline_commit`.
///
/// # Asset grammar
///
/// - Bare code `"USDC"` — resolved via the issuer pin table (testnet/mainnet).
/// - `"CODE:G…ISSUER"` — explicit code+issuer pair.
/// - `"C…"` (56-char C-strkey) — SAC address; deferred (returns a typed error).
///
/// # Security invariants
///
/// - USDT (any case) is refused unconditionally.
/// - Known lookalike `(code, issuer)` pairs are refused.
/// - Pinned codes with a non-canonical issuer are refused.
/// - Bare codes with no pin row are refused.
/// - Issuer flag fetch failure **fail-closes** the gate;
///   the tool never assumes "safe" when the RPC is unreachable.
/// - `opt_in_present` is NOT a caller-supplied argument; it is derived from
///   the wallet-controlled `PendingApprovalStore`.
///
/// # Examples
///
/// ```json
/// {
///   "chain_id": "stellar:testnet",
///   "from": "GABC...SRC",
///   "asset": "USDC",
///   "limit_stroops": null
/// }
/// ```
#[derive(Debug, Clone, serde::Deserialize, schemars::JsonSchema)]
#[serde(crate = "rmcp::serde")]
pub struct StellarTrustlineArgs {
    /// CAIP-2 chain identifier: `stellar:testnet` or `stellar:mainnet`.
    ///
    /// Must match the loaded profile's `chain_id`.
    pub chain_id: String,

    /// G-strkey of the account that will hold the trustline.
    ///
    /// Must exist on-chain and hold sufficient XLM for the transaction fee.
    pub from: String,

    /// Asset descriptor (denomination input).
    ///
    /// Grammar:
    /// - `"USDC"` — bare code, resolved via pin table.
    /// - `"USDC:G…ISSUER"` — explicit code+issuer.
    /// - `"C…"` (56-char) — SAC address (deferred; returns a typed error).
    pub asset: String,

    /// Optional explicit trustline limit in stroops, decimal-string encoded.
    ///
    /// `null` or absent → the Stellar protocol default (`i64::MAX`, unlimited).
    /// `"0"` removes the trustline. Accepted range is `0..=i64::MAX`
    /// (a client-side tightening over the raw `ChangeTrustOp.limit` field,
    /// which is a signed `i64`: a negative limit is always refused
    /// server-side, so this rejects it earlier, at the wallet boundary,
    /// with a clearer error). A raw JSON number is rejected by the schema.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit_stroops: Option<String>,

    /// Classic fee per operation: `<stroops>`, `auto`, or `auto:pNN`.
    #[serde(default, rename = "fee", skip_serializing_if = "Option::is_none")]
    pub classic_base: Option<String>,
}

/// Arguments for the `stellar_trustline_commit` (commit) MCP tool.
///
/// The agent supplies the `(nonce, expires_at_unix_ms, envelope_xdr)` triple
/// returned by `stellar_trustline`, plus the original call arguments, to sign
/// and submit the `ChangeTrust` transaction.
///
/// # Security invariants (policy-evaluation order)
///
/// 1. **Re-derive authoritative args:** the commit handler calls
///    `decode_authoritative_args("stellar_trustline_commit")` on the HMAC-bound
///    `envelope_xdr` and presents those values to the policy engine — NOT the
///    caller-supplied args.
/// 2. **Nonce verification:** HMAC-verified against `envelope_xdr` before signing.
/// 3. **Replay prevention:** the nonce salt is recorded in the in-memory
///    `ReplayWindow` after verification.
/// 4. **Mainnet refusal:** `destructive_hint = true`.
///
/// # Examples
///
/// ```json
/// {
///   "chain_id": "stellar:testnet",
///   "from": "GABC...SRC",
///   "asset": "USDC",
///   "nonce": "<base64 from simulate>",
///   "expires_at_unix_ms": 1234567890000,
///   "envelope_xdr": "<base64 from simulate>"
/// }
/// ```
#[derive(Debug, Clone, serde::Deserialize, schemars::JsonSchema)]
#[serde(crate = "rmcp::serde")]
pub struct StellarTrustlineCommitArgs {
    /// CAIP-2 chain identifier (same as simulate step).
    pub chain_id: String,

    /// G-strkey of the account that will hold the trustline (same as simulate).
    pub from: String,

    /// Base64-url-no-pad nonce returned by the simulate step.
    ///
    /// HMAC-verified against `envelope_xdr`, `expires_at_unix_ms`, and the
    /// registered commit tool name before signing.
    pub nonce: String,

    /// Unix timestamp (milliseconds) at which the nonce expires.
    pub expires_at_unix_ms: u64,

    /// Base64 XDR envelope returned by the simulate step.
    ///
    /// HMAC-bound to the nonce.  The authoritative `(asset, issuer, limit)` are
    /// re-derived from this envelope at commit time via `decode_authoritative_args`
    /// (the caller-supplied values are not trusted); a decode failure returns
    /// `simulation.divergence`.
    pub envelope_xdr: String,

    /// Wallet-issued approval nonce from the simulate-step `approval` block.
    ///
    /// Required only when the simulate step returned a `policy.approval_required`
    /// outcome.
    #[serde(default)]
    pub approval_nonce: Option<String>,

    /// HMAC-SHA256 attestation blob (URL-safe base64 no-pad, 32 bytes).
    ///
    /// Written by `stellar-agent approve --id <approval_nonce>` after the
    /// operator confirms.  Required alongside `approval_nonce` when policy
    /// requires approval.
    #[serde(default)]
    pub approval_attestation: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Denomination-input parser
// ─────────────────────────────────────────────────────────────────────────────

/// Parses the `asset` string field from tool args into a `DenominationInput`.
///
/// Grammar:
/// - Starts with `C` and is 56 chars → `SacAddress`
/// - Contains `:` → `CodeAndIssuer { code, issuer }` (split on first `:`)
/// - Otherwise → `BareCode`
fn parse_denomination_input(asset: &str) -> DenominationInput {
    // C-strkey SAC address (56 chars starting with 'C')
    if asset.len() == 56 && asset.starts_with('C') {
        return DenominationInput::SacAddress(asset.to_owned());
    }
    // CODE:ISSUER
    if let Some(colon) = asset.find(':') {
        let (code, issuer) = asset.split_at(colon);
        return DenominationInput::CodeAndIssuer {
            code: code.to_owned(),
            issuer: issuer[1..].to_owned(), // skip the ':'
        };
    }
    // Bare code
    DenominationInput::BareCode(asset.to_owned())
}

// ─────────────────────────────────────────────────────────────────────────────
// Approval-spine helper
// ─────────────────────────────────────────────────────────────────────────────

impl WalletServer {
    /// Persists a [`PendingApproval`] entry for a `stellar_trustline` simulate call.
    ///
    /// Reuses `PendingApproval::new_payment_pending` with trustline-adapted field
    /// values:
    ///
    /// - `summary_to` — the trustline holder (same as `from`).
    /// - `summary_amount_stroops` — the `limit_stroops` (or `0` for unlimited).
    /// - `summary_asset` — `"CODE:ISSUER"` string.
    ///
    /// Opens (or creates) the profile-scoped approval store, constructs an
    /// unattested entry, inserts it, and returns the entry for nonce/expiry
    /// extraction by the caller.
    ///
    /// # Errors
    ///
    /// Returns a string error on any I/O, store-lock, or clock failure.
    ///
    /// The simulate path persists a wallet-owned `PendingApproval` entry.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn persist_trustline_pending_approval(
        &self,
        envelope_xdr: &str,
        from_account: &str,
        summary_asset_code: &str,
        summary_asset_issuer: &str,
        summary_limit_stroops: Option<i64>,
        summary_simulated_total_stroops: u32,
        summary_simulated_seq_num: i64,
        profile_name: &str,
    ) -> Result<PendingApproval, String> {
        let approvals_dir =
            default_approval_dir().map_err(|e| format!("approval dir resolution failed: {e}"))?;
        std::fs::create_dir_all(&approvals_dir)
            .map_err(|e| format!("approval dir create_all failed: {e}"))?;
        let store_path = approvals_dir.join(format!("{profile_name}.toml"));
        let mut store = open_with_retry(&store_path, DEFAULT_RETRY_ATTEMPTS, DEFAULT_RETRY_BACKOFF)
            .map_err(|e| format!("approval store open failed: {e}"))?;

        let uid =
            process_uid_for_attestation().map_err(|e| format!("process UID unavailable: {e}"))?;

        // Reuse PaymentSimulated with adapted fields:
        //   summary_to       = trustline holder (from_account)
        //   summary_amount_stroops = limit_stroops or 0 for unlimited
        //   summary_asset    = "CODE:ISSUER"
        let asset_str = format!("{summary_asset_code}:{summary_asset_issuer}");
        let limit_stroops = summary_limit_stroops.unwrap_or(0_i64);

        let entry = PendingApproval::new_payment_pending(
            envelope_xdr.to_owned(),
            envelope_xdr.as_bytes(),
            from_account.to_owned(),
            limit_stroops,
            asset_str,
            None, // no memo for trustline
            summary_simulated_total_stroops,
            summary_simulated_seq_num,
            uid,
            APPROVAL_TTL_MS,
        )
        .map_err(|e| format!("PendingApproval::new_payment_pending (trustline) failed: {e}"))?;

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
#[tool_router(router = trustline_tool_router, vis = "pub(crate)")]
impl WalletServer {
    /// Builds a `ChangeTrust` transaction envelope and mints a single-use nonce.
    ///
    /// This is the **simulate step** of the simulate-then-commit pattern for
    /// a Stellar `ChangeTrust` operation.
    ///
    /// # Gate order (fail-closed at every step)
    ///
    /// 1. `dispatch_gate` — policy engine.
    /// 2. `resolve_denomination` — USDT refusal + lookalike denylist +
    ///    pinned-issuer-mismatch + unpinned-bare-code.
    /// 3. Live issuer-flag fetch → `IssuerFlagsView`.  Fetch failure = `Refuse`.
    /// 4. `clawback_gate` — wallet-controlled opt-in check (NOT agent-suppliable).
    /// 5. `TrustlinePreview::build` — typed JSON preview.
    /// 6. `RefuseWithWarning` / `Refuse` gate → early return.
    /// 7. Build `ChangeTrust` envelope via `ClassicOpBuilder::change_trust`.
    /// 8. Mint nonce bound to `"stellar_trustline_commit"`.
    ///
    /// # Tool annotations
    ///
    /// - `readOnlyHint = false` — mints a nonce (wallet state mutation).
    /// - `destructiveHint = false` — does NOT submit a transaction.
    #[mcp_tool_item(
        name = "stellar_trustline",
        destructive_hint = false,
        read_only_hint = false,
        chain_id_required = true,
        value_kind = "moves_value"
    )]
    #[tool(
        name = "stellar_trustline",
        description = "Build a ChangeTrust transaction envelope and mint a single-use nonce \
                       (simulate step). Resolves the denomination, fetches live issuer flags, \
                       runs the clawback gate, and returns \
                       {envelope_xdr, nonce, expires_at_unix_ms, preview}. \
                       Pass all three to stellar_trustline_commit to sign and submit. \
                       USDT is refused unconditionally. \
                       destructive_hint=false; read_only_hint=false.",
        annotations(read_only_hint = false, destructive_hint = false)
    )]
    async fn stellar_trustline(
        &self,
        Parameters(args): Parameters<StellarTrustlineArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let args_value = json!({
            "chain_id": &args.chain_id,
            "from": &args.from,
            "asset": &args.asset,
        });

        // ── Parse limit_stroops (0..=i64::MAX; see the field rustdoc for the
        // client-side lower-bound tightening) ─────────────────────────────
        let limit_stroops = crate::tools::amount_wire::parse_stroops_i64_opt_field(
            "limit_stroops",
            args.limit_stroops.as_deref(),
        )?;
        if let Some(v) = limit_stroops
            && v < 0
        {
            return Err(rmcp::ErrorData::invalid_params(
                "limit_stroops must be >= 0 (0 removes the trustline; omit or pass null for \
                 the default unlimited i64::MAX)",
                None,
            ));
        }

        // ── Validate G-strkey (from account) ─────────────────────────────────
        if let Err(err) = stellar_strkey::ed25519::PublicKey::from_string(&args.from) {
            return Err(rmcp::ErrorData::invalid_params(
                format!("invalid from (expected G-strkey): {err}"),
                None,
            ));
        }

        // ── Step 1: Resolve denomination (USDT deny + lookalike + pinned) ────
        let input = parse_denomination_input(&args.asset);
        let resolved: ResolvedAsset =
            match resolve_denomination(input, &self.profile.network_passphrase) {
                Ok(r) => r,
                Err(e) => {
                    tracing::info!(
                        tool = "stellar_trustline",
                        chain = %args.chain_id,
                        asset = %redact_asset_for_log(&args.asset),
                        error = %e,
                        "denomination resolver refused trustline"
                    );
                    let envelope = stellar_agent_core::envelope::Envelope::<()>::err_raw(
                        "trustline.denomination_refused",
                        e.to_string(),
                    );
                    let json = envelope
                        .to_json_pretty()
                        .unwrap_or_else(|_| String::from("{}"));
                    let mut result = CallToolResult::success(vec![Content::text(json)]);
                    result.is_error = Some(true);
                    return Ok(result);
                }
            };

        // ── Step 2: Live issuer account fetch ─────────────────────────────────
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

        // Fetch the ISSUER account (not the wallet account) for
        // `issuer_flags` (the clawback gate, below). The issuer account is
        // deliberately NOT supplied as the policy gate's `identity_view`:
        // `AccountEntry.home_domain` is self-asserted (any issuer can set an
        // arbitrary domain via SetOptions), so feeding it to
        // `counterparty_allowlist` HOME_DOMAIN matching would let an issuer
        // alias an allowlisted domain and convert that criterion's
        // fail-closed deny into an attacker-influenceable allow. Issuer
        // flags are third-party public facts; safe to log.
        let issuer_account_view: Option<AccountView> = match fetch_account(
            &client,
            &resolved.issuer,
            &[],
        )
        .await
        {
            Ok(account_view) => {
                let flags_opt = &account_view.account_flags;
                tracing::info!(
                    tool = "stellar_trustline",
                    issuer = %redact_strkey_first5_last5(&resolved.issuer),
                    auth_required = ?flags_opt.as_ref().map(|f| f.auth_required),
                    auth_revocable = ?flags_opt.as_ref().map(|f| f.auth_revocable),
                    auth_clawback_enabled = ?flags_opt.as_ref().map(|f| f.auth_clawback_enabled),
                    "issuer flags fetched"
                );
                Some(account_view)
            }
            Err(err) => {
                // Fetch failure fail-closes the gate.  Log at INFO so the
                // operator can diagnose; do NOT log issuer strkey beyond
                // first-5-last-5.
                tracing::info!(
                    tool = "stellar_trustline",
                    issuer = %redact_strkey_first5_last5(&resolved.issuer),
                    error = %err,
                    "issuer flag fetch failed — fail-closing gate"
                );
                None
            }
        };
        let issuer_flags: Option<AccountFlagsView> = issuer_account_view
            .as_ref()
            .and_then(|v| v.account_flags.clone());

        // ── Step 3: Fetch source account (feeds the policy gate's
        // account_view; sequence number consumed by the envelope build at
        // Step 8) ──────────────────────────────────────────────────────────
        let source_account_view = match fetch_account(&client, &args.from, &[]).await {
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
        let source_sequence = source_account_view.sequence_number;

        // ── Step 4: Dispatch gate (with policy views) ─────────────────────────
        // `account_view` is the fetched source account, feeding
        // `minimum_reserve`. `identity_view` stays `None`: the only
        // counterparty account a `ChangeTrust` has is the asset issuer, and
        // its self-asserted `home_domain` must not feed allowlist matching
        // (see the Step 2 comment), so identity-class criteria configured on
        // this verb fail closed.
        let source_adapter = AccountViewAdapter::new(&source_account_view);
        let dispatch_outcome = match self
            .dispatch_gate_with_views(
                "stellar_trustline",
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

        // ── Step 5: Wallet-controlled clawback opt-in lookup (HMAC-verified) ────
        //
        // `opt_in_present` is NOT an agent-suppliable bool; it is derived from
        // the wallet-controlled approval store.
        //
        // The lookup MUST be HMAC-verified against the attestation key.  A mere
        // presence check (`has_attested_trustline_clawback_opt_in`) allows any
        // writer of the profile store file to set a forged blob and bypass the
        // gate.  The `verify_attested_trustline_clawback_opt_in` method recomputes
        // `compute_trustline_clawback_opt_in_digest` and calls
        // `verify_attestation(key, nonce, &digest, process_uid, &blob)`
        // (constant-time HMAC-SHA256) — matching the `ToolsetGrant::verify_attestation`
        // sibling pattern and the `verify_attestation_gate` keyring-load pattern.
        //
        // If the key cannot be loaded (keyring unavailable) → fail-closed: opt-in
        // treated as absent (cannot confirm → refuse).
        //
        // Network key: `chain_id.caip2_str()` (e.g. `"stellar:testnet"`).
        // This single canonical form is used at mint, digest, record, and lookup
        // so they always agree.
        let now_ms = now_unix_ms()
            .map_err(|e| rmcp::ErrorData::internal_error(format!("clock_error: {e}"), None))?;
        let network_key = self.profile.chain_id.caip2_str();
        let opt_in_present = {
            // Load the attestation key for HMAC verification.  Fail-closed on
            // any keyring error — the gate then fires RefuseWithWarning for
            // clawback-enabled issuers, and the operator runs `approve --id`.
            let key_result = crate::tools::common::load_attestation_key(&self.profile);
            match key_result {
                Ok(key_bytes) => {
                    let attestation_key = Zeroizing::new(key_bytes);
                    let approvals_dir = default_approval_dir().ok();
                    let profile_name = self.profile_name_for_approval();
                    approvals_dir
                        .map(|dir| {
                            let store_path = dir.join(format!("{profile_name}.toml"));
                            open_with_retry(
                                &store_path,
                                DEFAULT_RETRY_ATTEMPTS,
                                DEFAULT_RETRY_BACKOFF,
                            )
                            .map(|store| {
                                store.verify_attested_trustline_clawback_opt_in(
                                    &attestation_key,
                                    network_key,
                                    &resolved.code,
                                    &resolved.issuer,
                                    now_ms,
                                )
                            })
                            .unwrap_or(false)
                        })
                        .unwrap_or(false)
                }
                Err(_) => {
                    // Keyring unavailable — fail-closed: treat opt-in as absent.
                    tracing::debug!(
                        tool = "stellar_trustline",
                        "attestation key load failed; treating clawback opt-in as absent (fail-closed)"
                    );
                    false
                }
            }
        };

        // ── Step 6: Build trustline preview (includes clawback gate decision) ─
        let preview = TrustlinePreview::build(
            resolved.clone(),
            limit_stroops,
            issuer_flags.as_ref(),
            opt_in_present,
        );

        // ── Step 7: Gate decision check — fail-closed ─────────────────────────
        //
        // RefuseWithWarning means `auth_clawback_enabled = true` and no VERIFIED
        // opt-in exists.  This is NOT a terminal refusal —
        // the operator MUST be able to provide the opt-in via `approve --id`.
        // Mint a `TrustlineClawbackOptIn` pending entry and return a
        // RequireApproval response so the operator can run:
        //
        //   stellar-agent approve --id <opt_in_nonce>
        //
        // On the NEXT simulate call the HMAC-verified opt-in clears the gate.
        // Two approvals are needed: first the opt-in, then the per-action commit.
        //
        // Refuse (fail-closed / hard-refusal) is still terminal.
        match &preview.gate_decision {
            GateDecisionView::Proceed => {
                // Gate passed — continue to envelope build.
            }
            GateDecisionView::RefuseWithWarning { warning } => {
                // Clawback gate: mint a TrustlineClawbackOptIn pending entry.
                // The operator must `approve --id <opt_in_nonce>` to record the
                // HMAC-attested opt-in, then re-invoke stellar_trustline.
                tracing::info!(
                    tool = "stellar_trustline",
                    chain = %args.chain_id,
                    code = %resolved.code,
                    issuer = %redact_strkey_first5_last5(&resolved.issuer),
                    warning = %warning,
                    "clawback gate RefuseWithWarning — minting opt-in pending entry"
                );

                let uid = match process_uid_for_attestation() {
                    Ok(u) => u,
                    Err(e) => {
                        return Err(rmcp::ErrorData::internal_error(
                            format!("approval.uid_unavailable: {e}"),
                            None,
                        ));
                    }
                };

                // Open the approval store and insert the TrustlineClawbackOptIn entry.
                let approvals_dir = default_approval_dir().map_err(|e| {
                    rmcp::ErrorData::internal_error(
                        format!("approval.store_error: dir resolution failed: {e}"),
                        None,
                    )
                })?;
                std::fs::create_dir_all(&approvals_dir).map_err(|e| {
                    rmcp::ErrorData::internal_error(
                        format!("approval.store_error: create_dir_all failed: {e}"),
                        None,
                    )
                })?;
                let profile_name = self.profile_name_for_approval();
                let store_path = approvals_dir.join(format!("{profile_name}.toml"));
                let mut store =
                    open_with_retry(&store_path, DEFAULT_RETRY_ATTEMPTS, DEFAULT_RETRY_BACKOFF)
                        .map_err(|e| {
                            rmcp::ErrorData::internal_error(
                                format!("approval.store_error: open failed: {e}"),
                                None,
                            )
                        })?;

                let opt_in_entry = PendingApproval::new_trustline_clawback_opt_in_pending(
                    network_key.to_owned(),
                    resolved.code.clone(),
                    resolved.issuer.clone(),
                    uid,
                    APPROVAL_TTL_MS,
                )
                .map_err(|e| {
                    rmcp::ErrorData::internal_error(
                        format!("approval.store_error: new_trustline_clawback_opt_in_pending failed: {e}"),
                        None,
                    )
                })?;

                let opt_in_expires = opt_in_entry.expires_at_unix_ms;
                let opt_in_nonce = opt_in_entry.approval_nonce.clone();

                let now_ms = now_unix_ms().map_err(|e| {
                    rmcp::ErrorData::internal_error(
                        format!("approval.store_error: current time unavailable: {e}"),
                        None,
                    )
                })?;
                store.insert(opt_in_entry, now_ms).map_err(|e| {
                    rmcp::ErrorData::internal_error(
                        format!("approval.store_error: insert failed: {e}"),
                        None,
                    )
                })?;

                // Return a structured RequireApproval response carrying the opt-in nonce.
                // The agent presents this to the operator, who runs:
                //   stellar-agent approve --id <opt_in_nonce>
                // On the next stellar_trustline call the verified opt-in clears the gate.
                // Pre-flight refusal: nothing was submitted, so this is a
                // business error (`is_error = true`, `ok: false`), not a success
                // envelope — an agent branching on `ok` per the documented
                // contract must not read a clawback-enabled trustline as created.
                // The opt-in `approval_nonce` and expiry are carried in the
                // message so the flow stays completable (the operator can also
                // find it via `stellar-agent approve list`).
                let message = format!(
                    "{warning} Run `stellar-agent approve --id {opt_in_nonce}` to record the \
                     clawback opt-in for asset {code} (issuer {issuer}; opt-in expires at \
                     {opt_in_expires} unix ms), then re-invoke stellar_trustline. Review pending \
                     approvals with `stellar-agent approve list`.",
                    code = resolved.code,
                    issuer = redact_strkey_first5_last5(&resolved.issuer),
                );
                return Ok(crate::tools::common::business_error_result(
                    "trustline.clawback_opt_in_required",
                    message,
                ));
            }
            GateDecisionView::Refuse { reason } => {
                tracing::info!(
                    tool = "stellar_trustline",
                    chain = %args.chain_id,
                    code = %resolved.code,
                    issuer = %redact_strkey_first5_last5(&resolved.issuer),
                    reason = %reason,
                    "clawback gate Refuse — trustline refused (fail-closed or hard-refusal)"
                );
                let envelope = stellar_agent_core::envelope::Envelope::<()>::err_raw(
                    "trustline.gate_refused",
                    reason,
                );
                let json = envelope
                    .to_json_pretty()
                    .unwrap_or_else(|_| String::from("{}"));
                let mut result = CallToolResult::success(vec![Content::text(json)]);
                result.is_error = Some(true);
                return Ok(result);
            }
        }

        // ── Step 8: Fee resolution ────────────────────────────────────────────
        let fee_choice = parse_classic_fee_choice(args.classic_base.as_deref()).map_err(|err| {
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

        // ── Step 9: Build unsigned ChangeTrust envelope ───────────────────────
        let asset = Asset::from_code_and_issuer(&resolved.code, &resolved.issuer).map_err(|e| {
            rmcp::ErrorData::internal_error(
                format!("envelope_build_error: asset construction: {e}"),
                None,
            )
        })?;

        let mut builder = ClassicOpBuilder::new(
            &args.from,
            source_sequence,
            &self.profile.network_passphrase,
            fee_per_op_stroops,
        );
        if let Err(err) = builder.change_trust(&asset, limit_stroops) {
            return Err(rmcp::ErrorData::internal_error(
                format!("envelope_build_error: change_trust: {err}"),
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

        // ── Step 10: Mint nonce ───────────────────────────────────────────────
        let expiry_unix_ms = now_ms.saturating_add(DEFAULT_NONCE_TTL_MS);

        let nonce = match self.nonce_mint.mint(
            self.tool_catalogue.as_ref(),
            envelope_xdr.as_bytes(),
            now_ms,
            expiry_unix_ms,
            "stellar_trustline_commit",
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
        let nonce_id_prefix = nonce_id_prefix(&nonce);
        tracing::info!(
            tool = "stellar_trustline",
            chain = %args.chain_id,
            nonce_id = %nonce_id_prefix,
            code = %resolved.code,
            issuer = %redact_strkey_first5_last5(&resolved.issuer),
            is_pinned = resolved.is_pinned,
            decision = "simulated",
            "ChangeTrust simulation complete; nonce minted"
        );

        // ── Step 11: Persist pending approval if policy requires it ──────────
        let approval_block = if let DispatchOutcome::RequireApproval(ref _req) = dispatch_outcome {
            let profile_name = self.profile_name_for_approval();
            match self.persist_trustline_pending_approval(
                &envelope_xdr,
                &args.from,
                &resolved.code,
                &resolved.issuer,
                limit_stroops,
                total_fee_stroops,
                source_sequence.saturating_add(1),
                &profile_name,
            ) {
                Ok(entry) => {
                    let approval_expires = entry.expires_at_unix_ms;
                    let approval_nonce = entry.approval_nonce.clone();
                    Some(json!({
                        "approval_nonce": approval_nonce,
                        "expires_at_unix_ms": approval_expires,
                        "summary": {
                            "asset_code": &resolved.code,
                            "asset_issuer": redact_strkey_first5_last5(&resolved.issuer),
                            "limit_stroops": limit_stroops.map(|v| v.to_string()),
                            "simulated_fee_stroops": total_fee_stroops.to_string(),
                            "simulated_seq_num": source_sequence + 1,
                        }
                    }))
                }
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
        // NEVER log envelope_xdr at info.
        tracing::debug!(
            tool = "stellar_trustline",
            chain = %args.chain_id,
            "envelope built (XDR logged at debug only)"
        );

        let simulation = json!({
            "source_account_id": &args.from,
            "source_sequence": source_sequence.to_string(),
            "fee_stroops": total_fee_stroops.to_string(),
            "selected_fee_per_op_stroops": fee_per_op_stroops.to_string(),
            "selected_fee_percentile": &fee_selection.selected_fee_percentile,
            "operation": {
                "type": "change_trust",
                "asset_code": &resolved.code,
                "asset_issuer": redact_strkey_first5_last5(&resolved.issuer),
                "limit_stroops": limit_stroops.map(|v| v.to_string()),
            },
        });

        let mut view = json!({
            "envelope_xdr": &envelope_xdr,
            "nonce": &nonce_b64,
            "expires_at_unix_ms": expiry_unix_ms,
            "simulation": simulation,
            "preview": preview,
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

    /// Signs and submits a `ChangeTrust` transaction (commit step).
    ///
    /// This is the **commit step** of the simulate-then-commit pattern for a
    /// Stellar `ChangeTrust` operation.  The agent supplies the
    /// `(nonce, expires_at_unix_ms, envelope_xdr)` triple returned by
    /// `stellar_trustline`, plus the original arguments.
    ///
    /// # Security invariants (policy-evaluation order)
    ///
    /// 1. **Re-derive authoritative args:** `decode_authoritative_args` decodes
    ///    the HMAC-bound `envelope_xdr` and extracts `(asset_code, asset_issuer,
    ///    limit_stroops)`.  Those values are presented to the policy engine — NOT
    ///    the caller-supplied args.
    /// 2. **Nonce verification:** HMAC-verified before signing.
    /// 3. **Replay prevention:** nonce recorded in the `ReplayWindow`.
    /// 4. **Mainnet refusal:** `destructive_hint = true`.
    #[mcp_tool_item(
        name = "stellar_trustline_commit",
        destructive_hint = true,
        read_only_hint = false,
        chain_id_required = true,
        value_kind = "moves_value"
    )]
    #[tool(
        name = "stellar_trustline_commit",
        description = "Sign and submit a ChangeTrust transaction (commit step). \
                       Requires the nonce, expires_at_unix_ms, and envelope_xdr returned \
                       by stellar_trustline. Verifies the nonce, re-builds the envelope, \
                       signs via keyring, and submits. Returns {tx_hash, ledger}. \
                       destructive_hint=true; read_only_hint=false.",
        annotations(read_only_hint = false, destructive_hint = true)
    )]
    async fn stellar_trustline_commit(
        &self,
        Parameters(args): Parameters<StellarTrustlineCommitArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        // ── Re-derive authoritative args from HMAC-bound envelope_xdr ─────────
        let mut authoritative_args =
            match decode_authoritative_args(&args.envelope_xdr, "stellar_trustline_commit") {
                Ok(a) => a,
                Err(e) => {
                    tracing::debug!(
                        error = %e,
                        tool = "stellar_trustline_commit",
                        "envelope_xdr re-derivation failed; returning simulation.divergence"
                    );
                    return Ok(crate::tools::common::business_error_result(
                        "simulation.divergence",
                        format!("envelope_xdr re-derivation failed: {e}"),
                    ));
                }
            };
        authoritative_args["chain_id"] = serde_json::Value::String(args.chain_id.clone());

        // ── Extract authoritative asset fields for rebuild ────────────────────
        let auth_asset_code = match authoritative_args
            .get("asset_code")
            .and_then(serde_json::Value::as_str)
        {
            Some(s) => s.to_owned(),
            None => {
                return Ok(crate::tools::common::business_error_result(
                    "simulation.divergence",
                    "asset_code missing from authoritative args",
                ));
            }
        };
        let auth_asset_issuer = match authoritative_args
            .get("asset_issuer")
            .and_then(serde_json::Value::as_str)
        {
            Some(s) => s.to_owned(),
            None => {
                return Ok(crate::tools::common::business_error_result(
                    "simulation.divergence",
                    "asset_issuer missing from authoritative args",
                ));
            }
        };
        let auth_limit_stroops = authoritative_args
            .get("limit_stroops")
            .and_then(crate::tools::amount_wire::value_as_stroops_i64);

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

        // ── Validate G-strkey ─────────────────────────────────────────────────
        // Runs BEFORE the source-account fetch below: `fetch_account` itself
        // parses `args.from` via the same strkey check and would otherwise
        // surface a malformed `from` as a redacted RPC-error business envelope
        // instead of this dedicated `invalid_params` protocol error.
        if let Err(err) = stellar_strkey::ed25519::PublicKey::from_string(&args.from) {
            return Err(rmcp::ErrorData::invalid_params(
                format!("invalid from (expected G-strkey): {err}"),
                None,
            ));
        }

        // ── Re-fetch source + issuer accounts (feed the policy gate's views;
        // sequence number also consumed by the rebuild below) ────────────────
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

        let source_account_view = match fetch_account(&client, &args.from, &[]).await {
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
        let source_sequence = source_account_view.sequence_number;

        // ── Dispatch gate (authoritative args + source account_view) ──────────
        // `identity_view` stays `None`, matching the simulate tool: the only
        // counterparty account (the asset issuer) carries a self-asserted
        // `home_domain`, which must not feed allowlist matching; identity-class
        // criteria configured on this verb fail closed.
        let source_adapter = AccountViewAdapter::new(&source_account_view);
        let dispatch_outcome = match self
            .dispatch_gate_with_views(
                "stellar_trustline_commit",
                &authoritative_args,
                &args.chain_id,
                Some(&source_adapter),
                None,
            )
            .await
        {
            Ok(o) => o,
            Err(e) => return e.into_result(),
        };

        // ── Attestation verification gate ─────────────────────────────────────
        if let Err(result) = verify_attestation_gate(
            self,
            &dispatch_outcome,
            &args.envelope_xdr,
            args.approval_nonce.as_deref(),
            args.approval_attestation.as_deref(),
            "stellar_trustline_commit",
        )
        .await
        {
            return Ok(result);
        }

        // ── Decode nonce ──────────────────────────────────────────────────────
        let nonce = match stellar_agent_nonce::Nonce::from_base64(&args.nonce) {
            Ok(n) => n,
            Err(_) => return Ok(commit_path_error_result("nonce parse failed")),
        };

        // ── Re-build envelope (divergence check) ──────────────────────────────
        let asset = match Asset::from_code_and_issuer(&auth_asset_code, &auth_asset_issuer) {
            Ok(a) => a,
            Err(err) => return Ok(commit_path_error_result(err)),
        };

        let mut builder = ClassicOpBuilder::new(
            &args.from,
            source_sequence,
            &self.profile.network_passphrase,
            fee_per_op_stroops,
        );
        if let Err(err) = builder.change_trust(&asset, auth_limit_stroops) {
            return Ok(commit_path_error_result(err));
        }
        let rebuilt_envelope_xdr = match builder.build() {
            Ok(xdr) => xdr,
            Err(err) => return Ok(commit_path_error_result(err)),
        };

        if rebuilt_envelope_xdr != args.envelope_xdr {
            return Ok(crate::tools::common::business_error_result(
                "simulation.divergence",
                "re-built envelope does not match presented envelope_xdr; \
                 re-simulate to obtain a fresh envelope",
            ));
        }

        // ── Nonce verification + replay window ────────────────────────────────
        let now_ms = now_unix_ms()
            .map_err(|e| rmcp::ErrorData::internal_error(format!("clock_error: {e}"), None))?;

        use crate::tools::common::commit_envelope_and_verify_nonce;
        if let Err(e) = commit_envelope_and_verify_nonce(
            &self.nonce_mint,
            &self.replay_window,
            &nonce,
            &args.envelope_xdr,
            args.expires_at_unix_ms,
            &args.chain_id,
            "stellar_trustline_commit",
            now_ms,
        )
        .await
        {
            return e.into_result();
        }

        // ── Load signer handle from keyring ───────────────────────────────────
        let handle = match signer_from_keyring(&self.profile.mcp_signer_default, &args.from).await {
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

        // ── Sign envelope ─────────────────────────────────────────────────────
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

        // Extract the gate-sized legs for the post-submit audit row: the SAME
        // ValueEffects the gate evaluated (single-derivation invariant). Empty on
        // any non-value allow path.
        // Resolved once and reused for BOTH the audit row's legs and the
        // window-state recording after confirmed submit (single-derivation
        // invariant on the recording side too).
        let gate_value_effects: Option<stellar_agent_core::policy::v1::ValueEffects> =
            match &dispatch_outcome {
                DispatchOutcome::Allow(Some(effects)) => Some(effects.clone()),
                _ => None,
            };
        let audit_legs: Vec<stellar_agent_core::audit_log::ValueLegRecord> = gate_value_effects
            .as_ref()
            .map(|effects| effects.legs().iter().map(Into::into).collect())
            .unwrap_or_default();

        // ── Submit ────────────────────────────────────────────────────────────
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
                // Log tx hash first-8-last-8 at info per the redaction policy.
                let tx_hash_redacted = format!(
                    "{}…{}",
                    &tx_hash[..8.min(tx_hash.len())],
                    if tx_hash.len() > 8 {
                        &tx_hash[tx_hash.len().saturating_sub(8)..]
                    } else {
                        ""
                    }
                );
                tracing::info!(
                    tool = "stellar_trustline_commit",
                    chain = %args.chain_id,
                    nonce_id = %nonce_id_prefix,
                    code = %auth_asset_code,
                    issuer = %redact_strkey_first5_last5(&auth_asset_issuer),
                    tx_hash = %tx_hash_redacted,
                    decision = "committed",
                    "ChangeTrust tx submitted"
                );

                // Non-fatal allow-path audit row carrying the gate-sized legs.
                let audit_request_id = uuid::Uuid::new_v4().to_string();
                let audit_entry =
                    stellar_agent_core::audit_log::AuditEntry::new_value_action_submitted(
                        "stellar_trustline_commit",
                        args.chain_id.as_str(),
                        audit_legs,
                        tx_hash_redacted.as_str(),
                        ledger,
                        stellar_agent_core::audit_log::PolicyDecision::Allow,
                        None,
                        Some(nonce_id_prefix.to_string()),
                        &audit_request_id,
                    );
                crate::tools::value_audit::emit_value_audit_row(
                    &self.profile,
                    &self.profile_name_for_approval(),
                    audit_entry,
                );

                if let Some(descriptor) = self.tool_registry.get("stellar_trustline_commit") {
                    let value_class = gate_value_effects
                        .clone()
                        .map(stellar_agent_core::policy::v1::ValueClass::Value)
                        .unwrap_or(stellar_agent_core::policy::v1::ValueClass::ReadOnly);
                    stellar_agent_network::policy_state::record_confirmed_window_state(
                        self.policy_engine.as_ref(),
                        descriptor,
                        &self.profile,
                        &self.profile_name_for_approval(),
                        &value_class,
                    );
                }

                // Best-effort: remove the consumed approval entry.
                if let Some(ref approval_nonce_str) = args.approval_nonce
                    && let Ok(approvals_dir) =
                        stellar_agent_core::profile::schema::default_approval_dir()
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
                                    "stellar_trustline_commit: approval entry remove failed after \
                                     successful submit; entry will expire via gc"
                                );
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                "stellar_trustline_commit: approval store open failed during \
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
// Test helpers
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(any(test, feature = "test-helpers"))]
impl WalletServer {
    /// Calls `stellar_trustline` (simulate step) bypassing the rmcp transport.
    ///
    /// Integration-test entry point.
    ///
    /// # Feature gate
    ///
    /// Gated on `test-helpers` feature or `#[cfg(test)]`.
    #[doc(hidden)]
    pub async fn call_stellar_trustline(
        &self,
        args: StellarTrustlineArgs,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.stellar_trustline(Parameters(args)).await
    }

    /// Calls `stellar_trustline_commit` (commit step) bypassing the rmcp transport.
    ///
    /// Integration-test entry point.
    ///
    /// # Feature gate
    ///
    /// Gated on `test-helpers` feature or `#[cfg(test)]`.
    #[doc(hidden)]
    pub async fn call_stellar_trustline_commit(
        &self,
        args: StellarTrustlineCommitArgs,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.stellar_trustline_commit(Parameters(args)).await
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::panic,
        reason = "test-only assertions use panic for explicit failure messages"
    )]

    use super::*;

    #[test]
    fn parse_denomination_input_bare_code() {
        let input = parse_denomination_input("USDC");
        assert!(matches!(input, DenominationInput::BareCode(c) if c == "USDC"));
    }

    #[test]
    fn parse_denomination_input_code_issuer() {
        let issuer = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";
        let asset = format!("USDC:{issuer}");
        let input = parse_denomination_input(&asset);
        match input {
            DenominationInput::CodeAndIssuer {
                ref code,
                issuer: ref actual_issuer,
            } => {
                assert_eq!(code, "USDC");
                assert_eq!(actual_issuer, issuer);
            }
            other => panic!("expected CodeAndIssuer, got: {other:?}"),
        }
    }

    #[test]
    fn parse_denomination_input_sac_address() {
        // 56-char C-strkey
        let sac = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";
        let input = parse_denomination_input(sac);
        assert!(matches!(input, DenominationInput::SacAddress(_)));
    }

    #[test]
    fn parse_denomination_input_short_c_prefix_is_bare_code() {
        // A short string starting with C is NOT a SAC address.
        let input = parse_denomination_input("CUPS");
        assert!(matches!(input, DenominationInput::BareCode(_)));
    }
}
