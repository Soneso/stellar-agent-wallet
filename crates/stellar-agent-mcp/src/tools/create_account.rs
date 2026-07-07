//! `stellar_create_account` and `stellar_create_account_commit` MCP tools.
//!
//! Contains argument types, the `#[tool_router]` impl block for the
//! `create_account_tool_router`, and test-helpers for integration tests.

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
    high_value_cross_check, ledger_err_result, nonce_id_prefix, redact_rpc_error_detail,
    redacted_wallet_error_envelope, resolve_classic_fee_per_op_stroops, submit_timeout,
    total_classic_fee_stroops, validate_g_strkey, verify_attestation_gate,
};
use stellar_agent_core::amount::McpAmountArgument;
use stellar_agent_core::approval::retry::{
    DEFAULT_RETRY_ATTEMPTS, DEFAULT_RETRY_BACKOFF, open_with_retry,
};
use stellar_agent_core::approval::store::PendingApproval;
use stellar_agent_core::approval::user_id::process_uid_for_attestation;
use stellar_agent_core::envelope_decode::decode_authoritative_args;
use stellar_agent_core::profile::schema::default_approval_dir;
use stellar_agent_core::timefmt::now_unix_ms;
use stellar_agent_core::wallet::Wallet;
use stellar_agent_network::{
    BASE_RESERVE_STROOPS, ClassicOpBuilder, StellarRpcClient, fetch_account,
    keyring::signer_from_keyring,
    parse_classic_fee_choice, resolve_classic_fee_selection,
    signing::envelope_signing::attach_signature,
    submit::{SubmissionResult, SubmissionSignerKind, submit_transaction_and_wait},
};

/// Computes the create-account pre-flight required balance in stroops:
/// `starting_balance + BASE_RESERVE + fee`.
///
/// `fee_stroops` denotes the classic transaction fee specifically.
/// Soroban resource fees use a different fee shape; do not pass them here.
///
/// # Errors
///
/// Returns [`rmcp::ErrorData::internal_error`] on `i64` overflow.  This masks
/// arithmetically impossible required-balance requests as hard rejections,
/// matching the `tools/pay.rs` overflow-handling pattern.
fn required_create_account_balance_stroops(
    starting_balance_stroops: i64,
    fee_stroops: i64,
) -> Result<i64, rmcp::ErrorData> {
    starting_balance_stroops
        .checked_add(BASE_RESERVE_STROOPS)
        .and_then(|x| x.checked_add(fee_stroops))
        .ok_or_else(|| {
            rmcp::ErrorData::internal_error(
                "internal_error: amount + reserve + fee overflow i64",
                None,
            )
        })
}

// ─────────────────────────────────────────────────────────────────────────────
// Argument types
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for the `stellar_create_account` (simulate) MCP tool.
///
/// This is the simulate step of the simulate-then-commit pattern.  The tool
/// builds an unsigned envelope, mints a single-use nonce binding it to
/// `stellar_create_account_commit`, and returns both for the agent to pass
/// back at the commit step.
///
/// # Unit-label boundary
///
/// `starting_balance` MUST be `McpAmountArgument` so unit-label enforcement
/// runs at deserialization time.
///
/// # Examples
///
/// Agent input JSON:
///
/// ```json
/// {
///   "chain_id": "stellar:testnet",
///   "source": "GABC...SRC",
///   "destination": "GDEF...NEW",
///   "starting_balance": "1 XLM"
/// }
/// ```
#[derive(Debug, Clone, serde::Deserialize, schemars::JsonSchema)]
#[serde(crate = "rmcp::serde")]
pub struct StellarCreateAccountArgs {
    /// CAIP-2 chain identifier: `stellar:testnet` or `stellar:mainnet`.
    ///
    /// Must match the loaded profile's `chain_id`.
    pub chain_id: String,

    /// G-strkey of the source (funding) account.
    ///
    /// This account pays the starting balance and the transaction fee.
    /// Must exist on the selected network.
    pub source: String,

    /// G-strkey of the destination (new) account to create.
    ///
    /// Must not yet exist on the network.
    pub destination: String,

    /// Starting balance for the new account, with explicit unit suffix.
    ///
    /// Example: `"1 XLM"`.  Must be sufficient to cover the Stellar base
    /// reserve.  The `McpAmountArgument` wrapper enforces the unit label at
    /// the deserialization boundary.
    pub starting_balance: McpAmountArgument,

    /// Classic fee per operation: `<stroops>`, `auto`, or `auto:pNN`.
    #[serde(default, rename = "fee", skip_serializing_if = "Option::is_none")]
    pub classic_base: Option<String>,
}

/// Arguments for the `stellar_create_account_commit` (commit) MCP tool.
///
/// The agent calls this with the triple `(nonce, expires_at_unix_ms,
/// envelope_xdr)` returned by the simulate step, plus the original call
/// arguments, to sign and submit the transaction.
///
/// # Security invariants
///
/// - The nonce is HMAC-verified against the envelope XDR and expiry before
///   signing (`NonceMint::verify`).
/// - The envelope is re-built from `source` / `destination` /
///   `starting_balance` / current sequence; a divergence between the re-built
///   and the presented `envelope_xdr` returns `simulation.divergence`.
/// - This tool has `destructive_hint = true` so `NoopPolicyEngine` refuses
///   mainnet profiles.
///
/// # Examples
///
/// Agent input JSON:
///
/// ```json
/// {
///   "chain_id": "stellar:testnet",
///   "source": "GABC...SRC",
///   "destination": "GDEF...NEW",
///   "starting_balance": "1 XLM",
///   "nonce": "<base64-url-no-pad from simulate>",
///   "expires_at_unix_ms": 1234567890000,
///   "envelope_xdr": "<base64 from simulate>"
/// }
/// ```
#[derive(Debug, Clone, serde::Deserialize, schemars::JsonSchema)]
#[serde(crate = "rmcp::serde")]
pub struct StellarCreateAccountCommitArgs {
    /// CAIP-2 chain identifier: `stellar:testnet` or `stellar:mainnet`.
    pub chain_id: String,

    /// G-strkey of the source (funding) account (same as simulate step).
    pub source: String,

    /// G-strkey of the destination (new) account (same as simulate step).
    pub destination: String,

    /// Starting balance for the new account (same as simulate step).
    ///
    /// Re-used to re-build the envelope for the divergence check.
    pub starting_balance: McpAmountArgument,

    /// Base64-url-no-pad nonce returned by the simulate step.
    ///
    /// HMAC-verified against `envelope_xdr`, `expires_at_unix_ms`, and the
    /// registered commit tool name before signing.
    pub nonce: String,

    /// Unix timestamp (milliseconds) at which the nonce expires.
    ///
    /// Must match the value returned by the simulate step exactly.
    pub expires_at_unix_ms: u64,

    /// Base64 XDR envelope returned by the simulate step.
    ///
    /// Compared byte-for-byte to a freshly re-built envelope; mismatch returns
    /// `simulation.divergence`.  Passed verbatim to HMAC verification.
    pub envelope_xdr: String,

    /// Wallet-issued approval nonce from the simulate-step `approval` block.
    ///
    /// Required only when the simulate step returned a `policy.approval_required`
    /// outcome (i.e. the policy engine emitted `Decision::RequireApproval`).
    /// When present, the commit handler verifies the HMAC-SHA256 attestation blob
    /// and confirms the envelope hash matches before proceeding.
    #[serde(default)]
    pub approval_nonce: Option<String>,

    /// HMAC-SHA256 attestation blob, URL-safe base64 no-pad encoded (32 bytes).
    ///
    /// Written to the pending-approvals store by `stellar-agent approve --id
    /// <approval_nonce>` after the user confirms on their own tty.  The commit
    /// handler re-computes and constant-time-compares the HMAC against the stored
    /// attestation key before proceeding to signing.
    ///
    /// Required alongside `approval_nonce` when the policy engine requires
    /// approval.  Absent or invalid → `policy.approval_required` (byte-identical
    /// wire code for all failure modes, for indistinguishability).
    #[serde(default)]
    pub approval_attestation: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// WalletServer — approval-spine helpers for create_account
// ─────────────────────────────────────────────────────────────────────────────

impl WalletServer {
    /// Persists a [`PendingApproval`] entry for a `stellar_create_account`
    /// simulate call.
    ///
    /// Opens (or creates) the profile-scoped approval store at
    /// `~/.local/state/stellar-agent/approvals/<profile_name>.toml`, constructs
    /// an unattested entry from the create-account arguments, inserts it, and
    /// returns the entry for nonce / expiry extraction by the caller.
    ///
    /// # Errors
    ///
    /// Returns a string error description on any I/O, store-lock, or clock failure.
    pub(crate) fn persist_create_account_pending_approval(
        &self,
        envelope_xdr: &str,
        summary_destination: &str,
        summary_starting_stroops: i64,
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
        let entry = PendingApproval::new_payment_pending(
            envelope_xdr.to_owned(),
            envelope_xdr.as_bytes(),
            summary_destination.to_owned(),
            summary_starting_stroops,
            "XLM".to_owned(),
            None, // CreateAccount has no memo
            summary_simulated_total_stroops,
            summary_simulated_seq_num,
            uid,
            APPROVAL_TTL_MS,
        )
        .map_err(|e| format!("PendingApproval::new_payment_pending failed: {e}"))?;

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
#[tool_router(router = create_account_tool_router, vis = "pub(crate)")]
impl WalletServer {
    /// Builds a `CreateAccount` transaction envelope and mints a single-use nonce.
    ///
    /// This is the **simulate step** of the simulate-then-commit pattern.  It
    /// returns an unsigned envelope plus a nonce bound to
    /// `stellar_create_account_commit`.  The agent MUST pass all three returned
    /// fields (`envelope_xdr`, `nonce`, `expires_at_unix_ms`) unmodified to the
    /// commit step.
    ///
    /// # Simulate vs Soroban preflight
    ///
    /// For classic XLM operations there is no Soroban preflight.  "Simulation"
    /// here means: build the envelope, verify it parses, and fetch the source
    /// account's current on-chain state (sequence number, native balance,
    /// sufficient-balance check).  No RPC write is performed.
    ///
    /// # Tool annotations
    ///
    /// - `readOnlyHint = false` — mints a nonce (wallet state mutation).
    /// - `destructiveHint = false` — does NOT submit a transaction; the commit
    ///   step (`stellar_create_account_commit`) carries `destructive_hint = true`.
    ///
    /// # Nonce lifetime
    ///
    /// The nonce is valid for 2 minutes (configurable in the range 30 s–5 min).
    /// After expiry the agent must re-call this tool to obtain a fresh nonce.
    ///
    /// # Errors
    ///
    /// Returns a tool-level error (not a JSON-RPC error) when:
    /// - The policy engine denies the call.
    /// - `chain_id` does not match the profile's configured chain.
    /// - `source` or `destination` are not valid G-strkeys.
    /// - The source account cannot be fetched (not found or RPC error).
    /// - The source account's available native balance (raw balance minus its
    ///   own minimum reserve: `balance - (2 + subentry_count) * base_reserve`)
    ///   is below `starting_balance + recipient_base_reserve + fee`.  The
    ///   check uses the full subentry-aware available balance formula.
    /// - `NonceMint::mint` fails (keyring unavailable, TTL out of range, etc.).
    ///
    /// # Examples
    ///
    /// ```json
    /// {
    ///   "chain_id": "stellar:testnet",
    ///   "source": "GABC...SRC",
    ///   "destination": "GDEF...NEW",
    ///   "starting_balance": "1 XLM"
    /// }
    /// ```
    #[mcp_tool_item(
        name = "stellar_create_account",
        destructive_hint = false,
        read_only_hint = false,
        chain_id_required = true
    )]
    #[tool(
        name = "stellar_create_account",
        description = "Build a CreateAccount transaction envelope and mint a single-use nonce \
                       (simulate step). Returns {envelope_xdr, nonce, expires_at_unix_ms, \
                       simulation}. Pass all three to stellar_create_account_commit to sign \
                       and submit. destructive_hint=false; read_only_hint=false.",
        annotations(read_only_hint = false, destructive_hint = false)
    )]
    async fn stellar_create_account(
        &self,
        Parameters(args): Parameters<StellarCreateAccountArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        // ── dispatch gate ────────────────────────────────────────────────────
        let args_value = json!({
            "chain_id": &args.chain_id,
            "source": &args.source,
            "destination": &args.destination,
            "starting_balance_stroops": args.starting_balance.as_stroops().to_string(),
        });
        // ── Validate G-strkeys ────────────────────────────────────────────────
        validate_g_strkey(&args.source, "source")?;
        validate_g_strkey(&args.destination, "destination")?;

        // ── Fetch source account state ────────────────────────────────────────
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

        let account_view = match fetch_account(&client, &args.source, &[]).await {
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

        // ── Dispatch gate (with policy views) ─────────────────────────────────
        // The source AccountView feeds the `minimum_reserve` criterion. The
        // destination is being created, so it has no on-chain `home_domain`;
        // `identity_view` is therefore `None` (a `home_domain_resolved` criterion
        // configured for this tool fails closed, which is correct — a not-yet-
        // existent account has no home_domain to resolve).
        let source_adapter = crate::policy_adapter::AccountViewAdapter::new(&account_view);
        let dispatch_outcome = match self
            .dispatch_gate_with_views(
                "stellar_create_account",
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

        let source_sequence = account_view.sequence_number;
        // Use the canonical decimal-to-stroops parser to avoid f64 precision
        // loss for large balances (≥ ~9 million XLM). No floating-point
        // arithmetic is involved.
        let native_balance_stroops = account_view
            .balances
            .first()
            .filter(|b| b.asset.asset_type == "native")
            .map(|b| b.balance_stroops())
            .transpose()
            .map_err(|e| {
                rmcp::ErrorData::internal_error(format!("balance_parse_error: {e}"), None)
            })?
            .unwrap_or(0_i64);

        // Full subentry-aware pre-flight balance check.
        //
        // Available native balance = raw balance minus the source account's own
        // minimum reserve: (2 + subentry_count) * BASE_RESERVE_STROOPS.
        // Required = starting_balance (transferred) + recipient's first
        // base_reserve (new account creation) + fee.
        let source_reserves = account_view.reserves_stroops(BASE_RESERVE_STROOPS);
        let starting_balance_stroops = args.starting_balance.as_stroops();
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
        let fee_stroops = i64::from(total_fee_stroops);

        // saturating_sub: under-reserved accounts (balance < reserves) yield
        // available = 0, which then fails the available < required check and
        // surfaces InsufficientBalance correctly instead of internal_error.
        let available = native_balance_stroops.saturating_sub(source_reserves);

        // BASE_RESERVE_STROOPS here is the recipient's first reserve unit (single
        // subentry equivalent for new account creation), distinct from the
        // `(2 + n) * base_reserve` source-account formula above.
        let required =
            required_create_account_balance_stroops(starting_balance_stroops, fee_stroops)?;

        if available < required {
            return Ok(ledger_err_result(&stellar_agent_core::WalletError::Ledger(
                stellar_agent_core::LedgerError::InsufficientBalance {
                    asset: "XLM".to_owned(),
                    have: available.to_string(),
                    need: required.to_string(),
                },
            )));
        }

        // ── Build unsigned envelope ───────────────────────────────────────────
        // Pass `source_sequence` (the current on-chain value) directly.
        // `stellar_baselib::TransactionBuilder::build` calls
        // `Account::increment_sequence_number` internally, matching the
        // js-stellar-base convention: caller passes CURRENT seq, builder produces
        // CURRENT+1 in the envelope. An explicit +1 here would produce
        // CURRENT+2 → TxBadSeq on submit.
        // `starting_balance_stroops` is already captured in the pre-flight block above.
        let mut builder = ClassicOpBuilder::new(
            &args.source,
            source_sequence,
            &self.profile.network_passphrase,
            fee_per_op_stroops,
        );
        if let Err(err) = builder.create_account(
            &args.destination,
            args.starting_balance.into_stellar_amount(),
        ) {
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
        // Use the typed helper; returns Err on clock anomaly instead of silently
        // producing a 1970 nonce (which would always appear expired).
        let now_ms = now_unix_ms()
            .map_err(|e| rmcp::ErrorData::internal_error(format!("clock_error: {e}"), None))?;
        let expiry_unix_ms = now_ms.saturating_add(DEFAULT_NONCE_TTL_MS);

        let nonce = match self.nonce_mint.mint(
            self.tool_catalogue.as_ref(),
            envelope_xdr.as_bytes(),
            now_ms,
            expiry_unix_ms,
            "stellar_create_account_commit",
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

        // Emit structured audit event with nonce_id (first 4 bytes of the nonce
        // base64 = first 3 bytes of salt in hex) for correlating simulate→commit
        // pairs in operator telemetry.
        let nonce_b64 = nonce.to_base64();
        let nonce_id_prefix = nonce_id_prefix(&nonce);
        tracing::info!(
            tool = "stellar_create_account",
            chain = %args.chain_id,
            nonce_id = %nonce_id_prefix,
            decision = "simulated",
            "CreateAccount simulation complete; nonce minted"
        );

        // ── Persist pending approval if policy requires it ───────────────────
        let approval_block = if let DispatchOutcome::RequireApproval(_) = &dispatch_outcome {
            let profile_name = self.profile_name_for_approval();
            match self.persist_create_account_pending_approval(
                &envelope_xdr,
                &args.destination,
                starting_balance_stroops,
                total_fee_stroops,
                source_sequence.saturating_add(1),
                &profile_name,
            ) {
                Ok(entry) => Some(json!({
                    "approval_nonce": entry.approval_nonce,
                    "expires_at_unix_ms": entry.expires_at_unix_ms,
                    "summary": {
                        "to": &args.destination,
                        "amount_stroops": starting_balance_stroops.to_string(),
                        "asset": "XLM",
                        "memo": null,
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
        let simulation = json!({
            "source_account_id": &args.source,
            "source_sequence": source_sequence.to_string(),
            "source_native_balance_stroops": native_balance_stroops.to_string(),
            "fee_stroops": total_fee_stroops.to_string(),
            "selected_fee_per_op_stroops": fee_per_op_stroops.to_string(),
            "selected_fee_percentile": &fee_selection.selected_fee_percentile,
            "operation": {
                "type": "create_account",
                "destination": &args.destination,
                "starting_balance_stroops": starting_balance_stroops.to_string(),
            }
        });
        let mut view = json!({
            "envelope_xdr": &envelope_xdr,
            "nonce": &nonce_b64,
            "expires_at_unix_ms": expiry_unix_ms,
            "simulation": simulation,
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

    /// Signs and submits a `CreateAccount` transaction (commit step).
    ///
    /// This is the **commit step** of the simulate-then-commit pattern.  The
    /// agent supplies the `(nonce, expires_at_unix_ms, envelope_xdr)` triple
    /// returned by `stellar_create_account`, plus the original call arguments.
    ///
    /// # Security invariants
    ///
    /// 1. **Nonce verification:** the nonce is HMAC-verified against the
    ///    presented `envelope_xdr` and `expires_at_unix_ms` before any signing
    ///    or network call.
    /// 2. **Envelope divergence check:** the envelope is re-built from the
    ///    presented args + current source account state.  If the re-built
    ///    envelope differs from `envelope_xdr`, the call returns
    ///    `simulation.divergence` without signing.
    /// 3. **Replay prevention:** the nonce salt is recorded in the in-memory
    ///    `ReplayWindow` after successful verification; a second call with the
    ///    same nonce returns `nonce.replayed`.
    /// 4. **Mainnet refusal:** `destructive_hint = true` causes
    ///    `NoopPolicyEngine` to return `Err(NotImplemented)` for mainnet
    ///    profiles.
    ///
    /// # Security
    ///
    /// **Rebuild is UX freshness; HMAC is the integrity gate.**
    ///
    /// The envelope divergence check (invariant 2 above) re-builds the
    /// `CreateAccount` envelope from the agent-supplied args + current on-chain
    /// source-account state.  This rebuild is a **freshness UX check**: if the
    /// sequence number or balance changed between simulate and commit, the agent
    /// learns before signing, not after a failed submission.
    ///
    /// The **load-bearing integrity defence** is the HMAC over `args.envelope_xdr`
    /// (verified in invariant 1).  The HMAC binds the exact envelope the wallet
    /// produced at simulate time to the nonce; an attacker who replaces
    /// `envelope_xdr` with a different transaction will fail HMAC verification.
    ///
    /// The rebuild and the HMAC are **complementary, not equivalent**:
    ///
    /// - Removing the rebuild would allow a stale (sequence-drifted) envelope to
    ///   proceed to signing and fail on-chain.  The agent would need a second
    ///   round-trip to discover the failure.
    /// - Removing the HMAC verification would allow an attacker who knows the
    ///   nonce token to substitute an arbitrary `envelope_xdr`.
    ///
    /// A future reviewer MUST NOT remove either check as "redundant".
    ///
    /// # Policy-evaluation order
    ///
    /// The commit handler MUST re-derive args from the HMAC-bound
    /// `envelope_xdr` before presenting them to the policy engine.  Caller-supplied
    /// args (`source`, `destination`, `starting_balance`) are NOT trusted at the
    /// policy evaluation step — they are only used for the G-strkey validation and
    /// the envelope-rebuild divergence check (defence-in-depth).
    ///
    /// `decode_authoritative_args` extracts the operation fields from the
    /// decoded XDR and these are passed to `dispatch_gate`.  Mismatch between
    /// the decoded op kind and the expected `CreateAccount` produces
    /// `simulation.divergence`.  This enforces the `args-not-bound` invariant.
    ///
    /// # Error code mapping
    ///
    /// | `NonceError` variant | MCP wire code |
    /// |---|---|
    /// | `Replayed` | `nonce.replayed` |
    /// | `Expired` | `nonce.expired` |
    /// | `HmacMismatch` | `nonce.expired` (indistinguishability) |
    /// | `InvalidTool` | `tool.unknown` |
    /// | `InvalidEnvelope` | `nonce.invalid_envelope` |
    /// | `ChainMismatch` | `nonce.chain_mismatch` |
    /// | `TtlExceeded` | `nonce.ttl_exceeded` |
    /// | `TtlTooShort` | `nonce.ttl_too_short` |
    /// | `KeyringError` | `keyring.error` |
    /// | `KeyTooShort` | `nonce.key_too_short` |
    /// | `SerialiseFailed` | `nonce.serialise_failed` |
    /// | Envelope divergence | `simulation.divergence` |
    ///
    /// See [`NonceError::wire_code`] for the canonical mapping table.
    ///
    /// # Errors
    ///
    /// Returns a tool-level error (not a JSON-RPC error) when:
    /// - The policy engine denies the call (mainnet + destructive).
    /// - `chain_id` does not match the profile.
    /// - `source` or `destination` are invalid G-strkeys.
    /// - The nonce is expired, replayed, or HMAC-mismatched.
    /// - The re-built envelope diverges from `envelope_xdr`.
    /// - The signing key does not match the source account (`SignerKeyMismatch`).
    /// - The RPC submission fails.
    ///
    /// # Examples
    ///
    /// ```json
    /// {
    ///   "chain_id": "stellar:testnet",
    ///   "source": "GABC...SRC",
    ///   "destination": "GDEF...NEW",
    ///   "starting_balance": "1 XLM",
    ///   "nonce": "<base64 from simulate>",
    ///   "expires_at_unix_ms": 1234567890000,
    ///   "envelope_xdr": "<base64 from simulate>"
    /// }
    /// ```
    #[mcp_tool_item(
        name = "stellar_create_account_commit",
        destructive_hint = true,
        read_only_hint = false,
        chain_id_required = true
    )]
    #[tool(
        name = "stellar_create_account_commit",
        description = "Sign and submit a CreateAccount transaction (commit step). \
                       Requires the nonce, expires_at_unix_ms, and envelope_xdr returned \
                       by stellar_create_account. Verifies the nonce, re-builds the envelope, \
                       signs via keyring, and submits. Returns {tx_hash, ledger}. \
                       destructive_hint=true; read_only_hint=false.",
        annotations(read_only_hint = false, destructive_hint = true)
    )]
    async fn stellar_create_account_commit(
        &self,
        Parameters(args): Parameters<StellarCreateAccountCommitArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        // ── Re-derive authoritative args from HMAC-bound envelope_xdr ────────
        //
        // The policy engine MUST evaluate nonce-bound fields. Caller-supplied
        // `source`, `destination`, `starting_balance` args are NOT forwarded to
        // the policy engine — the authoritative values are extracted from the
        // HMAC-bound `envelope_xdr` instead.
        //
        // Failure modes:
        // - XDR decode failure → `simulation.divergence`.
        // - Operation kind mismatch (non-CreateAccount op) → `simulation.divergence`.
        let mut authoritative_args =
            match decode_authoritative_args(&args.envelope_xdr, "stellar_create_account_commit") {
                Ok(a) => a,
                Err(e) => {
                    tracing::debug!(
                        error = %e,
                        tool = "stellar_create_account_commit",
                        "envelope_xdr re-derivation failed; returning simulation.divergence"
                    );
                    return Ok(crate::tools::common::business_error_result(
                        "simulation.divergence",
                        format!("envelope_xdr re-derivation failed: {e}"),
                    ));
                }
            };
        // Inject chain_id (not XDR-encoded; validated by CAIP-2 check in
        // dispatch_gate step 3).
        authoritative_args["chain_id"] = serde_json::Value::String(args.chain_id.clone());

        // ── dispatch gate (uses authoritative args, not caller args) ─────────
        // destructive_hint = true → engine evaluates per profile.policy.engine;
        // Noop refuses on mainnet, V1 evaluates typed criteria.
        let dispatch_outcome = match self
            .dispatch_gate(
                "stellar_create_account_commit",
                &authoritative_args,
                &args.chain_id,
            )
            .await
        {
            Ok(o) => o,
            Err(e) => return e.into_result(),
        };

        // ── Validate G-strkeys ────────────────────────────────────────────────
        validate_g_strkey(&args.source, "source")?;
        validate_g_strkey(&args.destination, "destination")?;

        // ── Decode nonce — map parse error to nonce.expired ──────────────────
        let nonce = match stellar_agent_nonce::Nonce::from_base64(&args.nonce) {
            Ok(n) => n,
            Err(_) => return Ok(commit_path_error_result("nonce parse failed")),
        };

        // ── Re-fetch source account state and re-build envelope ───────────────
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

        let account_view = match fetch_account(&client, &args.source, &[]).await {
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
        // Pass `source_sequence` (current on-chain value) directly.
        // `stellar_baselib::TransactionBuilder::build` auto-increments via
        // `Account::increment_sequence_number`; an explicit +1 here produces
        // CURRENT+2 → TxBadSeq.

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
        // Clone the starting balance before the primary rebuild consumes it;
        // the clone is used by the oracle rebuild closure (if cross-check fires).
        let starting_balance_for_oracle = args.starting_balance.clone();
        // SAFETY-MIRROR: this builder configuration MUST match the oracle-rebuild
        // closure below exactly.  Any change here that is not mirrored in the
        // oracle closure below silently breaks the high-value cross-check.
        // See also pay.rs primary rebuild (mirrored pair).
        let mut builder = ClassicOpBuilder::new(
            &args.source,
            source_sequence,
            &self.profile.network_passphrase,
            fee_per_op_stroops,
        );
        // Commit-path builder failures collapse to the same `nonce.expired`
        // envelope as memo/rebuild failures in pay/trustline commits, so the wire
        // does not distinguish a builder fault from an expired nonce on the commit
        // path (indistinguishability parity across the two-phase classic tools).
        if let Err(err) = builder.create_account(
            &args.destination,
            args.starting_balance.into_stellar_amount(),
        ) {
            return Ok(commit_path_error_result(err));
        }
        let rebuilt_envelope_xdr = match builder.build() {
            Ok(xdr) => xdr,
            Err(err) => return Ok(commit_path_error_result(err)),
        };

        // ── Envelope divergence check ────────────────────────────────────────
        // Byte-for-byte comparison of the re-built envelope against the one the
        // agent presented.  A divergence means the on-chain state changed between
        // simulate and commit (e.g. sequence bumped, balance changed).
        //
        // See `# Security` rustdoc on this function for the full rationale on why
        // the rebuild (UX freshness) and the HMAC (integrity gate) are complementary
        // and MUST NOT be removed as "redundant".
        if rebuilt_envelope_xdr != args.envelope_xdr {
            return Ok(crate::tools::common::business_error_result(
                "simulation.divergence",
                "re-built envelope does not match presented envelope_xdr; \
                 re-simulate to obtain a fresh envelope",
            ));
        }

        // ── High-value independent-RPC cross-check ───────────────────────────
        //
        // `CreateAccount` always transfers native XLM (the `starting_balance`).
        // For transactions at or above `profile.effective_usd_threshold()`,
        // re-builds the envelope against `profile.oracle_provider_url` and
        // asserts byte-identity with the primary rebuild.
        //
        // Skip conditions: value below threshold, or `oracle_provider_url` unset
        // (fail-open with tracing::warn!).
        {
            let starting_balance_stroops: i64 = match authoritative_args
                .get("starting_balance_stroops")
                .and_then(crate::tools::amount_wire::value_as_stroops_i64)
            {
                Some(v) => v,
                None => {
                    return Ok(crate::tools::common::business_error_result(
                        "simulation.divergence",
                        "authoritative_args missing required `starting_balance_stroops` field",
                    ));
                }
            };
            // CreateAccount always transfers native XLM.
            let asset_is_native = true;
            // Capture builder inputs needed for the oracle rebuild.
            let oracle_source = args.source.clone();
            let oracle_destination = args.destination.clone();
            let oracle_network_passphrase = self.profile.network_passphrase.clone();
            let oracle_starting_balance = starting_balance_for_oracle;

            if let Err(result) = high_value_cross_check(
                &self.profile,
                &rebuilt_envelope_xdr,
                &args.source,
                asset_is_native,
                starting_balance_stroops,
                |oracle_client| async move {
                    // Re-fetch account state from the independent RPC.
                    let oracle_account_view = fetch_account(&oracle_client, &oracle_source, &[])
                        .await
                        .map_err(|e| {
                            rmcp::ErrorData::internal_error(format!("oracle_rpc_error: {e}"), None)
                        })?;
                    // SAFETY-MIRROR: this builder configuration MUST match the
                    // primary rebuild above exactly.  Any change here that is not
                    // mirrored in the primary rebuild above silently breaks the
                    // high-value cross-check.
                    let mut oracle_builder = ClassicOpBuilder::new(
                        &oracle_source,
                        oracle_account_view.sequence_number,
                        &oracle_network_passphrase,
                        fee_per_op_stroops,
                    );
                    oracle_builder
                        .create_account(
                            &oracle_destination,
                            oracle_starting_balance.into_stellar_amount(),
                        )
                        .map_err(|e| {
                            rmcp::ErrorData::internal_error(
                                format!("oracle_build_error: {e}"),
                                None,
                            )
                        })?;
                    oracle_builder.build().map_err(|e| {
                        rmcp::ErrorData::internal_error(format!("oracle_build_error: {e}"), None)
                    })
                },
                "stellar_create_account_commit",
            )
            .await
            {
                return Ok(result);
            }
        }

        // ── Attestation verification gate ────────────────────────────────────
        //
        // The attestation gate MUST run BEFORE the nonce HMAC+replay window so
        // that forged-attestation probes cannot learn whether the nonce is still
        // live (timing oracle).  All failure modes collapse to
        // `policy.approval_required`.
        //
        // Ordering note: `stellar_pay_commit_impl` runs this gate BEFORE the
        // RPC fetch (fail-fast principle + toolset-gated test ergonomics).  Here
        // the gate runs AFTER the high-value cross-check because
        // `stellar_create_account_commit` does not have a toolset-gated variant,
        // so there is no test-bypass motivation to hoist the gate above RPC work.
        // The ordering invariant is still satisfied: the gate fires before nonce
        // HMAC+replay.
        //
        // This is a no-op when `dispatch_outcome` is `Allow`.
        if let Err(result) = verify_attestation_gate(
            self,
            &dispatch_outcome,
            &args.envelope_xdr,
            args.approval_nonce.as_deref(),
            args.approval_attestation.as_deref(),
            "stellar_create_account_commit",
        )
        .await
        {
            return Ok(result);
        }

        // ── Nonce verification + replay window ────────────────────────────────
        //
        // Runs AFTER the attestation gate so the nonce is only consumed when the
        // approval has been verified.
        //
        // The typed helper returns Err on clock anomaly instead of silently
        // producing a 1970 nonce.
        let now_ms = now_unix_ms()
            .map_err(|e| rmcp::ErrorData::internal_error(format!("clock_error: {e}"), None))?;

        // Delegates to `commit_envelope_and_verify_nonce` in `tools/common.rs`.
        // That helper encapsulates the HMAC + spawn_blocking + replay-window
        // pattern shared by every *_commit tool.  All wire codes, error-code
        // indistinguishability, and tracing::debug! calls are preserved
        // byte-identical inside the helper.
        if let Err(e) = commit_envelope_and_verify_nonce(
            &self.nonce_mint,
            &self.replay_window,
            &nonce,
            &args.envelope_xdr,
            args.expires_at_unix_ms,
            &args.chain_id,
            "stellar_create_account_commit",
            now_ms,
        )
        .await
        {
            return e.into_result();
        }

        // ── Wallet unlock deferred ───────────────────────────────────────────
        // See stellar_pay_commit for the identical rationale (signer-from-wallet
        // integration is not yet wired).
        {
            let mlock_req = self.profile.wallet.mlock_required;
            tracing::debug!(
                profile = %self.profile_name_for_approval(),
                mlock_required = ?mlock_req,
                "stellar_create_account_commit: Wallet::unlock deferred pending \
                 signer-from-wallet integration"
            );
        }
        let _wallet_guard: Option<Wallet> = None;

        // ── Load signer handle from keyring ──────────────────────────────────
        let handle = match signer_from_keyring(&self.profile.mcp_signer_default, &args.source).await
        {
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

        // ── Sign envelope (single SEP-23 call site) ──────────────────────────
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

        // Explicit dispose of wallet guard after signing.
        drop(_wallet_guard);

        // nonce_id prefix for audit correlation.  Computed here (after signing,
        // before submit) so the value is available in both the success and error
        // arms without cloning the full base64 string again.
        let nonce_id_prefix = nonce_id_prefix(&nonce);

        // ── Submit (mainnet defence-in-depth is inside submit_transaction_and_wait)
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
                // Emit audit event only on confirmed ledger inclusion.
                // decision = "committed" fires here (not before submit) so a
                // submission failure does not falsely record a committed decision.
                tracing::info!(
                    tool = "stellar_create_account_commit",
                    chain = %args.chain_id,
                    nonce_id = %nonce_id_prefix,
                    decision = "committed",
                    "stellar_create_account_commit: tx submitted"
                );

                // Remove the consumed approval entry from the store so it
                // cannot be replayed.  Best-effort: failure does NOT abort the
                // response — the transaction is already on-chain.
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
                                    "stellar_create_account_commit: approval entry remove \
                                     failed after successful submit; entry will expire via gc"
                                );
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                "stellar_create_account_commit: approval store open failed \
                                 during post-commit cleanup; entry will expire via gc"
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
    /// Calls `stellar_create_account` (simulate step) with the given args,
    /// bypassing the rmcp transport.
    ///
    /// Integration-test entry point for handler-level checks.
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// Gated on the `test-helpers` feature or `#[cfg(test)]`.
    #[doc(hidden)]
    pub async fn call_stellar_create_account(
        &self,
        args: StellarCreateAccountArgs,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.stellar_create_account(Parameters(args)).await
    }

    /// Calls `stellar_create_account_commit` (commit step) with the given args,
    /// bypassing the rmcp transport.
    ///
    /// Integration-test entry point for handler-level checks.
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// Gated on the `test-helpers` feature or `#[cfg(test)]`.
    #[doc(hidden)]
    pub async fn call_stellar_create_account_commit(
        &self,
        args: StellarCreateAccountCommitArgs,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.stellar_create_account_commit(Parameters(args)).await
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, reason = "test-only")]

    use super::*;

    #[test]
    fn required_create_account_balance_overflow_errors() {
        let result = required_create_account_balance_stroops(i64::MAX, 1);

        assert!(result.is_err(), "overflow must hard-reject");
    }

    #[test]
    fn required_create_account_balance_adds_starting_balance_reserve_and_fee() {
        let result = required_create_account_balance_stroops(10, 20)
            .expect("small deterministic values must not overflow");

        assert_eq!(result, 10 + BASE_RESERVE_STROOPS + 20);
    }
}
