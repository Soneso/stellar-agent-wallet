//! `stellar_pay` and `stellar_pay_commit` MCP tools.
//!
//! Contains argument types, the `#[tool_router]` impl block for the
//! `pay_tool_router`, and test-helpers for integration tests.

use rmcp::{
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Content},
    schemars, serde, tool, tool_router,
};
use serde_json::json;
use stellar_agent_mcp_macros::mcp_tool_router;
use stellar_xdr::Memo;

use crate::server::WalletServer;
use crate::tools::common::{
    APPROVAL_TTL_MS, CLASSIC_SINGLE_OPERATION_COUNT, DEFAULT_NONCE_TTL_MS, DispatchOutcome,
    commit_envelope_and_verify_nonce, commit_path_error_data, enforce_classic_fee_cap,
    hash_to_lower_hex, high_value_cross_check, ledger_err_result, nonce_id_prefix,
    redact_rpc_error_detail, redacted_wallet_error_envelope, resolve_classic_fee_per_op_stroops,
    submit_timeout, total_classic_fee_stroops, verify_attestation_gate,
};
// McpAmountArgument import: kept as a single-line full path so the
// amount-boundary lint does not treat the `amount:` token in a multi-line use
// block as a field-name declaration.
use stellar_agent_core::amount::McpMemoTextArgument;
use stellar_agent_core::amount::{McpAmountArgument, StellarAmount};
use stellar_agent_core::approval::store::PendingApproval;
use stellar_agent_core::approval::user_id::process_uid_for_attestation;
use stellar_agent_core::approval::{
    DEFAULT_RETRY_ATTEMPTS, DEFAULT_RETRY_BACKOFF, open_with_retry,
};
use stellar_agent_core::envelope_decode::decode_authoritative_args;
use stellar_agent_core::profile::schema::default_approval_dir;
use stellar_agent_core::timefmt::now_unix_ms;
use stellar_agent_core::wallet::Wallet;
use stellar_agent_network::{
    Asset, BASE_RESERVE_STROOPS, ClassicOpBuilder, StellarRpcClient, fetch_account,
    keyring::signer_from_keyring,
    parse_classic_fee_choice, parse_memo_fields, resolve_classic_fee_selection,
    sep29::check_memo_required,
    signing::envelope_signing::attach_signature,
    submit::{SubmissionResult, SubmissionSignerKind, submit_transaction_and_wait},
};

// ─────────────────────────────────────────────────────────────────────────────
// Argument types
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for the `stellar_pay` (simulate) MCP tool.
///
/// Simulate step of the simulate-then-commit pattern for a Stellar `Payment`
/// operation.  On success the tool returns
/// `{envelope_xdr, nonce, expires_at_unix_ms, simulation}` for the agent to
/// pass unmodified to `stellar_pay_commit`.
///
/// # Asset grammar
///
/// - `"native"` or `"XLM"` — native XLM.
/// - `"CODE:G…ISSUER"` — non-native asset (Alphanum4 or Alphanum12).
///
/// # Memo variants (mutually exclusive)
///
/// At most one memo field may be set.  Memo fields carry no amount units and
/// are exempt from amount-boundary unit-label enforcement.
///
/// # Amount boundary
///
/// `amount` MUST be `McpAmountArgument` when used so unit-label enforcement
/// runs at deserialization time. `amount_in_stroops`
/// is the explicit raw-stroop alternative and is mutually exclusive with
/// `amount`.
///
/// # SEP-29
///
/// `stellar_pay` runs the SEP-29 `config.memo_required` check at simulate
/// time against the destination account.  If the destination requires a memo
/// and none is provided, the tool returns `validation.memo_required` before
/// minting a nonce.
///
/// # Examples
///
/// ```json
/// {
///   "chain_id": "stellar:testnet",
///   "source": "GABC...SRC",
///   "destination": "GDEF...DST",
///   "amount": "10 XLM",
///   "asset": "native"
/// }
/// ```
#[derive(Debug, Clone, serde::Deserialize, schemars::JsonSchema)]
#[serde(crate = "rmcp::serde")]
pub struct StellarPayArgs {
    /// CAIP-2 chain identifier: `stellar:testnet` or `stellar:mainnet`.
    ///
    /// Must match the loaded profile's `chain_id`.
    pub chain_id: String,

    /// G-strkey of the source (funding) account.
    ///
    /// Must exist on the network and hold sufficient XLM to cover the payment
    /// amount plus the transaction fee.
    pub source: String,

    /// G-strkey of the recipient account.
    ///
    /// Must be a valid G-strkey.  The account does not need to exist on-chain
    /// for non-native payments (but a CreateAccount op is needed for new
    /// native-XLM accounts).
    pub destination: String,

    /// Payment amount with explicit unit suffix.
    ///
    /// Example: `"10 XLM"`.  The `McpAmountArgument` wrapper enforces the
    /// unit label at the deserialization boundary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<McpAmountArgument>,

    /// Payment amount as a raw stroop integer, decimal-string encoded.
    ///
    /// Mutually exclusive with `amount`. When set, the value is a decimal
    /// string of a non-negative stroop-typed integer with no unit suffix
    /// (e.g. `"10000000"`). Stellar wire amounts are i64 stroops; this value
    /// is rejected if it is negative, malformed, or exceeds `i64::MAX`. A raw
    /// JSON number is rejected by the schema: a JSON number backed by `f64`
    /// cannot represent a stroop amount exactly once it exceeds `2^53`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount_in_stroops: Option<String>,

    /// Asset descriptor.
    ///
    /// - `"native"` or `"XLM"` for XLM (case-insensitive).
    /// - `"CODE:G…ISSUER"` for non-native assets.
    pub asset: String,

    /// Optional UTF-8 text memo (at most 28 bytes).
    ///
    /// Mutually exclusive with `memo_id`, `memo_hash_hex`, `memo_return_hex`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memo_text: Option<McpMemoTextArgument>,

    /// Optional integer memo (u64).
    ///
    /// Mutually exclusive with `memo_text`, `memo_hash_hex`, `memo_return_hex`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memo_id: Option<u64>,

    /// Optional hash memo (64 hex characters = 32 bytes).
    ///
    /// Mutually exclusive with `memo_text`, `memo_id`, `memo_return_hex`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memo_hash_hex: Option<String>,

    /// Optional return memo (64 hex characters = 32 bytes).
    ///
    /// Mutually exclusive with `memo_text`, `memo_id`, `memo_hash_hex`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memo_return_hex: Option<String>,

    /// Classic fee per operation: `<stroops>`, `auto`, or `auto:pNN`.
    #[serde(default, rename = "fee", skip_serializing_if = "Option::is_none")]
    pub classic_base: Option<String>,
}

/// Arguments for the `stellar_pay_commit` (commit) MCP tool.
///
/// The agent calls this with the triple `(nonce, expires_at_unix_ms,
/// envelope_xdr)` returned by the simulate step, plus the original call
/// arguments, to sign and submit the payment transaction.
///
/// # Security invariants (identical to `stellar_create_account_commit`)
///
/// 1. **Nonce verification:** HMAC-verified against the presented
///    `envelope_xdr` before any signing.
/// 2. **Envelope divergence check:** the envelope is re-built from the
///    presented args + current source account state.  Divergence returns
///    `simulation.divergence`.
/// 3. **Replay prevention:** the nonce salt is recorded in the in-memory
///    `ReplayWindow` after verification.
/// 4. **Mainnet refusal:** `destructive_hint = true`.
///
/// # SEP-29 re-check at commit time
///
/// The commit step does NOT re-run `check_memo_required` against the
/// destination.  The simulate step enforces SEP-29 at the boundary where the
/// agent learns; the HMAC binding ensures the envelope is not tampered with
/// between simulate and commit.  Re-checking at commit would require an extra
/// RPC round-trip for no incremental security gain: if the envelope was tampered
/// the divergence check catches it, and if it was not tampered the SEP-29
/// check would produce the same outcome as at simulate time.
///
/// This is a deliberate design choice; it is documented so a future reviewer
/// does not add a redundant re-check.
///
/// # Examples
///
/// ```json
/// {
///   "chain_id": "stellar:testnet",
///   "source": "GABC...SRC",
///   "destination": "GDEF...DST",
///   "amount": "10 XLM",
///   "asset": "native",
///   "nonce": "<base64 from simulate>",
///   "expires_at_unix_ms": 1234567890000,
///   "envelope_xdr": "<base64 from simulate>"
/// }
/// ```
#[derive(Debug, Clone, serde::Deserialize, schemars::JsonSchema)]
#[serde(crate = "rmcp::serde")]
pub struct StellarPayCommitArgs {
    /// CAIP-2 chain identifier: `stellar:testnet` or `stellar:mainnet`.
    pub chain_id: String,

    /// G-strkey of the source (funding) account (same as simulate step).
    pub source: String,

    /// G-strkey of the recipient account (same as simulate step).
    pub destination: String,

    /// Payment amount with explicit unit suffix (same as simulate step).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<McpAmountArgument>,

    /// Payment amount as a raw stroop integer (same as simulate step).
    ///
    /// Mutually exclusive with `amount`. When set, the value is a decimal
    /// string of a non-negative stroop-typed integer with no unit suffix.
    /// Stellar wire amounts are i64 stroops; this value is rejected if it is
    /// negative, malformed, or exceeds `i64::MAX`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount_in_stroops: Option<String>,

    /// Asset descriptor (same as simulate step).
    pub asset: String,

    /// Optional UTF-8 text memo (same as simulate step).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memo_text: Option<McpMemoTextArgument>,

    /// Optional integer memo (same as simulate step).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memo_id: Option<u64>,

    /// Optional hash memo — 64 hex chars (same as simulate step).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memo_hash_hex: Option<String>,

    /// Optional return memo — 64 hex chars (same as simulate step).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memo_return_hex: Option<String>,

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
// Free helpers used by the simulate handler
// ─────────────────────────────────────────────────────────────────────────────

/// Returns a JSON representation of a [`Memo`] suitable for the approval
/// summary block.
///
/// `Memo::None` → `null`.  Text → string.  Id → number.  Hash/Return → hex string.
fn memo_summary_for_json(memo: &Memo) -> serde_json::Value {
    match memo {
        Memo::None => serde_json::Value::Null,
        Memo::Text(t) => {
            // Invariant: memo_text was constructed from a valid UTF-8 JSON string
            // by the caller. `from_utf8` (not `from_utf8_lossy`) is used here so a
            // forged non-UTF-8 memo surfaces a visible "<invalid-utf8>" marker
            // rather than silently substituting U+FFFD.
            let s = std::str::from_utf8(t.as_slice()).unwrap_or("<invalid-utf8>");
            serde_json::Value::String(s.to_owned())
        }
        Memo::Id(id) => serde_json::json!(id),
        Memo::Hash(h) => {
            let hex = hash_to_lower_hex(h);
            serde_json::Value::String(hex)
        }
        Memo::Return(h) => {
            let hex = hash_to_lower_hex(h);
            serde_json::Value::String(hex)
        }
    }
}

/// Returns the simulation JSON representation for a [`Memo`].
fn memo_json(memo: &Memo) -> serde_json::Value {
    match memo {
        Memo::None => json!({ "type": "none" }),
        Memo::Text(t) => {
            // Invariant: JSON deserialization only produces valid UTF-8 strings;
            // the memo_text argument originates from serde_json deserialization
            // of the tool call args, so the bytes are always valid UTF-8.
            // `from_utf8` (not `from_utf8_lossy`) is used to avoid silently
            // substituting U+FFFD for any forged-byte path.
            let text = std::str::from_utf8(t.as_slice()).unwrap_or("<invalid-utf8>");
            json!({ "type": "text", "value": text })
        }
        Memo::Id(id) => json!({ "type": "id", "value": id }),
        Memo::Hash(h) => {
            // Encode hash bytes as lowercase hex for agent readability.
            let hex = hash_to_lower_hex(h);
            json!({ "type": "hash", "value": hex })
        }
        Memo::Return(h) => {
            let hex = hash_to_lower_hex(h);
            json!({ "type": "return", "value": hex })
        }
    }
}

/// Returns the human-readable approval summary representation for a [`Memo`].
fn memo_summary(memo: &Memo) -> Option<String> {
    match memo {
        Memo::Text(t) => Some(
            std::str::from_utf8(t.as_slice())
                .unwrap_or("<invalid-utf8>")
                .to_owned(),
        ),
        Memo::Id(id) => Some(id.to_string()),
        Memo::None => None,
        _ => Some("<binary memo>".to_owned()),
    }
}

fn resolve_payment_amount(
    amount: Option<McpAmountArgument>,
    amount_in_stroops: Option<String>,
) -> Result<StellarAmount, rmcp::ErrorData> {
    match (amount, amount_in_stroops) {
        (Some(_), Some(_)) => Err(rmcp::ErrorData::invalid_params(
            "amount and amount_in_stroops are mutually exclusive",
            None,
        )),
        (None, None) => Err(rmcp::ErrorData::invalid_params(
            "amount or amount_in_stroops is required",
            None,
        )),
        (Some(amount), None) => Ok(amount.into_stellar_amount()),
        (None, Some(raw)) => {
            // Non-negativity is enforced here by parsing into `u64` (the
            // bound the field's Rust type used to carry before it became a
            // decimal string); the `<= i64::MAX` bound is then enforced
            // explicitly by the `i64::try_from` below.
            let stroops =
                crate::tools::amount_wire::parse_stroops_u64_field("amount_in_stroops", &raw)?;
            if stroops == 0 {
                return Err(rmcp::ErrorData::invalid_params(
                    "amount_in_stroops must be positive",
                    None,
                ));
            }
            let stroops = i64::try_from(stroops).map_err(|_| {
                rmcp::ErrorData::invalid_params("amount_in_stroops exceeds i64 max", None)
            })?;
            Ok(StellarAmount::from_stroops(stroops))
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WalletServer — approval-spine helpers
// ─────────────────────────────────────────────────────────────────────────────

impl WalletServer {
    /// Persists a [`PendingApproval`] entry for a `stellar_pay` simulate call.
    ///
    /// Opens (or creates) the profile-scoped approval store at
    /// `~/.local/state/stellar-agent/approvals/<profile_name>.toml`, constructs
    /// an unattested entry from the payment arguments, inserts it, and returns
    /// the entry for nonce / expiry extraction by the caller.
    ///
    /// # Errors
    ///
    /// Returns a string error description on any I/O, store-lock, or clock
    /// failure.  The caller maps this to an `internal_error` MCP response.
    ///
    /// # Feature gate
    ///
    /// Exposed as `pub` when the `test-helpers` feature is enabled, for use in
    /// integration tests.  `pub(crate)` otherwise. Under that same gate, this
    /// honours [`WalletServer::set_approval_dir_for_test`] so a test-isolated
    /// `stellar_pay` simulate call under a `RequireApproval` policy never
    /// writes into the real `default_approval_dir()`, mirroring the override
    /// already applied in `invoke_stellar_pay_commit_toolset_gated`.
    #[allow(clippy::too_many_arguments)]
    #[cfg_attr(not(any(test, feature = "test-helpers")), allow(dead_code))]
    pub(crate) fn persist_pay_pending_approval(
        &self,
        envelope_xdr: &str,
        summary_to: &str,
        summary_stroops: i64,
        summary_asset: &str,
        summary_memo: Option<String>,
        summary_simulated_total_stroops: u32,
        summary_simulated_seq_num: i64,
        profile_name: &str,
    ) -> Result<PendingApproval, String> {
        #[cfg(any(test, feature = "test-helpers"))]
        let approvals_dir = match self.approval_dir_override {
            Some(ref override_dir) => override_dir.clone(),
            None => default_approval_dir()
                .map_err(|e| format!("approval dir resolution failed: {e}"))?,
        };
        #[cfg(not(any(test, feature = "test-helpers")))]
        let approvals_dir =
            default_approval_dir().map_err(|e| format!("approval dir resolution failed: {e}"))?;
        // Create the directory if it does not exist.
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
            summary_to.to_owned(),
            summary_stroops,
            summary_asset.to_owned(),
            summary_memo,
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
#[tool_router(router = pay_tool_router, vis = "pub(crate)")]
impl WalletServer {
    /// Builds a `Payment` transaction envelope and mints a single-use nonce.
    ///
    /// This is the **simulate step** of the simulate-then-commit pattern for
    /// a Stellar `Payment` operation.  Supports both native
    /// XLM and non-native asset payments.
    ///
    /// The tool runs SEP-29 `config.memo_required` enforcement against the
    /// destination account at simulate time — before minting a nonce or
    /// returning the envelope.  If the destination requires a memo and none
    /// is provided, the tool returns `validation.memo_required`.
    ///
    /// # Simulate vs Soroban preflight
    ///
    /// For classic `Payment` operations there is no Soroban preflight.
    /// "Simulation" here means: build the envelope, verify it parses, fetch
    /// the source account's current on-chain state (sequence number, native
    /// balance), and run the SEP-29 check.  No RPC write is performed.
    ///
    /// # Tool annotations
    ///
    /// - `readOnlyHint = false` — mints a nonce (wallet state mutation).
    /// - `destructiveHint = false` — does NOT submit a transaction.
    ///
    /// # Nonce binding
    ///
    /// The nonce is bound to `"stellar_pay_commit"` (the commit tool name),
    /// the envelope XDR bytes, the expiry, and the chain_id.
    ///
    /// # Errors
    ///
    /// Returns a tool-level error (not a JSON-RPC error) when:
    /// - The policy engine denies the call.
    /// - `chain_id` does not match the profile's configured chain.
    /// - `source` or `destination` are not valid G-strkeys.
    /// - `asset` cannot be parsed.
    /// - Multiple memo variants are provided simultaneously.
    /// - The SEP-29 check fails (`validation.memo_required`).
    /// - The source account cannot be fetched (not found or RPC error).
    /// - For native XLM payments: the source account's available native balance
    ///   (`balance - (2 + subentry_count) * base_reserve`) is below
    ///   `amount + fee` (`ledger.insufficient_balance`).  The check uses the
    ///   full subentry-aware available balance formula.
    /// - For non-native asset payments: the source account's XLM available
    ///   balance is below `fee` (`ledger.insufficient_balance` with
    ///   `asset = "XLM"`), OR the source account has no trustline for the
    ///   asset (`ledger.trustline_missing`), OR the trustline balance is below
    ///   `amount` (`ledger.insufficient_balance` with `asset = <code>`).
    /// - `NonceMint::mint` fails (keyring unavailable, TTL out of range, etc.).
    ///
    /// # Examples
    ///
    /// ```json
    /// {
    ///   "chain_id": "stellar:testnet",
    ///   "source": "GABC...SRC",
    ///   "destination": "GDEF...DST",
    ///   "amount": "10 XLM",
    ///   "asset": "native"
    /// }
    /// ```
    #[mcp_tool_item(
        name = "stellar_pay",
        destructive_hint = false,
        read_only_hint = false,
        chain_id_required = true
    )]
    #[tool(
        name = "stellar_pay",
        description = "Build a Payment transaction envelope and mint a single-use nonce \
                       (simulate step). Supports native XLM and non-native assets. \
                       Runs SEP-29 memo-required enforcement at simulate time. \
                       Returns {envelope_xdr, nonce, expires_at_unix_ms, simulation}. \
                       Pass all three to stellar_pay_commit to sign and submit. \
                       destructive_hint=false; read_only_hint=false.",
        annotations(read_only_hint = false, destructive_hint = false)
    )]
    async fn stellar_pay(
        &self,
        Parameters(args): Parameters<StellarPayArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        // ── Dispatch gate ─────────────────────────────────────────────────────
        let payment_amount =
            resolve_payment_amount(args.amount.clone(), args.amount_in_stroops.clone())?;
        let args_value = json!({
            "chain_id": &args.chain_id,
            "source": &args.source,
            "destination": &args.destination,
            "amount": args.amount.as_ref().map(ToString::to_string),
            "amount_in_stroops": &args.amount_in_stroops,
            "amount_stroops": payment_amount.as_stroops().to_string(),
            "asset": &args.asset,
        });
        // ── Validate G-strkeys ────────────────────────────────────────────────
        if let Err(err) = stellar_strkey::ed25519::PublicKey::from_string(&args.source) {
            return Err(rmcp::ErrorData::invalid_params(
                format!("invalid source (expected G-strkey): {err}"),
                None,
            ));
        }
        if let Err(err) = stellar_strkey::ed25519::PublicKey::from_string(&args.destination) {
            return Err(rmcp::ErrorData::invalid_params(
                format!("invalid destination (expected G-strkey): {err}"),
                None,
            ));
        }

        // ── Parse asset ───────────────────────────────────────────────────────
        let asset = match Asset::parse(&args.asset) {
            Ok(a) => a,
            Err(err) => {
                return Err(rmcp::ErrorData::invalid_params(
                    format!("invalid asset: {}", err.code()),
                    None,
                ));
            }
        };

        // ── Parse memo (mutual exclusivity check) ─────────────────────────────
        let memo = match parse_memo_fields(
            args.memo_text.as_ref().map(McpMemoTextArgument::as_str),
            args.memo_id,
            args.memo_hash_hex.as_deref(),
            args.memo_return_hex.as_deref(),
        ) {
            Ok(m) => m,
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
        let memo_present = !matches!(memo, Memo::None);

        // ── Fetch source account state ────────────────────────────────────────
        // For non-native payments, also fetch the source trustline in the SAME
        // batched getLedgerEntries call (one RPC round-trip for account + trustline).
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

        let trustline_request: Vec<Asset> = if matches!(asset, Asset::Native) {
            Vec::new()
        } else {
            vec![asset.clone()]
        };

        let account_view = match fetch_account(&client, &args.source, &trustline_request).await {
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
        // The source AccountView feeds the `minimum_reserve` criterion; the
        // destination's on-chain `home_domain` feeds `home_domain_resolved`. The
        // destination fetch is non-fatal: a not-yet-created destination has no
        // home_domain, so `identity_view` is simply `None`.
        let dest_view = fetch_account(&client, &args.destination, &[]).await.ok();
        let source_adapter = crate::policy_adapter::AccountViewAdapter::new(&account_view);
        let dest_adapter = dest_view
            .as_ref()
            .map(crate::policy_adapter::AccountViewAdapter::new);
        let dispatch_outcome = self
            .dispatch_gate_with_views(
                "stellar_pay",
                &args_value,
                &args.chain_id,
                Some(&source_adapter),
                dest_adapter
                    .as_ref()
                    .map(|a| a as &dyn stellar_agent_core::policy::v1::AccountIdentityView),
            )
            .await?;

        let source_sequence = account_view.sequence_number;
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

        let amount_stroops_i64 = payment_amount.as_stroops();
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
        enforce_classic_fee_cap(
            fee_selection.per_op_stroops,
            &fee_selection.selected_fee_percentile,
            &self.profile,
        )?;
        let fee_per_op_stroops = fee_selection.per_op_stroops;
        let total_fee_stroops =
            total_classic_fee_stroops(fee_per_op_stroops, CLASSIC_SINGLE_OPERATION_COUNT)?;
        let fee_stroops = i64::from(total_fee_stroops);

        // ── Unified native/non-native pre-flight ─────────────────────────────
        //
        // Native path: available = balance - source_reserves; required = amount + fee.
        // Non-native path: check XLM fee affordability first, then trustline
        // existence + trustline balance ≥ amount.  Both paths use the full
        // subentry-aware available balance formula.
        if matches!(asset, Asset::Native) {
            // Native XLM payment: full subentry-aware balance check.
            let source_reserves = account_view.reserves_stroops(BASE_RESERVE_STROOPS);
            // saturating_sub: under-reserved accounts yield available = 0, which
            // fails the available < required check as InsufficientBalance, not
            // internal_error.
            let available = native_balance_stroops.saturating_sub(source_reserves);
            let required = amount_stroops_i64.checked_add(fee_stroops).ok_or_else(|| {
                rmcp::ErrorData::internal_error("internal_error: amount + fee overflow i64", None)
            })?;
            if available < required {
                return Ok(ledger_err_result(&stellar_agent_core::WalletError::Ledger(
                    stellar_agent_core::LedgerError::InsufficientBalance {
                        asset: "XLM".to_owned(),
                        have: available.to_string(),
                        need: required.to_string(),
                    },
                )));
            }
        } else {
            // Non-native payment.
            //
            // Step 1: check XLM fee affordability.  Fees are always paid in XLM
            // regardless of the payment asset; if the source cannot afford the fee
            // the transaction will fail on-chain anyway — surface early as XLM error.
            let source_reserves = account_view.reserves_stroops(BASE_RESERVE_STROOPS);
            // saturating_sub: under-reserved accounts yield available_native = 0,
            // which correctly surfaces as InsufficientBalance (XLM fee).
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

            // Step 2: trustline existence + balance check.
            // `account_view.balances[1..]` contains exactly 0 or 1 trustline
            // entry because we requested exactly 1 asset in `trustline_request`.
            // 0 entries means the account has no trustline for this asset.
            let asset_code = match &asset {
                Asset::Credit { code, .. } => code.clone(),
                // Asset::Native is handled in the outer if-branch above. Kept
                // explicit (instead of folding into the wildcard) so adding a
                // future wildcard arm cannot silently re-introduce a
                // mis-classification of Native as a non-native asset.
                Asset::Native => unreachable!("native handled in if-branch above"),
                // Non-exhaustive: future Asset variants (e.g. LP shares) must not
                // silently surface as XLM; warn and surface as "unknown" so the
                // trustline and balance checks use a visibly wrong code rather than
                // masking the gap.
                other => {
                    tracing::warn!(asset = ?other, "unsupported asset variant in pre-flight; surfacing as `unknown`");
                    "unknown".to_owned()
                }
            };

            if account_view.balances.len() < 2 {
                // No trustline for this asset.
                return Ok(ledger_err_result(&stellar_agent_core::WalletError::Ledger(
                    stellar_agent_core::LedgerError::TrustlineMissing {
                        asset: asset_code,
                        account: args.source.clone(),
                    },
                )));
            }

            // Trustline is present; check balance.
            let trustline_balance_stroops =
                account_view.balances[1].balance_stroops().map_err(|e| {
                    rmcp::ErrorData::internal_error(format!("balance_parse_error: {e}"), None)
                })?;

            if trustline_balance_stroops < amount_stroops_i64 {
                return Ok(ledger_err_result(&stellar_agent_core::WalletError::Ledger(
                    stellar_agent_core::LedgerError::InsufficientBalance {
                        asset: asset_code,
                        have: trustline_balance_stroops.to_string(),
                        need: amount_stroops_i64.to_string(),
                    },
                )));
            }
        }

        // ── SEP-29 memo-required check (simulate time) ────────────────────────
        // Run BEFORE building the envelope so the agent learns about the
        // requirement without having to attempt a commit.  The commit step
        // does NOT re-check SEP-29 (see `StellarPayCommitArgs` rustdoc).
        //
        // Cross-RPC: when `profile.oracle_provider_url` is set, both RPCs are
        // consulted and a mismatch returns `network.rpc_divergence`.
        // If the secondary RPC URL is the same as the primary (degraded profile),
        // a duplicate StellarRpcClient is constructed here; that is harmless
        // (both see the same ledger state) and consistent with how
        // `high_value_cross_check` handles the same condition.
        let sep29_secondary_client = self
            .profile
            .oracle_provider_url
            .as_ref()
            .and_then(|u| StellarRpcClient::new(u.as_str()).ok());
        if let Err(err) = check_memo_required(
            &client,
            sep29_secondary_client.as_ref(),
            &args.destination,
            memo_present,
        )
        .await
        {
            let envelope = stellar_agent_core::envelope::Envelope::<()>::err(&err);
            let json = envelope
                .to_json_pretty()
                .unwrap_or_else(|_| String::from("{}"));
            let mut result = CallToolResult::success(vec![Content::text(json)]);
            result.is_error = Some(true);
            return Ok(result);
        }

        // ── Build unsigned envelope ───────────────────────────────────────────
        // Pass `source_sequence` (the current on-chain value) directly.
        // `stellar_baselib::TransactionBuilder::build` calls
        // `Account::increment_sequence_number` internally.
        // An explicit +1 here would produce CURRENT+2 → TxBadSeq.
        // `amount_stroops_i64` is captured earlier in the pre-flight block.
        let mut builder = ClassicOpBuilder::new(
            &args.source,
            source_sequence,
            &self.profile.network_passphrase,
            fee_per_op_stroops,
        );
        if let Err(err) = builder.payment(&args.destination, payment_amount, &asset) {
            return Err(rmcp::ErrorData::internal_error(
                format!("envelope_build_error: {err}"),
                None,
            ));
        }
        if let Err(err) = builder.memo(&memo) {
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
        let now_ms = now_unix_ms()
            .map_err(|e| rmcp::ErrorData::internal_error(format!("clock_error: {e}"), None))?;
        let expiry_unix_ms = now_ms.saturating_add(DEFAULT_NONCE_TTL_MS);

        let nonce = match self.nonce_mint.mint(
            self.tool_catalogue.as_ref(),
            envelope_xdr.as_bytes(),
            now_ms,
            expiry_unix_ms,
            "stellar_pay_commit",
            &args.chain_id,
        ) {
            Ok(n) => n,
            Err(err) => {
                return Err(rmcp::ErrorData::internal_error(
                    format!("nonce.mint_failed: {err}"),
                    None,
                ));
            }
        };

        let nonce_b64 = nonce.to_base64();
        let nonce_id_prefix = nonce_id_prefix(&nonce);
        tracing::info!(
            tool = "stellar_pay",
            chain = %args.chain_id,
            nonce_id = %nonce_id_prefix,
            decision = "simulated",
            "Payment simulation complete; nonce minted"
        );

        // ── Build asset wire representation ───────────────────────────────────
        let asset_json = match &asset {
            Asset::Native => json!({ "type": "native" }),
            Asset::Credit { code, issuer } => json!({
                "type": "credit",
                "code": code,
                "issuer": issuer,
            }),
            // Non-exhaustive forward-compat wildcard.  If a new Asset variant
            // (e.g. Asset::LiquidityPool) is added in a stellar-baselib upgrade
            // without a matching arm here, this log line fires as a visibility
            // signal for the operator.
            _ => {
                tracing::warn!(
                    asset_type = ?asset,
                    "stellar_pay: Asset wildcard hit; new variant added without handler update"
                );
                json!({ "type": "unknown" })
            }
        };

        // ── Build memo wire representation ────────────────────────────────────
        let memo_json = memo_json(&memo);

        // ── Persist pending approval if policy requires it ────────────────────
        //
        // `process_uid_for_attestation` at simulate time is the user running the
        // MCP server process.  The CLI-side `stellar-agent approve` MUST run as
        // the same user because the HMAC input binds `process_uid`; an
        // attestation produced by a different UID fails HMAC verification at
        // commit time.  This is the cross-account-on-host non-replay binding.
        let approval_block = if let DispatchOutcome::RequireApproval(ref _req) = dispatch_outcome {
            // Derive asset string for summary.
            let asset_str = match &asset {
                stellar_agent_network::Asset::Native => "XLM".to_owned(),
                stellar_agent_network::Asset::Credit { code, issuer } => {
                    format!("{code}:{issuer}")
                }
                _ => "unknown".to_owned(),
            };
            // Derive memo string for summary (None if Memo::None).
            let memo_summary = memo_summary(&memo);

            let profile_name = self.profile_name_for_approval();
            match self.persist_pay_pending_approval(
                &envelope_xdr,
                &args.destination,
                amount_stroops_i64,
                &asset_str,
                memo_summary,
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
                            "to": &args.destination,
                            "amount_stroops": amount_stroops_i64.to_string(),
                            "asset": &asset_str,
                            "memo": memo_summary_for_json(&memo),
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
        let simulation = json!({
            "source_account_id": &args.source,
            "source_sequence": source_sequence.to_string(),
            "source_native_balance_stroops": native_balance_stroops.to_string(),
            "fee_stroops": total_fee_stroops.to_string(),
            "selected_fee_per_op_stroops": fee_per_op_stroops.to_string(),
            "selected_fee_percentile": &fee_selection.selected_fee_percentile,
            "operation": {
                "type": "payment",
                "destination": &args.destination,
                "amount_stroops": amount_stroops_i64.to_string(),
                "asset": asset_json,
            },
            "memo": memo_json,
        });
        let mut view = json!({
            "envelope_xdr": &envelope_xdr,
            "nonce": &nonce_b64,
            "expires_at_unix_ms": expiry_unix_ms,
            "simulation": simulation,
        });
        // Inject approval block only for RequireApproval paths; omitted on Allow.
        if let Some(approval) = approval_block {
            view["approval"] = approval;
        }
        let envelope = stellar_agent_core::envelope::Envelope::ok(view);
        let json_out = envelope
            .to_json_pretty()
            .unwrap_or_else(|_| String::from("{}"));
        Ok(CallToolResult::success(vec![Content::text(json_out)]))
    }

    /// Signs and submits a `Payment` transaction (commit step).
    ///
    /// This is the **commit step** of the simulate-then-commit pattern for a
    /// Stellar `Payment` operation.  The agent supplies the
    /// `(nonce, expires_at_unix_ms, envelope_xdr)` triple returned by
    /// `stellar_pay`, plus the original call arguments.
    ///
    /// # Security invariants (same as `stellar_create_account_commit`)
    ///
    /// 1. **Policy re-evaluation on authoritative args:** before calling
    ///    `dispatch_gate`, the commit handler decodes the HMAC-bound
    ///    `envelope_xdr` back to operation fields and presents those
    ///    authoritative values to the policy engine instead of the
    ///    caller-supplied args.  Mismatch between decoded args and XDR produces
    ///    `simulation.divergence`.
    /// 2. **Nonce verification:** HMAC-verified against the presented
    ///    `envelope_xdr` before any signing.
    /// 3. **Envelope divergence check:** the envelope is re-built from the
    ///    presented args + current source account state.  Divergence returns
    ///    `simulation.divergence`.
    /// 4. **Replay prevention:** the nonce salt is recorded in the in-memory
    ///    `ReplayWindow` after verification.
    /// 5. **Mainnet refusal:** `destructive_hint = true`.
    ///
    /// # Policy-evaluation order
    ///
    /// The commit step MUST present authoritative args (re-derived from the
    /// nonce-bound `envelope_xdr`) to the policy engine, not caller-supplied
    /// args which an attacker could mutate between simulate and commit.  This
    /// invariant is enforced by [`decode_authoritative_args`] called immediately
    /// before `dispatch_gate`.
    ///
    /// # SEP-29 at commit time
    ///
    /// The commit step does NOT re-run `check_memo_required` (see
    /// [`StellarPayCommitArgs`] rustdoc for the design rationale).
    ///
    /// # Error code mapping (same as `stellar_create_account_commit`)
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
    /// See [`stellar_agent_nonce::NonceError::wire_code`] for the canonical
    /// mapping table.
    ///
    /// # Trustline re-fetch
    ///
    /// Commit path does NOT re-fetch the trustline.  The HMAC + envelope rebuild
    /// divergence check covers envelope-bytes drift; a trustline removed between
    /// simulate and commit will surface as on-chain `op_no_trust`.  Re-fetching
    /// here would add a round-trip without preventing the race.
    ///
    /// # Errors
    ///
    /// Returns a tool-level error (not a JSON-RPC error) when:
    /// - `envelope_xdr` XDR decode fails (`simulation.divergence`).
    /// - The decoded operation kind does not match `Payment` / `PathPayment*`
    ///   (`simulation.divergence`).
    /// - The policy engine denies the call (mainnet + destructive).
    /// - `chain_id` does not match the profile.
    /// - `source` or `destination` are invalid G-strkeys.
    /// - The nonce is expired, replayed, or HMAC-mismatched.
    /// - The re-built envelope diverges from `envelope_xdr`.
    /// - The signing key does not match the source account.
    /// - The RPC submission fails.
    #[mcp_tool_item(
        name = "stellar_pay_commit",
        destructive_hint = true,
        read_only_hint = false,
        chain_id_required = true
    )]
    #[tool(
        name = "stellar_pay_commit",
        description = "Sign and submit a Payment transaction (commit step). \
                       Requires the nonce, expires_at_unix_ms, and envelope_xdr returned \
                       by stellar_pay. Verifies the nonce, re-builds the envelope, \
                       signs via keyring, and submits. Returns {tx_hash, ledger}. \
                       destructive_hint=true; read_only_hint=false.",
        annotations(read_only_hint = false, destructive_hint = true)
    )]
    async fn stellar_pay_commit(
        &self,
        Parameters(args): Parameters<StellarPayCommitArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.stellar_pay_commit_impl(args, None).await
    }

    /// Inner implementation of `stellar_pay_commit`.
    ///
    /// Separated from the public tool handler so the toolset-gated path
    /// (`invoke_stellar_pay_commit_toolset_gated`) can supply a forced
    /// `DispatchOutcome::RequireApproval` override.
    ///
    /// When `forced_dispatch_outcome` is `Some(outcome)`, the supplied outcome
    /// replaces the policy-engine result AFTER the chain_id check still runs via
    /// `dispatch_gate`.  The `Allow` no-op shortcut in `verify_attestation_gate`
    /// is therefore bypassed unconditionally for toolset-routed
    /// payments, making per-action approval cryptographically enforced regardless
    /// of what the policy engine returns.
    ///
    /// When `forced_dispatch_outcome` is `None`, the behaviour is identical to
    /// the original public handler (policy-engine outcome drives attestation gate).
    ///
    /// # Security
    ///
    /// The forced override is the load-bearing per-action-approval mechanism.
    /// Do NOT pass `None` from the toolset-gated routing arm.
    #[allow(clippy::too_many_lines)]
    pub(crate) async fn stellar_pay_commit_impl(
        &self,
        args: StellarPayCommitArgs,
        forced_dispatch_outcome: Option<super::common::DispatchOutcome>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        // ── Re-derive authoritative args from HMAC-bound envelope_xdr ────────
        //
        // The policy engine MUST evaluate the fields that are actually encoded
        // in the nonce-bound XDR envelope — not the caller-supplied args.  An
        // attacker who mutates args between simulate and commit would otherwise
        // subvert the policy decision even though the HMAC + divergence checks
        // catch the tampered envelope later.
        //
        // Failure modes:
        // - XDR decode failure → `simulation.divergence` (covers base64 errors,
        //   malformed XDR, wrong op count, op-kind mismatch).
        // - `Memo::Hash` / `Memo::Return` → decode succeeds with `memo: null`.
        //   A tampered Hash memo XDR is caught by the envelope-rebuild divergence
        //   check below instead (the re-built envelope uses `Memo::None`,
        //   differing from the Hash-memo XDR).
        //
        // The `chain_id` field is not encoded in XDR; it is injected from
        // `args.chain_id` after the decode.  The CAIP-2 check in dispatch_gate
        // validates it against the profile.
        let mut authoritative_args =
            decode_authoritative_args(&args.envelope_xdr, "stellar_pay_commit").map_err(|e| {
                tracing::debug!(
                    error = %e,
                    tool = "stellar_pay_commit",
                    "envelope_xdr re-derivation failed; returning simulation.divergence"
                );
                rmcp::ErrorData::internal_error(
                    format!("simulation.divergence: envelope_xdr re-derivation failed: {e}"),
                    None,
                )
            })?;
        // Inject chain_id (not XDR-encoded; validated by CAIP-2 check in
        // dispatch_gate step 3).
        authoritative_args["chain_id"] = serde_json::Value::String(args.chain_id.clone());

        // ── Dispatch gate (uses authoritative args, not caller args) ─────────
        // destructive_hint = true → engine evaluates per profile.policy.engine;
        // Noop refuses on mainnet, V1 evaluates typed criteria.
        //
        // When `forced_dispatch_outcome` is Some, the caller (toolset-gated path)
        // has already computed a RequireApproval outcome that MUST be used
        // instead of the policy-engine result.  We still call dispatch_gate to
        // preserve the chain_id validation and Deny arm — but if
        // forced_dispatch_outcome overrides Allow, the allow no-op in
        // verify_attestation_gate is bypassed.
        let dispatch_outcome = match forced_dispatch_outcome {
            Some(forced) => {
                // Still run dispatch_gate for chain_id validation + Deny check;
                // override Allow with the forced outcome if the gate does not deny.
                match self
                    .dispatch_gate("stellar_pay_commit", &authoritative_args, &args.chain_id)
                    .await?
                {
                    super::common::DispatchOutcome::Allow => {
                        // Override: policy said Allow but toolset-gated path forces RequireApproval.
                        tracing::debug!(
                            tool = "stellar_pay_commit",
                            "toolset_gated: overriding DispatchOutcome::Allow → forced RequireApproval"
                        );
                        forced
                    }
                    // Deny and RequireApproval from the engine are honoured as-is.
                    other => other,
                }
            }
            None => {
                // Normal path: use the policy-engine outcome directly.
                self.dispatch_gate("stellar_pay_commit", &authoritative_args, &args.chain_id)
                    .await?
            }
        };

        // ── Validate G-strkeys ────────────────────────────────────────────────
        if let Err(err) = stellar_strkey::ed25519::PublicKey::from_string(&args.source) {
            return Err(rmcp::ErrorData::invalid_params(
                format!("invalid source (expected G-strkey): {err}"),
                None,
            ));
        }
        if let Err(err) = stellar_strkey::ed25519::PublicKey::from_string(&args.destination) {
            return Err(rmcp::ErrorData::invalid_params(
                format!("invalid destination (expected G-strkey): {err}"),
                None,
            ));
        }

        // ── Attestation verification gate ────────────────────────────────────
        //
        // Placed BEFORE nonce parse and RPC fetch to:
        //   (a) Ensure the attestation gate fires before nonce HMAC+replay.
        //   (b) Avoid expensive RPC/nonce-HMAC operations when the attestation
        //       is absent or forged (fail-fast principle).
        //   (c) Make toolset-gated tests practical: the `forced_dispatch_outcome`
        //       override causes this gate to ALWAYS run for toolset-routed payments
        //       regardless of policy, so tests can verify the gate fires without
        //       needing a live RPC.
        //
        // Ordering note: `stellar_create_account_commit` runs the gate AFTER its
        // high-value cross-check (there is no toolset-gated variant to test without
        // RPC, so no motivation to hoist it above that work).  The ordering
        // invariant is satisfied in both tools: the gate fires before nonce
        // HMAC+replay either way.
        //
        // This is a no-op when `dispatch_outcome` is `DispatchOutcome::Allow`.
        // For the toolset-gated path, `forced_dispatch_outcome = Some(RequireApproval)`
        // makes it ALWAYS active.
        verify_attestation_gate(
            self,
            &dispatch_outcome,
            &args.envelope_xdr,
            args.approval_nonce.as_deref(),
            args.approval_attestation.as_deref(),
            "stellar_pay_commit",
        )
        .await?;

        // ── Decode nonce — map parse error to nonce.expired (indistinguishability) ──
        let nonce = match stellar_agent_nonce::Nonce::from_base64(&args.nonce) {
            Ok(n) => n,
            Err(_) => {
                return Err(rmcp::ErrorData::internal_error(
                    "nonce.expired: nonce parse failed (re-simulate to obtain a fresh nonce)",
                    None,
                ));
            }
        };

        // ── Parse asset ───────────────────────────────────────────────────────
        let asset = match Asset::parse(&args.asset) {
            Ok(a) => a,
            Err(err) => {
                return Err(rmcp::ErrorData::invalid_params(
                    format!("invalid asset: {}", err.code()),
                    None,
                ));
            }
        };
        let payment_amount = resolve_payment_amount(args.amount.clone(), args.amount_in_stroops)?;

        // ── Parse memo ────────────────────────────────────────────────────────
        let memo = match parse_memo_fields(
            args.memo_text.as_ref().map(McpMemoTextArgument::as_str),
            args.memo_id,
            args.memo_hash_hex.as_deref(),
            args.memo_return_hex.as_deref(),
        ) {
            Ok(m) => m,
            Err(err) => return Err(commit_path_error_data(err)),
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
        // `Account::increment_sequence_number`; an explicit +1 produces
        // CURRENT+2 → TxBadSeq.

        let total_fee_from_envelope = authoritative_args
            .get("total_fee_stroops")
            .and_then(serde_json::Value::as_u64)
            .and_then(|fee| u32::try_from(fee).ok())
            .ok_or_else(|| {
                rmcp::ErrorData::internal_error(
                    "simulation.divergence: envelope_xdr did not contain a valid fee",
                    None,
                )
            })?;
        let fee_per_op_stroops = total_fee_from_envelope
            .checked_div(CLASSIC_SINGLE_OPERATION_COUNT)
            .ok_or_else(|| {
                rmcp::ErrorData::internal_error("internal_error: operation count is zero", None)
            })?;
        // Capture the amount before the primary rebuild consumes it; the copy
        // is also used by the oracle rebuild closure (if cross-check fires).
        let payment_amount_for_oracle = payment_amount;
        // SAFETY-MIRROR: this builder configuration MUST match the oracle-rebuild
        // closure below exactly.  Any change here that is not mirrored in the
        // oracle closure below silently breaks the high-value cross-check.
        // See also create_account.rs primary rebuild (mirrored pair).
        let mut builder = ClassicOpBuilder::new(
            &args.source,
            source_sequence,
            &self.profile.network_passphrase,
            fee_per_op_stroops,
        );
        if let Err(err) = builder.payment(&args.destination, payment_amount, &asset) {
            return Err(commit_path_error_data(err));
        }
        if let Err(err) = builder.memo(&memo) {
            return Err(commit_path_error_data(err));
        }
        let rebuilt_envelope_xdr = match builder.build() {
            Ok(xdr) => xdr,
            Err(err) => return Err(commit_path_error_data(err)),
        };

        // ── Envelope divergence check ────────────────────────────────────────
        if rebuilt_envelope_xdr != args.envelope_xdr {
            return Err(rmcp::ErrorData::internal_error(
                "simulation.divergence: re-built envelope does not match presented envelope_xdr; \
                 re-simulate to obtain a fresh envelope",
                None,
            ));
        }

        // ── High-value independent-RPC cross-check ───────────────────────────
        //
        // For native-XLM payments at or above `profile.effective_usd_threshold()`,
        // re-builds the envelope against `profile.oracle_provider_url` and asserts
        // byte-identity with the primary rebuild.  A compromised primary RPC
        // returning stale account state would produce a divergent envelope here.
        //
        // Skip conditions: non-native asset, value below threshold, or
        // `oracle_provider_url` unset (fail-open with tracing::warn!).
        {
            let amount_stroops: i64 = authoritative_args
                .get("amount_stroops")
                .and_then(crate::tools::amount_wire::value_as_stroops_i64)
                .ok_or_else(|| {
                    rmcp::ErrorData::internal_error(
                        "simulation.divergence: authoritative_args missing required \
                         `amount_stroops` field",
                        None,
                    )
                })?;
            let asset_is_native = matches!(asset, Asset::Native);
            // Capture all builder inputs for the oracle re-build closure.
            let oracle_source = args.source.clone();
            let oracle_destination = args.destination.clone();
            let oracle_asset = asset.clone();
            let oracle_memo = memo.clone();
            let oracle_network_passphrase = self.profile.network_passphrase.clone();
            // Use the pre-captured payment amount (cloned before primary rebuild consumed it).
            let oracle_payment_amount = payment_amount_for_oracle;

            high_value_cross_check(
                &self.profile,
                &rebuilt_envelope_xdr,
                &args.source,
                asset_is_native,
                amount_stroops,
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
                        .payment(&oracle_destination, oracle_payment_amount, &oracle_asset)
                        .map_err(commit_path_error_data)?;
                    oracle_builder
                        .memo(&oracle_memo)
                        .map_err(commit_path_error_data)?;
                    oracle_builder.build().map_err(commit_path_error_data)
                },
                "stellar_pay_commit",
            )
            .await?;
        }

        // ── Nonce verification + replay window ────────────────────────────────
        //
        // Note: verify_attestation_gate runs BEFORE nonce parse + RPC fetch
        // (see its call site above, just after G-strkey validation) to support
        // toolset-gated tests that bypass the RPC.  The ordering remains correct:
        // the attestation gate still fires before this nonce HMAC+replay step.
        //
        // Running AFTER the attestation gate means the nonce is only consumed
        // when the approval has been verified.  This prevents replay-window
        // pollution by unauthenticated callers.
        let now_ms = now_unix_ms()
            .map_err(|e| rmcp::ErrorData::internal_error(format!("clock_error: {e}"), None))?;

        // Delegates to `commit_envelope_and_verify_nonce` in `tools/common.rs`.
        // Same split-phase pattern as stellar_create_account_commit; all wire
        // codes and indistinguishability invariants are preserved inside the
        // shared helper.
        commit_envelope_and_verify_nonce(
            &self.nonce_mint,
            &self.replay_window,
            &nonce,
            &args.envelope_xdr,
            args.expires_at_unix_ms,
            &args.chain_id,
            "stellar_pay_commit",
            now_ms,
        )
        .await?;

        // ── Load signer handle from keyring ───────────────────────────────────
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

        // ── Wallet unlock for mlock-protected signing window ─────────────────
        //
        // `KeyringSignHandle` intentionally does not expose seed bytes — its
        // design loads the secret per-call within `sign_tx_payload` and zeroes
        // it immediately (per-call-handle discipline).  There is therefore no
        // seed bytes to pass to `Wallet::unlock` at this integration stage.  The
        // actual signing still runs via `handle`.
        //
        // Deeper integration would refactor the signing pipeline so the keyring
        // secret is loaded once into a `Wallet`-held `LockedSeed` and then
        // consumed by `attach_signature`, making the mlock-protected region
        // genuinely cover the signing input.  This requires a new
        // `signer_from_wallet(&Wallet)` entry point in stellar-agent-network.
        //
        // For now, log the mlock posture from the profile so the operator has
        // visibility into what would happen when the deeper integration lands.
        {
            let mlock_req = self.profile.wallet.mlock_required;
            tracing::debug!(
                profile = %self.profile_name_for_approval(),
                mlock_required = ?mlock_req,
                "stellar_pay_commit: Wallet::unlock deferred pending signer-from-wallet \
                 integration; signing proceeds via KeyringSignHandle"
            );
        }
        // Declare _wallet_guard as None for now so the explicit drop below
        // compiles and the audit trail is obvious.
        let _wallet_guard: Option<Wallet> = None;

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

        // Explicit dispose of wallet guard after signing (RAII also fires on
        // scope exit, but explicit is clearer for auditability).
        drop(_wallet_guard);

        let nonce_id_prefix = nonce_id_prefix(&nonce);

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
                tracing::info!(
                    tool = "stellar_pay_commit",
                    chain = %args.chain_id,
                    nonce_id = %nonce_id_prefix,
                    decision = "committed",
                    "stellar_pay_commit: tx submitted"
                );

                // Remove the consumed approval entry from the store so it
                // cannot be replayed.  This is best-effort: a failure to remove
                // (e.g. store lock contention, I/O error) does NOT abort the
                // response — the transaction is already on-chain.  Log a warn so
                // the operator can clean up via `stellar-agent approve gc`.
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
                                    "stellar_pay_commit: approval entry remove failed after \
                                     successful submit; entry will expire via gc"
                                );
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                "stellar_pay_commit: approval store open failed during \
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
    /// Invoke `stellar_pay` (simulate step) by value, bypassing the rmcp
    /// transport layer.
    ///
    /// Used by the toolset-invocation routing path (`tools/toolsets.rs`).
    ///
    /// # Errors
    ///
    /// Same as [`WalletServer::stellar_pay`].
    pub(crate) async fn invoke_stellar_pay(
        &self,
        args: StellarPayArgs,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.stellar_pay(Parameters(args)).await
    }

    /// Invokes `stellar_pay_commit` for a toolset-gated signing-adjacent path
    /// with the per-action `PaymentSimulated` approval FORCED ON unconditionally.
    ///
    /// Unlike direct `stellar_pay_commit` which is a no-op when policy returns
    /// `Allow`, this wrapper FORCES the `RequireApproval` path by:
    ///
    /// 1. Running `decode_authoritative_args` on `args.envelope_xdr`.
    /// 2. If `args.approval_nonce` and `args.approval_attestation` are absent
    ///    (i.e., policy returned `Allow` and no approval was queued) → synthesise
    ///    a `PaymentSimulated` `PendingApproval` queue entry and return
    ///    `policy.approval_required` so the operator approves via
    ///    `stellar-agent approve --id <nonce>`.  The approval_nonce is surfaced
    ///    in the error payload.
    /// 3. If approval fields ARE present → delegate to the normal `stellar_pay_commit`
    ///    handler which will verify the attestation.
    ///
    /// # Security
    ///
    /// A `DispatchOutcome::Allow` from the policy engine is NEVER a shortcut
    /// for toolset-gated payments.  The per-action approval ALWAYS fires.
    pub(crate) async fn invoke_stellar_pay_commit_toolset_gated(
        &self,
        args: StellarPayCommitArgs,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        use super::common::approval_required_indistinguishable;
        use stellar_agent_core::approval::{
            DEFAULT_TTL_MS, PendingApproval, process_uid_for_attestation,
        };
        use stellar_agent_core::profile::schema::default_approval_dir;

        // ── Forced approval check ─────────────────────────────────────────────
        //
        // If approval_nonce + approval_attestation are ABSENT, the policy engine
        // returned Allow (no approval was queued yet).  We MUST force the
        // RequireApproval path: synthesise a PaymentSimulated pending approval,
        // persist it, and return policy.approval_required.
        //
        // If they ARE present, delegate to the normal stellar_pay_commit flow
        // which will verify the attestation (the approval was cleared by
        // `stellar-agent approve --id <nonce>`).
        // approval_nonce + approval_attestation are expected to come from a
        // previously-queued and operator-approved PaymentSimulated pending
        // approval (synthesised by the `!has_approval` branch below on the prior
        // invocation).  We MUST verify them against the stored entry — we CANNOT
        // delegate to `stellar_pay_commit` with the normal dispatch flow because
        // `verify_attestation_gate` is a no-op when the policy engine returns Allow.
        //
        // `stellar_pay_commit_impl` accepts a `forced_dispatch_outcome` parameter.
        // When `Some(RequireApproval(...))` is supplied, it overrides any `Allow`
        // result from the policy engine so that `verify_attestation_gate` ALWAYS
        // runs the cryptographic HMAC check regardless of policy.  This is the
        // load-bearing mechanism; field-presence alone CANNOT substitute.
        let has_approval = args.approval_nonce.is_some() && args.approval_attestation.is_some();

        if !has_approval {
            // Force per-action approval unconditionally.
            // Synthesise a PaymentSimulated pending approval from the authoritative
            // envelope params.
            let authoritative = decode_authoritative_args(&args.envelope_xdr, "stellar_pay_commit")
                .map_err(|e| {
                    rmcp::ErrorData::internal_error(
                        format!("simulation.divergence: toolset_gated envelope_xdr decode: {e}"),
                        None,
                    )
                })?;

            let summary_to = authoritative
                .get("destination")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();
            let summary_amount_stroops = authoritative
                .get("amount_stroops")
                .and_then(crate::tools::amount_wire::value_as_stroops_i64)
                .unwrap_or(0_i64);
            let summary_asset = authoritative
                .get("asset")
                .and_then(|v| v.as_str())
                .unwrap_or("XLM")
                .to_owned();

            // Decode envelope XDR bytes for SHA-256.
            use base64::Engine as _;
            let envelope_xdr_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(&args.envelope_xdr)
                .or_else(|_| base64::engine::general_purpose::STANDARD.decode(&args.envelope_xdr))
                .map_err(|e| {
                    rmcp::ErrorData::internal_error(
                        format!("simulation.divergence: base64 decode: {e}"),
                        None,
                    )
                })?;

            let uid = process_uid_for_attestation().map_err(|e| {
                rmcp::ErrorData::internal_error(format!("approval.uid_unavailable: {e}"), None)
            })?;

            let simulated_fee = authoritative
                .get("total_fee_stroops")
                .and_then(|v| v.as_u64())
                .and_then(|f| u32::try_from(f).ok())
                .unwrap_or(100_u32);
            let simulated_seq = authoritative
                .get("sequence_number")
                .and_then(|v| v.as_i64())
                .unwrap_or(0_i64);

            let pending = PendingApproval::new_payment_pending(
                args.envelope_xdr.clone(),
                &envelope_xdr_bytes,
                summary_to,
                summary_amount_stroops,
                summary_asset,
                args.memo_text.as_ref().map(|m| m.as_str().to_owned()),
                simulated_fee,
                simulated_seq,
                uid,
                DEFAULT_TTL_MS,
            )
            .map_err(|e| {
                rmcp::ErrorData::internal_error(format!("toolset.gated_approval_create: {e}"), None)
            })?;

            let approval_nonce = pending.approval_nonce.clone();

            // Persist the pending approval.
            #[cfg(any(test, feature = "test-helpers"))]
            let approvals_dir = {
                if let Some(ref override_dir) = self.approval_dir_override {
                    override_dir.clone()
                } else {
                    default_approval_dir().map_err(|e| {
                        rmcp::ErrorData::internal_error(format!("approval.dir_error: {e}"), None)
                    })?
                }
            };
            #[cfg(not(any(test, feature = "test-helpers")))]
            let approvals_dir = default_approval_dir().map_err(|e| {
                rmcp::ErrorData::internal_error(format!("approval.dir_error: {e}"), None)
            })?;

            let profile_name = self.profile_name_for_approval();
            let store_path = approvals_dir.join(format!("{profile_name}.toml"));
            let mut store =
                open_with_retry(&store_path, DEFAULT_RETRY_ATTEMPTS, DEFAULT_RETRY_BACKOFF)
                    .map_err(|e| {
                        rmcp::ErrorData::internal_error(format!("approval.store_open: {e}"), None)
                    })?;

            let now_ms = now_unix_ms().map_err(|e| {
                rmcp::ErrorData::internal_error(
                    format!("approval.store_insert: current time unavailable: {e}"),
                    None,
                )
            })?;
            store.insert(pending, now_ms).map_err(|e| {
                rmcp::ErrorData::internal_error(format!("approval.store_insert: {e}"), None)
            })?;

            tracing::debug!(
                nonce = %approval_nonce,
                "toolset_gated: forced per-action approval queued"
            );

            // Return indistinguishable approval_required (the nonce is in the
            // tracing log for operator forensics; not in the wire error).
            return Err(approval_required_indistinguishable());
        }

        // Approval fields present → delegate to the commit path with FORCED
        // RequireApproval override.
        //
        // The forced outcome is constructed from the caller-supplied approval_nonce.
        // `stellar_pay_commit_impl` with this override:
        //   1. Still runs dispatch_gate for chain_id validation + Deny check.
        //   2. Replaces any Allow result with the forced RequireApproval.
        //   3. Calls verify_attestation_gate with the RequireApproval outcome,
        //      which CRYPTOGRAPHICALLY verifies the HMAC attestation against the
        //      stored PaymentSimulated pending entry — no-op shortcut bypassed.
        //
        // This is NOT policy-conditional: the HMAC check ALWAYS runs for
        // toolset-routed payments, regardless of what the policy engine returns.
        // INVARIANT: `has_approval` is `true` here — we entered this branch only
        // when both `approval_nonce` and `approval_attestation` are `Some` (line
        // immediately above this block checks `has_approval`).  The
        // `unwrap_or_else` fallback is therefore unreachable; use `expect` to
        // make the invariant explicit and catch future refactoring mistakes.
        #[allow(
            clippy::expect_used,
            reason = "invariant-guarded: has_approval is true at this point, so approval_nonce is Some"
        )]
        let forced_nonce = args
            .approval_nonce
            .clone()
            .expect("approval_nonce is Some because has_approval is true at this point");
        let forced_outcome = super::common::DispatchOutcome::RequireApproval(
            stellar_agent_core::policy::ApprovalRequest::new(forced_nonce, 86_400),
        );
        self.stellar_pay_commit_impl(args, Some(forced_outcome))
            .await
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test helpers
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(any(test, feature = "test-helpers"))]
impl WalletServer {
    /// Calls `stellar_pay` (simulate step) with the given args, bypassing the
    /// rmcp transport.
    ///
    /// Integration-test entry point for handler-level checks.
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Feature gate
    ///
    /// Gated on the `test-helpers` feature or `#[cfg(test)]`.
    #[doc(hidden)]
    pub async fn call_stellar_pay(
        &self,
        args: StellarPayArgs,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.stellar_pay(Parameters(args)).await
    }

    /// Calls `stellar_pay_commit` (commit step) with the given args, bypassing
    /// the rmcp transport.
    ///
    /// Integration-test entry point for handler-level checks.
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Feature gate
    ///
    /// Gated on the `test-helpers` feature or `#[cfg(test)]`.
    #[doc(hidden)]
    pub async fn call_stellar_pay_commit(
        &self,
        args: StellarPayCommitArgs,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.stellar_pay_commit(Parameters(args)).await
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::panic,
        reason = "test-only assertions use panic for explicit failure messages"
    )]

    use super::*;
    use stellar_xdr::{Hash, StringM};

    #[test]
    fn memo_text_valid_utf8_round_trips() -> Result<(), stellar_xdr::Error> {
        let memo = Memo::Text(StringM::<28>::try_from("hello stellar")?);

        assert_eq!(memo_summary(&memo), Some("hello stellar".to_owned()));
        assert_eq!(
            memo_json(&memo),
            json!({ "type": "text", "value": "hello stellar" })
        );
        assert_eq!(memo_summary_for_json(&memo), json!("hello stellar"));

        Ok(())
    }

    #[test]
    fn memo_text_invalid_utf8_renders_invalid_utf8_marker() -> Result<(), stellar_xdr::Error> {
        let memo = Memo::Text(StringM::<28>::try_from(vec![0xff, 0xfe])?);

        assert_eq!(memo_summary(&memo), Some("<invalid-utf8>".to_owned()));
        assert_eq!(
            memo_json(&memo),
            json!({ "type": "text", "value": "<invalid-utf8>" })
        );
        assert_eq!(memo_summary_for_json(&memo), json!("<invalid-utf8>"));

        Ok(())
    }

    #[test]
    fn memo_hash_round_trips() {
        let memo = Memo::Hash(Hash([0xab; 32]));
        let expected_hex = "ab".repeat(32);

        assert_eq!(memo_summary(&memo), Some("<binary memo>".to_owned()));
        assert_eq!(
            memo_json(&memo),
            json!({ "type": "hash", "value": expected_hex })
        );
        assert_eq!(memo_summary_for_json(&memo), json!(expected_hex));
    }

    #[test]
    fn memo_return_round_trips() {
        let memo = Memo::Return(Hash([0xcd; 32]));
        let expected_hex = "cd".repeat(32);

        assert_eq!(memo_summary(&memo), Some("<binary memo>".to_owned()));
        assert_eq!(
            memo_json(&memo),
            json!({ "type": "return", "value": expected_hex })
        );
        assert_eq!(memo_summary_for_json(&memo), json!(expected_hex));
    }

    #[test]
    fn memo_none_renders_empty() {
        let memo = Memo::None;

        assert_eq!(memo_summary(&memo), None);
        assert_eq!(memo_json(&memo), json!({ "type": "none" }));
        assert_eq!(memo_summary_for_json(&memo), serde_json::Value::Null);
    }

    #[test]
    fn resolve_payment_amount_rejects_both_forms() {
        let amount = match serde_json::from_str(r#""1 XLM""#) {
            Ok(amount) => amount,
            Err(err) => panic!("valid amount must parse: {err}"),
        };
        let err = match resolve_payment_amount(Some(amount), Some("1".to_owned())) {
            Ok(amount) => panic!("both amount forms must reject, got {amount}"),
            Err(err) => err,
        };

        assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
        assert!(err.message.contains("mutually exclusive"));
    }

    #[test]
    fn resolve_payment_amount_rejects_missing_forms() {
        let err = match resolve_payment_amount(None, None) {
            Ok(amount) => panic!("missing amount forms must reject, got {amount}"),
            Err(err) => err,
        };

        assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
        assert!(err.message.contains("required"));
    }

    #[test]
    fn resolve_payment_amount_accepts_stroops() {
        let amount = match resolve_payment_amount(None, Some("123".to_owned())) {
            Ok(amount) => amount,
            Err(err) => panic!("stroops amount must parse: {err}"),
        };

        assert_eq!(amount.as_stroops(), 123);
    }

    #[test]
    fn resolve_payment_amount_accepts_stroops_above_f64_precision_limit() {
        // 2^53 + 1: the first integer an f64-backed JSON number cannot
        // represent exactly. The decimal-string field must round-trip it
        // byte-for-byte.
        let amount = match resolve_payment_amount(None, Some("9007199254740993".to_owned())) {
            Ok(amount) => amount,
            Err(err) => panic!("stroops amount must parse: {err}"),
        };

        assert_eq!(amount.as_stroops(), 9_007_199_254_740_993_i64);
    }

    #[test]
    fn resolve_payment_amount_rejects_zero_stroops() {
        let err = match resolve_payment_amount(None, Some("0".to_owned())) {
            Ok(amount) => panic!("zero stroops must reject, got {amount}"),
            Err(err) => err,
        };

        assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
        assert!(err.message.contains("positive"));
    }

    #[test]
    fn resolve_payment_amount_rejects_u64_overflow() {
        let err = match resolve_payment_amount(None, Some(u64::MAX.to_string())) {
            Ok(amount) => panic!("u64 overflow must reject, got {amount}"),
            Err(err) => err,
        };

        assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
        assert!(err.message.contains("i64 max"));
    }

    #[test]
    fn resolve_payment_amount_rejects_negative_stroops() {
        let err = match resolve_payment_amount(None, Some("-5".to_owned())) {
            Ok(amount) => panic!("negative stroops must reject, got {amount}"),
            Err(err) => err,
        };

        assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
    }

    #[test]
    fn resolve_payment_amount_rejects_malformed_decimal_string() {
        let err = match resolve_payment_amount(None, Some("not-a-number".to_owned())) {
            Ok(amount) => panic!("malformed stroops string must reject, got {amount}"),
            Err(err) => err,
        };

        assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
    }
}
