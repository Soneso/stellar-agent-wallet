//! Shared constants, helpers, and infrastructure for MCP tool handlers.
//!
//! This module contains items used by two or more tool implementation modules:
//! nonce TTL and fee constants, the `ToolCatalogueAdapter` bridge, the
//! link-time tool-registry builder, and the two centralised dispatch helpers:
//!
//! - [`WalletServer::dispatch_gate`] — the 3-step preamble shared by
//!   every MCP tool handler (registry lookup → policy_engine.evaluate →
//!   chain_id validation).  Returns [`DispatchOutcome`] so simulate handlers
//!   can observe `Decision::RequireApproval` and persist the pending-approval
//!   entry.
//! - [`commit_envelope_and_verify_nonce`] — the nonce HMAC verify + replay-window
//!   record block shared by every `*_commit` MCP tool handler.
//! - [`approval_required_indistinguishable`] — the uniform wire error for
//!   all attestation-gate failure modes (absent, forged, expired, hash-mismatch).

use std::{collections::HashMap, sync::Arc};

use rmcp::ErrorData;
use serde_json::Value;
use stellar_agent_core::observability::redact_strkey_first5_last5 as redact_account_id_value;
use stellar_agent_core::policy::{
    ApprovalRequest, BuildRegistryError, Decision, DenyReason, McpToolRegistration, ToolDescriptor,
};
use stellar_agent_core::profile::caip2::validate_chain_id_matches_profile;
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_nonce::{
    Nonce, NonceError, NonceMint, NonceVerifyHmacOnlyRequest, ReplayWindow, ToolCatalogue,
};
use stellar_xdr::Hash;
use tokio::sync::Mutex as TokioMutex;

use crate::server::WalletServer;

// ─────────────────────────────────────────────────────────────────────────────
// DispatchOutcome — returned by dispatch_gate
// ─────────────────────────────────────────────────────────────────────────────

/// Outcome returned by [`WalletServer::dispatch_gate`].
///
/// `dispatch_gate` returns this type instead of `()` so simulate handlers can
/// observe `Decision::RequireApproval` and persist the pending-approval entry
/// before returning the MCP response.
///
/// Commit handlers map `RequireApproval` to an attestation-verification block.
///
/// Single-shot sign tools have no simulate→commit split and therefore cannot
/// honour the two-phase approval flow. Any single-shot tool that receives
/// `RequireApproval` MUST reject the call fail-closed via
/// [`single_shot_require_approval_error`] rather than silently proceeding to
/// sign.
#[must_use]
#[derive(Debug)]
pub(crate) enum DispatchOutcome {
    /// Policy engine returned `Decision::Allow`; proceed with the tool logic.
    Allow,
    /// Policy engine returned `Decision::RequireApproval`; the simulate handler
    /// must persist a `PendingApproval` entry and embed `approval_nonce` in the
    /// response.  The commit handler must verify the attestation blob before
    /// proceeding.
    RequireApproval(ApprovalRequest),
}

// ─────────────────────────────────────────────────────────────────────────────
// Default nonce TTL (30 s–5 min window; 120 s chosen)
// ─────────────────────────────────────────────────────────────────────────────

/// Default TTL for nonces minted by simulate-step tools (2 minutes).
///
/// The value is within the `[MIN_TTL_MS, MAX_TTL_MS]` window (30 s lower bound,
/// 5 min upper bound).  Two minutes covers normal agent reasoning latency
/// without providing an attacker a long window.
pub(crate) const DEFAULT_NONCE_TTL_MS: u64 = 120_000;

// Compile-time assertion that DEFAULT_NONCE_TTL_MS stays within the
// NonceMint-enforced bounds.  Prevents drift where the constant is changed
// without checking the runtime-enforced bounds, which would cause every nonce
// mint to fail at startup with TtlTooShort / TtlExceeded.
const _: () = {
    assert!(
        DEFAULT_NONCE_TTL_MS >= NonceMint::MIN_TTL_MS,
        "DEFAULT_NONCE_TTL_MS must be >= NonceMint::MIN_TTL_MS"
    );
    assert!(
        DEFAULT_NONCE_TTL_MS <= NonceMint::MAX_TTL_MS,
        "DEFAULT_NONCE_TTL_MS must be <= NonceMint::MAX_TTL_MS"
    );
};

// ─────────────────────────────────────────────────────────────────────────────
// Submit timeout for commit steps (conservative; classic ops settle fast)
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum time to wait for a submitted transaction to confirm.
pub(crate) const SUBMIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

// ─────────────────────────────────────────────────────────────────────────────
// Oracle RPC timeout — independent-RPC cross-check
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum time allowed for the independent-RPC (oracle) rebuild call in
/// [`high_value_cross_check`].
///
/// A slow or unresponsive oracle would otherwise block the user-visible commit
/// for an unbounded duration.  Exceeding this limit is treated as
/// `simulation.divergence` — the same as a rebuild failure — which is the
/// fail-safe response: the wallet cannot confirm the envelope is safe to commit
/// without a valid oracle comparison.
///
/// 15 s is a conservative upper bound for a hosted Stellar RPC endpoint; it is
/// independent of `SUBMIT_TIMEOUT` (which governs transaction confirmation, not
/// the pre-commit cross-check).
///
/// Operator note: if `profile.submit_timeout_seconds` is smaller than 15, the
/// oracle timeout is not automatically reduced — the two timeouts have different
/// semantics.
pub(crate) const ORACLE_RPC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Resolves the submit timeout for a profile, falling back to the documented
/// 60-second default when the profile omits an override.
#[must_use]
pub(crate) fn submit_timeout(profile: &Profile) -> std::time::Duration {
    profile
        .submit_timeout_seconds
        .map(std::time::Duration::from_secs)
        .unwrap_or(SUBMIT_TIMEOUT)
}

// ─────────────────────────────────────────────────────────────────────────────
// APPROVAL_TTL_MS — 24-hour pending-approval TTL
// ─────────────────────────────────────────────────────────────────────────────

/// Default TTL for pending approvals persisted by simulate handlers: 24 hours.
///
/// An approval entry written to `~/.local/state/stellar-agent/approvals/<profile>.toml`
/// is valid for 24 hours from the time of the simulate call.  Entries older
/// than this are treated as expired and return `policy.approval_required` at
/// the commit boundary (per the indistinguishability rule).
///
/// Also re-exported by [`stellar_agent_core::approval::store::DEFAULT_TTL_MS`].
/// The constant is defined here (adjacent to `DEFAULT_NONCE_TTL_MS`) for
/// discoverability by tool-handler authors.
pub(crate) const APPROVAL_TTL_MS: u64 = 86_400_000; // 24 h

/// Returns the first 8 base64 characters of a nonce for use as a tracing
/// correlation prefix. Saturating: if the base64 encoding is shorter than 8
/// characters, the full string is returned.
///
/// Used in tracing spans where the full nonce is too long to display but a
/// stable prefix is useful for correlating log lines.
#[must_use]
pub(crate) fn nonce_id_prefix(nonce: &Nonce) -> String {
    let b64 = nonce.to_base64();
    b64[..b64.len().min(8)].to_owned()
}

/// Renders a Stellar `Hash` byte array as a lowercase-hex string.
///
/// 32 bytes -> 64-character lowercase-hex (no `0x` prefix, no separators).
/// Used for memo-hash and memo-return wire rendering.
#[must_use]
pub(crate) fn hash_to_lower_hex(h: &Hash) -> String {
    h.0.iter().map(|b| format!("{b:02x}")).collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Classic-op fee constant — re-exported from stellar-agent-core
// ─────────────────────────────────────────────────────────────────────────────

// DEFAULT_CLASSIC_FEE_STROOPS lives in stellar_agent_core::protocol_consts;
// re-export here so existing `crate::tools::common::DEFAULT_CLASSIC_FEE_STROOPS`
// call sites compile without change.
pub(crate) use stellar_agent_core::DEFAULT_CLASSIC_FEE_STROOPS;

/// Current classic MCP handlers build one-operation transactions.
pub(crate) const CLASSIC_SINGLE_OPERATION_COUNT: u32 = 1;

/// Resolves the per-operation classic fee for MCP classic-operation handlers.
#[must_use]
pub(crate) fn resolve_classic_fee_per_op_stroops(profile: &Profile) -> u32 {
    profile
        .classic_fee_per_op_stroops
        .unwrap_or(DEFAULT_CLASSIC_FEE_STROOPS)
}

/// Computes the total classic transaction fee from per-operation fee semantics.
///
/// Stellar builders accept a per-operation base fee; the XDR `Transaction.fee`
/// field and MCP wire summaries represent the total transaction fee.
pub(crate) fn total_classic_fee_stroops(
    per_op_stroops: u32,
    operation_count: u32,
) -> Result<u32, ErrorData> {
    per_op_stroops
        .checked_mul(operation_count)
        .ok_or_else(|| ErrorData::internal_error("internal_error: classic fee overflow", None))
}

/// Enforces the optional profile classic per-operation fee cap.
pub(crate) fn enforce_classic_fee_cap(
    per_op_stroops: u32,
    selected_percentile: &str,
    profile: &Profile,
) -> Result<(), ErrorData> {
    if let Some(cap) = profile.classic_max_fee_per_op_stroops
        && per_op_stroops > cap
    {
        return Err(ErrorData::invalid_params(
            "fees.percentile_exceeds_cap",
            Some(serde_json::json!({
                "selected_fee_per_op_stroops": per_op_stroops,
                "classic_max_fee_per_op_stroops": cap,
                "selected_fee_percentile": selected_percentile,
            })),
        ));
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// ledger_err_result — shared error-envelope helper
// ─────────────────────────────────────────────────────────────────────────────

/// Wraps a [`stellar_agent_core::WalletError`] in an error envelope and returns
/// a `CallToolResult` with `is_error = Some(true)`.
///
/// Deduplicates the four-line error-envelope pattern that appears in every
/// pre-flight failure arm across `create_account.rs` and `pay.rs`.
///
/// # Panics
///
/// Never panics.
pub(crate) fn ledger_err_result(
    err: &stellar_agent_core::WalletError,
) -> rmcp::model::CallToolResult {
    use rmcp::model::{CallToolResult, Content};
    let envelope = redacted_wallet_error_envelope(err);
    let json = envelope
        .to_json_pretty()
        .unwrap_or_else(|_| String::from("{}"));
    let mut result = CallToolResult::success(vec![Content::text(json)]);
    result.is_error = Some(true);
    result
}

/// Wraps a [`stellar_agent_core::WalletError`] in an envelope after applying
/// MCP wire redaction for sibling error variants whose `Display` includes
/// public account identifiers.
///
/// Redacted variants:
///
/// - [`NetworkError::AccountNotFound`] — `account_id` field is a full G-strkey;
///   redacted to first-5-last-5.
/// - [`LedgerError::TrustlineMissing`] — `account` field is a full G-strkey;
///   redacted to first-5-last-5.  `asset` is preserved verbatim (non-secret).
/// - [`LedgerError::DestinationInvalid`] — `destination` field may be a full
///   G-strkey; redacted to first-5-last-5.
///
/// All other variants are rendered verbatim via `Envelope::err`, which uses the
/// error's `Display` implementation.  Those display strings must not contain
/// secret material (see the redaction audit in `error.rs`).
///
/// # Panics
///
/// Never panics.
pub(crate) fn redacted_wallet_error_envelope(
    err: &stellar_agent_core::WalletError,
) -> stellar_agent_core::Envelope<()> {
    use stellar_agent_core::error::{LedgerError, NetworkError};
    match err {
        stellar_agent_core::WalletError::Network(NetworkError::AccountNotFound { account_id }) => {
            stellar_agent_core::Envelope::err_raw(
                err.code(),
                format!(
                    "account '{}' was not found on the network",
                    redact_account_id_value(account_id)
                ),
            )
        }
        stellar_agent_core::WalletError::Ledger(LedgerError::TrustlineMissing {
            account,
            asset,
        }) => stellar_agent_core::Envelope::err_raw(
            err.code(),
            format!(
                "account '{}' is missing a trustline for asset '{asset}'",
                redact_account_id_value(account)
            ),
        ),
        stellar_agent_core::WalletError::Ledger(LedgerError::DestinationInvalid {
            destination,
        }) => stellar_agent_core::Envelope::err_raw(
            err.code(),
            format!(
                "destination '{}' is not a valid destination for this operation",
                redact_account_id_value(destination)
            ),
        ),
        _ => stellar_agent_core::Envelope::err(err),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// decode_payment_required_input — shared x402 PaymentRequirements decode helper
// ─────────────────────────────────────────────────────────────────────────────

/// Decodes a `payment_required` input string to a [`stellar_agent_x402::wire::PaymentRequirements`].
///
/// Tries the crate's canonical base64 decode path first
/// ([`stellar_agent_x402::wire::decode_payment_required`]; RFC 4648 §4 standard
/// alphabet, `JSON.parse`); on error falls back to direct raw-JSON parse.
/// Returns an x402 error if both paths fail.
///
/// Used by `x402_create_payment.rs` and `x402_authenticated_payment.rs`.
///
/// # Errors
///
/// - [`stellar_agent_x402::X402Error::InvalidPaymentRequired`] when both
///   base64+JSON and direct-JSON parsing fail.
///
/// # Panics
///
/// Never panics.
pub(crate) fn decode_payment_required_input(
    input: &str,
) -> Result<stellar_agent_x402::wire::PaymentRequirements, stellar_agent_x402::X402Error> {
    use stellar_agent_x402::wire::decode_payment_required;

    // Try the crate's canonical base64 decode (RFC 4648 §4 standard alphabet).
    if let Ok(parsed) = decode_payment_required(input) {
        return Ok(parsed);
    }

    // Fall back: parse as raw JSON string (caller-supplied unencoded JSON).
    serde_json::from_str::<stellar_agent_x402::wire::PaymentRequirements>(input).map_err(|e| {
        stellar_agent_x402::X402Error::InvalidPaymentRequired {
            detail: format!("not valid base64+JSON or raw JSON PaymentRequirements: {e}"),
        }
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// x402_error_to_tool_result — shared x402 error-envelope helper
// ─────────────────────────────────────────────────────────────────────────────

/// Wraps an [`stellar_agent_x402::X402Error`] in the x402 error envelope and
/// returns a `CallToolResult` with `is_error = Some(true)`.
///
/// The envelope shape `{ "code": "x402.error", "message": "..." }` is the
/// single-sourced wire contract for x402 tool error responses; the `"x402.error"`
/// code string is defined here only, not in any individual tool file.
///
/// Used by `x402_create_payment.rs`, `x402_authenticated_payment.rs`, and
/// `x402_parse_receipt.rs`.
///
/// # Redaction
///
/// `X402Error::Display` carries no secret material (per the `error.rs` audit).
///
/// # Panics
///
/// Never panics.
pub(crate) fn x402_error_to_tool_result(
    err: &stellar_agent_x402::X402Error,
) -> rmcp::model::CallToolResult {
    use rmcp::model::{CallToolResult, Content};
    let resp = serde_json::json!({
        "code": "x402.error",
        "message": err.to_string(),
    });
    let json_str = serde_json::to_string_pretty(&resp).unwrap_or_else(|_| "{}".to_owned());
    let mut result = CallToolResult::success(vec![Content::text(json_str)]);
    result.is_error = Some(true);
    result
}

// ─────────────────────────────────────────────────────────────────────────────
// ToolCatalogueAdapter — bridges tool_registry HashMap to NonceMint::mint
// ─────────────────────────────────────────────────────────────────────────────

/// Adapts the `tool_registry` `HashMap` to the [`ToolCatalogue`] trait.
///
/// `NonceMint::mint` validates the target `tool_name` against the registered
/// catalogue BEFORE engaging key state.  This adapter
/// provides that validation by delegating to the `WalletServer`'s
/// `tool_registry` without coupling the nonce crate to the MCP framework types.
///
/// The adapter is private to this crate; callers interact via the
/// [`ToolCatalogue`] trait object reference passed to `NonceMint::mint`.
///
/// # Design note
///
/// The adapter holds an `Arc<HashMap<&'static str, ToolDescriptor>>` (cheap clone
/// from `WalletServer`) rather than a reference, so it can be constructed inside
/// an async tool handler without lifetime complications.
pub(crate) struct ToolCatalogueAdapter {
    registry: Arc<HashMap<&'static str, ToolDescriptor>>,
}

impl ToolCatalogueAdapter {
    /// Constructs the adapter from the server's shared registry.
    pub(crate) fn new(registry: Arc<HashMap<&'static str, ToolDescriptor>>) -> Self {
        Self { registry }
    }
}

impl ToolCatalogue for ToolCatalogueAdapter {
    fn is_registered(&self, tool_name: &str) -> bool {
        self.registry.contains_key(tool_name)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool registry builder
// ─────────────────────────────────────────────────────────────────────────────

/// Checks a stream of tool registrations for duplicate tool names and returns
/// the corresponding descriptor map.
///
/// This helper is public for integration-test coverage through
/// `stellar_agent_mcp::server`; production callers should use
/// [`build_tool_registry`] so the source remains the distributed `inventory`
/// registry.
///
/// # Errors
///
/// Returns [`BuildRegistryError::DuplicateRegistration`] when two
/// `McpToolRegistration` values with the same `name` are present.
#[doc(hidden)]
pub fn check_duplicate_registrations<'a, I>(
    registrations: I,
) -> Result<HashMap<&'static str, ToolDescriptor>, BuildRegistryError>
where
    I: IntoIterator<Item = &'a McpToolRegistration>,
{
    let mut map = HashMap::new();
    for reg in registrations {
        let descriptor = ToolDescriptor::from_registration(reg);
        if map.insert(reg.name, descriptor).is_some() {
            // Fail-closed: duplicate names are a fatal startup error.  Do NOT
            // log-and-continue; return Err immediately.  Library code must not
            // panic, so Err propagation is the correct mechanism here.
            return Err(BuildRegistryError::DuplicateRegistration { name: reg.name });
        }
    }
    Ok(map)
}

/// Builds a map from tool name → [`ToolDescriptor`] by iterating the
/// distributed `inventory` registry populated by `#[mcp_tool_item(...)]`
/// attributes.
///
/// Called once at `WalletServer::new` startup.  Returns
/// `Err(BuildRegistryError::DuplicateRegistration { name })` if two
/// `McpToolRegistration` values claim the same tool name — **fail-closed**.
///
/// # Security rationale
///
/// Silent first-registration-wins is rejected because linker order of
/// `inventory::submit!` items is non-deterministic across builds.  A malicious
/// contributor could register a second `McpToolRegistration` with the same
/// `name` but `destructive_hint = false` to shadow the legitimate
/// `destructive_hint = true` entry, bypassing the mainnet write-tools
/// gate in a way that would be non-deterministic to reproduce in a review.
/// Fail-closed eliminates this attack class (logic-level capability
/// escalation).
///
/// # Errors
///
/// Returns [`BuildRegistryError::DuplicateRegistration`] when two
/// `McpToolRegistration` values with the same `name` are collected by the
/// `inventory` iterator.
pub(crate) fn build_tool_registry()
-> Result<HashMap<&'static str, ToolDescriptor>, BuildRegistryError> {
    check_duplicate_registrations(inventory::iter::<McpToolRegistration>())
}

// ─────────────────────────────────────────────────────────────────────────────
// redact_deny_reason — account-ID redaction at the wire boundary
// ─────────────────────────────────────────────────────────────────────────────

/// Applies first-5-last-5 redaction to any account-ID-bearing
/// fields inside a [`DenyReason`] before the value is serialised into the MCP
/// wire error envelope.
///
/// The account-ID-bearing variants are redacted before crossing the MCP wire
/// boundary. All other variants are returned unchanged.
///
/// The redaction format is `GAAAA...ZZZZZ` (first 5 chars + `...` + last 5 chars).
/// For any `value` shorter than 11 characters the full value is replaced with
/// `G...?` (matches the shared observability helper used at other log boundaries).
fn redact_deny_reason(reason: &DenyReason) -> DenyReason {
    match reason {
        DenyReason::CounterpartyDenied { kind, value } => DenyReason::CounterpartyDenied {
            kind: kind.clone(),
            value: redact_account_id_value(value),
        },
        DenyReason::Sep10SessionMissing { account_id } => DenyReason::Sep10SessionMissing {
            account_id: redact_account_id_value(account_id),
        },
        DenyReason::Sep45SessionMissing { contract_id } => DenyReason::Sep45SessionMissing {
            contract_id: redact_account_id_value(contract_id),
        },
        // `BundleDenied` wraps an inner criterion's deny reason, which may itself
        // be a strkey-bearing variant (e.g. `CounterpartyDenied`). Recurse so the
        // inner reason is redacted too. (Today `BundleDenied` is produced only by
        // the smart-account bundle evaluator and does not reach this formatter,
        // but recursing here closes the latent leak if a future MCP tool routes a
        // bundle through `dispatch_gate`.)
        DenyReason::BundleDenied {
            inner_index,
            deny_reason,
        } => DenyReason::BundleDenied {
            inner_index: *inner_index,
            deny_reason: Box::new(redact_deny_reason(deny_reason)),
        },
        // All other variants carry no account IDs; pass through.
        other => other.clone(),
    }
}

/// Formats `"{prefix}: {err}"` and routes the result through the shared
/// authority-only RPC-URL redactor so no scheme/userinfo/path/query/fragment of
/// the configured RPC endpoint leaks into an MCP wire error.
///
/// Used at the `StellarRpcClient::new` construction-failure sites across the MCP
/// tools (RPC endpoint redaction).
pub(crate) fn redact_rpc_error_detail(prefix: &str, err: &impl std::fmt::Display) -> String {
    stellar_agent_network::redact_rpc_error(&format!("{prefix}: {err}"))
}

// ─────────────────────────────────────────────────────────────────────────────
// approval_required_indistinguishable — uniform wire error
// ─────────────────────────────────────────────────────────────────────────────

/// Returns the uniform `policy.approval_required` wire error used at every
/// attestation-gate failure mode.
///
/// Per the indistinguishability rule, **all** of the following
/// cases produce byte-identical wire errors so an oracle cannot distinguish
/// which step failed:
///
/// - `approval_nonce` / `approval_attestation` absent from args.
/// - Attestation blob fails base64 decode.
/// - Approval entry not found in the store.
/// - Approval entry has expired.
/// - Envelope SHA-256 does not match the stored hash.
/// - HMAC-SHA256 verification fails.
/// - Attestation key cannot be loaded from the keyring.
///
/// Internal `tracing::debug!` calls in each failure arm MAY distinguish for
/// operator forensics; the wire payload is uniform.
pub(crate) fn approval_required_indistinguishable() -> ErrorData {
    ErrorData::internal_error(
        "policy.approval_required: \
         approval attestation absent, invalid, or expired; \
         run `stellar-agent approve --id <nonce>` then re-submit with attestation",
        None,
    )
}

/// Returns the wire error for a live, non-expired `ApprovalKind::Rejected`
/// tombstone.
///
/// Distinct from [`approval_required_indistinguishable`] so the agent can
/// tell "the operator explicitly declined this request" apart from "no
/// decision has been made yet" and stop re-simulating a request the operator
/// already turned down. An expired (but not yet GC'd) tombstone is treated
/// as absent by the expiry check upstream of this function and still
/// produces the generic `policy.approval_required`.
pub(crate) fn approval_rejected_error() -> ErrorData {
    ErrorData::internal_error(
        "policy.approval_rejected: \
         the operator explicitly rejected this pending approval; \
         re-simulate to obtain a fresh approval request if this action is still desired",
        None,
    )
}

/// Returns the fail-closed wire error for a `RequireApproval` verdict on a
/// single-shot sign tool.
///
/// Single-shot sign tools (SEP-43 `signMessage`, `signTransaction`,
/// `signAuthEntry`, `signAndSubmitTransaction`; SEP-53 `sign_message`; x402
/// `create_payment`, `authenticated_payment`) have no simulate→commit split, so
/// the full two-phase approval flow cannot be honoured.  When the policy engine
/// returns `Decision::RequireApproval` for one of these tools, the call is
/// rejected fail-closed with this error rather than silently downgrading the
/// policy verdict to `Allow` and signing.
///
/// # Security
///
/// Returning this error preserves the policy engine's intent: the operator
/// configured a criterion that requires approval before signing, and the wallet
/// MUST NOT sign without it.  Silently discarding `RequireApproval` would be a
/// security defect.
pub(crate) fn single_shot_require_approval_error() -> ErrorData {
    ErrorData::internal_error(
        "policy.approval_required_unsupported: \
         this tool requires approval before signing; \
         single-shot sign tools do not support the two-phase approval flow; \
         configure a policy that allows this operation without \
         approval, or use a two-phase tool that supports the approval flow",
        None,
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// load_attestation_key — load HMAC key from keyring
// ─────────────────────────────────────────────────────────────────────────────

/// Loads the per-profile HMAC-SHA256 attestation key from the platform keyring.
///
/// Reads the keyring entry `stellar-agent-attestation-<profile>` / `"default"`
/// (as established by [`stellar_agent_core::profile::schema::KeyringEntryRef::default_attestation_key`]).
/// The stored value is URL-safe base64 no-pad-encoded 32 bytes.
///
/// # Errors
///
/// Returns `Err(ErrorData)` mapping to
/// [`approval_required_indistinguishable`] on any keyring or decode failure,
/// preserving the indistinguishability invariant at the call site.
///
/// # Security
///
/// The returned key MUST be wrapped in `zeroize::Zeroizing` by the caller to
/// ensure the bytes are zeroed on drop.  This function returns a plain
/// `[u8; 32]` because [`zeroize::Zeroizing`] is not in scope here; the caller
/// wraps immediately.
pub(crate) fn load_attestation_key(
    profile: &stellar_agent_core::profile::schema::Profile,
) -> Result<[u8; 32], ErrorData> {
    use base64::Engine as _;
    use keyring_core::Entry as KeyringEntry;

    let entry_ref = &profile.attestation_key_id;
    let entry = KeyringEntry::new(&entry_ref.service, &entry_ref.account).map_err(|e| {
        tracing::debug!(error = %e, "attestation key entry open failed");
        approval_required_indistinguishable()
    })?;

    let raw = entry.get_password().map_err(|e| {
        tracing::debug!(error = %e, "attestation key read failed");
        approval_required_indistinguishable()
    })?;

    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(raw.trim())
        .map_err(|e| {
            tracing::debug!(error = %e, "attestation key base64 decode failed");
            approval_required_indistinguishable()
        })?;

    if bytes.len() != 32 {
        tracing::debug!(len = bytes.len(), "attestation key length mismatch");
        return Err(approval_required_indistinguishable());
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

// ─────────────────────────────────────────────────────────────────────────────
// dispatch_gate — centralised 3-step preamble
// ─────────────────────────────────────────────────────────────────────────────

impl WalletServer {
    /// Centralised dispatch gate consolidating the 3-step preamble shared
    /// by every MCP tool handler (registry lookup → policy_engine.evaluate →
    /// chain_id validation).
    ///
    /// # Steps
    ///
    /// 1. Look up `tool_name` in `self.tool_registry`. Missing → fail-closed
    ///    `internal_error("tool.registry_missing: <name> not found in registry")`.
    /// 2. Call `self.policy_engine.evaluate(...)` with the registry descriptor,
    ///    the args, the profile, the optional account/identity views, and a
    ///    counterparty-cache snapshot.
    ///    - `Decision::Allow` → `Ok(DispatchOutcome::Allow)`.
    ///    - `Decision::Deny(reason)` → `Err(internal_error)` with wire code
    ///      `policy.deny.<reason.code()>` and the redacted `DenyReason` as
    ///      structured payload (first-5-last-5 on account IDs).
    ///    - `Decision::RequireApproval(req)` → `Ok(DispatchOutcome::RequireApproval(req))`.
    ///      The simulate handler persists a `PendingApproval` and embeds the
    ///      nonce in the response; commit handlers verify the attestation.
    ///    - Any future `Decision` variant not listed above → `Err(internal_error)`
    ///      with wire code `policy.unexpected_decision` (forward-compat catch-all).
    ///    - `Err` → `Err(internal_error)` with wire code `policy.engine_required: <err>`.
    /// 3. Call `validate_chain_id_matches_profile(chain_id, &self.profile)`.
    ///    Mismatch → `Err(invalid_params("chain_id mismatch: <err>"))`.
    ///
    /// # Errors
    ///
    /// Returns `Err(ErrorData)` for all failure modes listed in step 2 and step 3.
    pub(crate) async fn dispatch_gate(
        &self,
        tool_name: &'static str,
        args_value: &Value,
        chain_id: &str,
    ) -> Result<DispatchOutcome, ErrorData> {
        self.dispatch_gate_with_views(tool_name, args_value, chain_id, None, None)
            .await
    }

    /// Variant of [`Self::dispatch_gate`] that injects account-derived policy
    /// views.
    ///
    /// `account_view` is the SOURCE account, consumed by the `minimum_reserve`
    /// criterion. `identity_view` is the account whose on-chain `home_domain`
    /// is being checked, consumed by the `home_domain_resolved` criterion.
    /// Tools that fetch these accounts (e.g. `stellar_pay`,
    /// `stellar_create_account`) call this variant; all other tools call
    /// [`Self::dispatch_gate`], which passes `None` for both — those criteria
    /// then fail closed if an operator has configured them.
    pub(crate) async fn dispatch_gate_with_views(
        &self,
        tool_name: &'static str,
        args_value: &Value,
        chain_id: &str,
        account_view: Option<&dyn stellar_agent_core::policy::v1::AccountReservesView>,
        identity_view: Option<&dyn stellar_agent_core::policy::v1::AccountIdentityView>,
    ) -> Result<DispatchOutcome, ErrorData> {
        // Pre-step: dangerous-key guard.
        //
        // Reuse the same guard that toolset dispatch applies (validate_toolset_tool_args).
        // For first-party tools the args are not attacker-authored in the normal
        // flow, but a compromised upstream agent could route attacker JSON here.
        // Applying the guard at this chokepoint covers ALL first-party tools
        // without per-tool duplication.
        //
        // Note: toolset dispatch sites apply this guard before calling dispatch_gate,
        // so toolset-routed calls get a second (idempotent) application here — that
        // is correct and adds defence-in-depth at the chokepoint.
        stellar_agent_toolsets::validate_toolset_tool_args(args_value)
            .map_err(|e| ErrorData::invalid_params(format!("args.validation: {e}"), None))?;

        // Step 1 — registry lookup.
        let descriptor = match self.tool_registry.get(tool_name) {
            Some(d) => d,
            None => {
                return Err(ErrorData::internal_error(
                    format!("tool.registry_missing: {tool_name} not found in registry"),
                    None,
                ));
            }
        };

        let counterparty_cache =
            match stellar_agent_network::CounterpartyCacheSnapshot::from_resolver(
                &*self.counterparty_resolver,
            )
            .await
            {
                Ok(snapshot) => Some(snapshot),
                Err(err) => {
                    tracing::debug!(
                        tool = tool_name,
                        error = %err,
                        "dispatch_gate: counterparty cache snapshot unavailable"
                    );
                    None
                }
            };

        // Step 2 — policy engine evaluation with explicit typed arms.
        let outcome = match self.policy_engine.evaluate(
            descriptor,
            args_value,
            &self.profile,
            account_view,
            identity_view,
            counterparty_cache.as_ref().map(|snapshot| {
                snapshot as &dyn stellar_agent_core::policy::v1::CounterpartyCacheView
            }),
            None,
            None, // sep45_sessions: wired at dispatch site when sep45_session_active criterion active
        ) {
            Ok(Decision::Allow) => DispatchOutcome::Allow,

            Ok(Decision::Deny(reason)) => {
                // Redact account IDs in CounterpartyDenied before serialising
                // into the wire envelope.
                let redacted = redact_deny_reason(&reason);
                let wire_code = format!("policy.deny.{}", reason.code());
                let payload = serde_json::to_value(&redacted).ok();
                return Err(ErrorData::internal_error(wire_code, payload));
            }

            Ok(Decision::RequireApproval(req)) => {
                // Return the ApprovalRequest to the caller; simulate handlers
                // persist a PendingApproval entry; commit handlers verify
                // the attestation before proceeding.  Do NOT produce a wire
                // error here — that is the job of commit handlers that receive
                // a commit call without valid attestation.
                DispatchOutcome::RequireApproval(req)
            }

            // Forward-compat catch-all: Decision is #[non_exhaustive]; any future
            // variant not handled above falls here so the gate stays fail-closed.
            Ok(_) => {
                return Err(ErrorData::internal_error(
                    "policy.unexpected_decision",
                    None,
                ));
            }

            Err(err) => {
                // Engine error → fail closed as `policy.engine_required`
                // (fires for `Noop` and for `V1` engine errors such as a
                // missing policy document).
                return Err(ErrorData::internal_error(
                    format!("policy.engine_required: {err}"),
                    None,
                ));
            }
        };

        // Step 3 — chain_id validation.
        //
        // Only validate when `chain_id_required = true` (the tool must receive a
        // valid CAIP-2 chain identifier).  Tools with `chain_id_required = false`
        // (e.g. `stellar_toolset_invoke`, `stellar_toolset_list`, read-only tools)
        // may be called with an empty chain_id — skip validation for them.
        if descriptor.chain_id_required
            && let Err(err) = validate_chain_id_matches_profile(chain_id, &self.profile)
        {
            return Err(ErrorData::invalid_params(
                format!("chain_id mismatch: {err}"),
                None,
            ));
        }

        Ok(outcome)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// commit_envelope_and_verify_nonce — nonce commit substrate
// ─────────────────────────────────────────────────────────────────────────────

/// Verifies the nonce's HMAC + expiry + chain binding, then atomically records
/// it in the replay window — the shared substrate of `*_commit` MCP tools.
///
/// # Steps
///
/// 1. Spawn-blocking call to [`NonceMint::verify_hmac_only`] (keyring-sync I/O).
///    On failure: indistinguishability — `Expired`/`HmacMismatch` collapse
///    to a single generic message; other variants use `wire_code()` + Display.
/// 2. Acquire `replay_window` lock briefly (no I/O inside lock); evict expired,
///    then record the nonce. On `Replayed` → typed `nonce.replayed` error.
///
/// # Errors
///
/// Returns `rmcp::ErrorData::internal_error` with the wire codes below.  All
/// wire codes are byte-identical to the pre-extraction inline code; see
/// [`stellar_agent_nonce::NonceError::wire_code`] for the source of truth on
/// the per-variant mapping (the table below mirrors that mapping plus the
/// indistinguishability collapse).
///
/// | Wire code | Trigger | Detail format |
/// |---|---|---|
/// | `nonce.expired` | `NonceError::Expired` OR `NonceError::HmacMismatch` (indistinguishability collapse) | `"nonce expired or invalid; re-simulate to obtain a fresh nonce"` |
/// | `nonce.replayed` | replay window already contains this nonce | `"this nonce has already been used; re-simulate to obtain a fresh nonce"` |
/// | `<other wire_code>` | any other typed `NonceError` variant | the variant's Display message WITHOUT the wire-code prefix |
/// | `internal_error` | tokio `spawn_blocking` join failure | `"spawn_blocking join error: <e>"` |
///
/// # Design notes
///
/// `verify_hmac_only` performs keyring IPC (synchronous; tens to hundreds of ms
/// on D-Bus / macOS Keychain).  It MUST run inside `spawn_blocking` to avoid
/// blocking the Tokio executor.
///
/// `ReplayWindow` is not `Send`, so it cannot be moved into the `spawn_blocking`
/// closure.  The lock is therefore acquired **after** `spawn_blocking` returns.
/// The TOCTOU gap (a concurrent request could have committed the same nonce
/// between the HMAC check and the window lock) is bounded by the keyring
/// round-trip latency and is acceptable because the nonce's remaining replay
/// protection still holds (the second call also goes through HMAC verify before
/// the window check).
#[expect(
    clippy::too_many_arguments,
    reason = "minimal decomposition of the nonce-commit protocol: nonce authority \
              (1 Arc + 1 mutex ref), nonce identity + envelope binding (3 params), \
              chain+tool binding (2 params), and clock (1 param). Grouping them into an \
              intermediate struct would create a single-use type that increases indirection \
              without reducing cognitive load at the call sites; callers already spell each \
              argument out explicitly from their local context, which is the clearest form."
)]
pub(crate) async fn commit_envelope_and_verify_nonce(
    nonce_mint: &Arc<NonceMint>,
    replay_window: &TokioMutex<ReplayWindow>,
    nonce: &Nonce,
    envelope_xdr: &str,
    expires_at_unix_ms: u64,
    chain_id: &str,
    tool_name: &'static str,
    now_ms: u64,
) -> Result<(), ErrorData> {
    // Phase 1 — HMAC + expiry + chain check inside spawn_blocking (keyring sync I/O;
    // must not block the Tokio executor).
    let nonce_mint_clone = Arc::clone(nonce_mint);
    let nonce_for_hmac = nonce.clone();
    let envelope_bytes = envelope_xdr.as_bytes().to_vec();
    let expires_at = expires_at_unix_ms;
    let chain_id_for_hmac = chain_id.to_owned();

    let hmac_result = tokio::task::spawn_blocking(move || {
        nonce_mint_clone.verify_hmac_only(NonceVerifyHmacOnlyRequest {
            nonce: &nonce_for_hmac,
            envelope_xdr: &envelope_bytes,
            expiry_unix_ms: expires_at,
            tool_name,
            chain_id: &chain_id_for_hmac,
            now_unix_ms: now_ms,
        })
    })
    .await
    .map_err(|e| {
        ErrorData::internal_error(
            format!("internal_error: spawn_blocking join error: {e}"),
            None,
        )
    })?;

    if let Err(err) = hmac_result {
        tracing::debug!(error = %err, "nonce HMAC/expiry verification failed");
        return Err(nonce_verification_error_data(&err));
    }

    // Phase 2: replay window lock is held only for evict_expired + record_verified_nonce
    // (no I/O; sub-microsecond on non-contended path).
    let mut replay_window_guard = replay_window.lock().await;
    // Evict before record to bound HashMap memory growth.
    replay_window_guard.evict_expired(now_ms);
    if let Err(replay_err) =
        nonce_mint.record_verified_nonce(&mut replay_window_guard, nonce, expires_at_unix_ms)
    {
        tracing::debug!(error = %replay_err, "nonce replay check failed");
        return Err(nonce_replayed_error_data());
    }

    Ok(())
}

/// Collapses Expired and HmacMismatch to identical wire output;
/// non-collapsed variants must not double-prefix the wire-code.
fn nonce_verification_error_data(err: &NonceError) -> ErrorData {
    let detail = match err {
        // Indistinguishability: collapse Expired and HmacMismatch to the
        // same generic message.  Agent recovery is identical (re-simulate);
        // the detailed reason is operator-visible via tracing::debug! only.
        NonceError::Expired | NonceError::HmacMismatch => {
            "nonce expired or invalid; re-simulate to obtain a fresh nonce".to_owned()
        }
        other => other.to_string(),
    };
    let code = err.wire_code();
    ErrorData::internal_error(format!("{code}: {detail}"), None)
}

/// Collapses commit-path memo, envelope-build, and oracle-build failures to the
/// same public recovery envelope as expired/HMAC-mismatched nonces.
///
/// The detailed commit-path error remains operator-visible through debug
/// tracing only; callers must not expose memo parse, payment-builder,
/// envelope-builder, or oracle-builder distinctions on the wire.
///
/// Delegates to `nonce_verification_error_data(&NonceError::Expired)` so the
/// wire-byte equality with the nonce-expiry path is structurally guaranteed
/// rather than enforced only by test. A future edit to the collapsed message
/// in `nonce_verification_error_data` propagates here automatically.
pub(crate) fn commit_path_error_data(err: impl std::fmt::Display) -> ErrorData {
    tracing::debug!(error = %err, "stellar_pay_commit commit-path error collapsed");
    nonce_verification_error_data(&NonceError::Expired)
}

fn rpc_urls_equivalent_for_cross_check(left: &str, right: &str) -> bool {
    fn normalise(raw: &str) -> Option<(String, String, u16, String, Option<String>)> {
        let url = url::Url::parse(raw).ok()?;
        let host = url.host_str()?.trim_end_matches('.').to_ascii_lowercase();
        let port = url.port_or_known_default()?;
        let path = url.path().trim_end_matches('/').to_owned();
        Some((
            url.scheme().to_ascii_lowercase(),
            host,
            port,
            path,
            url.query().map(ToOwned::to_owned),
        ))
    }

    match (normalise(left), normalise(right)) {
        (Some(left), Some(right)) => left == right,
        _ => left
            .trim_end_matches('/')
            .eq_ignore_ascii_case(right.trim_end_matches('/')),
    }
}

fn nonce_replayed_error_data() -> ErrorData {
    ErrorData::internal_error(
        "nonce.replayed: this nonce has already been used; re-simulate to obtain a fresh nonce",
        None,
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// verify_attestation_gate — shared attestation-gate helper
// ─────────────────────────────────────────────────────────────────────────────

/// Runs the 8-step attestation verification gate for a `*_commit` MCP tool.
///
/// This helper encapsulates the `RequireApproval` attestation path shared by
/// `stellar_pay_commit` and `stellar_create_account_commit`.  It MUST be called
/// **before** [`commit_envelope_and_verify_nonce`] per the commit-step ordering:
///
/// > dispatch_gate → re-derive args → re-evaluate → **attestation gate** →
/// > nonce HMAC+replay → sign+submit+persist
///
/// Calling nonce-verify before attestation would allow a timing oracle: a
/// forged attestation could observe whether it reached the nonce-expiry check,
/// distinguishing `NotFound`/`Expired` entries from `HmacMismatch`.  The
/// indistinguishability invariant requires all failure modes to collapse
/// to the same wire error, which is only possible when the attestation gate
/// runs first (before any nonce-consume side effect).
///
/// # Steps
///
/// 1. Both `approval_nonce` and `approval_attestation` must be `Some`.
/// 2. Attestation blob decodes to exactly 32 bytes (URL-safe base64 no-pad).
/// 3. Approval store opens at `<approvals_dir>/<profile_name>.toml`.
/// 4. Entry exists in the store.
/// 5. Entry is not expired.
/// 6. Envelope SHA-256 matches the stored hash.
/// 7. Attestation key loads from the keyring.
/// 8. HMAC-SHA256 verifies byte-for-byte (constant-time).
///
/// # Errors
///
/// All failure modes produce [`approval_required_indistinguishable`] per the
/// indistinguishability invariant.  Internal `tracing::debug!` calls distinguish
/// each failure arm for operator forensics only.
///
/// Returns `Ok(())` when:
/// - `dispatch_outcome` is `DispatchOutcome::Allow` (gate is a no-op), OR
/// - all 8 attestation steps pass.
pub(crate) async fn verify_attestation_gate(
    server: &WalletServer,
    dispatch_outcome: &DispatchOutcome,
    envelope_xdr: &str,
    approval_nonce: Option<&str>,
    approval_attestation: Option<&str>,
    tool_name: &'static str,
) -> Result<(), ErrorData> {
    use base64::Engine as _;
    use stellar_agent_core::approval::{
        DEFAULT_RETRY_ATTEMPTS, DEFAULT_RETRY_BACKOFF, envelope_sha256, open_with_retry,
        verify_attestation,
    };
    use stellar_agent_core::profile::schema::default_approval_dir;

    if !matches!(dispatch_outcome, DispatchOutcome::RequireApproval(_)) {
        return Ok(());
    }

    let profile_name = server.profile_name_for_approval();

    // 1. Both fields must be present.
    let (approval_nonce_str, attestation_b64) = match (approval_nonce, approval_attestation) {
        (Some(n), Some(a)) => (n, a),
        _ => {
            tracing::debug!(
                tool = tool_name,
                "approval_nonce or approval_attestation absent"
            );
            return Err(approval_required_indistinguishable());
        }
    };

    // 2. Decode attestation blob (must be exactly 32 bytes).
    let attestation_bytes: [u8; 32] = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(attestation_b64)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| {
            tracing::debug!(tool = tool_name, "attestation base64 decode failed");
            approval_required_indistinguishable()
        })?;

    // 3. Open store and look up entry.
    //
    // In production, resolve the approval dir via `default_approval_dir()`.
    // Under the `test-helpers` feature (or `#[cfg(test)]`), prefer the per-test
    // override injected by `WalletServer::set_approval_dir_for_test` so that
    // integration tests write to a `tempfile::TempDir` and never touch the
    // developer's real wallet state.
    #[cfg(any(test, feature = "test-helpers"))]
    let approvals_dir: std::path::PathBuf = {
        if let Some(ref override_dir) = server.approval_dir_override {
            override_dir.clone()
        } else {
            default_approval_dir().map_err(|e| {
                tracing::debug!(tool = tool_name, "approval dir resolution failed");
                tracing::trace!(error = %e, tool = tool_name, "approval dir resolution failure detail");
                approval_required_indistinguishable()
            })?
        }
    };
    #[cfg(not(any(test, feature = "test-helpers")))]
    let approvals_dir = default_approval_dir().map_err(|e| {
        tracing::debug!(tool = tool_name, "approval dir resolution failed");
        tracing::trace!(error = %e, tool = tool_name, "approval dir resolution failure detail");
        approval_required_indistinguishable()
    })?;
    let store_path = approvals_dir.join(format!("{profile_name}.toml"));
    let store = open_with_retry(&store_path, DEFAULT_RETRY_ATTEMPTS, DEFAULT_RETRY_BACKOFF)
        .map_err(|e| {
            tracing::debug!(tool = tool_name, "approval store open failed");
            tracing::trace!(error = %e, tool = tool_name, "approval store open failure detail");
            approval_required_indistinguishable()
        })?;

    // 4. Entry must exist.
    let entry = match store.get(approval_nonce_str) {
        Some(e) => e.clone(),
        None => {
            tracing::debug!(
                nonce = %approval_nonce_str,
                tool = tool_name,
                "approval entry not found"
            );
            return Err(approval_required_indistinguishable());
        }
    };

    // 5. Confirm not expired.
    let now_ms_attest = server.clock.now_unix_ms().map_err(|e| {
        tracing::debug!(error = %e, tool = tool_name, "clock error for expiry check");
        approval_required_indistinguishable()
    })?;
    if entry.is_expired(now_ms_attest) {
        tracing::debug!(
            nonce = %approval_nonce_str,
            tool = tool_name,
            "approval entry expired"
        );
        return Err(approval_required_indistinguishable());
    }

    // 5b. A live rejection tombstone maps to a distinct wire code so the agent
    //     learns the operator declined, rather than retrying indefinitely
    //     under the generic policy.approval_required code.
    if matches!(
        entry.kind,
        stellar_agent_core::approval::ApprovalKind::Rejected { .. }
    ) {
        tracing::debug!(
            nonce = %approval_nonce_str,
            tool = tool_name,
            "approval entry was rejected by the operator"
        );
        return Err(approval_rejected_error());
    }

    // 6. Confirm envelope XDR hash matches the stored hash.
    //    Extract envelope_sha256_hex from the PaymentSimulated or ClaimSimulated
    //    arm; both bind a simulated classic-transaction envelope through the same
    //    envelope-hash HMAC attestation path. Non-envelope kinds (SignWithPasskey)
    //    do not carry an envelope XDR hash and are handled by a different commit
    //    path.
    let stored_sha256_hex = match &entry.kind {
        stellar_agent_core::approval::ApprovalKind::PaymentSimulated {
            envelope_sha256_hex,
            ..
        }
        | stellar_agent_core::approval::ApprovalKind::ClaimSimulated {
            envelope_sha256_hex,
            ..
        } => envelope_sha256_hex.clone(),
        other => {
            tracing::debug!(
                kind = other.kind_name(),
                tool = tool_name,
                "approval kind mismatch: expected PaymentSimulated or ClaimSimulated for HMAC \
                 attestation path"
            );
            return Err(approval_required_indistinguishable());
        }
    };
    let presented_sha256 = envelope_sha256(envelope_xdr.as_bytes());
    let presented_sha256_hex = hash_to_lower_hex(&Hash(presented_sha256));
    if presented_sha256_hex != stored_sha256_hex {
        tracing::debug!(
            presented = %presented_sha256_hex,
            stored = %stored_sha256_hex,
            tool = tool_name,
            "envelope hash mismatch"
        );
        return Err(approval_required_indistinguishable());
    }

    // 7. Load attestation key from keyring (zeroized via drop).
    let attestation_key_bytes = load_attestation_key(&server.profile)?;
    let attestation_key = zeroize::Zeroizing::new(attestation_key_bytes);

    // 8. Verify HMAC (constant-time).
    if !verify_attestation(
        &attestation_key,
        approval_nonce_str,
        &presented_sha256,
        &entry.process_uid,
        &attestation_bytes,
    ) {
        tracing::debug!(
            nonce = %approval_nonce_str,
            tool = tool_name,
            "HMAC attestation verification failed"
        );
        return Err(approval_required_indistinguishable());
    }
    // Attestation key zeroized here on `attestation_key` drop (Zeroizing fires).

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// high_value_cross_check — independent-RPC rebuild gate
// ─────────────────────────────────────────────────────────────────────────────

/// Outcome type for [`high_value_cross_check`].
///
/// Separates "cross-check not applicable / skipped" from "ran and passed".
/// Both variants allow the commit path to proceed; only `Err` blocks it.
#[derive(Debug)]
pub(crate) enum CrossCheckOutcome {
    /// Cross-check was skipped (asset non-native, value below threshold, or
    /// `oracle_provider_url` unset with a warning already emitted).
    Skipped,
    /// Cross-check ran and the independent-RPC envelope matched the primary
    /// rebuild.
    Passed,
}

/// High-value independent-RPC cross-check for native-XLM commit operations.
///
/// Re-builds the transaction envelope against `profile.oracle_provider_url` and
/// asserts byte-identity with the envelope already built against the primary RPC.
/// Fires only when all of the following hold:
///
/// 1. `asset_is_native` is `true` (native XLM only; non-native skipped
///    unconditionally — native-stroop threshold; non-native expansion paired
///    with a USD oracle is a future candidate).
/// 2. `value_stroops >= profile.effective_usd_threshold()` — the transaction
///    value is at or above the configured high-value floor.
/// 3. `profile.oracle_provider_url` is configured.
///
/// When condition 2 is met but `oracle_provider_url` is unset, the cross-check
/// is **skipped with a [`tracing::warn!`]** (fail-open for the cross-check; the
/// policy gate still runs on the primary rebuild).
/// Operators MUST configure `oracle_provider_url` to activate the mandatory
/// cross-check path for mainnet high-value flows.
///
/// # Errors
///
/// Returns `Err(ErrorData)` with wire code `simulation.divergence` when the
/// independent-RPC envelope does not match `primary_rebuilt_xdr`.  Oracle RPC
/// errors and envelope-build failures also map to `simulation.divergence` —
/// a non-responsive oracle is treated as divergence because the wallet cannot
/// confirm the envelope is safe to commit.
///
/// Returns `Ok(CrossCheckOutcome::Skipped)` for all skip conditions.
/// Returns `Ok(CrossCheckOutcome::Passed)` when the check ran and envelopes
/// matched.
///
/// # Security
///
/// The independent RPC is fetched against `profile.oracle_provider_url` — an
/// operator-configured URL distinct from `profile.rpc_url`.  The cross-check
/// defends against a compromised primary RPC returning stale or manipulated
/// account state.
///
/// **Operator trust requirement:** `oracle_provider_url` MUST be independently
/// administered from `rpc_url`.  A malicious operator that configures the same
/// endpoint (or a colluding endpoint) for both fields reduces the cross-check
/// to single-RPC verification and provides no defence against a compromised
/// primary RPC.
///
/// `source_account` is logged at `tracing::info!` level in first-5-last-5
/// form (the full G-strkey is never logged).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn high_value_cross_check<F, Fut>(
    profile: &Profile,
    primary_rebuilt_xdr: &str,
    source_account: &str,
    asset_is_native: bool,
    value_stroops: i64,
    oracle_rebuild_fn: F,
    tool_name: &'static str,
) -> Result<CrossCheckOutcome, ErrorData>
where
    F: FnOnce(stellar_agent_network::StellarRpcClient) -> Fut,
    Fut: std::future::Future<Output = Result<String, ErrorData>>,
{
    use stellar_agent_network::StellarRpcClient;

    // Guard 1: only native-XLM payments trigger the cross-check.
    if !asset_is_native {
        return Ok(CrossCheckOutcome::Skipped);
    }

    // Guard 2: value must be at or above the effective threshold.
    let threshold = profile.effective_usd_threshold();
    // i64 → u64: Stellar protocol enforces non-negative stroop amounts for
    // Payment and CreateAccount operations at the XDR-validation layer.
    // `decode_authoritative_args` already rejects negative values via serde_json
    // `as_i64` + fail-closed `.ok_or_else(...)`.
    // The cast is therefore lossless in all reachable paths.
    #[allow(clippy::cast_sign_loss)]
    let value_u64 = value_stroops as u64;
    if value_u64 < threshold {
        return Ok(CrossCheckOutcome::Skipped);
    }

    // Guard 3: oracle URL must be configured.
    let Some(oracle_provider_url) = profile.oracle_provider_url.as_ref() else {
        tracing::warn!(
            tool = tool_name,
            source_prefix = redact_account_id_value(source_account),
            value_stroops = value_stroops,
            threshold = threshold,
            "high-value transaction without independent-RPC cross-check; \
             configure profile.oracle_provider_url to activate mandatory cross-check"
        );
        return Ok(CrossCheckOutcome::Skipped);
    };

    if rpc_urls_equivalent_for_cross_check(oracle_provider_url.as_str(), &profile.rpc_url) {
        tracing::warn!(
            target: "policy.cross_check",
            tool = tool_name,
            source_prefix = redact_account_id_value(source_account),
            "oracle_provider_url == rpc_url; cross-check is degraded to single-RPC verification"
        );
    }

    // Canonical wire body for non-mismatch cross-check failure modes.  The
    // byte-mismatch arm below emits a more actionable operator diagnostic
    // because the wallet has both rebuilt envelopes and can compare sequence
    // numbers.
    const CROSS_CHECK_DIVERGENCE_WIRE_BODY: &str = "simulation.divergence: independent-RPC cross-check failed; \
         re-simulate to obtain a fresh envelope";

    // Build a client for the oracle/independent RPC URL.
    let oracle_client = StellarRpcClient::new(oracle_provider_url.as_str()).map_err(|e| {
        // Full error detail retained in debug logs for operator forensics only.
        // The wire response is the canonical CROSS_CHECK_DIVERGENCE_WIRE_BODY;
        // indistinguishability discipline prohibits non-uniform wire bodies.
        tracing::debug!(
            tool = tool_name,
            error = %e,
            "oracle RPC client construction failed; treating as divergence"
        );
        ErrorData::internal_error(CROSS_CHECK_DIVERGENCE_WIRE_BODY, None)
    })?;

    tracing::info!(
        tool = tool_name,
        source_prefix = redact_account_id_value(source_account),
        value_stroops = value_stroops,
        threshold = threshold,
        "high-value cross-check: re-building envelope against independent RPC"
    );

    // Invoke the caller-supplied rebuild closure against the oracle client,
    // bounded by ORACLE_RPC_TIMEOUT.  A slow or unresponsive oracle is treated
    // as divergence — the wallet cannot confirm envelope safety without a valid
    // oracle comparison.
    let oracle_xdr =
        match tokio::time::timeout(ORACLE_RPC_TIMEOUT, oracle_rebuild_fn(oracle_client)).await {
            Ok(Ok(xdr)) => xdr,
            Ok(Err(_)) => {
                tracing::debug!(
                    tool = tool_name,
                    "oracle RPC rebuild failed; treating as divergence"
                );
                return Err(ErrorData::internal_error(
                    CROSS_CHECK_DIVERGENCE_WIRE_BODY,
                    None,
                ));
            }
            Err(_elapsed) => {
                tracing::warn!(
                    tool = tool_name,
                    timeout_secs = ORACLE_RPC_TIMEOUT.as_secs(),
                    "oracle RPC timeout; treating as divergence"
                );
                return Err(ErrorData::internal_error(
                    CROSS_CHECK_DIVERGENCE_WIRE_BODY,
                    None,
                ));
            }
        };

    // Byte-identical comparison.
    if oracle_xdr != primary_rebuilt_xdr {
        let sequence_delta = sequence_delta_hint(primary_rebuilt_xdr, &oracle_xdr);
        tracing::warn!(
            target: "policy.cross_check",
            tool = tool_name,
            cause_hint = "ledger_lag_or_manipulation",
            sequence_delta = %sequence_delta,
            "high-value cross-check: oracle envelope diverges from primary rebuild"
        );
        return Err(ErrorData::internal_error(
            cross_check_divergence_wire_body(&sequence_delta),
            None,
        ));
    }

    tracing::info!(
        tool = tool_name,
        "high-value cross-check: oracle envelope matches primary rebuild"
    );
    Ok(CrossCheckOutcome::Passed)
}

fn cross_check_divergence_wire_body(sequence_delta: &str) -> String {
    format!(
        "simulation.divergence: oracle RPC returned a different sequence number than primary RPC. \
         Possible causes: (a) ledger-lag, where one RPC is behind the other (transient; retry will likely succeed); \
         (b) active manipulation, where primary or oracle returns a forged sequence (security event; investigate). \
         Current sequence delta: {sequence_delta}."
    )
}

fn sequence_delta_hint(primary_rebuilt_xdr: &str, oracle_xdr: &str) -> String {
    let Some(primary_sequence) = transaction_sequence_number(primary_rebuilt_xdr) else {
        return "unknown".to_owned();
    };
    let Some(oracle_sequence) = transaction_sequence_number(oracle_xdr) else {
        return "unknown".to_owned();
    };
    primary_sequence.abs_diff(oracle_sequence).to_string()
}

fn transaction_sequence_number(envelope_xdr: &str) -> Option<i64> {
    use stellar_xdr::{Limits, ReadXdr, TransactionEnvelope};

    // Bound the untrusted decode: an agent-supplied XDR must not be able to
    // exhaust the stack via deeply-nested structures. `depth = 500` is well
    // above any real transaction envelope, and the base64 input length is a
    // safe upper bound on the decoded byte length.
    let limits = Limits {
        depth: 500,
        len: envelope_xdr.len(),
    };
    match TransactionEnvelope::from_xdr_base64(envelope_xdr, limits).ok()? {
        TransactionEnvelope::Tx(envelope) => Some(envelope.tx.seq_num.0),
        _ => None,
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
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use stellar_agent_core::AuthError;
    use stellar_agent_core::policy::v1::{
        AccountIdentityView, AccountReservesView, CounterpartyCacheView, Sep10SessionView,
        Sep45SessionView,
    };
    use stellar_agent_core::policy::{
        ApprovalRequest, Decision, DenyReason, PolicyEngine, PolicyError, ToolDescriptor,
    };
    use stellar_agent_core::profile::schema::Profile;

    // ── MockPolicyEngine — hand-rolled since mockall is not in workspace deps ──

    /// Returns the configured `Decision` or `Err(PolicyError::NotImplemented)`
    /// on demand.  Used to drive explicit-arm tests on `dispatch_gate`.
    struct MockPolicyEngine {
        result: Result<Decision, PolicyError>,
    }

    impl MockPolicyEngine {
        fn returns(result: Result<Decision, PolicyError>) -> Self {
            Self { result }
        }
    }

    impl PolicyEngine for MockPolicyEngine {
        fn evaluate(
            &self,
            _tool: &ToolDescriptor,
            _args: &serde_json::Value,
            _profile: &Profile,
            _account_view: Option<&dyn AccountReservesView>,
            _identity_view: Option<&dyn AccountIdentityView>,
            _counterparty_cache: Option<&dyn CounterpartyCacheView>,
            _sep10_sessions: Option<&dyn Sep10SessionView>,
            _sep45_sessions: Option<&dyn Sep45SessionView>,
        ) -> Result<Decision, PolicyError> {
            self.result.clone()
        }
    }

    struct CacheAssertingPolicyEngine {
        observed: Arc<AtomicBool>,
    }

    impl PolicyEngine for CacheAssertingPolicyEngine {
        fn evaluate(
            &self,
            _tool: &ToolDescriptor,
            _args: &serde_json::Value,
            _profile: &Profile,
            _account_view: Option<&dyn AccountReservesView>,
            _identity_view: Option<&dyn AccountIdentityView>,
            counterparty_cache: Option<&dyn CounterpartyCacheView>,
            _sep10_sessions: Option<&dyn Sep10SessionView>,
            _sep45_sessions: Option<&dyn Sep45SessionView>,
        ) -> Result<Decision, PolicyError> {
            if counterparty_cache
                .map(|cache| cache.has_resolved("circle.com"))
                .unwrap_or(false)
            {
                self.observed.store(true, Ordering::Release);
                Ok(Decision::Allow)
            } else {
                Err(PolicyError::NotImplemented)
            }
        }
    }

    struct StubCounterpartyResolver;

    #[async_trait::async_trait]
    impl stellar_agent_network::CounterpartyResolver for StubCounterpartyResolver {
        async fn refresh(
            &self,
            _home_domain: &str,
        ) -> Result<
            stellar_agent_network::StellarTomlBinding,
            stellar_agent_network::CounterpartyError,
        > {
            Err(stellar_agent_network::CounterpartyError::FetchFailed {
                detail: "not used by dispatch_gate snapshot test".to_owned(),
            })
        }

        async fn list_cached(
            &self,
        ) -> Result<
            Vec<stellar_agent_network::StellarTomlBinding>,
            stellar_agent_network::CounterpartyError,
        > {
            let now = std::time::SystemTime::now();
            Ok(vec![stellar_agent_network::StellarTomlBinding::new(
                "circle.com".to_owned(),
                now,
                now + std::time::Duration::from_secs(3600),
                false,
            )])
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn make_server_with_engine(engine: impl PolicyEngine + 'static) -> crate::server::WalletServer {
        use std::sync::Arc;
        // Explicitly set Noop so WalletServer::new succeeds without a signed
        // policy file on disk (PolicyEngineKind::default() is V1, which requires
        // a signed policy file and a keyring owner-key entry).
        let mut server = crate::server::WalletServer::new(
            Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
                .with_noop_engine()
                .build(),
        )
        .expect("WalletServer::new must not fail in tests");
        // Replace the policy engine via Arc coercion.
        // `policy_engine` is `pub(crate)` so we can set it directly from within
        // the same crate.
        server.policy_engine = Arc::new(engine);
        server
    }

    fn star_tool_value() -> Value {
        serde_json::json!({ "chain_id": "stellar:testnet" })
    }

    fn transaction_envelope_xdr_with_sequence(sequence: i64) -> String {
        use stellar_xdr::{
            Limits, Memo, MuxedAccount, Preconditions, SequenceNumber, Transaction,
            TransactionEnvelope, TransactionExt, TransactionV1Envelope, Uint256, WriteXdr,
        };

        let tx = Transaction {
            source_account: MuxedAccount::Ed25519(Uint256([7_u8; 32])),
            fee: 100,
            seq_num: SequenceNumber(sequence),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: vec![].try_into().unwrap(),
            ext: TransactionExt::V0,
        };
        TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: vec![].try_into().unwrap(),
        })
        .to_xdr_base64(Limits::none())
        .unwrap()
    }

    #[test]
    fn nonce_id_prefix_returns_first_8_base64_chars() {
        let nonce = Nonce::from_raw([0_u8; 48]);
        let full = nonce.to_base64();

        assert_eq!(full.len(), 64, "nonce base64 fixture length changed");
        assert_eq!(nonce_id_prefix(&nonce), full[..8].to_owned());
    }

    #[test]
    fn hash_to_lower_hex_returns_64_lowercase_hex_chars() {
        let h = Hash([0xAB; 32]);
        let hex = hash_to_lower_hex(&h);

        assert_eq!(hex.len(), 64);
        assert_eq!(hex, "ab".repeat(32));
    }

    // ── nonce error formatting: indistinguishability ─────────────────────────

    #[test]
    fn nonce_expired_and_hmac_mismatch_have_identical_wire_message() {
        let expired = nonce_verification_error_data(&NonceError::Expired);
        let hmac_mismatch = nonce_verification_error_data(&NonceError::HmacMismatch);
        let expected =
            "nonce.expired: nonce expired or invalid; re-simulate to obtain a fresh nonce";

        assert_eq!(expired.message.to_string(), expected);
        assert_eq!(hmac_mismatch.message.to_string(), expected);
        assert_eq!(expired.message, hmac_mismatch.message);
        assert_eq!(
            expired.data, hmac_mismatch.data,
            "indistinguishability: .data must also be identical across the two arms"
        );
        assert!(
            expired.data.is_none(),
            "indistinguishability: .data must currently be None; if this fails, the indistinguishability invariant has drifted and the message-only assertion above is no longer load-bearing"
        );
    }

    #[test]
    fn memo_commit_errors_match_nonce_expired_wire_message() {
        let nonce_expired = nonce_verification_error_data(&NonceError::Expired);
        let memo_invalid = commit_path_error_data("validation.memo_invalid_type");

        assert_eq!(memo_invalid.message, nonce_expired.message);
        assert_eq!(memo_invalid.data, nonce_expired.data);
    }

    #[test]
    fn commit_envelope_build_failure_matches_nonce_hmac_wire_response() {
        let nonce_expired = nonce_verification_error_data(&NonceError::Expired);
        let envelope_build = commit_path_error_data("envelope_build_error: synthetic failure");

        assert_eq!(envelope_build.message, nonce_expired.message);
        assert_eq!(envelope_build.data, nonce_expired.data);
    }

    #[test]
    fn commit_oracle_build_failure_matches_nonce_hmac_wire_response() {
        let nonce_expired = nonce_verification_error_data(&NonceError::Expired);
        let oracle_build = commit_path_error_data("oracle_build_error: synthetic failure");

        assert_eq!(oracle_build.message, nonce_expired.message);
        assert_eq!(oracle_build.data, nonce_expired.data);
    }

    #[test]
    fn nonce_non_collapsed_errors_do_not_double_wire_code_prefix() {
        let cases = [
            NonceError::Replayed,
            NonceError::InvalidTool {
                tool: "unknown_tool".to_owned(),
            },
            NonceError::InvalidEnvelope,
            NonceError::ChainMismatch {
                expected: "stellar:testnet".to_owned(),
                got: "stellar:mainnet".to_owned(),
            },
            NonceError::TtlExceeded {
                max_ms: 300_000,
                requested_ms: 300_001,
            },
            NonceError::TtlTooShort {
                min_ms: 1_000,
                requested_ms: 999,
            },
            NonceError::KeyringError(AuthError::KeyringNotFound {
                name: "nonce-key".to_owned(),
            }),
            NonceError::KeyTooShort { actual: 16 },
            NonceError::InputTooLong {
                field: "tool_name",
                len: usize::MAX,
            },
            NonceError::SerialiseFailed {
                detail: "base64 decode error".to_owned(),
            },
        ];

        for err in cases {
            let code = err.wire_code();
            let display = err.to_string();
            assert!(
                !display.starts_with(&format!("{code}:")),
                "Display must not include the wire-code prefix: {display}"
            );

            let data = nonce_verification_error_data(&err);
            assert_eq!(data.message.to_string(), format!("{code}: {display}"));
        }
    }

    #[test]
    fn replay_window_replayed_maps_to_literal_replayed_message() {
        let mut replay_window = ReplayWindow::new();
        let nonce = [7u8; 48];
        replay_window.record_for_test(nonce, 9_999_999_999).unwrap();
        let replay_err = replay_window
            .record_for_test(nonce, 9_999_999_999)
            .unwrap_err();

        assert!(matches!(replay_err, NonceError::Replayed));
        let data = nonce_replayed_error_data();
        assert_eq!(
            data.message.to_string(),
            "nonce.replayed: this nonce has already been used; re-simulate to obtain a fresh nonce"
        );
    }

    // ── dispatch_gate: Decision::Allow proceeds ───────────────────────────────

    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn dispatch_gate_decision_allow_proceeds() {
        // The testnet profile + NoopPolicyEngine returns Allow for all tools.
        // Explicitly set Noop so WalletServer::new succeeds without a signed
        // policy file on disk (PolicyEngineKind::default() is V1).
        let profile = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
            .with_noop_engine()
            .build();
        stellar_agent_test_support::keyring_mock::install().ok();
        let server =
            crate::server::WalletServer::new(profile).expect("WalletServer::new must not fail");
        // stellar_balances is registered via inventory; use the args schema.
        let args = serde_json::json!({
            "account_id": "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY",
            "chain_id": "stellar:testnet"
        });
        // dispatch_gate should succeed with Allow outcome.
        let result = server
            .dispatch_gate("stellar_balances", &args, "stellar:testnet")
            .await;
        assert!(
            matches!(result, Ok(DispatchOutcome::Allow)),
            "Decision::Allow must produce DispatchOutcome::Allow; got {result:?}"
        );
    }

    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn dispatch_gate_wires_counterparty_cache_snapshot_into_policy() {
        stellar_agent_test_support::keyring_mock::install().ok();
        let observed = Arc::new(AtomicBool::new(false));
        let engine = CacheAssertingPolicyEngine {
            observed: Arc::clone(&observed),
        };
        let mut server = make_server_with_engine(engine);
        server.counterparty_resolver = Arc::new(StubCounterpartyResolver);

        let result = server
            .dispatch_gate("stellar_balances", &star_tool_value(), "stellar:testnet")
            .await;

        assert!(
            matches!(result, Ok(DispatchOutcome::Allow)),
            "cache-backed policy engine must allow when snapshot contains circle.com; got {result:?}"
        );
        assert!(
            observed.load(Ordering::Acquire),
            "policy engine must observe live counterparty cache snapshot"
        );
    }

    // ── dispatch_gate: Decision::Deny(PerTxCapExceeded) → policy.deny.per_tx_cap_exceeded ──

    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn dispatch_gate_decision_deny_per_tx_cap_emits_wire_code() {
        stellar_agent_test_support::keyring_mock::install().ok();
        let deny_reason = DenyReason::PerTxCapExceeded {
            asset: "XLM".into(),
            max_stroops: 1_000_000,
            attempted_stroops: 2_000_000,
        };
        let engine = MockPolicyEngine::returns(Ok(Decision::Deny(deny_reason)));
        let server = make_server_with_engine(engine);
        let result = server
            .dispatch_gate("stellar_balances", &star_tool_value(), "stellar:testnet")
            .await;
        let err = result.expect_err("Deny must produce Err(ErrorData)");
        assert!(
            err.message.contains("policy.deny.per_tx_cap_exceeded"),
            "wire code must contain policy.deny.per_tx_cap_exceeded, got: {}",
            err.message
        );
    }

    // ── dispatch_gate: Decision::Deny(CounterpartyDenied) redacts G-strkey ───

    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn dispatch_gate_decision_deny_counterparty_denied_redacts_g_strkey() {
        stellar_agent_test_support::keyring_mock::install().ok();
        let full_strkey = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";
        let deny_reason = DenyReason::CounterpartyDenied {
            kind: "ADDRESS".into(),
            value: full_strkey.to_owned(),
        };
        let engine = MockPolicyEngine::returns(Ok(Decision::Deny(deny_reason)));
        let server = make_server_with_engine(engine);
        let result = server
            .dispatch_gate("stellar_balances", &star_tool_value(), "stellar:testnet")
            .await;
        let err = result.expect_err("Deny must produce Err(ErrorData)");

        // The payload must NOT contain the full 56-char strkey.
        let payload_str = format!("{:?}", err.data);
        assert!(
            !payload_str.contains(full_strkey),
            "full G-strkey must NOT appear in wire payload; got: {payload_str}"
        );
        // The first 5 chars of the redacted form must appear.
        assert!(
            payload_str.contains("GAQAA"),
            "first-5 of G-strkey must appear in redacted form; got: {payload_str}"
        );
        // Wire code must be correct.
        assert!(
            err.message.contains("policy.deny.counterparty_denied"),
            "wire code must be policy.deny.counterparty_denied; got: {}",
            err.message
        );
    }

    // ── dispatch_gate: Decision::RequireApproval → DispatchOutcome::RequireApproval ──

    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn dispatch_gate_decision_require_approval_returns_outcome() {
        stellar_agent_test_support::keyring_mock::install().ok();
        let req = ApprovalRequest::new("test-nonce-abc".into(), 120);
        let engine = MockPolicyEngine::returns(Ok(Decision::RequireApproval(req)));
        let server = make_server_with_engine(engine);
        let result = server
            .dispatch_gate("stellar_balances", &star_tool_value(), "stellar:testnet")
            .await;
        // RequireApproval is returned as DispatchOutcome, not as a wire error.
        // The simulate handler is responsible for persisting the PendingApproval
        // and embedding the nonce in the response.
        match result {
            Ok(DispatchOutcome::RequireApproval(req)) => {
                assert_eq!(
                    req.nonce, "test-nonce-abc",
                    "nonce must be preserved in DispatchOutcome"
                );
            }
            other => panic!("expected Ok(RequireApproval), got {other:?}"),
        }
    }

    // ── dispatch_gate: approval_required_indistinguishable wire code ──────────

    #[test]
    fn approval_required_indistinguishable_has_expected_wire_code() {
        let err = approval_required_indistinguishable();
        assert!(
            err.message.contains("policy.approval_required"),
            "indistinguishable error must contain policy.approval_required; got: {}",
            err.message
        );
        // Payload must be None — no forensic detail leaked to wire.
        assert!(
            err.data.is_none(),
            "indistinguishable error must have no data payload; got: {:?}",
            err.data
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn high_value_cross_check_warns_when_oracle_matches_primary_rpc() {
        use stellar_agent_test_support::CaptureWriter;
        use tracing::instrument::WithSubscriber as _;

        let mut profile = Profile::builder_mainnet("svc", "acct", "n-svc", "n-acct")
            .with_noop_engine()
            .build();
        profile.rpc_url = "https://rpc.example.com".to_owned();
        profile.oracle_provider_url = Some(url::Url::parse("https://RPC.example.com/").unwrap());

        let capture = CaptureWriter::new();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::WARN)
            .finish();

        let outcome = high_value_cross_check(
            &profile,
            "same-envelope-xdr",
            "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI",
            true,
            i64::try_from(profile.effective_usd_threshold()).unwrap(),
            |_client| async { Ok("same-envelope-xdr".to_owned()) },
            "stellar_pay_commit",
        )
        .with_subscriber(subscriber)
        .await
        .expect("same-XDR cross-check must pass");

        assert!(
            matches!(outcome, CrossCheckOutcome::Passed),
            "same-XDR cross-check must pass, got {outcome:?}"
        );
        let captured = capture.captured_str();
        assert!(
            captured.contains("policy.cross_check"),
            "warning must use policy.cross_check target: {captured}"
        );
        assert!(
            captured.contains(
                "oracle_provider_url == rpc_url; cross-check is degraded to single-RPC verification"
            ),
            "same-URL warning must be emitted: {captured}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn high_value_cross_check_mismatch_reports_ledger_lag_or_manipulation() {
        use stellar_agent_test_support::CaptureWriter;
        use tracing::instrument::WithSubscriber as _;

        let mut profile = Profile::builder_mainnet("svc", "acct", "n-svc", "n-acct")
            .with_noop_engine()
            .build();
        profile.rpc_url = "https://primary.example.com".to_owned();
        profile.oracle_provider_url = Some(url::Url::parse("https://oracle.example.com").unwrap());

        let primary_xdr = transaction_envelope_xdr_with_sequence(100);
        let oracle_xdr = transaction_envelope_xdr_with_sequence(107);
        let capture = CaptureWriter::new();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::WARN)
            .finish();

        let err = high_value_cross_check(
            &profile,
            &primary_xdr,
            "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI",
            true,
            i64::try_from(profile.effective_usd_threshold()).unwrap(),
            |_client| async { Ok(oracle_xdr) },
            "stellar_pay_commit",
        )
        .with_subscriber(subscriber)
        .await
        .expect_err("mismatched oracle XDR must fail");

        let message = err.message.as_ref();
        assert!(
            message.contains("simulation.divergence"),
            "wire message must retain simulation.divergence code: {message}"
        );
        assert!(
            message.contains("Possible causes: (a) ledger-lag"),
            "wire message must name ledger-lag as one possible cause: {message}"
        );
        assert!(
            message.contains("(b) active manipulation"),
            "wire message must name manipulation as one possible cause: {message}"
        );
        assert!(
            message.contains("Current sequence delta: 7."),
            "wire message must include sequence delta: {message}"
        );

        let captured = capture.captured_str();
        assert!(
            captured.contains("policy.cross_check"),
            "warning must use policy.cross_check target: {captured}"
        );
        assert!(
            captured.contains("cause_hint=\"ledger_lag_or_manipulation\""),
            "warning must include cause_hint field: {captured}"
        );
        assert!(
            captured.contains("sequence_delta=7"),
            "warning must include sequence delta field: {captured}"
        );
    }

    #[test]
    fn rpc_urls_equivalent_for_cross_check_normalises_default_ports() {
        assert!(rpc_urls_equivalent_for_cross_check(
            "https://rpc.example.com",
            "https://RPC.example.com:443/"
        ));
        assert!(rpc_urls_equivalent_for_cross_check(
            "http://rpc.example.com",
            "http://rpc.example.com:80/"
        ));
        assert!(!rpc_urls_equivalent_for_cross_check(
            "https://rpc.example.com",
            "https://rpc.example.com:8443"
        ));
        assert!(!rpc_urls_equivalent_for_cross_check(
            "https://rpc.example.com/path?a=1",
            "https://rpc.example.com/path?a=2"
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    #[serial_test::serial(keyring)]
    async fn verify_attestation_gate_debug_logs_omit_absolute_paths() {
        use base64::Engine as _;
        use stellar_agent_test_support::CaptureWriter;
        use tracing_subscriber::fmt::Subscriber;

        stellar_agent_test_support::keyring_mock::install().ok();
        // Explicitly set Noop so WalletServer::new succeeds without a signed
        // policy file on disk (PolicyEngineKind::default() is V1).
        let mut profile = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
            .with_noop_engine()
            .build();
        profile.policy_owner_key_id.service = "stellar-agent-owner-\0path-leak".to_owned();
        let server =
            crate::server::WalletServer::new(profile).expect("WalletServer::new must not fail");
        let dispatch_outcome =
            DispatchOutcome::RequireApproval(ApprovalRequest::new("approval-nonce".into(), 120));
        let attestation_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0_u8; 32]);
        let capture = CaptureWriter::new();
        let subscriber = Subscriber::builder()
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .with_writer(capture.clone())
            .finish();

        let _guard = tracing::subscriber::set_default(subscriber);
        let result = verify_attestation_gate(
            &server,
            &dispatch_outcome,
            "AAAA",
            Some("approval-nonce"),
            Some(&attestation_b64),
            "stellar_pay_commit",
        )
        .await;
        assert!(
            result.is_err(),
            "invalid approval store path should produce approval_required"
        );

        let captured = capture.captured_str();
        assert!(
            captured.contains("approval store open failed"),
            "test must exercise the approval store open debug arm; got: {captured}"
        );
        assert!(
            !captured.contains("/Users/"),
            "DEBUG logs must not expose macOS absolute paths: {captured}"
        );
        assert!(
            !captured.contains("/home/"),
            "DEBUG logs must not expose Linux absolute paths: {captured}"
        );
        assert!(
            !captured.contains("\\Users\\"),
            "DEBUG logs must not expose Windows absolute paths: {captured}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    #[serial_test::serial(keyring)]
    async fn mcp_tools_common_propagates_clock_error_from_injected_failing_clock() {
        use base64::Engine as _;
        use stellar_agent_core::approval::{
            DEFAULT_TTL_MS, PendingApproval, PendingApprovalStore, process_uid_for_attestation,
        };
        use stellar_agent_core::timefmt::Clock;
        use stellar_agent_core::wallet::WalletLifecycleError;

        struct FailingClock;

        impl Clock for FailingClock {
            fn now_unix_ms(&self) -> Result<u64, WalletLifecycleError> {
                Err(WalletLifecycleError::ClockError {
                    detail: "mock clock failed".to_owned(),
                    source: None,
                })
            }
        }

        stellar_agent_test_support::keyring_mock::install().ok();
        let profile = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
            .with_noop_engine()
            .build();
        let clock = Arc::new(FailingClock);
        let mut server = crate::server::WalletServer::new_with_clock(profile, clock)
            .expect("WalletServer::new_with_clock must not fail");
        let approvals_dir = tempfile::tempdir().unwrap();
        server.set_approval_dir_for_test(approvals_dir.path().to_path_buf());

        let store_path = approvals_dir
            .path()
            .join(format!("{}.toml", server.profile_name_for_approval()));
        let mut store = PendingApprovalStore::open(store_path).unwrap();
        let entry = PendingApproval::new_payment_pending(
            "AAAA".to_owned(),
            b"AAAA",
            "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY".to_owned(),
            1_000_000,
            "XLM".to_owned(),
            None,
            100,
            123,
            process_uid_for_attestation().unwrap(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
        let approval_nonce = entry.approval_nonce.clone();
        let now_ms = stellar_agent_core::timefmt::now_unix_ms().unwrap();
        store.insert(entry, now_ms).unwrap();
        drop(store);

        let dispatch_outcome =
            DispatchOutcome::RequireApproval(ApprovalRequest::new(approval_nonce.clone(), 120));
        let attestation_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0_u8; 32]);

        let result = verify_attestation_gate(
            &server,
            &dispatch_outcome,
            "AAAA",
            Some(&approval_nonce),
            Some(&attestation_b64),
            "stellar_pay_commit",
        )
        .await;

        let err = result.expect_err("clock failure must map to approval_required");
        assert!(
            err.message.contains("policy.approval_required"),
            "clock error must use indistinguishable approval-required wire code, got: {}",
            err.message
        );
    }

    // ── Cross-check: a core-minted attestation verifies through this gate ─────
    //
    // `stellar_agent_core::approval::attest_and_persist` is the same function
    // `stellar-agent approve --id <nonce>` calls (lifted from the CLI into
    // core so both share one canonical attest path). This test proves the
    // blob it mints is byte-for-byte what `verify_attestation_gate` accepts —
    // the CLI and the MCP commit boundary agree on the attestation format.

    #[tokio::test(flavor = "current_thread")]
    #[serial_test::serial(keyring)]
    async fn core_minted_attestation_verifies_through_verify_attestation_gate() {
        use base64::Engine as _;
        use stellar_agent_core::approval::{
            DEFAULT_TTL_MS, PendingApproval, PendingApprovalStore, Surface, attest_and_persist,
            process_uid_for_attestation,
        };

        stellar_agent_test_support::keyring_mock::install().ok();
        // Unique service/account names (not shared with any other test in this
        // file) so this test cannot race on the process-global mock keyring
        // store against a test using a different `serial_test` group.
        let profile = Profile::builder_testnet(
            "cross-check-svc",
            "cross-check-acct",
            "cross-check-n-svc",
            "cross-check-n-acct",
        )
        .with_noop_engine()
        .build();

        // Seed the attestation key the profile resolves to.
        let attestation_key = [0x77_u8; 32];
        let attestation_key_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(attestation_key);
        keyring_core::Entry::new(
            &profile.attestation_key_id.service,
            &profile.attestation_key_id.account,
        )
        .expect("Entry::new for attestation key")
        .set_password(&attestation_key_b64)
        .expect("set_password for attestation key");

        let mut server =
            crate::server::WalletServer::new(profile).expect("WalletServer::new must not fail");
        let approvals_dir = tempfile::tempdir().unwrap();
        server.set_approval_dir_for_test(approvals_dir.path().to_path_buf());

        let envelope_xdr = "AAAA";
        let store_path = approvals_dir
            .path()
            .join(format!("{}.toml", server.profile_name_for_approval()));
        let mut store = PendingApprovalStore::open(store_path.clone()).unwrap();
        let entry = PendingApproval::new_payment_pending(
            envelope_xdr.to_owned(),
            envelope_xdr.as_bytes(),
            "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY".to_owned(),
            1_000_000,
            "XLM".to_owned(),
            None,
            100,
            123,
            process_uid_for_attestation().unwrap(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
        let approval_nonce = entry.approval_nonce.clone();
        let now_ms = stellar_agent_core::timefmt::now_unix_ms().unwrap();
        store.insert(entry.clone(), now_ms).unwrap();

        // Mint the attestation via the SAME core path `stellar-agent approve
        // --id <nonce>` calls — not a hand-rolled HMAC in this test.
        let attestation_b64 = attest_and_persist(
            &mut store,
            &entry,
            &attestation_key,
            Surface::Cli,
            None,
            |_req, _key| Err("must not be called for PaymentSimulated".to_owned()),
        )
        .unwrap()
        .expect("PaymentSimulated must surface an attestation blob");
        drop(store);

        let dispatch_outcome =
            DispatchOutcome::RequireApproval(ApprovalRequest::new(approval_nonce.clone(), 120));

        use stellar_agent_test_support::CaptureWriter;
        let capture = CaptureWriter::new();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .with_writer(capture.clone())
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        let result = verify_attestation_gate(
            &server,
            &dispatch_outcome,
            envelope_xdr,
            Some(&approval_nonce),
            Some(&attestation_b64),
            "stellar_pay_commit",
        )
        .await;

        assert!(
            result.is_ok(),
            "a core-minted attestation must verify through verify_attestation_gate: {result:?}; debug log: {}",
            capture.captured_str()
        );
    }

    // ── dispatch_gate: unexpected Decision variant falls through catch-all ────

    // Forward-compat test: if a new Decision variant is added to the enum in a
    // future phase and a test engine returns it, the catch-all arm must fire.
    // We can only test this with the existing non-exhaustive guard arm; the
    // mock engine is configured to return Allow (the only stable variant that
    // would reach the catch-all if the match arms are re-ordered).  This test
    // documents the forward-compat intent and verifies the Err → engine_required
    // path continues to work as a policy gate.
    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn dispatch_gate_unexpected_decision_fail_closed() {
        stellar_agent_test_support::keyring_mock::install().ok();
        // Simulate the policy engine returning Err (the current fail-closed path
        // for an unimplemented engine).  The dispatch gate must propagate it as
        // policy.engine_required.
        let engine = MockPolicyEngine::returns(Err(PolicyError::NotImplemented));
        let server = make_server_with_engine(engine);
        let result = server
            .dispatch_gate("stellar_balances", &star_tool_value(), "stellar:testnet")
            .await;
        let err = result.expect_err("Err from engine must produce Err(ErrorData)");
        assert!(
            err.message.contains("policy.engine_required"),
            "engine Err must map to policy.engine_required; got: {}",
            err.message
        );
    }

    // ── redact_deny_reason unit tests ─────────────────────────────────────────

    #[test]
    fn redact_deny_reason_counterparty_denied_redacts_value() {
        let full = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";
        let reason = DenyReason::CounterpartyDenied {
            kind: "ADDRESS".into(),
            value: full.to_owned(),
        };
        let redacted = redact_deny_reason(&reason);
        match redacted {
            DenyReason::CounterpartyDenied { value, .. } => {
                assert_eq!(value, "GAQAA...QSTVY", "first-5...last-5 form expected");
                assert!(!value.contains(full), "full strkey must not appear");
            }
            other => panic!("expected CounterpartyDenied, got {other:?}"),
        }
    }

    #[test]
    fn redact_deny_reason_bundle_denied_redacts_inner_strkey() {
        let full = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";
        let reason = DenyReason::BundleDenied {
            inner_index: 2,
            deny_reason: Box::new(DenyReason::CounterpartyDenied {
                kind: "ADDRESS".into(),
                value: full.to_owned(),
            }),
        };
        let redacted = redact_deny_reason(&reason);
        match redacted {
            DenyReason::BundleDenied {
                inner_index,
                deny_reason,
            } => {
                assert_eq!(inner_index, 2, "inner_index preserved");
                match *deny_reason {
                    DenyReason::CounterpartyDenied { value, .. } => {
                        assert_eq!(
                            value, "GAQAA...QSTVY",
                            "inner strkey redacted via recursion"
                        );
                        assert!(!value.contains(full), "full inner strkey must not appear");
                    }
                    other => panic!("expected inner CounterpartyDenied, got {other:?}"),
                }
            }
            other => panic!("expected BundleDenied, got {other:?}"),
        }
    }

    #[test]
    fn redact_deny_reason_session_missing_variants_redact_strkeys() {
        let account_id = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";
        let contract_id = "CAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";

        let sep10 = redact_deny_reason(&DenyReason::Sep10SessionMissing {
            account_id: account_id.to_owned(),
        });
        match sep10 {
            DenyReason::Sep10SessionMissing { account_id: value } => {
                assert_eq!(value, "GAQAA...QSTVY");
                assert!(!value.contains(account_id));
            }
            other => panic!("expected Sep10SessionMissing, got {other:?}"),
        }

        let sep45 = redact_deny_reason(&DenyReason::Sep45SessionMissing {
            contract_id: contract_id.to_owned(),
        });
        match sep45 {
            DenyReason::Sep45SessionMissing { contract_id: value } => {
                assert_eq!(value, "CAQAA...QSTVY");
                assert!(!value.contains(contract_id));
            }
            other => panic!("expected Sep45SessionMissing, got {other:?}"),
        }
    }

    #[test]
    fn redact_deny_reason_per_tx_cap_passes_through_unchanged() {
        let reason = DenyReason::PerTxCapExceeded {
            asset: "XLM".into(),
            max_stroops: 100,
            attempted_stroops: 200,
        };
        // Clone to compare; PerTxCapExceeded has no account-ID fields.
        let redacted = redact_deny_reason(&reason);
        assert!(
            matches!(
                redacted,
                DenyReason::PerTxCapExceeded {
                    max_stroops: 100,
                    attempted_stroops: 200,
                    ..
                }
            ),
            "non-counterparty variants must pass through: {redacted:?}"
        );
    }

    #[test]
    fn redact_rpc_error_detail_strips_url_secret_parts() {
        let raw = "RPC endpoint 'HTTPS://user:secret@private-node.example.com:8443/rpc?token=SECRET' \
                   is unreachable: error sending request for url \
                   (https://private-node.example.com:8443/rpc?token=SECRET)";
        let detail = redact_rpc_error_detail("rpc_client_error", &raw);

        assert!(detail.starts_with("rpc_client_error: "));
        assert!(detail.contains("private-node.example.com:8443"));
        assert!(!detail.to_ascii_lowercase().contains("https://"));
        assert!(!detail.contains("user"));
        assert!(!detail.contains("secret"));
        assert!(!detail.contains("/rpc"));
        assert!(!detail.contains("token=SECRET"));
    }

    #[test]
    fn redacted_wallet_error_envelope_redacts_account_not_found_strkey() {
        let account_id = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY".to_owned();
        let err = stellar_agent_core::WalletError::Network(
            stellar_agent_core::error::NetworkError::AccountNotFound {
                account_id: account_id.clone(),
            },
        );
        let envelope = redacted_wallet_error_envelope(&err);
        let wire = envelope.to_json_compact().unwrap();

        assert!(!wire.contains(&account_id), "full strkey leaked: {wire}");
        assert!(
            wire.contains("GAQAA...QSTVY"),
            "redacted strkey missing: {wire}"
        );
        assert!(wire.contains("network.account_not_found"));
    }

    #[test]
    fn redacts_short_account_id_value_to_fallback() {
        assert_eq!(redact_account_id_value("GABC"), "G...?");
        assert_eq!(redact_account_id_value(""), "G...?");
    }

    #[test]
    fn redacts_long_account_id_value_to_first5_last5() {
        let id = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";
        let r = redact_account_id_value(id);
        assert!(r.starts_with("GAQAA"), "must start with first 5");
        assert!(r.ends_with("STVY"), "must end with last 4 of last 5");
        assert!(r.contains("..."), "must contain ellipsis");
        // Must not be longer than first5 + "..." + last5 = 13 chars.
        assert_eq!(r.len(), 13, "redacted form must be exactly 13 chars");
    }

    /// Wire-redaction regression: `LedgerError::TrustlineMissing` must never
    /// emit a full G-strkey over the MCP wire.
    ///
    /// Covers the sibling variant of
    /// `redacted_wallet_error_envelope_redacts_account_not_found_strkey`.
    #[test]
    fn redacted_wallet_error_envelope_redacts_trustline_missing_account_strkey() {
        let account = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY".to_owned();
        let err = stellar_agent_core::WalletError::Ledger(
            stellar_agent_core::error::LedgerError::TrustlineMissing {
                account: account.clone(),
                asset: "USDC:GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5".to_owned(),
            },
        );
        let envelope = redacted_wallet_error_envelope(&err);
        let wire = envelope.to_json_compact().unwrap();

        assert!(
            !wire.contains(&account),
            "full account strkey leaked: {wire}"
        );
        assert!(
            wire.contains("GAQAA...QSTVY"),
            "redacted account strkey missing: {wire}"
        );
        // Asset code must be preserved verbatim (non-secret).
        assert!(
            wire.contains("USDC"),
            "asset code must be present in wire: {wire}"
        );
        assert!(wire.contains("ledger.trustline_missing"));
    }

    /// Wire-redaction regression: `LedgerError::DestinationInvalid` must never
    /// emit a full G-strkey over the MCP wire.
    #[test]
    fn redacted_wallet_error_envelope_redacts_destination_invalid_strkey() {
        let destination = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY".to_owned();
        let err = stellar_agent_core::WalletError::Ledger(
            stellar_agent_core::error::LedgerError::DestinationInvalid {
                destination: destination.clone(),
            },
        );
        let envelope = redacted_wallet_error_envelope(&err);
        let wire = envelope.to_json_compact().unwrap();

        assert!(
            !wire.contains(&destination),
            "full destination strkey leaked: {wire}"
        );
        assert!(
            wire.contains("GAQAA...QSTVY"),
            "redacted destination strkey missing: {wire}"
        );
        assert!(wire.contains("ledger.destination_invalid"));
    }
}
