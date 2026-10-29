//! Shared constants, helpers, and infrastructure for MCP tool handlers.
//!
//! This module contains items used by two or more tool implementation modules:
//! nonce TTL and fee constants, the `ToolCatalogueAdapter` bridge, the
//! link-time tool-registry builder, and the two centralised dispatch helpers:
//!
//! - [`WalletServer::dispatch_gate`]: the gated-handler preamble performs
//!   registry lookup, validates the call chain, and evaluates policy with the
//!   profile-bound descriptor. Returns [`DispatchOutcome`] so simulate handlers
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
    ///
    /// Carries the value descriptor the gate sized on the allow path
    /// (`Some` only for a permitted value-moving call; `None` for read-only /
    /// opaque tools and the no-op engine), so the value-verb handlers record
    /// exactly what the gate evaluated without re-deriving.
    Allow(AllowOutcome),
    /// Policy engine returned `Decision::RequireApproval`; the simulate handler
    /// must persist a `PendingApproval` entry and embed `approval_nonce` in the
    /// response.  The commit handler must verify the attestation blob before
    /// proceeding. The effects are the same descriptor the criteria evaluated
    /// and must be recorded when an attested submission proceeds.
    RequireApproval(ApprovalOutcome),
}

impl DispatchOutcome {
    pub(crate) fn governing_ttl_ms(&self) -> u64 {
        match self {
            Self::Allow(allowed) => allowed.governing_ttl_ms,
            Self::RequireApproval(approval) => approval.governing_ttl_ms,
        }
    }

    fn require_mainnet_confirmation(self, ttl_ms: u64) -> Result<Self, ToolError> {
        let ttl_seconds = u32::try_from(ttl_ms / 1_000)
            .ok()
            .filter(|ttl| *ttl > 0)
            .ok_or_else(|| {
                ToolError::Business(business_error_result(
                    "policy.unexpected_decision",
                    "approval lifetime cannot be represented",
                ))
            })?;
        let mut approval = match self {
            Self::Allow(allowed) => ApprovalOutcome {
                request: ApprovalRequest::new(String::new(), ttl_seconds)
                    .with_reason("mainnet confirmation".to_owned()),
                governing_ttl_ms: ttl_ms,
                value_effects: allowed.value_effects,
            },
            Self::RequireApproval(approval) => approval,
        };
        approval.governing_ttl_ms = ttl_ms;
        approval.request.ttl_seconds = ttl_seconds;
        Ok(Self::RequireApproval(approval))
    }

    /// The policy decision retained by submission audit rows.
    pub(crate) fn audit_decision(&self) -> stellar_agent_core::audit_log::PolicyDecision {
        match self {
            Self::Allow(_) => stellar_agent_core::audit_log::PolicyDecision::Allow,
            Self::RequireApproval(_) => {
                stellar_agent_core::audit_log::PolicyDecision::RequireApproval
            }
        }
    }
}

/// Effects and governing lifetime captured from one allowed evaluation.
#[derive(Debug)]
pub(crate) struct AllowOutcome {
    pub value_effects: Option<stellar_agent_core::policy::v1::ValueEffects>,
    pub governing_ttl_ms: u64,
}

/// An approval request together with the effects its policy criteria sized.
#[derive(Debug)]
pub(crate) struct ApprovalOutcome {
    pub request: ApprovalRequest,
    pub governing_ttl_ms: u64,
    pub value_effects: Option<stellar_agent_core::policy::v1::ValueEffects>,
}

impl From<ApprovalRequest> for ApprovalOutcome {
    fn from(request: ApprovalRequest) -> Self {
        // Only excluded rule-commit overrides use this conversion in production.
        // Admitted writes capture the lifetime from their actual evaluations.
        Self {
            governing_ttl_ms: u64::from(request.ttl_seconds) * 1_000,
            request,
            value_effects: None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ToolError — split error channel (business envelope vs protocol fault)
// ─────────────────────────────────────────────────────────────────────────────

/// Failure from a shared tool-substrate helper that can fail in two ways which
/// surface differently on the wire.
///
/// - **Business** — a domain refusal or policy/nonce/approval outcome the agent
///   is expected to branch on (`policy.deny.<reason>`, `policy.engine_required`,
///   `nonce.*`, …). These surface through the documented result envelope
///   (`is_error = true`, `ok: false`, `error.code`) like every other business
///   error, carried here as a ready-to-return [`CallToolResult`].
/// - **Protocol** — a genuine protocol fault or internal invariant (malformed
///   arguments via the dangerous-key guard, `tool.registry_missing`,
///   `chain_id mismatch`, a `spawn_blocking` join failure). These stay JSON-RPC
///   [`ErrorData`] because they indicate a protocol-contract violation or an
///   internal fault rather than a domain refusal.
///
/// Returned by [`WalletServer::dispatch_gate`] and
/// [`commit_envelope_and_verify_nonce`]. A tool handler folds it back into its
/// `Result<CallToolResult, ErrorData>` return type with
/// [`ToolError::into_result`].
#[must_use]
#[derive(Debug)]
pub(crate) enum ToolError {
    /// A refusal to surface as a business-error result envelope.
    Business(rmcp::model::CallToolResult),
    /// A protocol fault or internal invariant to surface as a JSON-RPC error.
    Protocol(ErrorData),
}

impl ToolError {
    /// Folds the split channel back into a tool handler's
    /// `Result<CallToolResult, ErrorData>` return type: a `Business` failure
    /// becomes `Ok(result)` (an `is_error` envelope) and a `Protocol` failure
    /// becomes `Err(error_data)`.
    pub(crate) fn into_result(self) -> Result<rmcp::model::CallToolResult, ErrorData> {
        match self {
            ToolError::Business(result) => Ok(result),
            ToolError::Protocol(err) => Err(err),
        }
    }

    /// The failure's machine-readable code without its message: the business
    /// envelope's `error.code`, or the JSON-RPC error code of a protocol fault.
    ///
    /// Diagnostics log this code because a message can carry caller-supplied
    /// values. A business result without a readable code yields an empty string.
    pub(crate) fn code(&self) -> String {
        match self {
            ToolError::Business(result) => result
                .content
                .first()
                .and_then(|content| content.as_text())
                .and_then(|text| serde_json::from_str::<Value>(&text.text).ok())
                .and_then(|envelope| envelope["error"]["code"].as_str().map(str::to_owned))
                .unwrap_or_default(),
            ToolError::Protocol(err) => err.code.0.to_string(),
        }
    }
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

/// Resolves the submit timeout for a profile through
/// [`Profile::submit_timeout`], which falls back to the documented 60-second
/// default when the profile omits an override.
#[must_use]
pub(crate) fn submit_timeout(profile: &Profile) -> std::time::Duration {
    profile.submit_timeout()
}

/// Asks the RPC endpoint which network it serves and which protocol it runs,
/// and requires the network to be the profile's.
///
/// The classic prepare and commit tools run this on their client before the
/// first read on it. The fee, the sequence, the claim entry, and the account
/// views they read feed the envelope that is signed or the policy gate, so an
/// endpoint serving a different network answers none of them. A commit tool's
/// client is also the one it submits with. Refusing there consumes no nonce,
/// so the caller can correct the endpoint and retry with the same approval.
///
/// The submit layer runs the same check on the same client before the send;
/// a refusal there comes after the nonce is consumed. This check runs under
/// its own deadline, `timeout` from now. `stellar_pay` is the exception: it
/// calls the identity check directly under the shared pay deadline.
///
/// # Errors
///
/// Returns the check's own refusal:
/// [`stellar_agent_core::error::NetworkError::MainnetWriteForbidden`],
/// [`stellar_agent_core::error::NetworkError::EndpointNetworkMismatch`],
/// [`stellar_agent_core::error::NetworkError::EndpointIdentityUnavailable`] or
/// [`stellar_agent_core::error::NetworkError::UnsupportedProtocolVersion`].
pub(crate) async fn probe_endpoint_network(
    client: &stellar_agent_network::StellarRpcClient,
    context: &stellar_agent_network::NetworkContext,
    timeout: std::time::Duration,
) -> Result<(), stellar_agent_core::error::WalletError> {
    let deadline = tokio::time::Instant::now() + timeout;
    client
        .endpoint_identity(context.network_passphrase(), deadline)
        .await?;
    Ok(())
}

/// Renders an endpoint identity refusal of a prepare or commit tool as an
/// error tool result.
///
/// The refusal carries its own wire code rather than being collapsed into the
/// nonce taxonomy: the caller has to be able to tell "your endpoint serves the
/// wrong network" from "your nonce expired", because only the first is fixed
/// by changing configuration.
pub(crate) fn endpoint_refusal_result(
    err: &stellar_agent_core::error::WalletError,
) -> rmcp::model::CallToolResult {
    let json = stellar_agent_core::envelope::Envelope::<()>::err(err)
        .to_json_pretty()
        .unwrap_or_else(|_| String::from("{}"));
    let mut result = rmcp::model::CallToolResult::success(vec![rmcp::model::Content::text(json)]);
    result.is_error = Some(true);
    result
}

// ─────────────────────────────────────────────────────────────────────────────
// APPROVAL_TTL_MS — 24-hour pending-approval TTL
// ─────────────────────────────────────────────────────────────────────────────

/// Default pending-approval lifetime when a rule supplies no TTL: 24 hours.
pub(crate) const APPROVAL_TTL_MS: u64 = stellar_agent_core::approval::store::DEFAULT_TTL_MS;

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

/// Validates that `value` is a well-formed G-strkey, naming `field_label` in
/// the refusal.
///
/// Used by every classic-op MCP tool (`pay`, `create_account`) that accepts
/// operator-supplied source/destination account fields.
///
/// # Errors
///
/// Returns `rmcp::ErrorData::invalid_params` naming `field_label` and the
/// underlying strkey parse error when `value` is not a valid G-strkey.
pub(crate) fn validate_g_strkey(value: &str, field_label: &str) -> Result<(), ErrorData> {
    if let Err(err) = stellar_strkey::ed25519::PublicKey::from_string(value) {
        return Err(ErrorData::invalid_params(
            format!("invalid {field_label} (expected G-strkey): {err}"),
            None,
        ));
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Classic-op fee constant — re-exported from stellar-agent-core
// ─────────────────────────────────────────────────────────────────────────────

// DEFAULT_CLASSIC_FEE_STROOPS lives in stellar_agent_core::protocol_consts;
// re-export here so existing `crate::tools::common::DEFAULT_CLASSIC_FEE_STROOPS`
// call sites compile without change.
pub(crate) use stellar_agent_core::DEFAULT_CLASSIC_FEE_STROOPS;

pub(crate) use stellar_agent_network::CLASSIC_SINGLE_OPERATION_COUNT;

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

// ─────────────────────────────────────────────────────────────────────────────
// business_error_result — documented business-error envelope
// ─────────────────────────────────────────────────────────────────────────────

/// Builds the documented result envelope `{ ok: false, error: { code, message },
/// request_id }` for a **business error** and returns a `CallToolResult` with
/// `is_error = Some(true)`.
///
/// A business error is any domain refusal, precondition failure, policy/approval
/// outcome, keyring/signing failure, submit failure, pin mismatch, quote failure,
/// or gate refusal — anything the agent should branch on via the documented
/// `ok`/`error.code` contract (see `SKILL.md` §1).  These are tool-execution
/// failures and belong in the tool result, not in a JSON-RPC transport error:
/// this matches the MCP guidance that execution failures are surfaced via
/// `is_error` in the result while JSON-RPC errors are reserved for protocol
/// faults (malformed arguments, internal invariant breakage).
///
/// Every business error routed through this helper gains a `request_id`
/// correlating the wire response with the audit log — a correlation the bare
/// `{code,message}` and JSON-RPC error shapes lacked.
///
/// `code` is the stable wire code (e.g. `"policy.approval_required"`,
/// `"nonce.expired"`, `"vault.wasm_pin_failed"`); `message` is the
/// human-readable, redaction-clean detail.  Callers that move public identifiers
/// into `message` MUST redact them first (the envelope applies no redaction).
///
/// # Panics
///
/// Never panics.
pub(crate) fn business_error_result(
    code: impl Into<String>,
    message: impl Into<String>,
) -> rmcp::model::CallToolResult {
    use rmcp::model::{CallToolResult, Content};
    let envelope = stellar_agent_core::Envelope::<()>::err_raw(code, message);
    let json = envelope
        .to_json_pretty()
        .unwrap_or_else(|_| String::from("{}"));
    let mut result = CallToolResult::success(vec![Content::text(json)]);
    result.is_error = Some(true);
    result
}

/// Test-only: asserts the shared business-error envelope invariants
/// (`is_error == true`, `ok == false`, non-empty `request_id`) and returns the
/// `(code, message, full_text)` triple for further per-tool assertions.
///
/// Used by tool-module unit tests to assert the normalised
/// `{ ok:false, error:{code,message}, request_id }` wire contract without
/// duplicating the JSON extraction at every call site.
#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test-only assertion helper"
)]
pub(crate) fn assert_business_envelope(
    result: &rmcp::model::CallToolResult,
) -> (String, String, String) {
    assert_eq!(
        result.is_error,
        Some(true),
        "business-error result must set is_error = true"
    );
    let text = result
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.clone())
        .expect("business-error result must carry a text content block");
    let v: serde_json::Value =
        serde_json::from_str(&text).expect("business-error content must be JSON");
    assert_eq!(
        v["ok"],
        serde_json::json!(false),
        "business-error envelope must have ok:false: {v}"
    );
    assert!(
        v["request_id"].as_str().is_some_and(|s| !s.is_empty()),
        "business-error envelope must carry a non-empty request_id: {v}"
    );
    let code = v["error"]["code"].as_str().unwrap_or_default().to_owned();
    let message = v["error"]["message"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    (code, message, text)
}

/// Test-only: a policy engine that allows every call.
///
/// A refusal placed ahead of the policy gate holds whatever the engine
/// decides, so the mainnet-refusal tests run on the Noop engine and on this
/// one.
#[cfg(test)]
pub(crate) struct AllowAllPolicyEngine;

#[cfg(test)]
impl stellar_agent_core::policy::PolicyEngine for AllowAllPolicyEngine {
    fn evaluate(
        &self,
        _tool: &stellar_agent_core::policy::ToolDescriptor,
        _args: &serde_json::Value,
        _profile: &stellar_agent_core::profile::schema::Profile,
        _account_view: Option<&dyn stellar_agent_core::policy::v1::AccountReservesView>,
        _identity_view: Option<&dyn stellar_agent_core::policy::v1::AccountIdentityView>,
        _counterparty_cache: Option<&dyn stellar_agent_core::policy::v1::CounterpartyCacheView>,
        _sep10_sessions: Option<&dyn stellar_agent_core::policy::v1::Sep10SessionView>,
        _sep45_sessions: Option<&dyn stellar_agent_core::policy::v1::Sep45SessionView>,
    ) -> Result<stellar_agent_core::policy::Decision, stellar_agent_core::policy::PolicyError> {
        Ok(stellar_agent_core::policy::Decision::Allow)
    }
}

/// Test-only: asserts the structural mainnet-write refusal envelope.
#[cfg(test)]
pub(crate) fn assert_mainnet_write_forbidden(result: &rmcp::model::CallToolResult) {
    let (code, _, _) = assert_business_envelope(result);
    assert_eq!(
        code, "network.mainnet_write_forbidden",
        "a mainnet context must answer the canonical refusal code"
    );
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
///   base64+JSON and direct-JSON parsing fail. An input that decodes as
///   base64 reports the JSON failure of its decoded payload; any other input
///   reports the raw-JSON failure.
///
/// # Panics
///
/// Never panics.
pub(crate) fn decode_payment_required_input(
    input: &str,
) -> Result<stellar_agent_x402::wire::PaymentRequirements, stellar_agent_x402::X402Error> {
    use base64::Engine as _;
    use stellar_agent_x402::wire::decode_payment_required;

    // Try the crate's canonical base64 decode (RFC 4648 §4 standard alphabet).
    let base64_error = match decode_payment_required(input) {
        Ok(parsed) => return Ok(parsed),
        Err(e) => e,
    };

    // An input that decodes as base64 is not raw JSON, because `{` and `[`
    // are outside the alphabet, so the failure of its decoded payload is the
    // one to report. That detail names the JSON error class and position.
    if base64::engine::general_purpose::STANDARD
        .decode(input.trim())
        .is_ok()
    {
        return Err(base64_error);
    }

    // Fall back: parse as raw JSON string (caller-supplied unencoded JSON).
    // The detail names the JSON error class and position only, because the
    // decoder's own text quotes the offending value.
    serde_json::from_str::<stellar_agent_x402::wire::PaymentRequirements>(input).map_err(|e| {
        stellar_agent_x402::X402Error::InvalidPaymentRequired {
            detail: format!(
                "the PaymentRequirements input {}",
                stellar_agent_x402::wire::describe_json_error(&e)
            ),
        }
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// x402 value-descriptor helpers — shared by both x402 payment tools
// ─────────────────────────────────────────────────────────────────────────────

/// Builds the single x402-payment [`ValueLeg`] from `requirements` and the
/// `amount` that [`stellar_agent_x402::exact::validate_requirements`] returned
/// for them.
///
/// The leg's `amount` is the atomic `i128` the SAC transfer carries, parsed
/// once by the validator over the same immutable requirements object the
/// payment is built from. `asset` is `requirements.asset` verbatim (a SAC
/// C-strkey; the value criteria normalise it) and `destination` is
/// `requirements.pay_to` verbatim.
pub(crate) fn x402_value_leg(
    requirements: &stellar_agent_x402::wire::PaymentRequirements,
    amount: i128,
) -> stellar_agent_core::policy::v1::ValueLeg {
    stellar_agent_core::policy::v1::ValueLeg {
        kind: stellar_agent_core::policy::v1::ActionKind::X402Payment,
        amount: Some(amount),
        asset: Some(requirements.asset.clone()),
        destination: Some(requirements.pay_to.clone()),
    }
}

/// The canonical identity of an x402 requirement's asset, under which the
/// cross-check rule looks up its threshold.
///
/// [`stellar_agent_x402::exact::validate_requirements`] holds the asset to a
/// contract strkey, and the canonical form parses with the same strict
/// decoder, so a validated asset converts. A failure answers as the
/// requirement's own asset refusal.
pub(crate) fn x402_canonical_asset(
    requirements: &stellar_agent_x402::wire::PaymentRequirements,
) -> Result<stellar_agent_core::asset_id::CanonicalAsset, rmcp::model::CallToolResult> {
    stellar_agent_core::asset_id::CanonicalAsset::contract(&requirements.asset).map_err(|_| {
        x402_error_to_tool_result(&stellar_agent_x402::X402Error::InvalidAssetAddress {
            detail: format!(
                "expected a canonical C-strkey (contract), got {}",
                stellar_agent_network::quote_server_text(&requirements.asset)
            ),
        })
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// x402_error_to_tool_result — shared x402 error-envelope helper
// ─────────────────────────────────────────────────────────────────────────────

/// Wraps an [`stellar_agent_x402::X402Error`] in the documented business-error
/// envelope and returns a `CallToolResult` with `is_error = Some(true)`.
///
/// The x402 tools have no spec-mandated error wire object (SEP-43 defines one;
/// x402 defines only `PaymentRequirements`), so their errors surface through the
/// documented envelope `{ ok: false, error: { code, message }, request_id }` like
/// every other business error. The `error.code` is derived per-variant via
/// [`stellar_agent_x402::X402Error::wire_code`] (the `x402.<snake_variant>`
/// taxonomy, with `MainnetSigningForbidden` mapping to the canonical
/// `network.mainnet_write_forbidden`), so an agent can branch on the specific
/// failure instead of a single collapsed code.
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
    business_error_result(err.wire_code(), err.to_string())
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

/// Renders a typed policy denial as the wire error an agent branches on.
///
/// The wire code is the reason's own `policy.deny.*` code and the message
/// carries the redacted reason, so no structured detail is lost in the move
/// from the JSON-RPC `data` field.
///
/// Used by the dispatch gate and by every surface that reports a denial the
/// spending-window reservation write decided, so one refusal reads the same
/// whichever step of the call made it.
pub(crate) fn policy_denial_error_result(reason: &DenyReason) -> rmcp::model::CallToolResult {
    let redacted = redact_deny_reason(reason);
    let detail = serde_json::to_string(&redacted).unwrap_or_else(|_| reason.code().to_owned());
    business_error_result(
        reason.wire_code(),
        format!("policy denied this operation: {detail}"),
    )
}

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
pub(crate) fn redact_deny_reason(reason: &DenyReason) -> DenyReason {
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
/// Used at the RPC client construction-failure sites across the MCP tools
/// (RPC endpoint redaction).
pub(crate) fn redact_rpc_error_detail(prefix: &str, err: &impl std::fmt::Display) -> String {
    stellar_agent_network::redact_rpc_error(&format!("{prefix}: {err}"))
}

/// Maps a failed RPC client construction to a tool outcome.
///
/// A credential failure (a missing or unreadable keyring entry, a stored
/// value the wallet refuses, or a credential the client cannot send) is an
/// error tool result with its own code, such as `auth.keyring_not_found`,
/// because only a configuration change fixes it. A transport refusal of the
/// URL stays the protocol-level `rpc_client_error`.
///
/// # Errors
///
/// Returns the `rpc_client_error` internal error for a transport refusal.
pub(crate) fn rpc_client_failure(
    err: &stellar_agent_core::error::WalletError,
) -> Result<rmcp::model::CallToolResult, rmcp::ErrorData> {
    if stellar_agent_network::is_credential_error(err) {
        return Ok(endpoint_refusal_result(err));
    }
    Err(rmcp::ErrorData::internal_error(
        redact_rpc_error_detail("rpc_client_error", err),
        None,
    ))
}

/// The `Debug` form of an optional approval attestation: `Some(<set>)` or
/// `None`, never the attestation itself.
///
/// The attestation is the operator's approval credential, so the argument
/// structs that carry one print it through this wrapper.
pub(crate) struct AttestationPresence<'a>(pub(crate) &'a Option<String>);

impl std::fmt::Debug for AttestationPresence<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.0.is_some() {
            "Some(<set>)"
        } else {
            "None"
        })
    }
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
pub(crate) fn approval_required_indistinguishable(
    profile_name: &str,
) -> rmcp::model::CallToolResult {
    business_error_result(
        "policy.approval_required",
        format!(
            "approval attestation absent, invalid, or expired; run `{}` then re-submit with attestation",
            stellar_agent_core::approval::approve_hint("<nonce>", profile_name)
        ),
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
pub(crate) fn approval_rejected_error() -> rmcp::model::CallToolResult {
    business_error_result(
        "policy.approval_rejected",
        "the operator explicitly rejected this pending approval; \
         re-simulate to obtain a fresh approval request if this action is still desired",
    )
}

/// Returns the wire error for a live `ApprovalKind::Consumed` tombstone.
///
/// Distinct from [`approval_rejected_error`] and
/// [`approval_required_indistinguishable`] so the agent can tell "this
/// approval was already spent on a submission" apart from "the operator
/// declined" and from "no decision yet". The three call for different next
/// steps: reconcile the transaction the approval was spent on, stop asking,
/// or wait.
pub(crate) fn approval_consumed_error() -> rmcp::model::CallToolResult {
    business_error_result(
        "policy.approval_consumed",
        "this pending approval was already spent on a submission; \
         check that transaction's status before simulating the action again",
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
pub(crate) fn single_shot_require_approval_error() -> rmcp::model::CallToolResult {
    business_error_result(
        "policy.approval_required_unsupported",
        "this tool requires approval before signing; \
         single-shot sign tools do not support the two-phase approval flow; \
         configure a policy that allows this operation without \
         approval, or use a two-phase tool that supports the approval flow",
    )
}

/// Returns the shared refusal `detail` string for the structural mainnet-signing
/// guard, carrying the canonical `network.mainnet_write_forbidden` wire code.
///
/// Single-sourced in [`stellar_agent_core::error::MAINNET_SIGNING_REFUSAL_DETAIL`],
/// so every SEP-43, SEP-53, and x402 surface embeds the identical canonical
/// code, keeping cross-surface audit correlation exact. The SEP-43 surfaces
/// include both refusals of `stellar_sep43_sign_and_submit_transaction`, at
/// entry and at the submit layer. The x402 surfaces include the library's
/// `create_payment`, which reads the constant directly.
pub(crate) fn mainnet_signing_refusal_detail() -> String {
    stellar_agent_core::error::MAINNET_SIGNING_REFUSAL_DETAIL.to_owned()
}

/// Returns the structural mainnet-signing refusal for the SEP-43 tools.
///
/// The sign-only tools (`signTransaction`, `signAuthEntry`, `signMessage`)
/// return a signature the caller uses outside the wallet, so the submit-layer
/// mainnet gate never fires. On a mainnet profile these tools MUST refuse
/// structurally, before any key access, so no valid mainnet signature is ever
/// produced. `stellar_sep43_sign_and_submit_transaction` returns it at entry on
/// a mainnet context, before the policy gate, any key access, and any RPC
/// request. It also returns it for a submit-layer mainnet refusal. The refusal
/// is the documented business-error envelope (`ok:false`, `is_error = true`)
/// carrying the canonical `network.mainnet_write_forbidden` wire code, so it
/// correlates with the CLI and submit-layer guards.
///
/// # Security
///
/// This is the sign-only counterpart to the submit-layer
/// [`stellar_agent_core::error::NetworkError::MainnetWriteForbidden`] guard,
/// which a signature returned to the caller never reaches. The
/// `NoopPolicyEngine` mainnet write gate keys on `destructive_hint`, which is
/// `false` for the sign-only tools, so the policy engine alone does not stop
/// them.
pub(crate) fn mainnet_signing_forbidden_result() -> rmcp::model::CallToolResult {
    let err = stellar_agent_sep43::Sep43Error::MainnetSigningForbidden {
        detail: mainnet_signing_refusal_detail(),
    };
    business_error_result(
        stellar_agent_core::error::NetworkError::MainnetWriteForbidden.code(),
        err.to_string(),
    )
}

/// Returns the structural mainnet-signing refusal for the x402 authenticated
/// payment tool.
///
/// The x402 payment tools sign a payment authorization the MCP host
/// broadcasts externally, so the submit-layer mainnet gate never fires.
/// `stellar_x402_authenticated_payment` refuses with this result, before any
/// key access, on a mainnet profile whose server holds no mainnet write
/// context, in a build without mainnet writes, and when a test build stands
/// a fixed session in for its identity gate. A server with the context
/// admits it through mainnet write admission and its two calls, the
/// approval preparation and the approved payment. The Message authorization
/// is consumed before the SEP-10 signature. The payment intent is consumed
/// before the signed simulation, and the submit authorization before the
/// payload release.
/// `stellar_x402_create_payment` is admitted on mainnet the same way;
/// without admission it refuses with the admission's
/// `network.mainnet_write_forbidden` result instead. Surfaced as an
/// [`stellar_agent_x402::X402Error::MainnetSigningForbidden`] tool result
/// (`is_error = true`) carrying the canonical `network.mainnet_write_forbidden`
/// wire code, matching the sign-only SEP-43 refusal in
/// [`mainnet_signing_forbidden_result`].
pub(crate) fn x402_mainnet_signing_forbidden_result() -> rmcp::model::CallToolResult {
    x402_error_to_tool_result(&stellar_agent_x402::X402Error::MainnetSigningForbidden {
        detail: mainnet_signing_refusal_detail(),
    })
}

/// Returns the structural mainnet-signing refusal for the SEP-53 message-signing
/// tool.
///
/// `stellar_sep53_sign_message` returns a signature the caller can use
/// externally; on a mainnet profile it MUST refuse structurally, before any key
/// access, so no signature is produced. SEP-53 defines a signing payload, not a
/// wallet error wire object, so the refusal surfaces through the documented
/// business-error envelope (`is_error = true`) with the canonical
/// `network.mainnet_write_forbidden` code, correlating with the CLI, submit-layer,
/// and SEP-43/x402 signing guards; the
/// [`stellar_agent_sep53::Sep53Error::MainnetSigningForbidden`] Display — which
/// also embeds that canonical code — is the `error.message`.
pub(crate) fn sep53_mainnet_signing_forbidden_result() -> rmcp::model::CallToolResult {
    let err = stellar_agent_sep53::Sep53Error::MainnetSigningForbidden {
        detail: mainnet_signing_refusal_detail(),
    };
    business_error_result(
        stellar_agent_core::error::NetworkError::MainnetWriteForbidden.code(),
        err.to_string(),
    )
}

/// Returns the structural mainnet-write refusal for the tools that load a
/// ledger signing key to sign and submit.
///
/// The DeFi, commit, and rule-commit tools and the toolset signing route
/// return it first on a mainnet context, before the policy gate, any key
/// access, and any RPC request. The DeFi submit-error renderer
/// `defi_submit_error_result` returns it for
/// `DefiAdapterError::MainnetWriteForbidden`. It is the business-error envelope
/// (`is_error = true`) of
/// [`stellar_agent_core::error::NetworkError::MainnetWriteForbidden`], with the
/// code `network.mainnet_write_forbidden` that the CLI and the submit layer
/// report for the same refusal.
pub(crate) fn mainnet_write_forbidden_result() -> rmcp::model::CallToolResult {
    let err = stellar_agent_core::error::WalletError::Network(
        stellar_agent_core::error::NetworkError::MainnetWriteForbidden,
    );
    business_error_result(err.code(), err.message())
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
/// A coordinate in the owner key namespace is refused before the read, and a
/// key equal to the profile's owner public key is refused after decoding.
/// Both refusals log `validation.key_matches_owner_public_key` at `warn`.
///
/// # Errors
///
/// Returns `Err(ErrorData)` mapping to
/// [`approval_required_indistinguishable`] on any keyring or decode failure
/// and on an owner-key refusal, preserving the indistinguishability invariant
/// at the call site.
///
/// # Security
///
/// The returned key MUST be wrapped in `zeroize::Zeroizing` by the caller to
/// ensure the bytes are zeroed on drop.  This function returns a plain
/// `[u8; 32]` because [`zeroize::Zeroizing`] is not in scope here; the caller
/// wraps immediately.
pub(crate) fn load_attestation_key(
    profile: &stellar_agent_core::profile::schema::Profile,
) -> Result<[u8; 32], rmcp::model::CallToolResult> {
    use base64::Engine as _;
    use keyring_core::Entry as KeyringEntry;
    use stellar_agent_network::keyring::{KeyringOperation, classify_keyring_operation_error};

    let profile_name = stellar_agent_core::profile::name::profile_name_for_approval(profile);
    let entry_ref = &profile.attestation_key_id;
    // The outward wire error stays uniform for every failure mode per the
    // indistinguishability rule (see `approval_required_indistinguishable`), so
    // an oracle cannot tell key-absence from an environmental keyring failure.
    // The classified cause is preserved at debug for operator forensics only.
    // An owner-key refusal is the operator's to fix, so its code is logged at
    // warn; the wire error stays uniform.
    let owner_refusal = |e: &stellar_agent_core::error::WalletError| {
        tracing::warn!(
            profile = %profile_name,
            code = %e.code(),
            "attestation key refused: it is or may be the owner public key"
        );
        approval_required_indistinguishable(&profile_name)
    };
    stellar_agent_core::profile::owner_key::refuse_owner_key_coordinate(
        entry_ref,
        stellar_agent_core::approval::attest::ATTESTATION_KEY_FIELD,
    )
    .map_err(|e| owner_refusal(&e))?;
    let entry = KeyringEntry::new(&entry_ref.service, &entry_ref.account).map_err(|e| {
        tracing::debug!(
            cause = ?classify_keyring_operation_error(&e, KeyringOperation::Construct, &entry_ref.service),
            "attestation key entry open failed"
        );
        approval_required_indistinguishable(&profile_name)
    })?;

    let raw = entry.get_password().map_err(|e| {
        tracing::debug!(
            cause = ?classify_keyring_operation_error(&e, KeyringOperation::Read, &entry_ref.service),
            "attestation key read failed"
        );
        approval_required_indistinguishable(&profile_name)
    })?;

    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(raw.trim())
        .map_err(|e| {
            tracing::debug!(error = %e, "attestation key base64 decode failed");
            approval_required_indistinguishable(&profile_name)
        })?;

    if bytes.len() != 32 {
        tracing::debug!(len = bytes.len(), "attestation key length mismatch");
        return Err(approval_required_indistinguishable(&profile_name));
    }

    stellar_agent_core::profile::owner_key::refuse_owner_public_key(
        &bytes,
        &stellar_agent_core::profile::owner_key::OwnerKeyContext::for_profile(
            &profile_name,
            profile,
        ),
        stellar_agent_core::approval::attest::ATTESTATION_KEY_FIELD,
    )
    .map_err(|e| {
        if matches!(
            e,
            stellar_agent_core::error::WalletError::Validation(
                stellar_agent_core::error::ValidationError::KeyMatchesOwnerPublicKey { .. }
            )
        ) {
            owner_refusal(&e)
        } else {
            tracing::debug!(error = %e, "owner key read failed for the attestation key check");
            approval_required_indistinguishable(&profile_name)
        }
    })?;

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

// ─────────────────────────────────────────────────────────────────────────────
// dispatch_gate: registry lookup, chain validation, policy evaluation
// ─────────────────────────────────────────────────────────────────────────────

/// Builds a tool descriptor whose policy chain is the bound profile's chain.
pub(crate) fn profile_bound_descriptor(
    registry: &HashMap<&'static str, ToolDescriptor>,
    profile: &Profile,
    tool: &str,
) -> Option<ToolDescriptor> {
    let mut descriptor = registry.get(tool)?.clone();
    descriptor.chain_id = profile.chain_id.caip2_str().to_owned();
    Some(descriptor)
}

impl WalletServer {
    /// Builds the call's policy context from the registry and the bound profile.
    ///
    /// Every gated tool matches and accounts against the profile's chain,
    /// including tools whose arguments require no chain identifier.
    pub(crate) fn policy_descriptor(&self, tool_name: &str) -> Option<ToolDescriptor> {
        profile_bound_descriptor(&self.tool_registry, self.security_profile(), tool_name)
    }

    /// The dispatch gate resolves the tool, validates the call chain, and
    /// evaluates policy with the profile-bound descriptor.
    ///
    /// # Steps
    ///
    /// 1. Look up `tool_name` in `self.tool_registry`. Missing → fail-closed
    ///    `internal_error("tool.registry_missing: <name> not found in registry")`.
    /// 2. For tools requiring a chain, validate it against the profile.
    ///    Mismatch returns `invalid_params("chain_id mismatch: <err>")`.
    /// 3. Evaluate policy with the profile-bound descriptor, the args,
    ///    the profile, the optional account/identity views,
    ///    and a counterparty-cache snapshot.
    ///    - `Decision::Allow` → `Ok(DispatchOutcome::Allow(value_effects))`, the
    ///      gate-sized effects (`Some` for a value-moving allow).
    ///    - `Decision::Deny(reason)` → `Err(ToolError::Business)` — a business
    ///      refusal surfaced as the documented result envelope with wire code
    ///      `policy.deny.<reason.code()>` and the redacted `DenyReason`
    ///      (first-5-last-5 on account IDs) carried in the message.
    ///    - `Decision::RequireApproval(req)` → `Ok(DispatchOutcome::RequireApproval(_))`.
    ///      The simulate handler persists a `PendingApproval` and embeds the
    ///      nonce in the response; commit handlers verify the attestation.
    ///    - Any future `Decision` variant not listed above →
    ///      `Err(ToolError::Business)` with wire code
    ///      `policy.unexpected_decision` (forward-compat catch-all).
    ///    - `Err` → `Err(ToolError::Business)` with wire code
    ///      `policy.engine_required`.
    ///
    /// # Errors
    ///
    /// Returns `Err(ToolError)` for every gate failure: policy refusals as
    /// [`ToolError::Business`] (result envelope),
    /// malformed-argument / registry / chain-id faults as
    /// [`ToolError::Protocol`] (JSON-RPC error). Fold back into a handler's
    /// return type with [`ToolError::into_result`].
    pub(crate) async fn dispatch_gate(
        &self,
        tool_name: &'static str,
        args_value: &Value,
        chain_id: &str,
    ) -> Result<DispatchOutcome, ToolError> {
        self.dispatch_gate_inner(tool_name, args_value, chain_id, None, None, None, false)
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
    ) -> Result<DispatchOutcome, ToolError> {
        self.dispatch_gate_inner(
            tool_name,
            args_value,
            chain_id,
            None,
            account_view,
            identity_view,
            false,
        )
        .await
    }

    /// Value-carrying gate for single-shot Soroban tools (DeFi, x402, MPP charge)
    /// whose value effects cannot appear in the pre-decode `args`.
    ///
    /// The handler decodes the operation ONCE, derives the
    /// [`ValueClass`](stellar_agent_core::policy::v1::ValueClass) from that SAME
    /// decode (single-decode invariant §2.1), and passes it here. The gate feeds
    /// it to [`PolicyEngine::evaluate_with_value`](stellar_agent_core::policy::PolicyEngine::evaluate_with_value)
    /// so the value criteria size the exact effect that will be signed. A
    /// `MovesValue` tool that reaches this gate MUST supply
    /// [`ValueClass::Value`]; supplying `ReadOnly`/`Opaque` makes the value
    /// criteria deny fail-closed (`policy.deny.unsizable_value_effect`).
    ///
    /// # Errors
    ///
    /// Same failure modes as [`Self::dispatch_gate_with_views`].
    pub(crate) async fn dispatch_gate_with_value(
        &self,
        tool_name: &'static str,
        args_value: &Value,
        chain_id: &str,
        value: stellar_agent_core::policy::v1::ValueClass,
        account_view: Option<&dyn stellar_agent_core::policy::v1::AccountReservesView>,
        identity_view: Option<&dyn stellar_agent_core::policy::v1::AccountIdentityView>,
    ) -> Result<DispatchOutcome, ToolError> {
        self.dispatch_gate_inner(
            tool_name,
            args_value,
            chain_id,
            Some(value),
            account_view,
            identity_view,
            false,
        )
        .await
    }

    /// Settles the spending-window reservations that have stood long enough to
    /// be settleable, before the gate reads them.
    ///
    /// Never fails the dispatch. An endpoint that cannot be reached, a
    /// receipt store that cannot be opened, and a window file that cannot be
    /// read all leave every reservation standing, which is the direction that
    /// keeps the operator's caps honest: a reservation that may still apply
    /// keeps counting.
    async fn reconcile_open_reservations(&self) {
        let Ok(now_ms) = stellar_agent_core::timefmt::now_unix_ms() else {
            tracing::debug!("window reconcile: system clock unavailable; reservations stand");
            return;
        };
        let Ok(client) = self.context.primary_client() else {
            return;
        };
        let profile_name = self.profile_name_for_approval();
        let receipts = stellar_agent_core::profile::receipt::ReceiptStore::open(&profile_name).ok();
        let window = stellar_agent_network::policy_state::PersistedWindowStore::at_path(
            self.window_path.clone(),
        );
        let report = match window
            .reconcile_due(
                self.security_profile(),
                &client,
                receipts.as_ref(),
                now_ms,
                stellar_agent_network::policy_state::RECONCILE_BUDGET,
            )
            .await
        {
            Ok(report) => report,
            Err(e) => {
                tracing::debug!(
                    profile = %profile_name,
                    error = ?e,
                    "window reconcile: pass failed; open reservations stand"
                );
                return;
            }
        };

        // A submission the pass settled is owed the value-action row it never
        // got to write. The writer is the same keyed one every value verb
        // uses, so a log that cannot be appended leaves the row owed rather
        // than the settlement undone.
        if report.settled.is_empty() {
            return;
        }
        let Ok(audit) = crate::tools::value_audit::require_value_audit_writer(
            self.security_profile(),
            &profile_name,
            self.audit_binding,
        ) else {
            tracing::debug!(
                profile = %profile_name,
                settled = report.settled.len(),
                "window reconcile: no audit writer; the settled rows stay owed"
            );
            return;
        };
        for settled in &report.settled {
            crate::tools::submission_record::write_settled_row(
                self.security_profile(),
                &profile_name,
                &audit,
                &settled.envelope_hash,
                &settled.tx_hash,
                &settled.status,
                settled.release_code,
                settled.ledger,
                stellar_agent_core::audit_log::PolicyDecision::Allow,
            );
        }
    }

    /// Checks policy inputs against the profile-bound descriptor.
    fn checked_policy_descriptor(
        &self,
        tool_name: &'static str,
        args_value: &Value,
        chain_id: &str,
    ) -> Result<ToolDescriptor, ToolError> {
        // Pre-step: dangerous-key guard.
        //
        // Reuse the same guard that toolset dispatch applies (validate_toolset_tool_args).
        // For first-party tools the args are not attacker-authored in the normal
        // flow, but a compromised upstream agent can route attacker JSON here.
        // Applying the guard at this chokepoint covers ALL first-party tools
        // without per-tool duplication.
        //
        // Note: toolset dispatch sites apply this guard before calling dispatch_gate,
        // so toolset-routed calls get a second (idempotent) application here, which
        // adds defence-in-depth at the chokepoint.
        stellar_agent_toolsets::validate_toolset_tool_args(args_value).map_err(|e| {
            ToolError::Protocol(ErrorData::invalid_params(
                format!("args.validation: {e}"),
                None,
            ))
        })?;

        // Resolve the profile-bound policy descriptor.
        let descriptor = match self.policy_descriptor(tool_name) {
            Some(d) => d,
            None => {
                return Err(ToolError::Protocol(ErrorData::internal_error(
                    format!("tool.registry_missing: {tool_name} not found in registry"),
                    None,
                )));
            }
        };

        // Required call chains match the profile before policy evaluation.
        if descriptor.chain_id_required
            && let Err(err) = validate_chain_id_matches_profile(chain_id, self.security_profile())
        {
            return Err(ToolError::Protocol(ErrorData::invalid_params(
                format!("chain_id mismatch: {err}"),
                None,
            )));
        }

        Ok(descriptor)
    }

    /// Evaluates `tool_name` against the engine's current window state without
    /// reconciling, refreshing, or writing anything.
    ///
    /// The gate runs the same evaluation after its refresh, and a simulate step
    /// calls this for its paired commit tool. Every verdict, `Deny` included,
    /// returns to the caller for inspection.
    ///
    /// # Errors
    ///
    /// Returns [`ToolError`] for a descriptor, chain, or engine failure.
    pub(crate) async fn evaluate_policy_only(
        &self,
        tool_name: &'static str,
        args_value: &Value,
        chain_id: &str,
        value: Option<stellar_agent_core::policy::v1::ValueClass>,
        account_view: Option<&dyn stellar_agent_core::policy::v1::AccountReservesView>,
        identity_view: Option<&dyn stellar_agent_core::policy::v1::AccountIdentityView>,
    ) -> Result<stellar_agent_core::policy::Evaluation, ToolError> {
        let descriptor = self.checked_policy_descriptor(tool_name, args_value, chain_id)?;
        self.evaluate_with_descriptor(&descriptor, args_value, value, account_view, identity_view)
            .await
    }

    /// Evaluates policy for a descriptor that [`Self::checked_policy_descriptor`]
    /// returned, so a gate dispatch checks its inputs once.
    ///
    /// # Errors
    ///
    /// Returns `policy.engine_required` when the engine fails to evaluate.
    async fn evaluate_with_descriptor(
        &self,
        descriptor: &ToolDescriptor,
        args_value: &Value,
        value: Option<stellar_agent_core::policy::v1::ValueClass>,
        account_view: Option<&dyn stellar_agent_core::policy::v1::AccountReservesView>,
        identity_view: Option<&dyn stellar_agent_core::policy::v1::AccountIdentityView>,
    ) -> Result<stellar_agent_core::policy::Evaluation, ToolError> {
        let counterparty_cache =
            match stellar_agent_network::CounterpartyCacheSnapshot::from_resolver(
                &*self.counterparty_resolver,
            )
            .await
            {
                Ok(snapshot) => Some(snapshot),
                Err(err) => {
                    tracing::debug!(
                        tool = descriptor.name.as_str(),
                        error = %err,
                        "evaluate_with_descriptor: counterparty cache snapshot unavailable"
                    );
                    None
                }
            };

        // Evaluate policy with the profile-bound descriptor.
        //
        // The value-carrying path (`value = Some`) sizes the exact effect the
        // handler decoded; the args-derived path (`value = None`) lets the engine
        // derive the descriptor from `args_value` (pay/create/opaque-sign tools).
        let counterparty_view = counterparty_cache
            .as_ref()
            .map(|snapshot| snapshot as &dyn stellar_agent_core::policy::v1::CounterpartyCacheView);
        // The `_full` evaluation additionally surfaces the value descriptor the
        // gate sized on the allow path, threaded into `DispatchOutcome::Allow` so
        // the value-verb handlers record exactly what the gate evaluated.
        let evaluation = match value {
            Some(value) => self.policy_engine.evaluate_with_value_full(
                descriptor,
                args_value,
                self.security_profile(),
                value,
                account_view,
                identity_view,
                counterparty_view,
                None,
                None,
            ),
            None => self.policy_engine.evaluate_full(
                descriptor,
                args_value,
                self.security_profile(),
                account_view,
                identity_view,
                counterparty_view,
                None,
                None, // sep45_sessions: wired at dispatch site when sep45_session_active criterion active
            ),
        };
        let evaluation = match evaluation {
            Ok(evaluation) => evaluation,
            Err(err) => {
                // Engine error → fail closed as `policy.engine_required`
                // (fires for `Noop` and for `V1` engine errors such as a
                // missing policy document).
                return Err(ToolError::Business(business_error_result(
                    "policy.engine_required",
                    format!("policy engine evaluation failed: {err}"),
                )));
            }
        };
        Ok(evaluation)
    }

    /// Evaluates the paired commit before an admitted preparation persists approval.
    /// Mainnet uses the tighter evaluated lifetime and refuses undecodable or denied actions.
    pub(crate) async fn paired_commit_outcome(
        &self,
        outcome: DispatchOutcome,
        envelope_xdr: &str,
        commit_tool: &'static str,
        chain_id: &str,
        account_view: Option<&dyn stellar_agent_core::policy::v1::AccountReservesView>,
        identity_view: Option<&dyn stellar_agent_core::policy::v1::AccountIdentityView>,
    ) -> Result<DispatchOutcome, ToolError> {
        let mainnet = self.mainnet_context.is_some();
        if !mainnet && !matches!(outcome, DispatchOutcome::Allow(_)) {
            return Ok(outcome);
        }
        let mut commit_args = match stellar_agent_core::envelope_decode::decode_authoritative_args(
            envelope_xdr,
            commit_tool,
        ) {
            Ok(args) => args,
            Err(err) => {
                tracing::debug!(
                    tool = commit_tool,
                    error_kind = envelope_decode_error_kind(&err),
                    "paired commit arguments cannot be decoded"
                );
                return if mainnet {
                    Err(ToolError::Business(business_error_result(
                        "simulation.divergence",
                        "paired commit envelope cannot be decoded",
                    )))
                } else {
                    Ok(outcome)
                };
            }
        };
        commit_args["chain_id"] = Value::String(chain_id.to_owned());
        let evaluation = match self
            .evaluate_policy_only(
                commit_tool,
                &commit_args,
                chain_id,
                None,
                account_view,
                identity_view,
            )
            .await
        {
            Ok(evaluation) => evaluation,
            Err(error) if mainnet => return Err(error),
            Err(_) => return Ok(outcome),
        };
        if let Decision::Deny(reason) = &evaluation.decision {
            return if mainnet {
                Err(ToolError::Business(policy_denial_error_result(reason)))
            } else {
                Ok(outcome)
            };
        }
        let paired_ttl_ms = stellar_agent_core::approval::governing_ttl_ms(&evaluation);
        let ttl_ms = outcome.governing_ttl_ms().min(paired_ttl_ms);
        let paired = match evaluation.decision {
            Decision::RequireApproval(request) => {
                DispatchOutcome::RequireApproval(ApprovalOutcome {
                    request,
                    value_effects: evaluation.value_effects,
                    governing_ttl_ms: paired_ttl_ms,
                })
            }
            Decision::Allow => outcome,
            _ => {
                return Err(ToolError::Business(business_error_result(
                    "policy.unexpected_decision",
                    "unrecognized paired policy decision",
                )));
            }
        };
        if mainnet {
            paired.require_mainnet_confirmation(ttl_ms)
        } else {
            Ok(paired)
        }
    }

    pub(crate) fn force_mainnet_confirmation(
        &self,
        tool: &str,
        outcome: DispatchOutcome,
    ) -> Result<DispatchOutcome, ToolError> {
        if self.mainnet_context.is_some() && requires_mainnet_confirmation(tool) {
            let ttl_ms = outcome.governing_ttl_ms();
            outcome.require_mainnet_confirmation(ttl_ms)
        } else {
            Ok(outcome)
        }
    }

    /// Refreshes verified local state without reconciling through RPC.
    #[cfg(feature = "mainnet-write")]
    pub(crate) async fn dispatch_preparation(
        &self,
        tool: &'static str,
        args: &Value,
        chain: &str,
        value: stellar_agent_core::policy::v1::ValueClass,
    ) -> Result<DispatchOutcome, ToolError> {
        self.dispatch_gate_inner(tool, args, chain, Some(value), None, None, true)
            .await
    }

    /// Shared gate core. `value` is `Some` for the value-carrying path
    /// ([`Self::dispatch_gate_with_value`]) and `None` for the args-derived path
    /// ([`Self::dispatch_gate`] / [`Self::dispatch_gate_with_views`]).
    #[allow(
        clippy::too_many_arguments,
        reason = "dispatch carries independent checked views and preparation mode"
    )]
    async fn dispatch_gate_inner(
        &self,
        tool_name: &'static str,
        args_value: &Value,
        chain_id: &str,
        value: Option<stellar_agent_core::policy::v1::ValueClass>,
        account_view: Option<&dyn stellar_agent_core::policy::v1::AccountReservesView>,
        identity_view: Option<&dyn stellar_agent_core::policy::v1::AccountIdentityView>,
        preparation: bool,
    ) -> Result<DispatchOutcome, ToolError> {
        let descriptor = self.checked_policy_descriptor(tool_name, args_value, chain_id)?;

        // Settle the reservations that have stood long enough to be
        // settleable, before the refresh below reads them.
        //
        // The order is deliberate: this pass writes the window FILE, and the
        // refresh below replaces the engine's in-memory view from that file.
        // Running it the other way round would leave the engine holding a view
        // the pass had just invalidated for the rest of the dispatch.
        //
        // A reservation counts against the operator's caps while it stands, so
        // the oldest few are asked about first. This pass is not a gate: a
        // failure to reach the endpoint leaves every reservation standing and
        // the dispatch continues, because counting a reservation that may
        // still apply is the safe direction. It never joins the hydration
        // errors below, which are fail-closed for a different reason.
        //
        // Only for a dispatch whose headroom the reservations actually shape.
        // A read-only tool spends none, so settling before it would buy two
        // keyring reads, an HMAC verify and a receipt-store read per call for
        // an answer nothing in that call uses.
        if !preparation
            && descriptor.value_kind != stellar_agent_core::policy::ToolValueKind::ReadOnly
            && self.policy_engine.window_state_store().is_some()
        {
            self.reconcile_open_reservations().await;
        }

        // Refresh window state before evaluation.
        //
        // The MCP server is a long-lived process: `self.policy_engine` is
        // constructed once and evaluates every dispatch for the life of the
        // server. Without this step, its in-memory window-state store would
        // be a startup-frozen snapshot, invisible to entries the CLI (or a
        // sibling request) has since recorded on disk. This is a REPLACE,
        // not a merge: `clear()` first, then `load_into` re-populates from
        // the CURRENT on-disk file — see `stellar_agent_network::policy_state`'s
        // module docs for the full rationale, the known intra-process race
        // this does NOT close, and why construction-time hydration is kept
        // in addition to this per-dispatch refresh.
        //
        // `window_state_store()` returns `None` for `NoopPolicyEngine` (no
        // window state to refresh) — this step is then a no-op. A refresh
        // failure (tampered/rolled-back/deleted store) is fail-closed: the
        // dispatch refuses rather than evaluating stateful criteria against
        // a store this process could not verify.
        if let Some(store) = self.policy_engine.window_state_store() {
            store.clear().map_err(|e| {
                ToolError::Business(business_error_result(
                    "policy.engine_required",
                    format!("policy window-state refresh failed (in-memory clear): {e}"),
                ))
            })?;
            let profile_name = self.profile_name_for_approval();
            let window_store = stellar_agent_network::policy_state::PersistedWindowStore::at_path(
                self.window_path.clone(),
            );
            if let Err(e) = window_store.load_into(&profile_name, self.security_profile(), store) {
                return Err(ToolError::Business(business_error_result(
                    "policy.engine_required",
                    format!(
                        "policy window-state store failed to refresh ({e}); stop the MCP server, \
                         then run `profile reset-window-state {profile_name} --reason <reason>` \
                         to recover; the running server holds the audit writer"
                    ),
                )));
            }
        }

        let evaluation = self
            .evaluate_with_descriptor(&descriptor, args_value, value, account_view, identity_view)
            .await?;
        let governing_ttl_ms = stellar_agent_core::approval::governing_ttl_ms(&evaluation);
        let value_effects = evaluation.value_effects;
        let outcome = match evaluation.decision {
            Decision::Allow => DispatchOutcome::Allow(AllowOutcome {
                value_effects,
                governing_ttl_ms,
            }),

            Decision::Deny(reason) => {
                // Redact account IDs in CounterpartyDenied before serialising
                // into the wire message. A policy denial is a business refusal the
                // agent branches on, so it surfaces as the documented result
                // envelope with wire code `policy.deny.<reason.code()>`. The
                // redacted `DenyReason` (first-5-last-5 on account IDs) is carried
                // in the message so no structured detail is lost in the move from
                // the JSON-RPC `data` field.
                return Err(ToolError::Business(policy_denial_error_result(&reason)));
            }

            Decision::RequireApproval(req) => {
                // Return the ApprovalRequest to the caller; simulate handlers
                // persist a PendingApproval entry; commit handlers verify
                // the attestation before proceeding.  Do NOT produce a wire
                // error here — that is the job of commit handlers that receive
                // a commit call without valid attestation.
                DispatchOutcome::RequireApproval(ApprovalOutcome {
                    request: req,
                    governing_ttl_ms,
                    value_effects,
                })
            }

            // Forward-compat catch-all: Decision is #[non_exhaustive]; any future
            // variant not handled above falls here so the gate stays fail-closed.
            _ => {
                return Err(ToolError::Business(business_error_result(
                    "policy.unexpected_decision",
                    "the policy engine returned a decision this build does not \
                     recognise; the operation is refused fail-closed",
                )));
            }
        };

        Ok(outcome)
    }
}

fn requires_mainnet_confirmation(tool: &str) -> bool {
    matches!(
        tool,
        "stellar_pay"
            | "stellar_pay_commit"
            | "stellar_claim"
            | "stellar_claim_commit"
            | "stellar_create_account"
            | "stellar_create_account_commit"
            | "stellar_trustline"
            | "stellar_trustline_commit"
            | "stellar_x402_create_payment"
            | "stellar_x402_authenticated_payment"
    )
}

/// Names the kind of an envelope decode failure without the values its
/// message can carry, such as an asset code.
fn envelope_decode_error_kind(
    err: &stellar_agent_core::envelope_decode::EnvelopeDecodeError,
) -> &'static str {
    use stellar_agent_core::envelope_decode::EnvelopeDecodeError;
    match err {
        EnvelopeDecodeError::Base64Decode { .. } => "base64_decode",
        EnvelopeDecodeError::XdrDecode { .. } => "xdr_decode",
        EnvelopeDecodeError::NotTransactionV1 => "not_transaction_v1",
        EnvelopeDecodeError::UnexpectedOperationCount { .. } => "unexpected_operation_count",
        EnvelopeDecodeError::OperationKindMismatch { .. } => "operation_kind_mismatch",
        EnvelopeDecodeError::UnsupportedTool { .. } => "unsupported_tool",
        EnvelopeDecodeError::IssuerEncodeFailed { .. } => "issuer_encode_failed",
        _ => "unrecognised",
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
) -> Result<(), ToolError> {
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
        ToolError::Protocol(ErrorData::internal_error(
            format!("internal_error: spawn_blocking join error: {e}"),
            None,
        ))
    })?;

    if let Err(err) = hmac_result {
        tracing::debug!(error = %err, "nonce HMAC/expiry verification failed");
        return Err(ToolError::Business(nonce_verification_error_result(&err)));
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
        return Err(ToolError::Business(nonce_replayed_error_result()));
    }

    Ok(())
}

/// Builds the nonce-verification business-error envelope.
///
/// Collapses `Expired` and `HmacMismatch` to a byte-identical envelope (code
/// `nonce.expired`, same message) so the wire cannot distinguish the two; the
/// detailed reason is operator-visible via `tracing::debug!` only. Every other
/// typed variant carries its own `wire_code()` and Display message.
fn nonce_verification_error_result(err: &NonceError) -> rmcp::model::CallToolResult {
    match err {
        // Indistinguishability: collapse Expired and HmacMismatch to the
        // same generic envelope.  Agent recovery is identical (re-simulate).
        NonceError::Expired | NonceError::HmacMismatch => business_error_result(
            "nonce.expired",
            "nonce expired or invalid; re-simulate to obtain a fresh nonce",
        ),
        other => business_error_result(other.wire_code(), other.to_string()),
    }
}

/// Collapses commit-path memo, envelope-build, and oracle-build failures to the
/// same public recovery envelope as expired/HMAC-mismatched nonces.
///
/// The detailed commit-path error remains operator-visible through debug
/// tracing only; callers must not expose memo parse, payment-builder,
/// envelope-builder, or oracle-builder distinctions on the wire.
///
/// Delegates to `nonce_verification_error_result(&NonceError::Expired)` so the
/// wire-byte equality with the nonce-expiry path is structurally guaranteed
/// rather than enforced only by test. A future edit to the collapsed message
/// in `nonce_verification_error_result` propagates here automatically.
pub(crate) fn commit_path_error_result(err: impl std::fmt::Display) -> rmcp::model::CallToolResult {
    tracing::debug!(error = %err, "stellar_pay_commit commit-path error collapsed");
    nonce_verification_error_result(&NonceError::Expired)
}

fn nonce_replayed_error_result() -> rmcp::model::CallToolResult {
    business_error_result(
        "nonce.replayed",
        "this nonce has already been used; re-simulate to obtain a fresh nonce",
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// verify_attestation_gate — shared attestation-gate helper
// ─────────────────────────────────────────────────────────────────────────────

/// Envelope approval kind required by a commit tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GatedApprovalKind {
    /// Payments and account creation.
    Payment,
    /// Claimable balance claims.
    Claim,
    /// Trustline changes.
    Trustline,
    /// Plain x402 payment intent.
    #[cfg(feature = "mainnet-write")]
    X402,
}

impl GatedApprovalKind {
    pub(crate) fn expectation(
        self,
        subject: [u8; 32],
    ) -> stellar_agent_core::approval::witness::ApprovalExpectation {
        use stellar_agent_core::approval::witness::{ApprovalExpectation, ApprovedKind};
        let kind = match self {
            Self::Payment => ApprovedKind::Payment,
            Self::Claim => ApprovedKind::Claim,
            Self::Trustline => ApprovedKind::Trustline,
            #[cfg(feature = "mainnet-write")]
            Self::X402 => ApprovedKind::X402Payment,
        };
        ApprovalExpectation { kind, subject }
    }
}

/// Runs the 8-step attestation verification gate for a `*_commit` MCP tool.
///
/// Payments, claims, account creation and trustlines share this approval gate.
/// The attestation binds the profile name and chain id. Call this gate
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
///    A submission receipt holding the nonce reports consumption before the store opens.
/// 3. Approval store opens at `<approvals_dir>/<profile_name>.toml`.
/// 4. Entry exists in the store.
/// 5. Entry is not expired.
/// 6. The kind matches the tool, and the envelope SHA-256 matches the stored hash.
/// 7. Attestation key loads from the keyring.
/// 8. HMAC-SHA256 verifies byte-for-byte (constant-time).
///
/// # Errors
///
/// Live rejection and consumption markers retain their terminal error codes.
/// A durable receipt holding the nonce also reports `policy.approval_consumed`.
/// Other failures produce [`approval_required_indistinguishable`].
/// Internal debug tracing identifies the refusal for operator forensics.
///
/// Returns `Ok(None)` when `dispatch_outcome` is `DispatchOutcome::Allow`,
/// where the gate is a no-op. When every step passes, an admitted mainnet
/// server returns `Ok(Some(witness))`, the sealed approval witness core's
/// `verify_approval` produces for the resolver, and every other server
/// returns `Ok(None)`.
pub(crate) async fn verify_attestation_gate(
    server: &WalletServer,
    dispatch_outcome: &DispatchOutcome,
    expected_kind: GatedApprovalKind,
    envelope_xdr: &str,
    approval_nonce: Option<&str>,
    approval_attestation: Option<&str>,
    tool_name: &'static str,
) -> Result<
    Option<stellar_agent_core::approval::witness::ApprovalWitness>,
    rmcp::model::CallToolResult,
> {
    use stellar_agent_core::approval::subject::approval_subject_classic;
    let expected = expected_kind.expectation(approval_subject_classic(envelope_xdr));
    verify_attestation_subject_gate(
        server,
        dispatch_outcome,
        expected,
        approval_nonce,
        approval_attestation,
        tool_name,
    )
    .await
}

pub(crate) async fn verify_attestation_subject_gate(
    server: &WalletServer,
    dispatch_outcome: &DispatchOutcome,
    expected: stellar_agent_core::approval::witness::ApprovalExpectation,
    approval_nonce: Option<&str>,
    approval_attestation: Option<&str>,
    tool_name: &'static str,
) -> Result<
    Option<stellar_agent_core::approval::witness::ApprovalWitness>,
    rmcp::model::CallToolResult,
> {
    use base64::Engine as _;
    use stellar_agent_core::approval::{
        DEFAULT_RETRY_ATTEMPTS, DEFAULT_RETRY_BACKOFF, open_with_retry, verify_attestation,
    };
    use stellar_agent_core::profile::schema::default_approval_dir;

    let DispatchOutcome::RequireApproval(approval) = dispatch_outcome else {
        return Ok(None);
    };

    let profile_name = server.profile_name_for_approval();

    // 1. Both fields must be present.
    let (approval_nonce_str, attestation_b64) = match (approval_nonce, approval_attestation) {
        (Some(n), Some(a)) => (n, a),
        _ => {
            tracing::debug!(
                tool = tool_name,
                "approval_nonce or approval_attestation absent"
            );
            return Err(approval_required_indistinguishable(&profile_name));
        }
    };

    // 2. Decode attestation blob (must be exactly 32 bytes).
    let attestation_bytes: [u8; 32] = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(attestation_b64)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| {
            tracing::debug!(tool = tool_name, "attestation base64 decode failed");
            approval_required_indistinguishable(&profile_name)
        })?;

    // A receipt that holds the nonce proves the approval was spent, also while
    // its tombstone is owed. It is read before the mutable approval store, so a
    // locked store or an expired entry cannot hide the spend.
    let receipt_hold = stellar_agent_core::profile::receipt::ReceiptStore::open(&profile_name)
        .and_then(|receipts| receipts.find_by_approval_nonce(approval_nonce_str));
    if matches!(&receipt_hold, Ok(Some(_))) {
        return Err(approval_consumed_error());
    }

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
                approval_required_indistinguishable(&profile_name)
            })?
        }
    };
    #[cfg(not(any(test, feature = "test-helpers")))]
    let approvals_dir = default_approval_dir().map_err(|e| {
        tracing::debug!(tool = tool_name, "approval dir resolution failed");
        tracing::trace!(error = %e, tool = tool_name, "approval dir resolution failure detail");
        approval_required_indistinguishable(&profile_name)
    })?;
    let store_path = approvals_dir.join(format!("{profile_name}.toml"));
    let store = open_with_retry(&store_path, DEFAULT_RETRY_ATTEMPTS, DEFAULT_RETRY_BACKOFF)
        .map_err(|e| {
            tracing::debug!(tool = tool_name, "approval store open failed");
            tracing::trace!(error = %e, tool = tool_name, "approval store open failure detail");
            approval_required_indistinguishable(&profile_name)
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
            return Err(approval_required_indistinguishable(&profile_name));
        }
    };

    // 5. Confirm not expired.
    let now_ms_attest = server.clock.now_unix_ms().map_err(|e| {
        tracing::debug!(error = %e, tool = tool_name, "clock error for expiry check");
        approval_required_indistinguishable(&profile_name)
    })?;
    // The requiring rule's lifetime bounds the entry as well as the stored expiry.
    let rule_expires_at_unix_ms = entry
        .created_at_unix_ms
        .saturating_add(approval.governing_ttl_ms);
    if entry.is_expired(now_ms_attest) || rule_expires_at_unix_ms <= now_ms_attest {
        tracing::debug!(
            nonce = %approval_nonce_str,
            tool = tool_name,
            "approval entry expired"
        );
        return Err(approval_required_indistinguishable(&profile_name));
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

    // 5c. A consumption tombstone refuses before any attestation check: the
    //     entry retains the attestation blob it was committed under, so an
    //     attestation check would pass and admit a second commit on an
    //     approval that has already been spent.
    if matches!(
        entry.kind,
        stellar_agent_core::approval::ApprovalKind::Consumed { .. }
    ) {
        tracing::debug!(
            nonce = %approval_nonce_str,
            tool = tool_name,
            "approval entry was already spent on a submission"
        );
        return Err(approval_consumed_error());
    }

    // An unreadable receipt still refuses before any approval can admit a send.
    receipt_hold.map_err(|_| approval_required_indistinguishable(&profile_name))?;

    if server.mainnet_context.is_some() {
        // Preserve the key-loader's indistinguishable rendering and operator diagnostics.
        let _key = zeroize::Zeroizing::new(load_attestation_key(server.security_profile())?);
        return stellar_agent_core::approval::witness::verify_approval(
            &store,
            server.security_profile(),
            &profile_name,
            approval_nonce_str,
            &attestation_bytes,
            &expected,
            now_ms_attest,
        )
        .map(Some)
        .map_err(|error| {
            // Steps 5b and 5c above already answered a rejected or consumed
            // entry with its own code, so every refusal here is uniform.
            tracing::debug!(
                tool = tool_name,
                code = error.code(),
                "approval proof refused"
            );
            if error.code() == "validation.key_matches_owner_public_key" {
                tracing::warn!(code = error.code(), "attestation owner key refused");
            }
            approval_required_indistinguishable(&profile_name)
        });
    }

    // 6. The tool accepts only its own envelope approval kind.
    let stored_sha256_hex = match &entry.kind {
        stellar_agent_core::approval::ApprovalKind::PaymentSimulated {
            envelope_sha256_hex,
            ..
        } if expected.kind == stellar_agent_core::approval::witness::ApprovedKind::Payment => {
            envelope_sha256_hex.clone()
        }
        stellar_agent_core::approval::ApprovalKind::ClaimSimulated {
            envelope_sha256_hex,
            ..
        } if expected.kind == stellar_agent_core::approval::witness::ApprovedKind::Claim => {
            envelope_sha256_hex.clone()
        }
        stellar_agent_core::approval::ApprovalKind::TrustlineSimulated {
            envelope_sha256_hex,
            ..
        } if expected.kind == stellar_agent_core::approval::witness::ApprovedKind::Trustline => {
            envelope_sha256_hex.clone()
        }
        other => {
            tracing::debug!(
                kind = other.kind_name(),
                tool = tool_name,
                kind = ?expected.kind,
                "approval kind mismatch"
            );
            return Err(approval_required_indistinguishable(&profile_name));
        }
    };
    let presented_sha256 = expected.subject;
    let presented_sha256_hex = hash_to_lower_hex(&Hash(presented_sha256));
    if presented_sha256_hex != stored_sha256_hex {
        tracing::debug!(
            presented = %presented_sha256_hex,
            stored = %stored_sha256_hex,
            tool = tool_name,
            "envelope hash mismatch"
        );
        return Err(approval_required_indistinguishable(&profile_name));
    }

    // 7. Load attestation key from keyring (zeroized via drop).
    let attestation_key_bytes = load_attestation_key(&server.profile)?;
    let attestation_key = zeroize::Zeroizing::new(attestation_key_bytes);

    // 8. Verify HMAC (constant-time) under the layout the record names; a
    // version this build does not read verifies nothing.
    let Some(scope) = entry.attestation_scope() else {
        tracing::debug!(
            nonce = %approval_nonce_str,
            tool = tool_name,
            version = entry.attestation_version,
            "unsupported attestation version"
        );
        return Err(approval_required_indistinguishable(&profile_name));
    };
    if !verify_attestation(
        &attestation_key,
        &stellar_agent_core::approval::AttestationBinding::new(
            &profile_name,
            server.context.chain_id.caip2_str(),
        ),
        approval_nonce_str,
        &presented_sha256,
        &entry.process_uid,
        &scope,
        &attestation_bytes,
    ) {
        tracing::debug!(
            nonce = %approval_nonce_str,
            tool = tool_name,
            "HMAC attestation verification failed"
        );
        return Err(approval_required_indistinguishable(&profile_name));
    }
    // Attestation key zeroized here on `attestation_key` drop (Zeroizing fires).

    Ok(None)
}

impl WalletServer {
    pub(crate) fn check_write_fee(
        &self,
        fee: u32,
        source: stellar_agent_core::error::FeeSource,
    ) -> Result<(), stellar_agent_core::WalletError> {
        let signed = self
            .verified_policy
            .as_ref()
            .and_then(|policy| policy.mainnet())
            .map(|body| body.classic_max_fee_per_op_stroops);
        stellar_agent_network::fees::check_classic_fee_cap_signed(
            fee,
            source,
            self.security_profile(),
            signed,
        )
    }

    pub(crate) async fn classic_witness(
        &self,
        value: stellar_agent_core::cross_check::CrossCheckValue<'_>,
        inputs: impl Into<stellar_agent_network::cross_check::ClassicInputs>,
        envelope: &str,
        tool: &'static str,
    ) -> Result<
        stellar_agent_network::cross_check::CrossCheckOutcome,
        stellar_agent_core::WalletError,
    > {
        if let Some(context) = &self.mainnet_context {
            let thresholds = stellar_agent_core::cross_check::ThresholdSet::from_profile_and_signed(
                context.profile(),
                self.verified_policy
                    .as_ref()
                    .and_then(|policy| policy.mainnet())
                    .and_then(|body| body.cross_check_thresholds.as_ref()),
            );
            stellar_agent_network::cross_check::obtain_classic_witness_bound(
                context.profile(),
                &context.network_context(),
                value,
                inputs,
                envelope,
                &thresholds,
                tool,
            )
            .await
        } else {
            stellar_agent_network::cross_check::obtain_classic_witness(
                &self.profile,
                &self.context,
                value,
                inputs,
                tool,
            )
            .await
        }
    }

    pub(crate) fn write_audit(
        &self,
    ) -> Result<
        (
            stellar_agent_network::submission_record::AuditWriterHandle,
            Option<stellar_agent_network::mainnet::audit_readiness::AuditReadiness>,
        ),
        stellar_agent_core::WalletError,
    > {
        if let Some(context) = &self.mainnet_context {
            let readiness = stellar_agent_network::mainnet::audit_readiness::audit_readiness(
                context.profile(),
                context.profile_name(),
            )?;
            Ok((Arc::clone(readiness.writer()), Some(readiness)))
        } else {
            crate::tools::value_audit::require_value_audit_writer(
                &self.profile,
                &self.profile_name_for_approval(),
                self.audit_binding,
            )
            .map(|writer| (writer, None))
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
pub(crate) mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, Ordering},
    };
    use stellar_agent_core::AuthError;

    // ── decode_payment_required_input ───────────────────────────────────────────

    /// Raw-JSON requirements whose field has the wrong type report the JSON
    /// error class and position; the marker value never reaches the detail.
    #[test]
    fn decode_payment_required_input_fallback_drops_decoded_values() {
        let input = r#"{"scheme":"exact","maxTimeoutSeconds":"MARKERSECRET"}"#;
        let err = decode_payment_required_input(input).unwrap_err();
        let stellar_agent_x402::X402Error::InvalidPaymentRequired { detail } = &err else {
            panic!("expected InvalidPaymentRequired, got {err:?}");
        };
        assert_eq!(
            detail,
            "the PaymentRequirements input has a missing field or a field of the wrong type \
             or value (line 1, column 52)"
        );
        assert!(!format!("{err} {err:?}").contains("MARKER"), "{err:?}");
    }

    /// A base64 input whose decoded payload has a field of the wrong type
    /// reports that payload's failure by class and position, not the raw-JSON
    /// failure of the base64 text, and without the field's value.
    #[test]
    fn decode_payment_required_input_reports_the_base64_payload_error() {
        use base64::Engine as _;
        let input = base64::engine::general_purpose::STANDARD
            .encode(r#"{"scheme":"exact","maxTimeoutSeconds":"MARKERSECRET"}"#);
        let err = decode_payment_required_input(&input).unwrap_err();
        let stellar_agent_x402::X402Error::InvalidPaymentRequired { detail } = &err else {
            panic!("expected InvalidPaymentRequired, got {err:?}");
        };
        assert_eq!(
            detail,
            "the PAYMENT-REQUIRED payload has a missing field or a field of the wrong type \
             or value (line 1, column 52)"
        );
        assert!(!format!("{err} {err:?}").contains("MARKER"), "{err:?}");
    }

    // ── submit_timeout ──────────────────────────────────────────────────────────

    /// An unset `submit_timeout_seconds` gives the 60-second default and a
    /// configured one its own value.
    #[test]
    fn submit_timeout_resolves_the_default_and_the_configured_value() {
        let mut profile = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct").build();
        profile.submit_timeout_seconds = None;
        assert_eq!(submit_timeout(&profile), std::time::Duration::from_secs(60));

        profile.submit_timeout_seconds = Some(17);
        assert_eq!(submit_timeout(&profile), std::time::Duration::from_secs(17));
    }

    // ── x402 value-descriptor helpers ───────────────────────────────────────────

    fn sample_requirements() -> stellar_agent_x402::wire::PaymentRequirements {
        let json = serde_json::json!({
            "scheme": "exact",
            "network": "stellar:testnet",
            "asset": "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA",
            "amount": "1000000",
            "payTo": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
            "maxTimeoutSeconds": 300,
            "extra": { "areFeesSponsored": true }
        })
        .to_string();
        decode_payment_required_input(&json).expect("sample requirements must decode")
    }

    #[test]
    fn x402_value_leg_builds_x402_payment_leg_from_requirements() {
        let requirements = sample_requirements();
        let amount = stellar_agent_x402::exact::validate_requirements(
            &requirements,
            "Test SDF Network ; September 2015",
            "https://soroban-testnet.stellar.org",
        )
        .expect("the sample requirements are valid");
        let leg = x402_value_leg(&requirements, amount);
        assert_eq!(
            leg.kind,
            stellar_agent_core::policy::v1::ActionKind::X402Payment
        );
        assert_eq!(leg.amount, Some(1_000_000_i128));
        assert_eq!(leg.asset.as_deref(), Some(requirements.asset.as_str()));
        assert_eq!(
            leg.destination.as_deref(),
            Some(requirements.pay_to.as_str())
        );
    }
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
                transient: false,
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
                vec![],
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

    struct RecordingPolicyEngine {
        inner: stellar_agent_core::PolicyEngineV1,
        evaluations: Arc<AtomicU32>,
    }

    impl PolicyEngine for RecordingPolicyEngine {
        fn evaluate(
            &self,
            tool: &ToolDescriptor,
            args: &Value,
            profile: &Profile,
            account_view: Option<&dyn AccountReservesView>,
            identity_view: Option<&dyn AccountIdentityView>,
            counterparty_cache: Option<&dyn CounterpartyCacheView>,
            sep10_sessions: Option<&dyn Sep10SessionView>,
            sep45_sessions: Option<&dyn Sep45SessionView>,
        ) -> Result<Decision, PolicyError> {
            self.evaluations.fetch_add(1, Ordering::SeqCst);
            self.inner.evaluate(
                tool,
                args,
                profile,
                account_view,
                identity_view,
                counterparty_cache,
                sep10_sessions,
                sep45_sessions,
            )
        }
    }

    fn chain_engine(chain: &str, cap: Option<i128>) -> stellar_agent_core::PolicyEngineV1 {
        use stellar_agent_core::policy::v1::criteria::per_tx_cap::PerTxCapCriterion;
        use stellar_agent_core::{PolicyDocument, PolicyEngineV1, PolicyRule, RuleMatch, ScopeId};
        let mut rules = vec![PolicyRule {
            r#match: RuleMatch {
                tool: "*".into(),
                chain: chain.into(),
            },
            criteria: cap
                .map(|max| {
                    vec![Box::new(PerTxCapCriterion::new("native".into(), max))
                        as Box<
                            dyn stellar_agent_core::policy::v1::criteria::Criterion,
                        >]
                })
                .unwrap_or_default(),
            decision: Decision::Allow,
            allow_opaque_signing: false,
        }];
        if cap.is_some() {
            rules.push(PolicyRule {
                r#match: RuleMatch {
                    tool: "*".into(),
                    chain: "*".into(),
                },
                criteria: vec![],
                decision: Decision::Allow,
                allow_opaque_signing: false,
            });
        }
        PolicyEngineV1::new(
            PolicyDocument {
                version: 1,
                scope: ScopeId::AllProfiles,
                rules,
                signature: None,
            },
            "default".into(),
        )
    }

    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn dispatch_gate_profile_chain_validation_precedes_evaluation() {
        let home = tempfile::tempdir().expect("isolated home");
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
        stellar_agent_test_support::keyring_mock::install().expect("mock keyring");
        let evaluations = Arc::new(AtomicU32::new(0));
        let server = make_server_with_engine(RecordingPolicyEngine {
            inner: chain_engine("*", None),
            evaluations: Arc::clone(&evaluations),
        });
        for chain in ["stellar:mainnet", "", "invalid"] {
            for explicit_value in [false, true] {
                let args = serde_json::json!({ "chain_id": chain });
                let result = if explicit_value {
                    server
                        .dispatch_gate_with_value(
                            "stellar_balances",
                            &args,
                            chain,
                            stellar_agent_core::policy::v1::ValueClass::ReadOnly,
                            None,
                            None,
                        )
                        .await
                } else {
                    server.dispatch_gate("stellar_balances", &args, chain).await
                };
                let Err(ToolError::Protocol(error)) = result else {
                    panic!("a mismatched chain must return a protocol error: {result:?}");
                };
                assert_eq!(error.code, rmcp::model::ErrorCode::INVALID_PARAMS);
                assert!(error.message.starts_with("chain_id mismatch:"), "{error:?}");
                assert_eq!(evaluations.load(Ordering::SeqCst), 0);
            }
        }
        assert!(
            server
                .dispatch_gate("stellar_balances", &star_tool_value(), "stellar:testnet")
                .await
                .is_ok()
        );
        assert_eq!(evaluations.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn dispatch_gate_profile_chain_exact_allow_both_branches() {
        use stellar_agent_core::policy::v1::value::derive_value_class;
        let home = tempfile::tempdir().expect("isolated home");
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
        stellar_agent_test_support::keyring_mock::install().expect("mock keyring");
        let server = make_server_with_engine(chain_engine("stellar:testnet", None));
        let args = serde_json::json!({
            "amount_stroops": "50", "asset": "native", "destination": "recipient"
        });
        let derived = server
            .dispatch_gate("stellar_pay", &args, "stellar:testnet")
            .await;
        assert!(
            matches!(
                derived,
                Ok(DispatchOutcome::Allow(AllowOutcome {
                    value_effects: Some(_),
                    ..
                }))
            ),
            "{derived:?}"
        );
        let supplied = server
            .dispatch_gate_with_value(
                "stellar_x402_create_payment",
                &args,
                "stellar:testnet",
                derive_value_class("stellar_pay", &args),
                None,
                None,
            )
            .await;
        assert!(
            matches!(
                supplied,
                Ok(DispatchOutcome::Allow(AllowOutcome {
                    value_effects: Some(_),
                    ..
                }))
            ),
            "{supplied:?}"
        );
    }

    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn dispatch_gate_profile_chain_cap_precedes_wildcard_both_branches() {
        use stellar_agent_core::policy::v1::value::derive_value_class;
        let home = tempfile::tempdir().expect("isolated home");
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
        stellar_agent_test_support::keyring_mock::install().expect("mock keyring");
        let server = make_server_with_engine(chain_engine("stellar:testnet", Some(100)));
        for explicit_value in [false, true] {
            for amount in [50, 150] {
                let args = serde_json::json!({
                    "amount_stroops": amount.to_string(),
                    "asset": "native",
                    "destination": "recipient"
                });
                let result = if explicit_value {
                    server
                        .dispatch_gate_with_value(
                            "stellar_x402_create_payment",
                            &args,
                            "stellar:testnet",
                            derive_value_class("stellar_pay", &args),
                            None,
                            None,
                        )
                        .await
                } else {
                    server
                        .dispatch_gate("stellar_pay", &args, "stellar:testnet")
                        .await
                };
                if amount < 100 {
                    assert!(
                        matches!(
                            result,
                            Ok(DispatchOutcome::Allow(AllowOutcome {
                                value_effects: Some(_),
                                ..
                            }))
                        ),
                        "{result:?}"
                    );
                } else {
                    let error = business_tool_error(result.expect_err("cap refusal"));
                    assert_eq!(
                        error_envelope_parts(&error).1,
                        "policy.deny.per_tx_cap_exceeded"
                    );
                }
            }
        }
    }

    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn dispatch_gate_profile_chain_mainnet_read_only_and_testnet_control() {
        let home = tempfile::tempdir().expect("isolated home");
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
        stellar_agent_test_support::keyring_mock::install().expect("mock keyring");
        let profile =
            Profile::builder_mainnet("https://rpc.example", "svc", "acct", "n-svc", "n-acct")
                .with_noop_engine()
                .build();
        let mut mainnet = WalletServer::new(profile).expect("mainnet read-only profile");
        mainnet.policy_engine = Arc::new(chain_engine("stellar:mainnet", None));
        let result = mainnet
            .dispatch_gate(
                "stellar_balances",
                &serde_json::json!({}),
                "stellar:mainnet",
            )
            .await;
        assert!(
            matches!(result, Ok(DispatchOutcome::Allow(_))),
            "{result:?}"
        );
        let testnet = make_server_with_engine(chain_engine("stellar:mainnet", None));
        let result = testnet
            .dispatch_gate("stellar_balances", &star_tool_value(), "stellar:testnet")
            .await;
        let error = business_tool_error(result.expect_err("mainnet rule excludes testnet"));
        assert_eq!(
            error_envelope_parts(&error).1,
            "policy.deny.no_matching_rule"
        );
    }

    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn dispatch_gate_profile_chain_tool_without_chain_argument() {
        let home = tempfile::tempdir().expect("isolated home");
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
        stellar_agent_test_support::keyring_mock::install().expect("mock keyring");
        let server = make_server_with_engine(chain_engine("stellar:testnet", None));
        let result = server
            .dispatch_gate("stellar_toolset_list", &serde_json::json!({}), "")
            .await;
        assert!(
            matches!(result, Ok(DispatchOutcome::Allow(_))),
            "{result:?}"
        );
        assert_eq!(
            server
                .tool_registry
                .get("stellar_toolset_list")
                .expect("registered tool")
                .chain_id,
            ""
        );
    }

    fn star_tool_value() -> Value {
        serde_json::json!({ "chain_id": "stellar:testnet" })
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

    /// Extracts `(is_error, code, message)` from a business-error result envelope
    /// (`{ ok:false, error:{code,message}, request_id }`) for test assertions.
    /// Also asserts the envelope invariants (`ok == false`, `request_id` present).
    fn error_envelope_parts(result: &rmcp::model::CallToolResult) -> (bool, String, String) {
        let text = result
            .content
            .first()
            .and_then(|c| c.as_text())
            .map(|t| t.text.clone())
            .expect("result must carry a text content block");
        let v: serde_json::Value = serde_json::from_str(&text).expect("content must be JSON");
        assert_eq!(
            v["ok"],
            serde_json::json!(false),
            "business-error envelope must have ok:false"
        );
        assert!(
            v["request_id"].as_str().is_some_and(|s| !s.is_empty()),
            "business-error envelope must carry a non-empty request_id: {v}"
        );
        let code = v["error"]["code"].as_str().unwrap_or_default().to_owned();
        let message = v["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        (result.is_error == Some(true), code, message)
    }

    /// Unwraps a [`ToolError::Business`] to its result envelope for assertions;
    /// panics if the error is a protocol fault.
    fn business_tool_error(err: ToolError) -> rmcp::model::CallToolResult {
        match err {
            ToolError::Business(result) => result,
            ToolError::Protocol(data) => {
                panic!("expected ToolError::Business, got Protocol: {data:?}")
            }
        }
    }

    /// Full text payload (the serialised envelope) of a business `CallToolResult`.
    fn result_text(result: &rmcp::model::CallToolResult) -> String {
        result
            .content
            .first()
            .and_then(|c| c.as_text())
            .map(|t| t.text.clone())
            .expect("result must carry a text content block")
    }

    #[test]
    fn nonce_expired_and_hmac_mismatch_have_identical_wire_message() {
        let expired = nonce_verification_error_result(&NonceError::Expired);
        let hmac_mismatch = nonce_verification_error_result(&NonceError::HmacMismatch);
        let expected_message = "nonce expired or invalid; re-simulate to obtain a fresh nonce";

        let (e_is_err, e_code, e_msg) = error_envelope_parts(&expired);
        let (h_is_err, h_code, h_msg) = error_envelope_parts(&hmac_mismatch);
        assert!(e_is_err && h_is_err, "both must set is_error = true");
        assert_eq!(e_code, "nonce.expired");
        assert_eq!(e_msg, expected_message);
        assert_eq!(
            (e_code, e_msg),
            (h_code, h_msg),
            "indistinguishability: Expired and HmacMismatch must produce byte-identical code+message"
        );
    }

    #[test]
    fn memo_commit_errors_match_nonce_expired_wire_message() {
        let nonce_expired =
            error_envelope_parts(&nonce_verification_error_result(&NonceError::Expired));
        let memo_invalid =
            error_envelope_parts(&commit_path_error_result("validation.memo_invalid_type"));
        assert_eq!(memo_invalid, nonce_expired);
    }

    #[test]
    fn commit_envelope_build_failure_matches_nonce_hmac_wire_response() {
        let nonce_expired =
            error_envelope_parts(&nonce_verification_error_result(&NonceError::Expired));
        let envelope_build = error_envelope_parts(&commit_path_error_result(
            "envelope_build_error: synthetic failure",
        ));
        assert_eq!(envelope_build, nonce_expired);
    }

    #[test]
    fn commit_oracle_build_failure_matches_nonce_hmac_wire_response() {
        let nonce_expired =
            error_envelope_parts(&nonce_verification_error_result(&NonceError::Expired));
        let oracle_build = error_envelope_parts(&commit_path_error_result(
            "oracle_build_error: synthetic failure",
        ));
        assert_eq!(oracle_build, nonce_expired);
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
            NonceError::KeyTooLong { actual: 42 },
            NonceError::KeyMatchesOwnerPublicKey,
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

            let (is_err, env_code, env_message) =
                error_envelope_parts(&nonce_verification_error_result(&err));
            assert!(is_err, "non-collapsed nonce error must set is_error = true");
            assert_eq!(
                env_code, code,
                "envelope code must equal the nonce wire_code"
            );
            assert_eq!(
                env_message, display,
                "envelope message must equal Display with no wire-code prefix"
            );
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
        let (is_err, code, message) = error_envelope_parts(&nonce_replayed_error_result());
        assert!(is_err, "replay error must set is_error = true");
        assert_eq!(code, "nonce.replayed");
        assert_eq!(
            message,
            "this nonce has already been used; re-simulate to obtain a fresh nonce"
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
            matches!(result, Ok(DispatchOutcome::Allow(_))),
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
            matches!(result, Ok(DispatchOutcome::Allow(_))),
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
        let err = business_tool_error(result.expect_err("Deny must produce Err(ToolError)"));
        let (is_err, code, _message) = error_envelope_parts(&err);
        assert!(is_err, "Deny envelope must set is_error = true");
        assert_eq!(
            code, "policy.deny.per_tx_cap_exceeded",
            "wire code must be policy.deny.per_tx_cap_exceeded"
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
        let err = business_tool_error(result.expect_err("Deny must produce Err(ToolError)"));
        let (is_err, code, _message) = error_envelope_parts(&err);
        assert!(is_err, "Deny envelope must set is_error = true");

        // The full serialised envelope must NOT contain the full 56-char strkey.
        let payload_str = result_text(&err);
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
        assert_eq!(
            code, "policy.deny.counterparty_denied",
            "wire code must be policy.deny.counterparty_denied"
        );
    }

    // ── dispatch_gate: DeFi-shaped tool + minimum_reserve, no account_view → fails closed ──

    /// Pins the terminal posture: the smart-account-fronted DeFi
    /// tools (`stellar_dex_trade`, `stellar_defindex_vault_deposit`,
    /// `stellar_defindex_vault_withdraw`)
    /// always call `dispatch_gate_with_value` with `account_view = None` —
    /// `from_address` on these tools is a smart-account contract (C-strkey)
    /// with no classic `AccountEntry`, so there is no account state to fetch.
    /// A rule that configures `minimum_reserve` on such a tool therefore fails
    /// closed on EVERY call by design, via the criterion's own fail-closed
    /// path (`PolicyError::CriterionEvaluationFailed` when `account_view` is
    /// `None`), surfaced at the wire as `policy.engine_required` — this is not
    /// missing wiring; there is no account to wire.
    ///
    /// Exercises the REAL `PolicyEngineV1` + `MinimumReserveCriterion`, not a
    /// `MockPolicyEngine`, so the assertion proves the criterion's own
    /// fail-closed branch fires, not just that dispatch_gate propagates an
    /// engine error generically.
    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn dispatch_gate_defi_tool_minimum_reserve_fails_closed_with_no_account_view() {
        use stellar_agent_core::policy::v1::criteria::MinimumReserveCriterion;
        use stellar_agent_core::policy::v1::{ValueClass, ValueEffects};
        use stellar_agent_core::{PolicyDocument, PolicyEngineV1, PolicyRule, RuleMatch, ScopeId};

        stellar_agent_test_support::keyring_mock::install().ok();

        const ROUTER: &str = "CCEBVDYM32YNYCVNRXQKDFFPISJJCV557CDZEIRBEE4NCV4KHPQ44HGF";
        const ASSET_A: &str = "CAQCFVLOBK5GIULPNZRGATJJMIZL5BSP7X5YJVMGCPTUEPFM4AVSRCJU";
        const ASSET_B: &str = "CAJJZSGMMM3PD7N33TAPHGBUGTB43OC73HVIK2L2G6BNGGGYOSSYBXBD";
        const FROM: &str = "CAJJZSGMMM3PD7N33TAPHGBUGTB43OC73HVIK2L2G6BNGGGYOSSYBXBD";

        let doc = PolicyDocument {
            version: 1,
            scope: ScopeId::AllProfiles,
            rules: vec![PolicyRule {
                r#match: RuleMatch {
                    tool: "stellar_dex_trade".into(),
                    chain: "*".into(),
                },
                criteria: vec![Box::new(MinimumReserveCriterion::new(0))],
                decision: Decision::Allow,
                allow_opaque_signing: false,
            }],
            signature: None,
        };
        let engine = PolicyEngineV1::new(doc, "svc".into());
        let server = make_server_with_engine(engine);

        let canonical_path = vec![ASSET_A.to_owned(), ASSET_B.to_owned()];
        let legs = vec![stellar_agent_dex::value::dex_trade_value_leg(
            500_000_000_i128,
            &canonical_path,
            ROUTER,
        )];
        let args_value = serde_json::json!({
            "chain_id": "stellar:testnet",
            "router_address": ROUTER,
            "from_address": FROM,
        });

        // Mirrors the real dispatch site exactly: account_view and
        // identity_view are both None (see dex_trade.rs's dispatch call).
        let result = server
            .dispatch_gate_with_value(
                "stellar_dex_trade",
                &args_value,
                "stellar:testnet",
                ValueClass::Value(ValueEffects::new(legs)),
                None,
                None,
            )
            .await;

        let err = business_tool_error(
            result.expect_err("minimum_reserve with no account_view must fail closed"),
        );
        let (is_err, code, _message) = error_envelope_parts(&err);
        assert!(
            is_err,
            "fail-closed criterion error must set is_error = true"
        );
        assert_eq!(
            code, "policy.engine_required",
            "a minimum_reserve criterion with no account_view must surface \
             policy.engine_required, got {code}"
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
                    req.request.nonce, "test-nonce-abc",
                    "nonce must be preserved in DispatchOutcome"
                );
            }
            other => panic!("expected Ok(RequireApproval), got {other:?}"),
        }
    }

    // ── paired_commit_outcome: only decodable commit arguments park a request ─

    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn paired_commit_outcome_requires_decodable_commit_arguments() {
        stellar_agent_test_support::keyring_mock::install().ok();
        let req = ApprovalRequest::new("commit-nonce".into(), 120);
        let engine = MockPolicyEngine::returns(Ok(Decision::RequireApproval(req)));
        let server = make_server_with_engine(engine);
        let envelope =
            stellar_agent_test_support::signed_envelope::SignedTestEnvelope::for_source([0x31; 32]);

        let decoded = server
            .paired_commit_outcome(
                DispatchOutcome::Allow(AllowOutcome {
                    value_effects: None,
                    governing_ttl_ms: 600_000,
                }),
                envelope.envelope_xdr(),
                "stellar_pay_commit",
                "stellar:testnet",
                None,
                None,
            )
            .await;
        match decoded {
            Ok(DispatchOutcome::RequireApproval(approval)) => {
                assert_eq!(approval.request.nonce, "commit-nonce");
            }
            other => panic!("expected the commit request, got {other:?}"),
        }

        let undecodable = server
            .paired_commit_outcome(
                DispatchOutcome::Allow(AllowOutcome {
                    value_effects: None,
                    governing_ttl_ms: 600_000,
                }),
                "not-an-envelope",
                "stellar_pay_commit",
                "stellar:testnet",
                None,
                None,
            )
            .await;
        assert!(
            matches!(
                undecodable,
                Ok(DispatchOutcome::Allow(AllowOutcome {
                    value_effects: None,
                    governing_ttl_ms: 600_000
                }))
            ),
            "an undecodable envelope leaves the outcome unchanged, got {undecodable:?}"
        );
    }

    #[test]
    fn tool_error_code_omits_the_message() {
        let business = ToolError::Business(business_error_result(
            "policy.engine_required",
            "policy engine evaluation failed: GAAAA",
        ));
        assert_eq!(business.code(), "policy.engine_required");
        let protocol = ToolError::Protocol(ErrorData::invalid_params(
            "chain_id mismatch: stellar:pubnet",
            None,
        ));
        assert_eq!(protocol.code(), "-32602");
    }

    // ── dispatch_gate: approval_required_indistinguishable wire code ──────────

    #[test]
    #[serial_test::serial(keyring)]
    fn load_attestation_key_answers_owner_key_forms_uniformly() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let mut profile = stellar_agent_core::profile::schema::Profile::builder_testnet_named(
            "mcp-attest-forms",
            "s",
            "a",
            "n",
            "a",
        )
        .build();
        let uniform =
            error_envelope_parts(&approval_required_indistinguishable("mcp-attest-forms"));
        keyring_core::Entry::new(
            &profile.attestation_key_id.service,
            &profile.attestation_key_id.account,
        )
        .unwrap()
        .set_password(&stellar_agent_core::profile::owner_key::encode_owner_public_key(&[0x23; 32]))
        .unwrap();
        let strkey = load_attestation_key(&profile).expect_err("a G-strkey is no key");
        assert_eq!(error_envelope_parts(&strkey), uniform);

        profile.attestation_key_id = stellar_agent_core::profile::schema::KeyringEntryRef::new(
            "stellar-agent-owner-B",
            "default",
        );
        let mut coordinate = None;
        let logs = stellar_agent_test_support::with_captured_logs(|| {
            coordinate = load_attestation_key(&profile).err();
        });
        let coordinate = coordinate.expect("an owner coordinate refuses");
        assert_eq!(error_envelope_parts(&coordinate), uniform);
        assert!(logs.contains("WARN"), "{logs}");
        assert!(
            logs.contains("validation.key_matches_owner_public_key"),
            "{logs}"
        );
    }

    #[test]
    fn approval_required_indistinguishable_has_expected_wire_code() {
        let result = approval_required_indistinguishable("default");
        let (is_err, code, _message) = error_envelope_parts(&result);
        assert!(is_err, "indistinguishable error must set is_error = true");
        assert_eq!(
            code, "policy.approval_required",
            "indistinguishable error must carry wire code policy.approval_required"
        );
        // The envelope error object exposes only `code` and `message` — no
        // structured `data` field exists to leak forensic approval detail.
        let v: serde_json::Value = serde_json::from_str(&result_text(&result)).unwrap();
        assert!(
            v["error"].get("data").is_none(),
            "envelope error object must expose no data field; got: {v}"
        );
        // `details` is the field that DOES exist on the error object, carried
        // by the three unresolved-submission codes. A refusal that names an
        // approval must never carry one: its presence or absence would be a
        // side channel distinguishing the reasons this uniform error covers.
        assert!(
            v["error"].get("details").is_none(),
            "an approval refusal must carry no details object; got: {v}"
        );
    }

    /// The three approval refusals differ in code and in nothing else.
    ///
    /// They are deliberately distinguishable from each other — an agent acts
    /// differently on each — but each must be uniform across the reasons it
    /// covers, so none of them may carry a `details` object.
    #[test]
    fn no_approval_refusal_carries_a_details_object() {
        for (label, result) in [
            ("required", approval_required_indistinguishable("default")),
            ("rejected", approval_rejected_error()),
            ("consumed", approval_consumed_error()),
        ] {
            let v: serde_json::Value = serde_json::from_str(&result_text(&result)).unwrap();
            assert!(
                v["error"].get("details").is_none(),
                "the {label} refusal must carry no details object; got: {v}"
            );
            assert!(
                v["error"].get("data").is_none(),
                "the {label} refusal must expose no data field; got: {v}"
            );
        }
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
        let dispatch_outcome = DispatchOutcome::RequireApproval(
            ApprovalRequest::new("approval-nonce".into(), 120).into(),
        );
        let attestation_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0_u8; 32]);
        let capture = CaptureWriter::new();
        let subscriber = Subscriber::builder()
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .with_writer(capture.clone())
            .finish();

        let _guard = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();
        let result = verify_attestation_gate(
            &server,
            &dispatch_outcome,
            GatedApprovalKind::Payment,
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

        let dispatch_outcome = DispatchOutcome::RequireApproval(
            ApprovalRequest::new(approval_nonce.clone(), 120).into(),
        );
        let attestation_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0_u8; 32]);

        let result = verify_attestation_gate(
            &server,
            &dispatch_outcome,
            GatedApprovalKind::Payment,
            "AAAA",
            Some(&approval_nonce),
            Some(&attestation_b64),
            "stellar_pay_commit",
        )
        .await;

        let err = result.expect_err("clock failure must map to approval_required");
        let (is_err, code, _message) = error_envelope_parts(&err);
        assert!(is_err, "clock-error envelope must set is_error = true");
        assert_eq!(
            code, "policy.approval_required",
            "clock error must use indistinguishable approval-required wire code"
        );
    }

    // ── verify_attestation_gate's `other =>` arm rejects RuleProposalSimulated ──
    //
    // GH issue #8: `RuleProposalSimulated`
    // has its OWN dedicated gate (`PendingApprovalStore::verify_rule_proposal_gate`,
    // wired inside `stellar_rule_create_commit`). The shared payment, claim,
    // and trustline gate refuses it at step 6 through the `other` arm,
    // with the same response as every wrong-kind entry.

    #[tokio::test(flavor = "current_thread")]
    #[serial_test::serial(keyring)]
    async fn verify_attestation_gate_rejects_rule_proposal_simulated_entry() {
        use base64::Engine as _;
        use stellar_agent_core::approval::rule_proposal::{
            ContextRuleProposalSnapshot, RuleProposalContextType, RuleProposalSigner,
        };
        use stellar_agent_core::approval::{
            DEFAULT_TTL_MS, PendingApproval, PendingApprovalStore, process_uid_for_attestation,
        };

        stellar_agent_test_support::keyring_mock::install().ok();
        let profile = Profile::builder_testnet(
            "rule-gate-svc",
            "rule-gate-acct",
            "rule-gate-n-svc",
            "rule-gate-n-acct",
        )
        .with_noop_engine()
        .build();
        let mut server =
            crate::server::WalletServer::new(profile).expect("WalletServer::new must not fail");
        let approvals_dir = tempfile::tempdir().unwrap();
        server.set_approval_dir_for_test(approvals_dir.path().to_path_buf());

        let store_path = approvals_dir
            .path()
            .join(format!("{}.toml", server.profile_name_for_approval()));
        let mut store = PendingApprovalStore::open(store_path).unwrap();

        let definition = ContextRuleProposalSnapshot::new(
            RuleProposalContextType::Default,
            "spend-daily".to_owned(),
            None,
            vec![RuleProposalSigner::delegated(
                "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                true,
            )],
            vec![],
            vec![0],
            false,
            false,
        );
        let entry = PendingApproval::new_rule_proposal_pending(
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned(),
            "Test SDF Network ; September 2015".to_owned(),
            "stellar:testnet".to_owned(),
            definition,
            [0x11_u8; 32],
            "CallContract rule \"spend-daily\"".to_owned(),
            process_uid_for_attestation().unwrap(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
        let approval_nonce = entry.approval_nonce.clone();
        let now_ms = stellar_agent_core::timefmt::now_unix_ms().unwrap();
        store.insert(entry, now_ms).unwrap();
        drop(store);

        let dispatch_outcome = DispatchOutcome::RequireApproval(
            ApprovalRequest::new(approval_nonce.clone(), 120).into(),
        );
        let attestation_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0_u8; 32]);

        let result = verify_attestation_gate(
            &server,
            &dispatch_outcome,
            GatedApprovalKind::Payment,
            "AAAA",
            Some(&approval_nonce),
            Some(&attestation_b64),
            "stellar_pay_commit",
        )
        .await;

        let err = result.expect_err(
            "verify_attestation_gate must refuse a RuleProposalSimulated entry, not accept it",
        );
        let (is_err, code, _message) = error_envelope_parts(&err);
        assert!(
            is_err,
            "wrong-kind refusal envelope must set is_error = true"
        );
        assert_eq!(
            code, "policy.approval_required",
            "RuleProposalSimulated must be refused with the same indistinguishable \
             approval-required wire code as any other wrong-kind entry"
        );
    }

    // ── Cross-check: a core-minted attestation verifies through this gate ─────
    //
    // The CLI and this test use the shared core attester,
    // `stellar_agent_core::approval::attest_and_persist`. Its blob verifies
    // through `verify_attestation_gate`, so the CLI and the MCP commit
    // boundary agree on the attestation format.

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
        let profile = Profile::builder_mainnet(
            "https://mainnet-gate.example",
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

        let envelope = stellar_agent_core::approval::fixtures::payment_envelope(
            "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL",
            "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY",
            "XLM",
            1_000_000,
            None,
            100,
            123,
        );
        let envelope_xdr = envelope.as_str();
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
        // --id <nonce> --profile <name>` calls.
        let mut consent_writer = stellar_agent_core::audit_log::AuditWriter::open(
            approvals_dir.path().join("audit").join("audit.jsonl"),
            None,
        )
        .unwrap();
        let attestation_b64 = attest_and_persist(
            &mut store,
            &entry,
            &attestation_key,
            &stellar_agent_core::approval::AttestationBinding::new(
                &server.profile_name_for_approval(),
                "stellar:mainnet",
            ),
            Surface::Cli,
            stellar_agent_core::approval::ConsentAudit::Writer(&mut consent_writer),
            None,
            |_req, _key| Err("must not be called for PaymentSimulated".to_owned()),
        )
        .unwrap()
        .expect("PaymentSimulated must surface an attestation blob");
        drop(store);

        let dispatch_outcome = DispatchOutcome::RequireApproval(
            ApprovalRequest::new(approval_nonce.clone(), 120).into(),
        );

        use stellar_agent_test_support::CaptureWriter;
        let capture = CaptureWriter::new();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .with_writer(capture.clone())
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();
        let result = verify_attestation_gate(
            &server,
            &dispatch_outcome,
            GatedApprovalKind::Payment,
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

    #[tokio::test(flavor = "current_thread")]
    #[serial_test::serial(keyring)]
    async fn attestation_gate_rejects_cross_profile_and_both_cross_chain_bindings() {
        use base64::Engine as _;
        use stellar_agent_core::approval::{
            DEFAULT_TTL_MS, PendingApproval, PendingApprovalStore, Surface, attest_and_persist,
            process_uid_for_attestation,
        };

        stellar_agent_test_support::keyring_mock::install().ok();
        // Unique service/account names (not shared with any other test in this
        // file) so this test cannot race on the process-global mock keyring
        // store against a test using a different `serial_test` group.
        let profile = Profile::builder_mainnet(
            "https://mainnet-gate.example",
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

        let envelope = stellar_agent_core::approval::fixtures::payment_envelope(
            "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL",
            "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY",
            "XLM",
            1_000_000,
            None,
            100,
            123,
        );
        let envelope_xdr = envelope.as_str();
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
        // --id <nonce> --profile <name>` calls.
        let mut consent_writer = stellar_agent_core::audit_log::AuditWriter::open(
            approvals_dir.path().join("audit").join("audit.jsonl"),
            None,
        )
        .unwrap();
        let attestation_b64 = attest_and_persist(
            &mut store,
            &entry,
            &attestation_key,
            &stellar_agent_core::approval::AttestationBinding::new(
                &server.profile_name_for_approval(),
                "stellar:mainnet",
            ),
            Surface::Cli,
            stellar_agent_core::approval::ConsentAudit::Writer(&mut consent_writer),
            None,
            |_req, _key| Err("must not be called for PaymentSimulated".to_owned()),
        )
        .unwrap()
        .expect("PaymentSimulated must surface an attestation blob");
        drop(store);

        let dispatch_outcome = DispatchOutcome::RequireApproval(
            ApprovalRequest::new(approval_nonce.clone(), 120).into(),
        );

        use stellar_agent_test_support::CaptureWriter;
        let capture = CaptureWriter::new();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .with_writer(capture.clone())
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();
        assert_eq!(
            load_attestation_key(&server.profile).unwrap(),
            attestation_key
        );
        assert!(
            PendingApprovalStore::open(store_path)
                .unwrap()
                .get(&approval_nonce)
                .is_some()
        );
        for (profile_name, chain_id) in [
            ("other-profile", "stellar:mainnet"),
            ("cross-check-acct", "stellar:testnet"),
        ] {
            let wrong_blob = stellar_agent_core::approval::compute_attestation(
                &attestation_key,
                &stellar_agent_core::approval::AttestationBinding::new(profile_name, chain_id),
                &approval_nonce,
                &stellar_agent_core::approval::envelope_sha256(envelope_xdr.as_bytes()),
                &entry.process_uid,
                &entry.attested_lifetime(),
            );
            let wrong_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(wrong_blob);
            capture.clear();
            let result = verify_attestation_gate(
                &server,
                &dispatch_outcome,
                GatedApprovalKind::Payment,
                envelope_xdr,
                Some(&approval_nonce),
                Some(&wrong_b64),
                "stellar_pay_commit",
            )
            .await
            .unwrap_err();
            let (code, message, _) = assert_business_envelope(&result);
            assert_eq!(code, "policy.approval_required");
            let (_, expected_message, _) =
                assert_business_envelope(&approval_required_indistinguishable("cross-check-acct"));
            assert_eq!(message, expected_message);
            assert!(
                capture
                    .captured_str()
                    .contains("HMAC attestation verification failed"),
                "{profile_name}/{chain_id} must reach HMAC verification: {}",
                capture.captured_str()
            );
        }
        std::sync::Arc::make_mut(&mut server.profile).chain_id =
            stellar_agent_core::profile::caip2::Caip2::Testnet;
        server.context = stellar_agent_network::NetworkContext::from_profile(&server.profile);
        capture.clear();
        let result = verify_attestation_gate(
            &server,
            &dispatch_outcome,
            GatedApprovalKind::Payment,
            envelope_xdr,
            Some(&approval_nonce),
            Some(&attestation_b64),
            "stellar_pay_commit",
        )
        .await
        .unwrap_err();
        let (code, message, _) = assert_business_envelope(&result);
        assert_eq!(code, "policy.approval_required");
        let (_, expected_message, _) =
            assert_business_envelope(&approval_required_indistinguishable("cross-check-acct"));
        assert_eq!(message, expected_message);
        assert!(
            capture
                .captured_str()
                .contains("HMAC attestation verification failed"),
            "mainnet blob under testnet must reach HMAC verification: {}",
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
        let err =
            business_tool_error(result.expect_err("Err from engine must produce Err(ToolError)"));
        let (is_err, code, _message) = error_envelope_parts(&err);
        assert!(is_err, "engine-required envelope must set is_error = true");
        assert_eq!(
            code, "policy.engine_required",
            "engine Err must map to policy.engine_required"
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

    fn envelope_gate_entry(
        kind: GatedApprovalKind,
    ) -> stellar_agent_core::approval::PendingApproval {
        use stellar_agent_core::approval::{
            DEFAULT_TTL_MS, PendingApproval, process_uid_for_attestation,
        };
        let holder = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned();
        let uid = process_uid_for_attestation().unwrap();
        match kind {
            #[cfg(feature = "mainnet-write")]
            GatedApprovalKind::X402 => panic!("classic fixture requires a classic kind"),
            GatedApprovalKind::Payment => PendingApproval::new_payment_pending(
                "AAAA".to_owned(),
                b"AAAA",
                holder,
                100,
                "XLM".to_owned(),
                None,
                100,
                1,
                uid,
                DEFAULT_TTL_MS,
            ),
            GatedApprovalKind::Claim => PendingApproval::new_claim_pending(
                "AAAA".to_owned(),
                b"AAAA",
                "ab".repeat(36),
                format!("B{}", "A".repeat(57)),
                "XLM".to_owned(),
                100,
                holder,
                100,
                1,
                uid,
                DEFAULT_TTL_MS,
            ),
            GatedApprovalKind::Trustline => PendingApproval::new_trustline_pending(
                "AAAA".to_owned(),
                b"AAAA",
                holder.clone(),
                "USDC".to_owned(),
                holder,
                None,
                100,
                1,
                uid,
                DEFAULT_TTL_MS,
            ),
        }
        .unwrap()
    }

    fn envelope_gate_server(dir: &std::path::Path) -> WalletServer {
        use base64::Engine as _;
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let profile = Profile::builder_testnet(
            "kind-matrix",
            "kind-matrix",
            "kind-matrix-n",
            "kind-matrix-n",
        )
        .with_noop_engine()
        .build();
        keyring_core::Entry::new(
            &profile.attestation_key_id.service,
            &profile.attestation_key_id.account,
        )
        .unwrap()
        .set_password(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([77; 32]))
        .unwrap();
        let mut server = WalletServer::new(profile).unwrap();
        server.set_approval_dir_for_test(dir.to_path_buf());
        server
    }

    fn park_gate_entry(
        server: &WalletServer,
        dir: &std::path::Path,
        entry: &stellar_agent_core::approval::PendingApproval,
    ) -> String {
        use base64::Engine as _;
        use stellar_agent_core::approval::{
            AttestationBinding, PendingApprovalStore, compute_attestation, envelope_sha256,
        };
        let blob = compute_attestation(
            &[77; 32],
            &AttestationBinding::new(&server.profile_name_for_approval(), "stellar:testnet"),
            &entry.approval_nonce,
            &envelope_sha256(b"AAAA"),
            &entry.process_uid,
            &entry.attested_lifetime(),
        );
        let mut store = PendingApprovalStore::open(
            dir.join(format!("{}.toml", server.profile_name_for_approval())),
        )
        .unwrap();
        let now = stellar_agent_core::timefmt::now_unix_ms().unwrap();
        if store.get(&entry.approval_nonce).is_none() {
            store.insert(entry.clone(), now).unwrap();
        }
        store
            .record_attestation(&entry.approval_nonce, blob)
            .unwrap();
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(blob)
    }

    #[tokio::test(flavor = "current_thread")]
    #[serial_test::serial(keyring)]
    async fn attestation_gate_expected_kind_matrix() {
        let dir = tempfile::tempdir().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(dir.path());
        let server = envelope_gate_server(dir.path());
        let kinds = [
            GatedApprovalKind::Payment,
            GatedApprovalKind::Claim,
            GatedApprovalKind::Trustline,
        ];
        for stored in kinds {
            let entry = envelope_gate_entry(stored);
            let blob = park_gate_entry(&server, dir.path(), &entry);
            let dispatch = DispatchOutcome::RequireApproval(
                ApprovalRequest::new(entry.approval_nonce.clone(), 120).into(),
            );
            for expected in kinds {
                let result = verify_attestation_gate(
                    &server,
                    &dispatch,
                    expected,
                    "AAAA",
                    Some(&entry.approval_nonce),
                    Some(&blob),
                    "kind-matrix",
                )
                .await;
                if stored == expected {
                    assert!(result.is_ok(), "{stored:?}/{expected:?}: {result:?}");
                } else {
                    let result = result.unwrap_err();
                    assert_eq!(
                        assert_business_envelope(&result).0,
                        "policy.approval_required",
                        "{stored:?}/{expected:?}"
                    );
                }
            }
        }
        assert!(
            verify_attestation_gate(
                &server,
                &DispatchOutcome::Allow(AllowOutcome {
                    value_effects: None,
                    governing_ttl_ms: 600_000
                }),
                GatedApprovalKind::Trustline,
                "AAAA",
                None,
                None,
                "kind-matrix"
            )
            .await
            .is_ok()
        );
    }

    /// A durable receipt reports consumption even while the approval store is locked.
    #[tokio::test(flavor = "current_thread")]
    #[serial_test::serial(keyring)]
    async fn an_owed_approval_is_consumed_before_reopening_the_approval_store() {
        use stellar_agent_core::approval::PendingApprovalStore;
        use stellar_agent_core::profile::receipt::ReceiptStore;

        let dir = tempfile::tempdir().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(dir.path());
        let server = envelope_gate_server(dir.path());
        let entry = envelope_gate_entry(GatedApprovalKind::Payment);
        let blob = park_gate_entry(&server, dir.path(), &entry);
        let receipts = ReceiptStore::open(&server.profile_name_for_approval()).unwrap();
        receipts
            .begin_submission_with_approval(
                "hash",
                &"ab".repeat(32),
                "source",
                1,
                0,
                100,
                Some(&entry.approval_nonce),
            )
            .unwrap();
        receipts.mark_submitted("hash").unwrap();
        let held = PendingApprovalStore::open(
            dir.path()
                .join(format!("{}.toml", server.profile_name_for_approval())),
        )
        .unwrap();
        let dispatch = DispatchOutcome::RequireApproval(
            ApprovalRequest::new(entry.approval_nonce.clone(), 120).into(),
        );
        let result = verify_attestation_gate(
            &server,
            &dispatch,
            GatedApprovalKind::Payment,
            "AAAA",
            Some(&entry.approval_nonce),
            Some(&blob),
            "stellar_pay_commit",
        )
        .await
        .unwrap_err();
        assert_eq!(
            assert_business_envelope(&result).0,
            "policy.approval_consumed"
        );
        for attestation in [None, Some("invalid-attestation")] {
            let result = verify_attestation_gate(
                &server,
                &dispatch,
                GatedApprovalKind::Payment,
                "AAAA",
                Some(&entry.approval_nonce),
                attestation,
                "stellar_pay_commit",
            )
            .await
            .unwrap_err();
            assert_eq!(
                assert_business_envelope(&result).0,
                "policy.approval_required"
            );
        }
        assert!(!receipts.get("hash").unwrap().unwrap().approval_consumed);
        drop(held);
    }

    /// An unreadable receipt store refuses even a valid, unspent approval.
    #[tokio::test(flavor = "current_thread")]
    #[serial_test::serial(keyring)]
    async fn an_unreadable_receipt_store_refuses_a_valid_attestation() {
        use stellar_agent_core::profile::receipt::ReceiptStore;

        let dir = tempfile::tempdir().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(dir.path());
        let server = envelope_gate_server(dir.path());
        let entry = envelope_gate_entry(GatedApprovalKind::Payment);
        let blob = park_gate_entry(&server, dir.path(), &entry);
        let receipts = ReceiptStore::open(&server.profile_name_for_approval()).unwrap();
        std::fs::write(receipts.file_path().unwrap(), "{unparsable").unwrap();
        let dispatch = DispatchOutcome::RequireApproval(
            ApprovalRequest::new(entry.approval_nonce.clone(), 120).into(),
        );
        let result = verify_attestation_gate(
            &server,
            &dispatch,
            GatedApprovalKind::Payment,
            "AAAA",
            Some(&entry.approval_nonce),
            Some(&blob),
            "stellar_pay_commit",
        )
        .await
        .unwrap_err();
        assert_eq!(
            assert_business_envelope(&result).0,
            "policy.approval_required"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    #[serial_test::serial(keyring)]
    async fn trustline_terminal_states_preserve_gate_errors() {
        use stellar_agent_core::approval::{ConsumedOutcome, DEFAULT_TTL_MS, PendingApprovalStore};
        use stellar_agent_core::profile::receipt::{BeginSubmissionOutcome, ReceiptStore};
        let dir = tempfile::tempdir().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(dir.path());
        let server = envelope_gate_server(dir.path());
        for terminal in ["rejected", "confirmed", "unknown", "receipt"] {
            // A payment record deliberately mismatches the trustline gate.
            let entry = envelope_gate_entry(GatedApprovalKind::Payment);
            let blob = park_gate_entry(&server, dir.path(), &entry);
            let nonce = &entry.approval_nonce;
            let mut store = PendingApprovalStore::open(
                dir.path()
                    .join(format!("{}.toml", server.profile_name_for_approval())),
            )
            .unwrap();
            match terminal {
                "rejected" => {
                    store
                        .reject(
                            nonce,
                            stellar_agent_core::timefmt::now_unix_ms().unwrap(),
                            DEFAULT_TTL_MS,
                        )
                        .unwrap();
                }
                "confirmed" => {
                    store
                        .consume(nonce, &"ab".repeat(32), ConsumedOutcome::Confirmed)
                        .unwrap();
                }
                "unknown" => {
                    store
                        .consume(nonce, &"ab".repeat(32), ConsumedOutcome::Unknown)
                        .unwrap();
                }
                "receipt" => {
                    let receipts = ReceiptStore::open(&server.profile_name_for_approval()).unwrap();
                    assert!(matches!(
                        receipts
                            .begin_submission_with_approval(
                                "hash",
                                &"ab".repeat(32),
                                "source",
                                1,
                                0,
                                100,
                                Some(nonce)
                            )
                            .unwrap(),
                        BeginSubmissionOutcome::Recorded
                    ));
                }
                _ => unreachable!(),
            }
            drop(store);
            let dispatch =
                DispatchOutcome::RequireApproval(ApprovalRequest::new(nonce.clone(), 120).into());
            let result = verify_attestation_gate(
                &server,
                &dispatch,
                GatedApprovalKind::Trustline,
                "AAAA",
                Some(nonce),
                Some(&blob),
                "stellar_trustline_commit",
            )
            .await
            .unwrap_err();
            assert_eq!(
                assert_business_envelope(&result).0,
                if terminal == "rejected" {
                    "policy.approval_rejected"
                } else {
                    "policy.approval_consumed"
                },
                "{terminal}"
            );
        }
    }
    #[cfg(feature = "mainnet-write")]
    pub(crate) mod mainnet {
        use super::*;
        use sha2::Digest as _;
        use stellar_agent_core::policy::v1::{
            canonical::canonical_bytes,
            signature::{digest, sign},
        };
        use stellar_agent_core::profile::{loader, name::ProfileNameSource, schema::*};
        use stellar_agent_test_support::{
            StellarAgentHomeGuard, keyring_mock, signed_envelope::SignedTestEnvelope,
        };

        /// A callback a test installs to run at one keyring coordinate's reads.
        pub(crate) type Observer = Arc<std::sync::Mutex<Option<Arc<dyn Fn() + Send + Sync>>>>;

        /// Runs the observer's callback, if one is installed, without holding
        /// its lock while the callback runs.
        fn notify(observer: &Observer) {
            let callback = observer.lock().unwrap().clone();
            if let Some(callback) = callback {
                callback();
            }
        }

        /// Installs `callback` on `observer`.
        pub(crate) fn observe(observer: &Observer, callback: impl Fn() + Send + Sync + 'static) {
            *observer.lock().unwrap() = Some(Arc::new(callback));
        }

        pub(crate) struct Fixture {
            pub server: WalletServer,
            pub raw: String,
            pub seed_reads: Arc<AtomicU32>,
            clock_after_seed: Arc<std::sync::atomic::AtomicU64>,
            _clock: Arc<
                std::sync::Mutex<Option<stellar_agent_network::mainnet::clock::TestClockGuard>>,
            >,
            /// Runs before every read of the signing seed.
            pub on_seed_read: Observer,
            /// Runs before every read of the enrolled signer identity record.
            pub on_identity_read: Observer,
            /// Runs before every read of the window-state key, which every
            /// authorization ledger operation reads.
            pub on_window_key_read: Observer,
            pub envelope: SignedTestEnvelope,
            _home: StellarAgentHomeGuard,
            _dir: tempfile::TempDir,
        }

        pub(crate) fn put(entry: &KeyringEntryRef, value: &str) {
            keyring_core::Entry::new(&entry.service, &entry.account)
                .unwrap()
                .set_password(value)
                .unwrap();
        }

        impl Fixture {
            pub(crate) fn new(edit: impl FnOnce(String) -> String) -> Self {
                Self::with_profile(edit, |_| {})
            }

            /// [`Fixture::new`] with `profile_edit` applied to the stored
            /// profile before the server starts.
            pub(crate) fn with_profile(
                edit: impl FnOnce(String) -> String,
                profile_edit: impl FnOnce(&mut Profile),
            ) -> Self {
                let dir = tempfile::tempdir().unwrap();
                let home = StellarAgentHomeGuard::new(dir.path());
                stellar_agent_core::audit_log::AuditWriterRegistry::remove_for_test("operator");
                let envelope = SignedTestEnvelope::builder([42; 32])
                    .network_passphrase(stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE)
                    .amount_stroops(10)
                    .sequence(2)
                    .unsigned()
                    .build();
                let mut profile = Profile::builder_mainnet_named(
                    "operator",
                    "https://rpc.example.invalid",
                    "stellar-agent-signer-operator",
                    envelope.source(),
                    "stellar-agent-nonce-operator",
                    "default",
                )
                .build();
                profile.audit_log_path = dir.path().join("audit.jsonl");
                profile_edit(&mut profile);
                let seed_reads = Arc::new(AtomicU32::new(0));
                let reads = Arc::clone(&seed_reads);
                let clock_after_seed = Arc::new(std::sync::atomic::AtomicU64::new(0));
                let advance = Arc::clone(&clock_after_seed);
                let clock = Arc::new(std::sync::Mutex::new(None));
                let clock_hook = Arc::downgrade(&clock);
                let on_seed_read = Observer::default();
                let on_identity_read = Observer::default();
                let on_window_key_read = Observer::default();
                let (seed, identity, window) = (
                    Arc::clone(&on_seed_read),
                    Arc::clone(&on_identity_read),
                    Arc::clone(&on_window_key_read),
                );
                let identity_ref = signer_identity_entry_ref(&profile.mcp_signer_default);
                keyring_mock::install_with_read_hooks(vec![
                    keyring_mock::ReadHook::new(
                        &profile.mcp_signer_default.service,
                        &profile.mcp_signer_default.account,
                        Arc::new(move || {
                            reads.fetch_add(1, Ordering::SeqCst);
                            let now = advance.load(Ordering::SeqCst);
                            if now != 0
                                && let Some(clock) = clock_hook.upgrade()
                            {
                                *clock.lock().unwrap() = Some(
                                    stellar_agent_network::mainnet::clock::set_now_ms_for_test(now),
                                );
                            }
                            notify(&seed);
                        }),
                    ),
                    keyring_mock::ReadHook::new(
                        &identity_ref.service,
                        &identity_ref.account,
                        Arc::new(move || notify(&identity)),
                    ),
                    keyring_mock::ReadHook::new(
                        &profile.policy_window_state_key_id.service,
                        &profile.policy_window_state_key_id.account,
                        Arc::new(move || notify(&window)),
                    ),
                ])
                .unwrap();
                let owner = ed25519_dalek::SigningKey::from_bytes(&[11; 32]);
                let owner_key =
                    stellar_strkey::ed25519::PublicKey(owner.verifying_key().to_bytes())
                        .to_string();
                put(&profile.policy_owner_key_id, &owner_key);
                put(&KeyringEntryRef::default_owner_key("operator"), &owner_key);
                put(
                    &profile.mcp_signer_default,
                    &stellar_strkey::Unredacted(&stellar_strkey::ed25519::PrivateKey([42; 32]))
                        .to_string(),
                );
                put(
                    &signer_identity_entry_ref(&profile.mcp_signer_default),
                    &stellar_agent_core::profile::signer_identity::SignerIdentityRecord::agent(
                        ed25519_dalek::SigningKey::from_bytes(&[42; 32])
                            .verifying_key()
                            .to_bytes(),
                    )
                    .render(),
                );
                for key in [
                    &profile.policy_window_state_key_id,
                    &profile.audit_log_hash_chain_key_id,
                    &profile.attestation_key_id,
                    &profile.mcp_nonce_key_alias,
                ] {
                    stellar_agent_network::keyring::rotate_keyring_secret_32(
                        &key.service,
                        &key.account,
                    )
                    .unwrap();
                }
                loader::save_to_dir("operator", &profile, &default_profile_dir().unwrap()).unwrap();
                let raw = include_str!("../../../stellar-agent-core/tests/fixtures/policy-v2.toml")
                    .replace(
                        &"0".repeat(64),
                        &stellar_agent_core::hex::encode(&sha2::Sha256::digest(
                            b"installation-nonce",
                        )),
                    )
                    .replace(
                        "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
                        envelope.destination(),
                    )
                    .replace("decision = \"require_approval\"", "decision = \"allow\"")
                    .replace("ttl_secs = 3600", "")
                    .replace("reason = \"review\"", "");
                let rule = raw[raw.find("[[rules]]").unwrap()..].to_owned();
                let token = stellar_strkey::Contract([3; 32]).to_string().to_string();
                let x402 = rule
                    .replace("stellar_pay", "stellar_x402_create_payment")
                    .replace("\"native\"", &format!("\"{token}\""));
                let raw = raw.replacen(
                    "[[rules]]",
                    &format!("\"{token}\" = \"10000000000\"\n\n[[rules]]"),
                    1,
                );
                let raw = edit(format!(
                    "{raw}\n{}\n{x402}\n[[rules]]\nmatch = {{tool = \"stellar_balances\", chain = \"stellar:mainnet\"}}\ncriteria = []\ndecision = \"allow\"\n",
                    rule.replace("stellar_pay", "stellar_pay_commit")
                ));
                Self::write_policy(&raw);
                drop(
                    crate::transport::build_server(
                        profile.clone(),
                        stellar_agent_core::audit_log::BindingCheck::Enforce,
                    )
                    .unwrap(),
                );
                put(
                    &mainnet_enablement_entry_ref(&profile.policy_window_state_key_id),
                    "installation-nonce",
                );
                let server = stellar_agent_mcp_transport_build(profile);
                Self {
                    server,
                    raw,
                    seed_reads,
                    clock_after_seed,
                    _clock: clock,
                    on_seed_read,
                    on_identity_read,
                    on_window_key_read,
                    envelope,
                    _home: home,
                    _dir: dir,
                }
            }

            pub(crate) fn write_policy(raw: &str) {
                let owner = ed25519_dalek::SigningKey::from_bytes(&[11; 32]);
                let signature = sign(&digest(&canonical_bytes(raw).unwrap()), &owner);
                let directory = default_policy_dir().unwrap();
                std::fs::create_dir_all(&directory).unwrap();
                std::fs::write(
                    directory.join("operator.toml"),
                    format!(
                        "{raw}\n[signature]\nowner_id = \"{}\"\nsig = \"{}\"\n",
                        stellar_strkey::ed25519::PublicKey(owner.verifying_key().to_bytes()),
                        stellar_agent_core::hex::encode(&signature)
                    ),
                )
                .unwrap();
            }

            pub(crate) fn args(&self) -> serde_json::Value {
                let mut args = stellar_agent_core::envelope_decode::decode_authoritative_args(
                    self.envelope.envelope_xdr(),
                    "stellar_pay_commit",
                )
                .unwrap();
                args["chain_id"] = serde_json::json!("stellar:mainnet");
                args
            }

            pub(crate) fn requirements(&self) -> stellar_agent_x402::wire::PaymentRequirements {
                serde_json::from_value(serde_json::json!({"scheme":"exact", "network":"stellar:pubnet", "asset":stellar_strkey::Contract([3;32]).to_string().as_str(),
                    "amount":"10", "payTo":self.envelope.destination(), "maxTimeoutSeconds":60, "extra":{"areFeesSponsored":true}})).unwrap()
            }

            pub(crate) fn attest(
                &self,
                entry: &stellar_agent_core::approval::PendingApproval,
            ) -> String {
                self.attest_bound(entry, "operator", "stellar:mainnet")
            }

            /// Attests `entry` as the operator does, bound to `profile` and
            /// `chain`, and returns the attestation.
            pub(crate) fn attest_bound(
                &self,
                entry: &stellar_agent_core::approval::PendingApproval,
                profile_name: &str,
                chain: &str,
            ) -> String {
                use stellar_agent_core::approval::{
                    AttestationBinding, ConsentAudit, Surface, attest_and_persist,
                    load_attestation_key,
                };
                let profile = self.server.security_profile();
                let mut store = stellar_agent_core::approval::PendingApprovalStore::open(
                    self.server
                        .resolve_approval_dir()
                        .unwrap()
                        .join("operator.toml"),
                )
                .unwrap();
                let now = stellar_agent_core::timefmt::now_unix_ms().unwrap();
                if store.get(&entry.approval_nonce).is_none() {
                    store.insert(entry.clone(), now).unwrap();
                }
                let readiness = stellar_agent_network::mainnet::audit_readiness::audit_readiness(
                    profile, "operator",
                )
                .unwrap();
                let key = load_attestation_key(
                    &profile.attestation_key_id,
                    &stellar_agent_core::profile::owner_key::OwnerKeyContext::for_profile(
                        "operator", profile,
                    ),
                )
                .unwrap();
                attest_and_persist(
                    &mut store,
                    entry,
                    &key,
                    &AttestationBinding::new(profile_name, chain),
                    Surface::Cli,
                    ConsentAudit::Writer(&mut readiness.writer().lock().unwrap()),
                    None,
                    |_, _| Err("unexpected grant".to_owned()),
                )
                .unwrap();
                store
                    .get(&entry.approval_nonce)
                    .unwrap()
                    .attestation_blob_b64
                    .clone()
                    .unwrap()
            }
        }

        fn stellar_agent_mcp_transport_build(profile: Profile) -> WalletServer {
            crate::transport::build_selected_server(
                profile,
                ProfileNameSource::Flag,
                stellar_agent_core::audit_log::BindingCheck::Enforce,
            )
            .unwrap()
        }

        #[test]
        #[serial_test::serial(keyring)]
        fn startup_retains_authority_and_rechecks_unchanged_facts() {
            let f = Fixture::new(|raw| raw);
            let guard = f
                .server
                .mainnet_write_admission(stellar_agent_network::mainnet::MainnetConsumer::McpPay)
                .unwrap();
            assert_eq!(guard.context.profile_name(), "operator");
            assert_eq!(guard.context.authority(), "https://rpc.example.invalid");
            assert!(f.server.verify_mainnet_freshness(&guard).is_ok());
            assert!(
                f.server
                    .mainnet_write_admission(
                        stellar_agent_network::mainnet::MainnetConsumer::X402Authenticated
                    )
                    .is_ok()
            );
            for consumer in [
                stellar_agent_network::mainnet::MainnetConsumer::CliPay,
                stellar_agent_network::mainnet::MainnetConsumer::CliClaim,
                stellar_agent_network::mainnet::MainnetConsumer::CliCreateAccount,
                stellar_agent_network::mainnet::MainnetConsumer::CliTrustline,
            ] {
                assert!(
                    f.server.mainnet_write_admission(consumer).is_err(),
                    "{consumer:?}"
                );
            }
        }

        #[test]
        #[serial_test::serial(keyring)]
        fn mainnet_admission_identifies_each_missing_startup_authority() {
            use stellar_agent_network::mainnet::MainnetConsumer;
            let f = Fixture::new(|raw| raw);
            for (missing, expected) in [
                ("engine", "V1 policy engine"),
                ("policy", "verified mainnet policy"),
                ("enablement", "verified enablement"),
                ("context", "enabled profile context"),
                ("directory", "selected profiles directory"),
                ("injected", "verified mainnet policy"),
            ] {
                let mut server = f.server.clone();
                match missing {
                    "engine" => {
                        Arc::make_mut(&mut server.profile).policy.engine = PolicyEngineKind::Noop
                    }
                    "policy" => server.verified_policy = None,
                    "enablement" => server.enablement = None,
                    "context" => server.mainnet_context = None,
                    "directory" => server.profiles_dir = None,
                    "injected" => server.set_policy_engine_for_test(Arc::new(
                        MockPolicyEngine::returns(Ok(Decision::Allow)),
                    )),
                    _ => unreachable!(),
                }
                let refusal = match server.mainnet_write_admission(MainnetConsumer::McpPay) {
                    Ok(_) => panic!("admitted missing {missing}"),
                    Err(refusal) => refusal,
                };
                let (code, message, _) = assert_business_envelope(&refusal);
                assert_eq!(code, "network.mainnet_write_forbidden");
                assert!(message.contains(expected), "{missing}: {message}");
            }
            assert!(
                WalletServer::new_with_selection(
                    (*f.server.profile).clone(),
                    ProfileNameSource::Env,
                    &default_profile_dir().unwrap(),
                )
                .is_err()
            );
            assert_eq!(f.seed_reads.load(Ordering::SeqCst), 0);
        }

        #[test]
        #[serial_test::serial(keyring)]
        fn rotated_enablement_requires_restart_before_action_access() {
            let f = Fixture::new(|raw| raw);
            let guard = f
                .server
                .mainnet_write_admission(stellar_agent_network::mainnet::MainnetConsumer::McpPay)
                .unwrap();
            put(
                &mainnet_enablement_entry_ref(&f.server.profile.policy_window_state_key_id),
                "rotated-installation",
            );
            let before = stellar_agent_network::client::constructions_on_this_thread();
            let result = f.server.verify_mainnet_freshness(&guard).unwrap_err();
            let (_, code, message) = error_envelope_parts(&result);
            assert_eq!(code, "network.mainnet_write_forbidden");
            assert!(message.contains("enablement or policy changed, restart the server"));
            assert_eq!(f.seed_reads.load(Ordering::SeqCst), 0);
            assert_eq!(
                before,
                stellar_agent_network::client::constructions_on_this_thread()
            );
        }

        #[test]
        #[serial_test::serial(keyring)]
        fn resigned_policy_requires_restart_without_advancing_pin() {
            let f = Fixture::new(|raw| raw);
            let guard = f
                .server
                .mainnet_write_admission(stellar_agent_network::mainnet::MainnetConsumer::McpPay)
                .unwrap();
            let entry = &f.server.profile.policy_window_state_key_id;
            let pin_ref =
                stellar_agent_core::policy::pin::PinScope::new(&f.server.window_path, entry)
                    .pin_entry_ref();
            let pin = keyring_core::Entry::new(&pin_ref.service, &pin_ref.account).unwrap();
            let before = pin.get_password().unwrap();
            Fixture::write_policy(&f.raw.replace("sequence = 7", "sequence = 8"));
            let refusal = f.server.verify_mainnet_freshness(&guard).unwrap_err();
            assert_eq!(
                error_envelope_parts(&refusal).1,
                "network.mainnet_write_forbidden"
            );
            assert_eq!(pin.get_password().unwrap(), before);
        }

        #[test]
        #[serial_test::serial(keyring)]
        fn compare_only_reverification_refuses_a_missing_lock_without_creating_it() {
            let f = Fixture::new(|raw| raw);
            let guard = f
                .server
                .mainnet_write_admission(stellar_agent_network::mainnet::MainnetConsumer::McpPay)
                .unwrap();
            let lock =
                stellar_agent_core::policy::state_lock::window_lock_path(&f.server.window_path);
            if lock.exists() {
                std::fs::remove_file(&lock).unwrap();
            }
            let result = f.server.verify_mainnet_freshness(&guard).unwrap_err();
            let (_, code, message) = error_envelope_parts(&result);
            assert_eq!(code, "network.mainnet_write_forbidden");
            assert!(message.contains("restart the server"), "{message}");
            // The compare-only load behind that refusal reads no pin on an
            // installation that holds a nonce.
            use stellar_agent_core::policy::v1::{
                PolicyStateStore,
                verified::{OwnerKeySource, PinMode, PolicyLoad, load_verified_policy},
            };
            let refusal = load_verified_policy(
                &PolicyLoad {
                    path: &default_policy_dir().unwrap().join("operator.toml"),
                    profile: &f.server.profile,
                    profile_name: "operator",
                    owner_pubkey: &ed25519_dalek::SigningKey::from_bytes(&[11; 32])
                        .verifying_key()
                        .to_bytes(),
                    owner_source: OwnerKeySource::Keyring,
                    window_path: &f.server.window_path,
                },
                PolicyStateStore::new(),
                PinMode::CompareOnly,
            )
            .err()
            .unwrap();
            assert_eq!(refusal.wire_code(), "policy.pin_absent");
            assert!(!lock.exists());
        }

        #[tokio::test]
        #[serial_test::serial(keyring)]
        async fn dispatch_carries_evaluation_ttls_and_exact_confirmation_scope() {
            let f = Fixture::new(|raw| raw);
            let args = f.args();
            let allowed = f
                .server
                .dispatch_gate("stellar_pay_commit", &args, "stellar:mainnet")
                .await
                .unwrap();
            assert_eq!(allowed.governing_ttl_ms(), 600_000);
            for tool in [
                "stellar_pay",
                "stellar_pay_commit",
                "stellar_claim",
                "stellar_claim_commit",
                "stellar_create_account",
                "stellar_create_account_commit",
                "stellar_trustline",
                "stellar_trustline_commit",
                "stellar_x402_create_payment",
                "stellar_x402_authenticated_payment",
            ] {
                let outcome = f
                    .server
                    .force_mainnet_confirmation(
                        tool,
                        DispatchOutcome::Allow(AllowOutcome {
                            value_effects: None,
                            governing_ttl_ms: 600_000,
                        }),
                    )
                    .unwrap();
                let DispatchOutcome::RequireApproval(approval) = outcome else {
                    panic!("confirmation omitted for {tool}")
                };
                assert_eq!(approval.request.ttl_seconds, 600);
                assert_eq!(
                    approval.request.reason.as_deref(),
                    Some("mainnet confirmation")
                );
                assert!(approval.request.approval_url.is_none());
            }
            let read = f
                .server
                .dispatch_gate(
                    "stellar_balances",
                    &serde_json::json!({"chain_id":"stellar:mainnet"}),
                    "stellar:mainnet",
                )
                .await
                .unwrap();
            assert!(matches!(
                f.server
                    .force_mainnet_confirmation("stellar_balances", read)
                    .unwrap(),
                DispatchOutcome::Allow(_)
            ));
        }

        #[tokio::test]
        #[serial_test::serial(keyring)]
        async fn paired_ttl_preserves_the_minimum_for_every_decision_order() {
            for (prepare, commit, expected) in [
                (None, Some(60_u32), 60),
                (Some(60), Some(120), 60),
                (Some(120), Some(60), 60),
                (Some(900), None, 600),
                (Some(120), Some(120), 120),
            ] {
                let f = Fixture::new(|raw| {
                    let mut doc: toml_edit::DocumentMut = raw.parse().unwrap();
                    for (index, ttl) in [(0, prepare), (1, commit)] {
                        let rule = doc["rules"]
                            .as_array_of_tables_mut()
                            .unwrap()
                            .get_mut(index)
                            .unwrap();
                        rule["decision"] = toml_edit::value(if ttl.is_some() {
                            "require_approval"
                        } else {
                            "allow"
                        });
                        if let Some(ttl) = ttl {
                            rule["ttl_secs"] = toml_edit::value(i64::from(ttl));
                            rule["reason"] = toml_edit::value("operator rule");
                        }
                    }
                    doc.to_string()
                });
                let server = &f.server;
                let outcome = server
                    .dispatch_gate("stellar_pay", &f.args(), "stellar:mainnet")
                    .await
                    .unwrap();
                assert_eq!(
                    outcome.governing_ttl_ms(),
                    u64::from(prepare.unwrap_or(600)) * 1000
                );
                let paired = server
                    .paired_commit_outcome(
                        outcome,
                        f.envelope.envelope_xdr(),
                        "stellar_pay_commit",
                        "stellar:mainnet",
                        None,
                        None,
                    )
                    .await
                    .unwrap();
                let DispatchOutcome::RequireApproval(approval) = paired else {
                    panic!("missing paired confirmation")
                };
                assert_eq!(approval.governing_ttl_ms, expected * 1000);
                assert_eq!(u64::from(approval.request.ttl_seconds), expected);
                let reason = match (prepare, commit) {
                    (_, Some(_)) | (Some(_), None) => "operator rule",
                    (None, None) => "mainnet confirmation",
                };
                assert_eq!(approval.request.reason.as_deref(), Some(reason));
                assert!(
                    approval.value_effects.is_some(),
                    "the payment's effects stay"
                );
            }
        }

        /// A preparation whose paired commit rule denies refuses with the
        /// denial's code and persists no approval.
        #[tokio::test]
        #[serial_test::serial(keyring)]
        async fn paired_preparation_denial_persists_no_approval() {
            for tool in Tool::ALL {
                let rpc = wiremock::MockServer::start().await;
                let f = routed_fixture(
                    move |raw| {
                        let mut doc: toml_edit::DocumentMut = classic_policy(&raw).parse().unwrap();
                        for rule in doc["rules"].as_array_of_tables_mut().unwrap().iter_mut() {
                            if rule["match"]["tool"].as_str() == Some(tool.commit_name()) {
                                rule["decision"] = toml_edit::value("deny");
                            }
                        }
                        doc.to_string()
                    },
                    &rpc,
                );
                let _control = mount_rpc(&f, &rpc).await;
                let result = wire(&tool.prepare(&f.server, &tool.prepare_args(&f)).await);
                assert_eq!(result["ok"], false, "{tool:?}: {result}");
                assert!(
                    result["error"]["code"]
                        .as_str()
                        .unwrap()
                        .starts_with("policy.deny."),
                    "{tool:?}: {result}"
                );
                assert!(
                    !f.server
                        .resolve_approval_dir()
                        .unwrap()
                        .join("operator.toml")
                        .exists(),
                    "{tool:?}"
                );
            }
        }

        /// The preparation persists the paired approval: the minimum lifetime
        /// of the two rules and the reason of the governing rule.
        #[tokio::test]
        #[serial_test::serial(keyring)]
        async fn paired_preparation_persists_the_minimum_lifetime_and_reason() {
            for (prepare, commit, ttl_ms, reason) in [
                (Some(120_u32), Some(60_u32), 60_000, "commit rule"),
                (Some(60), Some(120), 60_000, "commit rule"),
                (Some(120), None, 120_000, "prepare rule"),
                (None, Some(60), 60_000, "commit rule"),
                (None, None, 600_000, "mainnet confirmation"),
            ] {
                let run = ClassicRun::with(
                    Tool::Pay,
                    move |raw| {
                        let mut doc: toml_edit::DocumentMut = raw.parse().unwrap();
                        for rule in doc["rules"].as_array_of_tables_mut().unwrap().iter_mut() {
                            let (ttl, label) = match rule["match"]["tool"].as_str() {
                                Some("stellar_pay") => (prepare, "prepare rule"),
                                Some("stellar_pay_commit") => (commit, "commit rule"),
                                _ => continue,
                            };
                            if let Some(ttl) = ttl {
                                rule["decision"] = toml_edit::value("require_approval");
                                rule["ttl_secs"] = toml_edit::value(i64::from(ttl));
                                rule["reason"] = toml_edit::value(label);
                            }
                        }
                        doc.to_string()
                    },
                    |_| {},
                    |_| {},
                )
                .await;
                assert_eq!(
                    run.entry.expires_at_unix_ms - run.entry.created_at_unix_ms,
                    ttl_ms,
                    "{prepare:?} {commit:?}"
                );
                assert_eq!(
                    run.entry.reason.as_deref(),
                    Some(reason),
                    "{prepare:?} {commit:?}"
                );
            }
        }

        #[tokio::test]
        #[serial_test::serial(keyring)]
        async fn paired_decode_failure_refuses_before_pending_persistence() {
            let f = Fixture::new(|raw| raw);
            let outcome = f
                .server
                .dispatch_gate("stellar_pay", &f.args(), "stellar:mainnet")
                .await
                .unwrap();
            let error = f
                .server
                .paired_commit_outcome(
                    outcome,
                    "broken",
                    "stellar_pay_commit",
                    "stellar:mainnet",
                    None,
                    None,
                )
                .await
                .unwrap_err();
            assert_eq!(error.code(), "simulation.divergence");
            assert!(
                !f.server
                    .resolve_approval_dir()
                    .unwrap()
                    .join("operator.toml")
                    .exists()
            );
        }

        #[tokio::test]
        #[serial_test::serial(keyring)]
        async fn mainnet_gate_returns_a_real_classic_witness_and_checks_subject() {
            use stellar_agent_core::approval::{PendingApproval, process_uid_for_attestation};
            let f = Fixture::new(|raw| raw);
            let entry = PendingApproval::new_payment_pending(
                f.envelope.envelope_xdr().to_owned(),
                f.envelope.envelope_xdr().as_bytes(),
                f.envelope.destination().to_owned(),
                10,
                "XLM".to_owned(),
                None,
                100,
                2,
                process_uid_for_attestation().unwrap(),
                3_600_000,
            )
            .unwrap();
            let blob = f.attest(&entry);
            let outcome = f
                .server
                .dispatch_gate("stellar_pay_commit", &f.args(), "stellar:mainnet")
                .await
                .unwrap();
            let outcome = f
                .server
                .force_mainnet_confirmation("stellar_pay_commit", outcome)
                .unwrap();
            let witness = verify_attestation_gate(
                &f.server,
                &outcome,
                GatedApprovalKind::Payment,
                f.envelope.envelope_xdr(),
                Some(&entry.approval_nonce),
                Some(&blob),
                "stellar_pay_commit",
            )
            .await
            .unwrap();
            assert!(witness.is_some());
            let witness = witness.unwrap();
            assert_eq!(witness.expires_at_ms() - witness.created_at_ms(), 3_600_000);
            let refusal = verify_attestation_gate(
                &f.server,
                &outcome,
                GatedApprovalKind::Payment,
                "changed",
                Some(&entry.approval_nonce),
                Some(&blob),
                "stellar_pay_commit",
            )
            .await
            .unwrap_err();
            assert_eq!(error_envelope_parts(&refusal).1, "policy.approval_required");
            assert_eq!(f.seed_reads.load(Ordering::SeqCst), 0);
        }

        #[tokio::test]
        #[serial_test::serial(keyring)]
        async fn paired_denial_and_evaluation_failure_leave_no_pending_approval() {
            for denial in [true, false] {
                let f = Fixture::new(|raw| {
                    let mut document = raw.parse::<toml_edit::DocumentMut>().unwrap();
                    let rule = document["rules"]
                        .as_array_of_tables_mut()
                        .unwrap()
                        .get_mut(1)
                        .unwrap();
                    if denial {
                        rule["decision"] = toml_edit::value("deny");
                    } else {
                        let criterion = "{kind = \"minimum_reserve\", margin_stroops = 0}"
                            .parse::<toml_edit::Value>()
                            .unwrap();
                        rule["criteria"].as_array_mut().unwrap().push(criterion);
                    }
                    document.to_string()
                });
                let prepare = f
                    .server
                    .dispatch_gate("stellar_pay", &f.args(), "stellar:mainnet")
                    .await
                    .unwrap();
                let failure = f
                    .server
                    .paired_commit_outcome(
                        prepare,
                        f.envelope.envelope_xdr(),
                        "stellar_pay_commit",
                        "stellar:mainnet",
                        None,
                        None,
                    )
                    .await
                    .unwrap_err();
                if denial {
                    assert!(failure.code().starts_with("policy.deny."));
                } else {
                    assert_eq!(failure.code(), "policy.engine_required");
                }
                assert!(
                    !f.server
                        .resolve_approval_dir()
                        .unwrap()
                        .join("operator.toml")
                        .exists()
                );
                assert_eq!(f.seed_reads.load(Ordering::SeqCst), 0);
            }
        }

        #[tokio::test]
        #[serial_test::serial(keyring)]
        async fn mainnet_gate_checks_kind_age_terminal_states_and_keys() {
            use stellar_agent_core::approval::{
                ConsumedOutcome, PendingApproval, PendingApprovalStore, process_uid_for_attestation,
            };
            struct FixedClock(u64);
            impl stellar_agent_core::timefmt::Clock for FixedClock {
                fn now_unix_ms(
                    &self,
                ) -> Result<u64, stellar_agent_core::wallet::WalletLifecycleError> {
                    Ok(self.0)
                }
            }
            for change in [
                "kind",
                "attestation",
                "profile",
                "chain",
                "age",
                "rejected",
                "consumed",
                "key",
            ] {
                let mut f = Fixture::new(|raw| raw);
                let entry = PendingApproval::new_payment_pending(
                    f.envelope.envelope_xdr().to_owned(),
                    f.envelope.envelope_xdr().as_bytes(),
                    f.envelope.destination().to_owned(),
                    10,
                    "XLM".to_owned(),
                    None,
                    100,
                    2,
                    process_uid_for_attestation().unwrap(),
                    3_600_000,
                )
                .unwrap();
                let mut blob = match change {
                    "profile" => f.attest_bound(&entry, "other", "stellar:mainnet"),
                    "chain" => f.attest_bound(&entry, "operator", "stellar:testnet"),
                    _ => f.attest(&entry),
                };
                let mut kind = GatedApprovalKind::Payment;
                let expected_code = match change {
                    "profile" | "chain" => "policy.approval_required",
                    "kind" => {
                        kind = GatedApprovalKind::Trustline;
                        "policy.approval_required"
                    }
                    "attestation" => {
                        blob = "A".repeat(43);
                        "policy.approval_required"
                    }
                    "age" => {
                        f.server.clock = Arc::new(FixedClock(entry.created_at_unix_ms + 600_000));
                        "policy.approval_required"
                    }
                    "key" => {
                        let key = &f.server.security_profile().attestation_key_id;
                        keyring_core::Entry::new(&key.service, &key.account)
                            .unwrap()
                            .delete_credential()
                            .unwrap();
                        "policy.approval_required"
                    }
                    terminal => {
                        let mut store = PendingApprovalStore::open(
                            f.server
                                .resolve_approval_dir()
                                .unwrap()
                                .join("operator.toml"),
                        )
                        .unwrap();
                        if terminal == "rejected" {
                            assert!(
                                store
                                    .reject(
                                        &entry.approval_nonce,
                                        entry.created_at_unix_ms,
                                        600_000
                                    )
                                    .unwrap()
                            );
                            "policy.approval_rejected"
                        } else {
                            assert!(
                                store
                                    .consume(
                                        &entry.approval_nonce,
                                        &"a".repeat(64),
                                        ConsumedOutcome::Confirmed
                                    )
                                    .unwrap()
                            );
                            "policy.approval_consumed"
                        }
                    }
                };
                let outcome = f
                    .server
                    .dispatch_gate("stellar_pay_commit", &f.args(), "stellar:mainnet")
                    .await
                    .unwrap();
                let outcome = f
                    .server
                    .force_mainnet_confirmation("stellar_pay_commit", outcome)
                    .unwrap();
                let failure = verify_attestation_gate(
                    &f.server,
                    &outcome,
                    kind,
                    f.envelope.envelope_xdr(),
                    Some(&entry.approval_nonce),
                    Some(&blob),
                    "stellar_pay_commit",
                )
                .await
                .unwrap_err();
                assert_eq!(error_envelope_parts(&failure).1, expected_code, "{change}");
                assert_eq!(f.seed_reads.load(Ordering::SeqCst), 0);
            }
        }
        /// [`Fixture::with_profile`] whose server routes the primary endpoint
        /// host to `primary` and the oracle host to `oracle`.
        pub(crate) fn routed_fixture_with(
            raw_edit: impl FnOnce(String) -> String,
            profile_edit: impl FnOnce(&mut Profile),
            primary: &wiremock::MockServer,
            oracle: &wiremock::MockServer,
        ) -> Fixture {
            let mut f = Fixture::with_profile(raw_edit, profile_edit);
            let mut profile = (*f.server.profile).clone();
            profile.oracle_provider_url = Some("https://oracle.example.invalid".parse().unwrap());
            let providers = profile.providers.get_or_insert_with(Default::default);
            providers.primary = Some(PrimaryProviderRecord::new("primary", "rpc.example.invalid"));
            providers.oracle = Some(ProviderRecord::new(
                "oracle",
                "oracle.example.invalid",
                true,
            ));
            loader::save_to_dir("operator", &profile, &default_profile_dir().unwrap()).unwrap();
            f.server = WalletServer::new_with_selection_and_routes_for_test(
                profile,
                ProfileNameSource::Flag,
                &default_profile_dir().unwrap(),
                &[
                    ("rpc.example.invalid", primary.uri().as_str()),
                    ("oracle.example.invalid", oracle.uri().as_str()),
                ],
            )
            .unwrap();
            f
        }

        /// [`routed_fixture_with`] with one server for both hosts.
        pub(crate) fn routed_fixture(
            raw_edit: impl FnOnce(String) -> String,
            rpc: &wiremock::MockServer,
        ) -> Fixture {
            routed_fixture_with(raw_edit, |_| {}, rpc, rpc)
        }

        pub(crate) fn wire(result: &rmcp::model::CallToolResult) -> serde_json::Value {
            serde_json::from_str(&result.content[0].as_text().unwrap().text).unwrap()
        }

        /// The authorization ledger, or `None` before its first write.
        pub(crate) fn ledger(f: &Fixture) -> Option<serde_json::Value> {
            let bytes = std::fs::read(&f.server.window_path).ok()?;
            Some(serde_json::from_slice(&bytes[32..]).unwrap())
        }

        fn ledger_state(f: &Fixture) -> serde_json::Value {
            ledger(f).unwrap()
        }

        /// Every authorization record of the ledger.
        pub(crate) fn authorizations(f: &Fixture) -> Vec<serde_json::Value> {
            ledger(f)
                .and_then(|state| state["authorizations"].as_array().cloned())
                .unwrap_or_default()
        }

        /// Every window record of the ledger, across its buckets.
        fn window_records(f: &Fixture) -> Vec<serde_json::Value> {
            ledger(f)
                .and_then(|state| state["entries"].as_array().cloned())
                .unwrap_or_default()
                .iter()
                .flat_map(|bucket| bucket["records"].as_array().cloned().unwrap_or_default())
                .collect()
        }

        /// The pending approval stored under `nonce`.
        pub(crate) fn stored_approval(
            f: &Fixture,
            nonce: &str,
        ) -> Option<stellar_agent_core::approval::PendingApproval> {
            stellar_agent_core::approval::PendingApprovalStore::open(
                f.server
                    .resolve_approval_dir()
                    .unwrap()
                    .join("operator.toml"),
            )
            .unwrap()
            .get(nonce)
            .cloned()
        }

        fn is_consumed(entry: &stellar_agent_core::approval::PendingApproval) -> bool {
            matches!(
                entry.kind,
                stellar_agent_core::approval::ApprovalKind::Consumed { .. }
            )
        }

        fn receipts() -> Vec<stellar_agent_core::profile::receipt::SubmissionReceipt> {
            stellar_agent_core::profile::receipt::ReceiptStore::open("operator")
                .unwrap()
                .all()
                .unwrap()
        }

        /// Sets a network test hook while it lives.
        struct Armed(&'static std::sync::atomic::AtomicBool);

        impl Armed {
            fn new(flag: &'static std::sync::atomic::AtomicBool) -> Self {
                flag.store(true, Ordering::SeqCst);
                Self(flag)
            }
        }

        impl Drop for Armed {
            fn drop(&mut self) {
                self.0.store(false, Ordering::SeqCst);
            }
        }

        /// Makes a directory read-only while it lives, so nothing can be
        /// created or replaced in it.
        pub(crate) struct ReadOnlyDir(std::path::PathBuf);

        impl ReadOnlyDir {
            pub(crate) fn new(path: &std::path::Path) -> Self {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o500)).unwrap();
                Self(path.to_owned())
            }
        }

        impl Drop for ReadOnlyDir {
            fn drop(&mut self) {
                use std::os::unix::fs::PermissionsExt as _;
                let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
            }
        }

        /// A guard a hook creates at the moment it runs, dropped by the test.
        pub(crate) type HookGuard = Arc<std::sync::Mutex<Option<ReadOnlyDir>>>;

        /// What the RPC double answers, switched by a test, and what it saw.
        #[derive(Default)]
        pub(crate) struct RpcControl {
            /// Every request method, in order.
            methods: std::sync::Mutex<Vec<String>>,
            /// Every envelope a `sendTransaction` carried.
            sent: std::sync::Mutex<Vec<String>>,
            /// The ledger at each `sendTransaction`.
            state_at_send: std::sync::Mutex<Vec<serde_json::Value>>,
            /// The ledger at each signed `simulateTransaction`.
            state_at_signed_simulation: std::sync::Mutex<Vec<serde_json::Value>>,
            /// Whether the authorized x402 row preceded each signed simulation.
            row_before_signed_simulation: std::sync::Mutex<Vec<bool>>,
            /// `getNetwork` reports testnet once the seed was read.
            pub passphrase_after_seed: AtomicBool,
            /// `getNetwork` reports testnet.
            pub testnet_passphrase: AtomicBool,
            /// `getLedgerEntries` answers a JSON-RPC error.
            pub accounts_unavailable: AtomicBool,
            /// `sendTransaction` answers a definitive `ERROR` status.
            pub send_rejected: AtomicBool,
            /// `sendTransaction` answers a hash other than the envelope's.
            pub send_hash_mismatch: AtomicBool,
            /// The unsigned `simulateTransaction` answers an error.
            pub first_simulation_error: AtomicBool,
            /// The signed `simulateTransaction` answers an error.
            pub resimulation_error: AtomicBool,
            /// The signed `simulateTransaction` answers another authorization.
            pub resimulation_other_auth: AtomicBool,
            /// Ledger entries that replace the fixture's.
            pub entries: std::sync::Mutex<Option<Vec<serde_json::Value>>>,
            /// Runs before each answer with the request method.
            pub on_request: std::sync::Mutex<Option<RequestHook>>,
        }

        /// A callback the RPC double runs before it answers a request.
        pub(crate) type RequestHook = Arc<dyn Fn(&str) + Send + Sync>;

        impl RpcControl {
            pub(crate) fn methods(&self) -> Vec<String> {
                self.methods.lock().unwrap().clone()
            }

            pub(crate) fn count(&self, method: &str) -> usize {
                self.methods
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|seen| *seen == method)
                    .count()
            }

            pub(crate) fn clear(&self) {
                self.methods.lock().unwrap().clear();
                self.sent.lock().unwrap().clear();
                self.state_at_send.lock().unwrap().clear();
                self.state_at_signed_simulation.lock().unwrap().clear();
                self.row_before_signed_simulation.lock().unwrap().clear();
            }

            pub(crate) fn sent(&self) -> Vec<String> {
                self.sent.lock().unwrap().clone()
            }

            pub(crate) fn on_request(&self, callback: impl Fn(&str) + Send + Sync + 'static) {
                *self.on_request.lock().unwrap() = Some(Arc::new(callback));
            }
        }

        struct MainnetRpc {
            entries: Vec<serde_json::Value>,
            state_path: std::path::PathBuf,
            audit_path: std::path::PathBuf,
            control: Arc<RpcControl>,
            seed_reads: Arc<AtomicU32>,
        }

        impl MainnetRpc {
            fn state(&self) -> serde_json::Value {
                std::fs::read(&self.state_path)
                    .ok()
                    .map_or(serde_json::Value::Null, |bytes| {
                        serde_json::from_slice(&bytes[32..]).unwrap()
                    })
            }

            fn simulate(&self, body: &serde_json::Value) -> serde_json::Value {
                use stellar_xdr::*;
                let envelope = TransactionEnvelope::from_xdr_base64(
                    body["params"]["transaction"].as_str().unwrap(),
                    Limits::none(),
                )
                .unwrap();
                let TransactionEnvelope::Tx(envelope) = envelope else {
                    panic!("transaction expected")
                };
                let OperationBody::InvokeHostFunction(op) = &envelope.tx.operations[0].body else {
                    panic!("invocation expected")
                };
                let HostFunction::InvokeContract(invoke) = &op.host_function else {
                    panic!("contract invocation expected")
                };
                let signed = !op.auth.is_empty();
                let refused = if signed {
                    self.control.resimulation_error.load(Ordering::SeqCst)
                } else {
                    self.control.first_simulation_error.load(Ordering::SeqCst)
                };
                if signed {
                    self.control
                        .state_at_signed_simulation
                        .lock()
                        .unwrap()
                        .push(self.state());
                    let row = std::fs::read_to_string(&self.audit_path)
                        .unwrap_or_default()
                        .lines()
                        .any(|line| {
                            let row: serde_json::Value = serde_json::from_str(line).unwrap();
                            row["kind"] == "x402_payment_authorized"
                                && row["policy_decision"] == "require_approval"
                        });
                    self.control
                        .row_before_signed_simulation
                        .lock()
                        .unwrap()
                        .push(row);
                }
                if refused {
                    return serde_json::json!({"error":"simulation refused", "latestLedger":100});
                }
                let ScVal::Address(payer) = &invoke.args[0] else {
                    panic!("payer expected")
                };
                let unsigned_entry = |nonce: i64| {
                    SorobanAuthorizationEntry {
                        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                            address: payer.clone(),
                            nonce,
                            signature_expiration_ledger: 0,
                            signature: ScVal::Void,
                        }),
                        root_invocation: SorobanAuthorizedInvocation {
                            function: SorobanAuthorizedFunction::ContractFn(invoke.clone()),
                            sub_invocations: VecM::default(),
                        },
                    }
                    .to_xdr_base64(Limits::none())
                    .unwrap()
                };
                let auth = if !signed {
                    vec![unsigned_entry(7)]
                } else if self.control.resimulation_other_auth.load(Ordering::SeqCst) {
                    vec![unsigned_entry(8)]
                } else {
                    Vec::new()
                };
                let data = SorobanTransactionData {
                    ext: SorobanTransactionDataExt::V0,
                    resources: SorobanResources {
                        footprint: LedgerFootprint {
                            read_only: VecM::default(),
                            read_write: VecM::default(),
                        },
                        instructions: 1000,
                        disk_read_bytes: 0,
                        write_bytes: 0,
                    },
                    resource_fee: 1000,
                };
                serde_json::json!({"transactionData":data.to_xdr_base64(Limits::none()).unwrap(), "minResourceFee":"1000", "latestLedger":100, "results":[{"auth":auth, "xdr":ScVal::Void.to_xdr_base64(Limits::none()).unwrap()}]})
            }

            fn send(&self, body: &serde_json::Value) -> serde_json::Value {
                use stellar_xdr::*;
                let transaction = body["params"]["transaction"].as_str().unwrap().to_owned();
                self.control.sent.lock().unwrap().push(transaction);
                self.control
                    .state_at_send
                    .lock()
                    .unwrap()
                    .push(self.state());
                let hash = if self.control.send_hash_mismatch.load(Ordering::SeqCst) {
                    "ab".repeat(32)
                } else {
                    stellar_agent_test_support::send_transaction_hash_hex(
                        body,
                        stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE,
                    )
                };
                if self.control.send_rejected.load(Ordering::SeqCst) {
                    let result = TransactionResult {
                        fee_charged: 100,
                        result: TransactionResultResult::TxBadSeq,
                        ext: TransactionResultExt::V0,
                    }
                    .to_xdr_base64(Limits::none())
                    .unwrap();
                    return serde_json::json!({"hash":hash, "status":"ERROR", "errorResultXdr":result, "latestLedger":100, "latestLedgerCloseTime":"1234567890"});
                }
                serde_json::json!({"hash":hash, "status":"PENDING", "latestLedger":100, "latestLedgerCloseTime":"1234567890"})
            }
        }

        impl wiremock::Respond for MainnetRpc {
            fn respond(&self, request: &wiremock::Request) -> wiremock::ResponseTemplate {
                let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
                let method = body["method"].as_str().unwrap();
                self.control.methods.lock().unwrap().push(method.to_owned());
                let hook = self.control.on_request.lock().unwrap().clone();
                if let Some(hook) = hook {
                    hook(method);
                }
                let answer = |result: serde_json::Value| {
                    wiremock::ResponseTemplate::new(200).set_body_json(
                        serde_json::json!({"jsonrpc":"2.0", "id":body["id"], "result":result}),
                    )
                };
                match method {
                    "getNetwork" => answer(
                        stellar_agent_test_support::signed_envelope::get_network_result(
                            if self.control.testnet_passphrase.load(Ordering::SeqCst)
                                || (self.control.passphrase_after_seed.load(Ordering::SeqCst)
                                    && self.seed_reads.load(Ordering::SeqCst) != 0)
                            {
                                stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE
                            } else {
                                stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE
                            },
                        ),
                    ),
                    "getLedgerEntries" => {
                        if self.control.accounts_unavailable.load(Ordering::SeqCst) {
                            return wiremock::ResponseTemplate::new(200).set_body_json(
                                serde_json::json!({"jsonrpc":"2.0", "id":body["id"], "error":{"code":-32603, "message":"ledger unavailable"}}),
                            );
                        }
                        let replaced = self.control.entries.lock().unwrap().clone();
                        let entries = replaced.as_ref().unwrap_or(&self.entries);
                        let keys = body["params"]["keys"].as_array().unwrap();
                        answer(
                            serde_json::json!({"entries": entries.iter().filter(|entry| keys.contains(&entry["key"])).collect::<Vec<_>>(), "latestLedger":100}),
                        )
                    }
                    "getHealth" => answer(
                        serde_json::json!({"status":"healthy", "latestLedger":100, "oldestLedger":1, "ledgerRetentionWindow":100}),
                    ),
                    "sendTransaction" => answer(self.send(&body)),
                    "getTransaction" => answer(serde_json::json!({
                        "status":"SUCCESS", "ledger":101, "txHash":body["params"]["hash"],
                        "createdAt":(stellar_agent_core::timefmt::now_unix_ms().unwrap() / 1000)
                            .to_string()
                    })),
                    "simulateTransaction" => answer(self.simulate(&body)),
                    other => panic!("unexpected method {other}"),
                }
            }
        }

        /// The ledger entries the fixture's accounts, the trustline issuer and
        /// the claimable balance answer with.
        fn fixture_entries(f: &Fixture) -> Vec<serde_json::Value> {
            use stellar_xdr::*;
            let mut entries = f.envelope.ledger_entries_result()["entries"]
                .as_array()
                .unwrap()
                .clone();
            let issuer = stellar_agent_test_support::signed_envelope::account_id_for_seed([7; 32]);
            entries.extend(
                stellar_agent_test_support::signed_envelope::ledger_entries_result_for(&[&issuer])
                    ["entries"]
                    .as_array()
                    .unwrap()
                    .clone(),
            );
            let id = ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash([0xab; 32]));
            let key = LedgerKey::ClaimableBalance(LedgerKeyClaimableBalance {
                balance_id: id.clone(),
            })
            .to_xdr_base64(Limits::none())
            .unwrap();
            let account = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
                stellar_strkey::ed25519::PublicKey::from_string(f.envelope.source())
                    .unwrap()
                    .0,
            )));
            let entry = LedgerEntryData::ClaimableBalance(ClaimableBalanceEntry {
                balance_id: id,
                claimants: vec![Claimant::ClaimantTypeV0(ClaimantV0 {
                    destination: account,
                    predicate: ClaimPredicate::Unconditional,
                })]
                .try_into()
                .unwrap(),
                asset: Asset::Native,
                amount: 10,
                ext: ClaimableBalanceEntryExt::V0,
            })
            .to_xdr_base64(Limits::none())
            .unwrap();
            entries.push(serde_json::json!({"key":key,"xdr":entry,"lastModifiedLedgerSeq":100}));
            entries
        }

        pub(crate) async fn mount_rpc(f: &Fixture, rpc: &wiremock::MockServer) -> Arc<RpcControl> {
            let control = Arc::new(RpcControl::default());
            wiremock::Mock::given(wiremock::matchers::method("POST"))
                .respond_with(MainnetRpc {
                    entries: fixture_entries(f),
                    state_path: f.server.window_path.clone(),
                    audit_path: f.server.security_profile().audit_log_path.clone(),
                    control: Arc::clone(&control),
                    seed_reads: Arc::clone(&f.seed_reads),
                })
                .mount(rpc)
                .await;
            control
        }

        /// One of the four classic commit tools.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub(crate) enum Tool {
            Pay,
            Claim,
            CreateAccount,
            Trustline,
        }

        impl Tool {
            const ALL: [Self; 4] = [Self::Pay, Self::Claim, Self::CreateAccount, Self::Trustline];

            fn commit_name(self) -> &'static str {
                match self {
                    Self::Pay => "stellar_pay_commit",
                    Self::Claim => "stellar_claim_commit",
                    Self::CreateAccount => "stellar_create_account_commit",
                    Self::Trustline => "stellar_trustline_commit",
                }
            }

            /// The preparation arguments of a below-threshold action.
            fn prepare_args(self, f: &Fixture) -> serde_json::Value {
                let issuer =
                    stellar_agent_test_support::signed_envelope::account_id_for_seed([7; 32]);
                let mut args = match self {
                    Self::Pay => {
                        serde_json::json!({"source":f.envelope.source(), "destination":f.envelope.destination(), "amount_in_stroops":"10", "asset":"native", "fee":"100"})
                    }
                    Self::CreateAccount => {
                        serde_json::json!({"source":f.envelope.source(), "destination":f.envelope.destination(), "starting_balance":"1 XLM", "fee":"100"})
                    }
                    Self::Claim => {
                        serde_json::json!({"source_account":f.envelope.source(), "balance_id":"ab".repeat(32)})
                    }
                    Self::Trustline => {
                        serde_json::json!({"from":f.envelope.source(), "asset":format!("USD:{issuer}"), "limit_stroops":"10", "fee":"100"})
                    }
                };
                args["chain_id"] = serde_json::json!("stellar:mainnet");
                args
            }

            async fn prepare(
                self,
                server: &WalletServer,
                args: &serde_json::Value,
            ) -> rmcp::model::CallToolResult {
                let args = args.clone();
                match self {
                    Self::Pay => {
                        server
                            .call_stellar_pay(serde_json::from_value(args).unwrap())
                            .await
                    }
                    Self::CreateAccount => {
                        server
                            .call_stellar_create_account(serde_json::from_value(args).unwrap())
                            .await
                    }
                    Self::Claim => {
                        server
                            .call_stellar_claim(serde_json::from_value(args).unwrap())
                            .await
                    }
                    Self::Trustline => {
                        server
                            .call_stellar_trustline(serde_json::from_value(args).unwrap())
                            .await
                    }
                }
                .unwrap()
            }

            async fn commit(
                self,
                server: &WalletServer,
                args: serde_json::Value,
            ) -> Result<rmcp::model::CallToolResult, rmcp::ErrorData> {
                match self {
                    Self::Pay => {
                        server
                            .call_stellar_pay_commit(serde_json::from_value(args).unwrap())
                            .await
                    }
                    Self::CreateAccount => {
                        server
                            .call_stellar_create_account_commit(
                                serde_json::from_value(args).unwrap(),
                            )
                            .await
                    }
                    Self::Claim => {
                        server
                            .call_stellar_claim_commit(serde_json::from_value(args).unwrap())
                            .await
                    }
                    Self::Trustline => {
                        server
                            .call_stellar_trustline_commit(serde_json::from_value(args).unwrap())
                            .await
                    }
                }
            }
        }

        /// The fixture's payment rules plus allowing rules for the other three
        /// classic tools and their commits.
        fn classic_policy(raw: &str) -> String {
            let issuer = stellar_agent_test_support::signed_envelope::account_id_for_seed([7; 32]);
            let mut doc = raw.parse::<toml_edit::DocumentMut>().unwrap();
            let rules = doc["rules"].as_array_of_tables_mut().unwrap();
            let base = rules.get(0).unwrap().clone();
            for name in ["stellar_create_account", "stellar_create_account_commit"] {
                let mut rule = base.clone();
                rule["match"]["tool"] = toml_edit::value(name);
                for criterion in rule["criteria"].as_array_mut().unwrap().iter_mut() {
                    let criterion = criterion.as_inline_table_mut().unwrap();
                    if criterion.contains_key("max_stroops") {
                        criterion.insert("max_stroops", toml_edit::Value::from("200000000"));
                    }
                }
                rules.push(rule);
            }
            let mut raw = doc.to_string();
            for name in ["stellar_claim", "stellar_claim_commit"] {
                raw.push_str(&format!("\n[[rules]]\nmatch = {{tool = \"{name}\", chain = \"stellar:mainnet\"}}\ncriteria = [{{kind = \"rate_limit\", window = \"1d\", max_calls = 10}}]\ndecision = \"allow\"\n"));
            }
            for name in ["stellar_trustline", "stellar_trustline_commit"] {
                raw.push_str(&format!("\n[[rules]]\nmatch = {{tool = \"{name}\", chain = \"stellar:mainnet\"}}\ncriteria = [{{kind = \"asset_allowlist\", assets = [\"USD:{issuer}\"]}}, {{kind = \"rate_limit\", window = \"1d\", max_calls = 10}}]\ndecision = \"allow\"\n"));
            }
            raw
        }

        /// A classic action prepared, approved and ready to commit on a routed
        /// fixture with its own primary and oracle servers.
        pub(crate) struct ClassicRun {
            pub f: Fixture,
            _primary: wiremock::MockServer,
            _oracle: wiremock::MockServer,
            pub control: Arc<RpcControl>,
            pub oracle_control: Arc<RpcControl>,
            pub tool: Tool,
            /// The commit arguments, approval included.
            pub args: serde_json::Value,
            /// The pending approval the preparation stored.
            pub entry: stellar_agent_core::approval::PendingApproval,
        }

        impl ClassicRun {
            pub(crate) async fn new(tool: Tool) -> Self {
                Self::with(tool, |raw| raw, |_| {}, |_| {}).await
            }

            /// A run whose policy, profile and preparation arguments are
            /// edited first.
            pub(crate) async fn with(
                tool: Tool,
                policy: impl FnOnce(String) -> String,
                profile: impl FnOnce(&mut Profile),
                prepare: impl FnOnce(&mut serde_json::Value),
            ) -> Self {
                let primary = wiremock::MockServer::start().await;
                let oracle = wiremock::MockServer::start().await;
                let f = routed_fixture_with(
                    |raw| policy(classic_policy(&raw)),
                    profile,
                    &primary,
                    &oracle,
                );
                let control = mount_rpc(&f, &primary).await;
                let oracle_control = mount_rpc(&f, &oracle).await;
                let mut args = tool.prepare_args(&f);
                prepare(&mut args);
                let (args, entry) = Self::prepared(&f, tool, args).await;
                Self {
                    f,
                    _primary: primary,
                    _oracle: oracle,
                    control,
                    oracle_control,
                    tool,
                    args,
                    entry,
                }
            }

            /// Prepares `args` through the tool's handler, attests the stored
            /// approval, and returns the commit arguments and that approval.
            async fn prepared(
                f: &Fixture,
                tool: Tool,
                args: serde_json::Value,
            ) -> (
                serde_json::Value,
                stellar_agent_core::approval::PendingApproval,
            ) {
                let prepared = wire(&tool.prepare(&f.server, &args).await);
                assert_eq!(prepared["ok"], true, "{tool:?}: {prepared}");
                let data = &prepared["data"];
                let nonce = data["approval"]["approval_nonce"].as_str().unwrap();
                let entry = stored_approval(f, nonce).unwrap();
                let mut args = args;
                args["approval_nonce"] = serde_json::json!(nonce);
                args["approval_attestation"] = serde_json::json!(f.attest(&entry));
                for field in ["envelope_xdr", "nonce", "expires_at_unix_ms"] {
                    args[field] = data[field].clone();
                }
                assert_eq!(f.seed_reads.load(Ordering::SeqCst), 0);
                (args, entry)
            }

            /// A second preparation of the same action on the same fixture.
            async fn prepare_again(
                &self,
            ) -> (
                serde_json::Value,
                stellar_agent_core::approval::PendingApproval,
            ) {
                Self::prepared(&self.f, self.tool, self.tool.prepare_args(&self.f)).await
            }

            /// Commits the run's arguments; the request history then holds
            /// this commit's requests only.
            pub(crate) async fn commit(&self) -> serde_json::Value {
                self.commit_with(self.args.clone()).await
            }

            pub(crate) async fn commit_with(&self, args: serde_json::Value) -> serde_json::Value {
                wire(&self.commit_raw(args).await.unwrap())
            }

            async fn commit_raw(
                &self,
                args: serde_json::Value,
            ) -> Result<rmcp::model::CallToolResult, rmcp::ErrorData> {
                self.control.clear();
                self.oracle_control.clear();
                self.tool.commit(&self.f.server, args).await
            }

            fn seed_reads(&self) -> u32 {
                self.f.seed_reads.load(Ordering::SeqCst)
            }

            /// A commit of the approved transaction changed by `change`, with
            /// its own attested approval and its own protocol nonce.
            fn crafted(
                &self,
                change: impl FnOnce(&mut stellar_xdr::Transaction),
            ) -> serde_json::Value {
                use stellar_xdr::{Limits, ReadXdr as _, TransactionEnvelope, WriteXdr as _};
                let TransactionEnvelope::Tx(mut envelope) = TransactionEnvelope::from_xdr_base64(
                    self.args["envelope_xdr"].as_str().unwrap(),
                    Limits::none(),
                )
                .unwrap() else {
                    panic!("classic envelope expected")
                };
                change(&mut envelope.tx);
                let xdr = TransactionEnvelope::Tx(envelope)
                    .to_xdr_base64(Limits::none())
                    .unwrap();
                self.approved(&xdr, 600_000)
            }

            /// The run's commit arguments for `xdr` with a new approval of
            /// `xdr` whose lifetime is `ttl_ms`, attested, and a protocol
            /// nonce minted for `xdr`.
            fn approved(&self, xdr: &str, ttl_ms: u64) -> serde_json::Value {
                let entry = approval_for(self.tool, &self.f, xdr, ttl_ms);
                let blob = self.f.attest(&entry);
                let now = stellar_agent_core::timefmt::now_unix_ms().unwrap();
                let expiry = now + 60_000;
                let nonce = self
                    .f
                    .server
                    .nonce_mint
                    .mint(
                        self.f.server.tool_catalogue.as_ref(),
                        xdr.as_bytes(),
                        now,
                        expiry,
                        self.tool.commit_name(),
                        "stellar:mainnet",
                    )
                    .unwrap();
                let mut args = self.args.clone();
                args["envelope_xdr"] = serde_json::json!(xdr);
                args["nonce"] = serde_json::json!(nonce.to_base64());
                args["expires_at_unix_ms"] = serde_json::json!(expiry);
                args["approval_nonce"] = serde_json::json!(entry.approval_nonce);
                args["approval_attestation"] = serde_json::json!(blob);
                args
            }
        }

        /// A pending approval of the kind `tool` commits, for the envelope
        /// `xdr`, with a lifetime of `ttl_ms`.
        fn approval_for(
            tool: Tool,
            f: &Fixture,
            xdr: &str,
            ttl_ms: u64,
        ) -> stellar_agent_core::approval::PendingApproval {
            use stellar_agent_core::approval::{PendingApproval, process_uid_for_attestation};
            let uid = process_uid_for_attestation().unwrap();
            let holder = f.envelope.source().to_owned();
            match tool {
                Tool::Pay | Tool::CreateAccount => PendingApproval::new_payment_pending(
                    xdr.to_owned(),
                    xdr.as_bytes(),
                    f.envelope.destination().to_owned(),
                    10,
                    "XLM".to_owned(),
                    None,
                    100,
                    2,
                    uid,
                    ttl_ms,
                ),
                Tool::Claim => PendingApproval::new_claim_pending(
                    xdr.to_owned(),
                    xdr.as_bytes(),
                    "ab".repeat(36),
                    format!("B{}", "A".repeat(57)),
                    "XLM".to_owned(),
                    10,
                    holder,
                    100,
                    2,
                    uid,
                    ttl_ms,
                ),
                Tool::Trustline => PendingApproval::new_trustline_pending(
                    xdr.to_owned(),
                    xdr.as_bytes(),
                    holder,
                    "USD".to_owned(),
                    stellar_agent_test_support::signed_envelope::account_id_for_seed([7; 32]),
                    Some(10),
                    100,
                    2,
                    uid,
                    ttl_ms,
                ),
            }
            .unwrap()
        }

        /// Asserts that `result` refused with `code` before any authorization
        /// was minted: no ledger record, no seed read, no send.
        fn assert_refused_before_mint(run: &ClassicRun, result: &serde_json::Value, code: &str) {
            let tool = run.tool;
            assert_eq!(result["ok"], false, "{tool:?}: {result}");
            assert_eq!(result["error"]["code"], code, "{tool:?}: {result}");
            assert!(authorizations(&run.f).is_empty(), "{tool:?}: {result}");
            assert_eq!(run.seed_reads(), 0, "{tool:?}");
            assert_eq!(run.control.count("sendTransaction"), 0, "{tool:?}");
            assert!(
                !is_consumed(&stored_approval(&run.f, &run.entry.approval_nonce).unwrap()),
                "{tool:?}: the approval stays unspent"
            );
        }

        /// The kinds of the rows the fixture's audit log holds, in order.
        fn audit_kinds(f: &Fixture) -> Vec<String> {
            std::fs::read_to_string(&f.server.security_profile().audit_log_path)
                .unwrap_or_default()
                .lines()
                .map(|line| {
                    serde_json::from_str::<serde_json::Value>(line).unwrap()["kind"]
                        .as_str()
                        .unwrap_or_default()
                        .to_owned()
                })
                .collect()
        }

        /// Asserts that no submission entered its pre-send recording: no
        /// receipt and no pending audit row.
        fn assert_no_pre_send_entry(run: &ClassicRun) {
            let tool = run.tool;
            assert!(receipts().is_empty(), "{tool:?}");
            assert!(
                !audit_kinds(&run.f)
                    .iter()
                    .any(|kind| kind == "value_action_pending"),
                "{tool:?}: no pending row"
            );
        }

        /// Asserts that `result` refused with `code` after the authorization
        /// was minted, which is now invalidated at `stage` with nothing sent.
        fn assert_invalidated(
            run: &ClassicRun,
            result: &serde_json::Value,
            code: &str,
            stage: &str,
        ) {
            let tool = run.tool;
            assert_eq!(result["ok"], false, "{tool:?}: {result}");
            assert_eq!(result["error"]["code"], code, "{tool:?}: {result}");
            let records = authorizations(&run.f);
            assert_eq!(records.len(), 1, "{tool:?}");
            assert_eq!(records[0]["state"], "invalidated", "{tool:?}");
            assert_eq!(records[0]["invalidation"], stage, "{tool:?}");
            assert!(
                ledger_state(&run.f)["holds"]
                    .as_array()
                    .is_none_or(Vec::is_empty),
                "{tool:?}"
            );
            assert_eq!(run.control.count("sendTransaction"), 0, "{tool:?}");
            assert_no_pre_send_entry(run);
        }

        /// Asserts that `sent` carries exactly the approved transaction of
        /// `approved` with one signature and no time bounds.
        fn assert_approved_bytes_sent(approved: &str, sent: &str) {
            use stellar_xdr::{Limits, Preconditions, ReadXdr as _, TransactionEnvelope};
            let decode = |xdr: &str| match TransactionEnvelope::from_xdr_base64(xdr, Limits::none())
                .unwrap()
            {
                TransactionEnvelope::Tx(envelope) => envelope,
                _ => panic!("classic envelope expected"),
            };
            let (approved, sent) = (decode(approved), decode(sent));
            assert_eq!(
                sent.tx, approved.tx,
                "the sent transaction is the approved one"
            );
            assert_eq!(sent.signatures.len(), 1);
            assert!(matches!(sent.tx.cond, Preconditions::None));
        }

        /// The confirmed window rows each classic accept leaves: the count of
        /// rows and the sum of their amounts.
        fn settled_rows(tool: Tool) -> (usize, u64) {
            match tool {
                Tool::Pay => (2, 11),
                Tool::CreateAccount => (2, 10_000_001),
                Tool::Claim | Tool::Trustline => (1, 1),
            }
        }

        async fn accept(tool: Tool) {
            let run = ClassicRun::new(tool).await;
            let result = run.commit().await;
            assert_eq!(result["ok"], true, "{tool:?}: {result}");
            assert_eq!(
                run.control.methods()[0],
                "getNetwork",
                "{tool:?}: the commit's own first request is the endpoint probe"
            );
            let sent = run.control.sent();
            assert_eq!(sent.len(), 1, "{tool:?}");
            assert_approved_bytes_sent(run.args["envelope_xdr"].as_str().unwrap(), &sent[0]);
            let at_send = run.control.state_at_send.lock().unwrap()[0].clone();
            assert_eq!(
                at_send["authorizations"][0]["state"], "used",
                "{tool:?}: the authorization is consumed before the send"
            );
            let records = authorizations(&run.f);
            assert_eq!(records.len(), 1, "{tool:?}");
            assert_eq!(records[0]["state"], "used", "{tool:?}");
            assert!(
                ledger_state(&run.f)["holds"]
                    .as_array()
                    .is_none_or(Vec::is_empty),
                "{tool:?}"
            );
            let rows = window_records(&run.f);
            let (count, sum) = settled_rows(tool);
            assert_eq!(rows.len(), count, "{tool:?}: {rows:?}");
            assert!(
                rows.iter().all(|row| row["status"] == "confirmed"),
                "{tool:?}: {rows:?}"
            );
            assert_eq!(
                rows.iter()
                    .map(|row| row["amount"].as_str().unwrap().parse::<u64>().unwrap())
                    .sum::<u64>(),
                sum,
                "{tool:?}"
            );
            let approval = stored_approval(&run.f, &run.entry.approval_nonce).unwrap();
            let stellar_agent_core::approval::ApprovalKind::Consumed { tx_hash, .. } =
                &approval.kind
            else {
                panic!("{tool:?}: the approval is spent")
            };
            assert_eq!(
                tx_hash.as_str(),
                result["data"]["tx_hash"].as_str().unwrap(),
                "{tool:?}"
            );
            assert_eq!(run.seed_reads(), 1, "{tool:?}");
        }

        #[tokio::test]
        #[serial_test::serial(keyring)]
        async fn mainnet_pay_accepts_and_consumes_once() {
            accept(Tool::Pay).await;
        }
        #[tokio::test]
        #[serial_test::serial(keyring)]
        async fn mainnet_claim_accepts_and_consumes_once() {
            accept(Tool::Claim).await;
        }
        #[tokio::test]
        #[serial_test::serial(keyring)]
        async fn mainnet_create_account_accepts_and_consumes_once() {
            accept(Tool::CreateAccount).await;
        }
        #[tokio::test]
        #[serial_test::serial(keyring)]
        async fn mainnet_trustline_accepts_and_consumes_once() {
            accept(Tool::Trustline).await;
        }

        /// Asserts the restart refusal with no action request, no seed read
        /// and no authorization.
        fn assert_restart_refusal(
            context: &str,
            result: &serde_json::Value,
            f: &Fixture,
            requests: usize,
        ) {
            assert_eq!(result["ok"], false, "{context}: {result}");
            assert_eq!(
                result["error"]["code"], "network.mainnet_write_forbidden",
                "{context}: {result}"
            );
            assert!(
                result["error"]["message"]
                    .as_str()
                    .unwrap()
                    .contains("enablement or policy changed, restart the server"),
                "{context}: {result}"
            );
            assert_eq!(requests, 0, "{context}: no action request after the change");
            assert_eq!(f.seed_reads.load(Ordering::SeqCst), 0, "{context}");
            assert!(authorizations(f).is_empty(), "{context}");
        }

        #[tokio::test]
        #[serial_test::serial(keyring)]
        async fn mainnet_classic_commits_refuse_changed_enablement_or_policy() {
            for tool in Tool::ALL {
                for change in ["enablement", "policy"] {
                    let run = ClassicRun::new(tool).await;
                    if change == "enablement" {
                        put(
                            &mainnet_enablement_entry_ref(
                                &run.f.server.profile.policy_window_state_key_id,
                            ),
                            "rotated-installation",
                        );
                    } else {
                        Fixture::write_policy(&run.f.raw.replace("sequence = 7", "sequence = 8"));
                    }
                    let result = run.commit().await;
                    assert_restart_refusal(
                        &format!("{tool:?} {change}"),
                        &result,
                        &run.f,
                        run.control.methods().len() + run.oracle_control.methods().len(),
                    );
                }
            }
        }

        #[tokio::test]
        #[serial_test::serial(keyring)]
        async fn mainnet_classic_commits_refuse_malformed_envelopes_and_mismatched_arguments() {
            for tool in Tool::ALL {
                let run = ClassicRun::new(tool).await;
                let mut broken = run.args.clone();
                broken["envelope_xdr"] = serde_json::json!("AAAA");
                assert_refused_before_mint(
                    &run,
                    &run.commit_with(broken).await,
                    "simulation.divergence",
                );
                let mut mismatched = run.args.clone();
                match tool {
                    Tool::Pay | Tool::CreateAccount => {
                        mismatched["destination"] = serde_json::json!(run.f.envelope.source());
                    }
                    Tool::Claim => mismatched["balance_id"] = serde_json::json!("cd".repeat(32)),
                    Tool::Trustline => {
                        mismatched["from"] = serde_json::json!(
                            stellar_agent_test_support::signed_envelope::account_id_for_seed(
                                [7; 32]
                            )
                        );
                    }
                }
                if tool == Tool::Claim {
                    // The claim commit reads its balance and source from the
                    // approved envelope only; the arguments do not steer it.
                    let mut chain = mismatched.clone();
                    chain["chain_id"] = serde_json::json!("stellar:testnet");
                    let error = run.commit_raw(chain).await.unwrap_err();
                    assert_eq!(error.code, rmcp::model::ErrorCode::INVALID_PARAMS);
                    let result = run.commit_with(mismatched).await;
                    assert_eq!(result["ok"], true, "{result}");
                    assert_approved_bytes_sent(
                        run.args["envelope_xdr"].as_str().unwrap(),
                        &run.control.sent()[0],
                    );
                    continue;
                }
                assert_refused_before_mint(
                    &run,
                    &run.commit_with(mismatched).await,
                    "simulation.divergence",
                );
                let mut chain = run.args.clone();
                chain["chain_id"] = serde_json::json!("stellar:testnet");
                let error = run.commit_raw(chain).await.unwrap_err();
                assert_eq!(
                    error.code,
                    rmcp::model::ErrorCode::INVALID_PARAMS,
                    "{tool:?}"
                );
                assert!(authorizations(&run.f).is_empty(), "{tool:?}");
                assert_eq!(run.seed_reads(), 0, "{tool:?}");
            }
        }

        #[tokio::test]
        #[serial_test::serial(keyring)]
        async fn mainnet_classic_commits_probe_the_endpoint_before_reading() {
            for tool in Tool::ALL {
                let run = ClassicRun::new(tool).await;
                run.control.testnet_passphrase.store(true, Ordering::SeqCst);
                let result = run.commit().await;
                assert_refused_before_mint(&run, &result, "network.endpoint_network_mismatch");
                assert_eq!(run.control.methods(), ["getNetwork"], "{tool:?}");
                run.control
                    .testnet_passphrase
                    .store(false, Ordering::SeqCst);
                run.control
                    .accounts_unavailable
                    .store(true, Ordering::SeqCst);
                let result = run.commit().await;
                assert_eq!(result["ok"], false, "{tool:?}: {result}");
                assert!(authorizations(&run.f).is_empty(), "{tool:?}");
                assert_eq!(run.seed_reads(), 0, "{tool:?}");
                assert_eq!(
                    run.control.methods()[..2],
                    ["getNetwork", "getLedgerEntries"],
                    "{tool:?}: the probe precedes the first read"
                );
                assert_eq!(run.control.count("sendTransaction"), 0, "{tool:?}");
            }
        }

        #[tokio::test]
        #[serial_test::serial(keyring)]
        async fn mainnet_classic_commits_require_their_approval_before_the_protocol_nonce() {
            for tool in Tool::ALL {
                let run = ClassicRun::new(tool).await;
                let mut absent = run.args.clone();
                absent["approval_nonce"] = serde_json::Value::Null;
                absent["approval_attestation"] = serde_json::Value::Null;
                assert_refused_before_mint(
                    &run,
                    &run.commit_with(absent.clone()).await,
                    "policy.approval_required",
                );
                let mut forged = run.args.clone();
                forged["approval_attestation"] = serde_json::json!("A".repeat(43));
                assert_refused_before_mint(
                    &run,
                    &run.commit_with(forged).await,
                    "policy.approval_required",
                );
                absent["nonce"] = serde_json::json!("not-a-valid-nonce");
                assert_refused_before_mint(
                    &run,
                    &run.commit_with(absent).await,
                    "policy.approval_required",
                );
            }
        }

        /// Sets every rate limit of the commit rules of `tool` to one call.
        fn one_call_per_day(raw: &str, tool: Tool) -> String {
            let mut doc = raw.parse::<toml_edit::DocumentMut>().unwrap();
            for rule in doc["rules"].as_array_of_tables_mut().unwrap().iter_mut() {
                if rule["match"]["tool"].as_str() != Some(tool.commit_name()) {
                    continue;
                }
                for criterion in rule["criteria"].as_array_mut().unwrap().iter_mut() {
                    let criterion = criterion.as_inline_table_mut().unwrap();
                    if criterion.get("kind").and_then(|kind| kind.as_str()) == Some("rate_limit") {
                        criterion.insert("max_calls", toml_edit::Value::from(1));
                    }
                }
            }
            doc.to_string()
        }

        #[tokio::test]
        #[serial_test::serial(keyring)]
        async fn mainnet_classic_commits_refuse_a_commit_time_denial_or_evaluation_failure() {
            for tool in Tool::ALL {
                let run = ClassicRun::with(
                    tool,
                    move |raw| one_call_per_day(&raw, tool),
                    |_| {},
                    |_| {},
                )
                .await;
                let (second, _) = run.prepare_again().await;
                assert_eq!(run.commit().await["ok"], true, "{tool:?}");
                let identity_reads = Arc::new(AtomicU32::new(0));
                let reads = Arc::clone(&identity_reads);
                observe(&run.f.on_identity_read, move || {
                    reads.fetch_add(1, Ordering::SeqCst);
                });
                let result = run.commit_with(second).await;
                assert_eq!(
                    identity_reads.load(Ordering::SeqCst),
                    0,
                    "{tool:?}: the dispatch gate refuses before the signer is resolved"
                );
                assert_eq!(result["ok"], false, "{tool:?}: {result}");
                assert_eq!(
                    result["error"]["code"], "policy.deny.rate_limit_exceeded",
                    "{tool:?}: {result}"
                );
                assert_eq!(authorizations(&run.f).len(), 1, "{tool:?}");
                assert_eq!(run.seed_reads(), 1, "{tool:?}");
                assert_eq!(run.control.count("sendTransaction"), 0, "{tool:?}");

                let run = ClassicRun::new(tool).await;
                std::fs::write(&run.f.server.window_path, b"not a window file").unwrap();
                let result = run.commit().await;
                assert_eq!(result["ok"], false, "{tool:?}: {result}");
                assert_eq!(
                    result["error"]["code"], "policy.engine_required",
                    "{tool:?}: {result}"
                );
                assert_eq!(run.seed_reads(), 0, "{tool:?}");
                assert_eq!(run.control.count("sendTransaction"), 0, "{tool:?}");
            }
        }

        #[tokio::test]
        #[serial_test::serial(keyring)]
        async fn mainnet_classic_commits_refuse_signed_fee_and_rebuild_changes() {
            for tool in Tool::ALL {
                let run = ClassicRun::new(tool).await;
                let fee =
                    run.crafted(|tx| tx.fee = 600 * u32::try_from(tx.operations.len()).unwrap());
                assert_refused_before_mint(
                    &run,
                    &run.commit_with(fee).await,
                    "fees.percentile_exceeds_cap",
                );
                let rebuild = run.crafted(|tx| tx.seq_num.0 += 1);
                assert_refused_before_mint(
                    &run,
                    &run.commit_with(rebuild).await,
                    "simulation.divergence",
                );
            }
        }

        fn account_id(account: &str) -> stellar_xdr::AccountId {
            use stellar_xdr::*;
            AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
                stellar_strkey::ed25519::PublicKey::from_string(account)
                    .unwrap()
                    .0,
            )))
        }

        /// The fixture's ledger entries with the entry under `key` decoded,
        /// changed by `change`, and encoded again.
        fn entries_changing(
            run: &ClassicRun,
            key: &str,
            change: impl FnOnce(&mut stellar_xdr::LedgerEntryData),
        ) -> Vec<serde_json::Value> {
            use stellar_xdr::{LedgerEntryData, Limits, ReadXdr as _, WriteXdr as _};
            let mut change = Some(change);
            fixture_entries(&run.f)
                .into_iter()
                .map(|mut entry| {
                    if entry["key"] == key {
                        let mut data = LedgerEntryData::from_xdr_base64(
                            entry["xdr"].as_str().unwrap(),
                            Limits::none(),
                        )
                        .unwrap();
                        (change.take().unwrap())(&mut data);
                        entry["xdr"] =
                            serde_json::json!(data.to_xdr_base64(Limits::none()).unwrap());
                    }
                    entry
                })
                .collect()
        }

        /// The fixture's ledger entries plus a destination that requires a
        /// memo under SEP-29.
        fn entries_with_memo_required(run: &ClassicRun) -> Vec<serde_json::Value> {
            use stellar_xdr::*;
            let destination = run.f.envelope.destination();
            let mut entries = fixture_entries(&run.f);
            entries.extend(
                stellar_agent_test_support::signed_envelope::ledger_entries_result_for(&[
                    destination,
                ])["entries"]
                    .as_array()
                    .unwrap()
                    .clone(),
            );
            let name: String64 = "config.memo_required"
                .as_bytes()
                .to_vec()
                .try_into()
                .unwrap();
            let key = LedgerKey::Data(LedgerKeyData {
                account_id: account_id(destination),
                data_name: name.clone(),
            })
            .to_xdr_base64(Limits::none())
            .unwrap();
            let data = LedgerEntryData::Data(DataEntry {
                account_id: account_id(destination),
                data_name: name,
                data_value: DataValue(b"1".to_vec().try_into().unwrap()),
                ext: DataEntryExt::V0,
            })
            .to_xdr_base64(Limits::none())
            .unwrap();
            entries.push(serde_json::json!({"key":key, "xdr":data, "lastModifiedLedgerSeq":100}));
            entries
        }

        /// Each commit re-reads the ledger state its action depends on and
        /// refuses a change since the preparation: a destination that now
        /// requires a memo, a claim predicate that no longer holds, and an
        /// issuer that enabled clawback.
        #[tokio::test]
        #[serial_test::serial(keyring)]
        async fn mainnet_classic_commits_refuse_changed_ledger_state() {
            use stellar_xdr::*;
            for tool in [Tool::Pay, Tool::Claim, Tool::Trustline] {
                let run = ClassicRun::new(tool).await;
                let (entries, code) = match tool {
                    Tool::Pay => (entries_with_memo_required(&run), "validation.memo_required"),
                    Tool::Claim => {
                        let key = LedgerKey::ClaimableBalance(LedgerKeyClaimableBalance {
                            balance_id: ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash(
                                [0xab; 32],
                            )),
                        })
                        .to_xdr_base64(Limits::none())
                        .unwrap();
                        let entries = entries_changing(&run, &key, |data| {
                            let LedgerEntryData::ClaimableBalance(entry) = data else {
                                panic!("claimable balance expected")
                            };
                            let mut claimants = entry.claimants.to_vec();
                            let Claimant::ClaimantTypeV0(claimant) = &mut claimants[0];
                            claimant.predicate = ClaimPredicate::BeforeAbsoluteTime(1);
                            entry.claimants = claimants.try_into().unwrap();
                        });
                        (entries, "claim.predicate_not_satisfied")
                    }
                    Tool::Trustline => {
                        let issuer =
                            stellar_agent_test_support::signed_envelope::account_id_for_seed(
                                [7; 32],
                            );
                        let key = LedgerKey::Account(LedgerKeyAccount {
                            account_id: account_id(&issuer),
                        })
                        .to_xdr_base64(Limits::none())
                        .unwrap();
                        let entries = entries_changing(&run, &key, |data| {
                            let LedgerEntryData::Account(account) = data else {
                                panic!("account expected")
                            };
                            account.flags |= AccountFlags::ClawbackEnabledFlag as u32;
                        });
                        (entries, "trustline.clawback_opt_in_required")
                    }
                    Tool::CreateAccount => unreachable!(),
                };
                *run.control.entries.lock().unwrap() = Some(entries.clone());
                *run.oracle_control.entries.lock().unwrap() = Some(entries);
                assert_refused_before_mint(&run, &run.commit().await, code);
            }
        }

        #[tokio::test]
        #[serial_test::serial(keyring)]
        async fn mainnet_classic_commits_refuse_a_disagreeing_witness() {
            for tool in [Tool::Pay, Tool::Claim, Tool::Trustline] {
                let run = ClassicRun::new(tool).await;
                *run.oracle_control.entries.lock().unwrap() = Some(Vec::new());
                let result = run.commit().await;
                assert_refused_before_mint(&run, &result, "simulation.divergence");
                assert!(run.oracle_control.count("getLedgerEntries") > 0, "{tool:?}");
            }
            let run = ClassicRun::with(
                Tool::CreateAccount,
                |raw| raw.replace("\"200000000\"", "\"20000000000\""),
                |_| {},
                |args| args["starting_balance"] = serde_json::json!("1000 XLM"),
            )
            .await;
            *run.oracle_control.entries.lock().unwrap() = Some(Vec::new());
            assert_refused_before_mint(&run, &run.commit().await, "simulation.divergence");
        }

        /// The payment's own threshold, not its memo observation, requires the
        /// bound oracle witness: the signed native threshold is the mainnet
        /// floor, the profile's own threshold is twice that, and the payment
        /// carries a memo and pays exactly the floor.
        #[tokio::test]
        #[serial_test::serial(keyring)]
        async fn mainnet_pay_requires_a_bound_oracle_witness() {
            let floor = stellar_agent_core::profile::schema::MINIMUM_FLOOR;
            let run = ClassicRun::with(
                Tool::Pay,
                |raw| {
                    raw.replace("max_stroops = \"100\"", "max_stroops = \"20000000000\"")
                        .replace("max_stroops = \"200\"", "max_stroops = \"40000000000\"")
                },
                move |profile| profile.cross_check_threshold_stroops = 2 * floor,
                move |args| {
                    args["amount_in_stroops"] = serde_json::json!(floor.to_string());
                    args["memo_text"] = serde_json::json!("invoice");
                },
            )
            .await;
            let result = run.commit().await;
            assert_eq!(result["ok"], true, "{result}");
            assert_eq!(result["data"]["cross_check"]["status"], "passed");
            assert_eq!(
                result["data"]["cross_check"]["provider"],
                "https://oracle.example.invalid"
            );
            assert!(run.oracle_control.count("getLedgerEntries") > 0);
            assert_eq!(authorizations(&run.f)[0]["state"], "used");
        }

        #[tokio::test]
        #[serial_test::serial(keyring)]
        async fn mainnet_classic_commits_refuse_without_audit_readiness() {
            for tool in Tool::ALL {
                let run = ClassicRun::new(tool).await;
                stellar_agent_core::audit_log::AuditWriterRegistry::remove_for_test("operator");
                let key = &run.f.server.security_profile().audit_log_hash_chain_key_id;
                keyring_core::Entry::new(&key.service, &key.account)
                    .unwrap()
                    .delete_credential()
                    .unwrap();
                assert_refused_before_mint(&run, &run.commit().await, "auth.keyring_not_found");
            }
        }

        #[tokio::test]
        #[serial_test::serial(keyring)]
        async fn mainnet_classic_commits_refuse_changed_protocol_nonces() {
            for tool in Tool::ALL {
                let run = ClassicRun::new(tool).await;
                let nonce = run.args["nonce"].as_str().unwrap();
                let mut tampered = run.args.clone();
                let (head, last) = nonce.split_at(nonce.len() - 1);
                let flipped = if last == "A" { "B" } else { "A" };
                tampered["nonce"] = serde_json::json!(format!("{head}{flipped}"));
                assert_refused_before_mint(&run, &run.commit_with(tampered).await, "nonce.expired");
                let mut expiry = run.args.clone();
                expiry["expires_at_unix_ms"] =
                    serde_json::json!(run.args["expires_at_unix_ms"].as_u64().unwrap() + 1);
                assert_refused_before_mint(&run, &run.commit_with(expiry).await, "nonce.expired");
                let mut foreign = run.crafted(|tx| tx.fee += 1);
                foreign["nonce"] = run.args["nonce"].clone();
                foreign["expires_at_unix_ms"] = run.args["expires_at_unix_ms"].clone();
                assert_refused_before_mint(&run, &run.commit_with(foreign).await, "nonce.expired");

                let key = &run.f.server.security_profile().mcp_signer_default;
                let seed = keyring_core::Entry::new(&key.service, &key.account).unwrap();
                let stored = seed.get_password().unwrap();
                seed.delete_credential().unwrap();
                let first = run.commit().await;
                assert_eq!(first["ok"], false, "{tool:?}: {first}");
                seed.set_password(&stored).unwrap();
                let replay = run.commit().await;
                assert_eq!(replay["ok"], false, "{tool:?}: {replay}");
                assert_eq!(
                    replay["error"]["code"], "nonce.replayed",
                    "{tool:?}: {replay}"
                );
                assert_eq!(authorizations(&run.f).len(), 1, "{tool:?}: no second mint");
                assert_eq!(run.control.count("sendTransaction"), 0, "{tool:?}");
            }
        }

        #[tokio::test]
        #[serial_test::serial(keyring)]
        async fn mainnet_classic_commits_refuse_a_changed_enrollment() {
            for tool in Tool::ALL {
                for change in ["missing", "other"] {
                    let run = ClassicRun::new(tool).await;
                    let identity = signer_identity_entry_ref(
                        &run.f.server.security_profile().mcp_signer_default,
                    );
                    let entry =
                        keyring_core::Entry::new(&identity.service, &identity.account).unwrap();
                    if change == "missing" {
                        entry.delete_credential().unwrap();
                    } else {
                        entry
                            .set_password(
                                &stellar_agent_core::profile::signer_identity::SignerIdentityRecord::agent(
                                    ed25519_dalek::SigningKey::from_bytes(&[43; 32])
                                        .verifying_key()
                                        .to_bytes(),
                                )
                                .render(),
                            )
                            .unwrap();
                    }
                    let result = run.commit().await;
                    assert_eq!(result["ok"], false, "{tool:?} {change}: {result}");
                    assert!(
                        result["error"]["code"]
                            .as_str()
                            .unwrap()
                            .starts_with("auth."),
                        "{tool:?} {change}: {result}"
                    );
                    assert!(authorizations(&run.f).is_empty(), "{tool:?} {change}");
                    assert_eq!(run.seed_reads(), 0, "{tool:?} {change}");
                    assert_eq!(run.control.count("sendTransaction"), 0, "{tool:?} {change}");
                }
            }
        }

        #[tokio::test]
        #[serial_test::serial(keyring)]
        async fn mainnet_classic_recorder_preparation_refuses_before_mint() {
            for tool in Tool::ALL {
                let run = ClassicRun::new(tool).await;
                let receipts = stellar_agent_core::profile::receipt::default_receipts_dir()
                    .unwrap()
                    .join("operator.json");
                let unreadable = receipts.clone();
                observe(&run.f.on_identity_read, move || {
                    std::fs::create_dir_all(unreadable.parent().unwrap()).unwrap();
                    std::fs::write(&unreadable, b"not a receipt store").unwrap();
                });
                let result = run.commit().await;
                *run.f.on_identity_read.lock().unwrap() = None;
                std::fs::remove_file(&receipts).unwrap();
                assert_refused_before_mint(&run, &result, "submission.record_unavailable");

                let run = ClassicRun::new(tool).await;
                let window = run.f.server.window_path.clone();
                let original = std::fs::read(&window).ok();
                let corrupt = window.clone();
                observe(&run.f.on_identity_read, move || {
                    std::fs::write(&corrupt, b"not a window file").unwrap();
                });
                let result = run.commit().await;
                *run.f.on_identity_read.lock().unwrap() = None;
                assert_eq!(result["ok"], false, "{tool:?}: {result}");
                assert_eq!(
                    result["error"]["code"], "submission.record_unavailable",
                    "{tool:?}: {result}"
                );
                match original {
                    Some(original) => std::fs::write(&window, original).unwrap(),
                    None => std::fs::remove_file(&window).unwrap(),
                }
                assert!(authorizations(&run.f).is_empty(), "{tool:?}");
                assert_eq!(run.seed_reads(), 0, "{tool:?}");
            }
        }

        #[tokio::test]
        #[serial_test::serial(keyring)]
        async fn mainnet_classic_resolver_refusals_keep_their_codes() {
            for tool in Tool::ALL {
                let run = ClassicRun::new(tool).await;
                let overlong = run.approved(run.args["envelope_xdr"].as_str().unwrap(), 3_600_000);
                let (capture, _guard) =
                    stellar_agent_test_support::WarningCapture::capture(Some("stellar_agent"));
                let result = run.commit_with(overlong).await;
                assert_refused_before_mint(&run, &result, "network.mainnet_authorization_refused");
                let refusals: Vec<_> = capture
                    .seen()
                    .into_iter()
                    .filter(|fields| {
                        fields.get("message").is_some_and(|message| {
                            message.contains("mainnet authorization refused")
                        })
                    })
                    .collect();
                assert_eq!(
                    refusals.len(),
                    1,
                    "{tool:?}: one log of the refusal: {refusals:?}"
                );
                assert_eq!(
                    refusals[0]["precondition"].trim_matches('"'),
                    "approval_ttl_exceeds_rule",
                    "{tool:?}"
                );
            }
        }

        /// The resolver evaluates the policy again on its own account read:
        /// a reserve rule that held at the dispatch gate denies at mint once
        /// the source balance dropped, before anything is authorized.
        #[tokio::test]
        #[serial_test::serial(keyring)]
        async fn mainnet_classic_resolver_reevaluates_the_policy_atomically() {
            use stellar_xdr::*;
            for tool in Tool::ALL {
                let run = ClassicRun::with(
                    tool,
                    move |raw| {
                        let mut doc: toml_edit::DocumentMut = raw.parse().unwrap();
                        for rule in doc["rules"].as_array_of_tables_mut().unwrap().iter_mut() {
                            if rule["match"]["tool"].as_str() == Some(tool.commit_name()) {
                                rule["criteria"].as_array_mut().unwrap().push(
                                    "{kind = \"minimum_reserve\", margin_stroops = 0}"
                                        .parse::<toml_edit::Value>()
                                        .unwrap(),
                                );
                            }
                        }
                        doc.to_string()
                    },
                    |_| {},
                    |_| {},
                )
                .await;
                let source = LedgerKey::Account(LedgerKeyAccount {
                    account_id: account_id(run.f.envelope.source()),
                })
                .to_xdr_base64(Limits::none())
                .unwrap();
                let drained = entries_changing(&run, &source, |data| {
                    let LedgerEntryData::Account(account) = data else {
                        panic!("account expected")
                    };
                    account.balance = 1;
                });
                let primary = Arc::clone(&run.control);
                let reached = Arc::new(AtomicBool::new(false));
                let signer_resolved = Arc::clone(&reached);
                observe(&run.f.on_identity_read, move || {
                    signer_resolved.store(true, Ordering::SeqCst);
                    *primary.entries.lock().unwrap() = Some(drained.clone());
                });
                let result = run.commit().await;
                *run.f.on_identity_read.lock().unwrap() = None;
                assert!(
                    reached.load(Ordering::SeqCst),
                    "{tool:?}: the dispatch gate admitted the commit"
                );
                assert_refused_before_mint(&run, &result, "policy.deny.minimum_reserve_breached");
            }
        }

        #[tokio::test]
        #[serial_test::serial(keyring)]
        async fn mainnet_lazy_signer_failure_invalidates_without_send() {
            for tool in Tool::ALL {
                let run = ClassicRun::new(tool).await;
                let key = &run.f.server.security_profile().mcp_signer_default;
                keyring_core::Entry::new(&key.service, &key.account)
                    .unwrap()
                    .delete_credential()
                    .unwrap();
                let result = run.commit().await;
                assert!(
                    result["error"]["code"]
                        .as_str()
                        .unwrap()
                        .starts_with("auth."),
                    "{tool:?}: {result}"
                );
                let code = result["error"]["code"].as_str().unwrap().to_owned();
                assert_invalidated(&run, &result, &code, "signer_unavailable");
                assert_eq!(run.seed_reads(), 1, "{tool:?}");
                assert!(
                    !is_consumed(&stored_approval(&run.f, &run.entry.approval_nonce).unwrap()),
                    "{tool:?}"
                );
            }
        }

        #[tokio::test]
        #[serial_test::serial(keyring)]
        async fn mainnet_classic_pre_send_failure_invalidates_with_the_primary_error() {
            for tool in Tool::ALL {
                let run = ClassicRun::new(tool).await;
                let armed =
                    Armed::new(&stellar_agent_network::submission_record::FAIL_PENDING_ROW_APPEND);
                let result = run.commit().await;
                drop(armed);
                assert_invalidated(
                    &run,
                    &result,
                    "submission.record_unavailable",
                    "pre_send_refused",
                );
                assert_eq!(run.seed_reads(), 1, "{tool:?}");
            }
        }

        /// An authorization whose expiry passes between signing and the
        /// submit gate is swept to expired by the cleanup's ledger operation;
        /// the cleanup then finds it settled and invalidates nothing.
        #[tokio::test]
        #[serial_test::serial(keyring)]
        async fn mainnet_submit_expiry_refuses_before_pre_send() {
            for tool in Tool::ALL {
                let run = ClassicRun::new(tool).await;
                run.f.clock_after_seed.store(
                    stellar_agent_core::timefmt::now_unix_ms().unwrap() + 300_000,
                    Ordering::SeqCst,
                );
                let result = run.commit().await;
                assert_eq!(result["ok"], false, "{tool:?}: {result}");
                assert_eq!(
                    result["error"]["code"], "network.mainnet_authorization_refused",
                    "{tool:?}: {result}"
                );
                let records = authorizations(&run.f);
                assert_eq!(records.len(), 1, "{tool:?}");
                assert_eq!(records[0]["state"], "expired", "{tool:?}");
                assert!(
                    records[0]
                        .get("invalidation")
                        .is_none_or(serde_json::Value::is_null)
                );
                assert!(
                    ledger_state(&run.f)["holds"]
                        .as_array()
                        .is_none_or(Vec::is_empty),
                    "{tool:?}"
                );
                assert_no_pre_send_entry(&run);
                assert_eq!(run.control.count("sendTransaction"), 0, "{tool:?}");
            }
        }

        #[tokio::test]
        #[serial_test::serial(keyring)]
        async fn mainnet_submit_passphrase_change_refuses_before_pre_send() {
            for tool in Tool::ALL {
                let run = ClassicRun::new(tool).await;
                run.control
                    .passphrase_after_seed
                    .store(true, Ordering::SeqCst);
                let result = run.commit().await;
                assert_invalidated(
                    &run,
                    &result,
                    "network.endpoint_network_mismatch",
                    "submit_gate_refused",
                );
            }
        }

        #[tokio::test]
        #[serial_test::serial(keyring)]
        async fn mainnet_classic_definitive_rejection_releases_the_converted_rows() {
            for tool in Tool::ALL {
                let run = ClassicRun::new(tool).await;
                run.control.send_rejected.store(true, Ordering::SeqCst);
                let result = run.commit().await;
                assert_eq!(result["ok"], false, "{tool:?}: {result}");
                assert_eq!(run.control.count("sendTransaction"), 1, "{tool:?}");
                let records = authorizations(&run.f);
                assert_eq!(records.len(), 1, "{tool:?}");
                assert_eq!(records[0]["state"], "used", "{tool:?}");
                assert!(
                    window_records(&run.f).is_empty(),
                    "{tool:?}: the rows are released"
                );
                assert!(
                    ledger_state(&run.f)["holds"]
                        .as_array()
                        .is_none_or(Vec::is_empty),
                    "{tool:?}"
                );
                assert!(
                    !is_consumed(&stored_approval(&run.f, &run.entry.approval_nonce).unwrap()),
                    "{tool:?}: a refused send leaves the approval unspent"
                );
            }
        }

        #[tokio::test]
        #[serial_test::serial(keyring)]
        async fn mainnet_classic_consumption_without_send_keeps_the_primary_error_and_spends_the_approval_nonce()
         {
            for tool in Tool::ALL {
                let run = ClassicRun::new(tool).await;
                let (capture, _guard) =
                    stellar_agent_test_support::WarningCapture::capture(Some("stellar_agent"));
                let armed =
                    Armed::new(&stellar_agent_network::submission_record::FAIL_MARK_SUBMITTED);
                let result = run.commit().await;
                drop(armed);
                assert_eq!(result["ok"], false, "{tool:?}: {result}");
                assert_eq!(
                    result["error"]["code"], "submission.record_unavailable",
                    "{tool:?}: {result}"
                );
                let cleanup: Vec<_> = capture
                    .seen()
                    .into_iter()
                    .filter(|fields| {
                        fields.get("message").is_some_and(|message| {
                            message.contains("authorization cleanup refused")
                        })
                    })
                    .collect();
                assert_eq!(cleanup.len(), 1, "{tool:?}: {cleanup:?}");
                assert_eq!(cleanup[0]["settled"], "true", "{tool:?}");
                assert_eq!(cleanup[0]["stage"], "PreSendRefused", "{tool:?}");
                let records = authorizations(&run.f);
                assert_eq!(records.len(), 1, "{tool:?}");
                assert_eq!(records[0]["state"], "used", "{tool:?}");
                assert!(window_records(&run.f).is_empty(), "{tool:?}");
                assert_eq!(run.control.count("sendTransaction"), 0, "{tool:?}");
                assert!(
                    !is_consumed(&stored_approval(&run.f, &run.entry.approval_nonce).unwrap()),
                    "{tool:?}: no tombstone without a send"
                );

                let retry = run.approved(run.args["envelope_xdr"].as_str().unwrap(), 600_000);
                let mut retry_args = run.args.clone();
                retry_args["nonce"] = retry["nonce"].clone();
                retry_args["expires_at_unix_ms"] = retry["expires_at_unix_ms"].clone();
                let result = run.commit_with(retry_args).await;
                assert_eq!(result["ok"], false, "{tool:?}: {result}");
                assert_eq!(
                    result["error"]["code"], "network.mainnet_authorization_refused",
                    "{tool:?}: {result}"
                );
                let reused = capture.seen().into_iter().any(|fields| {
                    fields
                        .get("precondition")
                        .is_some_and(|label| label.trim_matches('"') == "approval_nonce_reused")
                });
                assert!(
                    reused,
                    "{tool:?}: the ledger refuses the spent approval nonce"
                );
                assert_eq!(authorizations(&run.f).len(), 1, "{tool:?}");
                assert_eq!(run.control.count("sendTransaction"), 0, "{tool:?}");
            }
        }

        #[tokio::test]
        #[serial_test::serial(keyring)]
        async fn mainnet_classic_cleanup_failure_keeps_the_primary_error() {
            for tool in Tool::ALL {
                let run = ClassicRun::new(tool).await;
                let guard = HookGuard::default();
                let hold = Arc::clone(&guard);
                let directory = run.f.server.window_path.parent().unwrap().to_owned();
                let seed_reads = Arc::clone(&run.f.seed_reads);
                run.control
                    .passphrase_after_seed
                    .store(true, Ordering::SeqCst);
                run.control.on_request(move |method| {
                    if method == "getNetwork" && seed_reads.load(Ordering::SeqCst) != 0 {
                        hold.lock()
                            .unwrap()
                            .get_or_insert_with(|| ReadOnlyDir::new(&directory));
                    }
                });
                let (capture, _guard) =
                    stellar_agent_test_support::WarningCapture::capture(Some("stellar_agent"));
                let result = run.commit().await;
                drop(guard.lock().unwrap().take());
                assert_eq!(result["ok"], false, "{tool:?}: {result}");
                assert_eq!(
                    result["error"]["code"], "network.endpoint_network_mismatch",
                    "{tool:?}: {result}"
                );
                let cleanup: Vec<_> = capture
                    .seen()
                    .into_iter()
                    .filter(|fields| {
                        fields.get("message").is_some_and(|message| {
                            message.contains("authorization cleanup refused")
                        })
                    })
                    .collect();
                assert_eq!(cleanup.len(), 1, "{tool:?}: {cleanup:?}");
                assert_eq!(cleanup[0]["settled"], "false", "{tool:?}");
                assert_eq!(cleanup[0]["stage"], "SubmitGateRefused", "{tool:?}");
                assert_eq!(authorizations(&run.f)[0]["state"], "open", "{tool:?}");
                assert_eq!(run.control.count("sendTransaction"), 0, "{tool:?}");
            }
        }

        #[tokio::test]
        #[serial_test::serial(keyring)]
        async fn mainnet_classic_receipt_held_approval_refuses_a_replay() {
            for tool in Tool::ALL {
                let run = ClassicRun::new(tool).await;
                let guard = HookGuard::default();
                let hold = Arc::clone(&guard);
                let approvals = run.f.server.resolve_approval_dir().unwrap();
                run.control.send_hash_mismatch.store(true, Ordering::SeqCst);
                run.control.on_request(move |method| {
                    if method == "sendTransaction" {
                        hold.lock()
                            .unwrap()
                            .get_or_insert_with(|| ReadOnlyDir::new(&approvals));
                    }
                });
                let result = run.commit().await;
                drop(guard.lock().unwrap().take());
                *run.control.on_request.lock().unwrap() = None;
                assert_eq!(result["ok"], false, "{tool:?}: {result}");
                assert!(
                    !is_consumed(&stored_approval(&run.f, &run.entry.approval_nonce).unwrap()),
                    "{tool:?}: the tombstone stays owed"
                );
                let held = stellar_agent_core::profile::receipt::ReceiptStore::open("operator")
                    .unwrap()
                    .find_by_approval_nonce(&run.entry.approval_nonce)
                    .unwrap();
                assert!(held.is_some(), "{tool:?}: the receipt holds the approval");
                let replay = run.commit().await;
                assert_eq!(replay["ok"], false, "{tool:?}: {replay}");
                assert_eq!(
                    replay["error"]["code"], "policy.approval_consumed",
                    "{tool:?}: {replay}"
                );
                assert_eq!(run.control.count("sendTransaction"), 0, "{tool:?}");
                assert_eq!(authorizations(&run.f).len(), 1, "{tool:?}");
            }
        }

        /// A selected server whose merged profile names another endpoint URL
        /// than the stored one refuses to start, although its policy and
        /// enablement verify: the mainnet context cannot be built.
        #[test]
        #[serial_test::serial(keyring)]
        fn selected_startup_propagates_a_context_construction_failure() {
            let f = Fixture::new(|raw| raw);
            let mut merged = (*f.server.profile).clone();
            merged.rpc_url = "https://rpc.example.invalid/other".to_owned();
            let error = match WalletServer::new_with_selection(
                merged,
                ProfileNameSource::Flag,
                &default_profile_dir().unwrap(),
            ) {
                Ok(_) => panic!("a server started without its mainnet context"),
                Err(error) => error,
            };
            assert!(
                error.to_string().contains("mainnet_write_forbidden")
                    || error.to_string().contains("structurally refused"),
                "{error}"
            );
            assert!(
                WalletServer::new_with_selection(
                    (*f.server.profile).clone(),
                    ProfileNameSource::Flag,
                    &default_profile_dir().unwrap(),
                )
                .unwrap()
                .mainnet_context
                .is_some()
            );
        }

        /// Freshness reads the owner key startup read: the selected profile's
        /// default owner entry, even when the profile's owner coordinate names
        /// another entry holding another key.
        #[test]
        #[serial_test::serial(keyring)]
        fn freshness_reads_the_owner_entry_startup_reads() {
            let f = Fixture::with_profile(
                |raw| raw,
                |profile| profile.policy_owner_key_id.account = "copy".to_owned(),
            );
            put(
                &KeyringEntryRef::default_owner_key("operator"),
                &stellar_strkey::ed25519::PublicKey(
                    ed25519_dalek::SigningKey::from_bytes(&[11; 32])
                        .verifying_key()
                        .to_bytes(),
                )
                .to_string(),
            );
            put(
                &f.server.profile.policy_owner_key_id,
                &stellar_strkey::ed25519::PublicKey(
                    ed25519_dalek::SigningKey::from_bytes(&[12; 32])
                        .verifying_key()
                        .to_bytes(),
                )
                .to_string(),
            );
            let guard = f
                .server
                .mainnet_write_admission(stellar_agent_network::mainnet::MainnetConsumer::McpPay)
                .unwrap();
            assert!(f.server.verify_mainnet_freshness(&guard).is_ok());
        }

        /// The mainnet create-payment arguments of the fixture's payment.
        pub(crate) fn x402_args(
            f: &Fixture,
            approval: Option<(&str, &str)>,
        ) -> crate::server::X402CreatePaymentArgs {
            crate::server::X402CreatePaymentArgs {
                payment_required: serde_json::to_string(&f.requirements()).unwrap(),
                chain_id: "stellar:mainnet".to_owned(),
                address: None,
                approval_nonce: approval.map(|(nonce, _)| nonce.to_owned()),
                approval_attestation: approval.map(|(_, attestation)| attestation.to_owned()),
            }
        }

        /// An x402 payment after its preparation call, approved and ready for
        /// its payment call.
        pub(crate) struct X402Run {
            pub f: Fixture,
            _rpc: wiremock::MockServer,
            pub control: Arc<RpcControl>,
            pub nonce: String,
            pub attestation: String,
        }

        impl X402Run {
            pub(crate) async fn new() -> Self {
                Self::with(|raw| raw).await
            }

            pub(crate) async fn with(policy: impl FnOnce(String) -> String) -> Self {
                let rpc = wiremock::MockServer::start().await;
                let f = routed_fixture(policy, &rpc);
                let control = mount_rpc(&f, &rpc).await;
                let (nonce, attestation) = Self::approve(&f, &control).await;
                Self {
                    f,
                    _rpc: rpc,
                    control,
                    nonce,
                    attestation,
                }
            }

            /// Runs the preparation call and attests its pending approval.
            async fn approve(f: &Fixture, control: &RpcControl) -> (String, String) {
                let prepared = wire(
                    &f.server
                        .call_stellar_x402_create_payment(x402_args(f, None))
                        .await
                        .unwrap(),
                );
                assert_eq!(prepared["ok"], true, "{prepared}");
                assert!(
                    control.methods().is_empty(),
                    "the preparation sends nothing"
                );
                let nonce = prepared["data"]["approval"]["approval_nonce"]
                    .as_str()
                    .unwrap()
                    .to_owned();
                let entry = stored_approval(f, &nonce).unwrap();
                (nonce, f.attest(&entry))
            }

            /// The payment call with the run's approval; the request history
            /// then holds this call's requests only.
            pub(crate) async fn pay(&self) -> serde_json::Value {
                self.pay_with(x402_args(&self.f, Some((&self.nonce, &self.attestation))))
                    .await
            }

            pub(crate) async fn pay_with(
                &self,
                args: crate::server::X402CreatePaymentArgs,
            ) -> serde_json::Value {
                self.control.clear();
                wire(
                    &self
                        .f
                        .server
                        .call_stellar_x402_create_payment(args)
                        .await
                        .unwrap(),
                )
            }

            fn simulations(&self) -> usize {
                self.control.count("simulateTransaction")
            }
        }

        /// Asserts an x402 refusal before the intent was minted: no
        /// authorization, no seed read, no payload, and no payment request.
        fn assert_x402_refused_before_intent(
            run: &X402Run,
            result: &serde_json::Value,
            code: &str,
            simulations: usize,
        ) {
            assert_eq!(result["ok"], false, "{result}");
            assert_eq!(result["error"]["code"], code, "{result}");
            assert!(result["data"].get("paymentSignature").is_none(), "{result}");
            assert!(authorizations(&run.f).is_empty(), "{result}");
            assert_eq!(run.f.seed_reads.load(Ordering::SeqCst), 0);
            assert_eq!(run.simulations(), simulations, "{result}");
        }

        /// The final envelope of a returned payment payload.
        fn released_transaction(result: &serde_json::Value) -> String {
            use base64::Engine as _;
            let payload = base64::engine::general_purpose::STANDARD
                .decode(result["data"]["paymentSignature"].as_str().unwrap())
                .unwrap();
            let payload: serde_json::Value = serde_json::from_slice(&payload).unwrap();
            payload["payload"]["transaction"]
                .as_str()
                .unwrap()
                .to_owned()
        }

        /// Asserts the debit a consumed intent retains, whether or not the
        /// payload was released: two confirmed window records, one call in the
        /// rate-limit window and the payment of 10 in the per-period cap, so
        /// the records sum to exactly 11.
        fn assert_x402_retained_debit(f: &Fixture) {
            let rows = window_records(f);
            assert!(
                rows.iter().all(|row| row["status"] == "confirmed"),
                "{rows:?}"
            );
            let mut amounts = rows
                .iter()
                .map(|row| row["amount"].as_str().unwrap().parse::<u64>().unwrap())
                .collect::<Vec<_>>();
            amounts.sort_unstable();
            assert_eq!(amounts, [1, 10], "{rows:?}");
        }

        #[tokio::test]
        #[serial_test::serial(keyring)]
        async fn mainnet_x402_consumes_intent_and_child_before_release() {
            let run = X402Run::new().await;
            let at_signing = Arc::new(std::sync::Mutex::new(Vec::new()));
            let seen = Arc::clone(&at_signing);
            let window = run.f.server.window_path.clone();
            observe(&run.f.on_seed_read, move || {
                let state: serde_json::Value = std::fs::read(&window)
                    .map(|bytes| serde_json::from_slice(&bytes[32..]).unwrap())
                    .unwrap_or_default();
                seen.lock().unwrap().push(state);
            });
            let tombstoned_early = Arc::new(AtomicBool::new(false));
            let early = Arc::clone(&tombstoned_early);
            let approvals = run
                .f
                .server
                .resolve_approval_dir()
                .unwrap()
                .join("operator.toml");
            let nonce = run.nonce.clone();
            observe(&run.f.on_window_key_read, move || {
                let consumed =
                    stellar_agent_core::approval::PendingApprovalStore::open(approvals.clone())
                        .ok()
                        .and_then(|store| store.get(&nonce).map(is_consumed))
                        .unwrap_or(false);
                if consumed {
                    early.store(true, Ordering::SeqCst);
                }
            });
            let result = run.pay().await;
            *run.f.on_seed_read.lock().unwrap() = None;
            *run.f.on_window_key_read.lock().unwrap() = None;
            assert_eq!(result["ok"], true, "{result}");
            let at_signing = at_signing.lock().unwrap().clone();
            assert_eq!(at_signing.len(), 1, "one seed read");
            assert_eq!(
                at_signing[0]["authorizations"].as_array().unwrap().len(),
                1,
                "the intent is minted before signing"
            );
            assert_eq!(at_signing[0]["authorizations"][0]["state"], "open");
            let at_simulation = run
                .control
                .state_at_signed_simulation
                .lock()
                .unwrap()
                .clone();
            assert_eq!(at_simulation.len(), 1);
            assert_eq!(
                at_simulation[0]["authorizations"].as_array().unwrap().len(),
                1,
                "the child is minted after the final simulation"
            );
            assert_eq!(
                at_simulation[0]["authorizations"][0]["state"], "used",
                "the intent is consumed before the signed simulation"
            );
            assert_eq!(
                *run.control.row_before_signed_simulation.lock().unwrap(),
                [true]
            );
            assert!(
                !tombstoned_early.load(Ordering::SeqCst),
                "the child is consumed before the approval is tombstoned"
            );
            let records = authorizations(&run.f);
            assert_eq!(records.len(), 2);
            assert!(records.iter().all(|record| record["state"] == "used"));
            assert_x402_retained_debit(&run.f);
            let approval = stored_approval(&run.f, &run.nonce).unwrap();
            let stellar_agent_core::approval::ApprovalKind::Consumed { tx_hash, .. } =
                &approval.kind
            else {
                panic!("the approval is tombstoned")
            };
            assert_eq!(
                *tx_hash,
                stellar_agent_core::hex::encode(
                    &stellar_agent_core::approval::subject::approval_subject_classic(
                        &released_transaction(&result)
                    )
                )
            );
            assert_eq!(run.f.seed_reads.load(Ordering::SeqCst), 1);
            let replay = run.pay().await;
            assert_eq!(replay["error"]["code"], "policy.approval_consumed");
            assert!(run.control.methods().is_empty());
        }

        #[tokio::test]
        #[serial_test::serial(keyring)]
        async fn mainnet_x402_payment_call_refuses_changed_enablement_or_policy() {
            for change in ["enablement", "policy"] {
                let run = X402Run::new().await;
                if change == "enablement" {
                    put(
                        &mainnet_enablement_entry_ref(
                            &run.f.server.profile.policy_window_state_key_id,
                        ),
                        "rotated-installation",
                    );
                } else {
                    Fixture::write_policy(&run.f.raw.replace("sequence = 7", "sequence = 8"));
                }
                let result = run.pay().await;
                assert_restart_refusal(
                    &format!("x402 {change}"),
                    &result,
                    &run.f,
                    run.control.methods().len(),
                );
                assert!(result["data"].get("paymentSignature").is_none());
            }
        }

        #[tokio::test]
        #[serial_test::serial(keyring)]
        async fn mainnet_x402_signer_failure_invalidates_before_transmission() {
            let run = X402Run::new().await;
            let key = &run.f.server.security_profile().mcp_signer_default;
            keyring_core::Entry::new(&key.service, &key.account)
                .unwrap()
                .delete_credential()
                .unwrap();
            let result = run.pay().await;
            assert_eq!(result["ok"], false, "{result}");
            assert!(result["data"].get("paymentSignature").is_none());
            let records = authorizations(&run.f);
            assert_eq!(records.len(), 1);
            assert_eq!(records[0]["state"], "invalidated");
            assert_eq!(records[0]["invalidation"], "signer_unavailable");
            assert_eq!(run.f.seed_reads.load(Ordering::SeqCst), 1);
            assert_eq!(run.simulations(), 1, "no signed simulation");
        }

        /// A failure after the intent was consumed keeps it used, keeps its
        /// debit, and mints no child.
        #[tokio::test]
        #[serial_test::serial(keyring)]
        async fn mainnet_x402_resimulation_failure_retains_used_intent() {
            for other_authorization in [false, true] {
                let run = X402Run::new().await;
                let (fault, code) = if other_authorization {
                    (
                        &run.control.resimulation_other_auth,
                        "x402.unexpected_auth_entries",
                    )
                } else {
                    (&run.control.resimulation_error, "x402.rpc_simulate_failed")
                };
                fault.store(true, Ordering::SeqCst);
                let result = run.pay().await;
                assert_eq!(result["ok"], false, "{result}");
                assert_eq!(result["error"]["code"], code, "{result}");
                assert!(
                    result["error"]["message"]
                        .as_str()
                        .unwrap()
                        .starts_with("payment withheld after intent authorization"),
                    "{result}"
                );
                assert!(result["data"].get("paymentSignature").is_none());
                let records = authorizations(&run.f);
                assert_eq!(records.len(), 1, "no child");
                assert_eq!(records[0]["state"], "used");
                assert_x402_retained_debit(&run.f);
                assert_eq!(run.simulations(), 2);
                assert_eq!(run.f.seed_reads.load(Ordering::SeqCst), 1);
            }
        }

        #[tokio::test]
        #[serial_test::serial(keyring)]
        async fn mainnet_x402_unavailable_anchor_at_the_transmit_gate_invalidates_the_intent() {
            let run = X402Run::new().await;
            let profile = run.f.server.security_profile();
            let anchor = stellar_agent_network::keyring::KeyringTipAnchorStore::new(
                &profile.audit_log_hash_chain_key_id,
                &profile.audit_log_path,
            )
            .anchor_entry_ref()
            .clone();
            observe(&run.f.on_seed_read, move || {
                keyring_mock::inject_error(
                    &anchor.service,
                    &anchor.account,
                    keyring_core::Error::NoStorageAccess(std::io::Error::other("locked").into()),
                )
                .unwrap();
            });
            let result = run.pay().await;
            *run.f.on_seed_read.lock().unwrap() = None;
            assert_eq!(result["ok"], false, "{result}");
            assert_eq!(
                result["error"]["code"], "audit.chain_key_unavailable",
                "{result}"
            );
            assert!(result["data"].get("paymentSignature").is_none());
            let records = authorizations(&run.f);
            assert_eq!(records.len(), 1);
            assert_eq!(records[0]["state"], "invalidated");
            assert_eq!(records[0]["invalidation"], "intent_pre_transmit_refused");
            assert!(
                ledger_state(&run.f)["holds"]
                    .as_array()
                    .is_none_or(Vec::is_empty)
            );
            assert_eq!(run.simulations(), 1, "no signed simulation");
        }

        #[tokio::test]
        #[serial_test::serial(keyring)]
        async fn mainnet_x402_tombstone_failure_keeps_both_records_used() {
            let run = X402Run::new().await;
            let guard = HookGuard::default();
            let hold = Arc::clone(&guard);
            let approvals = run.f.server.resolve_approval_dir().unwrap();
            run.control.on_request(move |method| {
                if method == "simulateTransaction" {
                    let mut held = hold.lock().unwrap();
                    if held.is_none() {
                        *held = Some(ReadOnlyDir::new(&approvals));
                    }
                }
            });
            let result = run.pay().await;
            drop(guard.lock().unwrap().take());
            assert_eq!(result["ok"], false, "{result}");
            assert!(
                result["error"]["message"]
                    .as_str()
                    .unwrap()
                    .starts_with("payment withheld at terminal approval"),
                "{result}"
            );
            assert!(result["data"].get("paymentSignature").is_none());
            let records = authorizations(&run.f);
            assert_eq!(records.len(), 2);
            assert!(records.iter().all(|record| record["state"] == "used"));
            assert!(!is_consumed(&stored_approval(&run.f, &run.nonce).unwrap()));
            let rows = std::fs::read_to_string(&run.f.server.security_profile().audit_log_path)
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
                .filter(|row| row["kind"] == "x402_authorization_withheld")
                .collect::<Vec<_>>();
            assert_eq!(rows.len(), 1, "{rows:?}");
            assert_eq!(rows[0]["failure_stage"], "terminal_approval");
        }

        #[tokio::test]
        #[serial_test::serial(keyring)]
        async fn mainnet_x402_transmit_gate_invalidates_the_open_intent() {
            use stellar_agent_core::approval::{PendingApproval, process_uid_for_attestation};
            use stellar_agent_network::mainnet::MainnetConsumer;
            use stellar_agent_x402::exact::{X402MainnetProofs, create_payment_authorized};
            let rpc = wiremock::MockServer::start().await;
            let f = routed_fixture(|raw| raw, &rpc);
            let control = mount_rpc(&f, &rpc).await;
            let requirements = f.requirements();
            let root = stellar_agent_x402::exact::payment_root(&requirements, f.envelope.source())
                .unwrap();
            let network_id =
                sha2::Sha256::digest(f.server.context.network_passphrase().as_bytes()).into();
            let entry = PendingApproval::new_x402_pending(
                &network_id,
                &root,
                None,
                process_uid_for_attestation().unwrap(),
                600_000,
            )
            .unwrap();
            let blob = f.attest(&entry);
            let outcome = f
                .server
                .dispatch_preparation(
                    "stellar_x402_create_payment",
                    &serde_json::json!({"chain_id":"stellar:mainnet"}),
                    "stellar:mainnet",
                    stellar_agent_core::policy::v1::ValueClass::single(x402_value_leg(
                        &requirements,
                        10,
                    )),
                )
                .await
                .unwrap();
            let outcome = f
                .server
                .force_mainnet_confirmation("stellar_x402_create_payment", outcome)
                .unwrap();
            let digest =
                stellar_agent_x402::exact::intent_digest(&requirements, f.envelope.source())
                    .unwrap();
            let approval = verify_attestation_subject_gate(
                &f.server,
                &outcome,
                GatedApprovalKind::X402.expectation(
                    stellar_agent_core::approval::subject::approval_subject_x402(&digest),
                ),
                Some(&entry.approval_nonce),
                Some(&blob),
                "stellar_x402_create_payment",
            )
            .await
            .unwrap()
            .unwrap();
            let guard = f
                .server
                .mainnet_write_admission(MainnetConsumer::X402Create)
                .unwrap();
            let signer = f.server.mainnet_enrolled_signer(&guard).unwrap();
            let handle = stellar_agent_network::keyring::lazy_signer_from_keyring(
                signer.seed_entry(),
                f.envelope.source(),
            )
            .unwrap();
            let audit = stellar_agent_network::mainnet::audit_readiness::audit_readiness(
                guard.context.profile(),
                "operator",
            )
            .unwrap();
            let store = stellar_agent_network::policy_state::PersistedWindowStore::at_path(
                f.server.window_path.clone(),
            );
            let asset = x402_canonical_asset(&requirements).unwrap();
            let result = create_payment_authorized(
                &requirements,
                MainnetConsumer::X402Create,
                X402MainnetProofs::new(
                    guard.context,
                    guard.policy,
                    guard.enablement,
                    &approval,
                    &signer,
                    &handle,
                    audit,
                    &store,
                ),
                stellar_agent_core::cross_check::CrossCheckValue::Amount {
                    asset: &asset,
                    base_units: 10,
                },
                tokio::time::Instant::now() + std::time::Duration::from_secs(5),
                |_| {
                    Err(stellar_agent_x402::X402Error::TransmitGateRefused {
                        detail: "audit gate refused".to_owned(),
                    })
                },
            )
            .await;
            let error = match result {
                Ok(_) => panic!("transmit gate refusal released a payment"),
                Err(error) => error,
            };
            assert!(matches!(
                error,
                stellar_agent_x402::X402Error::TransmitGateRefused { .. }
            ));
            let state = ledger_state(&f);
            assert_eq!(state["authorizations"].as_array().unwrap().len(), 1);
            assert_eq!(state["authorizations"][0]["state"], "invalidated");
            assert!(state.to_string().contains("intent_pre_transmit_refused"));
            assert!(state["holds"].as_array().is_none_or(Vec::is_empty));
            assert_eq!(f.seed_reads.load(Ordering::SeqCst), 1);
            assert_eq!(control.count("simulateTransaction"), 1);
        }

        /// Sets every x402 rate limit to one call.
        fn one_x402_call_per_day(raw: &str) -> String {
            let mut doc = raw.parse::<toml_edit::DocumentMut>().unwrap();
            for rule in doc["rules"].as_array_of_tables_mut().unwrap().iter_mut() {
                if rule["match"]["tool"].as_str() != Some("stellar_x402_create_payment") {
                    continue;
                }
                for criterion in rule["criteria"].as_array_mut().unwrap().iter_mut() {
                    let criterion = criterion.as_inline_table_mut().unwrap();
                    if criterion.get("kind").and_then(|kind| kind.as_str()) == Some("rate_limit") {
                        criterion.insert("max_calls", toml_edit::Value::from(1));
                    }
                }
            }
            doc.to_string()
        }

        #[tokio::test]
        #[serial_test::serial(keyring)]
        async fn mainnet_x402_policy_denial_refuses_before_the_intent() {
            let rpc = wiremock::MockServer::start().await;
            let f = routed_fixture(
                |raw| {
                    let mut doc = raw.parse::<toml_edit::DocumentMut>().unwrap();
                    for rule in doc["rules"].as_array_of_tables_mut().unwrap().iter_mut() {
                        if rule["match"]["tool"].as_str() == Some("stellar_x402_create_payment") {
                            rule["decision"] = toml_edit::value("deny");
                        }
                    }
                    doc.to_string()
                },
                &rpc,
            );
            let control = mount_rpc(&f, &rpc).await;
            let result = wire(
                &f.server
                    .call_stellar_x402_create_payment(x402_args(&f, None))
                    .await
                    .unwrap(),
            );
            assert_eq!(result["ok"], false, "{result}");
            assert!(
                result["error"]["code"]
                    .as_str()
                    .unwrap()
                    .starts_with("policy.deny."),
                "{result}"
            );
            assert!(
                !f.server
                    .resolve_approval_dir()
                    .unwrap()
                    .join("operator.toml")
                    .exists()
            );
            assert!(control.methods().is_empty());
            drop(f);

            let run = X402Run::with(|raw| one_x402_call_per_day(&raw)).await;
            let (second_nonce, second_attestation) = X402Run::approve(&run.f, &run.control).await;
            assert_eq!(run.pay().await["ok"], true);
            let seed_reads = run.f.seed_reads.load(Ordering::SeqCst);
            let result = run
                .pay_with(x402_args(
                    &run.f,
                    Some((&second_nonce, &second_attestation)),
                ))
                .await;
            assert_eq!(result["ok"], false, "{result}");
            assert_eq!(
                result["error"]["code"], "policy.deny.rate_limit_exceeded",
                "{result}"
            );
            assert!(result["data"].get("paymentSignature").is_none());
            assert_eq!(authorizations(&run.f).len(), 2, "no new authorization");
            assert_eq!(run.f.seed_reads.load(Ordering::SeqCst), seed_reads);
            assert!(run.control.methods().is_empty());
        }

        #[tokio::test]
        #[serial_test::serial(keyring)]
        async fn mainnet_x402_missing_approval_refuses_before_the_intent() {
            let run = X402Run::new().await;
            let unknown = base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                uuid::Uuid::new_v4().as_bytes(),
            );
            let result = run
                .pay_with(x402_args(&run.f, Some((&unknown, &run.attestation))))
                .await;
            assert_x402_refused_before_intent(&run, &result, "policy.approval_required", 0);
            assert!(run.control.methods().is_empty());
        }

        #[tokio::test]
        #[serial_test::serial(keyring)]
        async fn mainnet_x402_overlong_approval_refuses_the_intent_and_logs_once() {
            use stellar_agent_core::approval::{PendingApproval, process_uid_for_attestation};
            let run = X402Run::new().await;
            let requirements = run.f.requirements();
            let root =
                stellar_agent_x402::exact::payment_root(&requirements, run.f.envelope.source())
                    .unwrap();
            let network_id =
                sha2::Sha256::digest(run.f.server.context.network_passphrase().as_bytes()).into();
            let entry = PendingApproval::new_x402_pending(
                &network_id,
                &root,
                None,
                process_uid_for_attestation().unwrap(),
                3_600_000,
            )
            .unwrap();
            let blob = run.f.attest(&entry);
            let (capture, _guard) =
                stellar_agent_test_support::WarningCapture::capture(Some("stellar_agent"));
            let result = run
                .pay_with(x402_args(&run.f, Some((&entry.approval_nonce, &blob))))
                .await;
            assert_x402_refused_before_intent(
                &run,
                &result,
                "network.mainnet_authorization_refused",
                1,
            );
            assert!(
                result["error"]["message"]
                    .as_str()
                    .unwrap()
                    .starts_with("payment withheld before signed transmission"),
                "{result}"
            );
            let refusals: Vec<_> = capture
                .seen()
                .into_iter()
                .filter(|fields| {
                    fields
                        .get("message")
                        .is_some_and(|message| message.contains("mainnet authorization refused"))
                })
                .collect();
            assert_eq!(refusals.len(), 1, "one log of the refusal: {refusals:?}");
            assert_eq!(
                refusals[0]["precondition"].trim_matches('"'),
                "approval_ttl_exceeds_rule"
            );
        }

        #[tokio::test]
        #[serial_test::serial(keyring)]
        async fn mainnet_x402_first_simulation_failure_keeps_its_code() {
            let run = X402Run::new().await;
            run.control
                .first_simulation_error
                .store(true, Ordering::SeqCst);
            let result = run.pay().await;
            assert_eq!(result["ok"], false, "{result}");
            assert_eq!(
                result["error"]["code"], "x402.rpc_simulate_failed",
                "{result}"
            );
            assert!(
                result["error"]["message"]
                    .as_str()
                    .unwrap()
                    .starts_with("payment withheld before signed transmission"),
                "{result}"
            );
            assert!(result["data"].get("paymentSignature").is_none());
            assert!(authorizations(&run.f).is_empty());
            assert_eq!(run.f.seed_reads.load(Ordering::SeqCst), 0);
            assert_eq!(run.simulations(), 1);
        }
        /// The bound witness of the fixture's payment, from the oracle the
        /// routed fixture names, as the payment commit obtains it.
        async fn bound_payment_witness(
            f: &Fixture,
            client: &stellar_agent_network::StellarRpcClient,
        ) -> stellar_agent_network::cross_check::CrossCheckOutcome {
            let source = f.envelope.source();
            let destination = f.envelope.destination();
            let source_view = stellar_agent_network::fetch_account(client, source, &[])
                .await
                .unwrap();
            let destination_view = stellar_agent_network::fetch_account(client, destination, &[])
                .await
                .ok();
            let inputs = stellar_agent_network::cross_check::PayWitnessInputs {
                source: stellar_agent_network::cross_check::AccountObservation::from_view(
                    &source_view,
                )
                .unwrap(),
                destination: stellar_agent_network::cross_check::DestinationObservation::from_view(
                    destination,
                    destination_view.as_ref(),
                ),
                memo: stellar_agent_network::sep29::check_memo_required(client, destination, false)
                    .await
                    .unwrap(),
                trustline:
                    stellar_agent_network::cross_check::TrustlineObservation::read_send_asset(
                        client,
                        source,
                        &stellar_agent_network::Asset::Native,
                    )
                    .await
                    .unwrap(),
            };
            let outcome = f
                .server
                .classic_witness(
                    stellar_agent_core::cross_check::CrossCheckValue::Amount {
                        asset: &stellar_agent_core::asset_id::CanonicalAsset::Native,
                        base_units: 10,
                    },
                    inputs,
                    f.envelope.envelope_xdr(),
                    "stellar_pay_commit",
                )
                .await
                .unwrap();
            assert!(
                outcome.witness().is_some(),
                "the payment requires the witness"
            );
            outcome
        }

        #[tokio::test]
        #[serial_test::serial(keyring)]
        async fn mainnet_gate_preserves_overlong_approval_for_resolver_refusal() {
            use stellar_agent_core::approval::{PendingApproval, process_uid_for_attestation};
            use stellar_agent_network::mainnet::resolve::{TxSignRequest, resolve_tx_sign};
            use stellar_agent_network::mainnet::{
                MainnetAuthorizationError, MainnetConsumer, MainnetPrecondition,
            };
            let rpc = wiremock::MockServer::start().await;
            let f = routed_fixture(|raw| raw, &rpc);
            let control = mount_rpc(&f, &rpc).await;
            let entry = PendingApproval::new_payment_pending(
                f.envelope.envelope_xdr().to_owned(),
                f.envelope.envelope_xdr().as_bytes(),
                f.envelope.destination().to_owned(),
                10,
                "XLM".to_owned(),
                None,
                100,
                2,
                process_uid_for_attestation().unwrap(),
                3_600_000,
            )
            .unwrap();
            let blob = f.attest(&entry);
            let outcome = f
                .server
                .dispatch_gate("stellar_pay_commit", &f.args(), "stellar:mainnet")
                .await
                .unwrap();
            let outcome = f
                .server
                .force_mainnet_confirmation("stellar_pay_commit", outcome)
                .unwrap();
            let approval = verify_attestation_gate(
                &f.server,
                &outcome,
                GatedApprovalKind::Payment,
                f.envelope.envelope_xdr(),
                Some(&entry.approval_nonce),
                Some(&blob),
                "stellar_pay_commit",
            )
            .await
            .unwrap()
            .unwrap();
            let guard = f
                .server
                .mainnet_write_admission(MainnetConsumer::McpPay)
                .unwrap();
            let signer = f.server.mainnet_enrolled_signer(&guard).unwrap();
            let client = guard.context.primary_client().unwrap();
            let store = stellar_agent_network::policy_state::PersistedWindowStore::at_path(
                f.server.window_path.clone(),
            );
            let audit = stellar_agent_network::mainnet::audit_readiness::audit_readiness(
                guard.context.profile(),
                "operator",
            )
            .unwrap();
            let witness = bound_payment_witness(&f, &client).await;
            let failure = resolve_tx_sign(TxSignRequest {
                context: guard.context,
                consumer: MainnetConsumer::McpPay,
                unsigned_envelope_xdr: f.envelope.envelope_xdr(),
                client: &client,
                probe_deadline: std::time::Duration::from_secs(5),
                witness: witness.witness(),
                signer: &signer,
                policy: guard.policy,
                enablement: guard.enablement,
                approval: &approval,
                audit,
                store: &store,
            })
            .await
            .unwrap_err();
            assert!(
                matches!(
                    failure,
                    MainnetAuthorizationError::Refused(MainnetPrecondition::ApprovalTtlExceedsRule)
                ),
                "{failure}"
            );
            assert_eq!(f.seed_reads.load(Ordering::SeqCst), 0);
            assert_eq!(control.count("sendTransaction"), 0);
            assert!(
                store
                    .open_authorizations(
                        guard.context.profile(),
                        stellar_agent_core::timefmt::now_unix_ms().unwrap()
                    )
                    .unwrap()
                    .is_empty()
            );
        }

        #[test]
        #[serial_test::serial(keyring)]
        fn mainnet_nonce_minter_uses_the_disk_snapshot() {
            let f = Fixture::new(|raw| raw);
            let mut merged = (*f.server.profile).clone();
            merged.mcp_nonce_key_alias.account = "overlay".to_owned();
            let server = WalletServer::new_with_selection(
                merged,
                ProfileNameSource::Flag,
                &default_profile_dir().unwrap(),
            )
            .unwrap();
            let now = stellar_agent_core::timefmt::now_unix_ms().unwrap();
            assert!(
                server
                    .nonce_mint
                    .mint(
                        server.tool_catalogue.as_ref(),
                        f.envelope.envelope_xdr().as_bytes(),
                        now,
                        now + 60_000,
                        "stellar_pay_commit",
                        "stellar:mainnet"
                    )
                    .is_ok()
            );
            assert_eq!(
                server.security_profile().mcp_nonce_key_alias.account,
                "default"
            );
            assert_eq!(f.seed_reads.load(Ordering::SeqCst), 0);
        }
    }

    // value_descriptor_enumeration: family (a) and family (b) coverage cross-check

    /// Cross-checks the two derivation families of the typed value descriptor
    /// ([`stellar_agent_core::policy::v1::value::ValueClass`]) against each other
    /// and against the registered MCP tool inventory.
    ///
    /// A tool's value effect is derived one of two ways:
    ///
    /// - **Family (a), the args path.**
    ///   [`stellar_agent_core::policy::v1::value::derive_value_class`]
    ///   maps `(tool_name, args)` straight to a `ValueClass` for the two-phase
    ///   classic tools (`stellar_pay`, `stellar_create_account`, `stellar_claim`,
    ///   `stellar_trustline`, and their `_commit` twins) and the three SEP-43
    ///   opaque-sign tools. This module is placed inside `stellar-agent-mcp` (not
    ///   `stellar-agent-core`) specifically so it can also reach family (b).
    /// - **Family (b), handler-supplied.** Single-shot DeFi/DEX/x402 handlers
    ///   decode their operation once and build [`stellar_agent_core::policy::v1::ValueLeg`]s
    ///   directly via a shared per-domain builder (
    ///   `dex_trade_value_leg`, `vault_deposit_value_legs`,
    ///   `vault_withdraw_value_leg`, [`x402_value_leg`]), then wrap them in
    ///   `ValueClass::Value(ValueEffects::new(legs))` for
    ///   [`WalletServer::dispatch_gate_with_value`]. The dispatch gate does not
    ///   derive anything for these tools; the gate's fail-closed
    ///   `classify_value` default (a `MovesValue` tool that resolves no effects
    ///   denies rather than passing as read-only) and the `debug_assert!` inside
    ///   `ValueEffects::new` (non-empty legs) are what would surface a forgotten
    ///   family-(b) wiring at runtime. This module verifies the wiring itself is
    ///   present and correctly shaped, ahead of that runtime backstop.
    ///
    /// # Registry coverage and per-family enumeration
    ///
    /// `registry_cross_check_every_moves_value_tool_resolves_through_a_family`
    /// enforces that every `MovesValue` tool the `inventory` registry actually
    /// contains resolves through one of the two families (no unreachable tool).
    /// `family_a_derives_expected_action_kind_and_debit_per_tool` and
    /// `family_b_builders_produce_expected_action_kind_and_debit` exercise every
    /// family-(a) arm and every family-(b) builder individually with
    /// representative parsed inputs and assert the produced leg(s) carry the
    /// documented `ActionKind` and debit classification.
    mod value_descriptor_enumeration {
        #![allow(
            clippy::unwrap_used,
            clippy::expect_used,
            clippy::panic,
            reason = "test-only fixture construction"
        )]

        use std::collections::HashSet;

        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        use serde_json::json;
        use stellar_agent_core::policy::v1::value::derive_value_class;
        use stellar_agent_core::policy::v1::{ActionKind, ValueClass};
        use stellar_agent_core::policy::{McpToolRegistration, ToolValueKind};
        use stellar_agent_defindex::value::{vault_deposit_value_legs, vault_withdraw_value_leg};
        use stellar_agent_dex::value::dex_trade_value_leg;
        use stellar_agent_mpp::{
            ChallengeInput, HttpRequestContext, json::canonical_json, mpp_value_effects,
            select_and_validate,
        };

        use super::{decode_payment_required_input, x402_value_leg};

        // Representative fixtures shared by both tests below. Valid-shaped
        // G-/C-strkeys so `derive_value_class` / the builders exercise their real
        // parse paths rather than short-circuiting on malformed input.
        const DESTINATION: &str = "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL";
        const USDC_ASSET: &str = "USDC:GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";
        const RESERVE_ASSET_A: &str = "CAQCFVLOBK5GIULPNZRGATJJMIZL5BSP7X5YJVMGCPTUEPFM4AVSRCJU";
        const RESERVE_ASSET_B: &str = "CAJJZSGMMM3PD7N33TAPHGBUGTB43OC73HVIK2L2G6BNGGGYOSSYBXBD";
        const ROUTER: &str = "CCJUD55AG6W5HAI5LRVNKAE5WDP5XGZBUDS5WNTIVDU7O264UZZE7BRD";
        const VAULT: &str = "CBMVK2JK6NTOT2O4HNQAIQFJY232BHKGLIMXDVQVHIIZKDACXDFZDWHN";

        /// Family-(a) tool names: `derive_value_class` recognises these directly
        /// from `(tool_name, args)`. Mirrors the match arms in
        /// `stellar_agent_core::policy::v1::value::derive_value_class`.
        const FAMILY_A_TOOLS: &[&str] = &[
            "stellar_pay",
            "stellar_pay_commit",
            "stellar_create_account",
            "stellar_create_account_commit",
            "stellar_claim",
            "stellar_claim_commit",
            "stellar_trustline",
            "stellar_trustline_commit",
        ];

        /// Family-(b) tool names: the handler decodes once and builds legs via a
        /// shared builder before calling `dispatch_gate_with_value`. Mirrors the
        /// `value_kind = "moves_value"` handlers in `dex_trade.rs`,
        /// `vault.rs`, `x402_create_payment.rs`, `x402_authenticated_payment.rs`.
        const FAMILY_B_TOOLS: &[&str] = &[
            "stellar_dex_trade",
            "stellar_defindex_vault_deposit",
            "stellar_defindex_vault_withdraw",
            "stellar_x402_create_payment",
            "stellar_x402_authenticated_payment",
            "stellar_mpp_charge_prepare",
            "stellar_mpp_charge_commit",
        ];

        fn sample_x402_requirements() -> stellar_agent_x402::wire::PaymentRequirements {
            let json = json!({
                "scheme": "exact",
                "network": "stellar:testnet",
                "asset": "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA",
                "amount": "2500000",
                "payTo": DESTINATION,
                "maxTimeoutSeconds": 300,
                "extra": { "areFeesSponsored": true }
            })
            .to_string();
            decode_payment_required_input(&json).expect("sample x402 requirements must decode")
        }

        fn sample_mpp_legs() -> Vec<stellar_agent_core::policy::v1::ValueLeg> {
            let request = json!({
                "amount": "2500000",
                "currency": "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA",
                "methodDetails": {"feePayer": true, "network": "stellar:testnet"},
                "recipient": DESTINATION
            });
            let encoded =
                URL_SAFE_NO_PAD.encode(canonical_json(&request).expect("canonical request"));
            let selected = select_and_validate(
            &ChallengeInput::Http {
                www_authenticate: vec![format!(
                    "Payment id=one, realm=merchant, method=stellar, intent=charge, request={encoded}"
                )],
                selected_challenge_id: None,
                context: HttpRequestContext::new(
                    "https://merchant.example",
                    "POST",
                    "https://merchant.example/charge",
                    None,
                    None,
                )
                .expect("context"),
            },
            1_700_000_000,
        )
        .expect("selected challenge");
            mpp_value_effects(&selected).legs().to_vec()
        }

        /// Builds the non-empty leg vector a family-(b) tool would pass to
        /// `dispatch_gate_with_value` for `tool_name`, using representative
        /// parsed inputs. Panics (test-only) for any name outside
        /// [`FAMILY_B_TOOLS`]; every call site below only ever passes a name from
        /// that set.
        fn family_b_legs_for(tool_name: &str) -> Vec<stellar_agent_core::policy::v1::ValueLeg> {
            match tool_name {
                "stellar_dex_trade" => {
                    let canonical_path =
                        vec![RESERVE_ASSET_A.to_owned(), RESERVE_ASSET_B.to_owned()];
                    vec![dex_trade_value_leg(
                        1_000_000_000_i128,
                        &canonical_path,
                        ROUTER,
                    )]
                }
                "stellar_defindex_vault_deposit" => {
                    let amounts_desired = vec![250_000_000_i128, 100_000_000_i128];
                    let asset_addresses =
                        vec![RESERVE_ASSET_A.to_owned(), RESERVE_ASSET_B.to_owned()];
                    vault_deposit_value_legs(&amounts_desired, &asset_addresses, VAULT)
                }
                "stellar_defindex_vault_withdraw" => {
                    vec![vault_withdraw_value_leg(75_000_000_i128, VAULT)]
                }
                "stellar_x402_create_payment" | "stellar_x402_authenticated_payment" => {
                    let requirements = sample_x402_requirements();
                    let amount = stellar_agent_x402::exact::validate_requirements(
                        &requirements,
                        "Test SDF Network ; September 2015",
                        "https://soroban-testnet.stellar.org",
                    )
                    .expect("valid requirements must build a leg");
                    vec![x402_value_leg(&requirements, amount)]
                }
                "stellar_mpp_charge_prepare" | "stellar_mpp_charge_commit" => sample_mpp_legs(),
                other => panic!("family_b_legs_for: unrecognised family-(b) tool name '{other}'"),
            }
        }

        // Registry and no-dead-reference cross-check

        /// Enforces that every `ToolValueKind::MovesValue` tool the `inventory`
        /// registry actually contains resolves through EITHER derivation family.
        ///
        /// # Invariant enforced
        ///
        /// A derivation keyed to a tool name that no registered tool carries can
        /// never gate a real call; it silently no-ops. So every `MovesValue` tool
        /// the registry contains MUST resolve its value effect through family (a)
        /// (`derive_value_class` on `(tool_name, args)`) or family (b) (a shared
        /// per-domain leg builder); otherwise its effect cannot be sized and the
        /// policy gate cannot constrain it.
        ///
        /// This test enumerates the CURRENT registry (not a name literal copied
        /// from source) and asserts every `MovesValue` entry is in
        /// [`FAMILY_A_TOOLS`] or [`FAMILY_B_TOOLS`]: it FAILS if a future
        /// `MovesValue` tool is registered without adding a `derive_value_class`
        /// arm or a family-(b) builder call, because such a tool falls through
        /// `derive_value_class`'s wildcard `_ => ValueClass::ReadOnly` arm and
        /// does not appear in either family set here.
        ///
        /// The reverse direction is checked too: every name in [`FAMILY_A_TOOLS`]
        /// and [`FAMILY_B_TOOLS`] must itself be a real, currently-registered
        /// `MovesValue` tool, which guards against a derivation path keyed to a
        /// tool name absent from the registry.
        #[test]
        fn registry_cross_check_every_moves_value_tool_resolves_through_a_family() {
            let family_a: HashSet<&str> = FAMILY_A_TOOLS.iter().copied().collect();
            let family_b: HashSet<&str> = FAMILY_B_TOOLS.iter().copied().collect();
            assert!(
                family_a.is_disjoint(&family_b),
                "a tool name must not appear in both derivation families"
            );

            let registered: HashSet<&'static str> = inventory::iter::<McpToolRegistration>()
                .map(|reg| reg.name)
                .collect();
            let registered_moves_value: HashSet<&'static str> =
                inventory::iter::<McpToolRegistration>()
                    .filter(|reg| reg.value_kind == ToolValueKind::MovesValue)
                    .map(|reg| reg.name)
                    .collect();
            assert!(
                !registered_moves_value.is_empty(),
                "the registry must contain at least one MovesValue tool for this \
             cross-check to be non-vacuous"
            );

            // Forward direction: every registered MovesValue tool is covered.
            for name in registered_moves_value.iter().copied() {
                assert!(
                    family_a.contains(name) || family_b.contains(name),
                    "registered MovesValue tool '{name}' is not covered by either \
                 derivation family; its value effect cannot be sized by the \
                 policy gate, so no value rule could constrain it"
                );

                // The family-(a) coverage claim must be a REAL claim: calling
                // derive_value_class with representative args must actually
                // produce a populated, non-empty Value (not silently fall through
                // to the wildcard ReadOnly arm because the tool name was typo'd
                // in FAMILY_A_TOOLS).
                if family_a.contains(name) {
                    let args = representative_family_a_args(name);
                    let vc = derive_value_class(name, &args);
                    assert!(
                        matches!(&vc, ValueClass::Value(effects) if !effects.legs().is_empty()),
                        "FAMILY_A_TOOLS claims '{name}' is derived by derive_value_class, \
                     but derive_value_class returned {vc:?} for representative args"
                    );
                }

                // Same real-claim check for family (b): the builder must actually
                // produce a non-empty leg vector for this tool.
                if family_b.contains(name) {
                    let legs = family_b_legs_for(name);
                    assert!(
                        !legs.is_empty(),
                        "FAMILY_B_TOOLS claims '{name}' is covered by a shared builder, \
                     but the builder produced no legs"
                    );
                }
            }

            // Reverse direction: neither family set references a tool name absent
            // from the registry.
            for name in family_a.iter().copied().chain(family_b.iter().copied()) {
                assert!(
                    registered.contains(name),
                    "derivation family references tool '{name}', which is not a \
                 registered MCP tool; a derivation keyed to an unregistered \
                 tool name would never gate a real call"
                );
                assert!(
                    registered_moves_value.contains(name),
                    "derivation family references tool '{name}', which is registered \
                 but not classified ToolValueKind::MovesValue"
                );
            }
        }

        /// Representative pre-decode `args` for a [`FAMILY_A_TOOLS`] entry,
        /// shaped so `derive_value_class` resolves a populated leg (mirrors the
        /// fixtures in `derive_pay_builds_payment_leg_from_authoritative_args` /
        /// `derive_create_account_builds_native_account_creation_leg` /
        /// `derive_claim_builds_non_debit_claim_leg` /
        /// `derive_trustline_builds_non_debit_trustline_leg_with_asset` in
        /// `stellar_agent_core::policy::v1::value`).
        fn representative_family_a_args(tool_name: &str) -> serde_json::Value {
            match tool_name {
                "stellar_pay" | "stellar_pay_commit" => json!({
                    "amount_stroops": "1500000000",
                    "asset": "native",
                    "destination": DESTINATION,
                }),
                "stellar_create_account" | "stellar_create_account_commit" => json!({
                    "starting_balance_stroops": "50000000",
                    "destination": DESTINATION,
                }),
                "stellar_claim" | "stellar_claim_commit" => json!({
                    "balance_id": "00000000abcdef",
                }),
                "stellar_trustline" | "stellar_trustline_commit" => json!({
                    "asset": USDC_ASSET,
                }),
                other => {
                    panic!("representative_family_a_args: unrecognised family-(a) tool '{other}'")
                }
            }
        }

        // Two-family enumeration

        /// Exercises every family-(a) arm (pay/create/claim/trustline and their
        /// `_commit` twins) with representative parsed args and asserts the
        /// derived leg carries the documented [`ActionKind`] and debit
        /// classification.
        #[test]
        fn family_a_derives_expected_action_kind_and_debit_per_tool() {
            let cases: &[(&str, ActionKind, bool)] = &[
                ("stellar_pay", ActionKind::Payment, true),
                ("stellar_pay_commit", ActionKind::Payment, true),
                ("stellar_create_account", ActionKind::AccountCreation, true),
                (
                    "stellar_create_account_commit",
                    ActionKind::AccountCreation,
                    true,
                ),
                ("stellar_claim", ActionKind::Claim, false),
                ("stellar_claim_commit", ActionKind::Claim, false),
                ("stellar_trustline", ActionKind::Trustline, false),
                ("stellar_trustline_commit", ActionKind::Trustline, false),
            ];

            for (tool_name, expected_kind, expect_debit) in cases.iter().copied() {
                let args = representative_family_a_args(tool_name);
                let vc = derive_value_class(tool_name, &args);
                let ValueClass::Value(effects) = vc else {
                    panic!("expected ValueClass::Value for '{tool_name}', got {vc:?}");
                };
                assert!(
                    !effects.legs().is_empty(),
                    "'{tool_name}' must derive at least one leg"
                );
                for leg in effects.legs() {
                    assert_eq!(
                        leg.kind, expected_kind,
                        "'{tool_name}' leg kind must be {expected_kind:?}"
                    );
                    assert_eq!(
                        leg.kind.carries_debit(),
                        expect_debit,
                        "'{tool_name}' leg carries_debit must be {expect_debit}"
                    );
                }
            }
        }

        /// Exercises every family-(b) shared builder with representative parsed
        /// inputs and asserts the produced leg(s) carry the documented
        /// [`ActionKind`], debit classification, and (for DEX/vault-withdraw)
        /// the documented asset/destination shape.
        #[test]
        fn family_b_builders_produce_expected_action_kind_and_debit() {
            // DEX: single send-side debit leg.
            let dex_legs = family_b_legs_for("stellar_dex_trade");
            assert_eq!(dex_legs.len(), 1);
            assert_eq!(dex_legs[0].kind, ActionKind::DexTrade);
            assert!(dex_legs[0].kind.carries_debit(), "a DEX trade is a debit");
            assert_eq!(dex_legs[0].amount, Some(1_000_000_000_i128));
            assert_eq!(dex_legs[0].asset.as_deref(), Some(RESERVE_ASSET_A));
            assert_eq!(dex_legs[0].destination.as_deref(), Some(ROUTER));

            // Vault deposit: one debit leg per asset.
            let deposit_legs = family_b_legs_for("stellar_defindex_vault_deposit");
            assert_eq!(deposit_legs.len(), 2);
            for leg in &deposit_legs {
                assert_eq!(leg.kind, ActionKind::VaultDeposit);
                assert!(leg.kind.carries_debit(), "a vault deposit is a debit");
                assert_eq!(leg.destination.as_deref(), Some(VAULT));
            }
            assert_eq!(deposit_legs[0].amount, Some(250_000_000_i128));
            assert_eq!(deposit_legs[0].asset.as_deref(), Some(RESERVE_ASSET_A));
            assert_eq!(deposit_legs[1].amount, Some(100_000_000_i128));
            assert_eq!(deposit_legs[1].asset.as_deref(), Some(RESERVE_ASSET_B));

            // Vault withdraw: single non-debit leg; amount is the share count.
            let withdraw_legs = family_b_legs_for("stellar_defindex_vault_withdraw");
            assert_eq!(withdraw_legs.len(), 1);
            assert_eq!(withdraw_legs[0].kind, ActionKind::VaultWithdraw);
            assert!(
                !withdraw_legs[0].kind.carries_debit(),
                "a vault withdrawal returns funds; not a spendable-balance debit"
            );
            assert_eq!(withdraw_legs[0].amount, Some(75_000_000_i128));
            assert_eq!(withdraw_legs[0].asset, None);
            assert_eq!(withdraw_legs[0].destination.as_deref(), Some(VAULT));

            // x402: single debit leg from the decoded PaymentRequirements.
            for tool_name in [
                "stellar_x402_create_payment",
                "stellar_x402_authenticated_payment",
            ] {
                let x402_legs = family_b_legs_for(tool_name);
                assert_eq!(x402_legs.len(), 1);
                assert_eq!(x402_legs[0].kind, ActionKind::X402Payment);
                assert!(
                    x402_legs[0].kind.carries_debit(),
                    "an x402 payment is a debit"
                );
                assert_eq!(x402_legs[0].amount, Some(2_500_000_i128));
                assert_eq!(
                    x402_legs[0].destination.as_deref(),
                    Some(DESTINATION),
                    "x402 leg destination must be requirements.pay_to verbatim"
                );
            }

            // MPP: prepare and commit derive the same single debit leg from the
            // exact validated challenge persisted between the two phases.
            for tool_name in ["stellar_mpp_charge_prepare", "stellar_mpp_charge_commit"] {
                let mpp_legs = family_b_legs_for(tool_name);
                assert_eq!(mpp_legs.len(), 1);
                assert_eq!(mpp_legs[0].kind, ActionKind::MppCharge);
                assert!(mpp_legs[0].kind.carries_debit(), "an MPP charge is a debit");
                assert_eq!(mpp_legs[0].amount, Some(2_500_000_i128));
                assert_eq!(
                    mpp_legs[0].destination.as_deref(),
                    Some(DESTINATION),
                    "MPP destination must be the validated challenge recipient"
                );
            }
        }
        #[test]
        fn approval_required_hint_quotes_profile_name() {
            let result = super::approval_required_indistinguishable("treasury ops");
            let (code, message, _) = super::assert_business_envelope(&result);
            assert_eq!(code, "policy.approval_required");
            assert!(message.contains("--profile 'treasury ops'"));
        }
    }
}
