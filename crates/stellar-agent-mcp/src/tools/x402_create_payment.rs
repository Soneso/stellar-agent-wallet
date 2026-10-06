//! `stellar_x402_create_payment` MCP tool — x402 Exact Stellar payment construction.
//!
//! Constructs and signs a x402 v2 `PAYMENT-SIGNATURE` payload for the Exact
//! Stellar scheme.  The wallet is a **payer** (consumer); the MCP host
//! performs the actual HTTP request/retry to the facilitator.
//!
//! # Protocol reference (x402 v2)
//!
//! - `PAYMENT-REQUIRED` header (base64) → `PaymentRequirements` (accepts[] element).
//! - `PAYMENT-SIGNATURE` header (base64) → `PaymentPayload` (this tool's output).
//!
//! # Input
//!
//! `payment_required` may be supplied in two forms:
//!
//! 1. **Base64-encoded JSON** — a standard-base64 (RFC 4648 §4) encoded
//!    `PaymentRequirements` JSON object, as it appears in the raw
//!    `PAYMENT-REQUIRED` HTTP header value.
//! 2. **Raw JSON string** — the `PaymentRequirements` JSON object directly,
//!    without base64 wrapping.
//!
//! The handler tries base64-decode first; if that fails or yields non-UTF-8
//! bytes, it attempts to parse the input directly as JSON.  The caller should
//! pass ONE selected `PaymentRequirements` element (the `accepts[]` element the
//! host already chose), NOT a full 402-response envelope with a top-level
//! `accepts[]` array.
//!
//! # Security
//!
//! - RPC URL is resolved from the **active profile** (operator-controlled);
//!   it is NEVER accepted from the `payment_required` input.
//! - Network passphrase is taken from the active profile; a mismatch between
//!   the x402 `network` field and the profile passphrase is a hard error.
//! - Signer is loaded from the platform keyring at call time; the keypair is
//!   never held in memory between calls.
//!
//! # Output
//!
//! Returns `{ paymentSignature, payer, asset, amount, payTo, network }`:
//!
//! - `paymentSignature` — standard-base64 `PAYMENT-SIGNATURE` header value.
//! - `payer` — payer address (G-strkey), redacted in telemetry.
//! - `asset` — SAC contract address (C-strkey).
//! - `amount` — atomic-unit amount string from `PaymentRequirements`.
//! - `payTo` — recipient address from `PaymentRequirements`.
//! - `network` — x402 CAIP-2 network string from `PaymentRequirements`.

use rmcp::{
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Content},
    schemars, serde, tool, tool_router,
};
use serde_json::json;
use stellar_agent_core::audit_log::{AuditEntry, PolicyDecision, ValueLegRecord};
use stellar_agent_core::policy::v1::ValueClass;
use stellar_agent_mcp_macros::mcp_tool_router;

use crate::server::WalletServer;
use crate::tools::common::{
    business_error_result, decode_payment_required_input, x402_error_to_tool_result, x402_value_leg,
};
use crate::tools::value_audit::emit_value_audit_row_strict;

// ─────────────────────────────────────────────────────────────────────────────
// Argument type
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for the `stellar_x402_create_payment` MCP tool.
///
/// # Schema
///
/// - `payment_required` — base64-encoded `PAYMENT-REQUIRED` header value OR
///   raw JSON `PaymentRequirements` object.  The tool accepts both forms and
///   tries base64-decode first.
/// - `chain_id` — CAIP-2 chain identifier (`"stellar:pubnet"` or
///   `"stellar:testnet"`); validated against the active profile.
/// - `address` — optional signer address (G-strkey); when provided must match
///   the active signer enrolled in the profile.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(crate = "rmcp::serde")]
pub struct X402CreatePaymentArgs {
    /// Base64-encoded `PAYMENT-REQUIRED` header value OR raw JSON
    /// `PaymentRequirements` object.
    ///
    /// The tool tries base64-decode + JSON-parse first; falls back to direct
    /// JSON-parse when base64 decoding fails or yields non-JSON bytes.
    pub payment_required: String,

    /// CAIP-2 chain identifier (`"stellar:pubnet"` or `"stellar:testnet"`).
    ///
    /// Validated against the active profile.  Mismatch returns a JSON-RPC
    /// `ErrorData` from the `dispatch_gate` preamble.
    pub chain_id: String,

    /// Optional signer address (G-strkey).
    ///
    /// When provided must match the active signer enrolled in the profile.
    /// Omit to use the profile default signer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
}

// The x402 decode and error-envelope helpers are single-sourced in
// `crate::tools::common` and imported above.

// ─────────────────────────────────────────────────────────────────────────────
// Tool router impl block
// ─────────────────────────────────────────────────────────────────────────────

/// Constructs and signs an x402 v2 `PAYMENT-SIGNATURE` payload.
///
/// Accepts a `PaymentRequirements` object (as the base64-encoded
/// `PAYMENT-REQUIRED` header value OR raw JSON), performs the
/// validate → build-SAC-transfer → simulate → sign-auth-entry →
/// re-simulate → serialize flow, and returns the standard-base64
/// `PAYMENT-SIGNATURE` value ready for the `PAYMENT-SIGNATURE` HTTP header.
///
/// The wallet is the payment **payer**.  The MCP host is responsible for
/// the actual HTTP-402 request/retry cycle; this tool only produces the
/// signed payload.
///
/// Returns `{ paymentSignature, payer, asset, amount, payTo, network }` on
/// success.  Errors return the standard business-error envelope
/// `{ ok: false, error: { code, message }, request_id }` with `isError = true`;
/// `error.code` is the per-variant `x402.<reason>` wire code (the mainnet
/// refusal uses `network.mainnet_write_forbidden`).
///
/// # Tool annotations
///
/// - `readOnlyHint = false` — constructs a signed artifact (accesses keyring).
/// - `destructiveHint = false` — produces a signed payload only; the HOST
///   submits to the network.  The wallet does NOT submit.
///
/// # Security reference
///
/// RPC URL and passphrase come from the active profile (NEVER from input).
///
/// # Errors
///
/// Returns `isError = true` with the business-error envelope (per-variant
/// `x402.<reason>` `error.code`) when:
/// - `chain_id` does not match the active profile.
/// - `payment_required` is not valid base64+JSON or raw JSON `PaymentRequirements`.
/// - The `scheme` field is not `"exact"`.
/// - The `network` field is not `"stellar:pubnet"` or `"stellar:testnet"`.
/// - The x402 `network` passphrase does not match the profile passphrase.
/// - `extra.areFeesSponsored` is not `true`.
/// - The `amount` field cannot be parsed as an `i128`.
/// - The keyring entry for the signer cannot be loaded.
/// - The Soroban RPC simulate call fails.
/// - The auth-entry signing step fails.
///
/// The audit refusals carry their `audit.*` code: the pre-flight before the
/// signer load, and the `x402_payment_authorized` row the transmit gate writes
/// before the signed authorization leaves the wallet.
///
/// # Examples
///
/// ```json
/// {
///   "chain_id": "stellar:testnet",
///   "payment_required": "<base64-encoded PaymentRequirements>"
/// }
/// ```
#[mcp_tool_router]
#[tool_router(router = x402_create_payment_tool_router, vis = "pub(crate)")]
impl WalletServer {
    #[mcp_tool_item(
        name = "stellar_x402_create_payment",
        destructive_hint = false,
        read_only_hint = false,
        chain_id_required = true,
        value_kind = "moves_value"
    )]
    #[tool(
        name = "stellar_x402_create_payment",
        description = "Construct and sign an x402 v2 PAYMENT-SIGNATURE payload for the Exact Stellar scheme. \
                       Accepts a PaymentRequirements object (base64 PAYMENT-REQUIRED header or raw JSON), \
                       validates, simulates, signs the SAC transfer auth-entry, re-simulates, and returns \
                       { paymentSignature: string, payer: string, asset: string, amount: string, payTo: string, network: string }. \
                       RPC URL and passphrase come from the active profile (never from input). \
                       The wallet is a payer; the MCP host performs the HTTP 402 request. \
                       read_only_hint=false; destructive_hint=false.",
        annotations(read_only_hint = false, destructive_hint = false)
    )]
    async fn stellar_x402_create_payment(
        &self,
        Parameters(args): Parameters<X402CreatePaymentArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        use std::sync::Arc;

        use stellar_agent_network::keyring::enrolled_keyring_signer;
        use stellar_agent_x402::exact::create_payment;
        use stellar_agent_x402::wire::encode_payment_signature;

        // Mainnet structural refusal — before any key access or signing.
        // This tool returns a payment authorization the MCP host broadcasts
        // externally; the submit-layer mainnet gate never fires because the
        // wallet does not submit. Refuse on a mainnet profile so no valid
        // mainnet payment signature is ever produced. Wire code:
        // network.mainnet_write_forbidden.
        if self.context.chain_id.is_mainnet() {
            return Ok(crate::tools::common::x402_mainnet_signing_forbidden_result());
        }

        // ── Decode payment_required input FIRST ───────────────────────────────
        // The dispatch gate needs the value-carrying descriptor, which is
        // derived from this SAME decode (single-decode invariant §2.1) — the
        // gate must run before any signing but AFTER the decode it sizes.
        let requirements = match decode_payment_required_input(&args.payment_required) {
            Ok(r) => r,
            Err(ref err) => return Ok(x402_error_to_tool_result(err)),
        };

        // ── Build the value-carrying leg from the SAME decode ────────────────
        // `x402_value_leg` parses `requirements.amount` to the atomic i128 via
        // the identical logic `create_payment` applies to the same field
        // (mirrored, not shared, because `create_payment` lives in the
        // `stellar-agent-x402` crate and takes `&PaymentRequirements` rather
        // than a pre-parsed amount); both parses are deterministic over the
        // same immutable string and so cannot diverge.
        let value_leg = match x402_value_leg(&requirements) {
            Ok(leg) => leg,
            Err(ref err) => return Ok(x402_error_to_tool_result(err)),
        };

        // Capture the gate-derived leg as an audit record before it moves into
        // the value descriptor, so the row carries exactly what the gate sized.
        let audit_leg = ValueLegRecord::from(&value_leg);
        // Also retain an owned clone for the window-state record after
        // authorization (single-derivation invariant on the recording side
        // too) — `value_leg` itself moves into `ValueClass::single` below.
        let value_leg_for_record = value_leg.clone();

        // ── Telemetry preamble (redaction) ───────────────────────────────────
        let args_value = json!({
            "chain_id": &args.chain_id,
            "payment_required_len": args.payment_required.len(),
        });

        // The gate performs registry lookup, chain validation, and policy evaluation.
        // Value criteria use the supplied value_leg.
        // Single-shot sign tool: RequireApproval is fail-closed. The two-phase
        // approval flow is not supported on this surface. `account_view` /
        // `identity_view` are `None`: the `minimum_reserve` / `home_domain`
        // criteria fail closed on this tool pending account-view wiring.
        let dispatch_outcome = match self
            .dispatch_gate_with_value(
                "stellar_x402_create_payment",
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
        match dispatch_outcome {
            crate::tools::common::DispatchOutcome::Allow(_) => {}
            crate::tools::common::DispatchOutcome::RequireApproval(_) => {
                return Ok(crate::tools::common::single_shot_require_approval_error());
            }
        }

        // ── Audit pre-flight (fail-closed) ────────────────────────────────────
        // Runs AFTER the dispatch gate: a policy denial or approval escalation
        // authorizes no payment and needs no audit setup, so it must surface
        // its own code rather than audit.chain_key_unavailable. The pre-flight
        // precedes the signer load, so a log that cannot take a row refuses
        // before any key is touched. It keeps no handle: the transmit gate
        // writes the `x402_payment_authorized` row through its own registry
        // acquisition, which reruns the anchor check immediately before the
        // signed authorization is sent.
        if let Err(err) = crate::tools::value_audit::require_value_audit_writer(
            &self.profile,
            &self.profile_name_for_approval(),
            self.audit_binding,
        ) {
            return Ok(business_error_result(err.code(), err.to_string()));
        }

        tracing::debug!(
            chain_id = %args.chain_id,
            payment_required_len = args.payment_required.len(),
            "x402_create_payment: dispatch gate passed",
        );

        // ── Validate optional address arg matches profile signer ──────────────
        let account = self.profile.mcp_signer_default.account.as_str();
        if let Some(ref requested_addr) = args.address
            && requested_addr != account
        {
            let err = stellar_agent_x402::X402Error::InvalidPaymentRequired {
                detail: format!(
                    "requested address {requested_addr} does not match profile signer {account}"
                ),
            };
            return Ok(x402_error_to_tool_result(&err));
        }

        // ── Load signer from keyring ──────────────────────────────────────────
        let signer_handle = match enrolled_keyring_signer(
            &self.profile_name_for_approval(),
            &self.profile,
            account,
        )
        .await
        {
            Ok(h) => h,
            Err(err) => {
                if matches!(
                    &err,
                    stellar_agent_core::error::WalletError::Auth(
                        stellar_agent_core::error::AuthError::EnrolledSignerUnpinned { .. }
                            | stellar_agent_core::error::AuthError::EnrolledSignerMismatch { .. }
                    )
                ) {
                    return Ok(crate::tools::common::business_error_result(
                        err.code(),
                        err.to_string(),
                    ));
                }

                // Static detail, matching the signer-load refusal wording on
                // the other signing tools; the keyring error is traced only.
                tracing::debug!(error = %err, "x402 create-payment: signer load failed");
                let x402_err = stellar_agent_x402::X402Error::KeyringLoadFailed {
                    detail: "could not load signer from keyring".to_owned(),
                };
                return Ok(x402_error_to_tool_result(&x402_err));
            }
        };

        // ── Resolve RPC URL from active profile (NEVER from input) ────────────
        // RPC URL is operator-controlled, not facilitator-supplied.
        let rpc_url = self.context.rpc_url.as_str();
        let profile_passphrase = self.context.network_passphrase();

        let payer_address = account.to_owned();

        // ── Dispatch to stellar_agent_x402::create_payment ───────────────────
        let signer: Arc<dyn stellar_agent_network::signing::Signer + Send + Sync> =
            Arc::new(signer_handle);

        // Shared-window admission precedes signing and the signed RPC re-simulation.
        if let Err(refusal) = crate::tools::x402_create_payment::record_x402_authorization(
            self,
            "stellar_x402_create_payment",
            &stellar_agent_core::policy::v1::ValueClass::single(value_leg_for_record),
        ) {
            return Ok(refusal);
        }

        // The transmit gate writes `x402_payment_authorized` before the signed
        // authorization leaves the wallet in the re-simulation. Both rows of
        // this payment share the request id minted here.
        let mut audit = X402AuthorizationAudit::new(
            self,
            "stellar_x402_create_payment",
            args.chain_id.as_str(),
            audit_leg,
        );
        let created = create_payment(
            &requirements,
            signer.as_ref(),
            rpc_url,
            profile_passphrase,
            |authorization| audit.before_transmit(authorization),
        )
        .await;
        let payment_payload = match created {
            Ok(p) => p,
            Err(ref err) => {
                // Log error class without secret bleed (X402Error::Display is redaction-safe).
                tracing::warn!(
                    error_class = %classify_x402_error(err),
                    "x402_create_payment: create_payment failed",
                );
                if let Some(refusal) = audit.refusal_result() {
                    return Ok(refusal);
                }
                audit.record_withheld(X402Failure::CreatePayment(err));
                return Ok(x402_error_to_tool_result(err));
            }
        };

        // ── Encode PAYMENT-SIGNATURE ──────────────────────────────────────────
        let payment_signature = match encode_payment_signature(&payment_payload) {
            Ok(sig) => sig,
            Err(ref err) => {
                audit.record_withheld(X402Failure::Encoding);
                return Ok(x402_error_to_tool_result(err));
            }
        };

        // ── Redact payer address for telemetry ────────────────────────────────
        let redacted_payer =
            stellar_agent_core::observability::redact_strkey_first5_last5(&payer_address);
        tracing::info!(
            payer = %redacted_payer,
            network = %requirements.network,
            "x402_create_payment: payment payload constructed",
        );

        // ── Build response ────────────────────────────────────────────────────
        // amounts are public (payment values); account IDs in the response are
        // NOT telemetry — they are the intended tool output for the MCP caller.
        let response = json!({
            "paymentSignature": payment_signature,
            "payer": payer_address,
            "asset": requirements.asset,
            "amount": requirements.amount,
            "payTo": requirements.pay_to,
            "network": requirements.network,
        });
        let envelope = stellar_agent_core::envelope::Envelope::ok(response);
        let json_str = envelope
            .to_json_pretty()
            .unwrap_or_else(|_| String::from("{}"));
        Ok(CallToolResult::success(vec![Content::text(json_str)]))
    }
}

/// A failure after `create_payment` was called, as the withheld-row stage
/// helper classifies it.
#[derive(Debug, Clone, Copy)]
pub(super) enum X402Failure<'a> {
    /// `create_payment` returned this error.
    CreatePayment(&'a stellar_agent_x402::X402Error),
    /// The handler could not encode the payload as the `PAYMENT-SIGNATURE`
    /// header value.
    Encoding,
}

/// Returns the `x402_authorization_withheld` stage for `failure`, or `None`
/// when the transmit gate never returned `Ok`.
///
/// Before the gate returns `Ok` the signed authorization has not left the
/// wallet and no authorized row exists, so no withheld row is written. After
/// it, an RPC simulate error is the re-simulation itself, every other
/// `create_payment` error is the processing of its answer, and a failure to
/// encode the built payload is the encoding.
pub(super) fn x402_withheld_stage(
    gate_passed: bool,
    failure: X402Failure<'_>,
) -> Option<&'static str> {
    if !gate_passed {
        return None;
    }
    Some(match failure {
        X402Failure::CreatePayment(stellar_agent_x402::X402Error::RpcSimulateFailed { .. }) => {
            "resimulation"
        }
        X402Failure::CreatePayment(_) => "response_processing",
        X402Failure::Encoding => "encoding",
    })
}

/// The transmit gate both x402 tools pass to `create_payment`, and what it
/// observed.
///
/// The gate writes the `x402_payment_authorized` row through the strict
/// helper, which acquires the writer through the registry and reruns the
/// anchor check, so the row is durable before the signed authorization is
/// sent. A write that refuses keeps its wallet error here, and the handler
/// answers with that error's own code. The withheld row of a later failure
/// carries the same request id as the authorized row.
pub(super) struct X402AuthorizationAudit<'a> {
    profile: &'a stellar_agent_core::profile::schema::Profile,
    profile_name: String,
    binding: stellar_agent_core::audit_log::BindingCheck,
    tool: &'static str,
    chain_id: &'a str,
    leg: Option<ValueLegRecord>,
    request_id: String,
    network: String,
    scheme: String,
    gate_passed: bool,
    refusal: Option<stellar_agent_core::error::WalletError>,
}

impl<'a> X402AuthorizationAudit<'a> {
    /// Mints the request id both rows of this payment share.
    pub(super) fn new(
        server: &'a WalletServer,
        tool: &'static str,
        chain_id: &'a str,
        leg: ValueLegRecord,
    ) -> Self {
        Self {
            profile: &server.profile,
            profile_name: server.profile_name_for_approval(),
            binding: server.audit_binding,
            tool,
            chain_id,
            leg: Some(leg),
            request_id: uuid::Uuid::new_v4().to_string(),
            network: String::new(),
            scheme: String::new(),
            gate_passed: false,
            refusal: None,
        }
    }

    /// The transmit gate: writes the authorized row, or refuses.
    ///
    /// # Errors
    ///
    /// [`stellar_agent_x402::X402Error::TransmitGateRefused`] when the row
    /// cannot be written. The wallet error that refused is kept for
    /// [`X402AuthorizationAudit::refusal_result`].
    pub(super) fn before_transmit(
        &mut self,
        authorization: &stellar_agent_x402::exact::AuthorizationToTransmit<'_>,
    ) -> Result<(), stellar_agent_x402::X402Error> {
        self.network = authorization.network.to_owned();
        self.scheme = authorization.scheme.to_owned();
        let entry = AuditEntry::new_x402_payment_authorized(
            self.tool,
            self.chain_id,
            self.leg.take().into_iter().collect(),
            authorization.network,
            authorization.scheme,
            PolicyDecision::Allow,
            &self.request_id,
        );
        match emit_value_audit_row_strict(self.profile, &self.profile_name, self.binding, entry) {
            Ok(()) => {
                self.gate_passed = true;
                Ok(())
            }
            Err(error) => {
                self.refusal = Some(error);
                Err(stellar_agent_x402::X402Error::TransmitGateRefused {
                    detail: "the x402_payment_authorized audit row was not written".to_owned(),
                })
            }
        }
    }

    /// The tool result for the gate's own refusal, carrying the wallet error's
    /// code, or `None` when the gate did not refuse.
    pub(super) fn refusal_result(&mut self) -> Option<CallToolResult> {
        self.refusal
            .take()
            .map(|error| business_error_result(error.code(), error.to_string()))
    }

    /// Writes the `x402_authorization_withheld` row for `failure` when the gate
    /// wrote the authorized row.
    ///
    /// The caller returns its primary error unchanged whatever happens here; a
    /// row that cannot be written is logged at `error` with its code.
    pub(super) fn record_withheld(&self, failure: X402Failure<'_>) {
        let Some(stage) = x402_withheld_stage(self.gate_passed, failure) else {
            return;
        };
        let entry = AuditEntry::new_x402_authorization_withheld(
            self.tool,
            self.chain_id,
            self.network.as_str(),
            self.scheme.as_str(),
            stage,
            self.request_id.as_str(),
        );
        if let Err(error) =
            emit_value_audit_row_strict(self.profile, &self.profile_name, self.binding, entry)
        {
            tracing::error!(
                tool = self.tool,
                event_kind = "x402_authorization_withheld",
                failure_stage = stage,
                code = %error.code(),
                error = %error,
                "x402: the withheld-authorization audit row was not written"
            );
        }
    }
}

/// Accounts for an external payment while its credential can still be withheld.
pub(super) fn record_x402_authorization(
    server: &WalletServer,
    tool: &str,
    value: &stellar_agent_core::policy::v1::ValueClass,
) -> Result<(), CallToolResult> {
    let unavailable = || {
        business_error_result(
            "policy.engine_required",
            "authorized payment accounting is unavailable",
        )
    };
    let descriptor = server.policy_descriptor(tool).ok_or_else(unavailable)?;
    stellar_agent_network::policy_state::record_authorized_window_state(
        server.policy_engine.as_ref(),
        &descriptor,
        &server.profile,
        &server.profile_name_for_approval(),
        value,
    )
    .map_err(|error| match error {
        stellar_agent_network::policy_state::WindowStoreError::PolicyDenied { reason } => {
            crate::tools::common::policy_denial_error_result(&reason)
        }
        _ => unavailable(),
    })
}

/// Returns a stable telemetry class string for an [`stellar_agent_x402::X402Error`].
///
/// Safe to log: no secret material.  Used in `tracing::warn!` calls to emit a
/// machine-readable error class without interpolating the full Display (which
/// may include user-supplied addresses in some variants).
fn classify_x402_error(err: &stellar_agent_x402::X402Error) -> &'static str {
    use stellar_agent_x402::X402Error;
    match err {
        X402Error::InvalidPaymentRequired { .. } => "invalid_payment_required",
        X402Error::UnsupportedScheme { .. } => "unsupported_scheme",
        X402Error::UnsupportedNetwork { .. } => "unsupported_network",
        X402Error::NetworkPassphraseMismatch { .. } => "network_passphrase_mismatch",
        X402Error::MainnetSigningForbidden { .. } => "mainnet_signing_forbidden",
        X402Error::InvalidAssetAddress { .. } => "invalid_asset_address",
        X402Error::FeesNotSponsored => "fees_not_sponsored",
        X402Error::AmountConversion { .. } => "amount_conversion",
        X402Error::AuthEntrySignFailed { .. } => "auth_entry_sign_failed",
        X402Error::RpcSimulateFailed { .. } => "rpc_simulate_failed",
        X402Error::ReceiptParseFailed { .. } => "receipt_parse_failed",
        X402Error::TransactionBuildFailed { .. } => "transaction_build_failed",
        X402Error::UnexpectedAuthEntries { .. } => "unexpected_auth_entries",
        X402Error::TransmitGateRefused { .. } => "transmit_gate_refused",
        _ => "x402_error",
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test helpers
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(any(test, feature = "test-helpers"))]
impl WalletServer {
    /// Calls `stellar_x402_create_payment` with the given args, bypassing the
    /// rmcp transport.
    ///
    /// Integration-test and testnet-acceptance entry point for handler-level
    /// checks.  The method wraps the private handler in a `Parameters` envelope
    /// so test code does not need to import rmcp internals directly.
    ///
    /// # Errors
    ///
    /// Propagates `rmcp::ErrorData` from the `dispatch_gate` preamble (e.g.
    /// chain_id mismatch, policy deny).  X402 semantic errors are returned as
    /// `Ok(CallToolResult)` with `is_error = Some(true)`.
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Feature gate
    ///
    /// Gated on the `test-helpers` feature or `#[cfg(test)]`.
    #[doc(hidden)]
    pub async fn call_stellar_x402_create_payment(
        &self,
        args: X402CreatePaymentArgs,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.stellar_x402_create_payment(Parameters(args)).await
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics and unwraps acceptable in unit tests"
    )]

    use super::*;

    // ── decode_payment_required_input ──────────────────────────────────────────

    fn sample_requirements_json() -> String {
        serde_json::json!({
            "scheme": "exact",
            "network": "stellar:testnet",
            "asset": "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA",
            "amount": "1000000",
            "payTo": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "maxTimeoutSeconds": 300,
            "extra": { "areFeesSponsored": true }
        })
        .to_string()
    }

    #[test]
    fn decode_raw_json_input() {
        let json_str = sample_requirements_json();
        let result = decode_payment_required_input(&json_str);
        assert!(result.is_ok(), "raw JSON must be accepted; got {result:?}");
        let req = result.unwrap();
        assert_eq!(req.scheme, "exact");
        assert_eq!(req.network, "stellar:testnet");
    }

    #[test]
    fn decode_base64_encoded_json_input() {
        use base64::Engine as _;
        let json_str = sample_requirements_json();
        let encoded = base64::engine::general_purpose::STANDARD.encode(json_str.as_bytes());
        let result = decode_payment_required_input(&encoded);
        assert!(
            result.is_ok(),
            "base64-encoded JSON must be accepted; got {result:?}"
        );
        let req = result.unwrap();
        assert_eq!(req.scheme, "exact");
    }

    #[test]
    fn decode_invalid_input_returns_error() {
        let result = decode_payment_required_input("not_json_not_base64!!!");
        assert!(
            matches!(
                result,
                Err(stellar_agent_x402::X402Error::InvalidPaymentRequired { .. })
            ),
            "invalid input must return InvalidPaymentRequired; got {result:?}"
        );
    }

    #[test]
    fn classify_error_covers_all_variants() {
        use stellar_agent_x402::X402Error;
        // All variants must return a non-empty, non-"x402_error" class name
        // (the catch-all is only for unknown future variants).
        let cases: &[X402Error] = &[
            X402Error::InvalidPaymentRequired {
                detail: "x".to_owned(),
            },
            X402Error::UnsupportedScheme {
                scheme: "y".to_owned(),
            },
            X402Error::UnsupportedNetwork {
                network: "z".to_owned(),
            },
            X402Error::NetworkPassphraseMismatch {
                network: "a".to_owned(),
                expected_passphrase: "b",
                profile_passphrase: "c".to_owned(),
            },
            X402Error::MainnetSigningForbidden {
                detail: "network.mainnet_write_forbidden".to_owned(),
            },
            X402Error::InvalidAssetAddress {
                detail: "d".to_owned(),
            },
            X402Error::FeesNotSponsored,
            X402Error::AmountConversion {
                detail: "e".to_owned(),
            },
            X402Error::RpcSimulateFailed {
                detail: "f".to_owned(),
            },
            X402Error::ReceiptParseFailed {
                detail: "g".to_owned(),
            },
            X402Error::TransactionBuildFailed {
                detail: "h".to_owned(),
            },
            X402Error::UnexpectedAuthEntries {
                detail: "i".to_owned(),
            },
            X402Error::TransmitGateRefused {
                detail: "j".to_owned(),
            },
        ];
        for err in cases {
            let class = classify_x402_error(err);
            assert!(!class.is_empty());
            assert_ne!(
                class, "x402_error",
                "variant {err:?} must have a specific class"
            );
        }
    }

    // ── x402_withheld_stage: one test per arm ──────────────────────────────────

    #[test]
    fn withheld_stage_is_none_before_the_gate_returned_ok() {
        use stellar_agent_x402::X402Error;
        let errors = [
            X402Error::RpcSimulateFailed {
                detail: "first simulate".to_owned(),
            },
            X402Error::TransactionBuildFailed {
                detail: "before the gate".to_owned(),
            },
            X402Error::TransmitGateRefused {
                detail: "the gate refused".to_owned(),
            },
        ];
        for err in &errors {
            assert_eq!(
                x402_withheld_stage(false, X402Failure::CreatePayment(err)),
                None
            );
        }
        assert_eq!(x402_withheld_stage(false, X402Failure::Encoding), None);
    }

    #[test]
    fn withheld_stage_names_an_rpc_simulate_error_after_the_gate_resimulation() {
        let err = stellar_agent_x402::X402Error::RpcSimulateFailed {
            detail: "re-simulate returned error".to_owned(),
        };
        assert_eq!(
            x402_withheld_stage(true, X402Failure::CreatePayment(&err)),
            Some("resimulation")
        );
    }

    #[test]
    fn withheld_stage_names_any_other_error_after_the_gate_response_processing() {
        use stellar_agent_x402::X402Error;
        let errors = [
            X402Error::TransactionBuildFailed {
                detail: "re-simulate transaction_data decode failed".to_owned(),
            },
            X402Error::AmountConversion {
                detail: "fee".to_owned(),
            },
        ];
        for err in &errors {
            assert_eq!(
                x402_withheld_stage(true, X402Failure::CreatePayment(err)),
                Some("response_processing")
            );
        }
    }

    #[test]
    fn withheld_stage_names_a_handler_encoding_failure_encoding() {
        assert_eq!(
            x402_withheld_stage(true, X402Failure::Encoding),
            Some("encoding")
        );
    }

    // ── Security regression: RequireApproval is fail-closed ─────────────────────

    use stellar_agent_core::policy::ToolDescriptor;
    use stellar_agent_core::policy::v1::{
        AccountIdentityView, AccountReservesView, CounterpartyCacheView, Sep10SessionView,
        Sep45SessionView,
    };
    use stellar_agent_core::policy::{
        ApprovalRequest, Decision, DenyReason, PolicyEngine, PolicyError,
    };
    use stellar_agent_core::profile::schema::Profile;

    struct RequireApprovalEngine;

    impl PolicyEngine for RequireApprovalEngine {
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
            Ok(Decision::RequireApproval(ApprovalRequest::new(
                "test-nonce".into(),
                120,
            )))
        }
    }

    struct DenyEngine;

    impl PolicyEngine for DenyEngine {
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
            Ok(Decision::Deny(DenyReason::NoMatchingRule))
        }
    }

    fn make_require_approval_server() -> crate::server::WalletServer {
        use std::sync::Arc;
        let profile = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
            .with_noop_engine()
            .build();
        // No audit chain key is seeded at this profile's coordinate: gate
        // verdicts (RequireApproval here) precede the audit pre-flight, so
        // this scenario must complete without one — the test's assertion on
        // the fail-closed approval error doubles as the ordering pin.
        let mut server = crate::server::WalletServer::new(profile)
            .expect("WalletServer::new must not fail in tests");
        server.policy_engine = Arc::new(RequireApprovalEngine);
        server
    }

    fn make_mainnet_server() -> crate::server::WalletServer {
        crate::server::WalletServer::new(
            Profile::builder_mainnet(
                "https://rpc.example.invalid",
                "svc",
                "acct",
                "n-svc",
                "n-acct",
            )
            .with_noop_engine()
            .build(),
        )
        .expect("WalletServer::new must not fail in tests")
    }

    /// A mainnet profile MUST refuse `stellar_x402_create_payment` structurally
    /// before any key access: the result is an `is_error` x402 envelope carrying
    /// the canonical `network.mainnet_write_forbidden` wire code, and it MUST NOT
    /// contain a `paymentSignature`.
    ///
    /// The keyring mock is intentionally NOT installed: reaching the keyring
    /// would surface a `keyring load failed` message instead, so this test also
    /// proves the refusal fires before key access.
    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn mainnet_profile_refuses_before_signing_no_signature_produced() {
        let server = make_mainnet_server();
        let args = X402CreatePaymentArgs {
            chain_id: "stellar:mainnet".to_owned(),
            payment_required: sample_requirements_json(),
            address: None,
        };
        let result = server
            .call_stellar_x402_create_payment(args)
            .await
            .expect("structural mainnet refusal is surfaced as Ok(is_error), not Err");
        let (code, message, text) = crate::tools::common::assert_business_envelope(&result);
        assert_eq!(
            code, "network.mainnet_write_forbidden",
            "mainnet refusal must carry the canonical wire code"
        );
        assert!(
            message.contains("network.mainnet_write_forbidden"),
            "message must carry the canonical wire code; got: {message}"
        );
        assert!(
            !text.contains("keyring") && !text.contains("unlock"),
            "refusal must fire before key access — envelope must not mention keyring/unlock: {text}"
        );
        assert!(
            !text.contains("\"paymentSignature\""),
            "no payment signature must be produced on mainnet; got: {text}"
        );
    }

    /// Security regression: a `RequireApproval` policy verdict on
    /// `stellar_x402_create_payment` must return fail-closed `ErrorData` with
    /// wire code `policy.approval_required_unsupported` and MUST NOT produce a
    /// signed payment.
    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn require_approval_verdict_is_fail_closed_no_signature_produced() {
        stellar_agent_test_support::keyring_mock::install().ok();
        let server = make_require_approval_server();
        let args = X402CreatePaymentArgs {
            chain_id: "stellar:testnet".to_owned(),
            payment_required: sample_requirements_json(),
            address: None,
        };
        let result = server.call_stellar_x402_create_payment(args).await;
        let result = result.expect(
            "RequireApproval must return Ok(is_error) envelope, not a protocol error or a signature",
        );
        let (code, message, text) = crate::tools::common::assert_business_envelope(&result);
        assert_eq!(
            code, "policy.approval_required_unsupported",
            "wire code must be policy.approval_required_unsupported"
        );
        assert!(
            message.contains("single-shot"),
            "error message must mention single-shot; got: {message}"
        );
        assert!(
            !text.contains("\"paymentSignature\"") && !text.contains("\"signature\""),
            "fail-closed approval refusal must not produce a signature; got: {text}"
        );
    }

    /// A policy denial precedes the audit pre-flight: with a denying engine
    /// AND an unminted audit chain key, the surfaced wire code is the policy
    /// denial — a denial authorizes no payment and needs no audit setup, so it
    /// must never be masked by `audit.chain_key_unavailable`.
    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn policy_denial_precedes_the_audit_preflight() {
        use std::sync::Arc;
        stellar_agent_test_support::keyring_mock::install().ok();
        let profile = Profile::builder_testnet(
            "svc-x402cp-denyfirst",
            "acct-x402cp-denyfirst",
            "n-svc",
            "n-acct",
        )
        .with_noop_engine()
        .build();
        let mut server =
            crate::server::WalletServer::new(profile).expect("WalletServer::new in tests");
        server.policy_engine = Arc::new(DenyEngine);
        let args = X402CreatePaymentArgs {
            chain_id: "stellar:testnet".to_owned(),
            payment_required: sample_requirements_json(),
            address: None,
        };
        let result = server
            .call_stellar_x402_create_payment(args)
            .await
            .expect("denial must be a business envelope, not a protocol error");
        let (code, _message, text) = crate::tools::common::assert_business_envelope(&result);
        assert_eq!(code, "policy.deny.no_matching_rule");
        assert!(
            !text.contains("\"paymentSignature\""),
            "no payment signature may be produced on a policy denial; got: {text}"
        );
    }
}
