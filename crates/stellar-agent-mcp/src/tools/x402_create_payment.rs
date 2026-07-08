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
    decode_payment_required_input, x402_error_to_tool_result, x402_value_leg,
};
use crate::tools::value_audit::emit_value_audit_row;

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

        use stellar_agent_network::keyring::signer_from_keyring;
        use stellar_agent_x402::exact::create_payment;
        use stellar_agent_x402::wire::encode_payment_signature;

        // Mainnet structural refusal — before any key access or signing.
        // This tool returns a payment authorization the MCP host broadcasts
        // externally; the submit-layer mainnet gate never fires because the
        // wallet does not submit. Refuse on a mainnet profile so no valid
        // mainnet payment signature is ever produced. Wire code:
        // network.mainnet_write_forbidden.
        if self.profile.chain_id.is_mainnet() {
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

        // ── Telemetry preamble (redaction) ───────────────────────────────────
        let args_value = json!({
            "chain_id": &args.chain_id,
            "payment_required_len": args.payment_required.len(),
        });

        // ── dispatch_gate_with_value: registry lookup + policy evaluation +
        // chain_id, sizing the value criteria against `value_leg` ────────────
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
        let signer_handle =
            match signer_from_keyring(&self.profile.mcp_signer_default, account).await {
                Ok(h) => h,
                Err(err) => {
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
        let rpc_url = self.profile.rpc_url.as_str();
        let profile_passphrase = self.profile.network_passphrase.as_str();

        let payer_address = account.to_owned();

        // ── Dispatch to stellar_agent_x402::create_payment ───────────────────
        let signer: Arc<dyn stellar_agent_network::signing::Signer + Send + Sync> =
            Arc::new(signer_handle);

        let payment_payload =
            match create_payment(&requirements, signer.as_ref(), rpc_url, profile_passphrase).await
            {
                Ok(p) => p,
                Err(ref err) => {
                    // Log error class without secret bleed (X402Error::Display is redaction-safe).
                    tracing::warn!(
                        error_class = %classify_x402_error(err),
                        "x402_create_payment: create_payment failed",
                    );
                    return Ok(x402_error_to_tool_result(err));
                }
            };

        // ── Encode PAYMENT-SIGNATURE ──────────────────────────────────────────
        let payment_signature = match encode_payment_signature(&payment_payload) {
            Ok(sig) => sig,
            Err(ref err) => return Ok(x402_error_to_tool_result(err)),
        };

        // ── Redact payer address for telemetry ────────────────────────────────
        let redacted_payer =
            stellar_agent_core::observability::redact_strkey_first5_last5(&payer_address);
        tracing::info!(
            payer = %redacted_payer,
            network = %requirements.network,
            "x402_create_payment: payment payload constructed",
        );

        // Non-fatal audit row at signature production. The wallet is the payer;
        // the host settles externally, so there is no on-chain submit — the row
        // records the authorized value, not a confirmed transaction.
        let request_id = uuid::Uuid::new_v4().to_string();
        let audit_entry = AuditEntry::new_x402_payment_authorized(
            "stellar_x402_create_payment",
            args.chain_id.as_str(),
            vec![audit_leg],
            requirements.network.as_str(),
            requirements.scheme.as_str(),
            PolicyDecision::Allow,
            &request_id,
        );
        emit_value_audit_row(
            &self.profile,
            &self.profile_name_for_approval(),
            audit_entry,
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
        let json_str = serde_json::to_string_pretty(&response).unwrap_or_else(|_| "{}".to_owned());
        Ok(CallToolResult::success(vec![Content::text(json_str)]))
    }
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

    // ── Security regression: RequireApproval is fail-closed ─────────────────────

    use stellar_agent_core::policy::ToolDescriptor;
    use stellar_agent_core::policy::v1::{
        AccountIdentityView, AccountReservesView, CounterpartyCacheView, Sep10SessionView,
        Sep45SessionView,
    };
    use stellar_agent_core::policy::{ApprovalRequest, Decision, PolicyEngine, PolicyError};
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

    fn make_require_approval_server() -> crate::server::WalletServer {
        use std::sync::Arc;
        let mut server = crate::server::WalletServer::new(
            Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
                .with_noop_engine()
                .build(),
        )
        .expect("WalletServer::new must not fail in tests");
        server.policy_engine = Arc::new(RequireApprovalEngine);
        server
    }

    fn make_mainnet_server() -> crate::server::WalletServer {
        crate::server::WalletServer::new(
            Profile::builder_mainnet("svc", "acct", "n-svc", "n-acct")
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
}
