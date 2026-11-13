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
//! - The payment requirements are validated in full before the dispatch gate,
//!   so invalid requirements never reach the spending window.
//! - One RPC client serves the payment. Its first request is the endpoint
//!   identity check, under the profile's `submit_timeout_seconds`.
//! - Before the signer is read, the cross-check rule decides from the
//!   transfer amount, in the asset's atomic units, and the profile's
//!   thresholds and oracle whether the payment needs the independent-RPC
//!   witness. When it does, a second client to the profile's
//!   `oracle_provider_url` simulates the same unsigned transfer before the
//!   payer signs, and a disagreement refuses.
//! - Signer is loaded from the platform keyring at call time; the keypair is
//!   never held in memory between calls.
//!
//! # Output
//!
//! Returns `{ paymentSignature, payer, asset, amount, payTo, network,
//! cross_check }`:
//!
//! - `paymentSignature` — standard-base64 `PAYMENT-SIGNATURE` header value.
//! - `payer` — payer address (G-strkey), redacted in telemetry.
//! - `asset` — SAC contract address (C-strkey).
//! - `amount` — atomic-unit amount string from `PaymentRequirements`.
//! - `payTo` — recipient address from `PaymentRequirements`.
//! - `network` — x402 CAIP-2 network string from `PaymentRequirements`.
//! - `cross_check`: the witness outcome, which is `passed` with the oracle and
//!   its ledger, `skipped` with the reason, or `not_required`.

use rmcp::{
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Content},
    schemars, serde, tool, tool_router,
};
use serde_json::json;
use stellar_agent_core::audit_log::{
    AuditEntry, AuditWriter, PolicyDecision, ValueLegRecord, audit_writer_refusal,
};
use stellar_agent_core::cross_check::CrossCheckValue;
use stellar_agent_core::policy::v1::ValueClass;
use stellar_agent_mcp_macros::mcp_tool_router;
use stellar_agent_network::cross_check::{CrossCheckWitness, SorobanCrossCheck};

use crate::server::WalletServer;
use crate::tools::common::{
    business_error_result, decode_payment_required_input, x402_canonical_asset,
    x402_error_to_tool_result, x402_value_leg,
};
use crate::tools::value_audit::{
    emit_anchored_value_audit_row_strict, emit_value_audit_row_strict,
};

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
/// - `chain_id`: the wallet's CAIP-2 chain identifier, `"stellar:testnet"`
///   or `"stellar:mainnet"`; validated against the active profile after the
///   payment requirements are validated.
/// - `address` — optional signer address (G-strkey); when provided must match
///   the active signer enrolled in the profile.
#[derive(serde::Deserialize, schemars::JsonSchema)]
#[serde(crate = "rmcp::serde")]
pub struct X402CreatePaymentArgs {
    /// Wallet-issued approval nonce from the queueing call's `data.approval` block.
    /// Supply it with `approval_attestation` when the policy requires approval, on either network.
    pub approval_nonce: Option<String>,
    /// URL-safe base64 without padding of the 32-byte operator attestation.
    /// Required alongside `approval_nonce` when the policy requires approval.
    pub approval_attestation: Option<String>,
    /// Base64-encoded `PAYMENT-REQUIRED` header value OR raw JSON
    /// `PaymentRequirements` object.
    ///
    /// The tool tries base64-decode + JSON-parse first; falls back to direct
    /// JSON-parse when base64 decoding fails or yields non-JSON bytes.
    pub payment_required: String,

    /// The wallet's CAIP-2 chain identifier: `"stellar:testnet"` or
    /// `"stellar:mainnet"`. The x402 requirement `network` spells mainnet
    /// `"stellar:pubnet"`; this argument does not.
    ///
    /// Validated against the active profile after the payment requirements:
    /// invalid requirements answer their own `x402.*` code first. A mismatch
    /// returns a JSON-RPC `ErrorData` from the `dispatch_gate` preamble.
    pub chain_id: String,

    /// Optional signer address (G-strkey).
    ///
    /// When provided must match the active signer enrolled in the profile.
    /// Omit to use the profile default signer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// Business id naming this value operation: 1 to 64 printable ASCII
    /// characters, no space. Required on `stellar:mainnet`, where a retry
    /// with the same id returns the stored operation instead of new work;
    /// on another chain it is validated and echoed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub business_id: Option<String>,
}

/// Prints every field but the attestation, which shows only whether it is
/// set: the attestation is the operator's approval credential.
impl std::fmt::Debug for X402CreatePaymentArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X402CreatePaymentArgs")
            .field("approval_nonce", &self.approval_nonce)
            .field(
                "approval_attestation",
                &crate::tools::common::AttestationPresence(&self.approval_attestation),
            )
            .field("payment_required", &self.payment_required)
            .field("chain_id", &self.chain_id)
            .field("address", &self.address)
            .field("business_id", &self.business_id)
            .finish()
    }
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
/// validate → build-SAC-transfer → simulate → cross-check witness →
/// sign-auth-entry → re-simulate → serialize flow, and returns the
/// standard-base64 `PAYMENT-SIGNATURE` value ready for the
/// `PAYMENT-SIGNATURE` HTTP header.
///
/// The wallet is the payment **payer**.  The MCP host is responsible for
/// the actual HTTP-402 request/retry cycle; this tool only produces the
/// signed payload.
///
/// Returns `{ paymentSignature, payer, asset, amount, payTo, network,
/// cross_check }` on success.  Errors return the standard business-error envelope
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
/// - `payment_required` is not valid base64+JSON or raw JSON `PaymentRequirements`.
/// - The requirements fail validation. It runs before the dispatch gate, the
///   audit pre-flight, and the signer load, and consumes no spending window:
///   - the `scheme` is not `"exact"`;
///   - the `network` is not `"stellar:pubnet"` or `"stellar:testnet"`, or
///     does not match the profile passphrase;
///   - the `asset` is not a C-strkey;
///   - `extra.areFeesSponsored` is not `true`;
///   - the `amount` is not a positive `i128`;
///   - the `payTo` is not a G-, C-, M-, or W-strkey;
///   - `maxTimeoutSeconds` is zero.
/// - The keyring entry for the signer cannot be loaded.
/// - A Soroban RPC simulation, its answer, the health read, or the ledger and
///   fee bounds fail.
/// - The auth-entry signing step fails.
///
/// The cross-check witness refuses with its own code before the payer signs.
/// Credential failures keep `network.rpc_credential_refused` or the oracle
/// credential read's keyring code (`auth.keyring_*`). Disagreement returns
/// `simulation.divergence`. Other failures to obtain the witness or build
/// the oracle client return `network.witness_unavailable`.
///
/// A `chain_id` that does not match the active profile returns a JSON-RPC
/// `ErrorData` from the dispatch gate. The endpoint identity refusals carry
/// their `network.*` code: `network.endpoint_network_mismatch`,
/// `network.endpoint_identity_unavailable`, `network.mainnet_write_forbidden`,
/// and `network.rpc_credential_refused` for an HTTP 401 or 403 answer. A
/// client that cannot be built refuses with `network.rpc_unreachable`, with
/// `network.rpc_credential_refused` for a stored provider credential the
/// wallet refuses or cannot send, or with the keyring code of the credential
/// read: `auth.keyring_not_found`, `auth.keyring_platform_error`,
/// `auth.keyring_interactive_session_required`, or
/// `auth.keyring_config_invalid`. The audit
/// refusals carry their `audit.*` code: the pre-flight before the signer load,
/// and the `x402_payment_authorized` row the transmit gate writes before the
/// signed authorization leaves the wallet.
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
                       validates, simulates, obtains the cross-check witness, signs the SAC \
                       transfer auth-entry, re-simulates, and returns { paymentSignature: string, \
                       payer: string, asset: string, amount: string, payTo: string, \
                       network: string, cross_check: object }. \
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

        use crate::tools::common::{
            DispatchOutcome, GatedApprovalKind, approval_required_indistinguishable,
            verify_attestation_subject_gate,
        };
        use crate::tools::x402_create_payment::{
            ApprovalView, X402ApprovalProof, X402ApprovalSpend, X402CheckedSigner,
            approval_response, presented_x402_terms_refusal, x402_address_mismatch,
            x402_approval_callback, x402_protocol_refusal,
        };
        use stellar_agent_network::keyring::enrolled_keyring_signer;
        use stellar_agent_x402::exact::{create_payment_with_pre_sign, validate_requirements};

        if self.context.chain_id.is_mainnet() {
            let guard = match self.mainnet_write_admission(
                stellar_agent_network::mainnet::MainnetConsumer::X402Create,
            ) {
                Ok(guard) => guard,
                Err(result) => return Ok(result),
            };
            #[cfg(feature = "mainnet-write")]
            return self.mainnet_x402_payment(args, guard).await;
            // Without mainnet writes the server holds no write context, so no
            // admission succeeds and the guard is never present here.
            #[cfg(not(feature = "mainnet-write"))]
            {
                let _ = (args, guard);
                return Ok(crate::tools::common::x402_mainnet_signing_forbidden_result());
            }
        }

        // ── Decode and validate payment_required FIRST ────────────────────────
        // The dispatch gate needs the value-carrying descriptor, which is
        // derived from this single decode: the gate runs before any signing
        // and after the decode it sizes. The requirements are validated in
        // full before the gate, so invalid requirements answer their own
        // `x402.*` code and never reach the spending window.
        let requirements = match decode_payment_required_input(&args.payment_required) {
            Ok(r) => r,
            Err(ref err) => return Ok(x402_error_to_tool_result(err)),
        };
        let complete_proof = args.approval_nonce.is_some() && args.approval_attestation.is_some();
        if complete_proof && let Some(result) = presented_x402_terms_refusal(self, &requirements) {
            return Ok(result);
        }
        let amount = match validate_requirements(
            &requirements,
            self.context.network_passphrase(),
            &self.context.rpc_url,
        ) {
            Ok(amount) => amount,
            Err(ref err) => return Ok(x402_error_to_tool_result(err)),
        };
        if let Err(result) = crate::tools::common::check_x402_payee_protocol(
            &requirements.pay_to,
            &self.profile,
            || self.context.primary_client(),
        )
        .await
        {
            return Ok(x402_protocol_refusal(self, result, complete_proof));
        }
        // Off mainnet a supplied id is validated here and echoed. A mainnet
        // call takes its own path and checks its id at its record lookup,
        // after every refusal a call without one gives.
        let business_id = match self.echoed_business_id(&args.chain_id, args.business_id.as_deref())
        {
            Ok(id) => id,
            Err(result) => return Ok(result),
        };

        // ── Build the value-carrying leg from the SAME decode ────────────────
        // The amount is the one the validator parsed from this immutable
        // requirements object, which `create_payment` validates again and
        // builds the transfer from.
        let value_leg = x402_value_leg(&requirements, amount);

        // Capture the gate-derived leg as an audit record before it moves into
        // the value descriptor, so the row carries exactly what the gate sized.
        let audit_leg = ValueLegRecord::from(&value_leg);
        let value_leg_for_record = value_leg.clone();

        // ── Telemetry preamble (redaction) ───────────────────────────────────
        let args_value = json!({
            "chain_id": &args.chain_id,
            "payment_required_len": args.payment_required.len(),
        });

        // The gate performs registry lookup, chain validation, and policy evaluation.
        // Value criteria use the supplied value_leg.
        // Approval requirements queue an intent or verify the presented proof.
        // Account-reserve and account-identity criteria fail closed without views.
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
        let audit_decision = dispatch_outcome.audit_decision();
        let (value_for_record, approval) = match &dispatch_outcome {
            DispatchOutcome::Allow(outcome) => (
                outcome
                    .value_effects
                    .clone()
                    .map_or(ValueClass::single(value_leg_for_record), ValueClass::Value),
                None,
            ),
            DispatchOutcome::RequireApproval(outcome) => (
                outcome
                    .value_effects
                    .clone()
                    .map_or(ValueClass::single(value_leg_for_record), ValueClass::Value),
                Some(outcome),
            ),
        };
        let mut approval_proof = None;
        if let Some(approval) = approval {
            let profile_name = self.profile_name_for_approval();
            let payer = self.profile.mcp_signer_default.account.as_str();
            if let Some(result) = x402_address_mismatch(args.address.as_deref(), payer) {
                return Ok(if complete_proof {
                    approval_required_indistinguishable(&profile_name)
                } else if args.approval_nonce.is_none() && args.approval_attestation.is_none() {
                    crate::tools::common::single_shot_require_approval_error()
                } else {
                    result
                });
            }
            let root = match stellar_agent_x402::exact::payment_root(&requirements, payer) {
                Ok(root) => root,
                Err(error) => return Ok(x402_error_to_tool_result(&error)),
            };
            let digest = match stellar_agent_x402::exact::intent_digest(&requirements, payer) {
                Ok(digest) => digest,
                Err(error) => return Ok(x402_error_to_tool_result(&error)),
            };
            if args.approval_nonce.is_none() && args.approval_attestation.is_none() {
                let entry = match self.write_x402_pending_approval(&root, None, approval, || {
                    self.clock.now_unix_ms().map_err(|error| {
                        stellar_agent_core::WalletError::WalletState(
                            stellar_agent_core::error::WalletStateError::clock_error(&error),
                        )
                    })
                }) {
                    Ok(entry) => entry,
                    Err(error) => return Ok(business_error_result(error.code(), error.message())),
                };
                return Ok(approval_response(&ApprovalView {
                    entry: &entry,
                    profile: &profile_name,
                    chain_id: &args.chain_id,
                    endpoint_host: None,
                    signer: payer,
                    requirements: &requirements,
                    business_id: business_id.as_ref(),
                }));
            }
            let subject = stellar_agent_core::approval::subject::approval_subject_x402(&digest);
            if let Err(result) = verify_attestation_subject_gate(
                self,
                &dispatch_outcome,
                GatedApprovalKind::X402.expectation(subject),
                args.approval_nonce.as_deref(),
                args.approval_attestation.as_deref(),
                "stellar_x402_create_payment",
            )
            .await
            {
                return Ok(result);
            }
            if let (Some(nonce), Some(attestation)) =
                (&args.approval_nonce, &args.approval_attestation)
            {
                approval_proof = Some(X402ApprovalProof {
                    nonce: nonce.clone(),
                    attestation: attestation.clone(),
                    expected_subject: subject,
                    governing_ttl_ms: approval.governing_ttl_ms,
                });
            }
        }
        let approval_refusal = std::sync::Mutex::new(None);

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
        if let Some(result) = x402_address_mismatch(args.address.as_deref(), account) {
            return Ok(result);
        }

        // ── Cross-check requirement, before the signer is read ───────────────
        // The value is the transfer amount in the asset's atomic units, under
        // the asset's canonical contract identity. A required witness builds
        // its oracle client here, without a request.
        // A construction failure refuses before the signer entry is read.
        let asset = match x402_canonical_asset(&requirements) {
            Ok(asset) => asset,
            Err(refusal) => return Ok(refusal),
        };
        let cross_check = match SorobanCrossCheck::prepare(
            &self.profile,
            &self.context,
            CrossCheckValue::Amount {
                asset: &asset,
                base_units: amount,
            },
            "stellar_x402_create_payment",
        ) {
            Ok(cross_check) => cross_check,
            Err(err) => return Ok(crate::tools::common::endpoint_refusal_result(&err)),
        };

        // ── Load signer from keyring ──────────────────────────────────────────
        let signer_result = if approval_proof.is_some() {
            x402_mainnet_signing_handle(&self.profile.mcp_signer_default, account)
        } else {
            enrolled_keyring_signer(
                &self.profile_name_for_approval(),
                &self.profile,
                account,
                self.established_owner().as_ref(),
            )
            .await
        };
        let signer_handle = match signer_result {
            Ok(h) => h,
            Err(err) => {
                if matches!(&err, stellar_agent_core::error::WalletError::Auth(_)) {
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

        // ── One RPC client for the payment, from the active profile ──────────
        // The URL is operator-controlled, never facilitator-supplied. Every
        // request of the payment goes to this client, and `create_payment`
        // makes the endpoint identity check its first request. The witness
        // requests go to the oracle client prepared above.
        let client = match self.context.primary_client() {
            Ok(client) => client,
            Err(err) => return Ok(crate::tools::common::endpoint_refusal_result(&err)),
        };
        let profile_passphrase = self.context.network_passphrase();

        let payer_address = account.to_owned();

        // ── Dispatch to stellar_agent_x402::create_payment ───────────────────
        let signer: Arc<dyn stellar_agent_network::signing::Signer + Send + Sync> =
            Arc::new(X402CheckedSigner {
                inner: signer_handle,
                server: self,
                proof: &approval_proof,
                refusal: &approval_refusal,
            });

        // Shared-window admission precedes signing and the signed RPC
        // re-simulation. A failure after it, an endpoint identity refusal
        // included, keeps the admitted spend.
        if let Err(refusal) = crate::tools::x402_create_payment::record_x402_authorization(
            self,
            "stellar_x402_create_payment",
            &value_for_record,
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
        if let Some(proof) = &approval_proof {
            audit = audit
                .with_decision(audit_decision)
                .with_approval_spend(X402ApprovalSpend {
                    server: self,
                    nonce: proof.nonce.clone(),
                    governing_ttl_ms: proof.governing_ttl_ms,
                });
        }
        // The identity check runs under the profile's submit timeout, resolved
        // here; the requirement's `maxTimeoutSeconds` bounds the signed
        // authorization, never this deadline. Admission above stays when the
        // check refuses.
        let identity_deadline =
            tokio::time::Instant::now() + crate::tools::common::submit_timeout(&self.profile);
        let created = create_payment_with_pre_sign(
            &requirements,
            signer.as_ref(),
            &client,
            &cross_check,
            profile_passphrase,
            identity_deadline,
            x402_approval_callback(self, &approval_proof, &approval_refusal),
            |authorization| audit.before_transmit(authorization),
        )
        .await;
        let created = match created {
            Ok(created) => created,
            Err(ref err) => {
                // Log error class without secret bleed (X402Error::Display is redaction-safe).
                tracing::warn!(
                    error_class = %classify_x402_error(err),
                    "x402_create_payment: create_payment failed",
                );
                if let Some(refusal) = approval_refusal
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take()
                {
                    return Ok(refusal);
                }
                if let Some(refusal) = audit.refusal_result() {
                    return Ok(refusal);
                }
                if let stellar_agent_x402::X402Error::EndpointIdentity(refusal) = err {
                    return Ok(crate::tools::common::endpoint_refusal_result(refusal));
                }
                // A cross-check refusal precedes the transmit gate, so no row
                // is written; the fallback below carries its own code and
                // text, as `X402Error::CrossCheck` answers its wallet error's.
                audit.record_withheld(X402Failure::CreatePayment(err));
                return Ok(x402_error_to_tool_result(err));
            }
        };

        match payment_response(&created, &payer_address, business_id.as_ref()) {
            Ok(response) => Ok(response),
            Err(error) => {
                audit.record_withheld(X402Failure::Encoding);
                Ok(x402_error_to_tool_result(&error))
            }
        }
    }
}

#[cfg(feature = "mainnet-write")]
impl WalletServer {
    async fn mainnet_x402_payment(
        &self,
        args: X402CreatePaymentArgs,
        guard: crate::server::MainnetWriteGuard<'_>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        use crate::tools::common::{DispatchOutcome, approval_required_indistinguishable};
        use stellar_agent_core::approval::subject::approval_subject_x402;
        use stellar_agent_network::mainnet::authority::{AuthorityRefusal, MainnetAuthority};
        use stellar_agent_x402::exact::{
            X402MainnetProofs, create_payment_authorized, intent_digest, payment_root,
            validate_requirements_for_payment,
        };
        let profile = guard.context.profile();
        let name = guard.context.profile_name();
        let requirements = match decode_payment_required_input(&args.payment_required) {
            Ok(requirements) => requirements,
            Err(error) => return Ok(x402_error_to_tool_result(&error)),
        };
        let amount = match validate_requirements_for_payment(
            &requirements,
            guard.context.network_passphrase(),
        ) {
            Ok(amount) => amount,
            Err(error) => return Ok(x402_error_to_tool_result(&error)),
        };
        if let Err(result) =
            crate::tools::common::check_x402_payee_protocol(&requirements.pay_to, profile, || {
                guard.context.primary_client()
            })
            .await
        {
            return Ok(result);
        }
        stellar_agent_core::profile::caip2::validate_chain_id_matches_profile(
            &args.chain_id,
            profile,
        )
        .map_err(|error| rmcp::ErrorData::invalid_params(error.to_string(), None))?;
        let call_two = match (&args.approval_nonce, &args.approval_attestation) {
            (None, None) => false,
            (Some(_), Some(_)) => true,
            _ => return Ok(approval_required_indistinguishable(name)),
        };
        if call_two && let Err(result) = self.verify_mainnet_freshness(&guard) {
            return Ok(result);
        }
        let signer = match self.mainnet_enrolled_signer(&guard) {
            Ok(signer) => signer,
            Err(error) => return Ok(crate::tools::common::endpoint_refusal_result(&error)),
        };
        let payer = stellar_strkey::ed25519::PublicKey(signer.public_key())
            .to_string()
            .as_str()
            .to_owned();
        if args
            .address
            .as_ref()
            .is_some_and(|address| address != &payer)
        {
            let error = stellar_agent_x402::X402Error::InvalidPaymentRequired {
                detail: "requested address does not match the enrolled signer".to_owned(),
            };
            return Ok(x402_error_to_tool_result(&error));
        }
        let root = match payment_root(&requirements, &payer) {
            Ok(root) => root,
            Err(error) => return Ok(x402_error_to_tool_result(&error)),
        };
        let digest = match intent_digest(&requirements, &payer) {
            Ok(digest) => digest,
            Err(error) => return Ok(x402_error_to_tool_result(&error)),
        };
        // The payment names its operation; a retained one answers here with
        // its stored state, and an unknown id opens its record.
        let entry = match self.x402_entry(
            &args.chain_id,
            args.business_id.as_deref(),
            stellar_agent_network::policy_state::OperationTool::X402CreatePayment,
            stellar_agent_network::policy_state::OperationKind::X402Payment,
            digest,
            stellar_agent_network::policy_state::X402Intent {
                network: requirements.network.clone(),
                asset: requirements.asset.clone(),
                payer: payer.clone(),
                pay_to: requirements.pay_to.clone(),
                amount: requirements.amount.clone(),
            },
        ) {
            Ok(entry) => entry,
            Err(result) => return Ok(result),
        };
        let business_id = entry.as_ref().map(|handle| handle.business_id().clone());
        let value = ValueClass::single(x402_value_leg(&requirements, amount));
        let audit_leg = ValueLegRecord::from(&x402_value_leg(&requirements, amount));
        let dispatch = match self
            .dispatch_preparation(
                "stellar_x402_create_payment",
                &json!({"chain_id": args.chain_id}),
                &args.chain_id,
                value,
                stellar_agent_core::mainnet::decision::EvaluationScope::Classic,
            )
            .await
        {
            Ok(outcome) => outcome,
            Err(error) => return error.into_result(),
        };
        // An `Allow` without a proof pays in this call under policy
        // authority. An approval requirement without a proof writes the
        // pending approval and returns it. A proof verifies through the gate.
        let mut witness: Option<stellar_agent_core::approval::witness::ApprovalWitness> = None;
        let authority = match crate::tools::common::mainnet_authority(
            self,
            &dispatch,
            crate::tools::common::GatedApprovalKind::X402
                .expectation(approval_subject_x402(&digest)),
            &crate::tools::common::SuppliedProof {
                nonce: args.approval_nonce.clone(),
                attestation: args.approval_attestation.clone(),
            },
            "stellar_x402_create_payment",
            &mut witness,
        )
        .await
        {
            Ok(authority) => authority,
            Err(AuthorityRefusal::ApprovalRequired { .. }) => {
                let DispatchOutcome::RequireApproval(approval) = &dispatch else {
                    return Ok(approval_required_indistinguishable(name));
                };
                let entry = self.write_x402_pending_approval(
                    &root,
                    None,
                    approval,
                    stellar_agent_network::mainnet::clock::now_ms,
                );
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(error) => {
                        return Ok(business_error_result(error.code(), error.message()));
                    }
                };
                return Ok(approval_response(&ApprovalView {
                    entry: &entry,
                    profile: name,
                    chain_id: &args.chain_id,
                    endpoint_host: Some(guard.enablement.endpoint_host()),
                    signer: &payer,
                    requirements: &requirements,
                    business_id: business_id.as_ref(),
                }));
            }
            Err(refusal) => {
                return Ok(crate::tools::common::authority_refusal_result(
                    self, refusal,
                ));
            }
        };
        // Policy authority pays in this call, so the startup proofs are
        // checked here, before any preparation.
        if matches!(authority, MainnetAuthority::Policy(_))
            && let Err(result) = self.verify_mainnet_freshness(&guard)
        {
            return Ok(result);
        }
        let readiness =
            match stellar_agent_network::mainnet::audit_readiness::audit_readiness(profile, name) {
                Ok(readiness) => readiness,
                Err(error) => return Ok(crate::tools::common::endpoint_refusal_result(&error)),
            };
        let handle = match x402_mainnet_signing_handle(signer.seed_entry(), &payer) {
            Ok(handle) => handle,
            Err(error) => return Ok(crate::tools::common::endpoint_refusal_result(&error)),
        };
        let store = self.window_store.clone();
        let asset = match x402_canonical_asset(&requirements) {
            Ok(asset) => asset,
            Err(result) => return Ok(result),
        };
        let mut audit = X402AuthorizationAudit::new(
            self,
            "stellar_x402_create_payment",
            &args.chain_id,
            audit_leg,
        )
        .with_decision(dispatch.audit_decision())
        .with_provenance(
            dispatch
                .mainnet_decision()
                .map(stellar_agent_core::mainnet::decision::MainnetDecision::provenance),
        );
        let steps = crate::tools::business_entry::X402Steps::new(self, entry);
        let proofs = X402MainnetProofs::new(
            guard.context,
            guard.policy,
            guard.enablement,
            &authority,
            &signer,
            &handle,
            readiness,
            &store,
        );
        let proofs = match steps.link() {
            Some(link) => proofs.with_operation(link),
            None => proofs,
        };
        let created = create_payment_authorized(
            &requirements,
            stellar_agent_network::mainnet::MainnetConsumer::X402Create,
            proofs,
            CrossCheckValue::Amount {
                asset: &asset,
                base_units: amount,
            },
            tokio::time::Instant::now() + crate::tools::common::submit_timeout(profile),
            |authorization| audit.before_transmit(authorization),
            steps.hooks(),
        )
        .await;
        let created = match created {
            Ok(created) => created,
            Err(error) => {
                steps.failed(error.wire_code());
                if let Some(result) = steps.refusal_result() {
                    return Ok(result);
                }
                if let Some(error) = audit.refusal.take() {
                    return Ok(business_error_result(
                        error.code(),
                        format!("payment withheld at intent transmit gate: {error}"),
                    ));
                }
                let withheld = if audit.gate_passed {
                    "after intent authorization"
                } else {
                    "before signed transmission"
                };
                audit.record_withheld(X402Failure::CreatePayment(&error));
                return Ok(mainnet_x402_error(
                    &error,
                    withheld,
                    audit.transmitted_ledger(),
                ));
            }
        };
        let id = created.authorization.id();
        let withhold = |failure: ReleaseFailure| {
            let decision = release_decision(failure);
            steps.withheld();
            if let Some(stage) = decision.cleanup {
                crate::tools::submission_record::cleanup_authorization(
                    &store,
                    guard.context,
                    id,
                    stage,
                );
            }
            audit.record_withheld(decision.withheld);
            decision.withheld_at
        };
        let response = match payment_response(&created.payment, &payer, business_id.as_ref()) {
            Ok(response) => response,
            Err(error) => {
                let withheld = withhold(ReleaseFailure::Encoding);
                return Ok(mainnet_x402_error(
                    &error,
                    withheld,
                    audit.transmitted_ledger(),
                ));
            }
        };
        let envelope = &created.payment.payload.payload.transaction;
        if let Err(error) = stellar_agent_network::mainnet::resolve::consume_soroban_submit(
            guard.context,
            created.authorization,
            envelope,
            &store,
        ) {
            let withheld = withhold(ReleaseFailure::ReleaseConsume);
            let error = stellar_agent_x402::X402Error::MainnetAuthorization(error);
            return Ok(mainnet_x402_error(
                &error,
                withheld,
                audit.transmitted_ledger(),
            ));
        }
        // Only an approval is spent; policy authority holds no approval.
        if let MainnetAuthority::Approval(approval) = &authority {
            let digest = stellar_agent_core::hex::encode(
                &stellar_agent_core::approval::subject::approval_subject_classic(envelope),
            );
            let terminal = self.x402_approval_store().and_then(|mut pending| {
                pending
                    .consume(
                        approval.nonce(),
                        &digest,
                        stellar_agent_core::approval::ConsumedOutcome::Unknown,
                    )
                    .map_err(|error| stellar_agent_core::approval::attest::record_error(&error))
            });
            if let Err(error) = require_terminal_consumption(terminal) {
                let withheld = withhold(ReleaseFailure::TerminalApproval);
                return Ok(terminal_approval_error(
                    &error,
                    withheld,
                    audit.transmitted_ledger(),
                ));
            }
        }
        steps.released();
        Ok(response)
    }
}

impl WalletServer {
    /// Opens the locked approval store for this profile.
    pub(super) fn x402_approval_store(
        &self,
    ) -> Result<stellar_agent_core::approval::PendingApprovalStore, stellar_agent_core::WalletError>
    {
        let directory = self.resolve_approval_dir().map_err(|error| {
            stellar_agent_core::error::ValidationError::ConfigInvalid {
                component: "approval",
                reason: error.to_string(),
            }
        })?;
        stellar_agent_core::approval::open_with_retry(
            &directory.join(format!("{}.toml", self.profile_name_for_approval())),
            stellar_agent_core::approval::DEFAULT_RETRY_ATTEMPTS,
            stellar_agent_core::approval::DEFAULT_RETRY_BACKOFF,
        )
        .map_err(|error| stellar_agent_core::approval::attest::record_error(&error))
    }
}

impl WalletServer {
    /// Writes the pending approval of an x402 payment intent.
    pub(super) fn write_x402_pending_approval(
        &self,
        root: &stellar_xdr::SorobanAuthorizedInvocation,
        home_domain: Option<String>,
        approval: &crate::tools::common::ApprovalOutcome,
        now_ms: impl FnOnce() -> Result<u64, stellar_agent_core::WalletError>,
    ) -> Result<stellar_agent_core::approval::PendingApproval, stellar_agent_core::WalletError>
    {
        use sha2::{Digest, Sha256};
        use stellar_agent_core::approval::{
            PendingApproval, attest::record_error, user_id::process_uid_for_attestation,
        };
        let network_id = Sha256::digest(self.context.network_passphrase().as_bytes()).into();
        let uid = process_uid_for_attestation().map_err(|error| record_error(&error))?;
        let entry = PendingApproval::new_x402_pending(
            &network_id,
            root,
            home_domain,
            uid,
            approval.governing_ttl_ms,
        )
        .map_err(|error| record_error(&error))?
        .with_policy_request(&approval.request);
        let mut store = self.x402_approval_store()?;
        let now = now_ms()?;
        store
            .insert(entry.clone(), now)
            .map_err(|error| record_error(&error))?;
        Ok(entry)
    }
}

/// Returns the live attested entry without modifying it.
fn live_attested_x402_entry(
    store: &stellar_agent_core::approval::PendingApprovalStore,
    nonce: &str,
    now_ms: u64,
    governing_ttl_ms: u64,
    profile_name: &str,
) -> Result<stellar_agent_core::approval::PendingApproval, CallToolResult> {
    use crate::tools::common::{
        approval_consumed_error, approval_rejected_error, approval_required_indistinguishable,
    };
    use stellar_agent_core::approval::ApprovalKind;
    let required = || approval_required_indistinguishable(profile_name);
    let entry = store.get(nonce).ok_or_else(required)?;
    let expired = now_ms < entry.created_at_unix_ms
        || entry.is_expired(now_ms)
        || entry.created_at_unix_ms.saturating_add(governing_ttl_ms) <= now_ms;
    match &entry.kind {
        ApprovalKind::Consumed { .. } => Err(approval_consumed_error()),
        ApprovalKind::Rejected { .. } if !expired => Err(approval_rejected_error()),
        _ if expired => Err(required()),
        ApprovalKind::X402Payment { .. } if entry.attestation_blob_b64.is_some() => {
            Ok(entry.clone())
        }
        _ => Err(required()),
    }
}

/// Spends one live approval before its signed authorization leaves the wallet.
pub(super) fn spend_x402_approval(
    server: &WalletServer,
    nonce: &str,
    governing_ttl_ms: u64,
    signed_entries_sha256: &[u8; 32],
) -> Result<(), CallToolResult> {
    let profile = server.profile_name_for_approval();
    let required = || crate::tools::common::approval_required_indistinguishable(&profile);
    let mut store = server.x402_approval_store().map_err(|_| required())?;
    let now = server.clock.now_unix_ms().map_err(|_| required())?;
    live_attested_x402_entry(&store, nonce, now, governing_ttl_ms, &profile)?;
    let digest = stellar_agent_core::hex::encode(signed_entries_sha256);
    match store.consume(
        nonce,
        &digest,
        stellar_agent_core::approval::ConsumedOutcome::Unknown,
    ) {
        Ok(true) => Ok(()),
        _ => Err(required()),
    }
}

#[cfg(test)]
fn x402_crash_boundary(boundary: &str) {
    if std::env::var("X402_CRASH_AFTER").as_deref() == Ok(boundary) {
        std::process::exit(73);
    }
}

pub(super) struct X402ApprovalSpend<'a> {
    pub(super) server: &'a WalletServer,
    pub(super) nonce: String,
    pub(super) governing_ttl_ms: u64,
}

/// The exact proof revalidated before signing.
#[derive(Clone)]
pub(super) struct X402ApprovalProof {
    pub(super) nonce: String,
    pub(super) attestation: String,
    pub(super) expected_subject: [u8; 32],
    pub(super) governing_ttl_ms: u64,
}

#[cfg(test)]
thread_local! {
    static PRE_SIGN_CHECKS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static TRANSMIT_GATE_ENTRIES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(super) fn pre_sign_checks_on_this_thread() -> u64 {
    PRE_SIGN_CHECKS.with(std::cell::Cell::get)
}

#[cfg(test)]
pub(super) fn transmit_gate_entries_on_this_thread() -> u64 {
    TRANSMIT_GATE_ENTRIES.with(std::cell::Cell::get)
}

/// Verifies consent after all key reads and retains the store through signing.
fn x402_pre_sign_guard(
    server: &WalletServer,
    proof: &X402ApprovalProof,
) -> Result<stellar_agent_core::approval::PendingApprovalStore, CallToolResult> {
    use base64::Engine as _;
    use stellar_agent_core::approval::{ApprovalKind, AttestationBinding, verify_attestation};
    let profile = server.profile_name_for_approval();
    let required = || crate::tools::common::approval_required_indistinguishable(&profile);
    let store = server.x402_approval_store().map_err(|_| required())?;
    let key =
        crate::tools::common::load_attestation_key(&server.profile).map_err(|_| required())?;
    let now = server.clock.now_unix_ms().map_err(|_| required())?;
    let entry =
        live_attested_x402_entry(&store, &proof.nonce, now, proof.governing_ttl_ms, &profile)?;
    let ApprovalKind::X402Payment {
        intent_digest,
        root_invocation_xdr,
        home_domain,
        ..
    } = &entry.kind
    else {
        return Err(required());
    };
    let subject = stellar_agent_core::approval::subject::verified_x402_subject(
        intent_digest,
        root_invocation_xdr,
        home_domain.as_deref(),
        server.context.network_passphrase(),
    )
    .map_err(|_| required())?;
    if subject != proof.expected_subject {
        return Err(required());
    }
    let bytes: [u8; 32] = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&proof.attestation)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(required)?;
    let scope = entry.attestation_scope().ok_or_else(required)?;
    if !verify_attestation(
        &key,
        &AttestationBinding::new(&profile, server.context.chain_id.caip2_str()),
        &proof.nonce,
        &proof.expected_subject,
        &entry.process_uid,
        &scope,
        &bytes,
    ) {
        return Err(required());
    }
    Ok(store)
}

/// Revalidates the proof after payment preparation without spending it.
pub(super) fn x402_pre_sign_check(
    server: &WalletServer,
    proof: &X402ApprovalProof,
) -> Result<(), CallToolResult> {
    #[cfg(test)]
    PRE_SIGN_CHECKS.with(|count| count.set(count.get() + 1));
    x402_pre_sign_guard(server, proof).map(|_| ())
}

/// Retains the exact approval proof through the payer's final key read.
pub(super) struct X402CheckedSigner<'a> {
    pub(super) inner: stellar_agent_network::keyring::KeyringSignHandle,
    pub(super) server: &'a WalletServer,
    pub(super) proof: &'a Option<X402ApprovalProof>,
    pub(super) refusal: &'a std::sync::Mutex<Option<CallToolResult>>,
}

#[async_trait::async_trait]
impl stellar_agent_network::signing::Signer for X402CheckedSigner<'_> {
    async fn public_key(
        &self,
    ) -> Result<stellar_strkey::ed25519::PublicKey, stellar_agent_core::WalletError> {
        Ok(self.inner.public_key())
    }

    async fn sign_tx_payload(
        &self,
        payload: &stellar_agent_network::signing::TxSigningPayload,
    ) -> Result<[u8; 64], stellar_agent_core::WalletError> {
        self.inner.sign_tx_payload(payload).await
    }

    async fn sign_auth_digest(
        &self,
        payload: &stellar_agent_network::signing::SmartAccountAuthDigest,
    ) -> Result<[u8; 64], stellar_agent_core::WalletError> {
        self.inner.sign_auth_digest(payload).await
    }

    async fn sign_message(
        &self,
        payload: &stellar_agent_network::signing::MessagePayload,
    ) -> Result<[u8; 64], stellar_agent_core::WalletError> {
        self.inner.sign_message(payload).await
    }

    async fn sign_webauthn_assertion(
        &self,
        payload: &stellar_agent_network::signing::SmartAccountAuthDigest,
        id: &[u8],
    ) -> Result<stellar_agent_network::signing::WebAuthnAssertion, stellar_agent_core::WalletError>
    {
        self.inner.sign_webauthn_assertion(payload, id).await
    }

    async fn sign_soroban_address_auth_payload(
        &self,
        payload: &stellar_agent_network::signing::SorobanAuthPayload,
    ) -> Result<[u8; 64], stellar_agent_core::WalletError> {
        let Some(proof) = self.proof else {
            return self.inner.sign_soroban_address_auth_payload(payload).await;
        };
        // Approval preparation precedes both enrollment and signing key reads.
        let name = self.server.profile_name_for_approval();
        let profile = self.server.profile.clone();
        let payer = self.inner.public_key().to_string().to_string();
        let owner = self.server.established_owner();
        let signer = tokio::task::spawn_blocking(move || {
            tokio::runtime::Handle::current().block_on(
                stellar_agent_network::keyring::enrolled_keyring_signer(
                    &name,
                    &profile,
                    &payer,
                    owner.as_ref(),
                ),
            )
        })
        .await
        .map_err(
            |_| stellar_agent_core::error::InternalError::UnexpectedState {
                detail: "the x402 signer load does not complete".into(),
            },
        )??;
        signer
            .sign_soroban_address_auth_payload_checked(payload, || {
                x402_pre_sign_guard(self.server, proof).map_err(|result| {
                    *self
                        .refusal
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(result);
                    stellar_agent_core::WalletError::Approval(
                        stellar_agent_core::error::ApprovalFailure::AttestationInvalid {
                            detail: "the x402 approval is not valid at signing".to_owned(),
                        },
                    )
                })
            })
            .await
    }
}

/// Builds the preparation callback only for an approved payment.
pub(super) fn x402_approval_callback<'a>(
    server: &'a WalletServer,
    proof: &'a Option<X402ApprovalProof>,
    refusal: &'a std::sync::Mutex<Option<CallToolResult>>,
) -> Option<stellar_agent_x402::exact::BeforePayerSign<'a>> {
    proof.as_ref().map(|proof| {
        Box::new(move || {
            x402_pre_sign_check(server, proof).map_err(|result| {
                *refusal
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(result);
                stellar_agent_x402::X402Error::TransmitGateRefused {
                    detail: "the x402 approval is not valid at signing".to_owned(),
                }
            })
        }) as stellar_agent_x402::exact::BeforePayerSign<'a>
    })
}

/// Refuses invalid payment terms before ordinary non-term validation.
pub(super) fn presented_x402_terms_refusal(
    server: &WalletServer,
    requirements: &stellar_agent_x402::wire::PaymentRequirements,
) -> Option<CallToolResult> {
    let mut terms = requirements.clone();
    terms.scheme = "exact".to_owned();
    terms.extra = json!({"areFeesSponsored": true});
    terms.max_timeout_seconds = terms.max_timeout_seconds.max(1);
    stellar_agent_x402::exact::validate_requirements_for_payment(
        &terms,
        server.context.network_passphrase(),
    )
    .err()
    .map(|_| {
        crate::tools::common::approval_required_indistinguishable(
            &server.profile_name_for_approval(),
        )
    })
}

/// Maps unsupported W protocols uniformly when a complete proof is present.
pub(super) fn x402_protocol_refusal(
    server: &WalletServer,
    result: CallToolResult,
    complete_proof: bool,
) -> CallToolResult {
    let unsupported = result
        .content
        .iter()
        .filter_map(|content| content.as_text())
        .filter_map(|text| serde_json::from_str::<serde_json::Value>(&text.text).ok())
        .any(|value| value["error"]["code"] == "x402.muxed_contract_protocol_unsupported");
    if complete_proof && unsupported {
        crate::tools::common::approval_required_indistinguishable(
            &server.profile_name_for_approval(),
        )
    } else {
        result
    }
}

pub(super) fn x402_address_mismatch(
    address: Option<&str>,
    account: &str,
) -> Option<CallToolResult> {
    address.filter(|address| *address != account).map(|_| {
        x402_error_to_tool_result(&stellar_agent_x402::X402Error::InvalidPaymentRequired {
            detail: format!("the address argument does not match the profile signer {account}"),
        })
    })
}

/// The approval-required view of a preparation call.
pub(super) struct ApprovalView<'a> {
    pub(super) entry: &'a stellar_agent_core::approval::PendingApproval,
    pub(super) profile: &'a str,
    pub(super) chain_id: &'a str,
    pub(super) endpoint_host: Option<&'a str>,
    pub(super) signer: &'a str,
    pub(super) requirements: &'a stellar_agent_x402::wire::PaymentRequirements,
    /// The business id that names the payment's operation.
    pub(super) business_id: Option<&'a stellar_agent_network::policy_state::BusinessId>,
}

/// The preparation call's result: the success envelope whose `data.approval`
/// names the pending approval, as the classic preparation tools return it.
/// It adds the enabled endpoint host, the enrolled signer and the approval
/// instructions. `data.business_id` names the operation. It carries no
/// payment payload.
pub(super) fn approval_response(view: &ApprovalView<'_>) -> CallToolResult {
    let mut approval = json!({
        "approval_nonce": view.entry.approval_nonce,
        "profile": view.profile,
        "chain_id": view.chain_id,
        "expires_at_unix_ms": view.entry.expires_at_unix_ms,
        "reason": view.entry.reason,
        "signer": view.signer,
        "summary": {
            "payTo": view.requirements.pay_to,
            "amount": view.requirements.amount,
            "asset": view.requirements.asset,
        },
        "instructions": format!(
            "Run {} in a terminal, then repeat this call with approval_nonce and \
             approval_attestation",
            stellar_agent_core::approval::approve_hint(&view.entry.approval_nonce, view.profile)
        ),
    });
    if let Some(host) = view.endpoint_host {
        approval["endpoint_host"] = json!(host);
    }
    let mut data = json!({ "approval": approval });
    crate::tools::business_entry::echo_business_id(&mut data, view.business_id);
    let text = stellar_agent_core::envelope::Envelope::ok(data)
        .to_json_pretty()
        .unwrap_or_else(|_| String::from("{}"));
    CallToolResult::success(vec![Content::text(text)])
}

/// Where the release of a built mainnet payment failed.
#[cfg(feature = "mainnet-write")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ReleaseFailure {
    /// The payload could not be encoded as the `PAYMENT-SIGNATURE` value.
    Encoding,
    /// The release consumption of the child authorization refused.
    ReleaseConsume,
    /// The pending approval could not be tombstoned after the release
    /// consumption.
    TerminalApproval,
}

/// What the handler does for a [`ReleaseFailure`]; it returns no payload in
/// every case.
#[cfg(feature = "mainnet-write")]
#[derive(Debug)]
pub(super) struct ReleaseDecision {
    /// The invalidation stage of the child authorization, or `None` when the
    /// child is already consumed and both records stay used.
    pub(super) cleanup: Option<stellar_agent_network::mainnet::resolve::InvalidationStage>,
    /// The failure whose stage the withheld audit row carries.
    pub(super) withheld: X402Failure<'static>,
    /// Where the payment was withheld, as the error message names it.
    pub(super) withheld_at: &'static str,
}

/// Selects the cleanup, the withheld row, and the message for a release
/// failure.
///
/// Before the child is consumed the handler owns its cleanup and invalidates
/// it at the payload release stage. After the child is consumed nothing is
/// invalidated: the payment authorization is spent, and only the approval
/// tombstone is missing.
#[cfg(feature = "mainnet-write")]
pub(super) fn release_decision(failure: ReleaseFailure) -> ReleaseDecision {
    use stellar_agent_network::mainnet::resolve::InvalidationStage;
    match failure {
        ReleaseFailure::Encoding => ReleaseDecision {
            cleanup: Some(InvalidationStage::PayloadReleaseRefused),
            withheld: X402Failure::Encoding,
            withheld_at: "at payload encoding",
        },
        ReleaseFailure::ReleaseConsume => ReleaseDecision {
            cleanup: Some(InvalidationStage::PayloadReleaseRefused),
            withheld: X402Failure::PayloadRelease,
            withheld_at: "at payload release",
        },
        ReleaseFailure::TerminalApproval => ReleaseDecision {
            cleanup: None,
            withheld: X402Failure::TerminalApproval,
            withheld_at: "at terminal approval",
        },
    }
}

#[cfg(feature = "mainnet-write")]
pub(super) fn require_terminal_consumption(
    result: Result<bool, stellar_agent_core::WalletError>,
) -> Result<(), stellar_agent_core::WalletError> {
    if result? {
        Ok(())
    } else {
        Err(stellar_agent_core::error::NetworkError::MainnetAuthorizationRefused.into())
    }
}

/// The keyring handle that signs an x402 payment for `payer`.
///
/// Mainnet and approved testnet payments share this lazy handle factory.
/// Approved testnet payments verify enrollment after the preparation callback.
/// The handle reads the seed inside signing, after the preparation gates pass.
pub(super) fn x402_mainnet_signing_handle(
    entry: &stellar_agent_core::profile::KeyringEntryRef,
    payer: &str,
) -> Result<stellar_agent_network::keyring::KeyringSignHandle, stellar_agent_core::WalletError> {
    stellar_agent_network::keyring::lazy_signer_from_keyring(entry, payer)
}

/// Every mainnet x402 error reply after the transmit gate passes appends this
/// sentence, which names `signature_expiration_ledger`; before the gate it is
/// empty.
///
/// After the gate the signed authorization goes to the configured RPC in the
/// re-simulation, and the host accepts it through its signature expiration
/// ledger whatever the wallet does next. A retry before that ledger can pay
/// twice, so every error reply after the gate names it.
#[cfg(feature = "mainnet-write")]
pub(super) fn transmitted_authorization(signature_expiration_ledger: Option<u32>) -> String {
    signature_expiration_ledger.map_or_else(String::new, |ledger| {
        format!(
            "; the signed authorization may have reached the configured RPC and is valid \
             through ledger {ledger}"
        )
    })
}

/// Renders the refusal tombstone of the pending approval after the release
/// consumption under the error's own code, with a message that starts with
/// "payment withheld" followed by `withheld` and ends with the sentence of
/// [`transmitted_authorization`] for `transmitted`.
#[cfg(feature = "mainnet-write")]
pub(super) fn terminal_approval_error(
    error: &stellar_agent_core::WalletError,
    withheld: &str,
    transmitted: Option<u32>,
) -> CallToolResult {
    business_error_result(
        error.code(),
        format!(
            "payment withheld {withheld}: {}{}",
            error.message(),
            transmitted_authorization(transmitted),
        ),
    )
}

/// Renders a mainnet payment failure under its own code, with a message that
/// starts with "payment withheld" followed by `withheld`, which says where.
///
/// `transmitted` is the signature expiration ledger of an authorization the
/// transmit gate let through, and the message then ends with
/// [`transmitted_authorization`]'s sentence.
#[cfg(feature = "mainnet-write")]
pub(super) fn mainnet_x402_error(
    error: &stellar_agent_x402::X402Error,
    withheld: &str,
    transmitted: Option<u32>,
) -> CallToolResult {
    let transmitted = transmitted_authorization(transmitted);
    if let stellar_agent_x402::X402Error::MainnetAuthorization(
        stellar_agent_network::mainnet::MainnetAuthorizationError::PolicyDenied(reason),
    ) = error
    {
        let redacted = crate::tools::common::redact_deny_reason(reason);
        let detail = serde_json::to_string(&redacted).unwrap_or_else(|_| reason.code().to_owned());
        return business_error_result(
            reason.wire_code(),
            format!(
                "payment withheld {withheld}: policy denied this operation: {detail}{transmitted}"
            ),
        );
    }
    business_error_result(
        error.wire_code(),
        format!("payment withheld {withheld}: {error}{transmitted}"),
    )
}

fn payment_response(
    created: &stellar_agent_x402::exact::CreatedPayment,
    payer: &str,
    business_id: Option<&stellar_agent_network::policy_state::BusinessId>,
) -> Result<CallToolResult, stellar_agent_x402::X402Error> {
    let requirements = &created.payload.accepted;
    let signature = stellar_agent_x402::wire::encode_payment_signature(&created.payload)?;
    let mut response = json!({"paymentSignature": signature, "payer": payer,
        "asset": requirements.asset, "amount": requirements.amount, "payTo": requirements.pay_to,
        "network": requirements.network, "cross_check": created.cross_check.view()});
    crate::tools::business_entry::echo_business_id(&mut response, business_id);
    let text = stellar_agent_core::envelope::Envelope::ok(response)
        .to_json_pretty()
        .map_err(|_| stellar_agent_x402::X402Error::TransactionBuildFailed {
            detail: "payment response serialization failed".to_owned(),
        })?;
    Ok(CallToolResult::success(vec![Content::text(text)]))
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
    /// The release consumption of the mainnet child authorization refused.
    #[cfg(feature = "mainnet-write")]
    PayloadRelease,
    /// The mainnet pending approval could not be tombstoned after the child
    /// authorization was consumed.
    #[cfg(feature = "mainnet-write")]
    TerminalApproval,
}

/// Returns the `x402_authorization_withheld` stage for `failure`, or `None`
/// when the transmit gate never returned `Ok`.
///
/// Before the gate returns `Ok` the signed authorization has not left the
/// wallet, and no withheld row is written here: a gate that refused before its
/// authorized row wrote no row, and one that refused after it already paired
/// that row with an `anchor_unavailable` row. After the gate returns `Ok` the
/// stage is one of five:
///
/// - `resimulation`: an RPC simulate error, which is the re-simulation itself.
/// - `response_processing`: every other `create_payment` error. Either the
///   RPC answered the re-simulation and its answer could not be processed, or,
///   on mainnet, the consumption of the payment intent refused after the gate
///   and before the signed re-simulation request, so the signed authorization
///   never reached the RPC.
/// - `encoding`: the built payload could not be encoded.
/// - `payload_release`: the release consumption of the mainnet child
///   authorization refused; only in builds with the `mainnet-write` feature.
/// - `terminal_approval`: the mainnet pending approval could not be
///   tombstoned after the child authorization was consumed; only in builds
///   with the `mainnet-write` feature.
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
        #[cfg(feature = "mainnet-write")]
        X402Failure::PayloadRelease => "payload_release",
        #[cfg(feature = "mainnet-write")]
        X402Failure::TerminalApproval => "terminal_approval",
    })
}

/// The transmit gate both x402 tools pass to `create_payment`, and what it
/// observed.
///
/// The gate writes the `x402_payment_authorized` row through
/// [`emit_anchored_value_audit_row_strict`], which acquires the writer through
/// the registry, reruns the anchor check, and requires a current tip anchor
/// before and after the row, so the row is durable and anchored before the
/// signed authorization is sent. When the anchor fails after the row, the gate
/// pairs it with an `anchor_unavailable` withheld row through the writer it
/// still holds. A write that refuses keeps its wallet error here, and the
/// handler answers with that error's own code. The withheld row of a later
/// failure carries the same request id as the authorized row.
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
    pub(super) gate_passed: bool,
    /// The signature expiration ledger of the authorization the gate let
    /// through; `None` until the gate passes.
    #[cfg(feature = "mainnet-write")]
    transmitted_ledger: Option<u32>,
    decision: PolicyDecision,
    /// The provenance of the governing mainnet decision, which the
    /// authorized row records; `None` off mainnet.
    provenance: Option<stellar_agent_core::mainnet::decision::MainnetProvenance>,
    pub(super) refusal: Option<stellar_agent_core::error::WalletError>,
    spend: Option<X402ApprovalSpend<'a>>,
    approval_refusal: Option<CallToolResult>,
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
            profile: server.security_profile(),
            profile_name: server.profile_name_for_approval(),
            binding: server.audit_binding,
            tool,
            chain_id,
            leg: Some(leg),
            request_id: uuid::Uuid::new_v4().to_string(),
            network: String::new(),
            scheme: String::new(),
            gate_passed: false,
            #[cfg(feature = "mainnet-write")]
            transmitted_ledger: None,
            decision: PolicyDecision::Allow,
            provenance: None,
            refusal: None,
            spend: None,
            approval_refusal: None,
        }
    }

    pub(super) fn with_decision(mut self, decision: PolicyDecision) -> Self {
        self.decision = decision;
        self
    }

    pub(super) fn with_approval_spend(mut self, spend: X402ApprovalSpend<'a>) -> Self {
        self.spend = Some(spend);
        self
    }

    /// Records `provenance`, the governing mainnet decision's, on the
    /// authorized row.
    #[cfg(feature = "mainnet-write")]
    pub(super) fn with_provenance(
        mut self,
        provenance: Option<stellar_agent_core::mainnet::decision::MainnetProvenance>,
    ) -> Self {
        self.provenance = provenance;
        self
    }

    /// The signature expiration ledger of the authorization the transmit
    /// gate let through, which the authorized row records; `None` before the
    /// gate passed.
    #[cfg(feature = "mainnet-write")]
    pub(super) fn transmitted_ledger(&self) -> Option<u32> {
        self.transmitted_ledger
    }

    /// The transmit gate: writes the authorized row, or refuses.
    ///
    /// # Errors
    ///
    /// [`stellar_agent_x402::X402Error::TransmitGateRefused`] when the row
    /// or its tip anchor cannot be written. The wallet error that refused is
    /// kept for [`X402AuthorizationAudit::refusal_result`].
    pub(super) fn before_transmit(
        &mut self,
        authorization: &stellar_agent_x402::exact::AuthorizationToTransmit<'_>,
    ) -> Result<(), stellar_agent_x402::X402Error> {
        #[cfg(test)]
        TRANSMIT_GATE_ENTRIES.with(|count| count.set(count.get() + 1));
        if let Some(spend) = &self.spend
            && let Err(result) = spend_x402_approval(
                spend.server,
                &spend.nonce,
                spend.governing_ttl_ms,
                &authorization.signed_entries_sha256,
            )
        {
            tracing::debug!(tool = self.tool, nonce = %spend.nonce, "x402 approval spend refused");
            self.approval_refusal = Some(result);
            return Err(stellar_agent_x402::X402Error::TransmitGateRefused {
                detail: "the x402 approval is not available to spend".to_owned(),
            });
        }
        self.network = authorization.network.to_owned();
        #[cfg(test)]
        if self.spend.is_some() {
            x402_crash_boundary("spend");
        }
        self.scheme = authorization.scheme.to_owned();
        let entry = self.authorized_row(
            authorization.network,
            authorization.scheme,
            authorization.cross_check,
            Some(authorization.signature_expiration_ledger),
        );
        let result = emit_anchored_value_audit_row_strict(
            self.profile,
            &self.profile_name,
            self.binding,
            entry,
            |writer| self.pair_unanchored_authorization(writer),
        );
        match result {
            Ok(()) => {
                #[cfg(test)]
                if self.spend.is_some() {
                    x402_crash_boundary("audit");
                }
                self.gate_passed = true;
                #[cfg(feature = "mainnet-write")]
                {
                    self.transmitted_ledger = Some(authorization.signature_expiration_ledger);
                }
                Ok(())
            }
            Err(error) => {
                self.refusal = Some(error);
                Err(stellar_agent_x402::X402Error::TransmitGateRefused {
                    detail: "the x402 authorization audit row or its tip anchor is unavailable"
                        .to_owned(),
                })
            }
        }
    }

    fn authorized_row(
        &mut self,
        network: &str,
        scheme: &str,
        witness: Option<&CrossCheckWitness>,
        signature_expiration_ledger: Option<u32>,
    ) -> AuditEntry {
        let entry = AuditEntry::new_x402_payment_authorized(
            self.tool,
            self.chain_id,
            self.leg.take().into_iter().collect(),
            network,
            scheme,
            self.decision.clone(),
            &self.request_id,
            witness.map(CrossCheckWitness::record),
            signature_expiration_ledger,
        );
        match &self.provenance {
            Some(provenance) => entry.with_provenance(provenance),
            None => entry,
        }
    }

    /// The tool result for the gate's own refusal, carrying the wallet error's
    /// code, or `None` when the gate did not refuse.
    pub(super) fn refusal_result(&mut self) -> Option<CallToolResult> {
        if let Some(refusal) = self.approval_refusal.take() {
            return Some(refusal);
        }
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
        if let Err(error) = emit_value_audit_row_strict(
            self.profile,
            &self.profile_name,
            self.binding,
            self.withheld_row(stage),
        ) {
            self.log_withheld_row_not_written(stage, &error);
        }
    }

    /// Pairs an authorized row whose tip anchor could not be written with an
    /// `anchor_unavailable` withheld row, through the writer the gate holds.
    ///
    /// The gate reaches this only after the authorized row is durable, and the
    /// signed authorization has not left the wallet. A fresh acquisition would
    /// rerun the anchor repair and refuse while the keyring is still failing,
    /// so the row goes through the held writer, whose append stays best-effort
    /// for its own anchor. A row that cannot be written is logged at `error`
    /// with its code.
    fn pair_unanchored_authorization(&self, writer: &mut AuditWriter) {
        let stage = "anchor_unavailable";
        if let Err(error) = writer.write_entry(self.withheld_row(stage)) {
            let refusal = audit_writer_refusal(&self.profile_name, &error);
            self.log_withheld_row_not_written(stage, &refusal);
        }
    }

    /// The `x402_authorization_withheld` row for `stage`, carrying this
    /// payment's request id.
    fn withheld_row(&self, stage: &str) -> AuditEntry {
        AuditEntry::new_x402_authorization_withheld(
            self.tool,
            self.chain_id,
            self.network.as_str(),
            self.scheme.as_str(),
            stage,
            self.request_id.as_str(),
        )
    }

    /// Logs a withheld row that could not be written, with its stage and code.
    fn log_withheld_row_not_written(
        &self,
        stage: &str,
        error: &stellar_agent_core::error::WalletError,
    ) {
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
        X402Error::UnsupportedScheme => "unsupported_scheme",
        X402Error::UnsupportedNetwork => "unsupported_network",
        X402Error::NetworkPassphraseMismatch => "network_passphrase_mismatch",
        X402Error::MainnetSigningForbidden { .. } => "mainnet_signing_forbidden",
        X402Error::InvalidAssetAddress { .. } => "invalid_asset_address",
        X402Error::MuxedContractProtocolUnsupported { .. } => "muxed_contract_protocol_unsupported",
        X402Error::FeesNotSponsored => "fees_not_sponsored",
        X402Error::AmountConversion { .. } => "amount_conversion",
        X402Error::AuthEntrySignFailed { .. } => "auth_entry_sign_failed",
        X402Error::RpcSimulateFailed { .. } => "rpc_simulate_failed",
        X402Error::ReceiptParseFailed { .. } => "receipt_parse_failed",
        X402Error::TransactionBuildFailed { .. } => "transaction_build_failed",
        X402Error::UnexpectedAuthEntries { .. } => "unexpected_auth_entries",
        X402Error::TransmitGateRefused { .. } => "transmit_gate_refused",
        X402Error::EndpointIdentity(_) => "endpoint_identity",
        X402Error::CrossCheck(_) => "cross_check",
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
pub(super) mod approval_tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test assertions"
    )]
    mod review_tests {
        include!("x402_approval_review_tests.rs");
    }
    use super::*;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use sha2::Digest as _;
    use std::sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    };
    use stellar_agent_core::approval::{ApprovalKind, PendingApproval};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    const DATA: &str = "AAAAAAAAAAIAAAAGAAAAAcwD/nT9D7Dc2LxRdab+2vEUF8B+XoN7mQW21oxPT8ALAAAAFAAAAAEAAAAHy8vNUZ8vyZ2ybPHW0XbSrRtP7gEWsJ6zDzcfY9P8z88AAAABAAAABgAAAAHMA/50/Q+w3Ni8UXWm/trxFBfAfl6De5kFttaMT0/ACwAAABAAAAABAAAAAgAAAA8AAAAHQ291bnRlcgAAAAASAAAAAAAAAAAg4dbAxsGAGICfBG3iT2cKGYQ6hK4sJWzZ6or1C5v6GAAAAAEAHfKyAAAFiAAAAIgAAAAAAAAAAw==";

    struct Clock(Arc<AtomicU64>);
    impl stellar_agent_core::timefmt::Clock for Clock {
        fn now_unix_ms(&self) -> Result<u64, stellar_agent_core::wallet::WalletLifecycleError> {
            Ok(self.0.load(Ordering::SeqCst))
        }
    }

    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn authenticated_identity_failure_keeps_the_approval() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let fixture = crate::tools::message_signing_tests::Fixture::new();
        fixture.seed_signer();
        fixture.seed_audit();
        let mut server = fixture.server();
        server.policy_engine = super::tests::make_require_approval_server().policy_engine;
        server.set_approval_dir_for_test(fixture.dir.path().join("approvals"));
        server.set_x402_identity_session_for_test("jwt".into(), fixture.account.clone(), vec![]);
        let queued = call(&server, true, None).await;
        let nonce = value(&queued)["data"]["approval"]["approval_nonce"]
            .as_str()
            .unwrap()
            .to_owned();
        let proof = attest(&server, &nonce);
        crate::tools::x402_authenticated_payment::IDENTITY_FAILURE.with(|flag| flag.set(true));
        let before = transmit_gate_entries_on_this_thread();
        let identity_before =
            crate::tools::x402_authenticated_payment::identity_calls_on_this_thread();
        let result = call(&server, true, Some(&proof)).await;
        crate::tools::x402_authenticated_payment::IDENTITY_FAILURE.with(|flag| flag.set(false));
        assert_eq!(result.is_error, Some(true), "{}", value(&result));
        assert_eq!(transmit_gate_entries_on_this_thread(), before);
        assert_eq!(
            crate::tools::x402_authenticated_payment::identity_calls_on_this_thread(),
            identity_before + 1
        );
        assert_eq!(
            value(&result)["error"]["code"],
            "identity.home_domain_unresolvable"
        );
        let entry = server
            .x402_approval_store()
            .unwrap()
            .get(&nonce)
            .unwrap()
            .clone();
        assert!(matches!(entry.kind, ApprovalKind::X402Payment { .. }));
        assert!(entry.attestation_blob_b64.is_some());
    }

    struct FailingClock;
    impl stellar_agent_core::timefmt::Clock for FailingClock {
        fn now_unix_ms(&self) -> Result<u64, stellar_agent_core::wallet::WalletLifecycleError> {
            Err(
                stellar_agent_core::wallet::WalletLifecycleError::ClockError {
                    detail: "clock unavailable".into(),
                    source: None,
                },
            )
        }
    }

    fn requirements() -> String {
        json!({"scheme":"exact", "network":"stellar:testnet",
            "asset":"CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA",
            "amount":"10000000", "payTo":"GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
            "maxTimeoutSeconds":300, "extra":{"areFeesSponsored":true}})
        .to_string()
    }

    pub(super) async fn call(
        server: &WalletServer,
        auth: bool,
        proof: Option<&X402ApprovalProof>,
    ) -> CallToolResult {
        call_requirements(server, auth, proof, requirements()).await
    }

    async fn call_requirements(
        server: &WalletServer,
        auth: bool,
        proof: Option<&X402ApprovalProof>,
        requirements: String,
    ) -> CallToolResult {
        let nonce = proof.map(|proof| proof.nonce.clone());
        let attestation = proof.map(|proof| proof.attestation.clone());
        if auth {
            server
                .call_stellar_x402_authenticated_payment(
                    crate::server::X402AuthenticatedPaymentArgs {
                        approval_nonce: nonce,
                        approval_attestation: attestation,
                        chain_id: "stellar:testnet".into(),
                        payment_required: requirements.clone(),
                        address: None,
                        business_id: None,
                        home_domain: "merchant.example".into(),
                    },
                )
                .await
                .unwrap()
        } else {
            server
                .call_stellar_x402_create_payment(X402CreatePaymentArgs {
                    approval_nonce: nonce,
                    approval_attestation: attestation,
                    chain_id: "stellar:testnet".into(),
                    payment_required: requirements.clone(),
                    address: None,
                    business_id: None,
                })
                .await
                .unwrap()
        }
    }

    fn value(result: &CallToolResult) -> serde_json::Value {
        serde_json::from_str(&result.content[0].as_text().unwrap().text).unwrap()
    }

    fn attest(server: &WalletServer, nonce: &str) -> X402ApprovalProof {
        crate::tools::value_audit::require_value_audit_writer(
            &server.profile,
            &server.profile_name_for_approval(),
            server.audit_binding,
        )
        .unwrap();
        use stellar_agent_core::approval::{
            AttestationBinding, AttestedApprover, ConsentAuthorization,
            attest::{ConsentAudit, Surface, attest_and_persist},
        };
        let key = [0x5a; 32];
        let coord = &server.profile.attestation_key_id;
        keyring_core::Entry::new(&coord.service, &coord.account)
            .unwrap()
            .set_password(&URL_SAFE_NO_PAD.encode(key))
            .unwrap();
        let mut store = server.x402_approval_store().unwrap();
        let entry = store.get(nonce).unwrap().clone();
        let outbox = stellar_agent_core::audit_log::AuditOutbox::for_log(
            &server.profile.audit_log_path,
            stellar_agent_network::keyring::KeyringTipAnchorStore::shared(
                &server.profile.audit_log_hash_chain_key_id,
                &server.profile.audit_log_path,
            ),
        );
        attest_and_persist(
            &mut store,
            &entry,
            &key,
            &AttestationBinding::new(&server.profile_name_for_approval(), "stellar:testnet"),
            Surface::Cli,
            ConsentAudit::Outbox(&outbox),
            ConsentAuthorization::Standard(&AttestedApprover::Local),
            |_, _| Err("no grant".into()),
        )
        .unwrap();
        let entry = store.get(nonce).unwrap();
        let ApprovalKind::X402Payment {
            intent_digest,
            root_invocation_xdr,
            home_domain,
            ..
        } = &entry.kind
        else {
            panic!("x402");
        };
        X402ApprovalProof {
            nonce: nonce.to_owned(),
            attestation: entry.attestation_blob_b64.clone().unwrap(),
            expected_subject: stellar_agent_core::approval::subject::verified_x402_subject(
                intent_digest,
                root_invocation_xdr,
                home_domain.as_deref(),
                server.context.network_passphrase(),
            )
            .unwrap(),
            governing_ttl_ms: 120_000,
        }
    }

    struct Rpc {
        payer: stellar_xdr::ScAddress,
        clock: Arc<AtomicU64>,
        health_expiry: Arc<AtomicU64>,
        simulations: Arc<AtomicUsize>,
    }
    impl Respond for Rpc {
        fn respond(&self, request: &Request) -> ResponseTemplate {
            use stellar_xdr::*;
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            let result = match body["method"].as_str().unwrap() {
                "getNetwork" => {
                    json!({"passphrase":"Test SDF Network ; September 2015","protocolVersion":30})
                }
                "getHealth" => {
                    let expiry = self.health_expiry.load(Ordering::SeqCst);
                    if expiry != 0 {
                        self.clock.store(expiry, Ordering::SeqCst);
                    }
                    json!({"status":"healthy","latestLedger":1000,"oldestLedger":1,"ledgerRetentionWindow":17280})
                }
                "simulateTransaction" => {
                    self.simulations.fetch_add(1, Ordering::SeqCst);
                    let TransactionEnvelope::Tx(envelope) = TransactionEnvelope::from_xdr_base64(
                        body["params"]["transaction"].as_str().unwrap(),
                        Limits::none(),
                    )
                    .unwrap() else {
                        panic!("v1");
                    };
                    let OperationBody::InvokeHostFunction(host) = &envelope.tx.operations[0].body
                    else {
                        panic!("invoke");
                    };
                    let HostFunction::InvokeContract(invoke) = &host.host_function else {
                        panic!("contract");
                    };
                    let auth: Vec<String> = if host.auth.is_empty() {
                        vec![
                            SorobanAuthorizationEntry {
                                credentials: SorobanCredentials::Address(
                                    SorobanAddressCredentials {
                                        address: self.payer.clone(),
                                        nonce: 7,
                                        signature_expiration_ledger: 0,
                                        signature: ScVal::Void,
                                    },
                                ),
                                root_invocation: SorobanAuthorizedInvocation {
                                    function: SorobanAuthorizedFunction::ContractFn(invoke.clone()),
                                    sub_invocations: VecM::default(),
                                },
                            }
                            .to_xdr_base64(Limits::none())
                            .unwrap(),
                        ]
                    } else {
                        if let Ok(path) = std::env::var("X402_CHILD_TRANSMISSION") {
                            std::fs::write(path, b"signed").unwrap();
                        }
                        vec![]
                    };
                    json!({"transactionData":DATA,"minResourceFee":"1000","latestLedger":1000,
                        "results":[{"auth":auth,"xdr":ScVal::Void.to_xdr_base64(Limits::none()).unwrap()}]})
                }
                other => panic!("unexpected RPC {other}"),
            };
            ResponseTemplate::new(200)
                .set_body_json(json!({"jsonrpc":"2.0","id":body["id"],"result":result}))
        }
    }

    pub(crate) async fn expiry_case(auth: bool, key_read: bool) {
        for governing in [false, true] {
            for attestation_read in [false, true] {
                let mut fixture = crate::tools::message_signing_tests::Fixture::new();
                let now = Arc::new(AtomicU64::new(0));
                let expiry = Arc::new(AtomicU64::new(0));
                let reads = Arc::new(AtomicUsize::new(0));
                let active = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let coord = if attestation_read {
                    &fixture.profile.attestation_key_id
                } else {
                    &fixture.profile.mcp_signer_default
                };
                let (read_counter, active_hook, time, expires) =
                    (reads.clone(), active.clone(), now.clone(), expiry.clone());
                stellar_agent_test_support::keyring_mock::install_with_read_hooks(vec![
                    stellar_agent_test_support::keyring_mock::ReadHook::new(
                        &coord.service,
                        &coord.account,
                        Arc::new(move || {
                            let index = read_counter.fetch_add(1, Ordering::SeqCst) + 1;
                            if key_read
                                && active_hook.load(Ordering::SeqCst)
                                && index == if attestation_read { 3 } else { 2 }
                            {
                                let time = time.clone();
                                let expires = expires.clone();
                                let (send, receive) = std::sync::mpsc::channel();
                                let thread = std::thread::spawn(move || {
                                    time.store(expires.load(Ordering::SeqCst), Ordering::SeqCst);
                                    send.send(()).unwrap();
                                });
                                receive.recv().unwrap();
                                thread.join().unwrap();
                            }
                        }),
                    ),
                ])
                .unwrap();
                fixture.seed_signer();
                fixture.seed_audit();
                let mock = MockServer::start().await;
                fixture.profile.rpc_url = mock.uri();
                let mut server = fixture.server();
                server.policy_engine = super::tests::make_require_approval_server().policy_engine;
                server.set_approval_dir_for_test(fixture.dir.path().join("approvals"));
                server.set_x402_identity_session_for_test(
                    "jwt".into(),
                    fixture.account.clone(),
                    vec![],
                );
                let queued = call(&server, auth, None).await;
                let data = value(&queued);
                assert_ne!(queued.is_error, Some(true), "{data}");
                let nonce = data["data"]["approval"]["approval_nonce"]
                    .as_str()
                    .unwrap()
                    .to_owned();
                let mut store = server.x402_approval_store().unwrap();
                let mut entry = store.get(&nonce).unwrap().clone();
                expiry.store(entry.expires_at_unix_ms, Ordering::SeqCst);
                if governing {
                    entry.expires_at_unix_ms += 120_000;
                    drop(store);
                    server
                        .set_approval_dir_for_test(fixture.dir.path().join("governing-approvals"));
                    store = server.x402_approval_store().unwrap();
                    store
                        .insert(entry.clone(), entry.created_at_unix_ms)
                        .unwrap();
                }
                drop(store);
                let proof = attest(&server, &nonce);
                now.store(entry.created_at_unix_ms + 1, Ordering::SeqCst);
                server.clock = Arc::new(Clock(now.clone()));
                let simulations = Arc::new(AtomicUsize::new(0));
                let public =
                    stellar_strkey::ed25519::PublicKey::from_string(&fixture.account).unwrap();
                Mock::given(wiremock::matchers::method("POST"))
                    .respond_with(Rpc {
                        payer: stellar_xdr::ScAddress::Account(stellar_xdr::AccountId(
                            stellar_xdr::PublicKey::PublicKeyTypeEd25519(stellar_xdr::Uint256(
                                public.0,
                            )),
                        )),
                        clock: now,
                        health_expiry: if key_read {
                            Arc::new(AtomicU64::new(0))
                        } else {
                            expiry
                        },
                        simulations: simulations.clone(),
                    })
                    .mount(&mock)
                    .await;
                reads.store(0, Ordering::SeqCst);
                active.store(true, Ordering::SeqCst);
                let before = transmit_gate_entries_on_this_thread();
                let result = call(&server, auth, Some(&proof)).await;
                let data = value(&result);
                if !key_read && !attestation_read {
                    assert_eq!(
                        reads.load(Ordering::SeqCst),
                        0,
                        "a refusing preparation callback reads no payer key"
                    );
                }
                assert_eq!(data["error"]["code"], "policy.approval_required", "{data}");
                assert_eq!(
                    transmit_gate_entries_on_this_thread() - before,
                    0,
                    "expired approval signs nothing"
                );
                assert_eq!(simulations.load(Ordering::SeqCst), 1);
                let store = server.x402_approval_store().unwrap();
                assert!(matches!(
                    store.get(&proof.nonce).unwrap().kind,
                    ApprovalKind::X402Payment { .. }
                ));
                assert!(
                    store
                        .get(&proof.nonce)
                        .unwrap()
                        .attestation_blob_b64
                        .is_some()
                );
                let log =
                    std::fs::read_to_string(&server.profile.audit_log_path).unwrap_or_default();
                assert!(!log.contains("x402_payment_authorized"));
            }
        }
    }

    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn approval_expiring_during_preparation_signs_nothing() {
        expiry_case(false, false).await;
    }

    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn key_read_crossing_expiry_signs_nothing() {
        expiry_case(false, true).await;
    }

    pub(crate) async fn subject_gate_case(expired: bool) {
        use crate::tools::common::{
            ApprovalOutcome, DispatchOutcome, GatedApprovalKind, verify_attestation_subject_gate,
        };
        for auth in [false, true] {
            for governing in [false, true] {
                stellar_agent_test_support::keyring_mock::install().unwrap();
                let fixture = crate::tools::message_signing_tests::Fixture::new();
                let reads = Arc::new(AtomicUsize::new(0));
                let count = reads.clone();
                let coord = &fixture.profile.mcp_signer_default;
                stellar_agent_test_support::keyring_mock::install_with_read_hooks(vec![
                    stellar_agent_test_support::keyring_mock::ReadHook::new(
                        &coord.service,
                        &coord.account,
                        Arc::new(move || {
                            count.fetch_add(1, Ordering::SeqCst);
                        }),
                    ),
                ])
                .unwrap();
                fixture.seed_signer();
                fixture.seed_audit();
                let mut server = fixture.server();
                server.policy_engine = super::tests::make_require_approval_server().policy_engine;
                server.set_approval_dir_for_test(fixture.dir.path().join("approvals"));
                let queued = call(&server, auth, None).await;
                let nonce = value(&queued)["data"]["approval"]["approval_nonce"]
                    .as_str()
                    .unwrap()
                    .to_owned();
                let mut store = server.x402_approval_store().unwrap();
                let mut entry = store.get(&nonce).unwrap().clone();
                if governing {
                    entry.expires_at_unix_ms += 120_000;
                    drop(store);
                    server
                        .set_approval_dir_for_test(fixture.dir.path().join("governing-approvals"));
                    store = server.x402_approval_store().unwrap();
                    store
                        .insert(entry.clone(), entry.created_at_unix_ms)
                        .unwrap();
                }
                drop(store);
                let proof = attest(&server, &nonce);
                server.clock = Arc::new(Clock(Arc::new(AtomicU64::new(
                    entry.created_at_unix_ms + if expired { 120_000 } else { 1 },
                ))));
                let expected = if expired {
                    proof.expected_subject
                } else {
                    let ApprovalKind::X402Payment { intent_digest, .. } = &entry.kind else {
                        panic!("x402");
                    };
                    if auth {
                        stellar_agent_core::approval::subject::approval_subject_x402(intent_digest)
                    } else {
                        stellar_agent_core::approval::subject::approval_subject_x402_authenticated(
                            intent_digest,
                            "merchant.example",
                        )
                    }
                };
                let outcome = DispatchOutcome::RequireApproval(ApprovalOutcome::from(
                    stellar_agent_core::policy::ApprovalRequest::new("reason".into(), 120),
                ));
                reads.store(0, Ordering::SeqCst);
                let refusal = verify_attestation_subject_gate(
                    &server,
                    &outcome,
                    GatedApprovalKind::X402.expectation(expected),
                    Some(&nonce),
                    Some(&proof.attestation),
                    "stellar_x402_create_payment",
                )
                .await
                .unwrap_err();
                assert_eq!(value(&refusal)["error"]["code"], "policy.approval_required");
                assert_eq!(
                    reads.load(Ordering::SeqCst),
                    0,
                    "the refused subject reads no payer key"
                );
                if !expired {
                    use stellar_xdr::ReadXdr as _;
                    let ApprovalKind::X402Payment {
                        root_invocation_xdr,
                        home_domain,
                        ..
                    } = &entry.kind
                    else {
                        panic!("x402");
                    };
                    let root = stellar_xdr::SorobanAuthorizedInvocation::from_xdr_base64(
                        root_invocation_xdr,
                        stellar_xdr::Limits::none(),
                    )
                    .unwrap();
                    let network = sha2::Sha256::digest(
                        stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE.as_bytes(),
                    )
                    .into();
                    let digest = stellar_agent_core::approval::subject::soroban_intent_digest(
                        &network, &root,
                    )
                    .unwrap();
                    let foreign_subject = match home_domain {
                        Some(domain) => stellar_agent_core::approval::subject::approval_subject_x402_authenticated(&digest, domain),
                        None => stellar_agent_core::approval::subject::approval_subject_x402(&digest),
                    };
                    let outcome = DispatchOutcome::RequireApproval(ApprovalOutcome::from(
                        stellar_agent_core::policy::ApprovalRequest::new("reason".into(), 120),
                    ));
                    let result = verify_attestation_subject_gate(
                        &server,
                        &outcome,
                        GatedApprovalKind::X402.expectation(foreign_subject),
                        Some(&nonce),
                        Some(&proof.attestation),
                        "stellar_x402_create_payment",
                    )
                    .await
                    .unwrap_err();
                    assert_eq!(value(&result)["error"]["code"], "policy.approval_required");
                }
                assert!(matches!(
                    server
                        .x402_approval_store()
                        .unwrap()
                        .get(&nonce)
                        .unwrap()
                        .kind,
                    ApprovalKind::X402Payment { .. }
                ));
            }
        }
        #[cfg(feature = "mainnet-write")]
        if !expired {
            use crate::tools::common::tests::mainnet::{Fixture, require_approval_rules};
            let fixture = Fixture::new(|raw| {
                require_approval_rules(&raw, &["stellar_x402_create_payment"], 600)
            });
            let terms = fixture.requirements();
            let root =
                stellar_agent_x402::exact::payment_root(&terms, fixture.envelope.source()).unwrap();
            let mainnet_id =
                sha2::Sha256::digest(fixture.server.context.network_passphrase().as_bytes()).into();
            let entry = PendingApproval::new_x402_pending(
                &mainnet_id,
                &root,
                None,
                stellar_agent_core::approval::process_uid_for_attestation().unwrap(),
                600_000,
            )
            .unwrap();
            let blob = fixture.attest(&entry);
            let outcome = fixture
                .server
                .dispatch_preparation(
                    "stellar_x402_create_payment",
                    &json!({"chain_id":"stellar:mainnet"}),
                    "stellar:mainnet",
                    ValueClass::single(x402_value_leg(&terms, 10)),
                    stellar_agent_core::mainnet::decision::EvaluationScope::Classic,
                )
                .await
                .unwrap();
            let testnet_id = sha2::Sha256::digest(
                stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE.as_bytes(),
            )
            .into();
            let digest =
                stellar_agent_core::approval::subject::soroban_intent_digest(&testnet_id, &root)
                    .unwrap();
            let result = verify_attestation_subject_gate(
                &fixture.server,
                &outcome,
                GatedApprovalKind::X402.expectation(
                    stellar_agent_core::approval::subject::approval_subject_x402(&digest),
                ),
                Some(&entry.approval_nonce),
                Some(&blob),
                "stellar_x402_create_payment",
            )
            .await
            .unwrap_err();
            assert_eq!(value(&result)["error"]["code"], "policy.approval_required");
            assert!(matches!(
                fixture
                    .server
                    .x402_approval_store()
                    .unwrap()
                    .get(&entry.approval_nonce)
                    .unwrap()
                    .kind,
                ApprovalKind::X402Payment { .. }
            ));
        }
    }

    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn x402_writer_reads_insert_clock_after_open() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let fixture = crate::tools::message_signing_tests::Fixture::new();
        let mut server = fixture.server();
        server.set_approval_dir_for_test(fixture.dir.path().join("approvals"));
        let terms = serde_json::from_str(&requirements()).unwrap();
        let root = stellar_agent_x402::exact::payment_root(&terms, &fixture.account).unwrap();
        let approval = crate::tools::common::ApprovalOutcome::from(
            stellar_agent_core::policy::ApprovalRequest::new("reason".into(), 120),
        );
        let calls = std::cell::Cell::new(0);
        let store = server.x402_approval_store().unwrap();
        let result = server.write_x402_pending_approval(&root, None, &approval, || {
            calls.set(calls.get() + 1);
            Ok(0)
        });
        assert!(result.is_err());
        assert_eq!(
            calls.get(),
            0,
            "store acquisition precedes the insert clock"
        );
        drop(store);
        let mut old = pending(&server);
        old.created_at_unix_ms = 1;
        old.expires_at_unix_ms = 2;
        server
            .x402_approval_store()
            .unwrap()
            .insert(old.clone(), 1)
            .unwrap();
        let entry = server
            .write_x402_pending_approval(&root, None, &approval, || {
                calls.set(calls.get() + 1);
                Ok(3)
            })
            .unwrap();
        assert_eq!(calls.get(), 1);
        assert!(entry.created_at_unix_ms > 3);
        let store = server.x402_approval_store().unwrap();
        assert!(store.get(&old.approval_nonce).is_none());
        assert!(store.get(&entry.approval_nonce).is_some());
        drop(store);
        #[cfg(feature = "mainnet-write")]
        {
            use crate::tools::common::tests::mainnet::{Fixture, require_approval_rules};
            let mut fixture = Fixture::new(|raw| {
                require_approval_rules(&raw, &["stellar_x402_create_payment"], 600)
            });
            fixture.server.clock = Arc::new(FailingClock);
            let result = fixture
                .server
                .call_stellar_x402_create_payment(X402CreatePaymentArgs {
                    payment_required: serde_json::to_string(&fixture.requirements()).unwrap(),
                    chain_id: "stellar:mainnet".into(),
                    address: None,
                    approval_nonce: None,
                    approval_attestation: None,
                    business_id: Some(crate::tools::common::tests::fresh_business_id()),
                })
                .await
                .unwrap();
            assert_ne!(
                result.is_error,
                Some(true),
                "mainnet insertion uses its own clock: {}",
                value(&result)
            );
            assert!(value(&result)["data"]["approval"]["approval_nonce"].is_string());
            assert!(value(&result)["data"].get("paymentSignature").is_none());
        }
    }

    pub(crate) async fn queue_key_case(auth: bool) {
        let mut fixture = crate::tools::message_signing_tests::Fixture::new();
        let reads = Arc::new(AtomicUsize::new(0));
        let hooks = [
            &fixture.profile.mcp_signer_default,
            &fixture.profile.attestation_key_id,
            &fixture.profile.audit_log_hash_chain_key_id,
        ]
        .iter()
        .map(|coord| {
            let reads = reads.clone();
            stellar_agent_test_support::keyring_mock::ReadHook::new(
                &coord.service,
                &coord.account,
                Arc::new(move || {
                    reads.fetch_add(1, Ordering::SeqCst);
                }),
            )
        })
        .collect();
        stellar_agent_test_support::keyring_mock::install_with_read_hooks(hooks).unwrap();
        fixture.seed_signer();
        fixture.seed_audit();
        let coord = &fixture.profile.attestation_key_id;
        keyring_core::Entry::new(&coord.service, &coord.account)
            .unwrap()
            .set_password(&URL_SAFE_NO_PAD.encode([0x5a; 32]))
            .unwrap();
        let mock = MockServer::start().await;
        fixture.profile.rpc_url = mock.uri();
        Mock::given(wiremock::matchers::method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc":"2.0", "id":1,
                "result":{"passphrase":"Test SDF Network ; September 2015","protocolVersion":30}
            })))
            .mount(&mock)
            .await;
        let mut server = fixture.server();
        server.policy_engine = super::tests::make_require_approval_server().policy_engine;
        server.set_approval_dir_for_test(fixture.dir.path().join("approvals"));
        server.set_x402_identity_session_for_test("jwt".into(), fixture.account.clone(), vec![]);
        let identity = crate::tools::x402_authenticated_payment::identity_calls_on_this_thread();
        reads.store(0, Ordering::SeqCst);
        for payee in [
            stellar_strkey::ed25519::PublicKey([0; 32])
                .to_string()
                .to_string(),
            stellar_strkey::Contract([3; 32]).to_string().to_string(),
            stellar_strkey::ed25519::MuxedAccount {
                ed25519: [0; 32],
                id: 7,
            }
            .to_string()
            .to_string(),
            stellar_strkey::MuxedContract {
                contract_id: [3; 32],
                id: 7,
            }
            .to_string()
            .to_string(),
        ] {
            let mut requirements: serde_json::Value =
                serde_json::from_str(&requirements()).unwrap();
            requirements["payTo"] = payee.into();
            let result = call_requirements(&server, auth, None, requirements.to_string()).await;
            assert_ne!(result.is_error, Some(true), "{}", value(&result));
        }
        assert_eq!(reads.load(Ordering::SeqCst), 0, "queueing reads no keys");
        assert_eq!(
            crate::tools::x402_authenticated_payment::identity_calls_on_this_thread(),
            identity
        );
    }

    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn x402_queue_reads_no_signer_and_runs_no_identity_gate() {
        queue_key_case(false).await;
    }

    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn pre_sign_check_is_absent_without_an_approval_requirement() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let mut fixture = crate::tools::message_signing_tests::Fixture::new();
        fixture.seed_signer();
        fixture.seed_audit();
        let mock = MockServer::start().await;
        fixture.profile.rpc_url = mock.uri();
        let server = fixture.server();
        let public = stellar_strkey::ed25519::PublicKey::from_string(&fixture.account).unwrap();
        Mock::given(wiremock::matchers::method("POST"))
            .respond_with(Rpc {
                payer: stellar_xdr::ScAddress::Account(stellar_xdr::AccountId(
                    stellar_xdr::PublicKey::PublicKeyTypeEd25519(stellar_xdr::Uint256(public.0)),
                )),
                clock: Arc::new(AtomicU64::new(0)),
                health_expiry: Arc::new(AtomicU64::new(0)),
                simulations: Arc::new(AtomicUsize::new(0)),
            })
            .mount(&mock)
            .await;
        for proof in [
            None,
            Some(X402ApprovalProof {
                nonce: "ignored".into(),
                attestation: "ignored".into(),
                expected_subject: [0; 32],
                governing_ttl_ms: 0,
            }),
        ] {
            let before = pre_sign_checks_on_this_thread();
            let result = call(&server, false, proof.as_ref()).await;
            assert_ne!(result.is_error, Some(true), "{}", value(&result));
            assert_eq!(pre_sign_checks_on_this_thread() - before, 0);
        }
        for (source, signature) in [
            (
                include_str!("x402_create_payment.rs"),
                concat!("async fn ", "mainnet_x402_payment("),
            ),
            (
                include_str!("x402_authenticated_payment.rs"),
                concat!("async fn ", "mainnet_authenticated_payment("),
            ),
        ] {
            stellar_agent_test_support::source_order::assert_not_called(
                "x402",
                source,
                signature,
                &["create_payment_with_pre_sign("],
            );
            stellar_agent_test_support::source_order::assert_not_called(
                "x402",
                source,
                signature,
                &["x402_pre_sign_check("],
            );
        }
    }

    fn child_server() -> Option<WalletServer> {
        let profile = std::env::var("X402_CHILD_PROFILE").ok()?;
        let profile = serde_json::from_str(&profile).unwrap();
        let mut server = WalletServer::new(profile).unwrap();
        server.set_approval_dir_for_test(std::env::var_os("X402_CHILD_APPROVALS").unwrap().into());
        Some(server)
    }

    #[test]
    #[ignore = "child helper requires an isolated approval fixture"]
    fn x402_spend_child() {
        let server = child_server().expect("child fixture");
        let nonce = std::env::var("X402_CHILD_NONCE").unwrap();
        let digit: u8 = std::env::var("X402_CHILD_DIGEST").unwrap().parse().unwrap();
        let result = spend_x402_approval(&server, &nonce, 120_000, &[digit; 32]);
        std::process::exit(if result.is_ok() { 0 } else { 17 });
    }

    #[tokio::test]
    #[ignore = "child helper requires an isolated approval fixture"]
    async fn x402_crash_child() {
        let server = child_server().expect("child fixture");
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let coord = &server.profile.audit_log_hash_chain_key_id;
        keyring_core::Entry::new(&coord.service, &coord.account)
            .unwrap()
            .set_password(&URL_SAFE_NO_PAD.encode([0x41; 32]))
            .unwrap();
        crate::tools::value_audit::require_value_audit_writer(
            &server.profile,
            &server.profile_name_for_approval(),
            server.audit_binding,
        )
        .unwrap();
        let terms: stellar_agent_x402::wire::PaymentRequirements =
            serde_json::from_str(&requirements()).unwrap();
        let leg = ValueLegRecord::from(&x402_value_leg(&terms, 10_000_000));
        let mut audit = X402AuthorizationAudit::new(
            &server,
            "stellar_x402_create_payment",
            "stellar:testnet",
            leg,
        )
        .with_approval_spend(X402ApprovalSpend {
            server: &server,
            nonce: std::env::var("X402_CHILD_NONCE").unwrap(),
            governing_ttl_ms: 120_000,
        });
        let mock = MockServer::start().await;
        let public = stellar_strkey::ed25519::PublicKey::from_string(
            &server.profile.mcp_signer_default.account,
        )
        .unwrap();
        Mock::given(wiremock::matchers::method("POST"))
            .respond_with(Rpc {
                payer: stellar_xdr::ScAddress::Account(stellar_xdr::AccountId(
                    stellar_xdr::PublicKey::PublicKeyTypeEd25519(stellar_xdr::Uint256(public.0)),
                )),
                clock: Arc::new(AtomicU64::new(0)),
                health_expiry: Arc::new(AtomicU64::new(0)),
                simulations: Arc::new(AtomicUsize::new(0)),
            })
            .mount(&mock)
            .await;
        let signer = stellar_agent_network::signing::SoftwareSigningKey::new_from_zeroizing(
            zeroize::Zeroizing::new([0x63; 32]),
        );
        let client = stellar_agent_network::StellarRpcClient::new(&mock.uri()).unwrap();
        let _ = stellar_agent_x402::exact::create_payment(
            &terms,
            &signer,
            &client,
            &SorobanCrossCheck::NotRequired,
            server.context.network_passphrase(),
            tokio::time::Instant::now() + std::time::Duration::from_secs(60),
            |authorization| audit.before_transmit(authorization),
        )
        .await;
        panic!("the crash boundary must terminate the child");
    }

    fn crash_case(boundary: &str) {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let fixture = crate::tools::message_signing_tests::Fixture::new();
        let mut server = fixture.server();
        server.set_approval_dir_for_test(fixture.dir.path().join("approvals"));
        let entry = pending(&server);
        server
            .x402_approval_store()
            .unwrap()
            .insert(entry.clone(), entry.created_at_unix_ms)
            .unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "tools::x402_create_payment::approval_tests::x402_crash_child",
            ])
            .env(
                "X402_CHILD_PROFILE",
                serde_json::to_string(&server.profile).unwrap(),
            )
            .env(
                "X402_CHILD_APPROVALS",
                server.resolve_approval_dir().unwrap(),
            )
            .env("X402_CHILD_NONCE", &entry.approval_nonce)
            .env("X402_CRASH_AFTER", boundary)
            .env(
                "X402_CHILD_TRANSMISSION",
                fixture.dir.path().join("transmitted"),
            )
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(73));
        assert!(
            !fixture.dir.path().join("transmitted").exists(),
            "a crash sends no signed RPC request"
        );
        let store = server.x402_approval_store().unwrap();
        let ApprovalKind::Consumed { tx_hash, .. } =
            &store.get(&entry.approval_nonce).unwrap().kind
        else {
            panic!("crash retains the durable spend");
        };
        assert_eq!(tx_hash.len(), 64);
        assert!(
            tx_hash
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        );
        drop(store);
        let log = std::fs::read_to_string(&server.profile.audit_log_path).unwrap_or_default();
        assert_eq!(log.contains("x402_payment_authorized"), boundary == "audit");
        assert!(
            !spawn_spend(&server, &entry.approval_nonce, 2)
                .wait()
                .unwrap()
                .success()
        );
    }

    #[test]
    #[serial_test::serial(keyring)]
    fn x402_crash_after_spend_prevents_retry_release() {
        crash_case("spend");
    }

    #[test]
    #[serial_test::serial(keyring)]
    fn x402_crash_after_audit_prevents_retry_release() {
        crash_case("audit");
    }

    fn spawn_spend(server: &WalletServer, nonce: &str, digit: u8) -> std::process::Child {
        std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--ignored")
            .arg("--exact")
            .arg("tools::x402_create_payment::approval_tests::x402_spend_child")
            .env(
                "X402_CHILD_PROFILE",
                serde_json::to_string(&server.profile).unwrap(),
            )
            .env(
                "X402_CHILD_APPROVALS",
                server.resolve_approval_dir().unwrap(),
            )
            .env("X402_CHILD_NONCE", nonce)
            .env("X402_CHILD_DIGEST", digit.to_string())
            .spawn()
            .unwrap()
    }

    #[test]
    #[serial_test::serial(keyring)]
    fn one_x402_approval_has_one_spend_winner() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let fixture = crate::tools::message_signing_tests::Fixture::new();
        for processes in [false, true] {
            let mut server = fixture.server();
            server.set_approval_dir_for_test(fixture.dir.path().join(format!("race-{processes}")));
            let entry = pending(&server);
            server
                .x402_approval_store()
                .unwrap()
                .insert(entry.clone(), entry.created_at_unix_ms)
                .unwrap();
            let results = if processes {
                let mut first = spawn_spend(&server, &entry.approval_nonce, 1);
                let mut second = spawn_spend(&server, &entry.approval_nonce, 2);
                [
                    first.wait().unwrap().success(),
                    second.wait().unwrap().success(),
                ]
            } else {
                let barrier = std::sync::Barrier::new(2);
                std::thread::scope(|scope| {
                    let first = scope.spawn(|| {
                        barrier.wait();
                        spend_x402_approval(&server, &entry.approval_nonce, 120_000, &[1; 32])
                            .is_ok()
                    });
                    let second = scope.spawn(|| {
                        barrier.wait();
                        spend_x402_approval(&server, &entry.approval_nonce, 120_000, &[2; 32])
                            .is_ok()
                    });
                    [first.join().unwrap(), second.join().unwrap()]
                })
            };
            assert_eq!(
                results.iter().filter(|ok| **ok).count(),
                1,
                "one approval has one spend winner"
            );
            let store = server.x402_approval_store().unwrap();
            let ApprovalKind::Consumed { tx_hash, .. } =
                &store.get(&entry.approval_nonce).unwrap().kind
            else {
                panic!("durable spend");
            };
            assert_eq!(
                tx_hash,
                &stellar_agent_core::hex::encode(&[if results[0] { 1 } else { 2 }; 32])
            );
            drop(store);
            assert!(
                spend_x402_approval(&server, &entry.approval_nonce, 120_000, &[3; 32]).is_err()
            );
        }
    }

    #[tokio::test]
    #[ignore = "child helper requires an isolated approval fixture"]
    async fn x402_private_directory_child() {
        let directory = std::env::var("X402_QUEUE_DIRECTORY").expect("child fixture");
        let home = tempfile::tempdir().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let mut server = super::tests::make_require_approval_server();
        server.set_approval_dir_for_test(directory.clone().into());
        assert!(!std::path::Path::new(&directory).exists());
        let result = call(&server, false, None).await;
        assert_ne!(result.is_error, Some(true), "{}", value(&result));
        assert!(value(&result)["data"]["approval"]["approval_nonce"].is_string());
        assert!(value(&result)["data"].get("paymentSignature").is_none());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        #[cfg(feature = "mainnet-write")]
        {
            use crate::tools::common::tests::mainnet::{Fixture, require_approval_rules};
            let mut fixture = Fixture::new(|raw| {
                require_approval_rules(&raw, &["stellar_x402_create_payment"], 600)
            });
            let path = std::path::Path::new(&directory).with_file_name("mainnet-approvals");
            assert!(!path.exists());
            fixture.server.set_approval_dir_for_test(path.clone());
            let result = fixture
                .server
                .call_stellar_x402_create_payment(X402CreatePaymentArgs {
                    payment_required: serde_json::to_string(&fixture.requirements()).unwrap(),
                    chain_id: "stellar:mainnet".into(),
                    address: None,
                    approval_nonce: None,
                    approval_attestation: None,
                    business_id: Some(crate::tools::common::tests::fresh_business_id()),
                })
                .await
                .unwrap();
            assert_ne!(result.is_error, Some(true), "{}", value(&result));
            assert!(value(&result)["data"]["approval"]["approval_nonce"].is_string());
            assert!(value(&result)["data"].get("paymentSignature").is_none());
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                assert_eq!(
                    std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                    0o700
                );
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn x402_queue_creates_a_private_approval_directory() {
        use std::os::unix::fs::PermissionsExt as _;
        let home = tempfile::tempdir().unwrap();
        let directory = home.path().join("nested").join("approvals");
        let status = std::process::Command::new("sh")
            .args(["-c", "umask 0; exec \"$@\"", "x402"])
            .arg(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "tools::x402_create_payment::approval_tests::x402_private_directory_child",
            ])
            .env("X402_QUEUE_DIRECTORY", &directory)
            .status()
            .unwrap();
        assert!(status.success());
        assert_eq!(
            std::fs::metadata(directory).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    fn pending(server: &WalletServer) -> PendingApproval {
        let requirements = serde_json::from_str(&requirements()).unwrap();
        let root = stellar_agent_x402::exact::payment_root(
            &requirements,
            &server.profile.mcp_signer_default.account,
        )
        .unwrap();
        let mut entry = PendingApproval::new_x402_pending(
            &sha2::Sha256::digest(server.context.network_passphrase().as_bytes()).into(),
            &root,
            None,
            stellar_agent_core::approval::process_uid_for_attestation().unwrap(),
            120_000,
        )
        .unwrap();
        entry.attestation_blob_b64 = Some(URL_SAFE_NO_PAD.encode([0x5a; 32]));
        entry
    }

    #[test]
    #[serial_test::serial(keyring)]
    fn spend_refuses_a_spent_approval() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let fixture = crate::tools::message_signing_tests::Fixture::new();
        let mut server = fixture.server();
        server.set_approval_dir_for_test(fixture.dir.path().join("approvals"));
        let entry = pending(&server);
        server
            .x402_approval_store()
            .unwrap()
            .insert(entry.clone(), entry.created_at_unix_ms)
            .unwrap();
        spend_x402_approval(&server, &entry.approval_nonce, 120_000, &[1; 32]).unwrap();
        let refusal =
            spend_x402_approval(&server, &entry.approval_nonce, 120_000, &[2; 32]).unwrap_err();
        assert_eq!(value(&refusal)["error"]["code"], "policy.approval_consumed");
        let store = server.x402_approval_store().unwrap();
        let ApprovalKind::Consumed { tx_hash, .. } =
            &store.get(&entry.approval_nonce).unwrap().kind
        else {
            panic!("spent");
        };
        assert_eq!(tx_hash, &stellar_agent_core::hex::encode(&[1; 32]));
    }

    #[test]
    #[serial_test::serial(keyring)]
    fn spend_refuses_what_is_not_a_live_attested_x402_approval() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let fixture = crate::tools::message_signing_tests::Fixture::new();
        for case in 0..8 {
            let mut server = fixture.server();
            server.set_approval_dir_for_test(fixture.dir.path().join(format!("approvals-{case}")));
            let mut entry = pending(&server);
            let time = entry.created_at_unix_ms + 120_000;
            server.clock = Arc::new(Clock(Arc::new(AtomicU64::new(time))));
            if case == 0 {
                entry.expires_at_unix_ms = time + 120_000;
            }
            if case == 2 {
                entry.attestation_blob_b64 = None;
                entry.expires_at_unix_ms = time + 120_000;
            }
            if case == 6 {
                entry.kind = ApprovalKind::TrustlineClawbackOptIn {
                    network: "stellar:testnet".into(),
                    code: "USD".into(),
                    issuer: "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF".into(),
                };
                entry.expires_at_unix_ms = time + 120_000;
            }
            let ttl = if case == 0 { 120_000 } else { 240_000 };
            let mut store = server.x402_approval_store().unwrap();
            if case != 3 {
                store
                    .insert(entry.clone(), entry.created_at_unix_ms)
                    .unwrap();
            }
            if case == 4 || case == 5 {
                store
                    .reject(
                        &entry.approval_nonce,
                        entry.created_at_unix_ms,
                        if case == 4 { 240_000 } else { 120_000 },
                    )
                    .unwrap();
            }
            drop(store);
            if case == 7 {
                server.clock = Arc::new(FailingClock);
            }
            let refusal =
                spend_x402_approval(&server, &entry.approval_nonce, ttl, &[1; 32]).unwrap_err();
            assert_eq!(
                value(&refusal)["error"]["code"],
                if case == 4 {
                    "policy.approval_rejected"
                } else {
                    "policy.approval_required"
                }
            );
            let store = server.x402_approval_store().unwrap();
            assert!(
                !store
                    .get(&entry.approval_nonce)
                    .is_some_and(|entry| matches!(entry.kind, ApprovalKind::Consumed { .. }))
            );
        }

        let mut server = fixture.server();
        server.set_approval_dir_for_test(fixture.dir.path().join("persistence"));
        let entry = pending(&server);
        let mut locked = server.x402_approval_store().unwrap();
        locked
            .insert(entry.clone(), entry.created_at_unix_ms)
            .unwrap();
        let refusal =
            spend_x402_approval(&server, &entry.approval_nonce, 120_000, &[1; 32]).unwrap_err();
        assert_eq!(value(&refusal)["error"]["code"], "policy.approval_required");
        assert!(matches!(
            locked.get(&entry.approval_nonce).unwrap().kind,
            ApprovalKind::X402Payment { .. }
        ));
        drop(locked);
        struct RenameFailureClock {
            path: std::path::PathBuf,
            preserved: std::path::PathBuf,
            now: u64,
        }
        impl stellar_agent_core::timefmt::Clock for RenameFailureClock {
            fn now_unix_ms(&self) -> Result<u64, stellar_agent_core::wallet::WalletLifecycleError> {
                std::fs::rename(&self.path, &self.preserved).unwrap();
                std::fs::create_dir(&self.path).unwrap();
                Ok(self.now)
            }
        }
        let path = server
            .resolve_approval_dir()
            .unwrap()
            .join(format!("{}.toml", server.profile_name_for_approval()));
        let preserved = path.with_extension("preserved");
        server.clock = Arc::new(RenameFailureClock {
            path,
            preserved: preserved.clone(),
            now: entry.created_at_unix_ms + 1,
        });
        let refusal =
            spend_x402_approval(&server, &entry.approval_nonce, 120_000, &[1; 32]).unwrap_err();
        assert_eq!(value(&refusal)["error"]["code"], "policy.approval_required");
        let store = stellar_agent_core::approval::PendingApprovalStore::open(preserved).unwrap();
        assert!(matches!(
            store.get(&entry.approval_nonce).unwrap().kind,
            ApprovalKind::X402Payment { .. }
        ));
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

    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn muxed_contract_payment_refuses_before_state() {
        let home = tempfile::tempdir().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let rpc = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(stellar_agent_test_support::EchoIdResponder::new(
                serde_json::json!({
                    "passphrase": stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE,
                    "protocolVersion": 29
                }),
            ))
            .mount(&rpc)
            .await;
        let mut server = make_require_approval_server();
        server.context =
            stellar_agent_network::NetworkContext::new(server.profile.chain_id, rpc.uri());
        let mut requirements: serde_json::Value =
            serde_json::from_str(&sample_requirements_json()).unwrap();
        requirements["payTo"] = serde_json::json!(
            stellar_agent_test_support::xdr_fixtures::muxed_contract_address().to_string()
        );
        let before = std::fs::read_dir(home.path()).unwrap().count();
        let result = server
            .call_stellar_x402_create_payment(X402CreatePaymentArgs {
                payment_required: requirements.to_string(),
                chain_id: "stellar:testnet".to_owned(),
                address: None,
                business_id: None,
                approval_nonce: None,
                approval_attestation: None,
            })
            .await
            .unwrap();
        let (code, message, text) = crate::tools::common::assert_business_envelope(&result);
        assert_eq!(code, "x402.muxed_contract_protocol_unsupported");
        assert_eq!(
            message,
            "a W (muxed contract) payee requires Stellar protocol 30 or later; the network reports protocol 29"
        );
        assert!(!text.contains("paymentSignature"));
        assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), before);
    }

    #[cfg(feature = "mainnet-write")]
    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn muxed_contract_mainnet_payment_refuses_before_state() {
        use crate::tools::common::tests::mainnet::{
            authorizations, mount_rpc, routed_fixture, x402_args,
        };
        let rpc = wiremock::MockServer::start().await;
        let f = routed_fixture(|raw| raw, &rpc);
        let control = mount_rpc(&f, &rpc).await;
        let mut args = x402_args(&f, None);
        let mut requirements = f.requirements();
        requirements.pay_to =
            stellar_agent_test_support::xdr_fixtures::muxed_contract_address().to_string();
        args.payment_required = serde_json::to_string(&requirements).unwrap();
        let result = f
            .server
            .call_stellar_x402_create_payment(args)
            .await
            .unwrap();
        let (code, message, _) = crate::tools::common::assert_business_envelope(&result);
        assert_eq!(code, "x402.muxed_contract_protocol_unsupported");
        assert_eq!(
            message,
            "a W (muxed contract) payee requires Stellar protocol 30 or later; the network reports protocol 29"
        );
        assert_eq!(control.count("simulateTransaction"), 0);
        assert_eq!(f.seed_reads.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(authorizations(&f).is_empty());
    }

    fn sample_requirements_json() -> String {
        serde_json::json!({
            "scheme": "exact",
            "network": "stellar:testnet",
            "asset": "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA",
            "amount": "1000000",
            "payTo": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
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
            X402Error::UnsupportedScheme,
            X402Error::UnsupportedNetwork,
            X402Error::NetworkPassphraseMismatch,
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
            X402Error::EndpointIdentity(stellar_agent_core::error::WalletError::Network(
                stellar_agent_core::error::NetworkError::MainnetWriteForbidden,
            )),
            X402Error::CrossCheck(stellar_agent_core::error::WalletError::Network(
                stellar_agent_core::error::NetworkError::WitnessDivergence {
                    entry: stellar_agent_core::cross_check::WitnessEntry::SorobanSimulation,
                    field: stellar_agent_core::cross_check::WitnessField::Address,
                    sequence_delta: None,
                },
            )),
        ];
        assert_eq!(classify_x402_error(&cases[cases.len() - 1]), "cross_check");
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

    #[cfg(feature = "mainnet-write")]
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
        for failure in [
            X402Failure::Encoding,
            X402Failure::PayloadRelease,
            X402Failure::TerminalApproval,
        ] {
            assert_eq!(x402_withheld_stage(false, failure), None);
        }
    }

    #[cfg(feature = "mainnet-write")]
    #[test]
    fn withheld_stage_pins_every_failure_to_its_stage() {
        use stellar_agent_x402::X402Error;
        let simulate = X402Error::RpcSimulateFailed {
            detail: "re-simulate returned error".to_owned(),
        };
        let other = X402Error::TransactionBuildFailed {
            detail: "re-simulate transaction_data decode failed".to_owned(),
        };
        for (failure, stage) in [
            (X402Failure::CreatePayment(&simulate), "resimulation"),
            (X402Failure::CreatePayment(&other), "response_processing"),
            (X402Failure::Encoding, "encoding"),
            (X402Failure::PayloadRelease, "payload_release"),
            (X402Failure::TerminalApproval, "terminal_approval"),
        ] {
            assert_eq!(
                x402_withheld_stage(true, failure),
                Some(stage),
                "{failure:?}"
            );
        }
    }

    /// Before the child authorization is consumed the handler invalidates it
    /// at the payload release stage; after it is consumed nothing is
    /// invalidated. Every failure withholds the payload under its own stage.
    #[cfg(feature = "mainnet-write")]
    #[test]
    fn mainnet_release_failures_select_cleanup_and_withheld_stage() {
        use stellar_agent_network::mainnet::resolve::InvalidationStage;
        for (failure, cleanup, stage, withheld_at) in [
            (
                ReleaseFailure::Encoding,
                Some(InvalidationStage::PayloadReleaseRefused),
                "encoding",
                "at payload encoding",
            ),
            (
                ReleaseFailure::ReleaseConsume,
                Some(InvalidationStage::PayloadReleaseRefused),
                "payload_release",
                "at payload release",
            ),
            (
                ReleaseFailure::TerminalApproval,
                None,
                "terminal_approval",
                "at terminal approval",
            ),
        ] {
            let decision = release_decision(failure);
            assert_eq!(
                format!("{:?}", decision.cleanup),
                format!("{cleanup:?}"),
                "{failure:?}"
            );
            assert_eq!(
                x402_withheld_stage(true, decision.withheld),
                Some(stage),
                "{failure:?}"
            );
            assert_eq!(decision.withheld_at, withheld_at, "{failure:?}");
        }
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

    /// A refused consumption of the mainnet payment intent, as
    /// `consume_soroban_intent` returns it after the transmit gate and before
    /// the signed re-simulation request, is withheld at `response_processing`
    /// under its own code, with a message that names the withholding after
    /// intent authorization.
    #[cfg(feature = "mainnet-write")]
    #[test]
    fn withheld_stage_names_a_refused_intent_consumption_response_processing() {
        use stellar_agent_network::mainnet::{MainnetAuthorizationError, MainnetPrecondition};
        for precondition in [
            MainnetPrecondition::IntentDigest,
            MainnetPrecondition::StoreUnavailable,
        ] {
            let error = stellar_agent_x402::X402Error::from(MainnetAuthorizationError::Refused(
                precondition,
            ));
            assert_eq!(
                x402_withheld_stage(true, X402Failure::CreatePayment(&error)),
                Some("response_processing"),
                "{precondition:?}"
            );
            let result = mainnet_x402_error(&error, "after intent authorization", None);
            assert_eq!(result.is_error, Some(true), "{precondition:?}");
            let wire: serde_json::Value =
                serde_json::from_str(&result.content[0].as_text().unwrap().text).unwrap();
            assert_eq!(
                wire["error"]["code"], "network.mainnet_authorization_refused",
                "{wire}"
            );
            assert!(
                wire["error"]["message"]
                    .as_str()
                    .unwrap()
                    .starts_with("payment withheld after intent authorization: "),
                "{wire}"
            );
        }
    }

    /// A reply before the transmit gate names no transmitted authorization.
    /// Every error reply after it, at each stage, ends with the sentence
    /// naming the signature expiration ledger and keeps its code and its
    /// prefix.
    #[cfg(feature = "mainnet-write")]
    #[test]
    fn post_gate_replies_name_the_transmitted_authorization() {
        use stellar_agent_network::mainnet::{MainnetAuthorizationError, MainnetPrecondition};
        const SENTENCE: &str = "; the signed authorization may have reached the configured RPC \
                                and is valid through ledger 1060";
        let refused = stellar_agent_x402::X402Error::from(MainnetAuthorizationError::Refused(
            MainnetPrecondition::NotOpen,
        ));
        let build = stellar_agent_x402::X402Error::TransactionBuildFailed {
            detail: "envelope".to_owned(),
        };
        let message = |result: &CallToolResult| {
            let (code, message, _) = crate::tools::common::assert_business_envelope(result);
            (code, message)
        };

        let (code, before) = message(&mainnet_x402_error(
            &build,
            "before signed transmission",
            None,
        ));
        assert_eq!(code, "x402.transaction_build_failed");
        assert!(!before.contains("valid through ledger"), "{before}");

        let mut stages = vec![(
            mainnet_x402_error(&refused, "after intent authorization", Some(1060)),
            "network.mainnet_authorization_refused",
            "payment withheld after intent authorization: ",
        )];
        for (failure, error, code) in [
            (
                ReleaseFailure::Encoding,
                &build,
                "x402.transaction_build_failed",
            ),
            (
                ReleaseFailure::ReleaseConsume,
                &refused,
                "network.mainnet_authorization_refused",
            ),
        ] {
            let withheld_at = release_decision(failure).withheld_at;
            stages.push((
                mainnet_x402_error(error, withheld_at, Some(1060)),
                code,
                match failure {
                    ReleaseFailure::Encoding => "payment withheld at payload encoding: ",
                    _ => "payment withheld at payload release: ",
                },
            ));
        }
        let terminal = stellar_agent_core::WalletError::from(
            stellar_agent_core::error::NetworkError::MainnetAuthorizationRefused,
        );
        stages.push((
            terminal_approval_error(
                &terminal,
                release_decision(ReleaseFailure::TerminalApproval).withheld_at,
                Some(1060),
            ),
            "network.mainnet_authorization_refused",
            "payment withheld at terminal approval: ",
        ));
        for (result, expected_code, prefix) in &stages {
            let (code, text) = message(result);
            assert_eq!(code, *expected_code, "{text}");
            assert!(text.starts_with(prefix), "{text}");
            assert!(text.ends_with(SENTENCE), "{text}");
        }
        assert_eq!(transmitted_authorization(None), "");
        assert_eq!(transmitted_authorization(Some(1060)), SENTENCE);
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
            _now_ms: u64,
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
            _now_ms: u64,
        ) -> Result<Decision, PolicyError> {
            Ok(Decision::Deny(DenyReason::NoMatchingRule))
        }
    }

    pub(super) fn make_require_approval_server() -> crate::server::WalletServer {
        use std::sync::Arc;
        let profile = Profile::builder_testnet(
            "svc",
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
            "n-svc",
            "n-acct",
        )
        .with_noop_engine()
        .build();
        // Queueing requires no signer, attestation, or audit key.
        let mut server = crate::server::WalletServer::new(profile)
            .expect("WalletServer::new must not fail in tests");
        server.policy_engine = Arc::new(RequireApprovalEngine);
        server
    }

    /// A Noop-engine mainnet server over a fresh mock keyring store; callers
    /// hold the `keyring` serial key.
    fn make_mainnet_server() -> crate::server::WalletServer {
        stellar_agent_test_support::keyring_mock::install().expect("mock keyring");
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
            approval_nonce: None,
            approval_attestation: None,
            chain_id: "stellar:mainnet".to_owned(),
            payment_required: sample_requirements_json(),
            address: None,
            business_id: Some(crate::tools::common::tests::fresh_business_id()),
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

    /// Queueing requires no keys and persists the complete payment intent.
    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn require_approval_verdict_queues_the_payment_and_signs_nothing() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let home = tempfile::tempdir().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
        let mut server = make_require_approval_server();
        server.set_approval_dir_for_test(home.path().join("approvals"));
        let result = server
            .call_stellar_x402_create_payment(X402CreatePaymentArgs {
                approval_nonce: None,
                approval_attestation: None,
                chain_id: "stellar:testnet".to_owned(),
                address: None,
                business_id: None,
                payment_required: sample_requirements_json(),
            })
            .await
            .unwrap();
        let text = &result.content[0].as_text().unwrap().text;
        let value: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_ne!(result.is_error, Some(true), "{value}");
        let approval = &value["data"]["approval"];
        assert!(approval.get("endpoint_host").is_none());
        assert!(!text.contains("paymentSignature"));
        let requirements: serde_json::Value =
            serde_json::from_str(&sample_requirements_json()).unwrap();
        for field in ["payTo", "amount", "asset"] {
            assert_eq!(approval["summary"][field], requirements[field]);
        }
        let store = server.x402_approval_store().unwrap();
        let entry = store
            .get(approval["approval_nonce"].as_str().unwrap())
            .unwrap();
        assert_eq!(entry.expires_at_unix_ms, entry.created_at_unix_ms + 120_000);
        let stellar_agent_core::approval::ApprovalKind::X402Payment { home_domain, .. } =
            &entry.kind
        else {
            panic!("queue must persist an x402 approval");
        };
        assert_eq!(home_domain.as_deref(), None);
        assert!(!server.profile.audit_log_path.exists());
    }

    /// Half proofs refuse without creating an approval.
    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn require_approval_half_proof_is_refused() {
        stellar_agent_test_support::keyring_mock::install().ok();
        let home = tempfile::tempdir().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
        let mut server = make_require_approval_server();
        server.set_approval_dir_for_test(home.path().join("approvals"));
        for (nonce, attestation) in [
            (Some("approval-nonce"), None),
            (None, Some("approval-attestation")),
        ] {
            let result = server
                .call_stellar_x402_create_payment(X402CreatePaymentArgs {
                    approval_nonce: nonce.map(str::to_owned),
                    approval_attestation: attestation.map(str::to_owned),
                    chain_id: "stellar:testnet".to_owned(),
                    payment_required: sample_requirements_json(),
                    address: None,
                    business_id: None,
                })
                .await
                .unwrap();
            let (code, _message, text) = crate::tools::common::assert_business_envelope(&result);
            assert_eq!(code, "policy.approval_required", "{text}");
            assert!(!text.contains("\"paymentSignature\""), "{text}");
            assert!(server.x402_approval_store().unwrap().is_empty());
        }
    }

    /// The testnet payment's authorized row records the policy's `Allow`.
    #[test]
    #[serial_test::serial(keyring)]
    fn testnet_authorized_row_records_the_allow_decision() {
        stellar_agent_test_support::keyring_mock::install().ok();
        let server = make_require_approval_server();
        let requirements =
            stellar_agent_x402::wire::decode_payment_required(&base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                sample_requirements_json(),
            ))
            .unwrap();
        let leg = x402_value_leg(&requirements, 10_000_000);
        let mut audit = X402AuthorizationAudit::new(
            &server,
            "stellar_x402_create_payment",
            "stellar:testnet",
            ValueLegRecord::from(&leg),
        );
        let row = serde_json::to_value(audit.authorized_row(
            &requirements.network,
            &requirements.scheme,
            None,
            None,
        ))
        .unwrap();
        assert_eq!(row["policy_decision"], "allow");
    }

    /// `Debug` shows whether the attestation is set and never its value.
    #[test]
    fn args_debug_hides_the_attestation() {
        let args = X402CreatePaymentArgs {
            approval_nonce: Some("approval-nonce".to_owned()),
            approval_attestation: Some("SENTINEL-ATTESTATION".to_owned()),
            chain_id: "stellar:mainnet".to_owned(),
            payment_required: "payment-required".to_owned(),
            address: Some("GADDRESS".to_owned()),
            business_id: Some(crate::tools::common::tests::fresh_business_id()),
        };
        let printed = format!("{args:?}");
        assert!(!printed.contains("SENTINEL-ATTESTATION"), "{printed}");
        assert!(
            printed.contains("approval_attestation: Some(<set>)"),
            "{printed}"
        );
        for field in [
            "approval-nonce",
            "stellar:mainnet",
            "payment-required",
            "GADDRESS",
        ] {
            assert!(printed.contains(field), "{printed}");
        }
        let absent = X402CreatePaymentArgs {
            approval_attestation: None,
            ..args
        };
        assert!(format!("{absent:?}").contains("approval_attestation: None"));
    }

    /// An address argument that differs from the profile signer is refused by
    /// the field and the configured signer, without the argument.
    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn x402_address_marker_is_not_echoed() {
        use stellar_agent_test_support::rejected_value::{
            CREDENTIAL_MARKER, assert_no_marker_in_text,
        };

        stellar_agent_test_support::keyring_mock::install().unwrap();
        let fixture = crate::tools::message_signing_tests::Fixture::new();
        fixture.seed_audit();
        let result = fixture
            .server()
            .call_stellar_x402_create_payment(X402CreatePaymentArgs {
                approval_nonce: None,
                approval_attestation: None,
                chain_id: "stellar:testnet".to_owned(),
                payment_required: sample_requirements_json(),
                address: Some(CREDENTIAL_MARKER.to_owned()),
                business_id: None,
            })
            .await
            .expect("the mismatch is a business envelope");
        let (code, message, text) = crate::tools::common::assert_business_envelope(&result);
        assert_eq!(code, "x402.invalid_payment_required");
        assert_eq!(
            message,
            format!(
                "invalid payment-required: the address argument does not match the profile \
                 signer {}",
                fixture.account
            )
        );
        assert_no_marker_in_text(&text, CREDENTIAL_MARKER);
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
            approval_nonce: None,
            approval_attestation: None,
            chain_id: "stellar:testnet".to_owned(),
            payment_required: sample_requirements_json(),
            address: None,
            business_id: None,
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
    #[cfg(feature = "mainnet-write")]
    #[test]
    fn mainnet_terminal_consumption_requires_a_present_record() {
        assert!(require_terminal_consumption(Ok(true)).is_ok());
        assert_eq!(
            require_terminal_consumption(Ok(false)).unwrap_err().code(),
            "network.mainnet_authorization_refused"
        );
        let error = stellar_agent_core::error::NetworkError::MainnetWriteForbidden.into();
        assert!(require_terminal_consumption(Err(error)).is_err());
    }

    #[test]
    fn mainnet_approval_schema_keeps_fields_optional() {
        let schema = serde_json::to_value(schemars::schema_for!(X402CreatePaymentArgs)).unwrap();
        let properties = schema["properties"].as_object().unwrap();
        assert!(properties.contains_key("approval_nonce"));
        assert!(properties.contains_key("approval_attestation"));
        let required = schema["required"].as_array().unwrap();
        assert_eq!(required.len(), 2);
        assert!(required.contains(&json!("payment_required")));
        assert!(required.contains(&json!("chain_id")));
    }

    #[cfg(feature = "mainnet-write")]
    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn mainnet_preparation_persists_intent_without_rpc_or_signing() {
        use crate::tools::common::tests::mainnet::Fixture;
        use std::sync::atomic::Ordering;
        use stellar_agent_core::approval::{ApprovalKind, PendingApprovalStore};
        let f = Fixture::new(|raw| {
            crate::tools::common::tests::mainnet::require_approval_rules(
                &raw,
                &["stellar_x402_create_payment"],
                600,
            )
        });
        let requirements = f.requirements();
        let clients = stellar_agent_network::client::constructions_on_this_thread();
        let business_id = crate::tools::common::tests::fresh_business_id();
        let result = f
            .server
            .call_stellar_x402_create_payment(X402CreatePaymentArgs {
                payment_required: serde_json::to_string(&requirements).unwrap(),
                chain_id: "stellar:mainnet".to_owned(),
                address: None,
                approval_nonce: None,
                approval_attestation: None,
                business_id: Some(business_id.clone()),
            })
            .await
            .unwrap();
        assert_ne!(result.is_error, Some(true));
        let text = result.content[0].as_text().unwrap().text.clone();
        let wire: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(wire["ok"], true, "{wire}");
        let data = wire["data"].as_object().unwrap();
        assert_eq!(
            data.keys().collect::<Vec<_>>(),
            ["approval", "business_id"],
            "{wire}"
        );
        assert_eq!(wire["data"]["business_id"], business_id.as_str());
        assert!(wire["data"].get("paymentSignature").is_none());
        assert_eq!(
            clients,
            stellar_agent_network::client::constructions_on_this_thread()
        );
        assert_eq!(f.seed_reads.load(Ordering::SeqCst), 0);
        assert!(
            !f.server.window_store.exists()
                || crate::tools::common::tests::mainnet::authorizations(&f).is_empty(),
            "nothing is authorized, so nothing can be signed"
        );
        let approval = &wire["data"]["approval"];
        let mut fields = approval
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        fields.sort();
        assert_eq!(
            fields,
            [
                "approval_nonce",
                "chain_id",
                "endpoint_host",
                "expires_at_unix_ms",
                "instructions",
                "profile",
                "reason",
                "signer",
                "summary"
            ]
        );
        assert_eq!(approval["profile"], "operator");
        assert_eq!(approval["chain_id"], "stellar:mainnet");
        assert_eq!(approval["endpoint_host"], "rpc.example.invalid");
        assert_eq!(approval["signer"], f.envelope.source());
        assert_eq!(
            approval["summary"],
            json!({"payTo": requirements.pay_to, "amount": requirements.amount,
                "asset": requirements.asset})
        );
        let store = PendingApprovalStore::open(
            f.server
                .resolve_approval_dir()
                .unwrap()
                .join("operator.toml"),
        )
        .unwrap();
        let entry = store
            .get(approval["approval_nonce"].as_str().unwrap())
            .unwrap();
        assert_eq!(approval["expires_at_unix_ms"], entry.expires_at_unix_ms);
        assert_eq!(approval["reason"], "operator review");
        assert!(approval["instructions"].as_str().unwrap().contains(
            &stellar_agent_core::approval::approve_hint(&entry.approval_nonce, "operator"),
        ));
        let ApprovalKind::X402Payment {
            intent_digest,
            root_invocation_xdr,
            home_domain,
            amount,
            ..
        } = &entry.kind
        else {
            panic!("wrong pending kind")
        };
        assert!(home_domain.is_none());
        assert_eq!(amount, "10");
        assert_eq!(
            *intent_digest,
            stellar_agent_x402::exact::intent_digest(&requirements, f.envelope.source()).unwrap()
        );
        use stellar_xdr::WriteXdr as _;
        assert_eq!(
            *root_invocation_xdr,
            stellar_agent_x402::exact::payment_root(&requirements, f.envelope.source())
                .unwrap()
                .to_xdr_base64(stellar_xdr::Limits::none())
                .unwrap()
        );
        assert_eq!(entry.expires_at_unix_ms - entry.created_at_unix_ms, 600_000);
        assert_eq!(entry.reason.as_deref(), Some("operator review"));
    }

    #[cfg(feature = "mainnet-write")]
    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn mainnet_partial_approval_and_minimum_reserve_persist_nothing() {
        use crate::tools::common::tests::mainnet::Fixture;
        let f = Fixture::new(|raw| raw);
        for (nonce, attestation) in [(Some("partial"), None), (None, Some("partial"))] {
            let result = f
                .server
                .call_stellar_x402_create_payment(X402CreatePaymentArgs {
                    payment_required: serde_json::to_string(&f.requirements()).unwrap(),
                    chain_id: "stellar:mainnet".to_owned(),
                    address: None,
                    approval_nonce: nonce.map(str::to_owned),
                    approval_attestation: attestation.map(str::to_owned),
                    business_id: Some(crate::tools::common::tests::fresh_business_id()),
                })
                .await
                .unwrap();
            assert_eq!(
                crate::tools::common::assert_business_envelope(&result).0,
                "policy.approval_required"
            );
            assert!(
                !f.server
                    .resolve_approval_dir()
                    .unwrap()
                    .join("operator.toml")
                    .exists()
            );
        }
        drop(f);
        let f = Fixture::new(|raw| {
            raw.replace(
                "criteria = [",
                "criteria = [ { kind = \"minimum_reserve\", margin_stroops = 0 },",
            )
        });
        let clients = stellar_agent_network::client::constructions_on_this_thread();
        let result = f
            .server
            .call_stellar_x402_create_payment(X402CreatePaymentArgs {
                payment_required: serde_json::to_string(&f.requirements()).unwrap(),
                chain_id: "stellar:mainnet".to_owned(),
                address: None,
                approval_nonce: None,
                approval_attestation: None,
                business_id: Some(crate::tools::common::tests::fresh_business_id()),
            })
            .await
            .unwrap();
        assert_eq!(
            crate::tools::common::assert_business_envelope(&result).0,
            "policy.engine_required"
        );
        assert_eq!(
            clients,
            stellar_agent_network::client::constructions_on_this_thread()
        );
        assert!(
            !f.server
                .resolve_approval_dir()
                .unwrap()
                .join("operator.toml")
                .exists()
        );
    }

    #[cfg(feature = "mainnet-write")]
    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn mainnet_x402_witness_binds_the_plain_intent() {
        use crate::tools::common::{
            GatedApprovalKind, tests::mainnet::Fixture, verify_attestation_subject_gate,
        };
        use sha2::Digest as _;
        use stellar_agent_core::approval::{
            PendingApproval, process_uid_for_attestation, subject::approval_subject_x402,
        };
        let f = Fixture::new(|raw| {
            crate::tools::common::tests::mainnet::require_approval_rules(
                &raw,
                &["stellar_x402_create_payment"],
                600,
            )
        });
        let requirements = f.requirements();
        let root =
            stellar_agent_x402::exact::payment_root(&requirements, f.envelope.source()).unwrap();
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
                &json!({"chain_id":"stellar:mainnet"}),
                "stellar:mainnet",
                ValueClass::single(x402_value_leg(&requirements, 10)),
                stellar_agent_core::mainnet::decision::EvaluationScope::Classic,
            )
            .await
            .unwrap();
        let digest =
            stellar_agent_x402::exact::intent_digest(&requirements, f.envelope.source()).unwrap();
        let witness = verify_attestation_subject_gate(
            &f.server,
            &outcome,
            GatedApprovalKind::X402.expectation(approval_subject_x402(&digest)),
            Some(&entry.approval_nonce),
            Some(&blob),
            "stellar_x402_create_payment",
        )
        .await
        .unwrap();
        assert!(witness.is_some());
        let mut audit = X402AuthorizationAudit::new(
            &f.server,
            "stellar_x402_create_payment",
            "stellar:mainnet",
            ValueLegRecord::from(&x402_value_leg(&requirements, 10)),
        )
        .with_decision(PolicyDecision::RequireApproval);
        let row = serde_json::to_value(audit.authorized_row(
            &requirements.network,
            &requirements.scheme,
            None,
            None,
        ))
        .unwrap();
        assert_eq!(row["policy_decision"], "require_approval");
    }
    #[cfg(feature = "mainnet-write")]
    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn mainnet_x402_gate_refuses_changed_intents_and_authenticated_subjects() {
        use crate::tools::common::{
            GatedApprovalKind, tests::mainnet::Fixture, verify_attestation_subject_gate,
        };
        use sha2::Digest as _;
        use stellar_agent_core::approval::{
            PendingApproval, process_uid_for_attestation, subject::approval_subject_x402,
        };
        let f = Fixture::new(|raw| {
            crate::tools::common::tests::mainnet::require_approval_rules(
                &raw,
                &["stellar_x402_create_payment"],
                600,
            )
        });
        let requirements = f.requirements();
        let root =
            stellar_agent_x402::exact::payment_root(&requirements, f.envelope.source()).unwrap();
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
                &json!({"chain_id":"stellar:mainnet"}),
                "stellar:mainnet",
                ValueClass::single(x402_value_leg(&requirements, 10)),
                stellar_agent_core::mainnet::decision::EvaluationScope::Classic,
            )
            .await
            .unwrap();
        let original =
            stellar_agent_x402::exact::intent_digest(&requirements, f.envelope.source()).unwrap();
        let check = |subject, kind: GatedApprovalKind, nonce: String, blob: String| {
            let server = &f.server;
            let outcome = &outcome;
            async move {
                verify_attestation_subject_gate(
                    server,
                    outcome,
                    kind.expectation(subject),
                    Some(&nonce),
                    Some(&blob),
                    "stellar_x402_create_payment",
                )
                .await
            }
        };
        assert!(
            check(
                approval_subject_x402(&original),
                GatedApprovalKind::X402,
                entry.approval_nonce.clone(),
                blob.clone()
            )
            .await
            .unwrap()
            .is_some()
        );
        let clients = stellar_agent_network::client::constructions_on_this_thread();
        for field in ["payer", "payee", "amount", "asset", "network"] {
            let mut changed = requirements.clone();
            let mut payer = f.envelope.source().to_owned();
            match field {
                "payer" => payer = f.envelope.destination().to_owned(),
                "payee" => changed.pay_to = f.envelope.source().to_owned(),
                "amount" => changed.amount = "11".to_owned(),
                "asset" => {
                    changed.asset = stellar_strkey::Contract([4; 32]).to_string().to_string()
                }
                "network" => changed.network = "stellar:testnet".to_owned(),
                _ => unreachable!(),
            }
            let digest = stellar_agent_x402::exact::intent_digest(&changed, &payer).unwrap();
            let refusal = check(
                approval_subject_x402(&digest),
                GatedApprovalKind::X402,
                entry.approval_nonce.clone(),
                blob.clone(),
            )
            .await
            .unwrap_err();
            assert_eq!(
                crate::tools::common::assert_business_envelope(&refusal).0,
                "policy.approval_required",
                "{field}"
            );
        }
        for (kind, presented) in [
            (GatedApprovalKind::Payment, blob.clone()),
            (GatedApprovalKind::X402, "A".repeat(43)),
        ] {
            let refusal = check(
                approval_subject_x402(&original),
                kind,
                entry.approval_nonce.clone(),
                presented,
            )
            .await
            .unwrap_err();
            assert_eq!(
                crate::tools::common::assert_business_envelope(&refusal).0,
                "policy.approval_required"
            );
        }
        for home in [None, Some("example.invalid".to_owned())] {
            let mut stored_root = root.clone();
            if home.is_none() {
                stored_root.sub_invocations = vec![root.clone()].try_into().unwrap();
            }
            let changed = PendingApproval::new_x402_pending(
                &network_id,
                &stored_root,
                home,
                process_uid_for_attestation().unwrap(),
                600_000,
            )
            .unwrap();
            let changed_blob = f.attest(&changed);
            let refusal = check(
                approval_subject_x402(&original),
                GatedApprovalKind::X402,
                changed.approval_nonce,
                changed_blob,
            )
            .await
            .unwrap_err();
            assert_eq!(
                crate::tools::common::assert_business_envelope(&refusal).0,
                "policy.approval_required"
            );
        }
        // An x402 approval cannot be attested for another chain at all: core
        // recomputes the stored invocation's digest under the binding's
        // network. Another profile's binding attests and the gate refuses it.
        for (profile_name, chain) in [("other", "stellar:mainnet")] {
            let bound = PendingApproval::new_x402_pending(
                &network_id,
                &root,
                None,
                process_uid_for_attestation().unwrap(),
                600_000,
            )
            .unwrap();
            let bound_blob = f.attest_bound(&bound, profile_name, chain);
            let refusal = check(
                approval_subject_x402(&original),
                GatedApprovalKind::X402,
                bound.approval_nonce,
                bound_blob,
            )
            .await
            .unwrap_err();
            assert_eq!(
                crate::tools::common::assert_business_envelope(&refusal).0,
                "policy.approval_required",
                "{profile_name} {chain}"
            );
        }
        struct FixedClock(u64);
        impl stellar_agent_core::timefmt::Clock for FixedClock {
            fn now_unix_ms(&self) -> Result<u64, stellar_agent_core::wallet::WalletLifecycleError> {
                Ok(self.0)
            }
        }
        let mut expired = f.server.clone();
        expired.clock = std::sync::Arc::new(FixedClock(entry.expires_at_unix_ms));
        let refusal = verify_attestation_subject_gate(
            &expired,
            &outcome,
            GatedApprovalKind::X402.expectation(approval_subject_x402(&original)),
            Some(&entry.approval_nonce),
            Some(&blob),
            "stellar_x402_create_payment",
        )
        .await
        .unwrap_err();
        assert_eq!(
            crate::tools::common::assert_business_envelope(&refusal).0,
            "policy.approval_required"
        );
        assert_eq!(f.seed_reads.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(
            clients,
            stellar_agent_network::client::constructions_on_this_thread()
        );
    }

    /// Each argument of the payment call can change only into a refusal
    /// before the intent is minted, with no payment request and no seed read.
    #[cfg(feature = "mainnet-write")]
    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn mainnet_payment_call_refuses_tampered_arguments_without_payment_rpc() {
        use crate::tools::common::tests::mainnet::{X402Run, authorizations, x402_args};
        let run = X402Run::new().await;
        let other_contract = stellar_strkey::Contract([4; 32]).to_string().to_string();
        for (field, code) in [
            ("amount", "policy.approval_required"),
            ("payTo", "policy.deny.counterparty_denied"),
            ("asset", "policy.deny.asset_not_allowlisted"),
            ("address", "x402.invalid_payment_required"),
            ("approval_nonce", "policy.approval_required"),
            ("approval_attestation", "policy.approval_required"),
        ] {
            let mut args = x402_args(&run.f, Some((&run.nonce, &run.attestation)));
            let mut requirements = run.f.requirements();
            match field {
                "amount" => requirements.amount = "11".to_owned(),
                "payTo" => requirements.pay_to = run.f.envelope.source().to_owned(),
                "asset" => requirements.asset = other_contract.clone(),
                "address" => args.address = Some(run.f.envelope.destination().to_owned()),
                "approval_nonce" => {
                    args.approval_nonce = Some(base64::Engine::encode(
                        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                        uuid::Uuid::new_v4().as_bytes(),
                    ));
                }
                "approval_attestation" => args.approval_attestation = Some("A".repeat(43)),
                _ => unreachable!(),
            }
            args.payment_required = serde_json::to_string(&requirements).unwrap();
            let result = run.pay_with(args).await;
            assert_eq!(result["ok"], false, "{field}: {result}");
            assert_eq!(result["error"]["code"], code, "{field}: {result}");
            assert!(run.control.methods().is_empty(), "{field}");
            assert!(authorizations(&run.f).is_empty(), "{field}");
            assert_eq!(
                run.f.seed_reads.load(std::sync::atomic::Ordering::SeqCst),
                0
            );
        }
        let mut args = x402_args(&run.f, Some((&run.nonce, &run.attestation)));
        args.chain_id = "stellar:testnet".to_owned();
        let error = run
            .f
            .server
            .call_stellar_x402_create_payment(args)
            .await
            .unwrap_err();
        assert_eq!(error.code, rmcp::model::ErrorCode::INVALID_PARAMS);
        assert!(run.control.methods().is_empty());
        assert_eq!(
            run.pay().await["ok"],
            true,
            "the untampered call still pays"
        );
    }

    #[cfg(feature = "mainnet-write")]
    #[test]
    fn mainnet_error_keeps_the_withholding_stage_and_redacts_policy_values() {
        let address = stellar_strkey::ed25519::PublicKey([9; 32])
            .to_string()
            .to_string();
        let error = stellar_agent_x402::X402Error::MainnetAuthorization(
            stellar_agent_network::mainnet::MainnetAuthorizationError::PolicyDenied(Box::new(
                stellar_agent_core::policy::DenyReason::CounterpartyDenied {
                    kind: "ADDRESS".to_owned(),
                    value: address.clone(),
                },
            )),
        );
        let result = mainnet_x402_error(&error, "before signed transmission", None);
        let (code, message, _) = crate::tools::common::assert_business_envelope(&result);
        assert_eq!(code, "policy.deny.counterparty_denied");
        assert!(message.starts_with("payment withheld before signed transmission: "));
        assert!(!message.contains(&address));
    }

    /// A requirement asset that is not a canonical contract strkey is refused
    /// by the field and the expected form, without the asset text.
    #[test]
    fn x402_asset_marker_is_not_echoed() {
        use stellar_agent_test_support::rejected_value::{
            CREDENTIAL_MARKER, assert_no_marker_in_text,
        };

        let requirements = stellar_agent_x402::wire::PaymentRequirements {
            scheme: "exact".to_owned(),
            network: "stellar:testnet".to_owned(),
            asset: CREDENTIAL_MARKER.to_owned(),
            amount: "1000000".to_owned(),
            pay_to: "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY".to_owned(),
            max_timeout_seconds: 300,
            extra: serde_json::json!({ "areFeesSponsored": true }),
        };
        let result = x402_canonical_asset(&requirements).expect_err("the asset is refused");
        let (code, message, text) = crate::tools::common::assert_business_envelope(&result);
        assert_eq!(code, "x402.invalid_asset_address");
        assert_eq!(
            message,
            "invalid SAC asset address: the asset must be a canonical C-strkey (contract)"
        );
        assert_no_marker_in_text(&text, CREDENTIAL_MARKER);
    }

    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn x402_requirements_marker_is_not_echoed() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let capture = stellar_agent_test_support::log_capture::CaptureWriter::new();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .with_writer(capture.clone())
            .finish();
        let _inert = stellar_agent_test_support::log_capture::inert_dispatcher();
        let _subscriber = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();

        use stellar_agent_test_support::rejected_value::{
            CREDENTIAL_MARKER, assert_no_marker, assert_no_marker_in_text,
        };
        let profile = Profile::builder_testnet("svc", "acct", "nonce", "acct")
            .with_noop_engine()
            .build();
        let server = WalletServer::new(profile).unwrap();
        let cases = [
            (
                "payTo",
                "x402.invalid_recipient_address",
                "invalid recipient address: pay_to must be a G-, C-, M-, or W-strkey",
            ),
            (
                "scheme",
                "x402.unsupported_scheme",
                "unsupported x402 scheme; only \"exact\" is supported",
            ),
            (
                "network",
                "x402.unsupported_network",
                "unsupported x402 network; accepted values are \"stellar:pubnet\" and \"stellar:testnet\"",
            ),
            (
                "amount",
                "x402.amount_conversion",
                "amount conversion failed: wire amount must be a positive decimal i128",
            ),
            (
                "asset",
                "x402.invalid_asset_address",
                "invalid SAC asset address: the asset must be a canonical C-strkey (contract)",
            ),
        ];
        for (field, expected_code, expected) in cases {
            let mut input: serde_json::Value =
                serde_json::from_str(&sample_requirements_json()).unwrap();
            input[field] = serde_json::json!(CREDENTIAL_MARKER);
            let requirements = serde_json::from_value(input.clone()).unwrap();
            let error = stellar_agent_x402::exact::validate_requirements(
                &requirements,
                server.context.network_passphrase(),
                &server.context.rpc_url,
            )
            .unwrap_err();
            assert_eq!(error.wire_code(), expected_code);
            assert_eq!(error.to_string(), expected);
            assert_no_marker(&error, CREDENTIAL_MARKER);
            let result = server
                .call_stellar_x402_create_payment(X402CreatePaymentArgs {
                    approval_nonce: None,
                    approval_attestation: None,
                    chain_id: "stellar:testnet".to_owned(),
                    payment_required: input.to_string(),
                    address: None,
                    business_id: None,
                })
                .await
                .expect("validation returns a business envelope");
            let (code, message, text) = crate::tools::common::assert_business_envelope(&result);
            assert_eq!(code, expected_code);
            assert_eq!(message, expected);
            assert_no_marker_in_text(&text, CREDENTIAL_MARKER);
            assert_no_marker_in_text(&format!("{result:?}"), CREDENTIAL_MARKER);
        }
        stellar_agent_test_support::rejected_value::assert_no_marker_in_text(
            &capture.captured_str(),
            "CREDMARKER7",
        );
    }
}
