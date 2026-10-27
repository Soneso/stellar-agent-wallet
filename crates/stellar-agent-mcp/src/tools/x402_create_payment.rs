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
    /// Pending mainnet payment approval returned by the preparation call.
    pub approval_nonce: Option<String>,
    /// URL-safe base64 without padding of the 32-byte operator attestation.
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
///   - the `payTo` is not a G-, C-, or M-strkey;
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

        use stellar_agent_network::keyring::enrolled_keyring_signer;
        use stellar_agent_x402::exact::{create_payment, validate_requirements};

        if self.context.chain_id.is_mainnet() {
            let guard = match self.mainnet_write_admission(
                stellar_agent_network::mainnet::MainnetConsumer::X402Create,
            ) {
                Ok(guard) => guard,
                Err(result) => return Ok(result),
            };
            return self.mainnet_x402_payment(args, guard).await;
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
        let amount = match validate_requirements(
            &requirements,
            self.context.network_passphrase(),
            &self.context.rpc_url,
        ) {
            Ok(amount) => amount,
            Err(ref err) => return Ok(x402_error_to_tool_result(err)),
        };

        // ── Build the value-carrying leg from the SAME decode ────────────────
        // The amount is the one the validator parsed from this immutable
        // requirements object, which `create_payment` validates again and
        // builds the transfer from.
        let value_leg = x402_value_leg(&requirements, amount);

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
        let signer_handle = match enrolled_keyring_signer(
            &self.profile_name_for_approval(),
            &self.profile,
            account,
        )
        .await
        {
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
            Arc::new(signer_handle);

        // Shared-window admission precedes signing and the signed RPC
        // re-simulation. A failure after it, an endpoint identity refusal
        // included, keeps the admitted spend.
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
        // The identity check runs under the profile's submit timeout, resolved
        // here; the requirement's `maxTimeoutSeconds` bounds the signed
        // authorization, never this deadline. Admission above stays when the
        // check refuses.
        let identity_deadline =
            tokio::time::Instant::now() + crate::tools::common::submit_timeout(&self.profile);
        let created = create_payment(
            &requirements,
            signer.as_ref(),
            &client,
            &cross_check,
            profile_passphrase,
            identity_deadline,
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

        match payment_response(&created, &payer_address) {
            Ok(response) => Ok(response),
            Err(error) => {
                audit.record_withheld(X402Failure::Encoding);
                Ok(x402_error_to_tool_result(&error))
            }
        }
    }
}

impl WalletServer {
    async fn mainnet_x402_payment(
        &self,
        args: X402CreatePaymentArgs,
        guard: crate::server::MainnetWriteGuard<'_>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        use crate::tools::common::{
            DispatchOutcome, approval_required_indistinguishable, verify_attestation_subject_gate,
        };
        use stellar_agent_core::approval::subject::approval_subject_x402;
        use stellar_agent_core::approval::{PendingApproval, user_id::process_uid_for_attestation};
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
        let value = ValueClass::single(x402_value_leg(&requirements, amount));
        let audit_leg = ValueLegRecord::from(&x402_value_leg(&requirements, amount));
        let dispatch = match self
            .dispatch_preparation(
                "stellar_x402_create_payment",
                &json!({"chain_id": args.chain_id}),
                &args.chain_id,
                value,
            )
            .await
        {
            Ok(outcome) => outcome,
            Err(error) => return error.into_result(),
        };
        let dispatch =
            match self.force_mainnet_confirmation("stellar_x402_create_payment", dispatch) {
                Ok(outcome) => outcome,
                Err(error) => return error.into_result(),
            };
        if !call_two {
            let DispatchOutcome::RequireApproval(approval) = &dispatch else {
                return Ok(approval_required_indistinguishable(name));
            };
            let entry = (|| {
                use sha2::{Digest, Sha256};
                let network_id =
                    Sha256::digest(guard.context.network_passphrase().as_bytes()).into();
                let uid = process_uid_for_attestation()
                    .map_err(|error| stellar_agent_core::approval::attest::record_error(&error))?;
                let entry = PendingApproval::new_x402_pending(
                    &network_id,
                    &root,
                    None,
                    uid,
                    approval.governing_ttl_ms,
                )
                .map_err(|error| stellar_agent_core::approval::attest::record_error(&error))?
                .with_policy_request(&approval.request);
                let mut store = self.x402_approval_store()?;
                store
                    .insert(
                        entry.clone(),
                        stellar_agent_network::mainnet::clock::now_ms()?,
                    )
                    .map_err(|error| stellar_agent_core::approval::attest::record_error(&error))?;
                Ok::<_, stellar_agent_core::WalletError>(entry)
            })();
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => return Ok(business_error_result(error.code(), error.message())),
            };
            return Ok(approval_response(&ApprovalView {
                entry: &entry,
                profile: name,
                chain_id: &args.chain_id,
                endpoint_host: guard.enablement.endpoint_host(),
                signer: &payer,
                requirements: &requirements,
            }));
        }
        let approval = match verify_attestation_subject_gate(
            self,
            &dispatch,
            crate::tools::common::GatedApprovalKind::X402
                .expectation(approval_subject_x402(&digest)),
            args.approval_nonce.as_deref(),
            args.approval_attestation.as_deref(),
            "stellar_x402_create_payment",
        )
        .await
        {
            Ok(Some(approval)) => approval,
            Ok(None) => return Ok(approval_required_indistinguishable(name)),
            Err(result) => return Ok(result),
        };
        let readiness =
            match stellar_agent_network::mainnet::audit_readiness::audit_readiness(profile, name) {
                Ok(readiness) => readiness,
                Err(error) => return Ok(crate::tools::common::endpoint_refusal_result(&error)),
            };
        let handle = match stellar_agent_network::keyring::lazy_signer_from_keyring(
            signer.seed_entry(),
            &payer,
        ) {
            Ok(handle) => handle,
            Err(error) => return Ok(crate::tools::common::endpoint_refusal_result(&error)),
        };
        let store = stellar_agent_network::policy_state::PersistedWindowStore::at_path(
            self.window_path.clone(),
        );
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
        .with_decision(PolicyDecision::RequireApproval);
        let created = create_payment_authorized(
            &requirements,
            stellar_agent_network::mainnet::MainnetConsumer::X402Create,
            X402MainnetProofs::new(
                guard.context,
                guard.policy,
                guard.enablement,
                &approval,
                &signer,
                &handle,
                readiness,
                &store,
            ),
            CrossCheckValue::Amount {
                asset: &asset,
                base_units: amount,
            },
            tokio::time::Instant::now() + crate::tools::common::submit_timeout(profile),
            |authorization| audit.before_transmit(authorization),
        )
        .await;
        let created = match created {
            Ok(created) => created,
            Err(error) => {
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
                return Ok(mainnet_x402_error(&error, withheld));
            }
        };
        let id = created.authorization.id();
        let withhold = |failure: ReleaseFailure| {
            let decision = release_decision(failure);
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
        let response = match payment_response(&created.payment, &payer) {
            Ok(response) => response,
            Err(error) => {
                let withheld = withhold(ReleaseFailure::Encoding);
                return Ok(mainnet_x402_error(&error, withheld));
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
            return Ok(mainnet_x402_error(&error, withheld));
        }
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
            return Ok(business_error_result(
                error.code(),
                format!("payment withheld {withheld}: {}", error.message()),
            ));
        }
        Ok(response)
    }

    fn x402_approval_store(
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

/// The approval-required view of a mainnet preparation call.
struct ApprovalView<'a> {
    entry: &'a stellar_agent_core::approval::PendingApproval,
    profile: &'a str,
    chain_id: &'a str,
    endpoint_host: &'a str,
    signer: &'a str,
    requirements: &'a stellar_agent_x402::wire::PaymentRequirements,
}

/// The preparation call's result: the success envelope whose `data.approval`
/// names the pending approval, as the classic preparation tools return it,
/// plus the enabled endpoint host, the enrolled signer, and the approval
/// instructions. It carries no payment payload.
fn approval_response(view: &ApprovalView<'_>) -> CallToolResult {
    let approval = json!({
        "approval_nonce": view.entry.approval_nonce,
        "profile": view.profile,
        "chain_id": view.chain_id,
        "expires_at_unix_ms": view.entry.expires_at_unix_ms,
        "reason": view.entry.reason,
        "endpoint_host": view.endpoint_host,
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
    let text = stellar_agent_core::envelope::Envelope::ok(json!({ "approval": approval }))
        .to_json_pretty()
        .unwrap_or_else(|_| String::from("{}"));
    CallToolResult::success(vec![Content::text(text)])
}

/// Where the release of a built mainnet payment failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReleaseFailure {
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
#[derive(Debug)]
struct ReleaseDecision {
    /// The invalidation stage of the child authorization, or `None` when the
    /// child is already consumed and both records stay used.
    cleanup: Option<stellar_agent_network::mainnet::resolve::InvalidationStage>,
    /// The failure whose stage the withheld audit row carries.
    withheld: X402Failure<'static>,
    /// Where the payment was withheld, as the error message names it.
    withheld_at: &'static str,
}

/// Selects the cleanup, the withheld row, and the message for a release
/// failure.
///
/// Before the child is consumed the handler owns its cleanup and invalidates
/// it at the payload release stage. After the child is consumed nothing is
/// invalidated: the payment authorization is spent, and only the approval
/// tombstone is missing.
fn release_decision(failure: ReleaseFailure) -> ReleaseDecision {
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

fn require_terminal_consumption(
    result: Result<bool, stellar_agent_core::WalletError>,
) -> Result<(), stellar_agent_core::WalletError> {
    if result? {
        Ok(())
    } else {
        Err(stellar_agent_core::error::NetworkError::MainnetAuthorizationRefused.into())
    }
}

/// Renders a mainnet payment failure under its own code, with a message that
/// starts with "payment withheld" followed by `withheld`, which says where.
fn mainnet_x402_error(error: &stellar_agent_x402::X402Error, withheld: &str) -> CallToolResult {
    if let stellar_agent_x402::X402Error::MainnetAuthorization(
        stellar_agent_network::mainnet::MainnetAuthorizationError::PolicyDenied(reason),
    ) = error
    {
        let redacted = crate::tools::common::redact_deny_reason(reason);
        let detail = serde_json::to_string(&redacted).unwrap_or_else(|_| reason.code().to_owned());
        return business_error_result(
            reason.wire_code(),
            format!("payment withheld {withheld}: policy denied this operation: {detail}"),
        );
    }
    business_error_result(
        error.wire_code(),
        format!("payment withheld {withheld}: {error}"),
    )
}

fn payment_response(
    created: &stellar_agent_x402::exact::CreatedPayment,
    payer: &str,
) -> Result<CallToolResult, stellar_agent_x402::X402Error> {
    let requirements = &created.payload.accepted;
    let signature = stellar_agent_x402::wire::encode_payment_signature(&created.payload)?;
    let response = json!({"paymentSignature": signature, "payer": payer,
        "asset": requirements.asset, "amount": requirements.amount, "payTo": requirements.pay_to,
        "network": requirements.network, "cross_check": created.cross_check.view()});
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
    PayloadRelease,
    /// The mainnet pending approval could not be tombstoned after the child
    /// authorization was consumed.
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
///   authorization refused.
/// - `terminal_approval`: the mainnet pending approval could not be
///   tombstoned after the child authorization was consumed.
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
        X402Failure::PayloadRelease => "payload_release",
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
    gate_passed: bool,
    decision: PolicyDecision,
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
            decision: PolicyDecision::Allow,
            refusal: None,
        }
    }

    fn with_decision(mut self, decision: PolicyDecision) -> Self {
        self.decision = decision;
        self
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
        self.network = authorization.network.to_owned();
        self.scheme = authorization.scheme.to_owned();
        let entry = self.authorized_row(
            authorization.network,
            authorization.scheme,
            authorization.cross_check,
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
                self.gate_passed = true;
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
    ) -> AuditEntry {
        AuditEntry::new_x402_payment_authorized(
            self.tool,
            self.chain_id,
            self.leg.take().into_iter().collect(),
            network,
            scheme,
            self.decision.clone(),
            &self.request_id,
            witness.map(CrossCheckWitness::record),
        )
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
            let result = mainnet_x402_error(&error, "after intent authorization");
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
            approval_nonce: None,
            approval_attestation: None,
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
            approval_nonce: None,
            approval_attestation: None,
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

    /// Supplied approval arguments change nothing on testnet: a
    /// `RequireApproval` verdict still refuses the single-shot payment, absent,
    /// partial or complete.
    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn require_approval_verdict_with_supplied_approval_arguments_stays_unsupported() {
        stellar_agent_test_support::keyring_mock::install().ok();
        let server = make_require_approval_server();
        for (nonce, attestation) in [
            (Some("approval-nonce"), Some("approval-attestation")),
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
                })
                .await
                .unwrap();
            let (code, _message, text) = crate::tools::common::assert_business_envelope(&result);
            assert_eq!(code, "policy.approval_required_unsupported", "{text}");
            assert!(!text.contains("\"paymentSignature\""), "{text}");
        }
    }

    /// The testnet payment's authorized row records the policy's `Allow`.
    #[test]
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
        let f = Fixture::new(|raw| raw);
        let requirements = f.requirements();
        let clients = stellar_agent_network::client::constructions_on_this_thread();
        let result = f
            .server
            .call_stellar_x402_create_payment(X402CreatePaymentArgs {
                payment_required: serde_json::to_string(&requirements).unwrap(),
                chain_id: "stellar:mainnet".to_owned(),
                address: None,
                approval_nonce: None,
                approval_attestation: None,
            })
            .await
            .unwrap();
        assert_ne!(result.is_error, Some(true));
        let text = result.content[0].as_text().unwrap().text.clone();
        let wire: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(wire["ok"], true, "{wire}");
        let data = wire["data"].as_object().unwrap();
        assert_eq!(data.keys().collect::<Vec<_>>(), ["approval"], "{wire}");
        assert!(wire["data"].get("paymentSignature").is_none());
        assert_eq!(
            clients,
            stellar_agent_network::client::constructions_on_this_thread()
        );
        assert_eq!(f.seed_reads.load(Ordering::SeqCst), 0);
        assert!(
            !f.server.window_path.exists()
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
        assert_eq!(approval["reason"], "mainnet confirmation");
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
        assert_eq!(entry.reason.as_deref(), Some("mainnet confirmation"));
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
        let f = Fixture::new(|raw| raw);
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
            )
            .await
            .unwrap();
        let outcome = f
            .server
            .force_mainnet_confirmation("stellar_x402_create_payment", outcome)
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
        let f = Fixture::new(|raw| raw);
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
            )
            .await
            .unwrap();
        let outcome = f
            .server
            .force_mainnet_confirmation("stellar_x402_create_payment", outcome)
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
        let result = mainnet_x402_error(&error, "before signed transmission");
        let (code, message, _) = crate::tools::common::assert_business_envelope(&result);
        assert_eq!(code, "policy.deny.counterparty_denied");
        assert!(message.starts_with("payment withheld before signed transmission: "));
        assert!(!message.contains(&address));
    }
}
