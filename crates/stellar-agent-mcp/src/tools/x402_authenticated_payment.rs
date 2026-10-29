//! `stellar_x402_authenticated_payment` MCP tool — x402 payment with SEP-10
//! counterparty-identity pre-payment gate.
//!
//! # What this tool does
//!
//! Runs the SEP-10 counterparty-identity gate (via
//! `stellar-agent-x402-identity`) BEFORE constructing the x402 payment
//! payload.  Returns both the `PAYMENT-SIGNATURE` header value AND the
//! SEP-10 `Authorization: Bearer <jwt>` companion token so the MCP host
//! can attach both to the HTTP request to the x402-protected resource.
//!
//! # Design fact
//!
//! x402 has NO native identity wire field.  The SEP-10 JWT is an HTTP-layer
//! companion — the Soroban transaction XDR / SAC auth-entry / payment memo
//! is NEVER mutated to carry it.  The wallet returns BOTH:
//!
//! - `paymentSignature` (base64) — the `PAYMENT-SIGNATURE` header value.
//! - `authorization` — the `Authorization: Bearer <jwt>` value.
//!
//! # Abort-before-payment contract
//!
//! Any identity-gate failure ([`stellar_agent_x402_identity::IdentityError`])
//! aborts the tool BEFORE `create_payment` is called.  No `PaymentPayload`,
//! no SAC auth-entry, no nonce is generated on failure.
//!
//! # Security
//!
//! - RPC URL is resolved from the **active profile** (operator-controlled).
//! - Network passphrase is taken from the active profile.
//! - The payment requirements are validated in full before the dispatch gate
//!   and the SEP-10 gate. Invalid requirements answer their own `x402.*` code
//!   and never reach the spending window.
//! - One RPC client serves the payment. Its first request is the endpoint
//!   identity check, under the profile's `submit_timeout_seconds`.
//! - Before the signer is read, the cross-check rule decides from the
//!   transfer amount, in the asset's atomic units, and the profile's
//!   thresholds and oracle whether the payment needs the independent-RPC
//!   witness. When it does, a second client to the profile's
//!   `oracle_provider_url` simulates the same unsigned transfer before the
//!   payer signs, and a disagreement refuses.
//! - Signer is loaded from the platform keyring at call time.
//! - The SEP-10 ephemeral key is NOT the payment signer and NOT persisted.
//! - JWT: NEVER logged.  Returned in `authorization` field (the Bearer token
//!   is the product of a successful gate, like a signature).
//!
//! # Output
//!
//! Returns `{ paymentSignature, authorization, payer, asset, amount, payTo,
//! home_domain, network, payto_anchored, cross_check }`:
//!
//! - `paymentSignature` — base64 `PAYMENT-SIGNATURE` header value.
//! - `authorization` — `Bearer <jwt>` string for `Authorization:` header.
//! - `payer` — payer address (G-strkey).
//! - `asset` — SAC contract address (C-strkey).
//! - `amount` — atomic-unit amount string from `PaymentRequirements`.
//! - `payTo` — recipient address (operator display).
//! - `home_domain` — verified home domain (operator display).
//! - `network` — x402 CAIP-2 network string.
//! - `payto_anchored` — `"anchored"` | `"not_anchored"` | `"unknown"`:
//!   signals whether `payTo` is declared in the verified home-domain's
//!   `stellar.toml` `ACCOUNTS` list.  `"anchored"`
//!   means `payTo` is in the list; `"not_anchored"` means the list is non-empty
//!   and `payTo` is absent; `"unknown"` means the list is empty/absent and no
//!   determination can be made.  This is a **display signal only** — the tool
//!   does NOT hard-deny on `"not_anchored"` (SEP-1 `ACCOUNTS` does not reliably
//!   enumerate SAC payment destinations).
//! - `cross_check`: the witness outcome, which is `passed` with the oracle and
//!   its ledger, `skipped` with the reason, or `not_required`.
//!
use rmcp::{
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Content},
    schemars, serde, tool, tool_router,
};
use serde_json::json;
use stellar_agent_core::audit_log::ValueLegRecord;
use stellar_agent_core::cross_check::CrossCheckValue;
use stellar_agent_core::policy::v1::ValueClass;
use stellar_agent_mcp_macros::mcp_tool_router;
use stellar_agent_network::cross_check::SorobanCrossCheck;

use stellar_agent_x402_identity::{IdentityError, resolve_and_verify_counterparty};

use crate::server::WalletServer;
use crate::tools::common::{
    decode_payment_required_input, x402_canonical_asset, x402_error_to_tool_result, x402_value_leg,
};
use crate::tools::x402_create_payment::{X402AuthorizationAudit, X402Failure};

// ─────────────────────────────────────────────────────────────────────────────
// payTo-anchoring signal
// ─────────────────────────────────────────────────────────────────────────────

/// Three-valued signal for payTo anchoring against the verified home-domain's
/// `stellar.toml` `ACCOUNTS` list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PaytoAnchored {
    /// `payTo` is present in the verified domain's declared `ACCOUNTS` list.
    Anchored,
    /// The domain declared a non-empty `ACCOUNTS` list and `payTo` is not in it.
    ///
    /// This is a **display warning** only.  The tool does NOT hard-deny payments
    /// with this signal — SEP-1 `ACCOUNTS` does not reliably enumerate SAC
    /// payment destinations; the payer is always operator-gated.
    NotAnchored,
    /// The domain's `stellar.toml` `ACCOUNTS` list is absent or empty.
    ///
    /// No determination is possible; the operator should apply independent
    /// verification of the payment destination.
    Unknown,
}

impl PaytoAnchored {
    /// Returns the wire string included in the tool's JSON output.
    fn as_str(self) -> &'static str {
        match self {
            Self::Anchored => "anchored",
            Self::NotAnchored => "not_anchored",
            Self::Unknown => "unknown",
        }
    }
}

/// Compute the payTo-anchoring signal given the `payTo` address and the
/// verified domain's declared accounts.
///
/// # Arguments
///
/// - `pay_to` — the `payTo` address from `PaymentRequirements`.
/// - `accounts` — the verified domain's `ACCOUNTS` list from `stellar.toml`;
///   must be the list from a `VerifiedCounterpartySession` (already parsed and
///   validated by the gate).
///
/// # Returns
///
/// [`PaytoAnchored::Anchored`] if `pay_to` (a G-strkey) is in `accounts`.
/// [`PaytoAnchored::NotAnchored`] if `accounts` is non-empty and `pay_to` (a
/// G-strkey) is absent from it.
/// [`PaytoAnchored::Unknown`] if `accounts` is empty, OR `pay_to` is not a
/// G-strkey (e.g. a C-strkey SAC destination) — SEP-1 `ACCOUNTS` only enumerates
/// G-strkeys, so a non-G `pay_to` can never match and anchoring is indeterminate.
///
/// # Panics
///
/// Never panics.
fn compute_payto_anchored(pay_to: &str, accounts: &[String]) -> PaytoAnchored {
    if accounts.is_empty() {
        return PaytoAnchored::Unknown;
    }
    // SEP-1 `ACCOUNTS` only enumerates G-strkey accounts. An x402 `payTo` is
    // frequently a C-strkey (SAC contract destination), which can never appear in
    // a G-only `ACCOUNTS` list — so anchoring is genuinely indeterminate (Unknown),
    // not a substitution warning (a `NotAnchored` here would be a false alarm that
    // trains operators to ignore the signal).
    if !pay_to.starts_with('G') {
        return PaytoAnchored::Unknown;
    }
    if accounts.iter().any(|a| a == pay_to) {
        PaytoAnchored::Anchored
    } else {
        PaytoAnchored::NotAnchored
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Argument type
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for the `stellar_x402_authenticated_payment` MCP tool.
///
/// # Schema
///
/// - `payment_required` — base64-encoded `PAYMENT-REQUIRED` header value OR
///   raw JSON `PaymentRequirements` object.
/// - `chain_id`: the wallet's CAIP-2 chain identifier, `"stellar:testnet"`
///   or `"stellar:mainnet"`; validated against the active profile after the
///   payment requirements are validated.
/// - `home_domain` — operator-supplied home domain for SEP-10 identity
///   verification (e.g. `"testanchor.stellar.org"`).
/// - `address` — optional signer address (G-strkey).
/// - `approval_nonce`, `approval_attestation`: on mainnet, the approval of
///   the preparation call; both absent for the preparation call, both present
///   for the payment.
#[derive(serde::Deserialize, schemars::JsonSchema)]
#[serde(crate = "rmcp::serde")]
pub struct X402AuthenticatedPaymentArgs {
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

    /// Operator-supplied home domain for SEP-10 counterparty identity
    /// verification (e.g. `"testanchor.stellar.org"`).
    ///
    /// The gate resolves `stellar.toml` for this domain, extracts
    /// `WEB_AUTH_ENDPOINT` + `SIGNING_KEY`, verifies the SSRF bind,
    /// and runs the SEP-10 ephemeral challenge/response.
    ///
    /// Any failure aborts BEFORE `create_payment` is called.
    pub home_domain: String,

    /// Optional signer address (G-strkey).
    ///
    /// When provided must match the active signer enrolled in the profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,

    /// Wallet-issued approval nonce from the mainnet preparation call's
    /// `approval` block.
    ///
    /// Required only on mainnet, where the first call without approval
    /// arguments returns a pending approval. When present, the payment call
    /// verifies the HMAC-SHA256 attestation blob and confirms the approved
    /// payment intent and home domain before the SEP-10 authentication.
    #[serde(default)]
    pub approval_nonce: Option<String>,

    /// HMAC-SHA256 attestation blob, URL-safe base64 no-pad encoded (32 bytes).
    ///
    /// Written to the pending-approvals store by `stellar-agent approve --id
    /// <approval_nonce> --profile <name>` after the user confirms on their own tty.  The payment
    /// call re-computes and constant-time-compares the HMAC against the stored
    /// attestation key before the SEP-10 authentication.
    ///
    /// Required alongside `approval_nonce` on mainnet. An absent or invalid
    /// attestation returns `policy.approval_required`, the same wire code for
    /// every failure mode, so the modes stay indistinguishable.
    #[serde(default)]
    pub approval_attestation: Option<String>,
}

/// Prints every field but the attestation, which shows only whether it is
/// set: the attestation is the operator's approval credential.
impl std::fmt::Debug for X402AuthenticatedPaymentArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X402AuthenticatedPaymentArgs")
            .field("payment_required", &self.payment_required)
            .field("chain_id", &self.chain_id)
            .field("home_domain", &self.home_domain)
            .field("address", &self.address)
            .field("approval_nonce", &self.approval_nonce)
            .field(
                "approval_attestation",
                &crate::tools::common::AttestationPresence(&self.approval_attestation),
            )
            .finish()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Error → tool result helper
// ─────────────────────────────────────────────────────────────────────────────

/// Maps [`IdentityError`] to the standard business-error envelope with
/// `isError = true`, carrying the `identity.<reason>` wire code.
///
/// The gate passes server-derived text in `IdentityError::Display` that it
/// does not validate to a fixed shape through
/// `stellar_agent_network::quote_server_text`. A value validated to a fixed
/// shape, such as the LDH endpoint host, is printed as validated. Endpoints
/// are named by host and port, and the text carries no JWT and no response
/// body.
///
/// The two mainnet identity errors answer the agent-facing network codes:
/// the signing refusal is `network.mainnet_write_forbidden`, and a refused
/// authorization of the SEP-10 challenge is
/// `network.mainnet_authorization_refused` with a text that names no
/// precondition.
fn identity_error_to_tool_result(err: &IdentityError) -> CallToolResult {
    match err {
        IdentityError::MainnetSigningForbidden { .. } => {
            crate::tools::common::x402_mainnet_signing_forbidden_result()
        }
        IdentityError::MainnetAuthorizationRefused => crate::tools::common::business_error_result(
            stellar_agent_core::error::NetworkError::MainnetAuthorizationRefused.code(),
            SEP10_REFUSAL_TEXT,
        ),
        other => crate::tools::common::business_error_result(other.wire_code(), other.to_string()),
    }
}

/// The text of a refused mainnet authorization before the SEP-10 challenge
/// was submitted.
const SEP10_REFUSAL_TEXT: &str = "the mainnet authorization for this SEP-10 authentication was \
                                  refused; no signed challenge was submitted";

/// The text of a refused mainnet authorization of the payment: an intent,
/// submission or release refusal after the SEP-10 authentication.
#[cfg(feature = "mainnet-write")]
const PAYMENT_REFUSAL_TEXT: &str =
    "the mainnet authorization for this payment was refused; the payment payload was withheld";

/// Builds the standard business-error envelope for a payment-build failure that
/// occurs AFTER the identity gate has passed, carrying the
/// `x402.payment_build_failed` wire code; `detail` comes from a redaction-safe
/// error `Display`.
fn payment_build_error_result(detail: &str) -> CallToolResult {
    crate::tools::common::business_error_result("x402.payment_build_failed", detail)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool router impl block
// ─────────────────────────────────────────────────────────────────────────────

/// Authenticates with the counterparty via SEP-10 and constructs an x402
/// `PAYMENT-SIGNATURE` payload.
///
/// Runs the SEP-10 counterparty-identity gate (home domain → stellar.toml →
/// WEB_AUTH_ENDPOINT + SIGNING_KEY → SSRF bind → ephemeral SEP-10
/// challenge/response → JWT) and THEN calls `create_payment`, which obtains
/// the cross-check witness before it signs.  Any gate failure aborts before
/// the payment is built.
///
/// Returns `{ paymentSignature, authorization, payer, asset, amount, payTo,
/// home_domain, network, payto_anchored, cross_check }` on success.  Errors return the
/// standard business-error envelope `{ ok: false, error: { code, message },
/// request_id }` with `isError = true`; `error.code` is the per-variant
/// `x402.<reason>` wire code (the mainnet refusal uses
/// `network.mainnet_write_forbidden`).
///
/// # Tool annotations
///
/// - `readOnlyHint = false` — runs ephemeral SEP-10 auth session (anchor
///   interaction) + accesses keyring + constructs a signed artifact.
/// - `destructiveHint = false` — produces signed payload + Bearer JWT only;
///   the HOST submits to the network and the API.  The wallet does NOT submit.
///
/// # Protocol reference
///
/// x402 wire = `{ transaction }` only; the JWT is an HTTP-layer companion,
/// NOT embedded in the XDR.
///
/// # Security reference
///
/// RPC URL and passphrase come from the active profile (NEVER from input).
/// The SEP-10 server key is verified against the domain's `SIGNING_KEY`, and
/// the per-request SEP-10 key is ephemeral (never the payment signer).
///
/// # Errors
///
/// Returns `isError = true` with the business-error envelope when:
/// - `payment_required` is not valid base64+JSON or raw JSON, or the
///   requirements fail validation. These answer the field-specific `x402.*`
///   code before the dispatch gate, the audit pre-flight, the SEP-10 gate,
///   and the signer load, and consume no spending window.
/// - `home_domain` stellar.toml is unreachable or unparseable.
/// - `WEB_AUTH_ENDPOINT` or `SIGNING_KEY` absent from stellar.toml.
/// - `WEB_AUTH_ENDPOINT` host != `home_domain` (SSRF bind rejected).
/// - SEP-10 challenge/response fails.
/// - The RPC endpoint fails the identity check: its own `network.*` code,
///   `network.rpc_credential_refused` for an HTTP 401 or 403 answer.
/// - The RPC client cannot be built: `network.rpc_unreachable`,
///   `network.rpc_credential_refused` for a stored provider credential the
///   wallet refuses or cannot send, or the keyring code of the credential
///   read (`auth.keyring_not_found`, `auth.keyring_platform_error`,
///   `auth.keyring_interactive_session_required`, or
///   `auth.keyring_config_invalid`).
/// - The cross-check witness refuses with its own code before the payer signs.
///   Credential failures keep `network.rpc_credential_refused` or the oracle
///   credential read's keyring code (`auth.keyring_*`). Disagreement returns
///   `simulation.divergence`. Other failures to obtain the witness or build
///   the oracle client return `network.witness_unavailable`.
/// - Any other x402 `create_payment` error: `x402.payment_build_failed`.
///
/// A `chain_id` that does not match the active profile returns a JSON-RPC
/// `ErrorData` from the dispatch gate.
///
/// # Examples
///
/// ```json
/// {
///   "chain_id": "stellar:testnet",
///   "home_domain": "testanchor.stellar.org",
///   "payment_required": "<base64-encoded PaymentRequirements>"
/// }
/// ```
#[mcp_tool_router]
#[tool_router(router = x402_authenticated_payment_tool_router, vis = "pub(crate)")]
impl WalletServer {
    #[mcp_tool_item(
        name = "stellar_x402_authenticated_payment",
        destructive_hint = false,
        read_only_hint = false,
        chain_id_required = true,
        value_kind = "moves_value"
    )]
    #[tool(
        name = "stellar_x402_authenticated_payment",
        description = "Authenticate with a counterparty via SEP-10 and construct an x402 v2 \
                       PAYMENT-SIGNATURE payload. Runs the SEP-10 identity gate (home_domain → \
                       stellar.toml → WEB_AUTH_ENDPOINT + SIGNING_KEY → SSRF bind → \
                       ephemeral challenge/response → JWT) then calls create_payment, which \
                       obtains the cross-check witness before signing. Any gate failure aborts \
                       BEFORE the payment is built. \
                       Returns { paymentSignature, authorization (Bearer JWT for Authorization header), \
                       payer, asset, amount, payTo, home_domain, network, payto_anchored, \
                       cross_check }. \
                       payto_anchored is \"anchored\" | \"not_anchored\" | \"unknown\": whether payTo \
                       appears in the verified domain's stellar.toml ACCOUNTS list. \
                       not_anchored is a display warning only — the tool does NOT deny on it. \
                       RPC URL and passphrase come from the active profile (never from input). \
                       The SEP-10 ephemeral key is NOT the payment signer. \
                       read_only_hint=false; destructive_hint=false.",
        annotations(read_only_hint = false, destructive_hint = false)
    )]
    async fn stellar_x402_authenticated_payment(
        &self,
        Parameters(args): Parameters<X402AuthenticatedPaymentArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        use std::sync::Arc;

        use stellar_agent_network::keyring::enrolled_keyring_signer;
        use stellar_agent_x402::exact::{create_payment, validate_requirements};
        use stellar_agent_x402::wire::encode_payment_signature;

        // Mainnet: this tool returns a payment authorization the MCP host
        // broadcasts externally, so the submit-layer mainnet gate never fires
        // because the wallet does not submit. Without the server's mainnet
        // write context, which a build without mainnet writes never holds,
        // the tool refuses before any key access, SEP-10 identity gate, or
        // signing, so no mainnet payment signature is produced. Wire code:
        // network.mainnet_write_forbidden. With the context it runs the
        // approved two-call flow. The Message authorization is consumed
        // before the SEP-10 signature. The payment intent is consumed before
        // the signed simulation, and the submit authorization before the
        // payload release.
        if self.context.chain_id.is_mainnet() {
            if self.mainnet_context.is_none() {
                return Ok(crate::tools::common::x402_mainnet_signing_forbidden_result());
            }
            // A build without the mainnet-write feature refuses a mainnet
            // payment here.
            #[cfg(feature = "mainnet-write")]
            {
                // A fixed test session would stand in for the authorized
                // identity gate, so a server with the context refuses it.
                #[cfg(any(test, feature = "test-helpers"))]
                if self.x402_identity_session_override.is_some() {
                    return Ok(crate::tools::common::x402_mainnet_signing_forbidden_result());
                }
                let guard = match self.mainnet_write_admission(
                    stellar_agent_network::mainnet::MainnetConsumer::X402Authenticated,
                ) {
                    Ok(guard) => guard,
                    Err(result) => return Ok(result),
                };
                return self.mainnet_authenticated_payment(args, guard).await;
            }
            #[cfg(not(feature = "mainnet-write"))]
            return Ok(crate::tools::common::x402_mainnet_signing_forbidden_result());
        }

        // ── Decode and validate payment_required FIRST ────────────────────────
        // The dispatch gate needs the value-carrying descriptor, which is
        // derived from this single decode. The requirements are validated in
        // full before the gate and the SEP-10 gate below, so invalid
        // requirements answer their own `x402.*` code, run no SEP-10 session,
        // and never reach the spending window.
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
            "home_domain": &args.home_domain,
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
                "stellar_x402_authenticated_payment",
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
        // precedes the SEP-10 identity gate and the signer load, so a log that
        // cannot take a row refuses before any key is touched. It keeps no
        // handle: the transmit gate writes the `x402_payment_authorized` row
        // through its own registry acquisition, which reruns the anchor check
        // immediately before the signed authorization is sent.
        if let Err(err) = crate::tools::value_audit::require_value_audit_writer(
            &self.profile,
            &self.profile_name_for_approval(),
            self.audit_binding,
        ) {
            return Ok(crate::tools::common::business_error_result(
                err.code(),
                err.to_string(),
            ));
        }

        tracing::debug!(
            chain_id = %args.chain_id,
            // Redact: home_domain is not a secret but avoid over-logging.
            "x402_authenticated_payment: dispatch gate passed",
        );

        // ── Step 1: SEP-10 counterparty-identity gate (ABORT on failure) ─────
        // Resolve home_domain → stellar.toml → WEB_AUTH_ENDPOINT + SIGNING_KEY
        // → SSRF bind → ephemeral SEP-10 challenge/response → JWT.
        //
        // resolve_and_verify_counterparty builds its stellar.toml client
        // INTERNALLY (no-redirect + HTTPS-only + no-decompression). The MCP
        // tool does NOT pass a client here — this removes the foot-gun where a
        // caller-supplied auto-follow client could silently follow 3xx to an
        // attacker-chosen host.
        //
        // Any failure here aborts BEFORE create_payment is called.
        let network_passphrase = self.context.network_passphrase();
        let session = match self
            .verify_x402_counterparty(&args.home_domain, network_passphrase)
            .await
        {
            Ok(s) => s,
            Err(ref err) => {
                tracing::warn!(
                    error_code = %err.wire_code(),
                    home_domain = %args.home_domain,
                    "x402_authenticated_payment: identity gate aborted before payment",
                    // NEVER log err details that might contain URL paths
                    // (IdentityError::Display is redaction-safe, but explicit
                    // redact at the span boundary is belt-and-braces).
                );
                return Ok(identity_error_to_tool_result(err));
            }
        };

        tracing::debug!(
            home_domain = %args.home_domain,
            // NEVER log session.jwt here — JWT redaction.
            "x402_authenticated_payment: identity gate passed; proceeding to payment",
        );

        // ── Step 2: Validate optional address arg ─────────────────────────────
        // `requirements` was decoded above (before the gate), alongside
        // `value_leg` — not re-decoded here.
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
            "stellar_x402_authenticated_payment",
        ) {
            Ok(cross_check) => cross_check,
            Err(err) => return Ok(crate::tools::common::endpoint_refusal_result(&err)),
        };

        // ── Step 3: Load signer from keyring ─────────────────────────────────
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

                // Static message aligned with the DeFi signer-load surfaces
                // (dex / vault) for cross-surface uniformity; the
                // wire code stays `x402.keyring_load_failed`, consistent with
                // `stellar_x402_create_payment`.
                return Ok(crate::tools::common::business_error_result(
                    "x402.keyring_load_failed",
                    "could not load signer from keyring",
                ));
            }
        };

        // ── Step 4: One RPC client for the payment, from the active profile ──
        // The URL is operator-controlled, never facilitator-supplied. Every
        // request of the payment goes to this client, and `create_payment`
        // makes the endpoint identity check its first request. The witness
        // requests go to the oracle client prepared above.
        let client = match self.context.primary_client() {
            Ok(client) => client,
            Err(err) => return Ok(crate::tools::common::endpoint_refusal_result(&err)),
        };
        let payer_address = account.to_owned();

        // ── Step 5: Dispatch to stellar_agent_x402::create_payment ───────────
        let signer: Arc<dyn stellar_agent_network::signing::Signer + Send + Sync> =
            Arc::new(signer_handle);

        // Shared-window admission precedes signing and the signed RPC
        // re-simulation. A failure after it, an endpoint identity refusal
        // included, keeps the admitted spend.
        if let Err(refusal) = crate::tools::x402_create_payment::record_x402_authorization(
            self,
            "stellar_x402_authenticated_payment",
            &stellar_agent_core::policy::v1::ValueClass::single(value_leg_for_record),
        ) {
            return Ok(refusal);
        }

        // The transmit gate writes `x402_payment_authorized` before the signed
        // authorization leaves the wallet in the re-simulation. Both rows of
        // this payment share the request id minted here.
        let mut audit = X402AuthorizationAudit::new(
            self,
            "stellar_x402_authenticated_payment",
            args.chain_id.as_str(),
            audit_leg,
        );
        // The identity check runs under the profile's submit timeout, resolved
        // here; the requirement's `maxTimeoutSeconds` bounds the signed
        // authorization, never this deadline.
        let identity_deadline =
            tokio::time::Instant::now() + crate::tools::common::submit_timeout(&self.profile);
        let created = create_payment(
            &requirements,
            signer.as_ref(),
            &client,
            &cross_check,
            network_passphrase,
            identity_deadline,
            |authorization| audit.before_transmit(authorization),
        )
        .await;
        let created = match created {
            Ok(created) => created,
            Err(source) => {
                tracing::warn!(
                    "x402_authenticated_payment: create_payment failed after identity gate",
                );
                // An audit refusal at the transmit gate answers its own
                // `audit.*` code; it is not a payment-build failure.
                if let Some(refusal) = audit.refusal_result() {
                    return Ok(refusal);
                }
                // An endpoint that fails the identity check answers its own
                // `network.*` code: only a configuration change fixes it.
                if let stellar_agent_x402::X402Error::EndpointIdentity(refusal) = &source {
                    return Ok(crate::tools::common::endpoint_refusal_result(refusal));
                }
                // A cross-check refusal answers the witness's own code: a
                // disagreement, an unavailable witness, or a refused oracle
                // credential is not a payment-build failure.
                if let stellar_agent_x402::X402Error::CrossCheck(refusal) = &source {
                    return Ok(crate::tools::common::endpoint_refusal_result(refusal));
                }
                audit.record_withheld(X402Failure::CreatePayment(&source));
                // Surface a uniform single-pipeline error envelope. The
                // X402Error Display is redaction-safe (authority-only, no secrets).
                return Ok(payment_build_error_result(&source.to_string()));
            }
        };

        // ── Step 6: Encode PAYMENT-SIGNATURE ─────────────────────────────────
        let payment_signature = match encode_payment_signature(&created.payload) {
            Ok(sig) => sig,
            Err(source) => {
                audit.record_withheld(X402Failure::Encoding);
                return Ok(payment_build_error_result(&source.to_string()));
            }
        };

        // ── Redact payer address for telemetry ────────────────────────────────
        let redacted_payer =
            stellar_agent_core::observability::redact_strkey_first5_last5(&payer_address);
        tracing::info!(
            payer = %redacted_payer,
            network = %requirements.network,
            home_domain = %args.home_domain,
            "x402_authenticated_payment: payment payload constructed",
            // NEVER log session.jwt.
        );

        // ── Build response ────────────────────────────────────────────────────
        // `authorization` = the Bearer token for `Authorization: Bearer <jwt>`.
        // The JWT is the product of a successful gate; it is OK to return it
        // to the MCP host (like a signature — the host needs it to make the
        // authenticated request).  It is NEVER logged.
        //
        // `payto_anchored`:
        // "anchored"     = payTo found in the verified domain's ACCOUNTS list.
        // "not_anchored" = ACCOUNTS non-empty, payTo absent — display warning.
        // "unknown"      = ACCOUNTS absent/empty — no determination possible.
        // This is a DISPLAY signal only; the tool never hard-denies on it.
        Ok(payment_response(
            &payment_signature,
            &payer_address,
            &requirements,
            &session,
            &created.cross_check,
        ))
    }
}

/// The success result of a payment: the `PAYMENT-SIGNATURE` value, the
/// `Bearer` token of the verified session, the payment's display fields, the
/// home domain, the payTo-anchoring signal, and the witness outcome.
fn payment_response(
    payment_signature: &str,
    payer: &str,
    requirements: &stellar_agent_x402::wire::PaymentRequirements,
    session: &stellar_agent_x402_identity::VerifiedCounterpartySession,
    cross_check: &stellar_agent_network::cross_check::CrossCheckOutcome,
) -> CallToolResult {
    let payto_anchored = compute_payto_anchored(&requirements.pay_to, &session.accounts);
    let authorization = format!("Bearer {}", session.jwt);
    let response = json!({
        "paymentSignature": payment_signature,
        "authorization": authorization,
        "payer": payer,
        "asset": requirements.asset,
        "amount": requirements.amount,
        "payTo": requirements.pay_to,
        "home_domain": session.home_domain,
        "network": requirements.network,
        "payto_anchored": payto_anchored.as_str(),
        "cross_check": cross_check.view(),
    });
    let envelope = stellar_agent_core::envelope::Envelope::ok(response);
    let json_str = envelope
        .to_json_pretty()
        .unwrap_or_else(|_| String::from("{}"));
    CallToolResult::success(vec![Content::text(json_str)])
}

impl WalletServer {
    /// Runs the SEP-10 counterparty-identity gate for `home_domain`.
    ///
    /// A test build may stand a fixed session in for the gate; see
    /// `WalletServer::set_x402_identity_session_for_test`. Production always
    /// runs the gate.
    async fn verify_x402_counterparty(
        &self,
        home_domain: &str,
        network_passphrase: &str,
    ) -> Result<stellar_agent_x402_identity::VerifiedCounterpartySession, IdentityError> {
        #[cfg(any(test, feature = "test-helpers"))]
        if let Some((jwt, sub, accounts)) = &self.x402_identity_session_override {
            return Ok(stellar_agent_x402_identity::VerifiedCounterpartySession {
                jwt: jwt.clone(),
                sub: sub.clone(),
                home_domain: home_domain.to_owned(),
                accounts: accounts.clone(),
            });
        }
        resolve_and_verify_counterparty(home_domain, network_passphrase).await
    }
}

#[cfg(feature = "mainnet-write")]
impl WalletServer {
    /// The authenticated payment on a server holding the mainnet write
    /// context, in two calls.
    ///
    /// Both calls decode and validate the requirements, check the chain, the
    /// approval pair and the home domain, obtain the enrolled payer, check
    /// the optional address, recompute the payment root and intent digest,
    /// and run the dispatch gate with the forced mainnet confirmation. The
    /// first call, without approval arguments, writes a pending x402
    /// approval for the intent and the home domain, and sends no request.
    /// The second call checks that the startup proofs are unchanged,
    /// verifies the approval of the intent for the home domain, runs the
    /// authorized identity gate, which signs the SEP-10 challenge under a
    /// consumed message authorization, and builds the payment as the intent
    /// that continues the message receipt. It releases the payload only
    /// after the submission authorization is consumed and the approval is
    /// tombstoned.
    async fn mainnet_authenticated_payment(
        &self,
        args: X402AuthenticatedPaymentArgs,
        guard: crate::server::MainnetWriteGuard<'_>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        use crate::tools::common::{
            DispatchOutcome, GatedApprovalKind, approval_required_indistinguishable,
            business_error_result, endpoint_refusal_result, verify_attestation_subject_gate,
        };
        use crate::tools::x402_create_payment::{
            ApprovalView, ReleaseFailure, approval_response, mainnet_x402_error, release_decision,
            require_terminal_consumption,
        };
        use stellar_agent_core::approval::subject::approval_subject_x402_authenticated;
        use stellar_agent_core::approval::{PendingApproval, user_id::process_uid_for_attestation};
        use stellar_agent_core::audit_log::PolicyDecision;
        use stellar_agent_network::mainnet::MainnetConsumer;
        use stellar_agent_network::mainnet::audit_readiness::audit_readiness;
        use stellar_agent_x402::exact::{
            X402MainnetProofs, create_payment_authorized, intent_digest, payment_root,
            validate_requirements_for_payment,
        };
        use stellar_agent_x402_identity::MainnetIdentityInputs;

        const TOOL: &str = "stellar_x402_authenticated_payment";
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
        // The home domain is validated before the approval names it, so a
        // malformed domain is never approved.
        if let Err(error) =
            stellar_agent_network::counterparty::fetch::validate_home_domain(&args.home_domain)
        {
            let detail = match error {
                stellar_agent_network::counterparty::CounterpartyError::HomeDomainInvalid {
                    detail,
                } => detail,
                other => other.to_string(),
            };
            return Ok(identity_error_to_tool_result(
                &IdentityError::HomeDomainInvalid { detail },
            ));
        }
        if call_two && let Err(result) = self.verify_mainnet_freshness(&guard) {
            return Ok(result);
        }
        let signer = match self.mainnet_enrolled_signer(&guard) {
            Ok(signer) => signer,
            Err(error) => return Ok(endpoint_refusal_result(&error)),
        };
        let payer = stellar_strkey::ed25519::PublicKey(signer.public_key())
            .to_string()
            .as_str()
            .to_owned();
        // On mainnet the address check precedes the identity gate, so a
        // mismatching address spends no approval.
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
                TOOL,
                &json!({"chain_id": args.chain_id, "home_domain": args.home_domain}),
                &args.chain_id,
                value,
            )
            .await
        {
            Ok(outcome) => outcome,
            Err(error) => return error.into_result(),
        };
        let dispatch = match self.force_mainnet_confirmation(TOOL, dispatch) {
            Ok(outcome) => outcome,
            Err(error) => return error.into_result(),
        };
        let network_id: [u8; 32] = {
            use sha2::{Digest, Sha256};
            Sha256::digest(guard.context.network_passphrase().as_bytes()).into()
        };
        if !call_two {
            let DispatchOutcome::RequireApproval(approval) = &dispatch else {
                return Ok(approval_required_indistinguishable(name));
            };
            let entry = (|| {
                let uid = process_uid_for_attestation()
                    .map_err(|error| stellar_agent_core::approval::attest::record_error(&error))?;
                let entry = PendingApproval::new_x402_pending(
                    &network_id,
                    &root,
                    Some(args.home_domain.clone()),
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
            GatedApprovalKind::X402.expectation(approval_subject_x402_authenticated(
                &digest,
                &args.home_domain,
            )),
            args.approval_nonce.as_deref(),
            args.approval_attestation.as_deref(),
            TOOL,
        )
        .await
        {
            Ok(Some(approval)) => approval,
            Ok(None) => return Ok(approval_required_indistinguishable(name)),
            Err(result) => return Ok(result),
        };
        // ── Audit pre-flight (fail-closed) ────────────────────────────────────
        // A log that cannot take a row refuses before the SEP-10 exchange
        // spends the approval.
        if let Err(err) = crate::tools::value_audit::require_value_audit_writer(
            self.security_profile(),
            &self.profile_name_for_approval(),
            self.audit_binding,
        ) {
            return Ok(business_error_result(err.code(), err.to_string()));
        }
        let store = stellar_agent_network::policy_state::PersistedWindowStore::at_path(
            self.window_path.clone(),
        );
        let intent = stellar_agent_network::mainnet::resolve::SorobanIntent {
            consumer: MainnetConsumer::X402Authenticated,
            root_invocation: &root,
            network_id,
        };
        let identity_audit = match audit_readiness(profile, name) {
            Ok(readiness) => readiness,
            Err(error) => return Ok(endpoint_refusal_result(&error)),
        };
        let inputs = MainnetIdentityInputs {
            context: guard.context,
            intent: &intent,
            policy: guard.policy,
            enablement: guard.enablement,
            approval: &approval,
            audit: identity_audit,
            store: &store,
        };
        let verified = match self
            .verify_x402_counterparty_authorized(&args.home_domain, inputs)
            .await
        {
            Ok(verified) => verified,
            Err(ref err) => {
                // A refused authorization was logged with its precondition
                // where it was refused; every other identity failure is
                // logged here.
                if !matches!(err, IdentityError::MainnetAuthorizationRefused) {
                    tracing::warn!(
                        error_code = %err.wire_code(),
                        home_domain = %args.home_domain,
                        "x402_authenticated_payment: mainnet identity gate aborted before payment",
                    );
                }
                return Ok(identity_error_to_tool_result(err));
            }
        };
        let (session, receipt) = verified.into_parts();

        let readiness = match audit_readiness(profile, name) {
            Ok(readiness) => readiness,
            Err(error) => return Ok(endpoint_refusal_result(&error)),
        };
        let handle =
            match crate::tools::x402_create_payment::x402_mainnet_signing_handle(&signer, &payer) {
                Ok(handle) => handle,
                Err(result) => return Ok(result),
            };
        let asset = match x402_canonical_asset(&requirements) {
            Ok(asset) => asset,
            Err(result) => return Ok(result),
        };
        let mut audit = X402AuthorizationAudit::new(self, TOOL, &args.chain_id, audit_leg)
            .with_decision(PolicyDecision::RequireApproval);
        let created = create_payment_authorized(
            &requirements,
            MainnetConsumer::X402Authenticated,
            X402MainnetProofs::new(
                guard.context,
                guard.policy,
                guard.enablement,
                &approval,
                &signer,
                &handle,
                readiness,
                &store,
            )
            .with_authenticated(receipt),
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
                // An audit refusal at the transmit gate answers its own
                // `audit.*` code.
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
                return Ok(mainnet_payment_error(
                    &error,
                    withheld,
                    audit.transmitted_ledger(),
                ));
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
        let payment_signature =
            match stellar_agent_x402::wire::encode_payment_signature(&created.payment.payload) {
                Ok(signature) => signature,
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
            return Ok(mainnet_payment_error(
                &error,
                withheld,
                audit.transmitted_ledger(),
            ));
        }
        let final_digest = stellar_agent_core::hex::encode(
            &stellar_agent_core::approval::subject::approval_subject_classic(envelope),
        );
        let terminal = self.x402_approval_store().and_then(|mut pending| {
            pending
                .consume(
                    approval.nonce(),
                    &final_digest,
                    stellar_agent_core::approval::ConsumedOutcome::Unknown,
                )
                .map_err(|error| stellar_agent_core::approval::attest::record_error(&error))
        });
        if let Err(error) = require_terminal_consumption(terminal) {
            let withheld = withhold(ReleaseFailure::TerminalApproval);
            return Ok(terminal_payment_error(
                &error,
                withheld,
                audit.transmitted_ledger(),
            ));
        }
        Ok(payment_response(
            &payment_signature,
            &payer,
            &requirements,
            &session,
            &created.payment.cross_check,
        ))
    }

    /// Runs the authorized SEP-10 counterparty gate for `home_domain` over
    /// the mainnet `inputs`.
    ///
    /// A test build may point the gate at a test transport; see
    /// `WalletServer::set_x402_identity_transport_for_test`. The transport
    /// replaces the stellar.toml fetch and the SEP-10 requests only.
    async fn verify_x402_counterparty_authorized(
        &self,
        home_domain: &str,
        inputs: stellar_agent_x402_identity::MainnetIdentityInputs<'_>,
    ) -> Result<stellar_agent_x402_identity::MainnetCounterpartySession, IdentityError> {
        #[cfg(any(test, feature = "test-helpers"))]
        if let Some(transport) = &self.x402_identity_transport_override {
            return stellar_agent_x402_identity::resolve_and_verify_counterparty_authorized_at(
                home_domain,
                &transport.toml_base_url,
                &transport.http,
                transport.web_auth_override.as_deref(),
                inputs,
            )
            .await;
        }
        stellar_agent_x402_identity::resolve_and_verify_counterparty_authorized(home_domain, inputs)
            .await
    }
}

/// Renders a mainnet payment failure after the SEP-10 authentication.
///
/// A refused authorization of the intent, the submission or the release is
/// `network.mainnet_authorization_refused` with a text that says the payload
/// was withheld and names no precondition. A policy denial keeps the reason's
/// `policy.deny.*` code, `FeatureDisabled` maps to the signing refusal
/// `network.mainnet_write_forbidden`, an endpoint identity or cross-check
/// refusal keeps its own code, and every other failure is
/// `x402.payment_build_failed`.
///
/// `transmitted` is the signature expiration ledger of an authorization the
/// transmit gate let through. The denial, refusal and build-failure texts
/// then end with the sentence of
/// [`crate::tools::x402_create_payment::transmitted_authorization`]. The
/// `FeatureDisabled`, endpoint identity and cross-check refusals arise only
/// before anything is signed and keep their texts.
#[cfg(feature = "mainnet-write")]
fn mainnet_payment_error(
    error: &stellar_agent_x402::X402Error,
    withheld: &str,
    transmitted: Option<u32>,
) -> CallToolResult {
    use crate::tools::x402_create_payment::transmitted_authorization;
    use stellar_agent_network::mainnet::MainnetAuthorizationError;
    use stellar_agent_x402::X402Error;
    match error {
        X402Error::MainnetAuthorization(MainnetAuthorizationError::PolicyDenied(_)) => {
            crate::tools::x402_create_payment::mainnet_x402_error(error, withheld, transmitted)
        }
        X402Error::MainnetAuthorization(MainnetAuthorizationError::FeatureDisabled) => {
            crate::tools::common::x402_mainnet_signing_forbidden_result()
        }
        X402Error::MainnetAuthorization(_) | X402Error::MainnetAuthorizationRefused => {
            crate::tools::common::business_error_result(
                stellar_agent_core::error::NetworkError::MainnetAuthorizationRefused.code(),
                format!(
                    "{PAYMENT_REFUSAL_TEXT}{}",
                    transmitted_authorization(transmitted)
                ),
            )
        }
        X402Error::EndpointIdentity(refusal) | X402Error::CrossCheck(refusal) => {
            crate::tools::common::endpoint_refusal_result(refusal)
        }
        other => payment_build_error_result(&format!(
            "{other}{}",
            transmitted_authorization(transmitted)
        )),
    }
}

/// Renders the refusal tombstone of the pending approval after the release
/// consumption. A refused authorization answers with the payment refusal
/// text, every other error with its own message after "payment withheld" and
/// `withheld`; both end with the sentence of
/// [`crate::tools::x402_create_payment::transmitted_authorization`] for
/// `transmitted`.
#[cfg(feature = "mainnet-write")]
fn terminal_payment_error(
    error: &stellar_agent_core::WalletError,
    withheld: &str,
    transmitted: Option<u32>,
) -> CallToolResult {
    let code = error.code();
    let transmitted = crate::tools::x402_create_payment::transmitted_authorization(transmitted);
    let message =
        if code == stellar_agent_core::error::NetworkError::MainnetAuthorizationRefused.code() {
            format!("{PAYMENT_REFUSAL_TEXT}{transmitted}")
        } else {
            format!(
                "payment withheld {withheld}: {}{transmitted}",
                error.message()
            )
        };
    crate::tools::common::business_error_result(code, message)
}

// The x402 decode and error-envelope helpers are single-sourced in
// `crate::tools::common` and imported above.

// ─────────────────────────────────────────────────────────────────────────────
// Test helpers
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(any(test, feature = "test-helpers"))]
impl WalletServer {
    /// Calls `stellar_x402_authenticated_payment` with the given args,
    /// bypassing the rmcp transport.
    ///
    /// Integration-test entry point for handler-level checks.
    ///
    /// # Errors
    ///
    /// Propagates `rmcp::ErrorData` from the `dispatch_gate` preamble.
    /// Identity gate and X402 semantic errors are returned as
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
    pub async fn call_stellar_x402_authenticated_payment(
        &self,
        args: X402AuthenticatedPaymentArgs,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.stellar_x402_authenticated_payment(Parameters(args))
            .await
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
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

    // ── compute_payto_anchored ─────────────────────────────────────────────────

    const PAY_TO_A: &str = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";
    const PAY_TO_B: &str = "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI";
    const PAY_TO_C: &str = "GBBHQ7H4V6RRORKYLHTCAWP6MOHNORRFJSDPXDFYDGJB2LPZUFPXUEW3";
    // A C-strkey (SAC contract) destination — the dominant x402 `payTo` shape.
    const PAY_TO_SAC: &str = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";

    /// Empty ACCOUNTS list → "unknown".
    #[test]
    fn payto_anchored_unknown_when_accounts_empty() {
        let signal = compute_payto_anchored(PAY_TO_A, &[]);
        assert_eq!(
            signal,
            PaytoAnchored::Unknown,
            "empty accounts must yield Unknown"
        );
        assert_eq!(signal.as_str(), "unknown");
    }

    /// payTo in non-empty ACCOUNTS → "anchored".
    #[test]
    fn payto_anchored_anchored_when_paytoin_accounts() {
        let accounts = vec![PAY_TO_A.to_owned(), PAY_TO_B.to_owned()];
        let signal = compute_payto_anchored(PAY_TO_A, &accounts);
        assert_eq!(
            signal,
            PaytoAnchored::Anchored,
            "payTo in accounts must yield Anchored"
        );
        assert_eq!(signal.as_str(), "anchored");
    }

    /// payTo NOT in non-empty ACCOUNTS → "not_anchored".
    #[test]
    fn payto_anchored_not_anchored_when_paytomissing_from_accounts() {
        let accounts = vec![PAY_TO_A.to_owned(), PAY_TO_B.to_owned()];
        let signal = compute_payto_anchored(PAY_TO_C, &accounts);
        assert_eq!(
            signal,
            PaytoAnchored::NotAnchored,
            "payTo absent from non-empty accounts must yield NotAnchored"
        );
        assert_eq!(signal.as_str(), "not_anchored");
    }

    /// A C-strkey `payTo` (SAC destination) against a non-empty G-only
    /// ACCOUNTS list → "unknown", NOT "not_anchored" — SEP-1 ACCOUNTS only lists
    /// G-strkeys, so a C destination can never match and anchoring is
    /// indeterminate (avoids a false-alarm warning on the dominant x402 case).
    #[test]
    fn payto_anchored_unknown_when_payto_is_c_strkey() {
        let accounts = vec![PAY_TO_A.to_owned(), PAY_TO_B.to_owned()];
        let signal = compute_payto_anchored(PAY_TO_SAC, &accounts);
        assert_eq!(
            signal,
            PaytoAnchored::Unknown,
            "a C-strkey payTo against G-only ACCOUNTS must yield Unknown, not NotAnchored"
        );
        assert_eq!(signal.as_str(), "unknown");
    }

    /// Single-element ACCOUNTS, payTo matches → "anchored".
    #[test]
    fn payto_anchored_single_entry_match() {
        let accounts = vec![PAY_TO_B.to_owned()];
        let signal = compute_payto_anchored(PAY_TO_B, &accounts);
        assert_eq!(signal, PaytoAnchored::Anchored);
    }

    /// Single-element ACCOUNTS, payTo differs → "not_anchored".
    #[test]
    fn payto_anchored_single_entry_no_match() {
        let accounts = vec![PAY_TO_B.to_owned()];
        let signal = compute_payto_anchored(PAY_TO_A, &accounts);
        assert_eq!(signal, PaytoAnchored::NotAnchored);
    }

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

    // ── identity_error_to_tool_result ──────────────────────────────────────────

    #[test]
    fn identity_error_to_tool_result_is_error_true() {
        let err = IdentityError::SigningKeyMissing {
            home_domain: "example.com".to_owned(),
        };
        let result = identity_error_to_tool_result(&err);
        assert_eq!(
            result.is_error,
            Some(true),
            "identity error tool result must have is_error = true"
        );
    }

    #[test]
    fn identity_error_to_tool_result_contains_wire_code() {
        let err = IdentityError::WebAuthEndpointMissing {
            home_domain: "example.com".to_owned(),
        };
        let result = identity_error_to_tool_result(&err);
        assert_eq!(
            result.is_error,
            Some(true),
            "identity error tool result must have is_error = true"
        );
        // The content vector must have at least one element.
        assert!(
            !result.content.is_empty(),
            "identity error tool result must have content"
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

    /// A mainnet profile MUST refuse `stellar_x402_authenticated_payment`
    /// structurally before any key access or the SEP-10 identity gate: the
    /// result is an `is_error` x402 envelope carrying the canonical
    /// `network.mainnet_write_forbidden` wire code, and it MUST NOT contain a
    /// `paymentSignature`.
    ///
    /// The keyring mock is intentionally NOT installed, and `home_domain` is a
    /// placeholder that is never resolved: reaching either the identity gate or
    /// the keyring would surface a different message, so this test also proves
    /// the refusal fires before any of that work.
    #[cfg(not(feature = "mainnet-write"))]
    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn mainnet_profile_refuses_before_signing_no_signature_produced() {
        let server = make_mainnet_server();
        let args = X402AuthenticatedPaymentArgs {
            chain_id: "stellar:mainnet".to_owned(),
            home_domain: "example.com".to_owned(),
            payment_required: sample_requirements_json(),
            address: None,
            approval_nonce: None,
            approval_attestation: None,
        };
        let result = server
            .call_stellar_x402_authenticated_payment(args)
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
    /// `stellar_x402_authenticated_payment` must return fail-closed `ErrorData`
    /// with wire code `policy.approval_required_unsupported` and MUST NOT produce
    /// a signed payment or request a SEP-10 session.
    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn require_approval_verdict_is_fail_closed_no_signature_produced() {
        stellar_agent_test_support::keyring_mock::install().ok();
        let server = make_require_approval_server();
        let args = X402AuthenticatedPaymentArgs {
            chain_id: "stellar:testnet".to_owned(),
            home_domain: "example.com".to_owned(),
            payment_required: sample_requirements_json(),
            address: None,
            approval_nonce: None,
            approval_attestation: None,
        };
        let result = server.call_stellar_x402_authenticated_payment(args).await;
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
    /// denial — a denial authorizes no payment, runs no SEP-10 session, and
    /// needs no audit setup, so it must never be masked by
    /// `audit.chain_key_unavailable`.
    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn policy_denial_precedes_the_audit_preflight() {
        use std::sync::Arc;
        stellar_agent_test_support::keyring_mock::install().ok();
        let profile = Profile::builder_testnet(
            "svc-x402ap-denyfirst",
            "acct-x402ap-denyfirst",
            "n-svc",
            "n-acct",
        )
        .with_noop_engine()
        .build();
        let mut server =
            crate::server::WalletServer::new(profile).expect("WalletServer::new in tests");
        server.policy_engine = Arc::new(DenyEngine);
        let args = X402AuthenticatedPaymentArgs {
            chain_id: "stellar:testnet".to_owned(),
            home_domain: "example.com".to_owned(),
            payment_required: sample_requirements_json(),
            address: None,
            approval_nonce: None,
            approval_attestation: None,
        };
        let result = server
            .call_stellar_x402_authenticated_payment(args)
            .await
            .expect("denial must be a business envelope, not a protocol error");
        let (code, _message, text) = crate::tools::common::assert_business_envelope(&result);
        assert_eq!(code, "policy.deny.no_matching_rule");
        assert!(
            !text.contains("\"paymentSignature\""),
            "no payment signature may be produced on a policy denial; got: {text}"
        );
    }

    /// A build with mainnet writes still refuses on a mainnet server that
    /// holds no mainnet context, before any key access or SEP-10 request.
    #[cfg(feature = "mainnet-write")]
    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn a_mainnet_server_without_a_context_refuses() {
        let server = make_mainnet_server();
        assert!(server.mainnet_context.is_none());
        let result = server
            .call_stellar_x402_authenticated_payment(X402AuthenticatedPaymentArgs {
                chain_id: "stellar:mainnet".to_owned(),
                home_domain: "example.com".to_owned(),
                payment_required: sample_requirements_json(),
                address: None,
                approval_nonce: None,
                approval_attestation: None,
            })
            .await
            .unwrap();
        let (code, message, text) = crate::tools::common::assert_business_envelope(&result);
        assert_eq!(code, "network.mainnet_write_forbidden");
        let canonical = crate::tools::common::x402_mainnet_signing_forbidden_result();
        assert_eq!(
            message,
            crate::tools::common::assert_business_envelope(&canonical).1,
            "the signing refusal, before the mainnet admission"
        );
        assert!(!text.contains("\"paymentSignature\""), "{text}");
    }

    /// Both approval arguments are optional properties and the required
    /// fields are the three the testnet flow requires.
    #[test]
    fn the_approval_arguments_are_optional_in_the_schema() {
        let schema =
            serde_json::to_value(schemars::schema_for!(X402AuthenticatedPaymentArgs)).unwrap();
        let properties = schema["properties"].as_object().unwrap();
        assert!(properties.contains_key("approval_nonce"));
        assert!(properties.contains_key("approval_attestation"));
        let mut required = schema["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|field| field.as_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        required.sort();
        assert_eq!(required, ["chain_id", "home_domain", "payment_required"]);
    }

    /// The arguments print whether an attestation is set, never the
    /// attestation.
    #[test]
    fn the_arguments_debug_hides_the_attestation() {
        let args = X402AuthenticatedPaymentArgs {
            chain_id: "stellar:mainnet".to_owned(),
            home_domain: "anchor.example.com".to_owned(),
            payment_required: sample_requirements_json(),
            address: None,
            approval_nonce: Some("nonce-1".to_owned()),
            approval_attestation: Some("attestation-secret".to_owned()),
        };
        let text = format!("{args:?}");
        assert!(text.contains("approval_attestation: Some(<set>)"), "{text}");
        assert!(text.contains("nonce-1"), "{text}");
        assert!(!text.contains("attestation-secret"), "{text}");
    }

    /// Preconditions whose labels must never reach an agent-facing text.
    fn precondition_labels() -> Vec<&'static str> {
        use stellar_agent_network::mainnet::MainnetPrecondition as P;
        [
            P::MessageUseMismatch,
            P::MessageClientAccount,
            P::ApprovalNonceReused,
            P::NotYetValid,
            P::Expired,
            P::ChainNotMainnet,
            P::SignatureInvalid,
            P::ClockUnavailable,
            P::NotOpen,
        ]
        .into_iter()
        .map(P::label)
        .collect()
    }

    /// The two mainnet identity errors answer the network codes; the
    /// authorization refusal says that no signed challenge was submitted and
    /// names no precondition.
    #[test]
    fn the_mainnet_identity_errors_map_to_the_network_codes() {
        let forbidden = identity_error_to_tool_result(&IdentityError::MainnetSigningForbidden {
            detail: stellar_agent_core::error::MAINNET_SIGNING_REFUSAL_DETAIL.to_owned(),
        });
        let (code, message, _) = crate::tools::common::assert_business_envelope(&forbidden);
        assert_eq!(code, "network.mainnet_write_forbidden");
        let refused = identity_error_to_tool_result(&IdentityError::MainnetAuthorizationRefused);
        let (refused_code, refused_message, _) =
            crate::tools::common::assert_business_envelope(&refused);
        assert_eq!(refused_code, "network.mainnet_authorization_refused");
        assert_eq!(
            refused_message,
            "the mainnet authorization for this SEP-10 authentication was refused; no signed \
             challenge was submitted"
        );
        for label in precondition_labels() {
            assert!(!message.contains(label), "{label}: {message}");
            assert!(
                !refused_message.contains(label),
                "{label}: {refused_message}"
            );
        }
    }

    /// A refused authorization of the payment says that the payload was
    /// withheld; a denial keeps its policy code, `FeatureDisabled` the write
    /// refusal, and every other error its own code.
    #[cfg(feature = "mainnet-write")]
    #[test]
    fn library_errors_map_to_the_payment_codes() {
        use stellar_agent_network::mainnet::{
            MainnetAuthorizationError as A, MainnetPrecondition as P,
        };
        use stellar_agent_x402::X402Error;
        const PAYMENT: &str = "the mainnet authorization for this payment was refused; the payment payload was \
             withheld";
        for error in [
            X402Error::MainnetAuthorization(A::Refused(P::ApprovalNonceReused)),
            X402Error::MainnetAuthorizationRefused,
        ] {
            let result = mainnet_payment_error(&error, "after intent authorization", None);
            let (code, message, _) = crate::tools::common::assert_business_envelope(&result);
            assert_eq!(code, "network.mainnet_authorization_refused", "{error:?}");
            assert_eq!(message, PAYMENT, "{error:?}");
            for label in precondition_labels() {
                assert!(!message.contains(label), "{label}: {message}");
            }
        }
        let denied = mainnet_payment_error(
            &X402Error::MainnetAuthorization(A::PolicyDenied(Box::new(DenyReason::NoMatchingRule))),
            "before signed transmission",
            None,
        );
        assert_eq!(
            crate::tools::common::assert_business_envelope(&denied).0,
            "policy.deny.no_matching_rule"
        );
        let disabled = mainnet_payment_error(
            &X402Error::MainnetAuthorization(A::FeatureDisabled),
            "before signed transmission",
            None,
        );
        assert_eq!(
            crate::tools::common::assert_business_envelope(&disabled).0,
            "network.mainnet_write_forbidden"
        );
        let other = mainnet_payment_error(
            &X402Error::TransactionBuildFailed {
                detail: "build failed".to_owned(),
            },
            "before signed transmission",
            None,
        );
        assert_eq!(
            crate::tools::common::assert_business_envelope(&other).0,
            "x402.payment_build_failed"
        );
    }

    /// After the transmit gate the refusal, denial, build-failure and
    /// terminal-approval texts end with the sentence naming the signature
    /// expiration ledger, under unchanged codes; before it they do not.
    #[cfg(feature = "mainnet-write")]
    #[test]
    fn post_gate_payment_errors_name_the_transmitted_authorization() {
        use stellar_agent_network::mainnet::{
            MainnetAuthorizationError as A, MainnetPrecondition as P,
        };
        use stellar_agent_x402::X402Error;
        const SENTENCE: &str = "; the signed authorization may have reached the configured RPC \
                                and is valid through ledger 1060";
        let errors = [
            (
                X402Error::MainnetAuthorization(A::Refused(P::NotOpen)),
                "network.mainnet_authorization_refused",
            ),
            (
                X402Error::MainnetAuthorization(A::PolicyDenied(Box::new(
                    DenyReason::NoMatchingRule,
                ))),
                "policy.deny.no_matching_rule",
            ),
            (
                X402Error::RpcSimulateFailed {
                    detail: "re-simulate returned error".to_owned(),
                },
                "x402.payment_build_failed",
            ),
        ];
        for (error, expected) in &errors {
            let before = mainnet_payment_error(error, "before signed transmission", None);
            let (code, message, _) = crate::tools::common::assert_business_envelope(&before);
            assert_eq!(code, *expected, "{error:?}");
            assert!(!message.contains("valid through ledger"), "{message}");
            let after = mainnet_payment_error(error, "after intent authorization", Some(1060));
            let (code, message, _) = crate::tools::common::assert_business_envelope(&after);
            assert_eq!(code, *expected, "{error:?}");
            assert!(message.ends_with(SENTENCE), "{message}");
        }
        for (error, expected, prefix) in [
            (
                stellar_agent_core::WalletError::from(
                    stellar_agent_core::error::NetworkError::MainnetAuthorizationRefused,
                ),
                "network.mainnet_authorization_refused",
                PAYMENT_REFUSAL_TEXT.to_owned(),
            ),
            (
                stellar_agent_core::WalletError::from(
                    stellar_agent_core::error::ValidationError::ConfigInvalid {
                        component: "approval",
                        reason: "locked".to_owned(),
                    },
                ),
                "validation.config_invalid",
                "payment withheld at terminal approval: ".to_owned(),
            ),
        ] {
            let result = terminal_payment_error(&error, "at terminal approval", Some(1060));
            let (code, message, _) = crate::tools::common::assert_business_envelope(&result);
            assert_eq!(code, expected);
            assert!(message.starts_with(&prefix), "{message}");
            assert!(message.ends_with(SENTENCE), "{message}");
        }
    }

    /// Each failure point of the payment after the identity gate selects the
    /// cleanup stage, the withheld row's stage and the message the tool
    /// passes on.
    #[cfg(feature = "mainnet-write")]
    #[test]
    fn each_failure_point_selects_its_stage() {
        use crate::tools::x402_create_payment::{
            ReleaseFailure, X402Failure, release_decision, x402_withheld_stage,
        };
        use stellar_agent_network::mainnet::resolve::InvalidationStage;
        let simulate = stellar_agent_x402::X402Error::RpcSimulateFailed {
            detail: "re-simulate returned error".to_owned(),
        };
        let build = stellar_agent_x402::X402Error::TransactionBuildFailed {
            detail: "build failed".to_owned(),
        };
        // A library failure records its row with the gate's verdict.
        assert_eq!(
            x402_withheld_stage(false, X402Failure::CreatePayment(&build)),
            None
        );
        assert_eq!(
            x402_withheld_stage(true, X402Failure::CreatePayment(&simulate)),
            Some("resimulation")
        );
        assert_eq!(
            x402_withheld_stage(true, X402Failure::CreatePayment(&build)),
            Some("response_processing")
        );
        // The release failures select the cleanup and the row themselves.
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
}
