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
//! - Signer is loaded from the platform keyring at call time.
//! - The SEP-10 ephemeral key is NOT the payment signer and NOT persisted.
//! - JWT: NEVER logged.  Returned in `authorization` field (the Bearer token
//!   is the product of a successful gate, like a signature).
//!
//! # Output
//!
//! Returns `{ paymentSignature, authorization, payer, asset, amount, payTo,
//! home_domain, network, payto_anchored }`:
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
//!
use rmcp::{
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Content},
    schemars, serde, tool, tool_router,
};
use serde_json::json;
use stellar_agent_mcp_macros::mcp_tool_router;

use stellar_agent_x402_identity::{IdentityError, resolve_and_verify_counterparty};

use crate::server::WalletServer;
use crate::tools::common::{decode_payment_required_input, x402_error_to_tool_result};

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
/// - `chain_id` — CAIP-2 chain identifier (`"stellar:pubnet"` or
///   `"stellar:testnet"`).
/// - `home_domain` — operator-supplied home domain for SEP-10 identity
///   verification (e.g. `"testanchor.stellar.org"`).
/// - `address` — optional signer address (G-strkey).
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(crate = "rmcp::serde")]
pub struct X402AuthenticatedPaymentArgs {
    /// Base64-encoded `PAYMENT-REQUIRED` header value OR raw JSON
    /// `PaymentRequirements` object.
    ///
    /// The tool tries base64-decode + JSON-parse first; falls back to direct
    /// JSON-parse when base64 decoding fails or yields non-JSON bytes.
    pub payment_required: String,

    /// CAIP-2 chain identifier (`"stellar:pubnet"` or `"stellar:testnet"`).
    ///
    /// Validated against the active profile.
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
}

// ─────────────────────────────────────────────────────────────────────────────
// Error → tool result helper
// ─────────────────────────────────────────────────────────────────────────────

/// Maps [`IdentityError`] to a wire-safe `CallToolResult` with `isError = true`.
///
/// No JWT material, no full URLs — the `IdentityError::Display` is already
/// redaction-safe (authority-only URLs, no JWT).
fn identity_error_to_tool_result(err: &IdentityError) -> CallToolResult {
    let resp = json!({
        "error": err.wire_code(),
        "detail": err.to_string(),
    });
    let json_str = serde_json::to_string_pretty(&resp).unwrap_or_else(|_| "{}".to_owned());
    let mut result = CallToolResult::success(vec![Content::text(json_str)]);
    result.is_error = Some(true);
    result
}

/// Builds an `isError = true` tool result for a payment-build failure that
/// occurs AFTER the identity gate has passed. Mirrors the identity-error wire
/// shape so the agent gets a uniform `{ error, detail }` envelope across the
/// whole pipeline; `detail` comes from a redaction-safe error `Display`.
fn payment_build_error_result(detail: &str) -> CallToolResult {
    let resp = json!({
        "error": "payment_build_failed",
        "detail": detail,
    });
    let json_str = serde_json::to_string_pretty(&resp).unwrap_or_else(|_| "{}".to_owned());
    let mut result = CallToolResult::success(vec![Content::text(json_str)]);
    result.is_error = Some(true);
    result
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool router impl block
// ─────────────────────────────────────────────────────────────────────────────

/// Authenticates with the counterparty via SEP-10 and constructs an x402
/// `PAYMENT-SIGNATURE` payload.
///
/// Runs the SEP-10 counterparty-identity gate (home domain → stellar.toml →
/// WEB_AUTH_ENDPOINT + SIGNING_KEY → SSRF bind → ephemeral SEP-10
/// challenge/response → JWT) and THEN calls `create_payment`.  Any gate
/// failure aborts before the payment is built.
///
/// Returns `{ paymentSignature, authorization, payer, asset, amount, payTo,
/// home_domain, network, payto_anchored }` on success.  Errors return
/// `{ "error": "<machine_code>", "detail": "<msg>" }` with `isError = true`.
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
/// Returns `isError = true` with `{ "error": "<code>", "detail": "<msg>" }` when:
/// - `chain_id` does not match the active profile.
/// - `home_domain` stellar.toml is unreachable or unparseable.
/// - `WEB_AUTH_ENDPOINT` or `SIGNING_KEY` absent from stellar.toml.
/// - `WEB_AUTH_ENDPOINT` host != `home_domain` (SSRF bind rejected).
/// - SEP-10 challenge/response fails.
/// - `payment_required` is not valid base64+JSON or raw JSON.
/// - Any x402 `create_payment` error.
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
        chain_id_required = true
    )]
    #[tool(
        name = "stellar_x402_authenticated_payment",
        description = "Authenticate with a counterparty via SEP-10 and construct an x402 v2 \
                       PAYMENT-SIGNATURE payload. Runs the SEP-10 identity gate (home_domain → \
                       stellar.toml → WEB_AUTH_ENDPOINT + SIGNING_KEY → SSRF bind → \
                       ephemeral challenge/response → JWT) then calls create_payment. Any gate \
                       failure aborts BEFORE the payment is built. \
                       Returns { paymentSignature, authorization (Bearer JWT for Authorization header), \
                       payer, asset, amount, payTo, home_domain, network, payto_anchored }. \
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

        use stellar_agent_network::keyring::signer_from_keyring;
        use stellar_agent_x402::exact::create_payment;
        use stellar_agent_x402::wire::encode_payment_signature;

        // Mainnet structural refusal — before any key access, SEP-10 identity
        // gate, or signing. This tool returns a payment authorization the MCP
        // host broadcasts externally; the submit-layer mainnet gate never fires
        // because the wallet does not submit. Refuse on a mainnet profile so no
        // valid mainnet payment signature is ever produced. Wire code:
        // network.mainnet_write_forbidden.
        if self.profile.chain_id.is_mainnet() {
            return Ok(crate::tools::common::x402_mainnet_signing_forbidden_result());
        }

        // ── Telemetry preamble (redaction) ───────────────────────────────────
        let args_value = json!({
            "chain_id": &args.chain_id,
            "home_domain": &args.home_domain,
            "payment_required_len": args.payment_required.len(),
        });

        // ── dispatch_gate: registry lookup + policy evaluation + chain_id ────
        // Single-shot sign tool: RequireApproval is fail-closed. The two-phase
        // approval flow is not supported on this surface.
        match self
            .dispatch_gate(
                "stellar_x402_authenticated_payment",
                &args_value,
                &args.chain_id,
            )
            .await?
        {
            crate::tools::common::DispatchOutcome::Allow => {}
            crate::tools::common::DispatchOutcome::RequireApproval(_) => {
                return Err(crate::tools::common::single_shot_require_approval_error());
            }
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
        let network_passphrase = self.profile.network_passphrase.as_str();
        let session =
            match resolve_and_verify_counterparty(&args.home_domain, network_passphrase).await {
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

        // ── Step 2: Decode payment_required ──────────────────────────────────
        let requirements = match decode_payment_required_input(&args.payment_required) {
            Ok(r) => r,
            Err(ref err) => return Ok(x402_error_to_tool_result(err)),
        };

        // ── Step 3: Validate optional address arg ─────────────────────────────
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

        // ── Step 4: Load signer from keyring ─────────────────────────────────
        let signer_handle =
            match signer_from_keyring(&self.profile.mcp_signer_default, account).await {
                Ok(h) => h,
                Err(err) => {
                    let x402_err = stellar_agent_x402::X402Error::InvalidPaymentRequired {
                        detail: format!("keyring load failed: {err}"),
                    };
                    return Ok(x402_error_to_tool_result(&x402_err));
                }
            };

        // ── Step 5: Resolve RPC URL from active profile (NEVER from input) ───
        let rpc_url = self.profile.rpc_url.as_str();
        let payer_address = account.to_owned();

        // ── Step 6: Dispatch to stellar_agent_x402::create_payment ───────────
        let signer: Arc<dyn stellar_agent_network::signing::Signer + Send + Sync> =
            Arc::new(signer_handle);

        let payment_payload =
            match create_payment(&requirements, signer.as_ref(), rpc_url, network_passphrase).await
            {
                Ok(p) => p,
                Err(source) => {
                    tracing::warn!(
                        "x402_authenticated_payment: create_payment failed after identity gate",
                    );
                    // Surface a uniform single-pipeline error envelope. The
                    // X402Error Display is redaction-safe (authority-only, no secrets).
                    return Ok(payment_build_error_result(&source.to_string()));
                }
            };

        // ── Step 7: Encode PAYMENT-SIGNATURE ─────────────────────────────────
        let payment_signature = match encode_payment_signature(&payment_payload) {
            Ok(sig) => sig,
            Err(source) => {
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
        let payto_anchored = compute_payto_anchored(&requirements.pay_to, &session.accounts);
        let authorization = format!("Bearer {}", session.jwt);
        let response = json!({
            "paymentSignature": payment_signature,
            "authorization": authorization,
            "payer": payer_address,
            "asset": requirements.asset,
            "amount": requirements.amount,
            "payTo": requirements.pay_to,
            "home_domain": session.home_domain,
            "network": requirements.network,
            "payto_anchored": payto_anchored.as_str(),
        });
        let json_str = serde_json::to_string_pretty(&response).unwrap_or_else(|_| "{}".to_owned());
        Ok(CallToolResult::success(vec![Content::text(json_str)]))
    }
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
    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn mainnet_profile_refuses_before_signing_no_signature_produced() {
        let server = make_mainnet_server();
        let args = X402AuthenticatedPaymentArgs {
            chain_id: "stellar:mainnet".to_owned(),
            home_domain: "example.com".to_owned(),
            payment_required: sample_requirements_json(),
            address: None,
        };
        let result = server
            .call_stellar_x402_authenticated_payment(args)
            .await
            .expect("structural mainnet refusal is surfaced as Ok(is_error), not Err");
        assert_eq!(
            result.is_error,
            Some(true),
            "mainnet refusal must set is_error = true"
        );
        let text = result
            .content
            .first()
            .and_then(|c| c.as_text())
            .map(|t| t.text.as_str())
            .expect("refusal result must carry a text content block");
        let value: serde_json::Value =
            serde_json::from_str(text).expect("refusal content must be a JSON object");
        let message = value["message"].as_str().unwrap_or_default();
        assert!(
            message.contains("network.mainnet_write_forbidden"),
            "message must carry the canonical wire code; got: {value}"
        );
        assert!(
            !message.contains("keyring") && !message.contains("unlock"),
            "refusal must fire before key access — message must not mention keyring/unlock: {value}"
        );
        assert!(
            value.get("paymentSignature").is_none(),
            "no payment signature must be produced on mainnet; got: {value}"
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
        };
        let result = server.call_stellar_x402_authenticated_payment(args).await;
        let err = result.expect_err(
            "RequireApproval must return Err(ErrorData), not Ok (which would mean signing proceeded)",
        );
        assert!(
            err.message.contains("policy.approval_required_unsupported"),
            "wire code must be policy.approval_required_unsupported; got: {}",
            err.message
        );
        assert!(
            err.message.contains("single-shot"),
            "error message must mention single-shot; got: {}",
            err.message
        );
    }
}
