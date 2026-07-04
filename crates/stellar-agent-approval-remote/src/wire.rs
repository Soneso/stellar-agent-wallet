//! JSON wire types for WebAuthn assertion payloads posted by the browser.
//!
//! Mirrors the standard `PublicKeyCredential` JSON shape
//! (`navigator.credentials.get()`'s resolved value, JSON-serialised) that
//! `stellar-agent-webauthn-bridge`'s handlers already decode — base64url
//! string fields for the credential id and each `AuthenticatorAssertionResponse`
//! byte field, and a DER-encoded signature (browsers emit DER; this crate
//! normalises it to compact + low-S before calling `pre_verify_assertion`,
//! exactly as the bridge does).

use serde::Deserialize;

/// The `response` object of a WebAuthn assertion JSON payload.
#[derive(Debug, Clone, Deserialize)]
pub struct AssertionResponseWire {
    /// Base64url `authenticatorData`.
    pub authenticator_data: String,
    /// Base64url `clientDataJSON`.
    pub client_data_json: String,
    /// Base64url DER-encoded ECDSA signature.
    pub signature: String,
}

/// A full WebAuthn assertion JSON payload, as posted by the browser.
#[derive(Debug, Clone, Deserialize)]
pub struct AssertionWire {
    /// Base64url credential id (`PublicKeyCredential.id`).
    pub id: String,
    /// The assertion response byte fields.
    pub response: AssertionResponseWire,
}

/// `POST /login/assertion` request body: just the assertion.
#[derive(Debug, Clone, Deserialize)]
pub struct LoginAssertionRequest {
    /// The WebAuthn assertion produced over the login challenge.
    pub assertion: AssertionWire,
}

/// `POST /approval/{nonce}/decision` request body: the assertion plus which
/// decision it authorizes.
#[derive(Debug, Clone, Deserialize)]
pub struct ActionAssertionRequest {
    /// `"approve"` or `"reject"`.
    pub decision: String,
    /// The WebAuthn assertion produced over the per-action challenge.
    pub assertion: AssertionWire,
}
