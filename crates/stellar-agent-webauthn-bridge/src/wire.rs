//! JSON wire types for the WebAuthn browser-handoff bridge.
//!
//! Mirrors the `@simplewebauthn/browser` 13.x `RegistrationResponseJSON` and
//! `AuthenticationResponseJSON` types so that the bridge POST handlers can
//! deserialise the payloads the vendored JS bundle produces.
//!
//! # Security
//!
//! Wire types deliberately do NOT derive `Debug`. A stray
//! `tracing::debug!(?payload)` would otherwise emit raw credential IDs,
//! signature bytes, and client-data-JSON bytes into the structured log. The
//! redacted-Debug rule applies to all wire types that carry WebAuthn byte
//! fields.
//!
//! # Reference
//!
//! `@simplewebauthn/browser` 13.x type definitions; field names follow
//! `camelCase` JSON convention per the spec. `rename_all = "camelCase"` is
//! applied at the struct level.

// Wire struct fields mirror the full @simplewebauthn/browser JSON shape.
// Not every field is consumed by the current handlers — some are part of the
// spec shape and are retained for future validation steps.
#![allow(dead_code, reason = "wire fields: spec shape, future use")]

use serde::Deserialize;

// ─────────────────────────────────────────────────────────────────────────────
// Registration
// ─────────────────────────────────────────────────────────────────────────────

/// JSON wire shape for a completed WebAuthn registration ceremony.
///
/// Corresponds to `@simplewebauthn/browser` 13.x `RegistrationResponseJSON`.
///
/// The `credential_type` field is always `"public-key"` per the WebAuthn spec.
/// The `response` sub-object carries the CBOR-encoded attestation data from
/// the authenticator.
///
/// # Security
///
/// `Debug` is not derived — see module-level security note.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RegistrationResponseJSON {
    /// The base64url-encoded credential ID.
    ///
    /// Per WebAuthn-2 §5.1, `id` is the URL-safe base64 encoding of
    /// `rawId`. The bridge uses `id` as the canonical credential identifier.
    pub id: String,
    /// The raw credential ID, duplicated as a base64url string.
    ///
    /// Provided for completeness; `id` is preferred.
    pub raw_id: String,
    /// Always `"public-key"` per WebAuthn-2 §5.1.
    #[serde(rename = "type")]
    pub credential_type: String,
    /// The authenticator's registration response body.
    pub response: RegistrationResponse,
}

/// The `response` sub-object of a `RegistrationResponseJSON`.
///
/// # Security
///
/// `Debug` is not derived — see module-level security note.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RegistrationResponse {
    /// Base64url-encoded `clientDataJSON` bytes per WebAuthn-2 §5.8.1.1.
    ///
    /// The JSON key is `clientDataJSON` (uppercase `JSON`), which deviates
    /// from serde's `camelCase` output (`clientDataJson`). An explicit
    /// `rename` override is required per the `@simplewebauthn/browser` 13.x
    /// wire contract.
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    /// Base64url-encoded `attestationObject` CBOR bytes per WebAuthn-2 §6.4.
    ///
    /// Stored as `attestation_blob_b64` in `RegistrationInput` after
    /// normalisation from URL-safe to standard base64.
    pub attestation_object: String,
    /// CTAP2 transport hints returned by the authenticator.
    ///
    /// Empty when the authenticator does not report transports.
    #[serde(default)]
    pub transports: Vec<String>,
    /// Uncompressed SEC1 P-256 public key provided by the vendored JS.
    ///
    /// # Contract
    ///
    /// The vendored JS (`webauthn.js`) decodes the COSE public key from
    /// the attestation object client-side and provides the uncompressed SEC1
    /// form (`0x04 || X (32 bytes) || Y (32 bytes)`) here as standard base64.
    /// This avoids adding a CBOR / COSE parser to the bridge's Rust code for
    /// the registration path. The bridge handler validates the decoded bytes
    /// against the 65-byte uncompressed SEC1 constraint before persisting.
    ///
    /// Validated at `RegistrationInput::new` time: exactly 65 bytes,
    /// `[0] == 0x04` per ANSI X9.62 / SEC1 §2.3.3.
    pub public_key_sec1_b64: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Authentication
// ─────────────────────────────────────────────────────────────────────────────

/// JSON wire shape for a completed WebAuthn authentication (assertion) ceremony.
///
/// Corresponds to `@simplewebauthn/browser` 13.x `AuthenticationResponseJSON`.
///
/// # Security
///
/// `Debug` is not derived — see module-level security note.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AuthenticationResponseJSON {
    /// The base64url-encoded credential ID selected by the authenticator.
    pub id: String,
    /// Duplicate of `id` as a base64url string.
    pub raw_id: String,
    /// Always `"public-key"` per WebAuthn-2 §5.1.
    #[serde(rename = "type")]
    pub credential_type: String,
    /// The authenticator's assertion response body.
    pub response: AuthenticationResponse,
}

/// The `response` sub-object of an `AuthenticationResponseJSON`.
///
/// # Security
///
/// `Debug` is not derived — see module-level security note.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AuthenticationResponse {
    /// Base64url-encoded `clientDataJSON` per WebAuthn-2 §5.8.1.1.
    ///
    /// The JSON key is `clientDataJSON` (uppercase `JSON`) per the
    /// `@simplewebauthn/browser` 13.x wire contract; an explicit `rename`
    /// override is required because serde's `camelCase` would produce
    /// `clientDataJson`.
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    /// Base64url-encoded `authenticatorData` per WebAuthn-2 §6.1.
    ///
    /// Minimum 37 bytes when decoded: RP-ID hash (32 bytes) + flags (1 byte)
    /// + signature counter (4 bytes).
    pub authenticator_data: String,
    /// Base64url-encoded DER-encoded ECDSA-secp256r1 signature.
    ///
    /// Per WebAuthn-2 §6.3.3 ("the binary signature is DER-encoded"). The
    /// bridge normalises to compact + low-S via `normalize_der_to_compact_low_s`
    /// before running the pre-verifier pipeline.
    pub signature: String,
    /// Optional base64url-encoded `userHandle`.
    ///
    /// Present when the authenticator returned a user handle in the assertion
    /// response. Not required for the bridge's assertion-recording flow.
    #[serde(default)]
    pub user_handle: Option<String>,
}
