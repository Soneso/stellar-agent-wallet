//! Passkey-registration callback handlers.
//!
//! Implements the two-step browser-handoff registration ceremony:
//!
//! 1. `GET /register/<nonce>` — serves the registration HTML page.
//! 2. `POST /register/<nonce>/credential` — records the browser's registration
//!    response into the approval store.
//!
//! # State type
//!
//! Both handlers accept `State<Arc<tokio::sync::Mutex<PendingApprovalStore>>>`.
//! The GET handler holds the lock only for the duration of the lookup; the POST
//! handler holds the lock through the atomic persist step. The `tokio::sync::Mutex`
//! is async-aware and will not block the runtime.
//!
//! # Error indistinguishability
//!
//! POST handlers return GENERIC error codes only (`approval_not_found`,
//! `webauthn_registration_invalid`). The bridge never echoes typed
//! `ApprovalError` discriminators, validator-failure reasons, or specific
//! failure modes to the client. Distinction is for operator tracing only.
//!
//! # Tracing posture
//!
//! Handlers MUST NOT log request bodies, CSRF tokens, or credential bytes.

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use base64::{
    Engine as _, engine::general_purpose::STANDARD, engine::general_purpose::URL_SAFE_NO_PAD,
};
use serde_json::json;

use stellar_agent_core::approval::{ApprovalKind, RegistrationInput};

use crate::{BridgeState, CsrfToken, templates, wire::RegistrationResponseJSON};

// ─────────────────────────────────────────────────────────────────────────────
// GET /register/<nonce>
// ─────────────────────────────────────────────────────────────────────────────

/// Serve the passkey-registration HTML page for the given approval nonce.
///
/// Looks up `nonce` in the approval store. If found, not expired, and of kind
/// `RegisterPasskey`, renders and returns the HTML registration page.
///
/// # Error-shape contract (GET path)
///
/// - `404 Not Found` + `{"error":"approval_not_found"}` — nonce absent OR
///   expired (the two indistinguishable from the caller's view).
/// - `400 Bad Request` + `{"error":"approval_kind_mismatch"}` — entry
///   present but not `RegisterPasskey`. This deliberately distinguishes
///   wrong-kind from not-found because the caller (operator's MCP client
///   or browser) already knows the nonce via the URL path; the same-
///   information principle that drives the POST-path collapse to a single
///   `approval_not_found` does not apply here. POST handlers DO collapse
///   wrong-kind into the 400 + `approval_not_found` response (see
///   `register_post`).
///
/// # Errors
///
/// - `404 Not Found` — nonce absent or expired.
/// - `400 Bad Request` — entry is present but not a `RegisterPasskey` entry.
pub(crate) async fn register_get(
    Path(nonce): Path<String>,
    State(state): State<BridgeState>,
) -> impl IntoResponse {
    let guard = state.approval_store.lock().await;

    let entry = match guard.get(&nonce) {
        Some(e) => e,
        None => {
            return (
                StatusCode::NOT_FOUND,
                [("content-type", "application/json")],
                json!({"error": "approval_not_found"}).to_string(),
            )
                .into_response();
        }
    };

    // Check expiry against current system time.
    let now_ms = current_unix_ms();
    if entry.is_expired(now_ms) {
        tracing::debug!(path = "/register", "approval entry expired");
        return (
            StatusCode::NOT_FOUND,
            [("content-type", "application/json")],
            json!({"error": "approval_not_found"}).to_string(),
        )
            .into_response();
    }

    // Kind check — must be RegisterPasskey. Mismatch returns 400
    // with a distinct code (not 404) so the client knows the nonce exists but
    // is the wrong kind — acceptable because the nonce is already known to
    // the caller (they navigated to this URL).
    let (csrf_bytes, rp_id, user_handle) = match &entry.kind {
        ApprovalKind::RegisterPasskey {
            csrf_token,
            rp_id,
            user_handle,
            ..
        } => (*csrf_token, rp_id.clone(), *user_handle),
        _ => {
            tracing::debug!(path = "/register", "approval kind mismatch");
            return (
                StatusCode::BAD_REQUEST,
                [("content-type", "application/json")],
                json!({"error": "approval_kind_mismatch"}).to_string(),
            )
                .into_response();
        }
    };

    // Release lock before rendering.
    drop(guard);

    let csrf_hex = hex::encode(csrf_bytes);
    let user_handle_b64 = URL_SAFE_NO_PAD.encode(user_handle);

    let html = templates::render_register_page(&nonce, &csrf_hex, &rp_id, &user_handle_b64);
    axum::response::Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .body(axum::body::Body::from(html))
        .unwrap_or_else(|_| (StatusCode::INTERNAL_SERVER_ERROR, "").into_response())
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /register/<nonce>/credential
// ─────────────────────────────────────────────────────────────────────────────

/// Record the browser's WebAuthn registration response.
///
/// Validates the CSRF token, parses the `RegistrationResponseJSON` payload,
/// and records the result in the approval store.
///
/// # CSRF validation
///
/// The `X-Stellar-Approval-CSRF` header must carry the hex-encoded token that
/// was embedded in the registration page served by `register_get`. Validation
/// uses `subtle::ConstantTimeEq` for a constant-time comparison.
///
/// # Wire payload contract
///
/// The `response.public_key_sec1_b64` field is provided by the vendored
/// JS bundle, which decodes the COSE public key from the attestation object
/// client-side and passes the uncompressed SEC1 form (`0x04 || X || Y`) in
/// standard base64. This avoids adding a CBOR / COSE parser to the bridge.
///
/// # Error indistinguishability
///
/// `NotFound`, `Expired`, `WrongKind`, and `AlreadyAttested` store errors all
/// collapse to the single code `approval_not_found`. The `RegistrationInput`
/// validation failure collapses to `webauthn_registration_invalid`.
///
/// # Errors
///
/// - `403 Forbidden` — CSRF header absent, non-hex, or mismatch.
/// - `400 Bad Request` — nonce not found / expired / wrong kind; or
///   registration data failed validation.
/// - `200 OK` — `{"status":"recorded"}` on success.
pub(crate) async fn register_post(
    Path(nonce): Path<String>,
    State(state): State<BridgeState>,
    headers: HeaderMap,
    Json(payload): Json<RegistrationResponseJSON>,
) -> impl IntoResponse {
    // ── CSRF header read + decode ─────────────────────────────────────────
    let csrf_header = match headers.get("x-stellar-approval-csrf") {
        Some(v) => v,
        None => {
            return (
                StatusCode::FORBIDDEN,
                [("content-type", "application/json")],
                json!({"error": "csrf_invalid"}).to_string(),
            )
                .into_response();
        }
    };
    let csrf_str = match csrf_header.to_str() {
        Ok(s) => s,
        Err(_) => {
            return (
                StatusCode::FORBIDDEN,
                [("content-type", "application/json")],
                json!({"error": "csrf_invalid"}).to_string(),
            )
                .into_response();
        }
    };
    let submitted_csrf = match CsrfToken::from_hex(csrf_str) {
        Ok(t) => t,
        Err(_) => {
            return (
                StatusCode::FORBIDDEN,
                [("content-type", "application/json")],
                json!({"error": "csrf_invalid"}).to_string(),
            )
                .into_response();
        }
    };

    // ── Lookup + kind check ───────────────────────────────────────────────
    // All of: not-found, expired, wrong-kind collapse to the same 400 error
    // (error indistinguishability).
    let expected_csrf_bytes = {
        let guard = state.approval_store.lock().await;
        let entry = match guard.get(&nonce) {
            Some(e) => e,
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    [("content-type", "application/json")],
                    json!({"error": "approval_not_found"}).to_string(),
                )
                    .into_response();
            }
        };
        let now_ms = current_unix_ms();
        if entry.is_expired(now_ms) {
            return (
                StatusCode::BAD_REQUEST,
                [("content-type", "application/json")],
                json!({"error": "approval_not_found"}).to_string(),
            )
                .into_response();
        }
        match &entry.kind {
            ApprovalKind::RegisterPasskey { csrf_token, .. } => *csrf_token,
            _ => {
                return (
                    StatusCode::BAD_REQUEST,
                    [("content-type", "application/json")],
                    json!({"error": "approval_not_found"}).to_string(),
                )
                    .into_response();
            }
        }
    };

    // ── Constant-time CSRF compare ────────────────────────────────────────
    // Build a CsrfToken from the stored raw bytes for ct_eq comparison.
    let expected_csrf = CsrfToken::from_bytes(expected_csrf_bytes);
    let csrf_ok: bool = submitted_csrf.ct_eq(&expected_csrf).into();
    if !csrf_ok {
        return (
            StatusCode::FORBIDDEN,
            [("content-type", "application/json")],
            json!({"error": "csrf_invalid"}).to_string(),
        )
            .into_response();
    }

    // ── Parse the wire payload into RegistrationInput ─────────────────────

    // Decode credential_id from base64url.
    let credential_id = match URL_SAFE_NO_PAD.decode(&payload.id) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                [("content-type", "application/json")],
                json!({"error": "webauthn_registration_invalid"}).to_string(),
            )
                .into_response();
        }
    };

    // Decode public_key_sec1_b64 from standard base64 (per the vendored-JS contract).
    let public_key_uncompressed_sec1 = match STANDARD.decode(&payload.response.public_key_sec1_b64)
    {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                [("content-type", "application/json")],
                json!({"error": "webauthn_registration_invalid"}).to_string(),
            )
                .into_response();
        }
    };

    // Normalise attestation_object from URL-safe base64 to standard base64.
    // The WebAuthn spec provides attestationObject as base64url; RegistrationInput
    // stores it in standard base64 per the validation contract.
    let attestation_blob_b64 = if payload.response.attestation_object.is_empty() {
        None
    } else {
        match URL_SAFE_NO_PAD.decode(&payload.response.attestation_object) {
            Ok(raw_bytes) => Some(STANDARD.encode(&raw_bytes)),
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    [("content-type", "application/json")],
                    json!({"error": "webauthn_registration_invalid"}).to_string(),
                )
                    .into_response();
            }
        }
    };

    let transports = payload.response.transports;

    // Construct RegistrationInput — runs all invariant validators.
    let registration_input = match RegistrationInput::new(
        credential_id,
        public_key_uncompressed_sec1,
        attestation_blob_b64,
        transports,
    ) {
        Ok(ri) => ri,
        Err(_) => {
            // Error indistinguishability: never echo the typed ApprovalError reason.
            return (
                StatusCode::BAD_REQUEST,
                [("content-type", "application/json")],
                json!({"error": "webauthn_registration_invalid"}).to_string(),
            )
                .into_response();
        }
    };

    // ── Record in store ───────────────────────────────────────────────────
    let result = {
        let mut guard = state.approval_store.lock().await;
        guard.record_passkey_registration(&nonce, registration_input)
    };

    match result {
        Ok(()) => (
            StatusCode::OK,
            [("content-type", "application/json")],
            json!({"status": "recorded"}).to_string(),
        )
            .into_response(),
        Err(_) => {
            // Error indistinguishability: collapse all store errors to a single code.
            (
                StatusCode::BAD_REQUEST,
                [("content-type", "application/json")],
                json!({"error": "approval_not_found"}).to_string(),
            )
                .into_response()
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Current Unix epoch time in milliseconds, or `u64::MAX` if the system clock
/// fails.
///
/// The `u64::MAX` fallback is fail-closed: it is compared against an entry's
/// `expires_at_unix_ms` via `is_expired`, so on a clock failure every entry is
/// treated as expired and the handler returns the not-found response rather
/// than serving a possibly-stale approval.
pub(crate) fn current_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(u64::MAX)
}
