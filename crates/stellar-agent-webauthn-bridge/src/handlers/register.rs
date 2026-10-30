//! Passkey-registration callback handlers.
//!
//! Implements the two-step browser-handoff registration ceremony:
//!
//! 1. `GET /register/<nonce>`: serves the registration HTML page, which
//!    carries the entry's registration challenge.
//! 2. `POST /register/<nonce>/credential`: verifies the browser's
//!    registration response against that challenge, this bridge's origin and
//!    the entry's relying-party ID, and records the verified credential into
//!    the approval store.
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

use stellar_agent_core::approval::webauthn_registration::{
    CREDENTIAL_ID_MAX_BYTES, MAX_ATTESTATION_OBJECT_BYTES, MAX_CLIENT_DATA_JSON_BYTES,
    RegistrationExpectation, RegistrationResponse, decode_b64url_capped,
    verify_registration_response,
};
use stellar_agent_core::approval::{ApprovalKind, RegistrationInput};

use crate::{BridgeState, CsrfToken, templates, wire::RegistrationResponseJSON};

// ─────────────────────────────────────────────────────────────────────────────
// GET /register/<nonce>
// ─────────────────────────────────────────────────────────────────────────────

/// Serve the passkey-registration HTML page for the given approval nonce.
///
/// Looks up `nonce` in the approval store. If found, not expired, of kind
/// `RegisterPasskey` and carrying a registration challenge, renders and
/// returns the HTML registration page with that challenge.
///
/// # Error-shape contract (GET path)
///
/// - `404 Not Found` + `{"error":"approval_not_found"}`: nonce absent,
///   expired, or the entry carries no registration challenge (the three
///   indistinguishable from the caller's view).
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
/// - `404 Not Found`: nonce absent or expired, or no registration challenge.
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
    let (csrf_bytes, rp_id, user_handle, challenge) = match &entry.kind {
        ApprovalKind::RegisterPasskey {
            csrf_token,
            rp_id,
            user_handle,
            registration_challenge,
            ..
        } => (
            *csrf_token,
            rp_id.clone(),
            *user_handle,
            *registration_challenge,
        ),
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

    // An entry without a challenge has no response the POST could verify,
    // so it is served like an unknown nonce.
    let Some(challenge) = challenge else {
        tracing::debug!(
            path = "/register",
            "registration entry carries no challenge"
        );
        return (
            StatusCode::NOT_FOUND,
            [("content-type", "application/json")],
            json!({"error": "approval_not_found"}).to_string(),
        )
            .into_response();
    };

    let csrf_hex = hex::encode(csrf_bytes);
    let user_handle_b64 = URL_SAFE_NO_PAD.encode(user_handle);
    let challenge_b64url = URL_SAFE_NO_PAD.encode(challenge);

    let html = templates::render_register_page(
        &nonce,
        &csrf_hex,
        &rp_id,
        &user_handle_b64,
        &challenge_b64url,
        &state.identity,
    );
    axum::response::Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .body(axum::body::Body::from(html))
        .unwrap_or_else(|_| (StatusCode::INTERNAL_SERVER_ERROR, "").into_response())
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /register/<nonce>/credential
// ─────────────────────────────────────────────────────────────────────────────

/// Verify and record the browser's WebAuthn registration response.
///
/// Validates the CSRF token, verifies the `RegistrationResponseJSON` payload
/// against the entry's registration challenge, and records the verified
/// credential in the approval store.
///
/// # CSRF validation
///
/// The `X-Stellar-Approval-CSRF` header must carry the hex-encoded token that
/// was embedded in the registration page served by `register_get`. Validation
/// uses `subtle::ConstantTimeEq` for a constant-time comparison.
///
/// # Verification
///
/// `id` must equal `rawId` and decode as canonical unpadded base64url of
/// 16 to 64 bytes; the page's `publicKeySec1B64` is standard base64 of the
/// uncompressed SEC1 key; `clientDataJSON` and `attestationObject` are
/// canonical unpadded base64url within their caps, and an empty
/// `attestationObject` refuses. The decoded response then passes
/// [`verify_registration_response`] with the entry's challenge, this
/// bridge's origin `http://localhost:<port>` and the entry's `rp_id`: the
/// client data names the challenge, the origin and `webauthn.create`; the
/// `none` attestation's authenticator data names the RP ID hash, user
/// presence and user verification; and the attested credential ID and key
/// are the posted ones. Only the verified ID and key are recorded.
///
/// # Error indistinguishability
///
/// `NotFound`, `Expired`, `WrongKind`, `AlreadyAttested` and a missing
/// registration challenge all collapse to the single code
/// `approval_not_found`. Every decode or verification failure collapses to
/// `webauthn_registration_invalid`.
///
/// # Errors
///
/// - `403 Forbidden` — CSRF header absent, non-hex, or mismatch.
/// - `400 Bad Request`: nonce not found / expired / wrong kind / no
///   registration challenge; or the response failed decoding or
///   verification.
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
    // All of: not-found, expired, wrong-kind, no challenge collapse to the
    // same 400 error (error indistinguishability).
    let (expected_csrf_bytes, registration_challenge, rp_id) = {
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
            ApprovalKind::RegisterPasskey {
                csrf_token,
                registration_challenge,
                rp_id,
                ..
            } => (*csrf_token, *registration_challenge, rp_id.clone()),
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

    let Some(registration_challenge) = registration_challenge else {
        return (
            StatusCode::BAD_REQUEST,
            [("content-type", "application/json")],
            json!({"error": "approval_not_found"}).to_string(),
        )
            .into_response();
    };

    // ── Decode and verify the registration response ───────────────────────
    let Some(registration_input) = verified_registration_input(
        &payload,
        &registration_challenge,
        &state.expected_origin,
        &rp_id,
    ) else {
        // Error indistinguishability: never echo which rule refused.
        return (
            StatusCode::BAD_REQUEST,
            [("content-type", "application/json")],
            json!({"error": "webauthn_registration_invalid"}).to_string(),
        )
            .into_response();
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

/// Decodes `payload`, verifies it against `challenge`, `origin` and `rp_id`,
/// and returns the [`RegistrationInput`] of the verified credential, or
/// `None` for any refusal.
///
/// The recorded ID and key are the ones the verified authenticator data
/// names; the attestation object is kept in standard base64.
fn verified_registration_input(
    payload: &RegistrationResponseJSON,
    challenge: &[u8; 32],
    origin: &str,
    rp_id: &str,
) -> Option<RegistrationInput> {
    if payload.raw_id != payload.id {
        return None;
    }
    let credential_id = decode_b64url_capped(&payload.id, CREDENTIAL_ID_MAX_BYTES)?;
    // The page posts the SEC1 key in standard base64.
    let public_key_sec1 = STANDARD
        .decode(&payload.response.public_key_sec1_b64)
        .ok()?;
    let client_data_json = decode_b64url_capped(
        &payload.response.client_data_json,
        MAX_CLIENT_DATA_JSON_BYTES,
    )?;
    let attestation_object = decode_b64url_capped(
        &payload.response.attestation_object,
        MAX_ATTESTATION_OBJECT_BYTES,
    )?;

    let verified = verify_registration_response(
        &RegistrationResponse {
            credential_id: &credential_id,
            public_key_sec1: &public_key_sec1,
            client_data_json: &client_data_json,
            attestation_object: &attestation_object,
        },
        &RegistrationExpectation {
            challenge,
            origin,
            rp_id,
        },
    )
    .ok()?;

    RegistrationInput::new(
        verified.credential_id().to_vec(),
        verified.public_key_sec1().to_vec(),
        Some(STANDARD.encode(&attestation_object)),
        payload.response.transports.clone(),
    )
    .ok()
}

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
