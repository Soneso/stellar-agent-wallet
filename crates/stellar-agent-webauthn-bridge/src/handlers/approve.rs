//! Passkey-approval callback handlers.
//!
//! Implements the three-endpoint approve ceremony:
//!
//! 1. `GET /approve/<nonce>` — serves the approval HTML page.
//! 2. `POST /approve/<nonce>/assertion` — records the browser's WebAuthn
//!    assertion into the approval store after pre-verification.
//! 3. `POST /approve/<nonce>/cancel` — removes the approval entry.
//!
//! # State type
//!
//! All three handlers use [`crate::BridgeState`], which carries the shared
//! approval store plus the per-request passkey public-key lookup used by
//! `POST /approve/<nonce>/assertion`.
//!
//! # Error indistinguishability
//!
//! POST handlers return GENERIC error codes only. The bridge never echoes typed
//! `ApprovalError` discriminators, `WebAuthnInvalidReason` variants, or specific
//! failure modes to the client.
//!
//! # Tracing posture
//!
//! Handlers MUST NOT log request bodies, CSRF tokens, assertion bytes, or
//! WebAuthn error reason discriminators.

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::json;
use sha2::{Digest, Sha256};

use stellar_agent_core::approval::{ApprovalKind, AssertionInput};
use stellar_agent_smart_account::webauthn::{normalize_der_to_compact_low_s, pre_verify_assertion};

use super::register::current_unix_ms;
use crate::{BridgeState, CsrfToken, templates, wire::AuthenticationResponseJSON};

// ─────────────────────────────────────────────────────────────────────────────
// Lookup-failure reason-class (closed set)
// ─────────────────────────────────────────────────────────────────────────────
//
// Closed-set discriminators for the `reason` tracing field on the two
// `pubkey_lookup` failure branches in `approve_assertion_post`. Held as
// module-level `const`s so a future contributor adding a third branch must
// either add a third `const` here (visible in code review) OR pick one of the
// existing two (preserving the closed-set invariant). The wire response is the
// same `webauthn_assertion_invalid` 4xx envelope regardless of `reason`; the
// reason field is debug-trace-only and never leaks to the HTTP client
// (error-indistinguishability invariant).
const LOOKUP_REASON_NOT_FOUND: &str = "not_found";
const LOOKUP_REASON_MALFORMED: &str = "malformed";

// ─────────────────────────────────────────────────────────────────────────────
// GET /approve/<nonce>
// ─────────────────────────────────────────────────────────────────────────────

/// Serve the passkey-approval HTML page for the given approval nonce.
///
/// Looks up `nonce` in the approval store. If found, not expired, and of kind
/// `SignWithPasskey`, renders and returns the HTML approval page.
///
/// # `rp_id` source
///
/// The `SignWithPasskey` approval kind carries an `rp_id` field populated by
/// `CredentialsManager::sign_with_passkey_rule` from the credential's
/// registry-persisted `rp_id` at the time the approval entry is created.
/// `rp_id` flows end-to-end from the passkeys registry through the approval
/// store to the bridge HTML page.
///
/// # Error-shape contract (GET path)
///
/// - `404 Not Found` + `{"error":"approval_not_found"}` — nonce absent OR
///   expired (the two indistinguishable from the caller's view).
/// - `400 Bad Request` + `{"error":"approval_kind_mismatch"}` — entry
///   present but not `SignWithPasskey`. This deliberately distinguishes
///   wrong-kind from not-found because the caller (operator's MCP client
///   or browser) already knows the nonce via the URL path; the same-
///   information principle that drives the POST-path collapse to a single
///   `approval_not_found` does not apply here. POST handlers DO collapse
///   wrong-kind into the 400 + `approval_not_found` response (see
///   `approve_assertion_post`).
///
/// # Errors
///
/// - `404 Not Found` — nonce absent or expired.
/// - `400 Bad Request` — entry present but not `SignWithPasskey`.
pub(crate) async fn approve_get(
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

    let now_ms = current_unix_ms();
    if entry.is_expired(now_ms) {
        tracing::debug!(path = "/approve", "approval entry expired");
        return (
            StatusCode::NOT_FOUND,
            [("content-type", "application/json")],
            json!({"error": "approval_not_found"}).to_string(),
        )
            .into_response();
    }

    let (csrf_bytes, auth_digest, credential_id_bytes, entry_rp_id) = match &entry.kind {
        ApprovalKind::SignWithPasskey {
            csrf_token,
            auth_digest,
            credential_id,
            rp_id,
            ..
        } => (
            *csrf_token,
            *auth_digest,
            credential_id.clone(),
            rp_id.clone(),
        ),
        _ => {
            tracing::debug!(path = "/approve", "approval kind mismatch");
            return (
                StatusCode::BAD_REQUEST,
                [("content-type", "application/json")],
                json!({"error": "approval_kind_mismatch"}).to_string(),
            )
                .into_response();
        }
    };

    drop(guard);

    let csrf_hex = hex::encode(csrf_bytes);
    let auth_digest_hex = hex::encode(auth_digest);
    let credential_id_b64 = URL_SAFE_NO_PAD.encode(&credential_id_bytes);

    // Use the rp_id from the approval entry (stored at sign_with_passkey_rule
    // invocation time from the credential's registry-persisted rp_id).
    let rp_id = entry_rp_id.as_str();

    let html = templates::render_approve_page(
        &nonce,
        &csrf_hex,
        &auth_digest_hex,
        &credential_id_b64,
        rp_id,
    );
    axum::response::Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .body(axum::body::Body::from(html))
        .unwrap_or_else(|_| (StatusCode::INTERNAL_SERVER_ERROR, "").into_response())
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /approve/<nonce>/assertion
// ─────────────────────────────────────────────────────────────────────────────

/// Record the browser's WebAuthn assertion after pre-verification.
///
/// # Pipeline
///
/// 1. CSRF read + decode.
/// 2. Lookup + `SignWithPasskey` kind check (error collapse).
/// 3. Constant-time CSRF compare.
/// 4. Base64url-decode the assertion fields from the wire payload.
/// 5. Normalise the DER signature to compact + low-S via
///    `normalize_der_to_compact_low_s`.
/// 6. Compute `rp_id_hash = sha256(rp_id)`; pass raw `authenticator_data` and
///    `client_data_json` to `pre_verify_assertion`, which forms the
///    `authenticator_data || sha256(client_data_json)` signature payload itself.
/// 7. Run `pre_verify_assertion` (off-chain verification pipeline).
/// 8. Record the `AssertionInput` in the approval store.
///
/// # Error indistinguishability
///
/// Steps 5, 6, 7, 8 — ALL failures collapse to `{"error":"webauthn_assertion_invalid"}`.
/// The `WebAuthnInvalidReason` discriminator is NEVER echoed to the client
/// (timing-oracle defence + error indistinguishability).
///
/// # Errors
///
/// - `403 Forbidden` — CSRF absent, non-hex, or mismatch.
/// - `400 Bad Request` — nonce not found / expired / wrong kind; or assertion
///   failed pre-verification; or store record failed.
/// - `200 OK` — `{"status":"recorded"}` on success.
pub(crate) async fn approve_assertion_post(
    Path(nonce): Path<String>,
    State(state): State<BridgeState>,
    headers: HeaderMap,
    Json(payload): Json<AuthenticationResponseJSON>,
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
    let submitted_csrf = match crate::CsrfToken::from_hex(csrf_str) {
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
    let (expected_csrf_bytes, expected_auth_digest, expected_credential_id, entry_rp_id) = {
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
            ApprovalKind::SignWithPasskey {
                csrf_token,
                auth_digest,
                credential_id,
                rp_id,
                ..
            } => (
                *csrf_token,
                *auth_digest,
                credential_id.clone(),
                rp_id.clone(),
            ),
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

    // ── Decode assertion fields from wire payload ─────────────────────────
    let authenticator_data = match URL_SAFE_NO_PAD.decode(&payload.response.authenticator_data) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                [("content-type", "application/json")],
                json!({"error": "webauthn_assertion_invalid"}).to_string(),
            )
                .into_response();
        }
    };
    let client_data_json = match URL_SAFE_NO_PAD.decode(&payload.response.client_data_json) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                [("content-type", "application/json")],
                json!({"error": "webauthn_assertion_invalid"}).to_string(),
            )
                .into_response();
        }
    };
    let signature_der = match URL_SAFE_NO_PAD.decode(&payload.response.signature) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                [("content-type", "application/json")],
                json!({"error": "webauthn_assertion_invalid"}).to_string(),
            )
                .into_response();
        }
    };
    let credential_id = match URL_SAFE_NO_PAD.decode(&payload.id) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                [("content-type", "application/json")],
                json!({"error": "webauthn_assertion_invalid"}).to_string(),
            )
                .into_response();
        }
    };

    // ── Normalise DER → compact + low-S ──────────────────────────────────
    let (normalised_sig, _was_high_s) = match normalize_der_to_compact_low_s(&signature_der) {
        Ok(result) => result,
        Err(_) => {
            // Error indistinguishability: collapse to generic code.
            return (
                StatusCode::BAD_REQUEST,
                [("content-type", "application/json")],
                json!({"error": "webauthn_assertion_invalid"}).to_string(),
            )
                .into_response();
        }
    };

    // Error-indistinguishability invariant: the wire response collapses
    // `Ok(None)` (no matching record) and `Err(_)` (malformed record) into the
    // SAME `webauthn_assertion_invalid` envelope. We MUST NOT branch the
    // pre-verify wire path on credential-existence — a 2xx-vs-4xx differential
    // would be an oracle for "is this credential ID registered?". The
    // debug-level trace carries a redacted reason-class
    // (`reason = "not_found" | "malformed"`); the trace stays internal (no
    // credential_id bytes leaked) and is gated to debug-level so info-level
    // operator logs do not surface the discriminator.
    let expected_pubkey = match state
        .pubkey_lookup
        .public_key_sec1_for_credential_id(&expected_credential_id)
    {
        Ok(Some(pubkey)) => pubkey,
        Ok(None) => {
            tracing::debug!(
                path = "/approve/assertion",
                reason = LOOKUP_REASON_NOT_FOUND,
                "passkey public-key lookup failed"
            );
            return (
                StatusCode::BAD_REQUEST,
                [("content-type", "application/json")],
                json!({"error": "webauthn_assertion_invalid"}).to_string(),
            )
                .into_response();
        }
        Err(_) => {
            tracing::debug!(
                path = "/approve/assertion",
                reason = LOOKUP_REASON_MALFORMED,
                "passkey public-key lookup failed"
            );
            return (
                StatusCode::BAD_REQUEST,
                [("content-type", "application/json")],
                json!({"error": "webauthn_assertion_invalid"}).to_string(),
            )
                .into_response();
        }
    };

    // ── Pre-verify assertion ──────────────────────────────────────────────
    // Compute RP-ID hash for step 3 (wallet-only defence-in-depth).
    // Uses the rp_id from the approval entry.
    let rp_id_hash: [u8; 32] = Sha256::digest(entry_rp_id.as_bytes()).into();
    let sig_compact = normalised_sig.as_bytes();

    if let Err(_pre_verify_err) = pre_verify_assertion(
        &expected_auth_digest,
        &expected_pubkey,
        &authenticator_data,
        &client_data_json,
        sig_compact,
        &rp_id_hash,
    ) {
        // Error indistinguishability: NEVER echo the WebAuthnInvalidReason discriminator.
        tracing::debug!(path = "/approve/assertion", "pre_verify_assertion failed");
        return (
            StatusCode::BAD_REQUEST,
            [("content-type", "application/json")],
            json!({"error": "webauthn_assertion_invalid"}).to_string(),
        )
            .into_response();
    }

    // Validate credential_id matches expected.
    if credential_id != expected_credential_id {
        tracing::debug!(path = "/approve/assertion", "credential_id mismatch");
        return (
            StatusCode::BAD_REQUEST,
            [("content-type", "application/json")],
            json!({"error": "webauthn_assertion_invalid"}).to_string(),
        )
            .into_response();
    }

    // ── Record assertion in store ─────────────────────────────────────────
    let assertion_input = match AssertionInput::new(
        credential_id,
        authenticator_data,
        client_data_json,
        normalised_sig.as_bytes().to_vec(),
    ) {
        Ok(assertion_input) => assertion_input,
        Err(_err) => {
            tracing::debug!(
                path = "/approve/assertion",
                "assertion input signature invariant failed"
            );
            return (
                StatusCode::BAD_REQUEST,
                [("content-type", "application/json")],
                json!({"error": "webauthn_assertion_invalid"}).to_string(),
            )
                .into_response();
        }
    };

    let result = {
        let mut guard = state.approval_store.lock().await;
        guard.record_passkey_assertion(&nonce, assertion_input)
    };

    match result {
        Ok(()) => (
            StatusCode::OK,
            [("content-type", "application/json")],
            json!({"status": "recorded"}).to_string(),
        )
            .into_response(),
        Err(_) => (
            StatusCode::BAD_REQUEST,
            [("content-type", "application/json")],
            json!({"error": "approval_not_found"}).to_string(),
        )
            .into_response(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /approve/<nonce>/cancel
// ─────────────────────────────────────────────────────────────────────────────

/// Cancel a pending passkey-approval or passkey-registration flow.
///
/// Only `SignWithPasskey` and `RegisterPasskey` entries are removed. Any other
/// approval kind (and an absent nonce) returns `204 No Content` idempotently
/// without removal: the CLI-side cancel path remains authoritative for those
/// kinds, and the identical 204 response avoids a status-code oracle that would
/// reveal an entry's kind.
///
/// # CSRF validation
///
/// CSRF is required even for cancel, so that an attacker cannot force-cancel
/// an approval by sending a crafted request to the cancel endpoint.
///
/// # Errors
///
/// - `403 Forbidden` — CSRF absent, non-hex, or mismatch.
/// - `204 No Content` — entry removed (or was already absent — idempotent).
pub(crate) async fn approve_cancel_post(
    Path(nonce): Path<String>,
    State(state): State<BridgeState>,
    headers: HeaderMap,
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
    let submitted_csrf = match crate::CsrfToken::from_hex(csrf_str) {
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

    // ── Single-lock lookup + CSRF compare + remove (close TOCTOU) ─────────
    //
    // Hold one lock across lookup, CSRF compare, and remove so the three steps
    // are atomic: a concurrent POST cannot replace the entry between the
    // compare and the remove. The crypto (`subtle::ConstantTimeEq`) is fast,
    // so the lock-hold time is negligible.
    let mut guard = state.approval_store.lock().await;

    let entry = match guard.get(&nonce) {
        Some(e) => e,
        None => {
            // Already absent — idempotent cancel.
            return StatusCode::NO_CONTENT.into_response();
        }
    };

    // Only passkey-flow entries are cancellable through the bridge.
    // PaymentSimulated has its own CLI-side cancel path. To preserve error
    // indistinguishability across BOTH body AND status code, a non-passkey
    // entry MUST return the same `204 No Content` as the not-found path
    // (idempotent cancel) — neither 204+leak nor 400+JSON (which would
    // discriminate "exists as non-passkey kind" from "non-existent" via the
    // status code, even with identical bodies). The lock is held but the entry
    // is NOT removed in this arm: the CLI-side cancel path remains
    // authoritative for PaymentSimulated.
    let csrf_bytes = match &entry.kind {
        ApprovalKind::SignWithPasskey { csrf_token, .. } => csrf_token,
        ApprovalKind::RegisterPasskey { csrf_token, .. } => csrf_token,
        _ => {
            return StatusCode::NO_CONTENT.into_response();
        }
    };

    let expected_csrf = CsrfToken::from_bytes(*csrf_bytes);
    let csrf_ok: bool = submitted_csrf.ct_eq(&expected_csrf).into();
    if !csrf_ok {
        return (
            StatusCode::FORBIDDEN,
            [("content-type", "application/json")],
            json!({"error": "csrf_invalid"}).to_string(),
        )
            .into_response();
    }

    // ── Remove entry (still under the same lock) ──────────────────────────
    let _removed = guard.remove(&nonce).unwrap_or(false);
    drop(guard);

    StatusCode::NO_CONTENT.into_response()
}
