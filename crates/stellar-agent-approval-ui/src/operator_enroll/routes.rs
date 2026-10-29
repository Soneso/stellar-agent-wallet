//! HTTP router and handlers for the interactive operator-enrollment server.
//!
//! | Method | Path | Handler | Auth |
//! |--------|------|---------|------|
//! | `GET`  | `/bootstrap/{token}` | [`bootstrap_get`] | one-time token |
//! | `GET`  | `/enroll` | [`enroll_page_get`] | session cookie |
//! | `GET`  | `/static/operator-enroll.js` | [`operator_enroll_js_get`] | session cookie |
//! | `GET`  | `/static/session-bootstrap.js` | [`session_bootstrap_js_get`] | none |
//! | `POST` | `/enroll/credential` | [`enroll_credential_post`] | session + CSRF + proof |
//!
//! The Host / Origin / security-header / body-limit / trace layers are
//! applied at the router level by [`super::start_operator_enroll_server`],
//! not here. Session-cookie, CSRF and session-proof checks happen at the top
//! of each handler (the auth boundary), mirroring `crate::routes`. The
//! successful bootstrap response is the only response that carries the
//! session proof.
//!
//! # Server-side attestation verification is intentionally omitted
//!
//! `enroll_credential_post` never inspects an attestation statement (the
//! ceremony requests `attestation: "none"` client-side — see
//! `crate::operator_enroll::web::OPERATOR_ENROLL_JS`). Enrolling a
//! credential here authorizes nothing by itself: the profile's
//! `[remote_approval] allowed_credentials` allowlist is the sole
//! authorization gate, consulted only later, at assertion time. Verifying an
//! attestation statement would add complexity (a CBOR/COSE parser, a trust
//! anchor set) in exchange for a guarantee this surface has no use for —
//! knowing the authenticator's make and model does not change whether its
//! credential id ends up on the allowlist.
//!
//! # Error responses are distinguishable, not collapsed
//!
//! Unlike the WebAuthn bridge's `/approve` and `/register` POST handlers —
//! which collapse every failure mode to a generic code because they defend
//! against an adversary probing a network-reachable, multi-approval
//! surface — this server is loopback-only, single-operator, and single-use
//! for exactly one enrollment. There is no adversarial actor for whom
//! distinguishing "wrong label" from "duplicate credential" from "CSRF
//! mismatch" would be useful information; surfacing the specific reason is
//! strictly better for the operator driving the ceremony.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use serde_json::json;

use stellar_agent_core::approval::error::ApprovalError;
use stellar_agent_core::approval::operator_credentials::OperatorApprovalCredential;

use crate::auth::{
    CSRF_HEADER_NAME, SessionState, compute_csrf, require_session_proof, verify_csrf,
};
use crate::templates::render_session_bootstrap_page;

use super::OperatorEnrollState;
use super::templates::render_enroll_page;
use super::web;

/// The single logical action this server's per-session CSRF binds to. Unlike
/// the approval-inbox server (one CSRF value per pending-approval nonce),
/// this server has exactly one state-changing action, so a fixed nonce is
/// sufficient.
const ENROLL_NONCE: &str = "operator-enroll";

// ─────────────────────────────────────────────────────────────────────────────
// Wire-format bounds
// ─────────────────────────────────────────────────────────────────────────────

/// Minimum credential ID length in raw bytes.
///
/// Mirrors `CREDENTIAL_ID_MIN_BYTES` in
/// `stellar_agent_core::approval::operator_credentials` (CTAP2 §4.2 /
/// WebAuthn-2 §5.4.7). Duplicated at this wire boundary only so a bounds
/// violation gets its own distinguishing error code before the store's own
/// (redundant, defense-in-depth) validation runs.
const CREDENTIAL_ID_MIN_BYTES: usize = 16;

/// Maximum credential ID length in raw bytes. See
/// [`CREDENTIAL_ID_MIN_BYTES`].
const CREDENTIAL_ID_MAX_BYTES: usize = 64;

/// Length of an uncompressed SEC1 P-256 public key in bytes. Mirrors
/// `PUBLIC_KEY_UNCOMPRESSED_SEC1_LEN` in
/// `stellar_agent_core::approval::operator_credentials`.
const PUBLIC_KEY_UNCOMPRESSED_SEC1_LEN: usize = 65;

/// Maximum accepted label length in bytes, matching the page's
/// `maxlength="64"` input attribute.
const MAX_LABEL_BYTES: usize = 64;

// ─────────────────────────────────────────────────────────────────────────────
// Router
// ─────────────────────────────────────────────────────────────────────────────

/// Build the router (without the outer middleware stack, which is applied by
/// [`super::start_operator_enroll_server`]).
pub(super) fn build_router() -> Router<Arc<OperatorEnrollState>> {
    Router::new()
        .route("/bootstrap/{token}", get(bootstrap_get))
        .route("/enroll", get(enroll_page_get))
        .route("/static/operator-enroll.js", get(operator_enroll_js_get))
        .route(
            "/static/session-bootstrap.js",
            get(session_bootstrap_js_get),
        )
        .route("/enroll/credential", post(enroll_credential_post))
}

// ─────────────────────────────────────────────────────────────────────────────
// Auth boundary helpers
// ─────────────────────────────────────────────────────────────────────────────

/// A bare `404 Not Found` with no body — the uniform auth-boundary posture.
///
/// Absent / malformed / mismatched session, and an already-consumed or
/// unrecognised bootstrap token, collapse to this so no route reveals that a
/// session concept even exists.
fn not_found() -> Response {
    StatusCode::NOT_FOUND.into_response()
}

/// Recovers the [`SessionState`] iff the request carries the cookie of a
/// live, unexpired session.
///
/// Returns the session on success (with its per-run CSRF key), or a `404`
/// response on an absent / malformed / mismatched cookie or an expired
/// session. Never records activity.
#[allow(
    clippy::result_large_err,
    reason = "the Err variant is the ready-to-return axum Response for the auth-boundary rejection; boxing would only add an allocation on the reject path"
)]
fn require_session(
    state: &OperatorEnrollState,
    headers: &HeaderMap,
) -> Result<SessionState, Response> {
    let mut guard = match state.auth.lock() {
        Ok(g) => g,
        Err(poison) => poison.into_inner(),
    };
    let now = guard.now();
    guard.require_session(headers, now).ok_or_else(not_found)
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /bootstrap/{token}
// ─────────────────────────────────────────────────────────────────────────────

/// `GET /bootstrap/{token}` — one-time exchange of the bootstrap token for a
/// session.
///
/// The success response sets the session cookie and returns the bootstrap
/// page, which carries the session proof and navigates to `/enroll` once the
/// proof is stored. This is the only response that ever carries the proof.
async fn bootstrap_get(
    State(state): State<Arc<OperatorEnrollState>>,
    Path(token): Path<String>,
) -> Response {
    let mut guard = match state.auth.lock() {
        Ok(g) => g,
        Err(poison) => poison.into_inner(),
    };
    let now = guard.now();
    let Some(session) = guard.exchange_bootstrap(&token, now) else {
        return not_found();
    };
    let cookie = guard.set_cookie_value(&session);
    let purpose = guard.purpose();
    drop(guard);

    let mut resp = Html(render_session_bootstrap_page(
        &session.session_proof.to_hex(),
        purpose,
    ))
    .into_response();
    if let Ok(hv) = HeaderValue::from_str(&cookie) {
        resp.headers_mut().insert(header::SET_COOKIE, hv);
    }
    resp
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /static/session-bootstrap.js
// ─────────────────────────────────────────────────────────────────────────────

/// `GET /static/session-bootstrap.js`: the bootstrap page's script, the same
/// bytes the approval inbox serves.
///
/// Served without a session: the bootstrap page loads it in the same
/// navigation that sets the cookie, and the bytes are fixed and carry no
/// secret.
async fn session_bootstrap_js_get() -> Response {
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        crate::web::SESSION_BOOTSTRAP_JS,
    )
        .into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /enroll
// ─────────────────────────────────────────────────────────────────────────────

/// `GET /enroll` — the interactive enrollment page.
async fn enroll_page_get(
    State(state): State<Arc<OperatorEnrollState>>,
    headers: HeaderMap,
) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let csrf = compute_csrf(&session.csrf_key, ENROLL_NONCE);
    Html(render_enroll_page(
        &state.profile,
        &csrf,
        state.label_prefill.as_deref(),
        &state.identity,
    ))
    .into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /static/operator-enroll.js
// ─────────────────────────────────────────────────────────────────────────────

/// `GET /static/operator-enroll.js` — the ceremony browser glue.
async fn operator_enroll_js_get(
    State(state): State<Arc<OperatorEnrollState>>,
    headers: HeaderMap,
) -> Response {
    if let Err(resp) = require_session(&state, &headers) {
        return resp;
    }
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        web::OPERATOR_ENROLL_JS,
    )
        .into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /enroll/credential
// ─────────────────────────────────────────────────────────────────────────────

/// Wire payload for `POST /enroll/credential`.
///
/// `Debug` is deliberately not derived: the payload carries a credential id
/// and a public key, and this crate's tracing layer must never be able to
/// echo either — matching the wire-type convention documented at
/// `stellar_agent_webauthn_bridge::wire`.
#[derive(Deserialize)]
struct EnrollCredentialRequest {
    /// Base64url (no padding) WebAuthn credential id.
    credential_id_b64url: String,
    /// Base64url (no padding) uncompressed SEC1 P-256 public key.
    public_key_sec1_b64: String,
    /// Operator-chosen label, read from the page's label input.
    label: String,
    /// Best-effort sign-count seed extracted client-side. See
    /// `OperatorApprovalCredential::sign_count` for the advisory-trust and
    /// best-effort-seeding rationale. Typed `u32` so any wire value outside
    /// that range is rejected by the JSON extractor before this handler
    /// runs.
    sign_count: u32,
}

/// A `403 Forbidden` `csrf_invalid` JSON body.
fn csrf_invalid() -> Response {
    (
        StatusCode::FORBIDDEN,
        [(header::CONTENT_TYPE, "application/json")],
        json!({"error": "csrf_invalid"}).to_string(),
    )
        .into_response()
}

/// A `400 Bad Request` JSON body carrying `code` as the distinguishing
/// error string.
fn bad_request(code: &'static str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        [(header::CONTENT_TYPE, "application/json")],
        json!({"error": code}).to_string(),
    )
        .into_response()
}

/// A `409 Conflict` JSON body carrying `code` as the distinguishing error
/// string.
fn conflict(code: &'static str) -> Response {
    (
        StatusCode::CONFLICT,
        [(header::CONTENT_TYPE, "application/json")],
        json!({"error": code}).to_string(),
    )
        .into_response()
}

/// A `500 Internal Server Error` generic JSON body.
fn internal_error() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        [(header::CONTENT_TYPE, "application/json")],
        json!({"error": "enroll_failed"}).to_string(),
    )
        .into_response()
}

/// `true` iff `b64url` decodes to a base64url credential id within
/// [`CREDENTIAL_ID_MIN_BYTES`]..=[`CREDENTIAL_ID_MAX_BYTES`] raw bytes.
fn credential_id_shape_is_valid(b64url: &str) -> bool {
    URL_SAFE_NO_PAD
        .decode(b64url)
        .is_ok_and(|b| (CREDENTIAL_ID_MIN_BYTES..=CREDENTIAL_ID_MAX_BYTES).contains(&b.len()))
}

/// `true` iff `b64` decodes to exactly [`PUBLIC_KEY_UNCOMPRESSED_SEC1_LEN`]
/// raw bytes with a leading `0x04` uncompressed-SEC1-P-256 marker.
fn public_key_shape_is_valid(b64: &str) -> bool {
    URL_SAFE_NO_PAD
        .decode(b64)
        .is_ok_and(|b| b.len() == PUBLIC_KEY_UNCOMPRESSED_SEC1_LEN && b.first() == Some(&0x04))
}

/// `POST /enroll/credential` — validate, persist, and (on the first success)
/// fire the single-use completion signal.
///
/// # Session and CSRF
///
/// Requires the session cookie established by the `/bootstrap/{token}`
/// exchange — checked first, so an unauthenticated caller learns nothing
/// beyond a bare `404`. The `X-Stellar-Approval-CSRF` header must then carry
/// `hex(HMAC-SHA256(session_csrf_key, "operator-enroll"))`, the same value
/// embedded in the `/enroll` page's data island, recomputed server-side and
/// compared in constant time via [`crate::auth::verify_csrf`]; a failure is
/// `403` `csrf_invalid`. Last, the `X-Session-Proof` header must carry the
/// session proof the bootstrap page stored; a failure is `403`
/// `session_proof_invalid`. A request that passes all three records session
/// activity before anything is validated or persisted.
///
/// # Single-use enforcement
///
/// The completion latch (`state.completion`, a
/// `std::sync::Mutex<Option<oneshot::Sender<()>>>`) is checked and, on
/// success, consumed while the mutex guard is held across the synchronous
/// `store.enroll` call — never across an `.await` point. This makes the
/// check-is-still-available / persist / consume sequence atomic with
/// respect to any concurrent POST: a second successful-shape request either
/// sees the sender already gone (refused before it can persist anything) or
/// loses the race and is the one that persists — never both. A
/// `DuplicateCredentialId` or other store failure does NOT consume the
/// latch, so the operator can correct and retry within the same server
/// session.
async fn enroll_credential_post(
    State(state): State<Arc<OperatorEnrollState>>,
    headers: HeaderMap,
    Json(payload): Json<EnrollCredentialRequest>,
) -> Response {
    // ── Session, then CSRF, then proof ──────────────────────────────────────
    let session = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let Some(submitted_hex) = headers.get(CSRF_HEADER_NAME).and_then(|v| v.to_str().ok()) else {
        return csrf_invalid();
    };
    if !verify_csrf(&session.csrf_key, ENROLL_NONCE, submitted_hex) {
        return csrf_invalid();
    }
    if let Err(resp) = require_session_proof(&session, &headers) {
        return resp;
    }
    {
        let mut auth = match state.auth.lock() {
            Ok(g) => g,
            Err(poison) => poison.into_inner(),
        };
        let now = auth.now();
        if !auth.record_activity(&session.session_id, now) {
            return not_found();
        }
    }

    // ── Shape validation (before touching the store or the latch) ──────────
    // Decoded only to validate shape; the store re-decodes the original
    // base64 strings itself (`validate_credential_invariants` stays the
    // single source of truth for the persisted invariant).
    if !credential_id_shape_is_valid(&payload.credential_id_b64url) {
        return bad_request("credential_id_invalid");
    }
    if !public_key_shape_is_valid(&payload.public_key_sec1_b64) {
        return bad_request("public_key_invalid");
    }
    let label = payload.label.trim();
    if label.is_empty() || label.len() > MAX_LABEL_BYTES {
        return bad_request("label_invalid");
    }

    let registered_at_unix_ms = match stellar_agent_core::timefmt::now_unix_ms() {
        Ok(n) => n,
        Err(_) => return internal_error(),
    };

    let credential = OperatorApprovalCredential {
        credential_id_b64url: payload.credential_id_b64url,
        public_key_sec1_b64: payload.public_key_sec1_b64,
        rp_id: "localhost".to_owned(),
        label: label.to_owned(),
        registered_at_unix_ms,
        sign_count: Some(payload.sign_count),
    };

    // ── Single-use claim + persist, atomic under one lock ──────────────────
    let mut guard = match state.completion.lock() {
        Ok(g) => g,
        Err(poison) => poison.into_inner(),
    };
    if guard.is_none() {
        drop(guard);
        return conflict("already_completed");
    }

    match state.store.enroll(credential) {
        Ok(()) => {
            if let Some(tx) = guard.take() {
                let _ = tx.send(());
            }
            drop(guard);
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/json")],
                json!({"status": "enrolled"}).to_string(),
            )
                .into_response()
        }
        Err(ApprovalError::DuplicateCredentialId { .. }) => {
            drop(guard);
            conflict("duplicate_credential_id")
        }
        Err(_) => {
            drop(guard);
            internal_error()
        }
    }
}
