//! HTTP router and handlers for the interactive operator-enrollment server.
//!
//! | Method | Path | Handler | Auth |
//! |--------|------|---------|------|
//! | `GET`  | `/bootstrap/{token}` | [`bootstrap_get`] | one-time token |
//! | `GET`  | `/enroll` | [`enroll_page_get`] | session cookie |
//! | `GET`  | `/static/operator-enroll.js` | [`operator_enroll_js_get`] | session cookie |
//! | `GET`  | `/static/session-bootstrap.js` | [`session_bootstrap_js_get`] | none |
//! | `POST` | `/enroll/challenge` | [`enroll_challenge_post`] | session + CSRF + proof |
//! | `POST` | `/enroll/credential` | [`enroll_credential_post`] | session + CSRF + proof |
//!
//! The Host / Origin / security-header / body-limit / trace layers are
//! applied at the router level by [`super::start_operator_enroll_server`],
//! not here. Session-cookie, CSRF and session-proof checks happen at the top
//! of each handler (the auth boundary), mirroring `crate::routes`. The
//! successful bootstrap response is the only response that carries the
//! session proof.
//!
//! # Registration is verified, then staged
//!
//! `enroll_credential_post` verifies the posted registration response
//! against the challenge `enroll_challenge_post` issued (see
//! `super::registration`) and hands the verified credential to the CLI. It
//! never writes the credential store: the CLI persists an operator
//! credential, or exports a mainnet approval credential, only after the
//! operator types the page's confirmation code at the terminal.
//!
//! # Error responses are distinguishable, not collapsed
//!
//! Unlike the WebAuthn bridge's `/approve` and `/register` POST handlers —
//! which collapse every failure mode to a generic code because they defend
//! against an adversary probing a network-reachable, multi-approval
//! surface — this server is loopback-only, single-operator, and single-use
//! for exactly one enrollment. Its routes answer only the session that
//! exchanged the bootstrap token, so distinguishing "wrong label" from
//! "duplicate credential" from "CSRF mismatch" informs only the operator
//! driving the ceremony.

use std::sync::Arc;

use axum::{
    Router,
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::json;

use stellar_agent_core::approval::webauthn_registration::{
    COSE_ALG_ES256, CREDENTIAL_ID_MAX_BYTES, CREDENTIAL_ID_MIN_BYTES,
    PUBLIC_KEY_UNCOMPRESSED_SEC1_LEN,
};

use crate::auth::{
    CSRF_HEADER_NAME, SessionState, compute_csrf, require_session_proof, verify_csrf,
};
use crate::templates::render_session_bootstrap_page;

use super::confirmation::StagedEnrollment;
use super::registration::{
    EnrollCredentialRequest, OperatorRegistrationError, REGISTRATION_RP_ID, RegistrationChallenge,
    VerifiedOperatorRegistration, normalized_label, verify_operator_registration,
};
use super::templates::render_enroll_page;
use super::web;
use super::{Ceremony, OperatorEnrollState};

/// The single logical action this server's per-session CSRF binds to. Unlike
/// the approval-inbox server (one CSRF value per pending-approval nonce),
/// this server has exactly one state-changing action, so a fixed nonce is
/// sufficient.
const ENROLL_NONCE: &str = "operator-enroll";

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
        .route("/enroll/challenge", post(enroll_challenge_post))
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

    let Some(page) = render_session_bootstrap_page(&session.session_proof.to_hex(), purpose) else {
        return not_found();
    };
    let mut resp = Html(page).into_response();
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
        state.purpose,
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
// Shared POST helpers
// ─────────────────────────────────────────────────────────────────────────────

/// A `403 Forbidden` `csrf_invalid` JSON body.
fn csrf_invalid() -> Response {
    json_response(StatusCode::FORBIDDEN, &json!({"error": "csrf_invalid"}))
}

/// A `400 Bad Request` JSON body carrying `code` as the distinguishing
/// error string.
fn bad_request(code: &'static str) -> Response {
    json_response(StatusCode::BAD_REQUEST, &json!({"error": code}))
}

/// A `409 Conflict` JSON body carrying `code` as the distinguishing error
/// string.
fn conflict(code: &'static str) -> Response {
    json_response(StatusCode::CONFLICT, &json!({"error": code}))
}

/// A `500 Internal Server Error` generic JSON body.
fn internal_error() -> Response {
    json_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        &json!({"error": "enroll_failed"}),
    )
}

fn json_response(status: StatusCode, body: &serde_json::Value) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

/// Locks the ceremony state, recovering a poisoned guard: every mutation
/// under it is a whole-value replacement, so a panic mid-section cannot
/// leave it half-written.
fn lock_ceremony(state: &OperatorEnrollState) -> std::sync::MutexGuard<'_, Ceremony> {
    match state.ceremony.lock() {
        Ok(g) => g,
        Err(poison) => poison.into_inner(),
    }
}

/// The auth boundary of both POST routes, in order: the session cookie
/// (`404` on failure), the CSRF header bound to [`ENROLL_NONCE`] (`403`
/// `csrf_invalid`), and the session proof (`403` `session_proof_invalid`).
/// A request that passes all three records session activity, and the
/// session clock's reading is returned for the handler's checks.
#[allow(
    clippy::result_large_err,
    reason = "the Err variant is the ready-to-return axum Response for the auth-boundary rejection"
)]
fn authorize_post(
    state: &OperatorEnrollState,
    headers: &HeaderMap,
) -> Result<std::time::Instant, Response> {
    let session = require_session(state, headers)?;
    let Some(submitted_hex) = headers.get(CSRF_HEADER_NAME).and_then(|v| v.to_str().ok()) else {
        return Err(csrf_invalid());
    };
    if !verify_csrf(&session.csrf_key, ENROLL_NONCE, submitted_hex) {
        return Err(csrf_invalid());
    }
    require_session_proof(&session, headers)?;
    let mut auth = match state.auth.lock() {
        Ok(g) => g,
        Err(poison) => poison.into_inner(),
    };
    let now = auth.now();
    if !auth.record_activity(&session.session_id, now) {
        return Err(not_found());
    }
    Ok(now)
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /enroll/challenge
// ─────────────────────────────────────────────────────────────────────────────

/// `POST /enroll/challenge`: the ceremony's registration challenge and the
/// options the page registers with.
///
/// Passes [`authorize_post`] first. Returns the outstanding challenge while
/// it is unexpired, so a concurrent or repeated request never replaces it,
/// and issues a fresh one otherwise. Once a registration was accepted the
/// ceremony is over: `409` `already_completed`. The body never carries the
/// session proof.
async fn enroll_challenge_post(
    State(state): State<Arc<OperatorEnrollState>>,
    headers: HeaderMap,
    // The page posts `{}`. The body carries nothing the route uses, and is
    // read so the connection never closes with request bytes unread.
    _body: Bytes,
) -> Response {
    let now = match authorize_post(&state, &headers) {
        Ok(now) => now,
        Err(resp) => return resp,
    };
    let mut ceremony = lock_ceremony(&state);
    if ceremony.completion.is_none() {
        return conflict("already_completed");
    }
    if ceremony
        .challenge
        .as_ref()
        .is_none_or(|challenge| challenge.is_expired(now))
    {
        ceremony.challenge = Some(RegistrationChallenge::generate(now));
    }
    let Some(challenge) = ceremony.challenge.as_ref() else {
        return internal_error();
    };
    let body = json!({
        "challenge": challenge.to_b64url(),
        "rp_id": REGISTRATION_RP_ID,
        "alg": COSE_ALG_ES256,
        "user_verification": "required",
        "resident_key": "required",
        "attestation": "none",
        "timeout_ms": u64::try_from(challenge.remaining(now).as_millis()).unwrap_or(u64::MAX),
    });
    drop(ceremony);
    json_response(StatusCode::OK, &body)
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /enroll/credential
// ─────────────────────────────────────────────────────────────────────────────

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

/// Verifies `payload` against the ceremony's outstanding challenge and
/// returns the verified registration with the challenge it answers.
///
/// # Errors
///
/// - [`OperatorRegistrationError::AlreadyCompleted`] once a registration was
///   accepted.
/// - [`OperatorRegistrationError::Invalid`] when no challenge is outstanding
///   or verification fails; the challenge stays.
/// - [`OperatorRegistrationError::Expired`] when the challenge expired; it
///   is dropped, so the next `POST /enroll/challenge` issues a fresh one.
fn verify_against_ceremony(
    ceremony: &mut Ceremony,
    payload: &EnrollCredentialRequest,
    expected_origin: &str,
    now: std::time::Instant,
) -> Result<(VerifiedOperatorRegistration, [u8; 32]), OperatorRegistrationError> {
    if ceremony.completion.is_none() {
        return Err(OperatorRegistrationError::AlreadyCompleted);
    }
    let challenge = ceremony
        .challenge
        .as_ref()
        .ok_or(OperatorRegistrationError::Invalid)?;
    match verify_operator_registration(payload, challenge, expected_origin, now) {
        Ok(verified) => Ok((verified, *challenge.bytes())),
        Err(OperatorRegistrationError::Expired) => {
            ceremony.challenge = None;
            Err(OperatorRegistrationError::Expired)
        }
        Err(error) => Err(error),
    }
}

/// `POST /enroll/credential`: verify the registration response, stage the
/// credential, and hand it to the CLI for terminal confirmation.
///
/// # Checks, in order
///
/// 1. [`authorize_post`]: session, CSRF, proof, then activity. The body is
///    parsed only after it, so an unauthenticated request learns nothing
///    from its body's shape.
/// 2. A body that is not exactly the [`EnrollCredentialRequest`] fields
///    answers `400` `registration_invalid`; shape checks answer
///    `credential_id_invalid`, `public_key_invalid` and `label_invalid`
///    (`400`). A label is invalid when it holds a control character
///    anywhere, or when, trimmed, it is empty or longer than 64 bytes (see
///    [`normalized_label`]).
/// 3. Under the ceremony lock: a ceremony that already accepted a
///    registration answers `409` `already_completed`; one with no
///    outstanding challenge answers `400` `registration_invalid`.
/// 4. [`verify_operator_registration`]: an expired challenge answers `400`
///    `registration_expired` and is dropped, so the page asks for a fresh
///    one; any other failure answers `400` `registration_invalid` and keeps
///    the challenge.
/// 5. For an operator credential, a credential ID the store already holds
///    answers `409` `duplicate_credential_id`. The read takes no store lock,
///    and [`super::ConfirmedOperatorEnrollment::persist`] refuses a duplicate
///    again under the store's write lock. A mainnet approval ceremony has no
///    store; the owner-signed policy parser refuses a duplicate ID.
///
/// # Single-use enforcement
///
/// A response that passes every check consumes the challenge and the
/// completion latch in the same critical section, so of two concurrent
/// valid posts exactly one is staged and the other sees
/// `already_completed`. A refusal at steps 1 to 5 consumes neither, except
/// that an expired challenge is dropped (step 4). When the CLI has stopped
/// waiting, the challenge and the latch are already consumed and the post
/// answers `409` `already_completed`. The answer is `200`
/// `{"status":"awaiting_confirmation"}`; the store is untouched.
async fn enroll_credential_post(
    State(state): State<Arc<OperatorEnrollState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let now = match authorize_post(&state, &headers) {
        Ok(now) => now,
        Err(resp) => return resp,
    };
    let Ok(payload) = serde_json::from_slice::<EnrollCredentialRequest>(&body) else {
        return bad_request("registration_invalid");
    };

    if !credential_id_shape_is_valid(&payload.credential_id_b64url) {
        return bad_request("credential_id_invalid");
    }
    if !public_key_shape_is_valid(&payload.public_key_sec1_b64) {
        return bad_request("public_key_invalid");
    }
    if normalized_label(&payload.label).is_none() {
        return bad_request("label_invalid");
    }

    let mut ceremony = lock_ceremony(&state);
    let (verified, challenge) =
        match verify_against_ceremony(&mut ceremony, &payload, &state.expected_origin, now) {
            Ok(verified) => verified,
            Err(OperatorRegistrationError::AlreadyCompleted) => {
                return conflict("already_completed");
            }
            Err(OperatorRegistrationError::Expired) => return bad_request("registration_expired"),
            Err(OperatorRegistrationError::Invalid) => return bad_request("registration_invalid"),
        };
    if let Some(store) = state.store.as_ref() {
        match store.find_by_credential_id(verified.credential_id_b64url()) {
            Ok(None) => {}
            Ok(Some(_)) => return conflict("duplicate_credential_id"),
            Err(error) => {
                tracing::warn!(error = %error, "operator enroll: credential store read failed");
                return internal_error();
            }
        }
    }
    let staged = StagedEnrollment::new(verified, &challenge, state.purpose);
    ceremony.challenge = None;
    let Some(completion) = ceremony.completion.take() else {
        return conflict("already_completed");
    };
    drop(ceremony);
    if completion.send(staged).is_err() {
        // The handle stopped waiting: the ceremony window closed before this
        // registration arrived.
        return conflict("already_completed");
    }
    json_response(StatusCode::OK, &json!({"status": "awaiting_confirmation"}))
}
