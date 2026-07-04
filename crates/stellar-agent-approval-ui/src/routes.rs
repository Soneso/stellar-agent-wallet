//! HTTP router and handlers for the approval-inbox server.
//!
//! | Method | Path | Handler | Auth |
//! |--------|------|---------|------|
//! | `GET`  | `/bootstrap/{token}` | [`bootstrap_get`] | one-time token |
//! | `GET`  | `/inbox` | [`inbox_get`] | session cookie |
//! | `GET`  | `/pending.json` | [`pending_json`] | session cookie |
//! | `GET`  | `/approval/{nonce}` | [`approval_detail_get`] | session cookie |
//! | `POST` | `/approval/{nonce}/approve` | [`approve_post`] | session + CSRF |
//! | `POST` | `/approval/{nonce}/reject` | [`reject_post`] | session + CSRF |
//! | `GET`  | `/static/app.js` | [`app_js`] | session cookie |
//!
//! The Host / Origin / security-header / body-limit / trace layers are applied
//! at the router level in [`crate::start_serve`], not here. Session-cookie and
//! CSRF checks happen at the top of each handler (the auth boundary), never
//! inside [`apply_decision`].

use axum::{
    Router,
    extract::{Path, RawQuery, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use serde_json::json;

use stellar_agent_core::approval::error::ApprovalError;
use stellar_agent_core::approval::{
    DEFAULT_RETRY_ATTEMPTS, DEFAULT_RETRY_BACKOFF, PendingApprovalView, open_with_retry,
};
use stellar_agent_core::timefmt;

use crate::ServeState;
use crate::auth::{
    CSRF_HEADER_NAME, SESSION_COOKIE_NAME, SessionState, session_cookie_value, verify_csrf,
};
use crate::decision::{Decision, Outcome, RequestIdentity, apply_decision};
use crate::templates::{render_detail_page, render_inbox_page, render_not_found_page};
use crate::web;

/// Build the router (without the outer middleware stack, which is applied by
/// [`crate::start_serve`]).
pub(crate) fn build_router() -> Router<ServeState> {
    Router::new()
        .route("/bootstrap/{token}", get(bootstrap_get))
        .route("/inbox", get(inbox_get))
        .route("/pending.json", get(pending_json))
        .route("/approval/{nonce}", get(approval_detail_get))
        .route("/approval/{nonce}/approve", post(approve_post))
        .route("/approval/{nonce}/reject", post(reject_post))
        .route("/static/app.js", get(app_js))
}

// ─────────────────────────────────────────────────────────────────────────────
// Query
// ─────────────────────────────────────────────────────────────────────────────

/// Returns `true` iff the raw query string carries `include_expired=1`.
fn include_expired_flag(raw_query: Option<&str>) -> bool {
    let Some(q) = raw_query else {
        return false;
    };
    q.split('&').any(|pair| pair == "include_expired=1")
}

// ─────────────────────────────────────────────────────────────────────────────
// Auth boundary helpers
// ─────────────────────────────────────────────────────────────────────────────

/// A bare `404 Not Found` with no body — the uniform auth-boundary posture.
///
/// Absent / malformed / mismatched session, and any non-bootstrap request that
/// fails the session check, collapse to this so no route reveals that a session
/// concept even exists.
fn not_found() -> Response {
    StatusCode::NOT_FOUND.into_response()
}

/// A `403 Forbidden` with a generic JSON body for a failed CSRF check.
fn csrf_rejected() -> Response {
    (
        StatusCode::FORBIDDEN,
        [(header::CONTENT_TYPE, "application/json")],
        json!({"error": "csrf_rejected"}).to_string(),
    )
        .into_response()
}

/// A `503 Service Unavailable` `store_busy` body.
fn store_busy() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(header::CONTENT_TYPE, "application/json")],
        json!({"error": "store_busy", "retriable": true}).to_string(),
    )
        .into_response()
}

/// A `503 Service Unavailable` `store_unavailable` body.
fn store_unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(header::CONTENT_TYPE, "application/json")],
        json!({"error": "store_unavailable", "retriable": false}).to_string(),
    )
        .into_response()
}

/// Recovers the [`SessionState`] iff the request carries a valid session cookie.
///
/// Returns the session on success (with its per-run CSRF key), or a `404`
/// response on absent / malformed / mismatched cookie.
#[allow(
    clippy::result_large_err,
    reason = "the Err variant is the ready-to-return axum Response for the auth-boundary rejection; boxing would only add an allocation on the reject path"
)]
fn require_session(state: &ServeState, headers: &HeaderMap) -> Result<SessionState, Response> {
    let guard = match state.auth.lock() {
        Ok(g) => g,
        Err(poison) => poison.into_inner(),
    };
    let session = guard.session.as_ref().ok_or_else(not_found)?;

    let cookie = session_cookie_value(headers).ok_or_else(not_found)?;
    let submitted = crate::auth::OpaqueToken::from_hex(&cookie).ok_or_else(not_found)?;
    if session.session_id.ct_eq(&submitted) {
        Ok(session.clone())
    } else {
        Err(not_found())
    }
}

/// Verifies the per-nonce CSRF header against the session key.
#[allow(
    clippy::result_large_err,
    reason = "the Err variant is the ready-to-return axum Response for the CSRF rejection; boxing would only add an allocation on the reject path"
)]
fn require_csrf(session: &SessionState, headers: &HeaderMap, nonce: &str) -> Result<(), Response> {
    let submitted = headers
        .get(CSRF_HEADER_NAME)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(csrf_rejected)?;
    if verify_csrf(&session.csrf_key, nonce, submitted) {
        Ok(())
    } else {
        Err(csrf_rejected())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Snapshot helper (concurrency model: open → read → drop)
// ─────────────────────────────────────────────────────────────────────────────

enum SnapshotResult {
    Ok {
        pending: Vec<PendingApprovalView>,
        expired_count: usize,
    },
    Busy,
    Unavailable,
}

/// Opens the store, snapshots it, filters per `include_expired`, and drops the
/// store (releasing the file lock) before returning.
fn take_snapshot(store_path: &std::path::Path, include_expired: bool) -> SnapshotResult {
    let store = match open_with_retry(store_path, DEFAULT_RETRY_ATTEMPTS, DEFAULT_RETRY_BACKOFF) {
        Ok(s) => s,
        Err(ApprovalError::WriterLocked) => return SnapshotResult::Busy,
        Err(e) => {
            tracing::debug!(error = %e, "snapshot: store open failed");
            return SnapshotResult::Unavailable;
        }
    };
    let now_ms = match timefmt::now_unix_ms() {
        Ok(n) => n,
        Err(e) => {
            tracing::debug!(error = %e, "snapshot: clock read failed");
            return SnapshotResult::Unavailable;
        }
    };
    let snapshot = store.snapshot(now_ms);
    drop(store);

    let expired_count = snapshot.iter().filter(|v| v.expired).count();
    let pending = if include_expired {
        snapshot
    } else {
        snapshot.into_iter().filter(|v| !v.expired).collect()
    };
    SnapshotResult::Ok {
        pending,
        expired_count,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Handlers
// ─────────────────────────────────────────────────────────────────────────────

/// `GET /bootstrap/{token}` — one-time exchange of the bootstrap token for a
/// session cookie, then redirect to `/inbox`.
async fn bootstrap_get(State(state): State<ServeState>, Path(token): Path<String>) -> Response {
    let mut guard = match state.auth.lock() {
        Ok(g) => g,
        Err(poison) => poison.into_inner(),
    };

    let Some(submitted) = crate::auth::OpaqueToken::from_hex(&token) else {
        return not_found();
    };
    let matches = guard
        .bootstrap
        .as_ref()
        .is_some_and(|stored| stored.ct_eq(&submitted));
    if !matches {
        return not_found();
    }

    // Consume the token immediately: any later request to this path 404s.
    guard.bootstrap = None;
    let session = SessionState::generate();
    let cookie_value = session.session_id.to_hex();
    guard.session = Some(session);
    drop(guard);

    let cookie = format!("{SESSION_COOKIE_NAME}={cookie_value}; HttpOnly; SameSite=Strict; Path=/");
    let mut resp = Redirect::to("/inbox").into_response();
    if let Ok(hv) = HeaderValue::from_str(&cookie) {
        resp.headers_mut().insert(header::SET_COOKIE, hv);
    }
    resp
}

/// `GET /inbox` — HTML shell seeded with the current snapshot.
async fn inbox_get(
    State(state): State<ServeState>,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
) -> Response {
    if let Err(resp) = require_session(&state, &headers) {
        return resp;
    }

    let include_expired = include_expired_flag(raw_query.as_deref());
    match take_snapshot(&state.ctx.store_path, include_expired) {
        SnapshotResult::Ok {
            pending,
            expired_count,
        } => Html(render_inbox_page(&pending, expired_count, include_expired)).into_response(),
        // The shell still renders on a transient store failure; the client-side
        // poll of /pending.json recovers the rows once the lock clears.
        SnapshotResult::Busy | SnapshotResult::Unavailable => {
            Html(render_inbox_page(&[], 0, include_expired)).into_response()
        }
    }
}

/// `GET /pending.json` — the current snapshot as JSON.
async fn pending_json(
    State(state): State<ServeState>,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
) -> Response {
    if let Err(resp) = require_session(&state, &headers) {
        return resp;
    }
    let include_expired = include_expired_flag(raw_query.as_deref());
    match take_snapshot(&state.ctx.store_path, include_expired) {
        SnapshotResult::Ok {
            pending,
            expired_count,
        } => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            json!({ "pending": pending, "expired_count": expired_count }).to_string(),
        )
            .into_response(),
        SnapshotResult::Busy => store_busy(),
        SnapshotResult::Unavailable => store_unavailable(),
    }
}

/// `GET /approval/{nonce}` — the per-approval detail page.
async fn approval_detail_get(
    State(state): State<ServeState>,
    headers: HeaderMap,
    Path(nonce): Path<String>,
) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return resp,
    };

    let store = match open_with_retry(
        &state.ctx.store_path,
        DEFAULT_RETRY_ATTEMPTS,
        DEFAULT_RETRY_BACKOFF,
    ) {
        Ok(s) => s,
        Err(ApprovalError::WriterLocked) => return store_busy(),
        Err(e) => {
            tracing::debug!(error = %e, "detail: store open failed");
            return store_unavailable();
        }
    };
    let now_ms = match timefmt::now_unix_ms() {
        Ok(n) => n,
        Err(_) => return store_unavailable(),
    };

    let view = store
        .snapshot(now_ms)
        .into_iter()
        .find(|v| v.approval_nonce == nonce);

    let Some(view) = view else {
        return Html(render_not_found_page(&nonce)).into_response();
    };

    // For an already-attested payment-style entry, surface the stored blob so a
    // lost success response can be recovered.
    let attestation_blob = if view.attested {
        store
            .get(&nonce)
            .and_then(|e| e.attestation_blob_b64.clone())
    } else {
        None
    };
    drop(store);

    let csrf = crate::auth::compute_csrf(&session.csrf_key, &nonce);
    Html(render_detail_page(
        &view,
        &csrf,
        attestation_blob.as_deref(),
    ))
    .into_response()
}

/// `POST /approval/{nonce}/approve` — attest / record consent for the approval.
async fn approve_post(
    State(state): State<ServeState>,
    headers: HeaderMap,
    Path(nonce): Path<String>,
) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    if let Err(resp) = require_csrf(&session, &headers, &nonce) {
        return resp;
    }
    let outcome = apply_decision(
        &state.ctx,
        Decision::Approve { nonce },
        &RequestIdentity::Local,
    );
    outcome_to_response(outcome)
}

/// `POST /approval/{nonce}/reject` — write a rejection tombstone.
async fn reject_post(
    State(state): State<ServeState>,
    headers: HeaderMap,
    Path(nonce): Path<String>,
) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    if let Err(resp) = require_csrf(&session, &headers, &nonce) {
        return resp;
    }
    let outcome = apply_decision(
        &state.ctx,
        Decision::Reject { nonce },
        &RequestIdentity::Local,
    );
    outcome_to_response(outcome)
}

/// `GET /static/app.js` — the same-origin browser glue.
async fn app_js(State(state): State<ServeState>, headers: HeaderMap) -> Response {
    if let Err(resp) = require_session(&state, &headers) {
        return resp;
    }
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        web::APP_JS,
    )
        .into_response()
}

/// Maps an [`Outcome`] onto the wire JSON response.
fn outcome_to_response(outcome: Outcome) -> Response {
    let (status, body) = match outcome {
        Outcome::Attested {
            attestation: Some(blob),
            expires_at_unix_ms,
        } => (
            StatusCode::OK,
            json!({
                "status": "attested",
                "attestation": blob,
                "expires_at_unix_ms": expires_at_unix_ms,
            }),
        ),
        Outcome::Attested {
            attestation: None, ..
        } => (StatusCode::OK, json!({ "status": "grant_active" })),
        Outcome::Rejected => (StatusCode::OK, json!({ "status": "rejected" })),
        Outcome::AlreadyResolved { attestation } => (
            StatusCode::OK,
            json!({ "status": "already_resolved", "attestation": attestation }),
        ),
        Outcome::Expired => (StatusCode::OK, json!({ "status": "expired" })),
        Outcome::UserMismatch => (
            StatusCode::OK,
            json!({
                "status": "user_mismatch",
                "message": "this approval was created by a different OS user; \
                            run `approve serve` as the same OS user as the \
                            wallet's MCP server process",
            }),
        ),
        Outcome::NotFound => (StatusCode::OK, json!({ "status": "not_found" })),
        Outcome::WrongKind => (StatusCode::OK, json!({ "status": "wrong_kind" })),
        Outcome::Busy => (
            StatusCode::SERVICE_UNAVAILABLE,
            json!({ "status": "busy", "retriable": true }),
        ),
        Outcome::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            json!({ "status": "unavailable", "retriable": false }),
        ),
    };
    (
        status,
        [(header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}
