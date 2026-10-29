//! HTTP router and handlers for the approval-inbox server.
//!
//! | Method | Path | Handler | Auth |
//! |--------|------|---------|------|
//! | `GET`  | `/bootstrap/{token}` | [`bootstrap_get`] | one-time token |
//! | `GET`  | `/inbox` | [`inbox_get`] | session cookie |
//! | `GET`  | `/pending.json` | [`pending_json`] | session cookie |
//! | `GET`  | `/approval/{nonce}` | [`approval_detail_get`] | session cookie |
//! | `POST` | `/approval/{nonce}/approve` | [`approve_post`] | session + CSRF + proof |
//! | `POST` | `/approval/{nonce}/reject` | [`reject_post`] | session + CSRF + proof |
//! | `POST` | `/session/activity` | [`session_activity_post`] | session + CSRF + proof |
//! | `GET`  | `/static/app-shared.js` | [`app_shared_js`] | session cookie |
//! | `GET`  | `/static/app.js` | [`app_js`] | session cookie |
//! | `GET`  | `/static/session-bootstrap.js` | [`session_bootstrap_js`] | none |
//!
//! The Host / Origin / security-header / body-limit / trace layers are applied
//! at the router level in [`crate::start_serve`], not here. Session-cookie,
//! CSRF and session-proof checks happen at the top of each handler (the auth
//! boundary), never inside [`apply_decision`]. The successful bootstrap
//! response is the only response that carries the session proof; see
//! [`crate::auth`] for the session model and its lifetime.

use axum::{
    Router,
    extract::{Path, RawQuery, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use serde_json::json;

use stellar_agent_core::approval::error::ApprovalError;
use stellar_agent_core::approval::{
    DEFAULT_RETRY_ATTEMPTS, DEFAULT_RETRY_BACKOFF, PendingApprovalView, open_with_retry,
};
use stellar_agent_core::timefmt;

use crate::ServeState;
use crate::auth::{CSRF_HEADER_NAME, SessionState, require_session_proof, verify_csrf};
use crate::decision::{Decision, Outcome, RequestIdentity, apply_decision};
use crate::templates::{
    render_detail_page, render_inbox_page, render_not_found_page, render_session_bootstrap_page,
};
use crate::web;

/// The fixed CSRF nonce `POST /session/activity` binds to; the inbox and
/// detail pages carry its CSRF value next to the per-approval one.
pub(crate) const SESSION_ACTIVITY_NONCE: &str = "session-activity";

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
        .route("/session/activity", post(session_activity_post))
        .route("/static/app-shared.js", get(app_shared_js))
        .route("/static/app.js", get(app_js))
        .route("/static/session-bootstrap.js", get(session_bootstrap_js))
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

/// Recovers the [`SessionState`] iff the request carries the cookie of a live,
/// unexpired session.
///
/// Returns the session on success (with its per-run CSRF key), or a `404`
/// response on an absent / malformed / mismatched cookie or an expired
/// session. Never records activity.
#[allow(
    clippy::result_large_err,
    reason = "the Err variant is the ready-to-return axum Response for the auth-boundary rejection; boxing would only add an allocation on the reject path"
)]
fn require_session(state: &ServeState, headers: &HeaderMap) -> Result<SessionState, Response> {
    let mut guard = match state.auth.lock() {
        Ok(g) => g,
        Err(poison) => poison.into_inner(),
    };
    let now = guard.now();
    guard.require_session(headers, now).ok_or_else(not_found)
}

/// Authorizes a state-changing request: the session cookie, then the CSRF
/// value for `csrf_nonce`, then the session proof, then records the activity.
///
/// Each failure returns its own response: `404` for the session, `403`
/// `csrf_rejected`, `403` `session_proof_invalid`. A session that expired
/// between the cookie check and the activity record answers `404` as well.
#[allow(
    clippy::result_large_err,
    reason = "the Err variant is the ready-to-return axum Response for the auth-boundary rejection; boxing would only add an allocation on the reject path"
)]
fn authorize_mutation(
    state: &ServeState,
    headers: &HeaderMap,
    csrf_nonce: &str,
) -> Result<(), Response> {
    let session = require_session(state, headers)?;
    require_csrf(&session, headers, csrf_nonce)?;
    require_session_proof(&session, headers)?;
    let mut guard = match state.auth.lock() {
        Ok(g) => g,
        Err(poison) => poison.into_inner(),
    };
    let now = guard.now();
    if guard.record_activity(&session.session_id, now) {
        Ok(())
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
/// session.
///
/// The success response sets the session cookie and returns the bootstrap
/// page, which carries the session proof and navigates to `/inbox` once the
/// proof is stored. This is the only response that ever carries the proof.
async fn bootstrap_get(State(state): State<ServeState>, Path(token): Path<String>) -> Response {
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

/// `GET /inbox` — HTML shell seeded with the current snapshot.
async fn inbox_get(
    State(state): State<ServeState>,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let activity_csrf = crate::auth::compute_csrf(&session.csrf_key, SESSION_ACTIVITY_NONCE);

    let include_expired = include_expired_flag(raw_query.as_deref());
    match take_snapshot(&state.ctx.store_path, include_expired) {
        SnapshotResult::Ok {
            pending,
            expired_count,
        } => Html(render_inbox_page(
            &pending,
            expired_count,
            include_expired,
            &activity_csrf,
            &state.identity,
        ))
        .into_response(),
        // The shell still renders on a transient store failure; the client-side
        // poll of /pending.json recovers the rows once the lock clears.
        SnapshotResult::Busy | SnapshotResult::Unavailable => Html(render_inbox_page(
            &[],
            0,
            include_expired,
            &activity_csrf,
            &state.identity,
        ))
        .into_response(),
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
            json!({ "pending": crate::templates::pending_json_value(&pending), "expired_count": expired_count }).to_string(),
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
        return Html(render_not_found_page(&nonce, &state.identity)).into_response();
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
    let activity_csrf = crate::auth::compute_csrf(&session.csrf_key, SESSION_ACTIVITY_NONCE);
    Html(render_detail_page(
        &view,
        &state.ctx.context,
        &csrf,
        &activity_csrf,
        attestation_blob.as_deref(),
        &state.identity,
    ))
    .into_response()
}

/// `POST /approval/{nonce}/approve` — attest / record consent for the approval.
async fn approve_post(
    State(state): State<ServeState>,
    headers: HeaderMap,
    Path(nonce): Path<String>,
) -> Response {
    if let Err(resp) = authorize_mutation(&state, &headers, &nonce) {
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
    if let Err(resp) = authorize_mutation(&state, &headers, &nonce) {
        return resp;
    }
    let outcome = apply_decision(
        &state.ctx,
        Decision::Reject { nonce },
        &RequestIdentity::Local,
    );
    outcome_to_response(outcome)
}

/// `POST /session/activity`: records operator activity, extending the idle
/// limit; never the absolute one.
///
/// Requires the cookie, the CSRF value for [`SESSION_ACTIVITY_NONCE`] and the
/// session proof. Answers `204 No Content`. The browser sends it only on a
/// trusted user interaction, throttled to once a minute; background polling
/// never reaches it.
async fn session_activity_post(State(state): State<ServeState>, headers: HeaderMap) -> Response {
    match authorize_mutation(&state, &headers, SESSION_ACTIVITY_NONCE) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(resp) => resp,
    }
}

/// `GET /static/session-bootstrap.js`: the bootstrap page's script.
///
/// Served without a session: the bootstrap page loads it in the same
/// navigation that sets the cookie, and the bytes are fixed and carry no
/// secret.
async fn session_bootstrap_js() -> Response {
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        web::SESSION_BOOTSTRAP_JS,
    )
        .into_response()
}

/// `GET /static/app-shared.js` — the approval rendering both approval
/// surfaces share (see [`crate::web::APP_SHARED_JS`]).
async fn app_shared_js(State(state): State<ServeState>, headers: HeaderMap) -> Response {
    if let Err(resp) = require_session(&state, &headers) {
        return resp;
    }
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        web::APP_SHARED_JS,
    )
        .into_response()
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
        Outcome::BindingMismatch => (
            StatusCode::OK,
            json!({"status": "binding_mismatch", "message": "this request belongs to another profile or network"}),
        ),
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
        Outcome::Inconsistent => (
            StatusCode::OK,
            json!({
                "status": "inconsistent",
                "message": crate::templates::INCONSISTENT_MESSAGE,
            }),
        ),
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "route test fixture assertions")]
    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode, header},
    };
    use stellar_agent_core::approval::PendingApprovalStore;
    use tower::ServiceExt as _;

    #[tokio::test]
    #[serial_test::serial]
    async fn approve_route_reports_binding_mismatch() {
        let h = crate::tests::Harness::new("binding-mismatch-route");
        let definition = stellar_agent_core::approval::ContextRuleProposalSnapshot::new(
            stellar_agent_core::approval::RuleProposalContextType::Default,
            "rule".to_owned(),
            None,
            vec![stellar_agent_core::approval::RuleProposalSigner::delegated(
                "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                true,
            )],
            vec![],
            vec![0],
            false,
            false,
        );
        let entry = stellar_agent_core::approval::PendingApproval::new_rule_proposal_pending(
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            "Public Global Stellar Network ; September 2015".to_owned(),
            "stellar:mainnet".to_owned(),
            definition,
            [1; 32],
            "rule".to_owned(),
            stellar_agent_core::approval::process_uid_for_attestation().unwrap(),
            stellar_agent_core::approval::DEFAULT_TTL_MS,
        )
        .unwrap();
        let nonce = h.insert(entry);
        let cookie = h.bootstrap().await;
        let request = Request::builder()
            .method("POST")
            .uri(format!("/approval/{nonce}/approve"))
            .header(header::HOST, "127.0.0.1:8080")
            .header(header::ORIGIN, "http://127.0.0.1:8080")
            .header(header::COOKIE, cookie)
            .header("x-stellar-approval-csrf", h.csrf_for(&nonce))
            .header("x-session-proof", h.proof())
            .body(Body::empty())
            .unwrap();
        let response = h.router().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["status"], "binding_mismatch");
        assert_eq!(
            body["message"],
            "this request belongs to another profile or network"
        );
        let store = PendingApprovalStore::open(h.store_path.clone()).unwrap();
        assert!(store.get(&nonce).unwrap().attestation_blob_b64.is_none());
    }
}
