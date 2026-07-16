//! HTTP router and handlers for the remote-approval server.
//!
//! | Method | Path | Handler | Auth |
//! |--------|------|---------|------|
//! | `GET`  | `/` | [`login_page_get`] | none (pre-auth) |
//! | `GET`  | `/static/login.js` | [`login_js_get`] | none (pre-auth) |
//! | `POST` | `/login/challenge` | [`login_challenge_post`] | rate-limited, no session |
//! | `POST` | `/login/assertion` | [`login_assertion_post`] | none (establishes session) |
//! | `GET`  | `/enroll` | [`enroll_page_get`] | rate-limited, no session |
//! | `GET`  | `/static/enroll.js` | [`enroll_js_get`] | none (pre-auth) |
//! | `GET`  | `/inbox` | [`inbox_get`] | session cookie |
//! | `GET`  | `/pending.json` | [`pending_json`] | session cookie |
//! | `GET`  | `/approval/{nonce}` | [`approval_detail_get`] | session cookie |
//! | `POST` | `/approval/{nonce}/challenge` | [`action_challenge_post`] | session + CSRF |
//! | `POST` | `/approval/{nonce}/decision` | [`action_decision_post`] | session + CSRF |
//! | `GET`  | `/static/app.js` | [`app_js_get`] | session cookie |
//!
//! Session and CSRF checks happen at the top of each handler, mirroring the
//! loopback approval-inbox server's auth-boundary discipline: absent /
//! malformed / mismatched session collapses to a bare `404`.
//!
//! `/static/login.js` is deliberately ungated: it runs the passkey login
//! ceremony, which IS the authentication step, so no session can exist yet
//! for it to run behind. `/enroll` and `/static/enroll.js` are pre-auth for
//! the same reason: a WebAuthn credential is bound to its rp.id at creation,
//! so enrollment must run from this origin before any session exists.
//! `/enroll` (the page load, the only work this pre-auth surface does)
//! shares the SAME token bucket `/login/challenge` uses — it never accepts
//! or persists a credential; it only runs `navigator.credentials.create()`
//! client-side and displays the result for manual entry into the
//! loopback-only `approve operator enroll` CLI command. `/static/app.js` —
//! the inbox, detail, and per-action ceremony glue — is gated behind the
//! session cookie, mirroring the loopback approval-inbox server's own
//! `/static/app.js` gating.

use axum::{
    Router,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use serde_json::json;

use stellar_agent_approval_ui::{Decision, RequestIdentity, apply_decision};
use stellar_agent_core::approval::attest::decode_sha256_hex;
use stellar_agent_core::approval::error::ApprovalError;
use stellar_agent_core::approval::user_id::{ApproverIdentity, VerifiedPasskeyAssertion};
use stellar_agent_core::approval::{ApprovalKind, PendingApproval, PendingApprovalView};
use stellar_agent_core::timefmt;

use crate::RemoteServeState;
use crate::challenge_store::derive_action_challenge;
use crate::open_store;
use crate::session::{
    CSRF_HEADER_NAME, SessionState, compute_csrf, session_cookie_value, session_set_cookie_header,
    verify_csrf,
};
use crate::templates::{
    render_detail_page, render_enroll_page, render_inbox_page, render_login_page,
    render_message_page, render_not_found_page,
};
use crate::verify::verify_wire_assertion;
use crate::web;
use crate::wire::{ActionAssertionRequest, LoginAssertionRequest};

/// Build the router (without the outer middleware stack, applied by
/// [`crate::build_router`]).
pub(crate) fn build_router() -> Router<RemoteServeState> {
    Router::new()
        .route("/", get(login_page_get))
        .route("/static/login.js", get(login_js_get))
        .route("/login/challenge", post(login_challenge_post))
        .route("/login/assertion", post(login_assertion_post))
        .route("/enroll", get(enroll_page_get))
        .route("/static/enroll.js", get(enroll_js_get))
        .route("/inbox", get(inbox_get))
        .route("/pending.json", get(pending_json))
        .route("/approval/{nonce}", get(approval_detail_get))
        .route("/approval/{nonce}/challenge", post(action_challenge_post))
        .route("/approval/{nonce}/decision", post(action_decision_post))
        .route("/static/app.js", get(app_js_get))
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared response helpers
// ─────────────────────────────────────────────────────────────────────────────

fn not_found() -> Response {
    StatusCode::NOT_FOUND.into_response()
}

fn json_response(status: StatusCode, body: &serde_json::Value) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

fn assertion_invalid() -> Response {
    json_response(
        StatusCode::BAD_REQUEST,
        &json!({"error": "webauthn_assertion_invalid"}),
    )
}

fn csrf_rejected() -> Response {
    json_response(StatusCode::FORBIDDEN, &json!({"error": "csrf_rejected"}))
}

fn store_busy() -> Response {
    json_response(
        StatusCode::SERVICE_UNAVAILABLE,
        &json!({"error": "store_busy", "retriable": true}),
    )
}

fn store_unavailable() -> Response {
    json_response(
        StatusCode::SERVICE_UNAVAILABLE,
        &json!({"error": "store_unavailable", "retriable": false}),
    )
}

/// Recovers the [`SessionState`] iff the request carries a valid, unexpired
/// session cookie for the CURRENT (single, live) session.
///
/// An expired session (see [`SessionState::is_expired`]) is treated exactly
/// like no session at all: the same `404` response, and the stale session is
/// dropped from `state.session` so the next login starts clean rather than
/// leaving a dead entry around indefinitely.
#[allow(
    clippy::result_large_err,
    reason = "the Err variant is the ready-to-return Response for the auth-boundary rejection"
)]
fn require_session(
    state: &RemoteServeState,
    headers: &HeaderMap,
) -> Result<SessionState, Response> {
    let mut guard = match state.session.lock() {
        Ok(g) => g,
        Err(poison) => poison.into_inner(),
    };

    let expired = guard.as_ref().is_some_and(SessionState::is_expired);
    if expired {
        *guard = None;
    }

    let session = guard.as_ref().ok_or_else(not_found)?;

    let cookie = session_cookie_value(headers).ok_or_else(not_found)?;
    let submitted = crate::session::OpaqueToken::from_hex(&cookie).ok_or_else(not_found)?;
    if session.session_id.ct_eq(&submitted) {
        Ok(session.clone())
    } else {
        Err(not_found())
    }
}

#[allow(
    clippy::result_large_err,
    reason = "the Err variant is the ready-to-return Response for the CSRF rejection"
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

/// Derives the server-side envelope-hash input to the per-action challenge
/// for `entry`, per [`ApprovalKind`].
///
/// `PaymentSimulated` / `ClaimSimulated` entries carry a real envelope
/// SHA-256. MPP and rule-proposal entries carry their own content digests.
/// `RuleProposalSimulated` has no envelope but carries its own
/// domain-separated `proposal_sha256` digest over the resolved rule
/// definition — using it here (rather than falling back to the zero
/// placeholder) binds the per-action challenge to the EXACT rule the
/// operator reviewed, the same strengthening `envelope_sha256_hex` gives
/// `PaymentSimulated` / `ClaimSimulated`. Other attestable kinds
/// (`ToolsetFirstInvokeGate`, `TrustlineClawbackOptIn`) have no such digest,
/// and use a fixed all-zero 32-byte placeholder — the challenge's binding for
/// those kinds rests on `approval_nonce` (unique per entry) rather than a
/// content digest, which is the same binding the HMAC attestation preimage
/// itself uses for those kinds (`compute_attestation` with a domain-specific
/// digest, not an envelope hash).
fn entry_envelope_sha256(entry: &PendingApproval) -> [u8; 32] {
    match &entry.kind {
        ApprovalKind::PaymentSimulated {
            envelope_sha256_hex,
            ..
        }
        | ApprovalKind::ClaimSimulated {
            envelope_sha256_hex,
            ..
        } => decode_sha256_hex(envelope_sha256_hex).unwrap_or([0u8; 32]),
        ApprovalKind::RuleProposalSimulated {
            proposal_sha256, ..
        } => *proposal_sha256,
        ApprovalKind::MppChargeSimulated {
            prepared_artifact_hash,
            ..
        } => *prepared_artifact_hash,
        _ => [0u8; 32],
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Handlers — login
// ─────────────────────────────────────────────────────────────────────────────

/// `GET /` — the login page. No session required; this IS the
/// pre-authentication surface. Loads the ungated `/static/login.js`.
async fn login_page_get(State(state): State<RemoteServeState>) -> Response {
    Html(render_login_page(&state.rp_id)).into_response()
}

/// `GET /static/login.js` — the pre-authentication login-ceremony browser
/// glue. Ungated: the login ceremony itself IS the authentication step.
async fn login_js_get() -> Response {
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        web::LOGIN_JS,
    )
        .into_response()
}

/// `POST /login/challenge` — mints a single-use login challenge.
///
/// Rate-limited by a process-wide token bucket (see
/// `crate::rate_limit`) — this is the only endpoint reachable before any
/// WebAuthn assertion is checked, so it is the network-exposed surface the
/// bucket protects.
async fn login_challenge_post(State(state): State<RemoteServeState>) -> Response {
    let allowed = {
        let mut limiter = match state.login_rate_limiter.lock() {
            Ok(g) => g,
            Err(poison) => poison.into_inner(),
        };
        limiter.try_acquire()
    };
    if !allowed {
        return json_response(
            StatusCode::TOO_MANY_REQUESTS,
            &json!({"error": "rate_limited"}),
        );
    }

    let challenge = {
        let mut store = match state.login_challenges.lock() {
            Ok(g) => g,
            Err(poison) => poison.into_inner(),
        };
        store.mint()
    };
    let Some(challenge) = challenge else {
        return json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &json!({"error": "challenge_store_full", "retriable": true}),
        );
    };

    json_response(
        StatusCode::OK,
        &json!({
            "challenge": base64_url(&challenge),
            "rp_id": &*state.rp_id,
        }),
    )
}

/// `POST /login/assertion` — verifies a login assertion and establishes a
/// session.
///
/// Tries the presented credential id against BOTH the profile's
/// `allowed_credentials` allowlist and the operator-credential store's
/// enrolled public key; a credential that is enrolled but not allowlisted
/// (or vice versa) is refused identically to an unknown credential — see
/// the module-level error-indistinguishability note in
/// `crate::verify`.
async fn login_assertion_post(
    State(state): State<RemoteServeState>,
    body: axum::body::Bytes,
) -> Response {
    let Ok(request) = serde_json::from_slice::<LoginAssertionRequest>(&body) else {
        return assertion_invalid();
    };

    let credential_id = request.assertion.id.clone();
    if !state
        .allowed_credentials
        .iter()
        .any(|c| c == &credential_id)
    {
        return assertion_invalid();
    }

    let Ok(Some(record)) = state
        .operator_credentials
        .find_by_credential_id(&credential_id)
    else {
        return assertion_invalid();
    };

    let Ok(pubkey_bytes) = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        &record.public_key_sec1_b64,
    ) else {
        return assertion_invalid();
    };
    let Ok(pubkey): Result<[u8; 65], _> = pubkey_bytes.try_into() else {
        return assertion_invalid();
    };

    // The challenge is embedded in clientDataJSON; recover the raw bytes by
    // decoding it back out rather than trusting a separate field, so the
    // consumed value is exactly what is verified below. Decoded once and
    // reused for both the consume check and verification.
    let Some(challenge) = challenge_from_client_data(&request.assertion.response.client_data_json)
    else {
        return assertion_invalid();
    };

    let consumed = {
        let mut store = match state.login_challenges.lock() {
            Ok(g) => g,
            Err(poison) => poison.into_inner(),
        };
        store.consume(&challenge)
    };
    if !consumed {
        return assertion_invalid();
    }

    let verified = match verify_wire_assertion(
        &request.assertion,
        &challenge,
        &state.rp_id,
        &pubkey,
        &state.expected_origin,
    ) {
        Ok(v) => v,
        Err(_) => return assertion_invalid(),
    };

    // Sign-counter regression check: a cloned-authenticator signal refuses
    // the login even though the signature itself verified.
    if state
        .operator_credentials
        .update_sign_count(&credential_id, verified.sign_count)
        .is_err()
    {
        return assertion_invalid();
    }

    let session = SessionState::generate(credential_id);
    let cookie_value = session.session_id.to_hex();
    {
        let mut guard = match state.session.lock() {
            Ok(g) => g,
            Err(poison) => poison.into_inner(),
        };
        *guard = Some(session);
    }

    let mut resp = json_response(StatusCode::OK, &json!({"status": "logged_in"}));
    if let Ok(hv) = HeaderValue::from_str(&session_set_cookie_header(&cookie_value)) {
        resp.headers_mut().insert(header::SET_COOKIE, hv);
    }
    resp
}

/// Extracts the WebAuthn `challenge` field from raw `clientDataJSON` bytes
/// and decodes it from base64url back to the original 32 bytes.
fn challenge_from_client_data(client_data_json_b64url: &str) -> Option<[u8; 32]> {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let raw = URL_SAFE_NO_PAD.decode(client_data_json_b64url).ok()?;
    let value: serde_json::Value = serde_json::from_slice(&raw).ok()?;
    let challenge_str = value.get("challenge")?.as_str()?;
    let decoded = URL_SAFE_NO_PAD.decode(challenge_str).ok()?;
    decoded.try_into().ok()
}

fn base64_url(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

// ─────────────────────────────────────────────────────────────────────────────
// Handlers — enrollment helper page
// ─────────────────────────────────────────────────────────────────────────────

/// `GET /enroll` — the passkey-enrollment helper page. No session required:
/// a WebAuthn credential is bound to its `rp.id` at creation, so enrollment
/// must run from this origin before any session can exist.
///
/// Shares the SAME token-bucket rate limiter `/login/challenge` uses — this
/// is the only other pre-authentication endpoint that does real work before
/// any WebAuthn assertion is checked.
///
/// Never accepts or persists a credential: the rendered page only runs
/// `navigator.credentials.create()` client-side (in `/static/enroll.js`) and
/// displays the resulting credential id and public key for the operator to
/// copy into the loopback-only `approve operator enroll` CLI command — see
/// the crate-level "Enrollment stays loopback-only" note. There is no
/// corresponding write endpoint on this surface.
async fn enroll_page_get(State(state): State<RemoteServeState>) -> Response {
    let allowed = {
        let mut limiter = match state.login_rate_limiter.lock() {
            Ok(g) => g,
            Err(poison) => poison.into_inner(),
        };
        limiter.try_acquire()
    };
    if !allowed {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Html(render_message_page(
                "Too many requests",
                "Too many requests. Wait a moment and try again.",
            )),
        )
            .into_response();
    }
    Html(render_enroll_page(&state.rp_id)).into_response()
}

/// `GET /static/enroll.js` — the enrollment-page browser glue. Ungated, like
/// `/static/login.js`: it must run before any session exists.
async fn enroll_js_get() -> Response {
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        web::ENROLL_JS,
    )
        .into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// Handlers — pending list + detail
// ─────────────────────────────────────────────────────────────────────────────

/// The outcome of taking a store snapshot: the filtered pending views, or the
/// two ways opening the store can fail.
enum SnapshotResult {
    Ok(Vec<PendingApprovalView>),
    Busy,
    Unavailable,
}

/// Opens the store, snapshots it, filters out expired entries, and drops the
/// store (releasing the file lock) before returning.
fn take_snapshot(store_path: &std::path::Path) -> SnapshotResult {
    let store = match open_store(store_path) {
        Ok(s) => s,
        Err(ApprovalError::WriterLocked) => return SnapshotResult::Busy,
        Err(_) => return SnapshotResult::Unavailable,
    };
    let now_ms = match timefmt::now_unix_ms() {
        Ok(n) => n,
        Err(_) => return SnapshotResult::Unavailable,
    };
    let snapshot = store.snapshot(now_ms);
    drop(store);
    SnapshotResult::Ok(snapshot.into_iter().filter(|v| !v.expired).collect())
}

/// `GET /inbox` — HTML shell seeded with the current snapshot.
async fn inbox_get(State(state): State<RemoteServeState>, headers: HeaderMap) -> Response {
    if let Err(resp) = require_session(&state, &headers) {
        return resp;
    }
    match take_snapshot(&state.ctx.store_path) {
        SnapshotResult::Ok(pending) => Html(render_inbox_page(&pending)).into_response(),
        // The shell still renders on a transient store failure; the
        // client-side poll of /pending.json recovers the rows once the lock
        // clears.
        SnapshotResult::Busy | SnapshotResult::Unavailable => {
            Html(render_inbox_page(&[])).into_response()
        }
    }
}

/// `GET /pending.json` — the current pending-approval snapshot as JSON, used
/// by `/static/app.js`'s two-second poll.
async fn pending_json(State(state): State<RemoteServeState>, headers: HeaderMap) -> Response {
    if let Err(resp) = require_session(&state, &headers) {
        return resp;
    }
    match take_snapshot(&state.ctx.store_path) {
        SnapshotResult::Ok(pending) => {
            json_response(StatusCode::OK, &json!({ "pending": pending }))
        }
        SnapshotResult::Busy => store_busy(),
        SnapshotResult::Unavailable => store_unavailable(),
    }
}

/// `GET /approval/{nonce}` — the per-approval detail page.
///
/// Renders the same entry fields (`PendingApprovalView`) that
/// `entry_envelope_sha256` reads to derive the per-action challenge's
/// envelope hash, so what the operator reads here is what the challenge
/// minted by [`action_challenge_post`] is over.
async fn approval_detail_get(
    State(state): State<RemoteServeState>,
    headers: HeaderMap,
    Path(nonce): Path<String>,
) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let store = match open_store(&state.ctx.store_path) {
        Ok(s) => s,
        Err(ApprovalError::WriterLocked) => return store_busy(),
        Err(_) => return store_unavailable(),
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
        drop(store);
        return Html(render_not_found_page(&nonce)).into_response();
    };

    // For an already-attested payment-style entry, surface the stored blob
    // so a lost success response can be recovered.
    let attestation_blob = if view.attested {
        store
            .get(&nonce)
            .and_then(|e| e.attestation_blob_b64.clone())
    } else {
        None
    };
    drop(store);

    let csrf = compute_csrf(&session.csrf_key, &nonce);
    Html(render_detail_page(
        &view,
        &csrf,
        attestation_blob.as_deref(),
    ))
    .into_response()
}

/// `GET /static/app.js` — post-authentication browser glue (inbox listing,
/// detail rendering, per-action ceremony). Session-gated.
async fn app_js_get(State(state): State<RemoteServeState>, headers: HeaderMap) -> Response {
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

// ─────────────────────────────────────────────────────────────────────────────
// Handlers — per-action ceremony
// ─────────────────────────────────────────────────────────────────────────────

/// `POST /approval/{nonce}/challenge` — mints the per-action challenge,
/// server-deriving the envelope hash from the parked entry.
async fn action_challenge_post(
    State(state): State<RemoteServeState>,
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

    let store = match open_store(&state.ctx.store_path) {
        Ok(s) => s,
        Err(ApprovalError::WriterLocked) => return store_busy(),
        Err(_) => return store_unavailable(),
    };
    let Some(entry) = store.get(&nonce).cloned() else {
        return json_response(StatusCode::NOT_FOUND, &json!({"error": "not_found"}));
    };
    drop(store);

    let envelope_sha256 = entry_envelope_sha256(&entry);
    let rand32 = crate::challenge_store::random_32();
    let challenge = derive_action_challenge(&rand32, &envelope_sha256, &entry.approval_nonce);

    {
        let mut store = match state.action_challenges.lock() {
            Ok(g) => g,
            Err(poison) => poison.into_inner(),
        };
        store.mint(challenge, entry.approval_nonce.clone());
    }

    json_response(
        StatusCode::OK,
        &json!({ "challenge": base64_url(&challenge) }),
    )
}

/// `POST /approval/{nonce}/decision` — verifies the per-action assertion and
/// applies the decision.
async fn action_decision_post(
    State(state): State<RemoteServeState>,
    headers: HeaderMap,
    Path(nonce): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let session = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    if let Err(resp) = require_csrf(&session, &headers, &nonce) {
        return resp;
    }

    let Ok(request) = serde_json::from_slice::<ActionAssertionRequest>(&body) else {
        return assertion_invalid();
    };

    // Validated immediately after parsing, before any challenge-store
    // consumption or WebAuthn verification work: a malformed decision string
    // is rejected before a single-use challenge is spent on it.
    if request.decision != "approve" && request.decision != "reject" {
        return json_response(StatusCode::BAD_REQUEST, &json!({"error": "bad_decision"}));
    }

    // The assertion's credential id must be the SAME operator who logged in
    // for this session — a stolen session cookie alone cannot approve or
    // reject, because it carries no assertion, and an assertion from a
    // different (even allowlisted) credential does not match this session.
    if request.assertion.id != session.credential_id_b64url {
        return assertion_invalid();
    }

    let Ok(Some(record)) = state
        .operator_credentials
        .find_by_credential_id(&request.assertion.id)
    else {
        return assertion_invalid();
    };
    let Ok(pubkey_bytes) = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        &record.public_key_sec1_b64,
    ) else {
        return assertion_invalid();
    };
    let Ok(pubkey): Result<[u8; 65], _> = pubkey_bytes.try_into() else {
        return assertion_invalid();
    };

    let Some(challenge) = challenge_from_client_data(&request.assertion.response.client_data_json)
    else {
        return assertion_invalid();
    };

    // Consume-then-verify: single-use and bound to THIS nonce. A challenge
    // minted for a different entry never consumes here even if the raw
    // bytes were replayed against this nonce parameter.
    let consumed = {
        let mut store = match state.action_challenges.lock() {
            Ok(g) => g,
            Err(poison) => poison.into_inner(),
        };
        store.consume(&challenge, &nonce)
    };
    if !consumed {
        return assertion_invalid();
    }

    let verify_result = verify_wire_assertion(
        &request.assertion,
        &challenge,
        &state.rp_id,
        &pubkey,
        &state.expected_origin,
    );
    let Ok(verified) = &verify_result else {
        return assertion_invalid();
    };

    if state
        .operator_credentials
        .update_sign_count(&request.assertion.id, verified.sign_count)
        .is_err()
    {
        return assertion_invalid();
    }

    // The witness is bound to `nonce` — the entry actually being decided —
    // and consumes the ACTUAL `Result` `verify_wire_assertion` produced
    // (mapped to `()` on success), not a value asserted to be `Ok`. This is
    // what makes `VerifiedPasskeyAssertion::new_verified` a genuine proof of
    // verification rather than a claim: a caller cannot skip the check
    // above and still obtain a witness.
    let Some(witness) =
        VerifiedPasskeyAssertion::new_verified(nonce.clone(), verify_result.map(|_| ()))
    else {
        return assertion_invalid();
    };
    let identity =
        ApproverIdentity::from_verified_passkey_assertion(request.assertion.id.clone(), witness);

    let requester = RequestIdentity::Remote {
        identity,
        allowed_credentials: state.allowed_credentials.as_ref().clone(),
    };

    // `request.decision` was already validated to be exactly "approve" or
    // "reject" immediately after body parsing, above.
    let decision = if request.decision == "approve" {
        Decision::Approve { nonce }
    } else {
        Decision::Reject { nonce }
    };

    let outcome = apply_decision(&state.ctx, decision, &requester);
    outcome_to_response(outcome)
}

fn outcome_to_response(outcome: stellar_agent_approval_ui::Outcome) -> Response {
    use stellar_agent_approval_ui::Outcome;
    let (status, body) = match outcome {
        Outcome::Attested {
            attestation: Some(blob),
            expires_at_unix_ms,
        } => (
            StatusCode::OK,
            json!({"status": "attested", "attestation": blob, "expires_at_unix_ms": expires_at_unix_ms}),
        ),
        Outcome::Attested {
            attestation: None, ..
        } => (StatusCode::OK, json!({"status": "grant_active"})),
        Outcome::Rejected => (StatusCode::OK, json!({"status": "rejected"})),
        Outcome::AlreadyResolved { attestation } => (
            StatusCode::OK,
            json!({"status": "already_resolved", "attestation": attestation}),
        ),
        Outcome::Expired => (StatusCode::OK, json!({"status": "expired"})),
        Outcome::UserMismatch => (StatusCode::OK, json!({"status": "user_mismatch"})),
        Outcome::NotFound => (StatusCode::OK, json!({"status": "not_found"})),
        Outcome::WrongKind => (StatusCode::OK, json!({"status": "wrong_kind"})),
        Outcome::Busy => (
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"status": "busy", "retriable": true}),
        ),
        Outcome::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"status": "unavailable", "retriable": false}),
        ),
        _ => (
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"status": "unavailable", "retriable": false}),
        ),
    };
    json_response(status, &body)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests — the full ceremony, exercised through the real HTTP handlers
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(all(test, feature = "test-helpers"))]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use std::sync::{Arc, Mutex as StdMutex};

    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::Request;
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use keyring_core::Entry as KeyringEntry;
    use serial_test::serial;
    use tempfile::TempDir;
    use tower::ServiceExt as _;

    use stellar_agent_approval_ui::DecisionContext;
    use stellar_agent_core::approval::operator_credentials::{
        OperatorApprovalCredential, OperatorApprovalCredentialStore,
    };
    use stellar_agent_core::approval::{DEFAULT_TTL_MS, PendingApprovalStore};
    use stellar_agent_core::audit_log::writer::AuditWriter;
    use stellar_agent_core::profile::schema::KeyringEntryRef;

    use crate::RemoteServeState;
    use crate::challenge_store::{ActionChallengeStore, LoginChallengeStore};
    use crate::rate_limit::TokenBucket;
    use crate::test_helpers::SoftwareAuthenticator;

    const RP_ID: &str = "wallet.test.internal";
    const ORIGIN: &str = "https://wallet.test.internal:8443";

    struct Fixture {
        _dir: TempDir,
        state: RemoteServeState,
        authenticator: SoftwareAuthenticator,
    }

    fn seed_attestation_key(service: &str) -> [u8; 32] {
        let key = [0xABu8; 32];
        let entry = KeyringEntry::new(service, "default").unwrap();
        entry.set_password(&URL_SAFE_NO_PAD.encode(key)).unwrap();
        key
    }

    /// Builds a fixture with one enrolled + allowlisted operator credential.
    fn fixture(tag: &str) -> Fixture {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let store_path = dir.path().join("approvals.toml");
        let audit_path = dir.path().join("audit.log");
        let grant_path = dir.path().join("grants.toml");
        let operator_credentials_path = dir.path().join("operator_credentials.toml");
        let svc = format!("stellar-agent-attestation-remote-{tag}");
        seed_attestation_key(&svc);

        let credential_id = URL_SAFE_NO_PAD.encode([0x42u8; 16]);
        let authenticator = SoftwareAuthenticator::new([0x11u8; 32], credential_id.clone());

        let op_store = OperatorApprovalCredentialStore::new(operator_credentials_path.clone());
        op_store
            .enroll(OperatorApprovalCredential {
                credential_id_b64url: credential_id.clone(),
                public_key_sec1_b64: authenticator.pubkey_uncompressed_b64(),
                rp_id: RP_ID.to_owned(),
                label: "test-device".to_owned(),
                registered_at_unix_ms: 1_750_000_000_000,
                sign_count: None,
            })
            .unwrap();

        let audit_writer = Arc::new(std::sync::Mutex::new(
            AuditWriter::open(audit_path, None).expect("open audit writer"),
        ));
        let ctx = DecisionContext::new(
            "remote-test".to_owned(),
            store_path,
            KeyringEntryRef::new(svc, "default"),
            audit_writer,
            Some(grant_path),
        );

        let state = RemoteServeState {
            rp_id: RP_ID.into(),
            expected_origin: ORIGIN.into(),
            allowed_credentials: Arc::new(vec![credential_id.clone()]),
            ctx: Arc::new(ctx),
            operator_credentials: Arc::new(OperatorApprovalCredentialStore::new(
                operator_credentials_path,
            )),
            login_challenges: Arc::new(StdMutex::new(LoginChallengeStore::new())),
            action_challenges: Arc::new(StdMutex::new(ActionChallengeStore::new())),
            login_rate_limiter: Arc::new(StdMutex::new(TokenBucket::default())),
            session: Arc::new(StdMutex::new(None)),
        };

        Fixture {
            _dir: dir,
            state,
            authenticator,
        }
    }

    fn insert_payment_entry(store_path: &std::path::Path) -> String {
        let mut store = PendingApprovalStore::open(store_path.to_path_buf()).unwrap();
        let entry = stellar_agent_core::approval::PendingApproval::new_payment_pending(
            "b64xdr".to_owned(),
            b"fake-xdr-bytes",
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            2_500_000,
            "XLM".to_owned(),
            None,
            100,
            1_234_567,
            // Must be a well-formed process_uid (numeric ASCII / SID / stub)
            // for the store's on-reload validator, but its VALUE is
            // irrelevant to a `PasskeyCredential` identity's authorization —
            // `is_authorized_for_entry` never consults `entry.process_uid`
            // for that variant.
            "424242".to_owned(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
        let nonce = entry.approval_nonce.clone();
        store
            .insert(entry, stellar_agent_core::timefmt::now_unix_ms().unwrap())
            .unwrap();
        nonce
    }

    async fn body_json(resp: axum::response::Response) -> serde_json::Value {
        let bytes = to_bytes(resp.into_body(), 1024 * 16).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// Full happy-path login: mint challenge, sign, POST assertion, extract
    /// the session cookie.
    async fn login(
        router: &Router<RemoteServeState>,
        state: &RemoteServeState,
        auth: &SoftwareAuthenticator,
    ) -> String {
        let resp = router
            .clone()
            .with_state(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/login/challenge")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "challenge mint must succeed");
        let body = body_json(resp).await;
        let challenge_b64 = body["challenge"].as_str().unwrap().to_owned();
        let challenge: [u8; 32] = URL_SAFE_NO_PAD
            .decode(&challenge_b64)
            .unwrap()
            .try_into()
            .unwrap();

        let assertion = auth.sign_valid(&challenge, RP_ID, ORIGIN, 1);
        let resp = router
            .clone()
            .with_state(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/login/assertion")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(decision_body_login(&assertion)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "login assertion must succeed"
        );
        let cookie = resp
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        // Extract just "name=value" from the full Set-Cookie header.
        cookie.split(';').next().unwrap().to_owned()
    }

    /// Extracts a named string field out of a `<script type="application/json"
    /// id="{island_id}">…</script>` data island embedded in rendered page
    /// HTML — the same island `/static/app.js` reads via `readIsland` in a
    /// real browser.
    fn extract_data_island_field(html: &str, island_id: &str, field: &str) -> String {
        let marker = format!(r#"id="{island_id}""#);
        let tag_start = html.find(&marker).expect("data island tag present");
        let content_start = html[tag_start..].find('>').unwrap() + tag_start + 1;
        let content_end = html[content_start..].find("</script>").unwrap() + content_start;
        let json_text = &html[content_start..content_end];
        let value: serde_json::Value = serde_json::from_str(json_text).unwrap();
        value[field].as_str().unwrap().to_owned()
    }

    async fn html_body(resp: axum::response::Response) -> String {
        let bytes = to_bytes(resp.into_body(), 1024 * 64).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    /// Fetches the detail page and extracts its CSRF value from the
    /// `#approval-data` island — the real path a browser follows before
    /// minting an action challenge.
    async fn get_csrf(
        router: &Router<RemoteServeState>,
        state: &RemoteServeState,
        cookie: &str,
        nonce: &str,
    ) -> String {
        let resp = router
            .clone()
            .with_state(state.clone())
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/approval/{nonce}"))
                    .header(header::COOKIE, cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let html = html_body(resp).await;
        extract_data_island_field(&html, "approval-data", "csrf")
    }

    /// Re-opens the approval store and asserts `nonce`'s entry was left
    /// untouched by a refused decision: no attestation minted, no rejection
    /// tombstone written. Mirrors `stellar-agent-approval-ui`'s
    /// `decision.rs` side-effect assertions for the equivalent
    /// `RequestIdentity::Local` refusal paths.
    fn assert_entry_untouched(store_path: &std::path::Path, nonce: &str) {
        let store = PendingApprovalStore::open(store_path.to_path_buf()).unwrap();
        let entry = store.get(nonce).unwrap();
        assert!(
            entry.attestation_blob_b64.is_none(),
            "a refused decision must not mint an attestation"
        );
        assert!(
            !matches!(entry.kind, ApprovalKind::Rejected { .. }),
            "a refused decision must not write a rejection tombstone"
        );
    }

    async fn mint_action_challenge(
        router: &Router<RemoteServeState>,
        state: &RemoteServeState,
        cookie: &str,
        csrf: &str,
        nonce: &str,
    ) -> [u8; 32] {
        let resp = router
            .clone()
            .with_state(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/approval/{nonce}/challenge"))
                    .header(header::COOKIE, cookie)
                    .header(CSRF_HEADER_NAME, csrf)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "action challenge mint must succeed"
        );
        let body = body_json(resp).await;
        URL_SAFE_NO_PAD
            .decode(body["challenge"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    }

    fn decision_body(decision: &str, assertion: &crate::wire::AssertionWire) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "decision": decision,
            "assertion": {
                "id": assertion.id,
                "response": {
                    "authenticator_data": assertion.response.authenticator_data,
                    "client_data_json": assertion.response.client_data_json,
                    "signature": assertion.response.signature,
                },
            },
        }))
        .unwrap()
    }

    #[test]
    #[serial]
    fn happy_path_approve_mints_attestation() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let fx = fixture("happy");
            let nonce = insert_payment_entry(&fx.state.ctx.store_path);
            let router = build_router();

            let cookie = login(&router, &fx.state, &fx.authenticator).await;
            let csrf = get_csrf(&router, &fx.state, &cookie, &nonce).await;
            let challenge = mint_action_challenge(&router, &fx.state, &cookie, &csrf, &nonce).await;
            let assertion = fx.authenticator.sign_valid(&challenge, RP_ID, ORIGIN, 2);

            let resp = router
                .clone()
                .with_state(fx.state.clone())
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!("/approval/{nonce}/decision"))
                        .header(header::COOKIE, &cookie)
                        .header(CSRF_HEADER_NAME, &csrf)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(decision_body("approve", &assertion)))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = body_json(resp).await;
            assert_eq!(body["status"], "attested");
            let attestation_b64 = body["attestation"].as_str().expect("attestation string");

            // Byte-identical-to-loopback check: independently recompute the
            // HMAC attestation from the entry's own stored fields and the
            // fixed test attestation key, and assert it matches exactly what
            // the remote ceremony surfaced. The preimage is unchanged by
            // remote approval — it binds the nonce, envelope SHA-256, and
            // the entry's stored `process_uid`, never the operator's
            // passkey identity.
            let store = PendingApprovalStore::open(fx.state.ctx.store_path.clone()).unwrap();
            let entry = store.get(&nonce).unwrap().clone();
            drop(store);
            let envelope_sha256_hex = match &entry.kind {
                stellar_agent_core::approval::ApprovalKind::PaymentSimulated {
                    envelope_sha256_hex,
                    ..
                } => envelope_sha256_hex.clone(),
                _ => panic!("expected PaymentSimulated"),
            };
            let envelope_sha256 =
                stellar_agent_core::approval::decode_sha256_hex(&envelope_sha256_hex).unwrap();
            let expected = stellar_agent_core::approval::compute_attestation(
                &[0xABu8; 32],
                &nonce,
                &envelope_sha256,
                &entry.process_uid,
            );
            let actual: [u8; 32] = URL_SAFE_NO_PAD
                .decode(attestation_b64)
                .unwrap()
                .try_into()
                .unwrap();
            assert_eq!(
                actual, expected,
                "remote-approval attestation must be byte-identical to the loopback HMAC preimage"
            );
        });
    }

    #[test]
    #[serial]
    fn wysiwys_challenge_for_entry_a_does_not_authorize_entry_b() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let fx = fixture("wysiwys");
            let nonce_a = insert_payment_entry(&fx.state.ctx.store_path);
            let nonce_b = insert_payment_entry(&fx.state.ctx.store_path);
            let router = build_router();

            let cookie = login(&router, &fx.state, &fx.authenticator).await;
            let csrf_a = get_csrf(&router, &fx.state, &cookie, &nonce_a).await;
            let csrf_b = get_csrf(&router, &fx.state, &cookie, &nonce_b).await;

            let challenge_a =
                mint_action_challenge(&router, &fx.state, &cookie, &csrf_a, &nonce_a).await;
            let assertion_for_a = fx.authenticator.sign_valid(&challenge_a, RP_ID, ORIGIN, 2);

            // Attempt to use entry A's assertion (over entry A's challenge) to
            // decide entry B.
            let resp = router
                .clone()
                .with_state(fx.state.clone())
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!("/approval/{nonce_b}/decision"))
                        .header(header::COOKIE, &cookie)
                        .header(CSRF_HEADER_NAME, &csrf_b)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(decision_body("approve", &assertion_for_a)))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::BAD_REQUEST,
                "a challenge/assertion minted for entry A must never authorize entry B"
            );
            assert_entry_untouched(&fx.state.ctx.store_path, &nonce_b);
        });
    }

    #[test]
    #[serial]
    fn unminted_challenge_is_refused() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let fx = fixture("unminted");
            let nonce = insert_payment_entry(&fx.state.ctx.store_path);
            let router = build_router();

            let cookie = login(&router, &fx.state, &fx.authenticator).await;
            let csrf = get_csrf(&router, &fx.state, &cookie, &nonce).await;
            // Never call the challenge-mint endpoint: sign an arbitrary,
            // never-issued challenge instead.
            let bogus_challenge = [0x77u8; 32];
            let assertion = fx
                .authenticator
                .sign_valid(&bogus_challenge, RP_ID, ORIGIN, 2);

            let resp = router
                .clone()
                .with_state(fx.state.clone())
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!("/approval/{nonce}/decision"))
                        .header(header::COOKIE, &cookie)
                        .header(CSRF_HEADER_NAME, &csrf)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(decision_body("approve", &assertion)))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
            assert_entry_untouched(&fx.state.ctx.store_path, &nonce);
        });
    }

    #[test]
    #[serial]
    fn replayed_challenge_is_refused_second_time() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let fx = fixture("replay");
            let nonce = insert_payment_entry(&fx.state.ctx.store_path);
            let router = build_router();

            let cookie = login(&router, &fx.state, &fx.authenticator).await;
            let csrf = get_csrf(&router, &fx.state, &cookie, &nonce).await;
            let challenge = mint_action_challenge(&router, &fx.state, &cookie, &csrf, &nonce).await;
            let assertion = fx.authenticator.sign_valid(&challenge, RP_ID, ORIGIN, 2);

            let first = router
                .clone()
                .with_state(fx.state.clone())
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!("/approval/{nonce}/decision"))
                        .header(header::COOKIE, &cookie)
                        .header(CSRF_HEADER_NAME, &csrf)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(decision_body("approve", &assertion)))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(first.status(), StatusCode::OK, "first use must succeed");
            let blob_after_first = {
                let store = PendingApprovalStore::open(fx.state.ctx.store_path.clone()).unwrap();
                let blob = store.get(&nonce).unwrap().attestation_blob_b64.clone();
                assert!(blob.is_some(), "the first, legitimate use must attest");
                blob
            };

            let second = router
                .clone()
                .with_state(fx.state.clone())
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!("/approval/{nonce}/decision"))
                        .header(header::COOKIE, &cookie)
                        .header(CSRF_HEADER_NAME, &csrf)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(decision_body("approve", &assertion)))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                second.status(),
                StatusCode::BAD_REQUEST,
                "replaying the same (challenge, assertion) pair must be refused"
            );

            let blob_after_second = {
                let store = PendingApprovalStore::open(fx.state.ctx.store_path.clone()).unwrap();
                store.get(&nonce).unwrap().attestation_blob_b64.clone()
            };
            assert_eq!(
                blob_after_first, blob_after_second,
                "a refused replay must not re-attest or alter the recorded attestation"
            );
        });
    }

    #[test]
    #[serial]
    fn wrong_origin_is_refused() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let fx = fixture("wrong-origin");
            let nonce = insert_payment_entry(&fx.state.ctx.store_path);
            let router = build_router();

            let cookie = login(&router, &fx.state, &fx.authenticator).await;
            let csrf = get_csrf(&router, &fx.state, &cookie, &nonce).await;
            let challenge = mint_action_challenge(&router, &fx.state, &cookie, &csrf, &nonce).await;
            // Correct rp_id, but a clientDataJSON origin that does not match
            // the server's expected origin — as if a foreign page relayed a
            // same-RP-ID assertion.
            let assertion = fx
                .authenticator
                .sign_valid(&challenge, RP_ID, "https://attacker.example:8443", 2);

            let resp = router
                .clone()
                .with_state(fx.state.clone())
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!("/approval/{nonce}/decision"))
                        .header(header::COOKIE, &cookie)
                        .header(CSRF_HEADER_NAME, &csrf)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(decision_body("approve", &assertion)))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::BAD_REQUEST,
                "a clientDataJSON origin that does not match the server's expected origin must be refused"
            );
            assert_entry_untouched(&fx.state.ctx.store_path, &nonce);
        });
    }

    #[test]
    #[serial]
    fn origin_port_mismatch_is_refused() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let fx = fixture("origin-port-mismatch");
            let nonce = insert_payment_entry(&fx.state.ctx.store_path);
            let router = build_router();

            let cookie = login(&router, &fx.state, &fx.authenticator).await;
            let csrf = get_csrf(&router, &fx.state, &cookie, &nonce).await;
            let challenge = mint_action_challenge(&router, &fx.state, &cookie, &csrf, &nonce).await;
            // Same host as ORIGIN, but the wrong port.
            let assertion = fx.authenticator.sign_valid(
                &challenge,
                RP_ID,
                "https://wallet.test.internal:9999",
                2,
            );

            let resp = router
                .clone()
                .with_state(fx.state.clone())
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!("/approval/{nonce}/decision"))
                        .header(header::COOKIE, &cookie)
                        .header(CSRF_HEADER_NAME, &csrf)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(decision_body("approve", &assertion)))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::BAD_REQUEST,
                "an origin with the correct host but wrong port must be refused"
            );
            assert_entry_untouched(&fx.state.ctx.store_path, &nonce);
        });
    }

    #[test]
    #[serial]
    fn expired_session_is_refused_like_no_session() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let fx = fixture("expired-session");
            let router = build_router();

            let cookie = login(&router, &fx.state, &fx.authenticator).await;

            // Overwrite the freshly-minted session with one anchored far
            // enough in the past to already be expired, keeping the same
            // session id / csrf key so the cookie the client holds is still
            // the "right" one — only its age makes it invalid.
            {
                let mut guard = fx.state.session.lock().unwrap();
                let live = guard.as_ref().unwrap().clone();
                let expired_created_at = std::time::Instant::now()
                    - crate::session::SESSION_ABSOLUTE_TTL
                    - std::time::Duration::from_secs(1);
                let mut expired = SessionState::generate_at(
                    live.credential_id_b64url.clone(),
                    expired_created_at,
                );
                expired.session_id = live.session_id.clone();
                expired.csrf_key = live.csrf_key;
                *guard = Some(expired);
            }

            let resp = router
                .clone()
                .with_state(fx.state.clone())
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri("/inbox")
                        .header(header::COOKIE, &cookie)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::NOT_FOUND,
                "an expired session must be refused exactly like no session at all"
            );

            // The stale session must have been dropped, not merely refused
            // once: a fresh login is required, not a retry of the same
            // request.
            let cleared = fx.state.session.lock().unwrap().is_none();
            assert!(cleared, "an expired session must be cleared from state");
        });
    }

    #[test]
    #[serial]
    fn wrong_rp_id_is_refused() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let fx = fixture("wrong-rp-id");
            let nonce = insert_payment_entry(&fx.state.ctx.store_path);
            let router = build_router();

            let cookie = login(&router, &fx.state, &fx.authenticator).await;
            let csrf = get_csrf(&router, &fx.state, &cookie, &nonce).await;
            let challenge = mint_action_challenge(&router, &fx.state, &cookie, &csrf, &nonce).await;
            // Sign with a DIFFERENT rp_id than the server expects.
            let assertion = fx
                .authenticator
                .sign_valid(&challenge, "attacker.example", ORIGIN, 2);

            let resp = router
                .clone()
                .with_state(fx.state.clone())
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!("/approval/{nonce}/decision"))
                        .header(header::COOKIE, &cookie)
                        .header(CSRF_HEADER_NAME, &csrf)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(decision_body("approve", &assertion)))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
            assert_entry_untouched(&fx.state.ctx.store_path, &nonce);
        });
    }

    #[test]
    #[serial]
    fn uv_absent_is_refused() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let fx = fixture("uv-absent");
            let nonce = insert_payment_entry(&fx.state.ctx.store_path);
            let router = build_router();

            let cookie = login(&router, &fx.state, &fx.authenticator).await;
            let csrf = get_csrf(&router, &fx.state, &cookie, &nonce).await;
            let challenge = mint_action_challenge(&router, &fx.state, &cookie, &csrf, &nonce).await;
            // UP set, UV NOT set.
            let assertion = fx.authenticator.sign_assertion(
                &challenge,
                RP_ID,
                ORIGIN,
                crate::test_helpers::FLAG_UP,
                2,
            );

            let resp = router
                .clone()
                .with_state(fx.state.clone())
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!("/approval/{nonce}/decision"))
                        .header(header::COOKIE, &cookie)
                        .header(CSRF_HEADER_NAME, &csrf)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(decision_body("approve", &assertion)))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
            assert_entry_untouched(&fx.state.ctx.store_path, &nonce);
        });
    }

    #[test]
    #[serial]
    fn credential_not_allowlisted_is_refused_at_login() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let fx = fixture("not-allowlisted");
            let router = build_router();

            // A DIFFERENT authenticator/credential, never allowlisted (and
            // never enrolled).
            let stranger =
                SoftwareAuthenticator::new([0x99u8; 32], URL_SAFE_NO_PAD.encode([0x55u8; 16]));

            let resp = router
                .clone()
                .with_state(fx.state.clone())
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/login/challenge")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let body = body_json(resp).await;
            let challenge: [u8; 32] = URL_SAFE_NO_PAD
                .decode(body["challenge"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            let assertion = stranger.sign_valid(&challenge, RP_ID, ORIGIN, 1);

            let resp = router
                .clone()
                .with_state(fx.state.clone())
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/login/assertion")
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(decision_body_login(&assertion)))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::BAD_REQUEST,
                "a credential absent from allowed_credentials must be refused at login"
            );
        });
    }

    fn decision_body_login(assertion: &crate::wire::AssertionWire) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "assertion": {
                "id": assertion.id,
                "response": {
                    "authenticator_data": assertion.response.authenticator_data,
                    "client_data_json": assertion.response.client_data_json,
                    "signature": assertion.response.signature,
                },
            },
        }))
        .unwrap()
    }

    #[test]
    #[serial]
    fn sign_counter_regression_is_refused() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let fx = fixture("counter-regression");
            let nonce = insert_payment_entry(&fx.state.ctx.store_path);
            let router = build_router();

            // First login advances the counter to 5.
            let challenge_resp = router
                .clone()
                .with_state(fx.state.clone())
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/login/challenge")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let body = body_json(challenge_resp).await;
            let challenge: [u8; 32] = URL_SAFE_NO_PAD
                .decode(body["challenge"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            let assertion = fx.authenticator.sign_valid(&challenge, RP_ID, ORIGIN, 5);
            let login_resp = router
                .clone()
                .with_state(fx.state.clone())
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/login/assertion")
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(decision_body_login(&assertion)))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(login_resp.status(), StatusCode::OK);
            let cookie = login_resp
                .headers()
                .get(header::SET_COOKIE)
                .unwrap()
                .to_str()
                .unwrap()
                .split(';')
                .next()
                .unwrap()
                .to_owned();

            let csrf = get_csrf(&router, &fx.state, &cookie, &nonce).await;
            let challenge2 =
                mint_action_challenge(&router, &fx.state, &cookie, &csrf, &nonce).await;
            // Present counter 3 — LOWER than the stored counter (5): a
            // cloned-authenticator signal.
            let assertion2 = fx.authenticator.sign_valid(&challenge2, RP_ID, ORIGIN, 3);

            let resp = router
                .clone()
                .with_state(fx.state.clone())
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!("/approval/{nonce}/decision"))
                        .header(header::COOKIE, &cookie)
                        .header(CSRF_HEADER_NAME, &csrf)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(decision_body("approve", &assertion2)))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::BAD_REQUEST,
                "a non-advancing sign counter must be refused (cloned-authenticator signal)"
            );
            assert_entry_untouched(&fx.state.ctx.store_path, &nonce);
        });
    }

    // ─────────────────────────────────────────────────────────────────────
    // Tests — enrollment helper page
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    #[serial]
    fn enroll_page_is_reachable_pre_auth() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let fx = fixture("enroll-reachable");
            let router = build_router();

            let resp = router
                .clone()
                .with_state(fx.state.clone())
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri("/enroll")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::OK,
                "the enrollment helper page must be reachable with no session"
            );
            let html = html_body(resp).await;
            assert!(html.contains(RP_ID));
            assert!(html.contains(r#"id="enroll-btn""#));
        });
    }

    #[test]
    #[serial]
    fn enroll_page_shares_login_rate_limiter_and_refuses_once_exhausted() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let fx = fixture("enroll-rate-limited");
            let router = build_router();

            // Exhaust the SAME bucket `/login/challenge` draws from, by
            // calling that endpoint directly — proving the two routes
            // genuinely share one limiter rather than each having its own.
            loop {
                let resp = router
                    .clone()
                    .with_state(fx.state.clone())
                    .oneshot(
                        Request::builder()
                            .method("POST")
                            .uri("/login/challenge")
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                if resp.status() == StatusCode::TOO_MANY_REQUESTS {
                    break;
                }
                assert_eq!(resp.status(), StatusCode::OK);
            }

            let resp = router
                .clone()
                .with_state(fx.state.clone())
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri("/enroll")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::TOO_MANY_REQUESTS,
                "/enroll must be refused once the shared bucket is exhausted"
            );
        });
    }

    #[test]
    #[serial]
    fn enroll_page_interaction_leaves_operator_credential_store_untouched() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let fx = fixture("enroll-no-side-effect");
            let router = build_router();

            let before = fx.state.operator_credentials.list().unwrap();

            for _ in 0..3 {
                let resp = router
                    .clone()
                    .with_state(fx.state.clone())
                    .oneshot(
                        Request::builder()
                            .method("GET")
                            .uri("/enroll")
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(resp.status(), StatusCode::OK);

                let resp = router
                    .clone()
                    .with_state(fx.state.clone())
                    .oneshot(
                        Request::builder()
                            .method("GET")
                            .uri("/static/enroll.js")
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(resp.status(), StatusCode::OK);
            }

            let after = fx.state.operator_credentials.list().unwrap();
            assert_eq!(
                before, after,
                "no /enroll interaction may change the enrolled-credential registry; \
                 this surface has no write endpoint"
            );
        });
    }

    #[test]
    #[serial]
    fn enroll_page_has_no_inline_event_handler_attributes() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let fx = fixture("enroll-no-inline-handlers");
            let router = build_router();

            let resp = router
                .clone()
                .with_state(fx.state.clone())
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri("/enroll")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let html = html_body(resp).await;
            assert!(
                !html_has_inline_event_handler_attribute(&html),
                "the enrollment page must wire its button via addEventListener in \
                 /static/enroll.js, never an inline on*= attribute"
            );
        });
    }

    /// Returns `true` if `html` contains a known inline-event-handler
    /// attribute (`onclick=`, `onload=`, etc.) — this codebase never uses
    /// one; every ceremony is wired via `addEventListener` in same-origin JS,
    /// which is what keeps the CSP at `script-src 'self'` with no
    /// `'unsafe-inline'` meaningful (an inline handler attribute executes
    /// regardless of `script-src`, so this is a distinct check from
    /// [`html_has_disallowed_inline_script`]).
    fn html_has_inline_event_handler_attribute(html: &str) -> bool {
        const HANDLER_ATTRS: &[&str] = &[
            "onclick=",
            "onload=",
            "onerror=",
            "onsubmit=",
            "onchange=",
            "oninput=",
            "onfocus=",
            "onblur=",
            "onmouseover=",
            "onkeydown=",
            "onkeyup=",
        ];
        let lower = html.to_lowercase();
        HANDLER_ATTRS.iter().any(|attr| lower.contains(attr))
    }

    #[test]
    #[serial]
    fn csp_contract_holds_across_html_routes() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let fx = fixture("csp-contract");
            let nonce = insert_payment_entry(&fx.state.ctx.store_path);

            // The fully-layered router (`crate::build_router`, not this
            // module's unlayered `build_router`) is the only one that applies
            // `SecurityHeadersLayer` — the CSP contract only holds through
            // that stack, exactly as a real browser experiences it.
            let layered_router = crate::build_router(fx.state.clone(), RP_ID, 8443);

            // Pre-auth: GET / (the login page).
            let resp = layered_router
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri("/")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_csp_contract(resp).await;

            // Pre-auth: GET /enroll (the enrollment helper page).
            let resp = layered_router
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri("/enroll")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_csp_contract(resp).await;

            // Establish a real session via the full login ceremony (the
            // login endpoints allow a missing `Origin` header, so no header
            // juggling is required here) using the unlayered router the
            // `login` helper expects, then reuse the resulting cookie
            // against the layered router.
            let unlayered = build_router();
            let cookie = login(&unlayered, &fx.state, &fx.authenticator).await;

            let resp = layered_router
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri("/inbox")
                        .header(header::COOKIE, &cookie)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_csp_contract(resp).await;

            let resp = layered_router
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri(format!("/approval/{nonce}"))
                        .header(header::COOKIE, &cookie)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_csp_contract(resp).await;
        });
    }

    // ── entry_envelope_sha256: non-zero binding for every digest-carrying kind ─
    //
    // Package D, GH issue #8, Leg 3: `RuleProposalSimulated` must bind the
    // per-action challenge to its `proposal_sha256`, exactly as
    // `PaymentSimulated` / `ClaimSimulated` bind to their envelope digest.
    // Regression guard: if the `RuleProposalSimulated` arm were ever removed
    // or fell through to the wildcard, this test catches it immediately
    // (the fallback zero placeholder is the WRONG behaviour for a kind that
    // has a real content digest to bind to).

    #[test]
    fn entry_envelope_sha256_is_non_zero_for_every_digest_carrying_kind() {
        let payment = stellar_agent_core::approval::PendingApproval::new_payment_pending(
            "b64xdr".to_owned(),
            b"fake-xdr-bytes",
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            2_500_000,
            "XLM".to_owned(),
            None,
            100,
            1_234_567,
            "424242".to_owned(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
        assert_ne!(
            entry_envelope_sha256(&payment),
            [0u8; 32],
            "PaymentSimulated"
        );

        let claim = stellar_agent_core::approval::PendingApproval::new_claim_pending(
            "b64xdr".to_owned(),
            b"fake-xdr-bytes",
            "a".repeat(72),
            "B".to_owned() + &"A".repeat(57),
            "XLM".to_owned(),
            500,
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            100,
            1,
            "424242".to_owned(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
        assert_ne!(entry_envelope_sha256(&claim), [0u8; 32], "ClaimSimulated");

        let definition = stellar_agent_core::approval::ContextRuleProposalSnapshot::new(
            stellar_agent_core::approval::RuleProposalContextType::Default,
            "spend-daily".to_owned(),
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
        let rule_proposal =
            stellar_agent_core::approval::PendingApproval::new_rule_proposal_pending(
                "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned(),
                "Test SDF Network ; September 2015".to_owned(),
                "stellar:testnet".to_owned(),
                definition,
                [0x11u8; 32],
                "Default rule \"spend-daily\"".to_owned(),
                "424242".to_owned(),
                DEFAULT_TTL_MS,
            )
            .unwrap();
        assert_eq!(
            entry_envelope_sha256(&rule_proposal),
            [0x11u8; 32],
            "RuleProposalSimulated must bind to proposal_sha256, not the zero placeholder"
        );

        let mpp = stellar_agent_core::approval::PendingApproval::new_mpp_charge_pending(
            [0x22; 32],
            [0x33; 32],
            "default".to_owned(),
            "stellar:testnet".to_owned(),
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            "http".to_owned(),
            "merchant.example".to_owned(),
            "/checkout".to_owned(),
            "1000".to_owned(),
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned(),
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            u64::MAX / 1_000,
            1_000,
            "424242".to_owned(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
        assert_eq!(
            entry_envelope_sha256(&mpp),
            [0x33; 32],
            "MppChargeSimulated must bind to its prepared artifact"
        );

        // Kinds with no content digest of their own correctly fall back to
        // the zero placeholder — binding for these rests on approval_nonce
        // alone, by design (see the fn's doc comment).
        let toolset_gate =
            stellar_agent_core::approval::PendingApproval::new_toolset_first_invoke_gate_pending(
                "my-toolset".to_owned(),
                "sign-payment".to_owned(),
                "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                "XLM".to_owned(),
                0,
                1_000_000,
                "424242".to_owned(),
                DEFAULT_TTL_MS,
            )
            .unwrap();
        assert_eq!(
            entry_envelope_sha256(&toolset_gate),
            [0u8; 32],
            "ToolsetFirstInvokeGate has no content digest; must use the placeholder"
        );

        let clawback =
            stellar_agent_core::approval::PendingApproval::new_trustline_clawback_opt_in_pending(
                "Test SDF Network ; September 2015".to_owned(),
                "USDC".to_owned(),
                "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5".to_owned(),
                "424242".to_owned(),
                DEFAULT_TTL_MS,
            )
            .unwrap();
        assert_eq!(
            entry_envelope_sha256(&clawback),
            [0u8; 32],
            "TrustlineClawbackOptIn has no content digest; must use the placeholder"
        );
    }

    /// Asserts `resp` carries the hardened CSP (`script-src 'self'`, no
    /// `unsafe-inline`/`unsafe-eval` on it) and that its HTML body contains
    /// no `<script>` tag lacking a `src` attribute, UNLESS that tag is a
    /// `type="application/json"` data island — inert to the browser (never
    /// executed as script), the same sanctioned exception `crate::templates`
    /// relies on throughout.
    async fn assert_csp_contract(resp: Response) {
        assert_eq!(resp.status(), StatusCode::OK);
        let csp = resp
            .headers()
            .get(header::CONTENT_SECURITY_POLICY)
            .expect("CSP header must be present on every response")
            .to_str()
            .unwrap()
            .to_owned();
        assert!(csp.contains("script-src 'self'"));
        assert!(!csp.contains("script-src 'self' 'unsafe-inline'"));
        assert!(!csp.contains("unsafe-eval"));

        let html = html_body(resp).await;
        assert!(
            !html_has_disallowed_inline_script(&html),
            "HTML response must contain no executable inline <script>"
        );
    }

    /// Returns `true` if `html` contains a `<script>` tag that is neither
    /// externally sourced (`src=`) nor an inert JSON data island
    /// (`type="application/json"`) — i.e. a real, executable inline script,
    /// which the CSP's `script-src 'self'` (no `'unsafe-inline'`) would block
    /// in a real browser and which this codebase must never reintroduce.
    fn html_has_disallowed_inline_script(html: &str) -> bool {
        let mut rest = html;
        while let Some(idx) = rest.find("<script") {
            let after = &rest[idx + "<script".len()..];
            let Some(close) = after.find('>') else {
                return true; // malformed tag: fail closed
            };
            let tag_attrs = &after[..close];
            // Attribute-token matching: `src=` must be its own attribute
            // token, so a hypothetical `data-src=` attribute never counts as
            // externally sourced, and both quote styles of the inert JSON
            // data-island type are recognised.
            let is_data_island = tag_attrs
                .split_whitespace()
                .any(|t| t == r#"type="application/json""# || t == "type='application/json'");
            let has_src = tag_attrs.split_whitespace().any(|t| t.starts_with("src="));
            if !is_data_island && !has_src {
                return true;
            }
            rest = &after[close + 1..];
        }
        false
    }
}
