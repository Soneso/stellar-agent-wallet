//! HTTP router for the WebAuthn browser-handoff bridge.
//!
//! Registers all bridge routes and wires the approval-store state:
//!
//! | Method | Path | Handler |
//! |--------|------|---------|
//! | `GET`  | `/healthz` | [`handlers::healthz`] |
//! | `GET`  | `/register/{nonce}` | [`handlers::register_get`] |
//! | `POST` | `/register/{nonce}/credential` | [`handlers::register_post`] |
//! | `GET`  | `/approve/{nonce}` | [`handlers::approve_get`] |
//! | `POST` | `/approve/{nonce}/assertion` | [`handlers::approve_assertion_post`] |
//! | `POST` | `/approve/{nonce}/cancel` | [`handlers::approve_cancel_post`] |
//! | `GET`  | `/static/webauthn.js` | vendored `@simplewebauthn/browser` 13.3.0 UMD bundle |
//! | `GET`  | `/static/glue.js` | wallet-authored browser glue |
//!
//! The middleware stack (TraceLayer, `HostHeaderAllowlistLayer`,
//! `OriginHeaderAllowlistLayer`, `SecurityHeadersLayer`,
//! `RequestBodyLimitLayer`, `DefaultBodyLimit`) is NOT applied here — it is
//! applied at the router level by [`crate::start_bridge_register_only`] so that the
//! middleware wraps the entire router consistently.
//!
//! # Static assets
//!
//! `/static/webauthn.js` returns `200 OK` with the vendored
//! `@simplewebauthn/browser` v13.3.0 UMD bundle bytes (SHA-pinned in the
//! `crate::web` module).  `/static/glue.js` returns the wallet-authored DOM
//! glue that reads the server-rendered data island, invokes
//! `SimpleWebAuthnBrowser.start*`, and POSTs the credential / assertion
//! back to the bridge with the `X-Stellar-Approval-CSRF` header.
//!
//! Both responses set `Content-Type: application/javascript; charset=utf-8`.
//! The `SecurityHeadersLayer` injects `Cache-Control: no-store` on every
//! response — including these static-asset responses — so a stale browser
//! cache cannot outlive a re-vendoring step.

use axum::{
    Router,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};

use crate::{BridgeState, handlers, web};

/// Build and return the bridge's [`axum::Router`] with state.
///
/// The router is built with approval-store state so all POST handlers can
/// mutate the store held in [`BridgeState`] (an
/// `Arc<tokio::sync::Mutex<PendingApprovalStore>>`).
///
/// # Returns
///
/// A [`Router<BridgeState>`] with all routes registered.  The
/// caller (`build_router` in `lib.rs`) calls `.with_state(store)` to produce
/// the final stateful `Router`.
pub(crate) fn build_router() -> Router<BridgeState> {
    Router::new()
        .route("/healthz", get(handlers::healthz))
        // Passkey registration ceremony.
        .route("/register/{nonce}", get(handlers::register_get))
        .route(
            "/register/{nonce}/credential",
            post(handlers::register_post),
        )
        // Passkey approval ceremony + cancel.
        .route("/approve/{nonce}", get(handlers::approve_get))
        .route(
            "/approve/{nonce}/assertion",
            post(handlers::approve_assertion_post),
        )
        .route(
            "/approve/{nonce}/cancel",
            post(handlers::approve_cancel_post),
        )
        // Static assets: vendored bundle + wallet glue.
        .route("/static/webauthn.js", get(static_webauthn_bundle))
        .route("/static/glue.js", get(static_wallet_glue))
}

// ─────────────────────────────────────────────────────────────────────────────
// Static asset handlers
// ─────────────────────────────────────────────────────────────────────────────

/// Serve `GET /static/webauthn.js` with the vendored
/// `@simplewebauthn/browser` v13.3.0 UMD bundle bytes.
///
/// Returns `200 OK` + `Content-Type: application/javascript; charset=utf-8`
/// + the SHA-pinned bytes from `crate::web::SIMPLEWEBAUTHN_BUNDLE`.
///
/// Caching is governed by the `SecurityHeadersLayer` which forces
/// `Cache-Control: no-store` on every response (so a stale-cache bundle
/// can never outlive a re-vendoring).
async fn static_webauthn_bundle() -> impl IntoResponse {
    (
        StatusCode::OK,
        [("content-type", "application/javascript; charset=utf-8")],
        web::SIMPLEWEBAUTHN_BUNDLE,
    )
}

/// Serve `GET /static/glue.js` with the wallet-authored DOM/fetch glue.
///
/// Returns `200 OK` + `Content-Type: application/javascript; charset=utf-8`
/// + the bytes from `crate::web::WALLET_GLUE_JS`.
///
/// The glue is loaded by both `register.html` and `approve.html` after the
/// vendored bundle; it reads the server-rendered data island and invokes
/// `SimpleWebAuthnBrowser.start{Registration,Authentication}` accordingly.
async fn static_wallet_glue() -> impl IntoResponse {
    (
        StatusCode::OK,
        [("content-type", "application/javascript; charset=utf-8")],
        web::WALLET_GLUE_JS,
    )
}
