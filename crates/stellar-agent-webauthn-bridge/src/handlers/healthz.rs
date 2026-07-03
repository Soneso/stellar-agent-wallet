//! `GET /healthz` readiness-probe handler.
//!
//! Returns `{"status":"ok"}` with `200 OK`. No authentication or CSRF check —
//! this is a public diagnostic endpoint.
//!
//! # Tracing posture
//!
//! This handler performs no I/O that requires structured logging beyond what
//! the outer `TraceLayer` already emits (path + method + status).

use axum::{Json, http::StatusCode};
use serde_json::{Value, json};

// ─────────────────────────────────────────────────────────────────────────────
// GET /healthz
// ─────────────────────────────────────────────────────────────────────────────

/// Readiness probe — returns `{"status":"ok"}` with `200 OK`.
///
/// This route requires no authentication and carries no CSRF check; it is a
/// public diagnostic endpoint.  The response shape is fixed and deterministic.
///
/// # Errors
///
/// This handler is infallible.
pub(crate) async fn healthz() -> (StatusCode, Json<Value>) {
    (StatusCode::OK, Json(json!({"status": "ok"})))
}
