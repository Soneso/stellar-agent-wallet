//! HTTP route handlers for the WebAuthn browser-handoff bridge.
//!
//! This module is a directory with three sub-modules:
//!
//! - [`healthz`] — `GET /healthz` readiness probe.
//! - [`register`] — `GET /register/{nonce}` and `POST /register/{nonce}/credential`.
//! - [`approve`] — `GET /approve/{nonce}`, `POST /approve/{nonce}/assertion`,
//!   and `POST /approve/{nonce}/cancel`.
//!
//! # Tracing posture
//!
//! Handlers MUST NOT log request bodies, query strings, CSRF tokens, or
//! assertion bytes. The `TraceLayer`
//! is configured in [`crate::start_bridge_register_only`] to log only the request path,
//! not the full URI.

pub(crate) mod approve;
pub(crate) mod healthz;
pub(crate) mod register;

use axum::{
    Json,
    extract::{FromRequest, Request},
    response::{IntoResponse, Response},
};
use serde::de::DeserializeOwned;
use serde_json::json;

pub(crate) use approve::{approve_assertion_post, approve_cancel_post, approve_get};
pub(crate) use healthz::healthz;
pub(crate) use register::{register_get, register_post};

/// A JSON request body whose refusal holds none of the body.
///
/// The rejection of [`axum::Json`] renders the `serde_json` message, which
/// quotes the posted value. This extractor keeps its status and answers
/// `{"error":"invalid_body"}`.
pub(crate) struct JsonBody<T>(pub(crate) T);

impl<S, T> FromRequest<S> for JsonBody<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = Response;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(request, state).await {
            Ok(Json(value)) => Ok(Self(value)),
            Err(rejection) => Err((
                rejection.status(),
                [("content-type", "application/json")],
                json!({"error": "invalid_body"}).to_string(),
            )
                .into_response()),
        }
    }
}
