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

pub(crate) use approve::{approve_assertion_post, approve_cancel_post, approve_get};
pub(crate) use healthz::healthz;
pub(crate) use register::{register_get, register_post};
