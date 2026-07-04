//! Shared defence-in-depth middleware for the wallet's loopback-only HTTP
//! listeners.
//!
//! [`stellar-agent-webauthn-bridge`](https://docs.rs/stellar-agent-webauthn-bridge)
//! and [`stellar-agent-approval-ui`](https://docs.rs/stellar-agent-approval-ui)
//! each run an independent `127.0.0.1`-bound axum listener with the same
//! browser-facing threat model: DNS rebinding, cross-origin state-changing
//! requests, and response caching/sniffing/framing by an untrusted page. This
//! crate is the single implementation of the three tower layers that guard
//! against that threat model, so the two listeners cannot silently drift
//! apart.
//!
//! - [`host_header`] — `Host:` header allowlist (DNS-rebinding defence).
//! - [`origin_header`] — `Origin:` header allowlist on state-changing methods.
//! - [`security_headers`] — hardened response headers + CSP on every response.
//!
//! Each consumer constructs the layers with its own bound [`std::net::SocketAddr`]
//! and applies them via `Router::layer`; this crate exposes no router or
//! server surface of its own.

#![forbid(unsafe_code)]

pub mod host_header;
pub mod origin_header;
pub mod security_headers;
