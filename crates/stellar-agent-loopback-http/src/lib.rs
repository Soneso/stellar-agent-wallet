//! Shared defence-in-depth middleware for the wallet's loopback-only HTTP
//! listeners.
//!
//! [`stellar-agent-webauthn-bridge`](https://docs.rs/stellar-agent-webauthn-bridge)
//! and [`stellar-agent-approval-ui`](https://docs.rs/stellar-agent-approval-ui)
//! each run independent loopback axum listeners with the same browser-facing
//! threat model: DNS rebinding, cross-origin state-changing requests, and
//! response caching/sniffing/framing by an untrusted page. A listener the
//! browser reaches at `http://localhost:<port>` binds both `127.0.0.1` and
//! `::1` on that port through [`loopback_pair`]. This crate is the single
//! implementation of the three tower layers that guard against that threat
//! model, so the listeners cannot silently drift apart.
//!
//! - [`host_header`] — `Host:` header allowlist (DNS-rebinding defence).
//! - [`origin_header`] — `Origin:` header allowlist on state-changing methods.
//! - [`security_headers`] — hardened response headers + CSP on every response.
//!
//! Each consumer constructs the layers with its own bound [`std::net::SocketAddr`]
//! and applies them via `Router::layer`. The layers read only the port, so
//! one router serves both sockets of a pair.
//!
//! [`loopback_pair`] is the server surface: [`LoopbackPair`] holds
//! `127.0.0.1:<port>` and `[::1]:<port>` together before a ceremony creates
//! any token, and [`PairServer`] serves one router on both and closes both
//! together. A ceremony that cannot hold both addresses does not start.
//!
//! [`brand`] is the second shared surface: the stylesheet and inline mark the
//! operator-facing pages render, plus [`brand::PageIdentity`], the optional
//! per-deployment name and mark rendered inside that design. Kept here for the
//! same reason as the middleware — one definition, so the listeners cannot
//! drift apart. It fits inside the CSP [`security_headers`] sets and adds no
//! served asset and no executable content.
//!
//! [`escape`] is the third: the single HTML-escaping definition every page
//! applies to dynamic text.
//!
//! [`request_trace`] is the fourth: the route label each listener's request
//! span records in place of the request path, which can carry a bearer
//! secret.
//!
//! [`stellar-agent-approval-remote`](https://docs.rs/stellar-agent-approval-remote)
//! serves over TLS on a private network rather than loopback; it uses the same
//! response headers and the same brand surface, so it depends on this crate
//! too.

#![forbid(unsafe_code)]

pub mod brand;
pub mod escape;
pub mod host_header;
pub mod loopback_pair;
pub mod origin_header;
pub mod request_trace;
pub mod security_headers;

pub use loopback_pair::{
    LoopbackFamily, LoopbackPair, PAIR_BIND_ATTEMPTS, PairBindError, PairServer,
};
