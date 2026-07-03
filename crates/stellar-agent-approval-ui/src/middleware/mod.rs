//! Layered defence middleware for the approval-inbox server.
//!
//! Each layer is a small, self-contained tower `Layer`/`Service` pair, mirroring
//! the WebAuthn bridge's middleware faithfully rather than sharing a library:
//! the two servers are independent loopback listeners with independent
//! dependency closures. The duplication is deliberate.
//!
//! - [`host_header`] — Host-header allowlist (DNS-rebinding defence).
//! - [`origin_header`] — Origin-header allowlist on state-changing methods.
//! - [`security_headers`] — hardened response headers + CSP on every response.

pub mod host_header;
pub mod origin_header;
pub mod security_headers;
