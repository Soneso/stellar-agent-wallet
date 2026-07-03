//! Host-header allowlist middleware (DNS-rebinding defence).
//!
//! Every inbound HTTP request must carry a
//! `Host` header whose value is exactly `127.0.0.1:<port>`,
//! `localhost:<port>`, or `[::1]:<port>`, where `<port>` is the bridge's
//! actual bound port.
//! Requests with any other `Host` value — including a missing header — are
//! rejected with `421 Misdirected Request` and a JSON error body
//! `{"error":"host_header_rejected"}`.
//!
//! # Why this defence matters
//!
//! A malicious site `attacker.example` can repoint its DNS A-record to
//! `127.0.0.1` while a tab is open (DNS rebinding).  The browser then permits
//! fetches to `http://wallet-rebound.attacker.example:<port>/...`, the kernel
//! routes the packets to the bridge (loopback satisfied), and the browser
//! considers the destination same-origin.  By checking the `Host:` header we
//! reject such requests before any route handler runs.
//!
//! # IPv6 loopback
//!
//! `[::1]:<port>` is accepted as a loopback-equivalent `Host` header. Wallet
//! registration and signing URLs are still emitted with `localhost` so browser
//! WebAuthn RP-ID binding remains stable.
//!
//! Key types: [`HostHeaderAllowlistLayer`], [`HostHeaderAllowlistService`].

use std::{
    future::Future,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

use axum::{
    body::Body,
    http::{Request, Response, StatusCode},
    response::IntoResponse,
};
use serde_json::json;
use tower::{Layer, Service};

// ─────────────────────────────────────────────────────────────────────────────
// Layer
// ─────────────────────────────────────────────────────────────────────────────

/// Tower `Layer` that enforces the `Host`-header allowlist.
///
/// Constructed with the bridge's actual bound [`SocketAddr`]; the service
/// accepts only `Host: 127.0.0.1:<port>`, `Host: localhost:<port>`, and
/// `Host: [::1]:<port>`.
///
/// # Examples
///
/// ```no_run
/// use std::net::SocketAddr;
/// use stellar_agent_webauthn_bridge::middleware::host_header::HostHeaderAllowlistLayer;
///
/// let bound: SocketAddr = "127.0.0.1:8443".parse().unwrap();
/// let _layer = HostHeaderAllowlistLayer::new(bound);
/// ```
#[derive(Clone, Debug)]
pub struct HostHeaderAllowlistLayer {
    bound_addr: SocketAddr,
}

impl HostHeaderAllowlistLayer {
    /// Create a new layer that allows only the three canonical `Host` forms
    /// (`127.0.0.1`, `localhost`, and `[::1]`) for `bound_addr`.
    #[must_use]
    pub fn new(bound_addr: SocketAddr) -> Self {
        Self { bound_addr }
    }
}

impl<S> Layer<S> for HostHeaderAllowlistLayer {
    type Service = HostHeaderAllowlistService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        HostHeaderAllowlistService {
            inner,
            bound_addr: self.bound_addr,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Service
// ─────────────────────────────────────────────────────────────────────────────

/// Tower `Service` that enforces the `Host`-header allowlist.
///
/// Rejects any request whose `Host` header is not `127.0.0.1:<port>`,
/// `localhost:<port>`, or `[::1]:<port>` with `421 Misdirected Request`.
#[derive(Clone, Debug)]
pub struct HostHeaderAllowlistService<S> {
    inner: S,
    bound_addr: SocketAddr,
}

impl<S> Service<Request<Body>> for HostHeaderAllowlistService<S>
where
    S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let port = self.bound_addr.port();
        let allowed = host_is_allowed(req.headers(), port);
        if !allowed {
            let body = json!({"error": "host_header_rejected"}).to_string();
            let resp = Response::builder()
                .status(StatusCode::MISDIRECTED_REQUEST)
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap_or_else(|_| {
                    // Builder failure here is a logic error (fixed status +
                    // header values).  Fall back to an empty 421.
                    (StatusCode::MISDIRECTED_REQUEST, "").into_response()
                });
            return Box::pin(async move { Ok(resp) });
        }
        Box::pin(self.inner.call(req))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Allow-list logic
// ─────────────────────────────────────────────────────────────────────────────

/// Returns `true` iff the `Host` header value matches `127.0.0.1:<port>`,
/// `localhost:<port>`, or `[::1]:<port>`.
///
/// The comparison is ASCII-case-insensitive on the host-name component per
/// RFC 9110 §7.2 ("the host subcomponent is case-insensitive") so that
/// `LocalHost:<port>` and `LOCALHOST:<port>` are accepted just as
/// `localhost:<port>` is. The numeric port suffix is compared verbatim
/// (RFC 9110 requires exact match for the port digits).
///
/// Rejects: missing header, subdomain of `localhost` (e.g.
/// `rebound.attacker.example:<port>`), wrong port.
fn host_is_allowed(headers: &axum::http::HeaderMap, port: u16) -> bool {
    let Some(host_value) = headers.get(axum::http::header::HOST) else {
        return false;
    };
    let Ok(host_str) = host_value.to_str() else {
        return false;
    };
    if host_str.contains('@') {
        return false;
    }
    let v4_form = format!("127.0.0.1:{port}");
    let localhost_form = format!("localhost:{port}");
    let ipv6_form = format!("[::1]:{port}");
    // Host headers are `host:port` values, not URLs; use exact allowlist forms.
    // `eq_ignore_ascii_case` for all three keeps the comparison primitive uniform;
    // the bracketed IPv6 literal `[::1]` has no letters to fold but matching the
    // sibling forms' primitive avoids reader confusion.
    host_str.eq_ignore_ascii_case(&v4_form)
        || host_str.eq_ignore_ascii_case(&localhost_form)
        || host_str.eq_ignore_ascii_case(&ipv6_form)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only"
    )]
    use super::*;
    use axum::{
        Router,
        body::to_bytes,
        http::{Request, header},
        routing::get,
    };
    use tower::ServiceExt as _;

    /// Build a minimal test router wrapped in the host-header middleware,
    /// bound to the given port.
    fn test_router(port: u16) -> Router {
        let bound: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(HostHeaderAllowlistLayer::new(bound))
    }

    async fn do_request(router: Router, host: &str) -> u16 {
        let req = Request::builder()
            .uri("/")
            .header(header::HOST, host)
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        resp.status().as_u16()
    }

    async fn do_request_no_host(router: Router) -> u16 {
        let req = Request::builder().uri("/").body(Body::empty()).unwrap();
        let resp = router.oneshot(req).await.unwrap();
        resp.status().as_u16()
    }

    #[tokio::test]
    async fn accepts_loopback_v4_host_with_port() {
        let status = do_request(test_router(8080), "127.0.0.1:8080").await;
        assert_eq!(status, 200, "127.0.0.1:<port> should be accepted");
    }

    #[tokio::test]
    async fn accepts_localhost_host_with_port() {
        let status = do_request(test_router(8080), "localhost:8080").await;
        assert_eq!(status, 200, "localhost:<port> should be accepted");
    }

    /// RFC 9110 §7.2 — host-name comparison is case-insensitive. Browsers
    /// occasionally normalise the `Host` header to mixed case; the bridge
    /// must accept `LocalHost:<port>` and `LOCALHOST:<port>` identically to
    /// `localhost:<port>`.
    #[tokio::test]
    async fn accepts_uppercase_localhost_host_with_port() {
        let status_upper = do_request(test_router(8080), "LOCALHOST:8080").await;
        assert_eq!(
            status_upper, 200,
            "uppercase LOCALHOST:<port> should be accepted (RFC 9110 §7.2)"
        );
        let status_mixed = do_request(test_router(8080), "LocalHost:8080").await;
        assert_eq!(
            status_mixed, 200,
            "mixed-case LocalHost:<port> should be accepted (RFC 9110 §7.2)"
        );
    }

    #[tokio::test]
    async fn rejects_wrong_port() {
        let status = do_request(test_router(8080), "127.0.0.1:9999").await;
        assert_eq!(status, 421, "wrong port should yield 421");
    }

    #[tokio::test]
    async fn rejects_non_loopback_host() {
        let status = do_request(test_router(8080), "example.com:8080").await;
        assert_eq!(status, 421, "non-loopback host should yield 421");
    }

    #[tokio::test]
    async fn rejects_missing_host_header() {
        let status = do_request_no_host(test_router(8080)).await;
        assert_eq!(status, 421, "missing Host header should yield 421");
    }

    #[tokio::test]
    async fn rejects_host_with_subdomain() {
        // DNS-rebinding scenario: attacker subdomain rebounded to 127.0.0.1.
        let status = do_request(test_router(8080), "rebound.attacker.example:8080").await;
        assert_eq!(status, 421, "DNS-rebinding host should yield 421");
    }

    #[tokio::test]
    async fn accepts_ipv6_loopback() {
        let status = do_request(test_router(8080), "[::1]:8080").await;
        assert_eq!(status, 200, "IPv6 loopback host should be accepted");
    }

    /// Confirm the rejection body is the expected JSON.
    #[tokio::test]
    async fn rejection_body_is_json() {
        let router = test_router(8080);
        let req = Request::builder()
            .uri("/")
            .header(header::HOST, "attacker.example:8080")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::MISDIRECTED_REQUEST);
        let body_bytes = to_bytes(resp.into_body(), 1024).await.unwrap();
        let body_str = std::str::from_utf8(&body_bytes).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(body_str).unwrap();
        assert_eq!(
            parsed,
            json!({"error": "host_header_rejected"}),
            "rejection body should be {{\"error\":\"host_header_rejected\"}}"
        );
    }
}
