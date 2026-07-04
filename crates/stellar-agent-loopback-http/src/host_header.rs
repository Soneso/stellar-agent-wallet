//! Host-header allowlist middleware (DNS-rebinding defence).
//!
//! Every inbound HTTP request must carry a `Host` header whose value is
//! exactly `127.0.0.1:<port>`, `localhost:<port>`, or `[::1]:<port>`, where
//! `<port>` is the listener's actual bound port. Requests with any other
//! `Host` value — including a missing header — are rejected with
//! `421 Misdirected Request` and a JSON error body
//! `{"error":"host_header_rejected"}`, before any route handler runs.
//!
//! # Why this defence matters
//!
//! A malicious site `attacker.example` can repoint its DNS A-record to
//! `127.0.0.1` while a tab is open (DNS rebinding). The browser then permits
//! fetches to `http://wallet-rebound.attacker.example:<port>/...`, the kernel
//! routes the packets to the listener (loopback satisfied), and the browser
//! considers the destination same-origin. Checking the `Host:` header rejects
//! such requests before any route handler runs.
//!
//! # IPv6 loopback
//!
//! `[::1]:<port>` is accepted as a loopback-equivalent `Host` header.
//!
//! # RFC 9110 §7.2 case-insensitivity
//!
//! Host-name comparison is ASCII-case-insensitive per RFC 9110 §7.2; the
//! numeric port is compared verbatim.
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
/// Constructed with the listener's actual bound [`SocketAddr`]; the service
/// accepts only `Host: 127.0.0.1:<port>`, `Host: localhost:<port>`, and
/// `Host: [::1]:<port>`.
///
/// # Examples
///
/// ```no_run
/// use std::net::SocketAddr;
/// use stellar_agent_loopback_http::host_header::HostHeaderAllowlistLayer;
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
        if !host_is_allowed(req.headers(), port) {
            // A loopback-named Host at the WRONG port is the classic SSH
            // tunnel misconfiguration (forwarding a different local port than
            // the one the server is bound to). Hint at that specific cause on
            // the server's own log; the wire body stays generic either way.
            if let Some(host_str) = req
                .headers()
                .get(axum::http::header::HOST)
                .and_then(|v| v.to_str().ok())
                && host_name_is_loopback(host_str)
            {
                tracing::warn!(
                    bound_port = port,
                    "host header names a loopback address at the wrong port; \
                     when tunneling, forward the same local port: \
                     ssh -L <port>:127.0.0.1:<port>"
                );
            }
            let body = json!({"error": "host_header_rejected"}).to_string();
            let resp = Response::builder()
                .status(StatusCode::MISDIRECTED_REQUEST)
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap_or_else(|_| {
                    // Builder failure here is a logic error (fixed status +
                    // header values). Fall back to an empty 421.
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
/// Rejects: missing header, userinfo (`user@host:port`), subdomain of
/// `localhost` (e.g. `rebound.attacker.example:<port>`), wrong port.
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
    host_str.eq_ignore_ascii_case(&v4_form)
        || host_str.eq_ignore_ascii_case(&localhost_form)
        || host_str.eq_ignore_ascii_case(&ipv6_form)
}

/// Returns `true` iff `host_str`'s name component (everything before the last
/// `:`) is one of the three loopback names this allowlist accepts, regardless
/// of whether the port suffix matches the bound port.
///
/// Used only to decide whether a rejection warrants the wrong-port tunnel
/// hint; it never affects the accept/reject decision itself.
fn host_name_is_loopback(host_str: &str) -> bool {
    let Some((name, _port)) = host_str.rsplit_once(':') else {
        return false;
    };
    name.eq_ignore_ascii_case("127.0.0.1")
        || name.eq_ignore_ascii_case("localhost")
        || name.eq_ignore_ascii_case("[::1]")
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

    async fn do_request(router: Router, host: Option<&str>) -> u16 {
        let mut b = Request::builder().uri("/");
        if let Some(h) = host {
            b = b.header(header::HOST, h);
        }
        let resp = router
            .oneshot(b.body(Body::empty()).unwrap())
            .await
            .unwrap();
        resp.status().as_u16()
    }

    #[tokio::test]
    async fn accepts_loopback_forms() {
        assert_eq!(
            do_request(test_router(8080), Some("127.0.0.1:8080")).await,
            200
        );
        assert_eq!(
            do_request(test_router(8080), Some("localhost:8080")).await,
            200
        );
        assert_eq!(
            do_request(test_router(8080), Some("LOCALHOST:8080")).await,
            200
        );
        assert_eq!(do_request(test_router(8080), Some("[::1]:8080")).await, 200);
    }

    #[tokio::test]
    async fn rejects_bad_host() {
        assert_eq!(
            do_request(test_router(8080), Some("127.0.0.1:9999")).await,
            421
        );
        assert_eq!(
            do_request(test_router(8080), Some("example.com:8080")).await,
            421
        );
        assert_eq!(
            do_request(test_router(8080), Some("rebound.attacker.example:8080")).await,
            421
        );
        assert_eq!(do_request(test_router(8080), None).await, 421);
    }

    /// A `Host` header carrying userinfo (`user@host:port`) is rejected
    /// outright, even though the trailing host:port would otherwise match —
    /// this defends against userinfo-based Host confusion.
    #[tokio::test]
    async fn rejects_host_with_userinfo() {
        assert_eq!(
            do_request(test_router(8080), Some("user@127.0.0.1:8080")).await,
            421
        );
    }

    /// A `Host` header that is not valid UTF-8 fails `HeaderValue::to_str`
    /// and is rejected, never panics.
    #[tokio::test]
    async fn rejects_non_utf8_host_header() {
        let bound: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let router = Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(HostHeaderAllowlistLayer::new(bound));
        let req = Request::builder()
            .uri("/")
            .header(
                header::HOST,
                axum::http::HeaderValue::from_bytes(&[0x80, 0x81, 0x82]).unwrap(),
            )
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status().as_u16(), 421);
    }

    /// RFC 9110 §7.2 — host-name comparison is case-insensitive. Browsers
    /// occasionally normalise the `Host` header to mixed case; the listener
    /// must accept `LocalHost:<port>` and `LOCALHOST:<port>` identically to
    /// `localhost:<port>`.
    #[tokio::test]
    async fn accepts_uppercase_localhost_host_with_port() {
        let status_upper = do_request(test_router(8080), Some("LOCALHOST:8080")).await;
        assert_eq!(
            status_upper, 200,
            "uppercase LOCALHOST:<port> should be accepted (RFC 9110 §7.2)"
        );
        let status_mixed = do_request(test_router(8080), Some("LocalHost:8080")).await;
        assert_eq!(
            status_mixed, 200,
            "mixed-case LocalHost:<port> should be accepted (RFC 9110 §7.2)"
        );
    }

    #[tokio::test]
    async fn rejects_host_with_subdomain() {
        // DNS-rebinding scenario: attacker subdomain rebounded to 127.0.0.1.
        let status = do_request(test_router(8080), Some("rebound.attacker.example:8080")).await;
        assert_eq!(status, 421, "DNS-rebinding host should yield 421");
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

    /// The wrong-port tunnel hint fires only for a loopback NAME at the wrong
    /// port; a wire-level rejection still occurs either way (covered by
    /// `rejects_bad_host` above) — this test covers the pure classifier
    /// directly so the two cases (hint vs. no hint) are independently
    /// verified rather than only inferred from log output.
    #[test]
    fn host_name_is_loopback_classifies_correctly() {
        assert!(host_name_is_loopback("127.0.0.1:9999"));
        assert!(host_name_is_loopback("localhost:1"));
        assert!(host_name_is_loopback("LOCALHOST:1"));
        assert!(host_name_is_loopback("[::1]:9999"));
        assert!(!host_name_is_loopback("example.com:8080"));
        assert!(!host_name_is_loopback("rebound.attacker.example:8080"));
        assert!(!host_name_is_loopback("no-port-at-all"));
    }
}
