//! Origin-header validation middleware (cross-origin POST hardening).
//!
//! State-changing HTTP methods (POST, PUT, PATCH, DELETE) must carry an
//! `Origin:` header whose value is exactly `http://127.0.0.1:<port>` or
//! `http://localhost:<port>`. Requests missing or mismatching that header on
//! those methods are rejected with `403 Forbidden` and a JSON body
//! `{"error":"origin_header_rejected"}`.
//!
//! `GET` and `HEAD` requests are allowed through unconditionally — browsers do
//! not reliably send `Origin` on same-origin GET requests, and these methods
//! cause no state change.
//!
//! `[::1]` is intentionally NOT accepted here: wallet-emitted URLs use
//! `127.0.0.1`/`localhost`, so the browser's `Origin` for a page loaded from
//! the bootstrap URL is always one of those two.
//!
//! # RFC 9110 §7.2 case-insensitivity
//!
//! The host part of the `Origin:` header is compared ASCII-case-insensitively
//! per RFC 9110 §7.2. The scheme is compared in lowercase (browsers always
//! normalise the scheme to lowercase in `Origin:`).
//!
//! # DNS rebinding
//!
//! Unlike the `Host:` header check, the `Origin:` header is set by the
//! browser and cannot be forged by a DNS-rebinding attack: the browser's
//! Origin-reflection rules constrain the value to the page's actual origin.
//! A page from `attacker.example` whose DNS is rebounded to `127.0.0.1` still
//! sends `Origin: http://attacker.example:<port>`, which fails this check.
//!
//! Key types: [`OriginHeaderAllowlistLayer`], [`OriginHeaderAllowlistService`].

use std::{
    future::Future,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

use axum::{
    body::Body,
    http::{Method, Request, Response, StatusCode},
    response::IntoResponse,
};
use serde_json::json;
use tower::{Layer, Service};

// ─────────────────────────────────────────────────────────────────────────────
// Layer
// ─────────────────────────────────────────────────────────────────────────────

/// Tower `Layer` that enforces the `Origin`-header allowlist on
/// state-changing HTTP methods.
///
/// Constructed with the listener's actual bound [`SocketAddr`]; the service
/// accepts only `Origin: http://127.0.0.1:<port>` and
/// `Origin: http://localhost:<port>` on POST/PUT/PATCH/DELETE.
///
/// GET and HEAD requests are passed through regardless of `Origin`.
///
/// # Examples
///
/// ```no_run
/// use std::net::SocketAddr;
/// use stellar_agent_loopback_http::origin_header::OriginHeaderAllowlistLayer;
///
/// let bound: SocketAddr = "127.0.0.1:8443".parse().unwrap();
/// let _layer = OriginHeaderAllowlistLayer::new(bound);
/// ```
#[derive(Clone, Debug)]
pub struct OriginHeaderAllowlistLayer {
    bound_addr: SocketAddr,
}

impl OriginHeaderAllowlistLayer {
    /// Create a new layer that allows only the two canonical `Origin` forms for
    /// `bound_addr` on state-changing HTTP methods.
    #[must_use]
    pub fn new(bound_addr: SocketAddr) -> Self {
        Self { bound_addr }
    }
}

impl<S> Layer<S> for OriginHeaderAllowlistLayer {
    type Service = OriginHeaderAllowlistService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        OriginHeaderAllowlistService {
            inner,
            bound_addr: self.bound_addr,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Service
// ─────────────────────────────────────────────────────────────────────────────

/// Tower `Service` that enforces the `Origin`-header allowlist.
///
/// Rejects state-changing requests whose `Origin:` header is absent or not
/// `http://127.0.0.1:<port>` or `http://localhost:<port>` with
/// `403 Forbidden`.
#[derive(Clone, Debug)]
pub struct OriginHeaderAllowlistService<S> {
    inner: S,
    bound_addr: SocketAddr,
}

impl<S> Service<Request<Body>> for OriginHeaderAllowlistService<S>
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
        let method = req.method().clone();
        let port = self.bound_addr.port();

        // GET and HEAD: allow through without Origin check.
        // Browsers do not reliably send Origin on same-origin GET requests.
        if method == Method::GET || method == Method::HEAD {
            return Box::pin(self.inner.call(req));
        }

        // For state-changing methods: require a valid Origin header.
        let allowed = origin_is_allowed(req.headers(), port);
        if !allowed {
            let body = json!({"error": "origin_header_rejected"}).to_string();
            let resp = Response::builder()
                .status(StatusCode::FORBIDDEN)
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap_or_else(|_| {
                    // Builder failure is a logic error (fixed status + header values).
                    (StatusCode::FORBIDDEN, "").into_response()
                });
            return Box::pin(async move { Ok(resp) });
        }

        Box::pin(self.inner.call(req))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Allow-list logic
// ─────────────────────────────────────────────────────────────────────────────

/// Returns `true` iff the `Origin` header value matches
/// `http://127.0.0.1:<port>` or `http://localhost:<port>`.
///
/// The scheme is always lowercase (`http://`) — browsers normalise it.
/// The host component is compared ASCII-case-insensitively per RFC 9110 §7.2
/// so that `LOCALHOST` and `LocalHost` are accepted alongside `localhost`.
/// The numeric port is compared verbatim.
///
/// A missing `Origin` header returns `false` (caller maps to rejection).
///
/// Rejects:
/// - Missing header.
/// - `https://` scheme (wrong scheme for the HTTP-only listener).
/// - Wrong port.
/// - Foreign origin (e.g. `http://attacker.example:<port>`).
/// - DNS-rebind subdomain (e.g. `http://rebound.attacker.example:<port>`).
fn origin_is_allowed(headers: &axum::http::HeaderMap, port: u16) -> bool {
    let Some(origin_value) = headers.get(axum::http::header::ORIGIN) else {
        return false;
    };
    let Ok(origin_str) = origin_value.to_str() else {
        return false;
    };
    let v4_form = format!("http://127.0.0.1:{port}");

    // Compare v4 form case-sensitively (IP addresses are not hostname components).
    if origin_str == v4_form {
        return true;
    }

    // Compare localhost form case-insensitively on the host component per RFC 9110 §7.2.
    // The scheme prefix `http://` is lowercase-fixed (browsers normalise it); only
    // the host varies. Split at the `http://` boundary to compare host independently.
    if let Some(rest) = origin_str.strip_prefix("http://") {
        // rest is "<host>:<port>"
        let localhost_rest = format!("localhost:{port}");
        if rest.eq_ignore_ascii_case(&localhost_rest) {
            return true;
        }
    }

    false
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

    fn test_router(port: u16) -> Router {
        let bound: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        Router::new()
            .route("/", get(|| async { "ok" }))
            .route("/post", axum::routing::post(|| async { "ok" }))
            .layer(OriginHeaderAllowlistLayer::new(bound))
    }

    async fn do_post(router: Router, origin: Option<&str>) -> u16 {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/post")
            .header(header::HOST, "127.0.0.1:8080");
        if let Some(o) = origin {
            builder = builder.header(header::ORIGIN, o);
        }
        let req = builder.body(Body::empty()).unwrap();
        let resp = router.oneshot(req).await.unwrap();
        resp.status().as_u16()
    }

    async fn do_get(router: Router, origin: Option<&str>) -> u16 {
        let mut builder = Request::builder()
            .method("GET")
            .uri("/")
            .header(header::HOST, "127.0.0.1:8080");
        if let Some(o) = origin {
            builder = builder.header(header::ORIGIN, o);
        }
        let req = builder.body(Body::empty()).unwrap();
        let resp = router.oneshot(req).await.unwrap();
        resp.status().as_u16()
    }

    #[tokio::test]
    async fn accepts_loopback_origin_on_post() {
        let status = do_post(test_router(8080), Some("http://127.0.0.1:8080")).await;
        assert_eq!(status, 200, "loopback origin should be accepted on POST");
    }

    #[tokio::test]
    async fn accepts_localhost_origin_on_post() {
        let status = do_post(test_router(8080), Some("http://localhost:8080")).await;
        assert_eq!(status, 200, "localhost origin should be accepted on POST");
    }

    #[tokio::test]
    async fn accepts_uppercase_localhost_origin_on_post() {
        let status = do_post(test_router(8080), Some("http://LOCALHOST:8080")).await;
        assert_eq!(
            status, 200,
            "uppercase LOCALHOST should be accepted (RFC 9110 §7.2)"
        );
        let status_mixed = do_post(test_router(8080), Some("http://LocalHost:8080")).await;
        assert_eq!(
            status_mixed, 200,
            "mixed-case LocalHost should be accepted (RFC 9110 §7.2)"
        );
    }

    #[tokio::test]
    async fn rejects_https_scheme_on_post() {
        let status = do_post(test_router(8080), Some("https://127.0.0.1:8080")).await;
        assert_eq!(status, 403, "https scheme should be rejected");
    }

    #[tokio::test]
    async fn rejects_wrong_port_on_post() {
        let status = do_post(test_router(8080), Some("http://127.0.0.1:9999")).await;
        assert_eq!(status, 403, "wrong port should be rejected");
    }

    #[tokio::test]
    async fn rejects_foreign_origin_on_post() {
        let status = do_post(test_router(8080), Some("http://example.com:8080")).await;
        assert_eq!(status, 403, "foreign origin should be rejected");
    }

    #[tokio::test]
    async fn rejects_dns_rebind_subdomain_on_post() {
        let status = do_post(
            test_router(8080),
            Some("http://rebound.attacker.example:8080"),
        )
        .await;
        assert_eq!(status, 403, "DNS-rebind subdomain should be rejected");
    }

    #[tokio::test]
    async fn accepts_get_without_origin() {
        // GET without Origin: allowed (browsers don't reliably send it).
        let status = do_get(test_router(8080), None).await;
        assert_eq!(status, 200, "GET without Origin should be allowed");
    }

    #[tokio::test]
    async fn rejects_post_without_origin() {
        let status = do_post(test_router(8080), None).await;
        assert_eq!(status, 403, "POST without Origin should be rejected");
    }

    /// An `Origin` header that is not valid UTF-8 fails `HeaderValue::to_str`
    /// and is rejected, never panics.
    #[tokio::test]
    async fn rejects_non_utf8_origin_header() {
        let bound: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let router = Router::new()
            .route("/post", axum::routing::post(|| async { "ok" }))
            .layer(OriginHeaderAllowlistLayer::new(bound));
        let req = Request::builder()
            .method("POST")
            .uri("/post")
            .header(header::HOST, "127.0.0.1:8080")
            .header(
                header::ORIGIN,
                axum::http::HeaderValue::from_bytes(&[0x80, 0x81, 0x82]).unwrap(),
            )
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status().as_u16(), 403);
    }

    #[tokio::test]
    async fn rejection_body_is_json() {
        let router = test_router(8080);
        let req = Request::builder()
            .method("POST")
            .uri("/post")
            .header(header::HOST, "127.0.0.1:8080")
            .header(header::ORIGIN, "http://attacker.example:8080")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body_bytes = to_bytes(resp.into_body(), 1024).await.unwrap();
        let body_str = std::str::from_utf8(&body_bytes).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(body_str).unwrap();
        assert_eq!(
            parsed,
            serde_json::json!({"error": "origin_header_rejected"}),
            "rejection body should be {{\"error\":\"origin_header_rejected\"}}"
        );
    }
}
