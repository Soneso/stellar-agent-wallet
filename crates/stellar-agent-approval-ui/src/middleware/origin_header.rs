//! Origin-header validation middleware (cross-origin POST hardening).
//!
//! State-changing methods (POST/PUT/PATCH/DELETE) must carry an `Origin` header
//! equal to `http://127.0.0.1:<port>` or `http://localhost:<port>`. Requests
//! missing or mismatching that header are rejected with `403 Forbidden` and a
//! JSON body `{"error":"origin_header_rejected"}`. `GET`/`HEAD` pass through
//! unconditionally — browsers do not reliably send `Origin` on same-origin GETs.
//!
//! `[::1]` is intentionally NOT accepted here (matching the WebAuthn bridge):
//! wallet-emitted URLs use `127.0.0.1`/`localhost`, so the browser's `Origin`
//! for a page loaded from the bootstrap URL is always one of those two.

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

/// Tower `Layer` enforcing the `Origin`-header allowlist on state-changing
/// methods for `bound_addr`.
#[derive(Clone, Debug)]
pub struct OriginHeaderAllowlistLayer {
    bound_addr: SocketAddr,
}

impl OriginHeaderAllowlistLayer {
    /// Create a layer that accepts only the two canonical loopback `Origin`
    /// forms for `bound_addr` on POST/PUT/PATCH/DELETE.
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

/// Tower `Service` enforcing the `Origin`-header allowlist.
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

        if method == Method::GET || method == Method::HEAD {
            return Box::pin(self.inner.call(req));
        }

        if !origin_is_allowed(req.headers(), port) {
            let body = json!({"error": "origin_header_rejected"}).to_string();
            let resp = Response::builder()
                .status(StatusCode::FORBIDDEN)
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap_or_else(|_| (StatusCode::FORBIDDEN, "").into_response());
            return Box::pin(async move { Ok(resp) });
        }

        Box::pin(self.inner.call(req))
    }
}

/// Returns `true` iff the `Origin` header matches `http://127.0.0.1:<port>` or
/// `http://localhost:<port>` (host-name compared case-insensitively).
fn origin_is_allowed(headers: &axum::http::HeaderMap, port: u16) -> bool {
    let Some(origin_value) = headers.get(axum::http::header::ORIGIN) else {
        return false;
    };
    let Ok(origin_str) = origin_value.to_str() else {
        return false;
    };
    let v4_form = format!("http://127.0.0.1:{port}");
    if origin_str == v4_form {
        return true;
    }
    if let Some(rest) = origin_str.strip_prefix("http://") {
        let localhost_rest = format!("localhost:{port}");
        if rest.eq_ignore_ascii_case(&localhost_rest) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]
    use super::*;
    use axum::{Router, http::header, routing::get};
    use tower::ServiceExt as _;

    fn test_router(port: u16) -> Router {
        let bound: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        Router::new()
            .route("/", get(|| async { "ok" }))
            .route("/post", axum::routing::post(|| async { "ok" }))
            .layer(OriginHeaderAllowlistLayer::new(bound))
    }

    async fn do_post(router: Router, origin: Option<&str>) -> u16 {
        let mut b = Request::builder()
            .method("POST")
            .uri("/post")
            .header(header::HOST, "127.0.0.1:8080");
        if let Some(o) = origin {
            b = b.header(header::ORIGIN, o);
        }
        let resp = router
            .oneshot(b.body(Body::empty()).unwrap())
            .await
            .unwrap();
        resp.status().as_u16()
    }

    #[tokio::test]
    async fn accepts_loopback_origin_on_post() {
        assert_eq!(
            do_post(test_router(8080), Some("http://127.0.0.1:8080")).await,
            200
        );
        assert_eq!(
            do_post(test_router(8080), Some("http://localhost:8080")).await,
            200
        );
        assert_eq!(
            do_post(test_router(8080), Some("http://LOCALHOST:8080")).await,
            200
        );
    }

    #[tokio::test]
    async fn rejects_bad_origin_on_post() {
        assert_eq!(
            do_post(test_router(8080), Some("https://127.0.0.1:8080")).await,
            403
        );
        assert_eq!(
            do_post(test_router(8080), Some("http://127.0.0.1:9999")).await,
            403
        );
        assert_eq!(
            do_post(test_router(8080), Some("http://example.com:8080")).await,
            403
        );
        assert_eq!(do_post(test_router(8080), None).await, 403);
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
    async fn allows_get_without_origin() {
        let router = test_router(8080);
        let req = Request::builder()
            .method("GET")
            .uri("/")
            .header(header::HOST, "127.0.0.1:8080")
            .body(Body::empty())
            .unwrap();
        assert_eq!(router.oneshot(req).await.unwrap().status().as_u16(), 200);
    }
}
