//! Security response-headers middleware.
//!
//! Injects five hardened headers on every response regardless of status code:
//! `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`,
//! `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and a
//! `Content-Security-Policy` restricting executable content to same-origin.
//!
//! The CSP permits `script-src 'self'` (the same-origin `/static/app.js` drives
//! polling and fetch) with no `'unsafe-inline'` for scripts; inline styles are
//! allowed. All dynamic values reach the browser through a
//! `<script type="application/json">` data island, never inline JS.

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use axum::{
    body::Body,
    http::{Request, Response, header},
};
use tower::{Layer, Service};

/// Content Security Policy for every approval-inbox page.
///
/// `default-src 'none'` deny-by-default; `script-src 'self'` allows only the
/// same-origin `/static/app.js`; `'unsafe-inline'` is limited to `style-src`.
/// Tests assert against this exact constant.
pub(crate) const CSP_VALUE: &str = "default-src 'none'; \
    script-src 'self'; \
    style-src 'self' 'unsafe-inline'; \
    connect-src 'self'; \
    img-src 'self'; \
    base-uri 'none'; \
    form-action 'none'; \
    frame-ancestors 'none'";

/// Tower `Layer` injecting hardened security response headers.
#[derive(Clone, Debug, Default)]
pub struct SecurityHeadersLayer;

impl SecurityHeadersLayer {
    /// Create a new `SecurityHeadersLayer`.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for SecurityHeadersLayer {
    type Service = SecurityHeadersService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SecurityHeadersService { inner }
    }
}

/// Tower `Service` injecting hardened security response headers.
#[derive(Clone, Debug)]
pub struct SecurityHeadersService<S> {
    inner: S,
}

impl<S> Service<Request<Body>> for SecurityHeadersService<S>
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
        let fut = self.inner.call(req);
        Box::pin(async move {
            let mut resp = fut.await?;
            inject_security_headers(resp.headers_mut());
            Ok(resp)
        })
    }
}

/// Injects the five hardened security response headers into `headers`.
fn inject_security_headers(headers: &mut axum::http::HeaderMap) {
    headers.insert(
        header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    headers.insert(
        header::HeaderName::from_static("x-content-type-options"),
        axum::http::HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::HeaderName::from_static("x-frame-options"),
        axum::http::HeaderValue::from_static("DENY"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        axum::http::HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        axum::http::HeaderValue::from_static(CSP_VALUE),
    );
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
    use axum::{Router, http::Request, routing::get};
    use tower::ServiceExt as _;

    fn test_router() -> Router {
        Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(SecurityHeadersLayer::new())
    }

    async fn get_response(router: Router) -> axum::http::Response<Body> {
        let req = Request::builder()
            .uri("/")
            .header(header::HOST, "127.0.0.1:8080")
            .body(Body::empty())
            .unwrap();
        router.oneshot(req).await.unwrap()
    }

    #[tokio::test]
    async fn injects_all_five_headers() {
        let resp = get_response(test_router()).await;
        assert_eq!(
            resp.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert_eq!(
            resp.headers().get("x-content-type-options").unwrap(),
            "nosniff"
        );
        assert_eq!(resp.headers().get("x-frame-options").unwrap(), "DENY");
        assert_eq!(
            resp.headers().get(header::REFERRER_POLICY).unwrap(),
            "no-referrer"
        );
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_SECURITY_POLICY)
                .unwrap()
                .to_str()
                .unwrap(),
            CSP_VALUE
        );
    }

    #[tokio::test]
    async fn csp_has_no_unsafe_inline_scripts() {
        assert!(CSP_VALUE.contains("script-src 'self'"));
        assert!(!CSP_VALUE.contains("script-src 'self' 'unsafe-inline'"));
        assert!(!CSP_VALUE.contains("unsafe-eval"));
    }
}
