//! Security response headers middleware.
//!
//! Injects hardened HTTP response headers on every response from the bridge,
//! regardless of status code (200, 4xx, 5xx, or upstream-produced errors all
//! receive the headers).
//!
//! # Headers injected
//!
//! | Header | Value | Defence |
//! |---|---|---|
//! | `Cache-Control` | `no-store` | Prevents browser/proxy caching of credential pages |
//! | `X-Content-Type-Options` | `nosniff` | Prevents MIME sniffing |
//! | `X-Frame-Options` | `DENY` | Blocks iframe-based clickjacking |
//! | `Referrer-Policy` | `no-referrer` | Prevents URL (with CSRF token) leaking via Referer |
//! | `Content-Security-Policy` | (see constant) | Restricts executable content sources |
//!
//! # CSP policy
//!
//! The `Content-Security-Policy` value is the most security-critical header.
//! It restricts executable content to `'self'` (the bridge origin) only:
//!
//! - `default-src 'none'` — deny-by-default for all resource types.
//! - `script-src 'self'` — only `/static/webauthn.js` may execute.
//! - `style-src 'self' 'unsafe-inline'` — inline `<style>` blocks permitted
//!   for the minimal UI (no external stylesheet dependencies).
//! - `connect-src 'self'` — only same-origin XHR/fetch (POST to bridge).
//! - `img-src 'self'` — only same-origin images.
//! - `base-uri 'none'` — `<base>` tag attacks disabled.
//! - `form-action 'none'` — `<form>` submissions disabled (bridge uses XHR).
//! - `frame-ancestors 'none'` — supersedes `X-Frame-Options: DENY` per
//!   CSP3 §6.3.1 in modern browsers; pairs with the XFO header for legacy
//!   fallback (clickjacking defence in depth).
//!
//! `'unsafe-eval'` and remote origins are intentionally absent.
//!
//! Key types: [`SecurityHeadersLayer`], [`SecurityHeadersService`].

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

// ─────────────────────────────────────────────────────────────────────────────
// CSP constant
// ─────────────────────────────────────────────────────────────────────────────

/// Content Security Policy for all bridge-served pages.
///
/// Hardening properties:
/// - No `'unsafe-eval'`, no remote origins, no wildcard.
/// - `'unsafe-inline'` only on `style-src` (inline `<style>` blocks needed
///   by the minimal UI; NO inline scripts).
///
/// This constant is a single `'static` `&str` to ensure byte-for-byte
/// consistency across all response headers. Tests validate against this
/// exact constant.
pub(crate) const CSP_VALUE: &str = "default-src 'none'; \
    script-src 'self'; \
    style-src 'self' 'unsafe-inline'; \
    connect-src 'self'; \
    img-src 'self'; \
    base-uri 'none'; \
    form-action 'none'; \
    frame-ancestors 'none'";

// ─────────────────────────────────────────────────────────────────────────────
// Layer
// ─────────────────────────────────────────────────────────────────────────────

/// Tower `Layer` that injects hardened security response headers.
///
/// Applied unconditionally on every response; status code does not affect
/// header injection.
///
/// # Examples
///
/// ```no_run
/// use stellar_agent_webauthn_bridge::middleware::security_headers::SecurityHeadersLayer;
///
/// let _layer = SecurityHeadersLayer::new();
/// ```
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

// ─────────────────────────────────────────────────────────────────────────────
// Service
// ─────────────────────────────────────────────────────────────────────────────

/// Tower `Service` that injects hardened security response headers.
///
/// Injects five headers on every response regardless of status code or whether
/// the response was produced by a handler, a middleware rejection, or a body-
/// limit error.
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

// ─────────────────────────────────────────────────────────────────────────────
// Header injection
// ─────────────────────────────────────────────────────────────────────────────

/// Inject the five hardened security response headers into `headers`.
///
/// Existing values for these headers are overwritten to prevent a handler
/// from accidentally weakening the policy.  All header values are `'static`
/// ASCII strings, so construction via `HeaderValue::from_static` is infallible.
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
    // CSP is the most security-critical header; use the single-source constant.
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        axum::http::HeaderValue::from_static(CSP_VALUE),
    );
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
            .header(axum::http::header::HOST, "127.0.0.1:8080")
            .body(Body::empty())
            .unwrap();
        router.oneshot(req).await.unwrap()
    }

    #[tokio::test]
    async fn injects_cache_control_no_store() {
        let resp = get_response(test_router()).await;
        let val = resp
            .headers()
            .get(header::CACHE_CONTROL)
            .expect("Cache-Control header must be present")
            .to_str()
            .unwrap();
        assert_eq!(val, "no-store");
    }

    #[tokio::test]
    async fn injects_x_content_type_options() {
        let resp = get_response(test_router()).await;
        let val = resp
            .headers()
            .get("x-content-type-options")
            .expect("X-Content-Type-Options must be present")
            .to_str()
            .unwrap();
        assert_eq!(val, "nosniff");
    }

    #[tokio::test]
    async fn injects_x_frame_options() {
        let resp = get_response(test_router()).await;
        let val = resp
            .headers()
            .get("x-frame-options")
            .expect("X-Frame-Options must be present")
            .to_str()
            .unwrap();
        assert_eq!(val, "DENY");
    }

    #[tokio::test]
    async fn injects_referrer_policy() {
        let resp = get_response(test_router()).await;
        let val = resp
            .headers()
            .get(header::REFERRER_POLICY)
            .expect("Referrer-Policy must be present")
            .to_str()
            .unwrap();
        assert_eq!(val, "no-referrer");
    }

    #[tokio::test]
    async fn injects_csp_matching_exact_constant() {
        let resp = get_response(test_router()).await;
        let val = resp
            .headers()
            .get(header::CONTENT_SECURITY_POLICY)
            .expect("Content-Security-Policy must be present")
            .to_str()
            .unwrap();
        assert_eq!(val, CSP_VALUE, "CSP must match the exact constant");
    }

    #[tokio::test]
    async fn all_five_headers_present_on_200() {
        let resp = get_response(test_router()).await;
        assert_eq!(resp.status().as_u16(), 200);
        assert!(
            resp.headers().get(header::CACHE_CONTROL).is_some(),
            "Cache-Control missing"
        );
        assert!(
            resp.headers().get("x-content-type-options").is_some(),
            "X-Content-Type-Options missing"
        );
        assert!(
            resp.headers().get("x-frame-options").is_some(),
            "X-Frame-Options missing"
        );
        assert!(
            resp.headers().get(header::REFERRER_POLICY).is_some(),
            "Referrer-Policy missing"
        );
        assert!(
            resp.headers()
                .get(header::CONTENT_SECURITY_POLICY)
                .is_some(),
            "Content-Security-Policy missing"
        );
    }

    #[tokio::test]
    async fn headers_present_on_404() {
        let router = Router::new().layer(SecurityHeadersLayer::new());
        let req = Request::builder()
            .uri("/nonexistent")
            .header(axum::http::header::HOST, "127.0.0.1:8080")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        // axum returns 404 for unregistered routes.
        assert_eq!(resp.status().as_u16(), 404);
        assert!(
            resp.headers()
                .get(header::CONTENT_SECURITY_POLICY)
                .is_some(),
            "CSP must be injected on 404 responses too"
        );
        assert!(
            resp.headers().get(header::CACHE_CONTROL).is_some(),
            "Cache-Control must be injected on 404 responses"
        );
    }
}
