//! `Origin`-header allowlist middleware for the remote-approval listener.
//!
//! Replaces the loopback `HostHeaderAllowlistLayer` /
//! `OriginHeaderAllowlistLayer` pair from `stellar-agent-loopback-http`: those
//! two layers assume a `127.0.0.1` / `localhost` bind, which does not apply
//! once the listener is reachable from beyond loopback. This layer instead
//! allows only `Origin: https://<rp_id>:<port>` — the exact TLS origin the
//! WebAuthn ceremony's Relying Party ID is scoped to — on ALL methods
//! (including `GET`), since every route here is part of the authenticated
//! surface and there is no unauthenticated static-asset case to special-case
//! the way the loopback bootstrap flow does.

use std::{
    future::Future,
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

/// Constructs the expected `https://<rp_id>[:<port>]` origin string for
/// `rp_id` bound on `port`.
///
/// Browsers omit the port from both the `Origin` header and
/// `clientDataJSON.origin` when it is the default port for the scheme (443
/// for `https:`) — an expected-origin string that always includes `:443`
/// would never match a real browser's request on that port. This is the
/// single, startup-time construction of the expected origin; both the
/// `Origin`-header layer ([`RemoteOriginAllowlistLayer`]) and the
/// `clientDataJSON.origin` check (`crate::verify::verify_wire_assertion`)
/// derive their expected value from this function so the two checks can
/// never disagree.
#[must_use]
pub fn expected_https_origin(rp_id: &str, port: u16) -> String {
    if port == 443 {
        format!("https://{rp_id}")
    } else {
        format!("https://{rp_id}:{port}")
    }
}

/// Tower `Layer` enforcing that every request's `Origin` header (when
/// present) equals the expected origin (see [`expected_https_origin`]).
///
/// Requests with NO `Origin` header are allowed through (browsers omit
/// `Origin` on plain navigations / same-origin GETs in some cases). The
/// authoritative same-origin proof for the WebAuthn ceremonies is
/// `crate::verify::verify_wire_assertion`'s comparison of the signed
/// `clientDataJSON.origin` field against this same expected-origin string —
/// that check runs on every login and per-action assertion regardless of
/// what `Origin` header (if any) the request carried, so a request missing
/// or spoofing this header cannot bypass it. This layer is
/// belt-and-suspenders hardening against a foreign page's cross-origin
/// fetch, not the primary origin-binding mechanism.
#[derive(Clone, Debug)]
pub struct RemoteOriginAllowlistLayer {
    expected_origin: String,
}

impl RemoteOriginAllowlistLayer {
    /// Constructs a layer that allows only the expected origin for `rp_id`
    /// bound on `port` (see [`expected_https_origin`]).
    #[must_use]
    pub fn new(rp_id: &str, port: u16) -> Self {
        Self {
            expected_origin: expected_https_origin(rp_id, port),
        }
    }
}

impl<S> Layer<S> for RemoteOriginAllowlistLayer {
    type Service = RemoteOriginAllowlistService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RemoteOriginAllowlistService {
            inner,
            expected_origin: self.expected_origin.clone(),
        }
    }
}

/// Tower `Service` implementing [`RemoteOriginAllowlistLayer`].
#[derive(Clone, Debug)]
pub struct RemoteOriginAllowlistService<S> {
    inner: S,
    expected_origin: String,
}

impl<S> Service<Request<Body>> for RemoteOriginAllowlistService<S>
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
        if let Some(origin_value) = req.headers().get(axum::http::header::ORIGIN) {
            let matches = origin_value
                .to_str()
                .is_ok_and(|s| s == self.expected_origin);
            if !matches {
                let body = json!({"error": "origin_header_rejected"}).to_string();
                let resp = Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap_or_else(|_| (StatusCode::FORBIDDEN, "").into_response());
                return Box::pin(async move { Ok(resp) });
            }
        }
        Box::pin(self.inner.call(req))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, reason = "test-only")]
    use super::*;
    use axum::{Router, http::Request, http::header, routing::get};
    use tower::ServiceExt as _;

    fn test_router() -> Router {
        Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(RemoteOriginAllowlistLayer::new("wallet.internal", 8443))
    }

    async fn do_get(router: Router, origin: Option<&str>) -> u16 {
        let mut builder = Request::builder().method("GET").uri("/");
        if let Some(o) = origin {
            builder = builder.header(header::ORIGIN, o);
        }
        let req = builder.body(Body::empty()).unwrap();
        let resp = router.oneshot(req).await.unwrap();
        resp.status().as_u16()
    }

    #[tokio::test]
    async fn accepts_matching_origin() {
        let status = do_get(test_router(), Some("https://wallet.internal:8443")).await;
        assert_eq!(status, 200);
    }

    #[tokio::test]
    async fn accepts_missing_origin() {
        let status = do_get(test_router(), None).await;
        assert_eq!(status, 200);
    }

    #[tokio::test]
    async fn rejects_http_scheme() {
        let status = do_get(test_router(), Some("http://wallet.internal:8443")).await;
        assert_eq!(status, 403);
    }

    #[tokio::test]
    async fn rejects_wrong_port() {
        let status = do_get(test_router(), Some("https://wallet.internal:9999")).await;
        assert_eq!(status, 403);
    }

    #[tokio::test]
    async fn rejects_foreign_host() {
        let status = do_get(test_router(), Some("https://attacker.example:8443")).await;
        assert_eq!(status, 403);
    }

    #[test]
    fn expected_https_origin_omits_default_port_443() {
        assert_eq!(
            expected_https_origin("wallet.internal", 443),
            "https://wallet.internal"
        );
    }

    #[test]
    fn expected_https_origin_includes_non_default_port() {
        assert_eq!(
            expected_https_origin("wallet.internal", 8443),
            "https://wallet.internal:8443"
        );
    }

    #[tokio::test]
    async fn accepts_default_port_origin_without_port_suffix() {
        let router = Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(RemoteOriginAllowlistLayer::new("wallet.internal", 443));
        let status = do_get(router, Some("https://wallet.internal")).await;
        assert_eq!(status, 200);
    }
}
