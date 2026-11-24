//! `Host` and `Origin` checks for a listener served at one signed HTTPS
//! origin.
//!
//! A listener the owner names in a signed policy serves exactly one origin,
//! `https://<host>[:<port>]`, whose grammar is lowercase with the default port
//! 443 omitted. The two layers here admit that origin and nothing else:
//!
//! - [`SignedHostLayer`] admits a request only when its `Host` header is
//!   exactly the origin's authority, the origin without `https://`, so a
//!   nondefault port is part of it. Every other request, a missing header
//!   among them, gets `421 Misdirected Request` with
//!   `{"error":"host_header_rejected"}`, as
//!   [`crate::host_header`] answers.
//! - [`SignedOriginLayer`] admits a request whose `Origin` header is exactly
//!   the origin, on every method. A state-changing request without `Origin`
//!   gets `403 Forbidden` with `{"error":"origin_header_rejected"}`, as
//!   [`crate::origin_header`] answers; `GET` and `HEAD` pass without one,
//!   because browsers do not reliably send it on same-origin reads.
//!
//! Both compare bytes exactly. The signed grammar is lowercase and has one
//! spelling per origin, so no case folding or port normalization applies.
//! The layers take the origin as a string and read nothing else, so this
//! crate needs no policy type. An origin that does not start with
//! `https://` admits no request.
//!
//! Key types: [`SignedHostLayer`], [`SignedOriginLayer`].

use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use axum::{
    body::Body,
    http::{HeaderMap, Method, Request, Response, StatusCode, header},
    response::IntoResponse,
};
use serde_json::json;
use tower::{Layer, Service};

/// The only scheme a signed origin has, with its separator.
const SCHEME: &str = "https://";

/// A JSON rejection with `status` and `{"error": error}`.
fn rejection(status: StatusCode, error: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(json!({ "error": error }).to_string()))
        .unwrap_or_else(|_| {
            // Builder failure is a logic error: the status and header are
            // fixed. Fall back to an empty response with the same status.
            (status, "").into_response()
        })
}

/// The value of header `name` as text, or `None` when it is absent or not
/// visible ASCII.
fn header_text<'a>(headers: &'a HeaderMap, name: &header::HeaderName) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

// ─────────────────────────────────────────────────────────────────────────────
// Host
// ─────────────────────────────────────────────────────────────────────────────

/// Tower `Layer` that admits only the `Host` of one signed origin.
///
/// # Examples
///
/// ```no_run
/// use stellar_agent_loopback_http::signed_origin::SignedHostLayer;
///
/// let _layer = SignedHostLayer::new("https://approve.example.invalid:8443");
/// ```
#[derive(Clone, Debug)]
pub struct SignedHostLayer {
    authority: Option<Arc<str>>,
}

impl SignedHostLayer {
    /// A layer that admits only `Host: <authority>` of `origin`, the origin
    /// without `https://`. An `origin` without that scheme admits nothing.
    #[must_use]
    pub fn new(origin: &str) -> Self {
        Self {
            authority: origin.strip_prefix(SCHEME).map(Arc::from),
        }
    }
}

impl<S> Layer<S> for SignedHostLayer {
    type Service = SignedHostService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SignedHostService {
            inner,
            authority: self.authority.clone(),
        }
    }
}

/// Tower `Service` of [`SignedHostLayer`].
#[derive(Clone, Debug)]
pub struct SignedHostService<S> {
    inner: S,
    authority: Option<Arc<str>>,
}

impl<S> Service<Request<Body>> for SignedHostService<S>
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
        let admitted = self
            .authority
            .as_deref()
            .is_some_and(|authority| header_text(req.headers(), &header::HOST) == Some(authority));
        if !admitted {
            let response = rejection(StatusCode::MISDIRECTED_REQUEST, "host_header_rejected");
            return Box::pin(async move { Ok(response) });
        }
        Box::pin(self.inner.call(req))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Origin
// ─────────────────────────────────────────────────────────────────────────────

/// Tower `Layer` that admits only the `Origin` of one signed origin.
///
/// # Examples
///
/// ```no_run
/// use stellar_agent_loopback_http::signed_origin::SignedOriginLayer;
///
/// let _layer = SignedOriginLayer::new("https://approve.example.invalid");
/// ```
#[derive(Clone, Debug)]
pub struct SignedOriginLayer {
    origin: Option<Arc<str>>,
}

impl SignedOriginLayer {
    /// A layer that admits only `Origin: <origin>` on every method and
    /// requires it on state-changing ones. An `origin` without `https://`
    /// admits nothing.
    #[must_use]
    pub fn new(origin: &str) -> Self {
        Self {
            origin: origin.starts_with(SCHEME).then(|| Arc::from(origin)),
        }
    }
}

impl<S> Layer<S> for SignedOriginLayer {
    type Service = SignedOriginService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SignedOriginService {
            inner,
            origin: self.origin.clone(),
        }
    }
}

/// Tower `Service` of [`SignedOriginLayer`].
#[derive(Clone, Debug)]
pub struct SignedOriginService<S> {
    inner: S,
    origin: Option<Arc<str>>,
}

impl<S> Service<Request<Body>> for SignedOriginService<S>
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
        let read = req.method() == Method::GET || req.method() == Method::HEAD;
        let admitted = match (self.origin.as_deref(), req.headers().get(header::ORIGIN)) {
            (None, _) => false,
            (Some(_), None) => read,
            (Some(origin), Some(value)) => value.as_bytes() == origin.as_bytes(),
        };
        if !admitted {
            let response = rejection(StatusCode::FORBIDDEN, "origin_header_rejected");
            return Box::pin(async move { Ok(response) });
        }
        Box::pin(self.inner.call(req))
    }
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
        routing::{get, post},
    };
    use tower::ServiceExt as _;

    const DEFAULT_PORT_ORIGIN: &str = "https://approve.example.invalid";
    const PORT_ORIGIN: &str = "https://approve.example.invalid:8443";

    /// The status and JSON body of `request` through `router`.
    async fn send(router: Router, request: Request<Body>) -> (u16, serde_json::Value) {
        let response = router.oneshot(request).await.unwrap();
        let status = response.status().as_u16();
        let bytes = to_bytes(response.into_body(), 1024).await.unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    fn host_router(origin: &str) -> Router {
        Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(SignedHostLayer::new(origin))
    }

    async fn host_status(origin: &str, host: Option<&str>) -> (u16, serde_json::Value) {
        let mut builder = Request::builder().uri("/");
        if let Some(host) = host {
            builder = builder.header(header::HOST, host);
        }
        send(host_router(origin), builder.body(Body::empty()).unwrap()).await
    }

    /// The Host layer admits exactly the signed authority, with its port
    /// when the origin names one, and refuses every other form with 421 and
    /// `host_header_rejected`.
    #[tokio::test]
    async fn signed_origin_host_admits_only_the_signed_authority() {
        let rejected = json!({"error": "host_header_rejected"});
        for (origin, authority) in [
            (DEFAULT_PORT_ORIGIN, "approve.example.invalid"),
            (PORT_ORIGIN, "approve.example.invalid:8443"),
        ] {
            let (status, _) = host_status(origin, Some(authority)).await;
            assert_eq!(status, 200, "{origin} admits {authority}");
        }
        let refused: [(&str, Option<&str>); 13] = [
            (PORT_ORIGIN, Some("approve.example.invalid")),
            (PORT_ORIGIN, Some("approve.example.invalid:443")),
            (PORT_ORIGIN, Some("approve.example.invalid:8444")),
            (PORT_ORIGIN, Some("APPROVE.example.invalid:8443")),
            (PORT_ORIGIN, Some("user@approve.example.invalid:8443")),
            (PORT_ORIGIN, Some("attacker.example:8443")),
            (
                PORT_ORIGIN,
                Some("approve.example.invalid.attacker.example:8443"),
            ),
            (PORT_ORIGIN, Some("127.0.0.1:8443")),
            (PORT_ORIGIN, Some("https://approve.example.invalid:8443")),
            (PORT_ORIGIN, None),
            (DEFAULT_PORT_ORIGIN, Some("approve.example.invalid:443")),
            (DEFAULT_PORT_ORIGIN, Some("Approve.example.invalid")),
            (
                "http://approve.example.invalid",
                Some("approve.example.invalid"),
            ),
        ];
        for (origin, host) in refused {
            let (status, body) = host_status(origin, host).await;
            assert_eq!((status, &body), (421, &rejected), "{origin} with {host:?}");
        }
    }

    fn origin_router(origin: &str) -> Router {
        Router::new()
            .route("/", get(|| async { "ok" }))
            .route("/post", post(|| async { "ok" }))
            .layer(SignedOriginLayer::new(origin))
    }

    async fn origin_status(
        origin: &str,
        method: &str,
        header_value: Option<&str>,
    ) -> (u16, serde_json::Value) {
        let path = if method == "POST" { "/post" } else { "/" };
        let mut builder = Request::builder().method(method).uri(path);
        if let Some(value) = header_value {
            builder = builder.header(header::ORIGIN, value);
        }
        send(origin_router(origin), builder.body(Body::empty()).unwrap()).await
    }

    /// The Origin layer admits exactly the signed origin on every method,
    /// passes GET and HEAD without an Origin, and refuses every other form
    /// with 403 and `origin_header_rejected`.
    #[tokio::test]
    async fn signed_origin_origin_admits_only_the_signed_origin() {
        let rejected = json!({"error": "origin_header_rejected"});
        for origin in [DEFAULT_PORT_ORIGIN, PORT_ORIGIN] {
            for method in ["GET", "HEAD", "POST"] {
                let (status, _) = origin_status(origin, method, Some(origin)).await;
                assert_eq!(status, 200, "{method} from {origin}");
            }
            for method in ["GET", "HEAD"] {
                let (status, _) = origin_status(origin, method, None).await;
                assert_eq!(status, 200, "{method} without Origin at {origin}");
            }
            let (status, body) = origin_status(origin, "POST", None).await;
            assert_eq!(
                (status, &body),
                (403, &rejected),
                "POST without Origin at {origin}"
            );
        }
        let refused: [(&str, &str); 10] = [
            (PORT_ORIGIN, "https://approve.example.invalid"),
            (PORT_ORIGIN, "https://approve.example.invalid:443"),
            (PORT_ORIGIN, "https://approve.example.invalid:8444"),
            (PORT_ORIGIN, "https://APPROVE.example.invalid:8443"),
            (PORT_ORIGIN, "https://user@approve.example.invalid:8443"),
            (PORT_ORIGIN, "https://attacker.example:8443"),
            (PORT_ORIGIN, "http://approve.example.invalid:8443"),
            (PORT_ORIGIN, "null"),
            (DEFAULT_PORT_ORIGIN, "https://approve.example.invalid:443"),
            (DEFAULT_PORT_ORIGIN, "http://approve.example.invalid"),
        ];
        for (origin, value) in refused {
            for method in ["GET", "HEAD", "POST"] {
                let (status, body) = origin_status(origin, method, Some(value)).await;
                // A response to HEAD carries no body.
                let expected = if method == "HEAD" {
                    serde_json::Value::Null
                } else {
                    rejected.clone()
                };
                assert_eq!(
                    (status, &body),
                    (403, &expected),
                    "{method} from {value} at {origin}"
                );
            }
        }
        for method in ["GET", "POST"] {
            let (status, body) = origin_status(
                "http://approve.example.invalid",
                method,
                Some("http://approve.example.invalid"),
            )
            .await;
            assert_eq!(
                (status, &body),
                (403, &rejected),
                "{method} at an origin without https"
            );
        }
    }
}
