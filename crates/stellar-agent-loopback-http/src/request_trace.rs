//! The route label every loopback listener's request span records.
//!
//! A request path on these listeners can carry a bearer secret: a bootstrap
//! token (`/bootstrap/{token}`), a registration or approval nonce
//! (`/register/{nonce}`, `/approval/{nonce}/approve`). A span that recorded
//! the raw path would copy that secret into every log sink the operator
//! enables. [`route_label`] records the matched route template instead, the
//! path with its placeholders unfilled, and a fixed label for a request that
//! matched no route.
//!
//! The template comes from axum's [`MatchedPath`], which routing inserts into
//! the request extensions before it calls the matched route. A span made
//! inside a layer applied with `Router::layer` therefore sees it; a layer
//! wrapped around the whole router, which runs before routing, does not, and
//! records the fixed label.

use axum::extract::MatchedPath;
use axum::http::Request;

/// The label recorded for a request that matched no route.
pub const UNMATCHED_ROUTE_LABEL: &str = "[unmatched]";

/// The route template `request` matched, or [`UNMATCHED_ROUTE_LABEL`].
///
/// Never returns any part of the request's own path.
#[must_use]
pub fn route_label<B>(request: &Request<B>) -> &str {
    request
        .extensions()
        .get::<MatchedPath>()
        .map_or(UNMATCHED_ROUTE_LABEL, MatchedPath::as_str)
}

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
        body::Body,
        http::{HeaderValue, Response},
        middleware::{self, Next},
        routing::get,
    };
    use tower::ServiceExt as _;

    const SECRET: &str = "Zm9vYmFyYmF6cXV4cXV1eA";

    /// A router whose route-level middleware echoes [`route_label`] in a
    /// response header, the position a request span occupies.
    fn router() -> Router {
        Router::new()
            .route("/register/{nonce}", get(|| async { "ok" }))
            .route("/register/{nonce}/credential", get(|| async { "ok" }))
            .route("/healthz", get(|| async { "ok" }))
            .layer(middleware::from_fn(
                |request: Request<Body>, next: Next| async move {
                    let label = HeaderValue::from_str(route_label(&request)).unwrap();
                    let mut response: Response<Body> = next.run(request).await;
                    response.headers_mut().insert("x-route-label", label);
                    response
                },
            ))
    }

    async fn label_for(path: &str) -> String {
        let response = router()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        response
            .headers()
            .get("x-route-label")
            .expect("the route-level middleware ran")
            .to_str()
            .unwrap()
            .to_owned()
    }

    /// A matched request yields its template, never the captured segment.
    #[tokio::test]
    async fn matched_request_records_the_template() {
        assert_eq!(
            label_for(&format!("/register/{SECRET}")).await,
            "/register/{nonce}"
        );
        assert_eq!(
            label_for(&format!("/register/{SECRET}/credential?x={SECRET}")).await,
            "/register/{nonce}/credential"
        );
        assert_eq!(label_for("/healthz").await, "/healthz");
    }

    /// A registered path asked with a method its route does not serve still
    /// yields the template: routing matched the path before the method
    /// check refused it.
    #[tokio::test]
    async fn method_mismatch_records_the_template() {
        let response = router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/register/{SECRET}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            axum::http::StatusCode::METHOD_NOT_ALLOWED
        );
        assert_eq!(
            response.headers().get("x-route-label").unwrap(),
            "/register/{nonce}"
        );
    }

    /// A request that matches no route yields the fixed label.
    #[tokio::test]
    async fn unmatched_request_records_the_fixed_label() {
        assert_eq!(
            label_for(&format!("/missing/{SECRET}")).await,
            UNMATCHED_ROUTE_LABEL
        );
    }

    /// Outside routing, with no matched path in the extensions, the label is
    /// the fixed one.
    #[test]
    fn request_without_routing_records_the_fixed_label() {
        let request = Request::builder()
            .uri(format!("/register/{SECRET}"))
            .body(())
            .unwrap();
        assert_eq!(route_label(&request), UNMATCHED_ROUTE_LABEL);
    }
}
