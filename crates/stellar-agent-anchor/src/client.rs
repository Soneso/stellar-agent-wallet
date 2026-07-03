//! Bounded HTTPS client for anchor endpoints.
//!
//! # What this module does
//!
//! Provides [`AnchorClient`] — the crate's own `reqwest::Client` configured
//! with:
//!
//! - **HTTPS-only** (`.https_only(true)`) — any `http://` URL is rejected at
//!   request time.
//! - **No redirects** (`redirect::Policy::none()`) — anchor endpoints must
//!   not redirect; a redirect would bypass the same-domain SSRF bind.
//! - **No decompression** (`.no_gzip().no_brotli().no_deflate()`) — defence
//!   against decompression-bomb attacks.
//! - **Connect timeout: 10 s** — limits TCP+TLS handshake time.
//! - **Request timeout: 30 s** — total round-trip budget; guards against
//!   slowloris-style stalls.
//! - **Body cap: 64 KiB** — enforced by streaming chunks with a running total
//!   before any single-buffer allocation, so memory is bounded before buffering.
//! - **Bounded `serde_json` decode** — only the already-capped bytes are
//!   deserialised; oversized bodies are rejected before decode.
//!
//! # Test-only constructor
//!
//! `new_without_https_enforcement()` builds the same client without
//! `.https_only(true)`.  It is available only under `test-helpers` or
//! `#[cfg(test)]` and must never be called from production code.
//!
//! # Why a fresh client
//!
//! `fetch_stellar_toml` is hardcoded to `/.well-known/stellar.toml` and
//! rejects non-`text/*` content-types; it cannot serve JSON endpoints.
//! The network crate's bounded fetch helper accepts only a single overall
//! timeout and does not set a per-request connect timeout; this crate
//! additionally enforces a streaming 64 KiB body cap, and a non-HTTPS variant
//! is needed for local-server tests.  Per the established per-SEP pattern in
//! this workspace, this crate constructs its own guarded client with equivalent
//! security properties.

use std::time::Duration;

use reqwest::redirect;

use crate::error::AnchorError;

// serde_json is used by post_json_with_bearer to serialise the JSON request body.
use serde_json::Value as JsonValue;

/// Maximum response body bytes accepted from any anchor endpoint.
///
/// 64 KiB matches the body cap used by other network fetch helpers in this
/// workspace.
pub(crate) const MAX_BODY_BYTES: usize = 64 * 1024;

/// Connect timeout for anchor HTTP requests.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Total request timeout (defence against slowloris-style stalls).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// A `reqwest::Client` pre-configured for anchor JSON endpoints.
///
/// See module-level documentation for the full security configuration.
/// Production code must construct instances via `new()`.
///
/// Under `test-helpers` or `#[cfg(test)]`, this type is re-exported via the
/// `test_helpers` module so integration tests can call
/// `new_without_https_enforcement()`.  The constructor is gated so it is only
/// callable in test contexts.
// The struct is `pub` so it can be re-exported from `crate::test_helpers`
// under the test-helpers feature without a `pub(crate)` re-export error.
// The production API surface is controlled by which constructors are exposed:
// only `new()` is `pub(crate)` in production; `new_without_https_enforcement`
// is gated to cfg(any(test, feature = "test-helpers")).
pub struct AnchorClient {
    inner: reqwest::Client,
}

impl AnchorClient {
    /// Constructs a production [`AnchorClient`] with HTTPS-only enforcement.
    ///
    /// # Errors
    ///
    /// Returns [`AnchorError::AnchorFetchFailed`] if the underlying
    /// `reqwest::Client` cannot be constructed (extremely rare; indicates a
    /// system-level TLS initialisation failure).
    pub(crate) fn new() -> Result<Self, AnchorError> {
        let inner = reqwest::Client::builder()
            // SEC: HTTPS-only enforcement — rejects any http:// URL at request time.
            .https_only(true)
            // SEC: Reject all redirects.  A redirect from TRANSFER_SERVER* to an
            // unrelated host would bypass the same-domain SSRF bind.
            .redirect(redirect::Policy::none())
            // SEC: Disable automatic decompression to prevent decompression-bomb
            // attacks.  A compressed payload could expand to gigabytes without
            // this guard.
            .no_gzip()
            .no_brotli()
            .no_deflate()
            // SEC: Connect timeout limits TCP+TLS handshake.
            .connect_timeout(CONNECT_TIMEOUT)
            // SEC: Request timeout — total round-trip budget.
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|e| AnchorError::AnchorFetchFailed {
                authority_hint: "<reqwest-init>".to_owned(),
                detail: format!("HTTP client construction failed: {e}"),
            })?;
        Ok(Self { inner })
    }

    /// Constructs an [`AnchorClient`] WITHOUT HTTPS enforcement.
    ///
    /// Test-only: omits `.https_only(true)` so a local HTTP test server can be
    /// the target.  All other security settings (redirect blocking, no
    /// decompression, timeouts, body cap) are identical to `new()`.
    /// Production code MUST use `new()`.
    ///
    /// # Errors
    ///
    /// Returns [`AnchorError::AnchorFetchFailed`] if the `reqwest::Client`
    /// cannot be constructed.
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn new_without_https_enforcement() -> Result<Self, AnchorError> {
        let inner = reqwest::Client::builder()
            .redirect(redirect::Policy::none())
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|e| AnchorError::AnchorFetchFailed {
                authority_hint: "<test-reqwest-init>".to_owned(),
                detail: format!("HTTP client construction failed: {e}"),
            })?;
        Ok(Self { inner })
    }

    /// Fetches a URL and returns the response body as a `String`, enforcing
    /// the 64 KiB body cap via streaming.
    ///
    /// The body is read chunk-by-chunk with a running total so the cap is
    /// enforced before any full-buffer allocation.
    ///
    /// The caller is responsible for same-domain SSRF validation (that `url` is
    /// an HTTPS URL on an allowed host) BEFORE calling this method.
    ///
    /// # Errors
    ///
    /// - [`AnchorError::AnchorFetchFailed`] — transport or non-200 error.
    /// - [`AnchorError::HttpStatusError`] — anchor returned non-200 HTTP status.
    /// - [`AnchorError::AnchorResponseDecodeFailed`] — body exceeds cap or is
    ///   not valid UTF-8.
    pub async fn fetch_json_str(
        &self,
        url: &str,
        authority_hint: &str,
    ) -> Result<String, AnchorError> {
        let response =
            self.inner
                .get(url)
                .send()
                .await
                .map_err(|e| AnchorError::AnchorFetchFailed {
                    authority_hint: authority_hint.to_owned(),
                    detail: format!("request failed: {e}"),
                })?;

        let status = response.status();
        if !status.is_success() {
            return Err(AnchorError::HttpStatusError {
                authority_hint: authority_hint.to_owned(),
                status: status.as_u16(),
            });
        }

        read_capped_body(response, authority_hint).await
    }

    /// POSTs a JSON body with a Bearer JWT in the `Authorization` header,
    /// then reads the response body under the 64 KiB cap.
    ///
    /// The body is serialised by reqwest's `json` builder method, which sets
    /// `Content-Type: application/json`.  The Anchor Platform requires this
    /// encoding for the SEP-24 interactive POST; `application/x-www-form-urlencoded`
    /// is rejected with HTTP 500.
    ///
    /// The bearer JWT travels in the `Authorization` header only, never in the
    /// request body (per SEP-24 §4.2).
    ///
    /// # Errors
    ///
    /// Same error variants as `fetch_json_str`.
    pub async fn post_json_with_bearer(
        &self,
        url: &str,
        authority_hint: &str,
        bearer_jwt: &str,
        body: &JsonValue,
    ) -> Result<String, AnchorError> {
        let response = self
            .inner
            .post(url)
            .header("Authorization", format!("Bearer {bearer_jwt}"))
            .json(body)
            .send()
            .await
            .map_err(|e| AnchorError::AnchorFetchFailed {
                authority_hint: authority_hint.to_owned(),
                detail: format!("request failed: {e}"),
            })?;

        let status = response.status();
        if !status.is_success() {
            return Err(AnchorError::HttpStatusError {
                authority_hint: authority_hint.to_owned(),
                status: status.as_u16(),
            });
        }

        read_capped_body(response, authority_hint).await
    }
}

/// Reads the response body chunk-by-chunk, enforcing the 64 KiB cap with a
/// running total before full buffering.
///
/// The cap is checked after each chunk so memory never exceeds
/// `MAX_BODY_BYTES + last_chunk_len` rather than being enforced only after the
/// entire body is buffered.
async fn read_capped_body(
    response: reqwest::Response,
    authority_hint: &str,
) -> Result<String, AnchorError> {
    let mut body: Vec<u8> = Vec::with_capacity(4096.min(MAX_BODY_BYTES));
    let mut stream = response;

    // Stream chunks, accumulating with a running cap check.
    loop {
        match stream.chunk().await {
            Ok(Some(chunk)) => {
                body.extend_from_slice(&chunk);
                if body.len() > MAX_BODY_BYTES {
                    return Err(AnchorError::AnchorResponseDecodeFailed {
                        authority_hint: authority_hint.to_owned(),
                        detail: format!(
                            "response body exceeds 64 KiB cap (> {} bytes)",
                            MAX_BODY_BYTES
                        ),
                    });
                }
            }
            Ok(None) => break,
            Err(e) => {
                return Err(AnchorError::AnchorFetchFailed {
                    authority_hint: authority_hint.to_owned(),
                    detail: format!("body read failed: {e}"),
                });
            }
        }
    }

    String::from_utf8(body).map_err(|_| AnchorError::AnchorResponseDecodeFailed {
        authority_hint: authority_hint.to_owned(),
        detail: "response body is not valid UTF-8".to_owned(),
    })
}

/// Extracts the `scheme://host[:port]` authority from a URL string for
/// use in error messages (redacts path/query/fragment).
///
/// Returns `"<invalid-url>"` when the URL cannot be parsed.
pub(crate) fn authority_hint(url: &str) -> String {
    stellar_agent_network::redact_url_authority(url)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;

    /// `AnchorClient::new()` enforces HTTPS-only at request time.
    ///
    /// Reqwest's `.https_only(true)` rejects any `http://` URL with a "builder
    /// error" before any TCP connection is attempted.  The rejection occurs at
    /// request-construction time, so it fires even when the target host is
    /// unreachable (port 1 is always ECONNREFUSED on loopback).
    ///
    /// This exercises the production constructor body and independently locks in
    /// the transport-level guard.  The assertion checks that the error detail
    /// contains `"builder error"` — the exact string reqwest uses for a
    /// scheme-rejected URL.  Without `.https_only(true)` the client attempts a
    /// TCP connection; port 1 produces ECONNREFUSED whose error message does NOT
    /// contain `"builder error"`, so the assertion fails when the guard is absent.
    #[tokio::test]
    async fn new_rejects_http_url_at_request_time() {
        let client = AnchorClient::new().expect("production client must construct");

        // Port 1 is always ECONNREFUSED.  With https_only(true) the scheme is
        // rejected before any TCP call, so the error is "builder error" regardless
        // of reachability.  Without https_only the error is "tcp connect error:
        // Connection refused", which does NOT match the assertion below.
        let result = client
            .fetch_json_str("http://127.0.0.1:1/info", "127.0.0.1:1")
            .await;

        assert!(
            matches!(result, Err(AnchorError::AnchorFetchFailed { ref detail, .. }) if detail.contains("builder error")),
            "production AnchorClient::new() must reject http:// URLs with \
             AnchorFetchFailed whose detail contains 'builder error' (https_only scheme \
             rejection before TCP); got: {result:?}"
        );
    }
}
