//! SEP-10 v3.4.1 HTTP client: challenge fetch + signed-challenge submit.
//!
//! [`Sep10Client`] wraps `reqwest::Client` and exposes two async operations:
//!
//! - [`Sep10Client::fetch_challenge`] — GET the challenge XDR from the server's
//!   `WEB_AUTH_ENDPOINT`, parse the JSON response, verify the server signing
//!   key, and validate via [`Challenge::parse_and_validate`].
//! - [`Sep10Client::submit_signed_challenge`] — POST the signed XDR to the same
//!   endpoint, parse the `{"token": "<jwt>"}` response, and extract a
//!   [`Sep10Session`] via [`Sep10Session::parse`].
//!
//! Both methods are fail-closed on non-200 HTTP status and on JSON parse failure.
//!
//! # Wire protocol
//!
//! Per SEP-10 v3.4.1:
//!
//! **GET** `<WEB_AUTH_ENDPOINT>?account=<G…>&memo=<u64>&home_domain=<domain>
//! &client_domain=<domain>`
//!
//! Response JSON:
//! ```json
//! { "transaction": "<xdr_b64>", "network_passphrase": "<passphrase>" }
//! ```
//!
//! **POST** `<WEB_AUTH_ENDPOINT>` with `Content-Type: application/json`:
//! ```json
//! { "transaction": "<signed_xdr_b64>" }
//! ```
//!
//! Response JSON:
//! ```json
//! { "token": "<jwt>" }
//! ```
//!
//! # Security model
//!
//! All connections must use HTTPS (TLS-authenticated). The JWT returned by the
//! server is trusted based on the TLS channel integrity — see
//! [`Sep10Session::parse`] for the no-signature-verification rationale.
//!
//! [`Sep10Client::new`] enforces HTTPS-only at the `reqwest` layer via
//! `.https_only(true)`. Any `http://` URL will be rejected by `reqwest` at
//! request time and surfaced as [`Sep10Error::HttpError`].
//! Redirect following is disabled; any 3xx response is surfaced as an HTTP
//! error instead of moving the web-auth request to a different origin.
//!
//! # Timeouts
//!
//! - **Connect timeout: 10 seconds** — limits initial TCP+TLS handshake.
//! - **Request timeout: 30 seconds** — total request budget (defence against
//!   slowloris-style stall attacks).

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Deserialize;

use crate::challenge::Challenge;
use crate::error::Sep10Error;
use crate::session::Sep10Session;

// ─────────────────────────────────────────────────────────────────────────────
// JSON response shape helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Deserialisation target for the GET challenge response per SEP-10 v3.4.1.
#[derive(Debug, Deserialize)]
struct ChallengeResponse {
    /// The base64-encoded `TransactionEnvelope` XDR.
    transaction: String,
    /// The Stellar network passphrase.
    network_passphrase: String,
}

/// Deserialisation target for the POST signed-challenge response per SEP-10 v3.4.1.
#[derive(Debug, Deserialize)]
struct TokenResponse {
    /// The JWT token string.
    token: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// ChallengeRequest
// ─────────────────────────────────────────────────────────────────────────────

/// Parameters for [`Sep10Client::fetch_challenge`].
///
/// All string parameters are `&str` references bound to the lifetime `'a`.
/// Grouping them into a struct prevents silent transposition of the several
/// domain/key fields, which all have the same type.
///
/// # `web_auth_domain`
///
/// When `None`, the expected `web_auth_domain` for challenge validation is
/// derived from the host component of `web_auth_endpoint` (e.g.
/// `"anchor.example.com"`). If the endpoint URL cannot be parsed or has no
/// host, `fetch_challenge` returns
/// [`Sep10Error::InvalidWebAuthEndpoint`] — fail-closed; no fallback.
///
/// # Examples
///
/// ```no_run
/// use stellar_agent_sep10::{Sep10Client, ChallengeRequest};
///
/// # async fn example() -> Result<(), stellar_agent_sep10::Sep10Error> {
/// let client = Sep10Client::new("Test SDF Network ; September 2015")?;
/// let challenge = client.fetch_challenge(ChallengeRequest {
///     web_auth_endpoint: "https://anchor.example.com/auth",
///     account_id: "GABC123",
///     home_domain: "anchor.example.com",
///     server_signing_key: "GCHLHDBOKG2JWMJQBTLSL5XG6NO7ESXI2TAQKZXCXWXB5WI2X6W233PR",
///     memo: None,
///     client_domain: None,
///     web_auth_domain: None,
/// }).await?;
/// # Ok(())
/// # }
/// ```
pub struct ChallengeRequest<'a> {
    /// The `WEB_AUTH_ENDPOINT` URL. Must be an `https://` URL in production
    /// (the client enforces HTTPS-only).
    pub web_auth_endpoint: &'a str,
    /// Stellar account G-key (or M-key) identifying the authenticating
    /// account. Sent as the `account` query parameter.
    pub account_id: &'a str,
    /// Expected `home_domain` value in the challenge's first ManageData
    /// operation key (`"<home_domain> auth"`). Sent as the `home_domain`
    /// query parameter.
    pub home_domain: &'a str,
    /// Expected server signing key G-strkey. The challenge server signature
    /// must verify against this key.
    pub server_signing_key: &'a str,
    /// Optional memo (u64), sent as the `memo` query parameter when `Some`.
    pub memo: Option<u64>,
    /// Optional client domain, sent as the `client_domain` query parameter
    /// when `Some`.
    pub client_domain: Option<&'a str>,
    /// Expected `web_auth_domain` in the challenge's ManageData operation.
    /// When `None`, the host of `web_auth_endpoint` is used; if the endpoint
    /// URL is unparseable or has no host component, `fetch_challenge` returns
    /// [`Sep10Error::InvalidWebAuthEndpoint`].
    pub web_auth_domain: Option<&'a str>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Sep10Client
// ─────────────────────────────────────────────────────────────────────────────

/// Async SEP-10 HTTP client.
///
/// Wraps `reqwest::Client` and exposes the two SEP-10 HTTP operations.
/// HTTPS is enforced at the `reqwest` layer with rustls as the TLS backend.
///
/// # Construction
///
/// ```no_run
/// use stellar_agent_sep10::Sep10Client;
///
/// let client = Sep10Client::new("Test SDF Network ; September 2015")
///     .expect("reqwest client construction failed");
/// ```
pub struct Sep10Client {
    /// Underlying `reqwest` async HTTP client.
    http: reqwest::Client,
    /// Stellar network passphrase for `TransactionSignaturePayload` hashing.
    network_passphrase: String,
}

impl Sep10Client {
    /// Constructs a new [`Sep10Client`] for the given network passphrase.
    ///
    /// Initialises a `reqwest::Client` with the following security settings:
    ///
    /// - **HTTPS-only** (`.https_only(true)`): any `http://` URL is rejected at
    ///   request time. HTTPS is the security boundary for SEP-10: TLS
    ///   authenticates the server and the JWT is trusted via TLS integrity.
    /// - **No redirects** (`Policy::none()`): any 3xx web-auth response is
    ///   returned as a non-success HTTP status rather than followed.
    /// - **Connect timeout: 10 seconds** — limits TCP+TLS handshake duration.
    /// - **Request timeout: 30 seconds** — total request budget; defence against
    ///   slowloris-style stall attacks.
    ///
    /// # Errors
    ///
    /// - [`Sep10Error::HttpError`] if the underlying `reqwest::Client` cannot
    ///   be constructed (extremely rare; indicates system-level TLS init failure).
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use stellar_agent_sep10::Sep10Client;
    ///
    /// let client = Sep10Client::new("Test SDF Network ; September 2015").unwrap();
    /// ```
    pub fn new(network_passphrase: impl Into<String>) -> Result<Self, Sep10Error> {
        let http = reqwest::Client::builder()
            // HTTPS-only enforcement: rejects any http:// URL at request time.
            // HTTPS is the security boundary for SEP-10: the JWT is trusted
            // solely via TLS channel integrity.
            .https_only(true)
            // Do not move a SEP-10 web-auth request to a different origin.
            .redirect(reqwest::redirect::Policy::none())
            // Connect timeout limits TCP+TLS handshake to 10 s.
            .connect_timeout(Duration::from_secs(10))
            // Request timeout: total round-trip budget of 30 s; defence against
            // slowloris-style stall on challenge or submit.
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| Sep10Error::HttpError {
                detail: format!("reqwest client construction failed: {e}"),
            })?;
        Ok(Self {
            http,
            network_passphrase: network_passphrase.into(),
        })
    }

    /// Returns the network passphrase this client was constructed with.
    #[must_use]
    pub fn network_passphrase(&self) -> &str {
        &self.network_passphrase
    }

    /// Constructs a `Sep10Client` for use against a plain-HTTP mock server.
    ///
    /// Omits the `.https_only(true)` constraint so that `http://127.0.0.1:...`
    /// mock server URLs work in tests. All production code must use
    /// [`Sep10Client::new`] which enforces HTTPS.
    ///
    /// Only available under `#[cfg(test)]` or the `test-helpers` feature, so it
    /// is never compiled into a production binary. Exposed under `test-helpers`
    /// so integration-test binaries in dependent crates (which do not receive
    /// `cfg(test)`) can drive the client against a wiremock server.
    ///
    /// # Errors
    ///
    /// - [`Sep10Error::HttpError`] if the underlying `reqwest::Client` cannot
    ///   be constructed.
    ///
    /// # Panics
    ///
    /// Never panics.
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn new_for_unit_test(network_passphrase: impl Into<String>) -> Result<Self, Sep10Error> {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| Sep10Error::HttpError {
                detail: format!("reqwest client construction failed: {e}"),
            })?;
        Ok(Self {
            http,
            network_passphrase: network_passphrase.into(),
        })
    }

    /// Fetches and validates a SEP-10 challenge from the server.
    ///
    /// Issues a GET request to
    /// `<request.web_auth_endpoint>?account=<account_id>&home_domain=<home_domain>`
    /// (plus optional `&memo=<memo>` and `&client_domain=<client_domain>` when
    /// `Some`), then:
    ///
    /// 1. If `request.web_auth_domain` is `None`, derives it from the host of
    ///    `request.web_auth_endpoint` (fail-closed: returns
    ///    [`Sep10Error::InvalidWebAuthEndpoint`] if the URL cannot be parsed or
    ///    has no host).
    /// 2. Parses the JSON response `{ "transaction": "<xdr_b64>",
    ///    "network_passphrase": "<passphrase>" }`.
    /// 3. Verifies the response `network_passphrase` matches the one this client
    ///    was constructed with (fail-closed on mismatch).
    /// 4. Calls [`Challenge::parse_and_validate`] with the derived
    ///    `web_auth_domain`, `request.server_signing_key`, and `now_unix` from
    ///    `std::time::SystemTime::now()`.
    ///
    /// Per SEP-10 v3.4.1.
    ///
    /// # Errors
    ///
    /// - [`Sep10Error::InvalidWebAuthEndpoint`] if `request.web_auth_domain`
    ///   is `None` and the endpoint URL cannot be parsed or has no host.
    /// - [`Sep10Error::HttpError`] on network failure or non-200 HTTP status.
    /// - [`Sep10Error::JwtParseError`] if the response is not valid JSON or
    ///   the expected `transaction` / `network_passphrase` fields are absent.
    /// - Any [`Sep10Error`] variant from [`Challenge::parse_and_validate`] on
    ///   challenge validation failure.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub async fn fetch_challenge(
        &self,
        request: ChallengeRequest<'_>,
    ) -> Result<Challenge, Sep10Error> {
        let web_auth_endpoint = request.web_auth_endpoint;

        // Resolve web_auth_domain up front (before any network I/O) so a
        // bad endpoint is rejected fast and the check is purely offline.
        let derived_domain;
        let expected_web_auth_domain: &str = match request.web_auth_domain {
            Some(d) => d,
            None => {
                derived_domain = reqwest::Url::parse(web_auth_endpoint)
                    .ok()
                    .and_then(|u| u.host_str().map(str::to_owned))
                    .ok_or_else(|| Sep10Error::InvalidWebAuthEndpoint {
                        detail: format!(
                            "cannot derive web_auth_domain: endpoint \
                             {:?} has no parseable host; pass web_auth_domain \
                             explicitly",
                            web_auth_endpoint
                        ),
                    })?;
                &derived_domain
            }
        };

        let mut params: Vec<(&str, String)> = vec![
            ("account", request.account_id.to_owned()),
            ("home_domain", request.home_domain.to_owned()),
        ];
        if let Some(m) = request.memo {
            params.push(("memo", m.to_string()));
        }
        if let Some(cd) = request.client_domain {
            params.push(("client_domain", cd.to_owned()));
        }

        let response = self
            .http
            .get(web_auth_endpoint)
            .query(&params)
            .send()
            .await
            .map_err(|e| Sep10Error::HttpError {
                detail: format!("GET {web_auth_endpoint}: {e}"),
            })?;

        let status = response.status();
        if !status.is_success() {
            // char-boundary-safe truncation: use .chars().take(512) rather than
            // &body[..512] to avoid a panic at a multi-byte UTF-8 char boundary
            // when a server-controlled error body has a multi-byte sequence at
            // byte 512.
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<unreadable>".to_owned());
            let truncated = if body.chars().count() > 512 {
                format!("{}…", body.chars().take(512).collect::<String>())
            } else {
                body
            };
            return Err(Sep10Error::HttpError {
                detail: format!("GET {web_auth_endpoint} returned HTTP {status}: {truncated}"),
            });
        }

        let challenge_response: ChallengeResponse =
            response
                .json()
                .await
                .map_err(|e| Sep10Error::JwtParseError {
                    detail: format!("GET {web_auth_endpoint}: failed to parse JSON response: {e}"),
                })?;

        if challenge_response.network_passphrase != self.network_passphrase {
            return Err(Sep10Error::InvalidServerSignature {
                detail: format!(
                    "server returned network_passphrase {:?} but client expected {:?}",
                    // Truncate to first 16 chars: sufficient for diagnosis without
                    // echoing the full passphrase in error detail.
                    &challenge_response.network_passphrase
                        [..challenge_response.network_passphrase.len().min(16)],
                    &self.network_passphrase[..self.network_passphrase.len().min(16)],
                ),
            });
        }

        let now_unix = system_time_unix_secs()?;

        Challenge::parse_and_validate(
            &challenge_response.transaction,
            &self.network_passphrase,
            request.home_domain,
            expected_web_auth_domain,
            request.server_signing_key,
            now_unix,
        )
    }

    /// Submits a signed challenge XDR to the SEP-10 server and returns the JWT
    /// session.
    ///
    /// Issues a POST request to `<web_auth_endpoint>` with
    /// `Content-Type: application/json` and body `{"transaction": "<signed_xdr>"}`,
    /// then parses the `{"token": "<jwt>"}` response via [`Sep10Session::parse`].
    ///
    /// Per SEP-10 v3.4.1.
    ///
    /// # Errors
    ///
    /// - [`Sep10Error::HttpError`] on network failure or non-200 HTTP status.
    /// - [`Sep10Error::JwtParseError`] if the response JSON cannot be parsed or
    ///   the `token` field is absent or empty.
    /// - Any [`Sep10Error`] variant from [`Sep10Session::parse`] if the JWT is
    ///   malformed.
    /// - [`Sep10Error::JwtExpired`] if the received JWT is already expired.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub async fn submit_signed_challenge(
        &self,
        web_auth_endpoint: &str,
        signed_xdr: &str,
    ) -> Result<Sep10Session, Sep10Error> {
        let mut body = HashMap::new();
        body.insert("transaction", signed_xdr);

        let response = self
            .http
            .post(web_auth_endpoint)
            .json(&body)
            .send()
            .await
            .map_err(|e| Sep10Error::HttpError {
                detail: format!("POST {web_auth_endpoint}: {e}"),
            })?;

        let status = response.status();
        if !status.is_success() {
            // char-boundary-safe truncation (see fetch_challenge).
            let body_text = response
                .text()
                .await
                .unwrap_or_else(|_| "<unreadable>".to_owned());
            let truncated = if body_text.chars().count() > 512 {
                format!("{}…", body_text.chars().take(512).collect::<String>())
            } else {
                body_text
            };
            return Err(Sep10Error::HttpError {
                detail: format!("POST {web_auth_endpoint} returned HTTP {status}: {truncated}"),
            });
        }

        let token_response: TokenResponse =
            response
                .json()
                .await
                .map_err(|e| Sep10Error::JwtParseError {
                    detail: format!("POST {web_auth_endpoint}: failed to parse JSON response: {e}"),
                })?;

        if token_response.token.is_empty() {
            return Err(Sep10Error::JwtParseError {
                detail: format!("POST {web_auth_endpoint}: response 'token' field is empty"),
            });
        }

        let session = Sep10Session::parse(&token_response.token)?;
        let now_unix = system_time_unix_secs()?;
        if session.is_expired(now_unix) {
            return Err(Sep10Error::JwtExpired {
                exp_unix: session.exp,
                now_unix,
            });
        }

        Ok(session)
    }
}

impl std::fmt::Debug for Sep10Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sep10Client")
            .field(
                "network_passphrase",
                // Truncate to avoid emitting full passphrase in debug output.
                &&self.network_passphrase[..self.network_passphrase.len().min(16)],
            )
            .finish()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: system clock → Unix seconds
// ─────────────────────────────────────────────────────────────────────────────

/// Returns the current system time as Unix seconds.
///
/// # Errors
///
/// - [`Sep10Error::HttpError`] if `SystemTime::now()` predates the Unix epoch
///   (impossible on any real OS; included for type completeness).
fn system_time_unix_secs() -> Result<u64, Sep10Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| Sep10Error::HttpError {
            detail: format!("system clock is before UNIX epoch: {e}"),
        })
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
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde_json::json;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // Convenience helper to build a ChallengeRequest for tests that only care
    // about the endpoint and want standard placeholder values for everything else.
    fn simple_request<'a>(
        endpoint: &'a str,
        web_auth_domain: Option<&'a str>,
    ) -> ChallengeRequest<'a> {
        ChallengeRequest {
            web_auth_endpoint: endpoint,
            account_id: "GABC",
            home_domain: "example.com",
            server_signing_key: PLACEHOLDER_SERVER_KEY,
            memo: None,
            client_domain: None,
            web_auth_domain,
        }
    }

    const TEST_PASSPHRASE: &str = "Test SDF Network ; September 2015";
    // A valid G-strkey used as a placeholder server signing key in tests where
    // the check fires before the server-key verification step.
    const PLACEHOLDER_SERVER_KEY: &str = "GCHLHDBOKG2JWMJQBTLSL5XG6NO7ESXI2TAQKZXCXWXB5WI2X6W233PR";

    // ── Constructor ───────────────────────────────────────────────────────────

    #[test]
    fn constructor_stores_passphrase() {
        let client = Sep10Client::new(TEST_PASSPHRASE).unwrap();
        assert_eq!(client.network_passphrase(), TEST_PASSPHRASE);
    }

    #[test]
    fn debug_does_not_echo_full_passphrase() {
        let client = Sep10Client::new(TEST_PASSPHRASE).unwrap();
        let debug = format!("{client:?}");
        assert!(!debug.contains(TEST_PASSPHRASE));
        assert!(debug.contains("Test SDF Network"));
    }

    // ── HTTPS-only enforcement ────────────────────────────────────────────────

    /// Verifies that the production `Sep10Client::new` constructor rejects
    /// plain `http://` URLs at request time.
    #[tokio::test]
    async fn https_only_enforcement_rejects_http_url() {
        let client = Sep10Client::new(TEST_PASSPHRASE).unwrap();
        let err = client
            .fetch_challenge(simple_request(
                "http://example.com/auth",
                Some("example.com"),
            ))
            .await
            .unwrap_err();
        assert!(
            matches!(err, Sep10Error::HttpError { .. }),
            "http:// URL must produce Sep10Error::HttpError via https_only; got {err:?}"
        );
    }

    // ── web_auth_domain derivation ────────────────────────────────────────────

    /// When `web_auth_domain` is `None` and the endpoint URL cannot be parsed
    /// or has no host, `fetch_challenge` must return `InvalidWebAuthEndpoint`
    /// before issuing any network request (fail-closed, testable offline).
    #[tokio::test]
    async fn fetch_challenge_rejects_hostless_endpoint_when_web_auth_domain_none() {
        // "not a url" has no parseable host. Because we pass web_auth_domain:
        // None, derivation must fail-closed with InvalidWebAuthEndpoint.
        let client = Sep10Client::new_for_unit_test(TEST_PASSPHRASE).unwrap();
        let err = client
            .fetch_challenge(simple_request("not-a-url", None))
            .await
            .unwrap_err();
        assert!(
            matches!(err, Sep10Error::InvalidWebAuthEndpoint { .. }),
            "expected InvalidWebAuthEndpoint for hostless endpoint + None web_auth_domain; \
             got {err:?}"
        );
        assert_eq!(err.wire_code(), "sep10.invalid_web_auth_endpoint");
    }

    // ── HTTP error mapping ────────────────────────────────────────────────────

    #[tokio::test]
    async fn fetch_challenge_maps_http_401_to_http_error() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/auth"))
            .respond_with(ResponseTemplate::new(401).set_body_string(r#"{"error":"unauthorized"}"#))
            .mount(&mock_server)
            .await;

        let client = Sep10Client::new_for_unit_test(TEST_PASSPHRASE).unwrap();
        let endpoint = format!("{}/auth", mock_server.uri());
        let err = client
            .fetch_challenge(simple_request(&endpoint, Some("example.com")))
            .await
            .unwrap_err();
        assert!(
            matches!(err, Sep10Error::HttpError { .. }),
            "expected HttpError for 401, got {err:?}"
        );
        assert_eq!(err.wire_code(), "sep10.http_error");
    }

    #[tokio::test]
    async fn fetch_challenge_does_not_follow_redirects() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/auth"))
            .respond_with(ResponseTemplate::new(302).insert_header("location", "/redirected"))
            .mount(&mock_server)
            .await;

        let client = Sep10Client::new_for_unit_test(TEST_PASSPHRASE).unwrap();
        let endpoint = format!("{}/auth", mock_server.uri());
        let err = client
            .fetch_challenge(simple_request(&endpoint, Some("example.com")))
            .await
            .unwrap_err();

        assert!(
            matches!(err, Sep10Error::HttpError { ref detail } if detail.contains("302")),
            "expected no-follow redirect to surface as 302 HttpError, got {err:?}"
        );
    }

    #[tokio::test]
    async fn submit_signed_challenge_maps_http_400_to_http_error() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/auth"))
            .respond_with(ResponseTemplate::new(400).set_body_string(r#"{"error":"bad request"}"#))
            .mount(&mock_server)
            .await;

        let client = Sep10Client::new_for_unit_test(TEST_PASSPHRASE).unwrap();
        let endpoint = format!("{}/auth", mock_server.uri());
        let err = client
            .submit_signed_challenge(&endpoint, "FAKEXDR")
            .await
            .unwrap_err();
        assert!(
            matches!(err, Sep10Error::HttpError { .. }),
            "expected HttpError for 400, got {err:?}"
        );
    }

    // ── Malformed JSON response ───────────────────────────────────────────────

    #[tokio::test]
    async fn fetch_challenge_rejects_malformed_json_response() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/auth"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not-json-at-all"))
            .mount(&mock_server)
            .await;

        let client = Sep10Client::new_for_unit_test(TEST_PASSPHRASE).unwrap();
        let endpoint = format!("{}/auth", mock_server.uri());
        let err = client
            .fetch_challenge(simple_request(&endpoint, Some("example.com")))
            .await
            .unwrap_err();
        assert!(
            matches!(err, Sep10Error::JwtParseError { .. }),
            "expected JwtParseError for malformed JSON, got {err:?}"
        );
    }

    #[tokio::test]
    async fn submit_signed_challenge_rejects_missing_token_field() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/auth"))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"not_a_token":"value"}"#))
            .mount(&mock_server)
            .await;

        let client = Sep10Client::new_for_unit_test(TEST_PASSPHRASE).unwrap();
        let endpoint = format!("{}/auth", mock_server.uri());
        let err = client
            .submit_signed_challenge(&endpoint, "FAKEXDR")
            .await
            .unwrap_err();
        assert!(
            matches!(err, Sep10Error::JwtParseError { .. }),
            "expected JwtParseError for missing token field, got {err:?}"
        );
    }

    #[tokio::test]
    async fn submit_signed_challenge_does_not_follow_redirects() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/auth"))
            .respond_with(ResponseTemplate::new(302).insert_header("location", "/redirected"))
            .mount(&mock_server)
            .await;

        let client = Sep10Client::new_for_unit_test(TEST_PASSPHRASE).unwrap();
        let endpoint = format!("{}/auth", mock_server.uri());
        let err = client
            .submit_signed_challenge(&endpoint, "FAKEXDR")
            .await
            .unwrap_err();

        assert!(
            matches!(err, Sep10Error::HttpError { ref detail } if detail.contains("302")),
            "expected no-follow redirect to surface as 302 HttpError, got {err:?}"
        );
    }

    #[tokio::test]
    async fn submit_signed_challenge_rejects_expired_jwt() {
        let mock_server = MockServer::start().await;
        let token = build_test_jwt("GABC", 1);
        Mock::given(method("POST"))
            .and(path("/auth"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "token": token })))
            .mount(&mock_server)
            .await;

        let client = Sep10Client::new_for_unit_test(TEST_PASSPHRASE).unwrap();
        let endpoint = format!("{}/auth", mock_server.uri());
        let err = client
            .submit_signed_challenge(&endpoint, "FAKEXDR")
            .await
            .unwrap_err();

        assert!(
            matches!(err, Sep10Error::JwtExpired { exp_unix: 1, now_unix } if now_unix > 1),
            "expected expired JWT rejection, got {err:?}"
        );
    }

    // ── Query-param URL encoding ──────────────────────────────────────────────

    #[tokio::test]
    async fn fetch_challenge_encodes_optional_memo_and_client_domain() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/auth"))
            .and(query_param("account", "GABCDEF"))
            .and(query_param("home_domain", "example.com"))
            .and(query_param("memo", "12345"))
            .and(query_param("client_domain", "wallet.example.com"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(r#"{"transaction":"bad_xdr","network_passphrase":"Test SDF Network ; September 2015"}"#),
            )
            .mount(&mock_server)
            .await;

        let client = Sep10Client::new_for_unit_test(TEST_PASSPHRASE).unwrap();
        let endpoint = format!("{}/auth", mock_server.uri());
        // This will fail at challenge validation (bad XDR), but we only need
        // to verify the HTTP request was formed correctly — the mock server
        // will only match if all four query params are present.
        let result = client
            .fetch_challenge(ChallengeRequest {
                web_auth_endpoint: &endpoint,
                account_id: "GABCDEF",
                home_domain: "example.com",
                server_signing_key: PLACEHOLDER_SERVER_KEY,
                memo: Some(12345),
                client_domain: Some("wallet.example.com"),
                web_auth_domain: Some("example.com"),
            })
            .await;
        // The mock matched (no 404/500) — that proves query params were correct.
        // The result is an error because "bad_xdr" fails XDR decode, which is fine.
        assert!(result.is_err());
        assert!(
            !matches!(result.as_ref().unwrap_err(), Sep10Error::HttpError { detail }
                if detail.contains("404")),
            "got unexpected 404; mock query param matching failed: {result:?}"
        );
    }

    #[tokio::test]
    async fn fetch_challenge_omits_optional_params_when_none() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/auth"))
            .and(query_param("account", "GABC"))
            .and(query_param("home_domain", "example.com"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(r#"{"transaction":"bad_xdr","network_passphrase":"Test SDF Network ; September 2015"}"#),
            )
            .mount(&mock_server)
            .await;

        let client = Sep10Client::new_for_unit_test(TEST_PASSPHRASE).unwrap();
        let endpoint = format!("{}/auth", mock_server.uri());
        let result = client
            .fetch_challenge(simple_request(&endpoint, Some("example.com")))
            .await;
        assert!(result.is_err());
        assert!(
            !matches!(result.as_ref().unwrap_err(), Sep10Error::HttpError { detail }
                if detail.contains("404")),
            "mock did not match: {result:?}"
        );
    }

    // ── Network passphrase mismatch ───────────────────────────────────────────

    #[tokio::test]
    async fn fetch_challenge_rejects_wrong_network_passphrase() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/auth"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(
                        r#"{"transaction":"bad_xdr","network_passphrase":"Public Global Stellar Network ; September 2015"}"#,
                    ),
            )
            .mount(&mock_server)
            .await;

        let client = Sep10Client::new_for_unit_test(TEST_PASSPHRASE).unwrap();
        let endpoint = format!("{}/auth", mock_server.uri());
        let err = client
            .fetch_challenge(simple_request(&endpoint, Some("example.com")))
            .await
            .unwrap_err();
        assert!(
            matches!(err, Sep10Error::InvalidServerSignature { .. }),
            "expected InvalidServerSignature for passphrase mismatch, got {err:?}"
        );
    }

    fn build_test_jwt(sub: &str, exp: u64) -> String {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#);
        let payload = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({
                "sub": sub,
                "iss": "https://anchor.example.com",
                "iat": 0,
                "exp": exp
            }))
            .unwrap(),
        );
        format!("{header}.{payload}.")
    }
}
