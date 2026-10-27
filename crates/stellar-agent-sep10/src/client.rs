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
//! # Error texts
//!
//! A transport failure, a non-2xx answer, or an answer that is not SEP-10 JSON
//! is reported by method and class, without the endpoint URL, its query, or
//! the answer body. A challenge that fails validation or a token whose claims
//! do not parse can name a decoded field; a caller that relays these texts
//! bounds them. A network passphrase appears only as its class: the testnet or
//! mainnet passphrase, or `<other network>`.
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
use stellar_agent_core::profile::caip2::{MAINNET_PASSPHRASE, TESTNET_PASSPHRASE};

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
                derived_domain = web_auth_domain_for_endpoint(web_auth_endpoint)?;
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
            .map_err(|e| transport_failure("GET", e))?;

        let status = response.status();
        if !status.is_success() {
            // The body of a refused answer is the server's text and is not
            // read; the method and the status are enough to triage.
            return Err(Sep10Error::HttpError {
                detail: format!("GET returned HTTP {}", status.as_u16()),
            });
        }

        let challenge_response: ChallengeResponse =
            response
                .json()
                .await
                .map_err(|_| Sep10Error::JwtParseError {
                    detail: "challenge answer is not SEP-10 JSON".to_owned(),
                })?;

        if challenge_response.network_passphrase != self.network_passphrase {
            return Err(Sep10Error::InvalidServerSignature {
                detail: format!(
                    "server returned network passphrase '{}' but the client expects '{}'",
                    passphrase_class(&challenge_response.network_passphrase),
                    passphrase_class(&self.network_passphrase),
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
            .map_err(|e| transport_failure("POST", e))?;

        let status = response.status();
        if !status.is_success() {
            // The body of a refused answer is not read (see fetch_challenge).
            return Err(Sep10Error::HttpError {
                detail: format!("POST returned HTTP {}", status.as_u16()),
            });
        }

        let token_response: TokenResponse =
            response
                .json()
                .await
                .map_err(|_| Sep10Error::JwtParseError {
                    detail: "token answer is not SEP-10 JSON".to_owned(),
                })?;

        if token_response.token.is_empty() {
            return Err(Sep10Error::JwtParseError {
                detail: "token answer has an empty token".to_owned(),
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
                &passphrase_class(&self.network_passphrase),
            )
            .finish()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Web auth domain
// ─────────────────────────────────────────────────────────────────────────────

/// The web auth domain a challenge from `web_auth_endpoint` must name: the
/// endpoint URL's host, without scheme, port or path.
///
/// [`Sep10Client::fetch_challenge`] applies this rule when the request names
/// no web auth domain.
///
/// # Errors
///
/// [`Sep10Error::InvalidWebAuthEndpoint`] when `web_auth_endpoint` is not a
/// URL or has no host.
///
/// # Examples
///
/// ```
/// use stellar_agent_sep10::client::web_auth_domain_for_endpoint;
///
/// assert_eq!(
///     web_auth_domain_for_endpoint("https://auth.example.com:8443/auth").unwrap(),
///     "auth.example.com"
/// );
/// assert!(web_auth_domain_for_endpoint("not-a-url").is_err());
/// ```
pub fn web_auth_domain_for_endpoint(web_auth_endpoint: &str) -> Result<String, Sep10Error> {
    reqwest::Url::parse(web_auth_endpoint)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
        .ok_or_else(|| Sep10Error::InvalidWebAuthEndpoint {
            detail: format!(
                "cannot derive web_auth_domain: endpoint \
                 {:?} has no parseable host; pass web_auth_domain \
                 explicitly",
                web_auth_endpoint
            ),
        })
}

// ─────────────────────────────────────────────────────────────────────────────
// Error-text helpers
// ─────────────────────────────────────────────────────────────────────────────

/// The class of a network passphrase for an error or `Debug` text.
///
/// The two public passphrases render verbatim, so an operator can read a
/// mismatch directly; any other value, whether a private network's or one a
/// server chose, renders as `<other network>`.
fn passphrase_class(passphrase: &str) -> &'static str {
    match passphrase {
        TESTNET_PASSPHRASE => TESTNET_PASSPHRASE,
        MAINNET_PASSPHRASE => MAINNET_PASSPHRASE,
        _ => "<other network>",
    }
}

/// The [`Sep10Error::HttpError`] for a request with `method` that failed
/// before an answer arrived.
///
/// The detail names the method and a fixed class: a timeout, a failed
/// connection, or the transport's error kind. The URL the transport would
/// append is removed first, so neither the endpoint's path nor its query (the
/// account and the home domain) reaches the text.
fn transport_failure(method: &str, error: reqwest::Error) -> Sep10Error {
    let detail = if error.is_timeout() {
        format!("{method} request timed out")
    } else if error.is_connect() {
        format!("{method} connection failed")
    } else {
        format!("{method} request failed: {}", error.without_url())
    };
    Sep10Error::HttpError { detail }
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
        clippy::panic,
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

    /// `Debug` renders a private passphrase as its class and never the value;
    /// a public passphrase renders verbatim.
    #[test]
    fn debug_does_not_echo_full_passphrase() {
        const PRIVATE: &str = "Operator Private Chain ; March 2026";
        let client = Sep10Client::new(PRIVATE).unwrap();
        let debug = format!("{client:?}");
        assert!(!debug.contains(PRIVATE), "{debug}");
        assert!(!debug.contains("Operator"), "{debug}");
        assert!(debug.contains("<other network>"), "{debug}");

        let client = Sep10Client::new(TEST_PASSPHRASE).unwrap();
        let debug = format!("{client:?}");
        assert!(debug.contains(TEST_PASSPHRASE), "{debug}");
    }

    /// The class names the two public passphrases verbatim and nothing else.
    #[test]
    fn passphrase_class_names_only_the_two_public_networks() {
        assert_eq!(TESTNET_PASSPHRASE, "Test SDF Network ; September 2015");
        assert_eq!(
            MAINNET_PASSPHRASE,
            "Public Global Stellar Network ; September 2015"
        );
        assert_eq!(
            passphrase_class("Test SDF Network ; September 2015"),
            "Test SDF Network ; September 2015"
        );
        assert_eq!(
            passphrase_class("Public Global Stellar Network ; September 2015"),
            "Public Global Stellar Network ; September 2015"
        );
        for other in [
            "",
            "Test SDF Future Network ; October 2022",
            "Test SDF Network ; September 2015 ",
            "aaaaaaaaaaaaaaa\u{20ac}x",
        ] {
            assert_eq!(passphrase_class(other), "<other network>", "{other:?}");
        }
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

    /// The web auth domain is the endpoint's host without its port; an
    /// endpoint without a host refuses.
    #[test]
    fn web_auth_domain_is_the_endpoint_host() {
        assert_eq!(
            web_auth_domain_for_endpoint("http://127.0.0.1:41234/auth").unwrap(),
            "127.0.0.1"
        );
        assert_eq!(
            web_auth_domain_for_endpoint("https://auth.example.com:8443/auth").unwrap(),
            "auth.example.com"
        );
        for endpoint in ["not-a-url", "data:text/plain,challenge"] {
            let err = web_auth_domain_for_endpoint(endpoint).unwrap_err();
            assert!(
                matches!(err, Sep10Error::InvalidWebAuthEndpoint { .. }),
                "{endpoint}: {err:?}"
            );
        }
    }

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

    /// A refused challenge request reports the method and the status; the
    /// answer body, the endpoint path, and the query stay out of the detail.
    #[tokio::test]
    async fn fetch_challenge_non_2xx_reports_method_and_status_only() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/auth/QPATHSECRET"))
            .respond_with(
                ResponseTemplate::new(503)
                    .set_body_string("BODYSECRET https://user:pw@leak.example/x \u{1b}[2J"),
            )
            .mount(&mock_server)
            .await;

        let client = Sep10Client::new_for_unit_test(TEST_PASSPHRASE).unwrap();
        let endpoint = format!("{}/auth/QPATHSECRET?tok=QSECRET", mock_server.uri());
        let err = client
            .fetch_challenge(simple_request(&endpoint, Some("example.com")))
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                Sep10Error::HttpError { ref detail } if detail == "GET returned HTTP 503"
            ),
            "{err:?}"
        );
    }

    /// A refused token request reports the method and the status only.
    #[tokio::test]
    async fn submit_non_2xx_reports_method_and_status_only() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/auth/QPATHSECRET"))
            .respond_with(ResponseTemplate::new(401).set_body_string("BODYSECRET"))
            .mount(&mock_server)
            .await;

        let client = Sep10Client::new_for_unit_test(TEST_PASSPHRASE).unwrap();
        let endpoint = format!("{}/auth/QPATHSECRET?tok=QSECRET", mock_server.uri());
        let err = client
            .submit_signed_challenge(&endpoint, "FAKEXDR")
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                Sep10Error::HttpError { ref detail } if detail == "POST returned HTTP 401"
            ),
            "{err:?}"
        );
    }

    /// The detail of an error that carries an HTTP status, which a closed
    /// port cannot produce: the port was taken by another listener between
    /// its release and the request.
    fn answered_with_a_status(err: &Sep10Error) -> Option<&str> {
        match err {
            Sep10Error::HttpError { detail } if detail.contains(" returned HTTP ") => Some(detail),
            _ => None,
        }
    }

    /// A request to a closed loopback port reports the method and the
    /// connection class; neither the endpoint's host, path, or query nor the
    /// account parameter reaches the detail.
    ///
    /// The port is released before the request, so a server of a parallel
    /// test can take it; an answer with an HTTP status then gets a fresh
    /// port, at most three attempts in all.
    #[tokio::test]
    async fn transport_failure_detail_names_the_class_and_no_url() {
        const ATTEMPTS: usize = 3;
        let client = Sep10Client::new_for_unit_test(TEST_PASSPHRASE).unwrap();
        let mut answered = Vec::new();
        let mut refused = None;
        for _ in 0..ATTEMPTS {
            let port = {
                let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                listener.local_addr().unwrap().port()
            };
            let endpoint = format!("http://127.0.0.1:{port}/auth/QPATHSECRET?tok=QSECRET");
            let fetch = client
                .fetch_challenge(simple_request(&endpoint, Some("example.com")))
                .await
                .unwrap_err();
            let submit = client
                .submit_signed_challenge(&endpoint, "FAKEXDR")
                .await
                .unwrap_err();
            let statuses: Vec<String> = [&fetch, &submit]
                .into_iter()
                .filter_map(|err| answered_with_a_status(err).map(str::to_owned))
                .collect();
            if statuses.is_empty() {
                refused = Some((fetch, submit));
                break;
            }
            answered.extend(statuses);
        }
        let Some((fetch, submit)) = refused else {
            panic!("every one of {ATTEMPTS} closed ports answered with a status: {answered:?}");
        };

        for (err, expected) in [
            (fetch, "GET connection failed"),
            (submit, "POST connection failed"),
        ] {
            let Sep10Error::HttpError { ref detail } = err else {
                panic!("expected HttpError, got {err:?}");
            };
            assert_eq!(detail, expected);
            let rendered = format!("{err} {err:?}");
            for leaked in [
                "QPATHSECRET",
                "QSECRET",
                "account=",
                "GABC",
                "127.0.0.1",
                "/auth",
            ] {
                assert!(!rendered.contains(leaked), "{leaked}: {rendered}");
            }
        }
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
            matches!(
                err,
                Sep10Error::JwtParseError { ref detail }
                    if detail == "challenge answer is not SEP-10 JSON"
            ),
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
            matches!(
                err,
                Sep10Error::JwtParseError { ref detail }
                    if detail == "token answer is not SEP-10 JSON"
            ),
            "expected JwtParseError for missing token field, got {err:?}"
        );
    }

    #[tokio::test]
    async fn submit_signed_challenge_rejects_an_empty_token() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/auth"))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"token":""}"#))
            .mount(&mock_server)
            .await;

        let client = Sep10Client::new_for_unit_test(TEST_PASSPHRASE).unwrap();
        let endpoint = format!("{}/auth", mock_server.uri());
        let err = client
            .submit_signed_challenge(&endpoint, "FAKEXDR")
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                Sep10Error::JwtParseError { ref detail }
                    if detail == "token answer has an empty token"
            ),
            "{err:?}"
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
            matches!(
                err,
                Sep10Error::InvalidServerSignature { ref detail }
                    if detail == "server returned network passphrase \
                                  'Public Global Stellar Network ; September 2015' but the \
                                  client expects 'Test SDF Network ; September 2015'"
            ),
            "expected InvalidServerSignature for passphrase mismatch, got {err:?}"
        );
    }

    /// A server passphrase with a multi-byte character across byte 16 renders
    /// as its class and does not panic.
    #[tokio::test]
    async fn a_multibyte_server_passphrase_renders_the_class() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/auth"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "transaction": "bad_xdr",
                "network_passphrase": "aaaaaaaaaaaaaaa\u{20ac}x",
            })))
            .mount(&mock_server)
            .await;

        let client = Sep10Client::new_for_unit_test(TEST_PASSPHRASE).unwrap();
        let endpoint = format!("{}/auth", mock_server.uri());
        let err = client
            .fetch_challenge(simple_request(&endpoint, Some("example.com")))
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                Sep10Error::InvalidServerSignature { ref detail }
                    if detail == "server returned network passphrase '<other network>' \
                                  but the client expects 'Test SDF Network ; September 2015'"
            ),
            "{err:?}"
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
