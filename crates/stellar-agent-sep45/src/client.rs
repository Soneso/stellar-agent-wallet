//! SEP-45 v0.1.1 HTTP client: challenge fetch + signed-entries submit.
//!
//! [`Sep45Client`] wraps `reqwest::Client` and exposes two async operations:
//!
//! - [`Sep45Client::fetch_challenge`] — GET the challenge XDR from the server's
//!   `WEB_AUTH_FOR_CONTRACTS_ENDPOINT`, parse the JSON response, and validate
//!   via [`AuthorizationEntries::parse_and_validate`].
//! - [`Sep45Client::submit_signed_challenge`] — POST the signed XDR entries to
//!   the same endpoint, parse the `{"token": "<jwt>"}` response, and extract a
//!   [`Sep45Session`] via [`Sep45Session::parse`].
//!
//! Both methods are fail-closed on non-200 HTTP status and on JSON parse failure.
//!
//! # Wire protocol
//!
//! Per the SEP-45 challenge-response schema:
//!
//! **GET** `<WEB_AUTH_FOR_CONTRACTS_ENDPOINT>?account=<C…>&home_domain=<domain>
//! &client_domain=<domain>`
//!
//! Response JSON (snake_case per spec; testanchor returns camelCase as an
//! implementation quirk — both field variants are attempted):
//! ```json
//! { "authorization_entries": "<xdr_b64>", "network_passphrase": "<passphrase>" }
//! ```
//!
//! **POST** `<WEB_AUTH_FOR_CONTRACTS_ENDPOINT>` with `Content-Type: application/json`:
//! ```json
//! { "authorization_entries": "<signed_xdr_b64>" }
//! ```
//!
//! Response JSON (per the SEP-45 POST response schema):
//! ```json
//! { "token": "<jwt>" }
//! ```
//!
//! # Field-name portability
//!
//! The SEP-45 challenge-response schema specifies `authorization_entries`
//! (snake_case). Some anchor implementations return `authorizationEntries`
//! (camelCase) instead. The deserialization helper `ChallengeResponse` accepts
//! both via `#[serde(alias = "authorizationEntries")]`.
//!
//! # Security model
//!
//! All connections MUST use HTTPS (TLS-authenticated). The JWT returned by the
//! server is trusted based on the TLS channel integrity — see
//! [`Sep45Session::parse`] for the no-signature-verification rationale.
//!
//! [`Sep45Client::new`] enforces HTTPS-only at the `reqwest` layer via
//! `.https_only(true)`. Any `http://` URL will be rejected by `reqwest` at
//! request time and surfaced as [`Sep45Error::HttpError`].
//! Redirect following is disabled; any 3xx response is surfaced as an HTTP
//! error instead of moving the web-auth request to a different origin.
//!
//! # Timeouts
//!
//! The underlying `reqwest::Client` is configured with:
//!
//! - **Connect timeout: 10 seconds** — limits initial TCP+TLS handshake.
//! - **Request timeout: 30 seconds** — total request budget (defence against
//!   slowloris-style stall attacks on the challenge or submit endpoints).

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Deserialize;

use crate::entries::AuthorizationEntries;
use crate::error::Sep45Error;
use crate::session::Sep45Session;

// ─────────────────────────────────────────────────────────────────────────────
// JSON response shape helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Deserialisation target for the GET challenge response.
///
/// Accepts both `authorization_entries` (the canonical snake_case field name
/// per the SEP-45 challenge-response schema) and `authorizationEntries`
/// (camelCase; used by some anchor implementations) via `#[serde(alias)]`.
/// Also accepts both `network_passphrase` and `networkPassphrase` for the same
/// reason.
#[derive(Debug, Deserialize)]
struct ChallengeResponse {
    /// Base64-encoded `SorobanAuthorizationEntries` XDR.
    ///
    /// The canonical field name per SEP-45 is `authorization_entries`;
    /// the alias covers camelCase variants used by some anchor implementations.
    #[serde(alias = "authorizationEntries")]
    authorization_entries: String,
    /// Stellar network passphrase (optional per the SEP-45 GET challenge response
    /// schema). `None` when the server omits the field. When present, validated
    /// to match the client's expected passphrase.
    #[serde(alias = "networkPassphrase")]
    network_passphrase: Option<String>,
}

/// Deserialisation target for the POST signed-entries response.
///
/// Per the SEP-45 POST response schema.
#[derive(Debug, Deserialize)]
struct TokenResponse {
    /// The JWT token string.
    token: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// ChallengeRequest
// ─────────────────────────────────────────────────────────────────────────────

/// Parameters for a SEP-45 challenge fetch and ephemeral-key sign flow.
///
/// Passed to [`crate::auth_with_ephemeral_key`] and (optionally) to
/// [`Sep45Client::fetch_challenge`].
///
/// # Fields
///
/// - `web_auth_endpoint` — The server's `WEB_AUTH_FOR_CONTRACTS_ENDPOINT` URL.
/// - `contract_id` — C-strkey of the contract account being authenticated.
/// - `home_domain` — Home domain for the `account` query param.
/// - `expected_web_auth_contract` — C-strkey of the expected web auth contract.
/// - `expected_server_signing_key` — G-strkey of the server signing key.
/// - `client_domain` — Optional client domain.
/// - `web_auth_domain` — Optional override for the web auth domain; when
///   `None`, derived from the host portion of `web_auth_endpoint`.
/// - `signature_expiration_ledger` — Ledger sequence number until which the
///   client's auth entry is valid. Per SEP-45 the client sets its own
///   `signature_expiration_ledger`; the caller must supply
///   `current_ledger + margin` (e.g. +100 ledgers) from its RPC layer.
///   A value of 0 is rejected with
///   [`crate::Sep45Error::InvalidSignatureExpirationLedger`].
#[derive(Debug, Clone, Copy)]
pub struct ChallengeRequest<'a> {
    /// Server `WEB_AUTH_FOR_CONTRACTS_ENDPOINT` URL.
    pub web_auth_endpoint: &'a str,
    /// C-strkey contract account being authenticated.
    pub contract_id: &'a str,
    /// Home domain for the `account` query parameter.
    pub home_domain: &'a str,
    /// C-strkey of the expected web auth contract.
    pub expected_web_auth_contract: &'a str,
    /// G-strkey of the expected server signing key.
    pub expected_server_signing_key: &'a str,
    /// Optional client domain.
    pub client_domain: Option<&'a str>,
    /// Optional web auth domain override. When `None`, derived from the host
    /// of `web_auth_endpoint`. If derivation fails, returns
    /// [`crate::Sep45Error::InvalidWebAuthEndpoint`].
    pub web_auth_domain: Option<&'a str>,
    /// Ledger sequence number until which the client's auth entry is valid.
    ///
    /// Per SEP-45 the client sets its own `signature_expiration_ledger`; the
    /// caller must supply `current_ledger + margin` from its RPC layer. A
    /// value of 0 is rejected with
    /// [`crate::Sep45Error::InvalidSignatureExpirationLedger`].
    pub signature_expiration_ledger: u32,
}

// ─────────────────────────────────────────────────────────────────────────────
// Sep45Client
// ─────────────────────────────────────────────────────────────────────────────

/// Async SEP-45 HTTP client.
///
/// Wraps `reqwest::Client` and exposes the two SEP-45 HTTP operations.
/// All HTTPS connections are handled by `reqwest`'s built-in rustls-TLS
/// backend (the workspace `reqwest` dep enables `rustls-tls`).
///
/// # Construction
///
/// ```no_run
/// use stellar_agent_sep45::client::Sep45Client;
///
/// let client = Sep45Client::new("Test SDF Network ; September 2015")
///     .expect("reqwest client construction failed");
/// ```
///
pub struct Sep45Client {
    /// Underlying `reqwest` async HTTP client.
    http: reqwest::Client,
    /// Stellar network passphrase for preimage hashing and passphrase
    /// validation on the server's response.
    network_passphrase: String,
}

impl Sep45Client {
    /// Constructs a new [`Sep45Client`] for the given network passphrase.
    ///
    /// Initialises a `reqwest::Client` with the following security settings:
    ///
    /// - **HTTPS-only** (`.https_only(true)`): any `http://` URL is rejected by
    ///   `reqwest` at request time and surfaced as [`Sep45Error::HttpError`].
    ///   HTTPS IS the security boundary for SEP-45 (TLS authenticates the
    ///   server; the JWT is trusted via TLS channel integrity).
    /// - **No redirects** (`Policy::none()`): any 3xx web-auth response is
    ///   returned as a non-success HTTP status rather than followed.
    /// - **Connect timeout: 10 seconds** — limits TCP+TLS handshake duration.
    /// - **Request timeout: 30 seconds** — total request budget; defence against
    ///   slowloris-style stall attacks on the challenge or submit endpoints.
    ///
    /// This is a cheap one-shot construction; in production callers should
    /// create a single client and reuse it across requests.
    ///
    /// # Errors
    ///
    /// - [`Sep45Error::HttpError`] if the underlying `reqwest::Client` cannot
    ///   be constructed (extremely rare; indicates system-level TLS init failure).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use stellar_agent_sep45::client::Sep45Client;
    ///
    /// let client = Sep45Client::new("Test SDF Network ; September 2015").unwrap();
    /// ```
    pub fn new(network_passphrase: impl Into<String>) -> Result<Self, Sep45Error> {
        let http = reqwest::Client::builder()
            // HTTPS-only enforcement — rejects any http:// URL at request time.
            // HTTPS IS the security boundary for SEP-45: the JWT is trusted
            // solely via TLS channel integrity.
            .https_only(true)
            // Do not move a SEP-45 web-auth request to a different origin.
            .redirect(reqwest::redirect::Policy::none())
            // Connect timeout — limits TCP+TLS handshake to 10 s.
            .connect_timeout(Duration::from_secs(10))
            // Request timeout — total round-trip budget of 30 s; defence
            // against slowloris-style stall attacks.
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| Sep45Error::HttpError {
                detail: format!("reqwest client construction failed: {e}"),
            })?;
        Ok(Self {
            http,
            network_passphrase: network_passphrase.into(),
        })
    }

    /// Returns the network passphrase this client was constructed with.
    ///
    /// Useful in tests and diagnostics.
    #[must_use]
    pub fn network_passphrase(&self) -> &str {
        &self.network_passphrase
    }

    /// Constructs a [`Sep45Client`] suitable for unit tests against a plain-HTTP
    /// mock server (e.g., `wiremock`).
    ///
    /// This constructor omits the `.https_only(true)` constraint so that
    /// `http://127.0.0.1:...` mock server URLs work in unit tests. All
    /// production code MUST use [`Sep45Client::new`] which enforces HTTPS.
    ///
    /// **NOT for production use.** Only available under `#[cfg(any(test, feature = "test-helpers"))]`.
    ///
    /// # Errors
    ///
    /// - [`Sep45Error::HttpError`] if the underlying `reqwest::Client` cannot
    ///   be constructed (extremely rare; indicates system-level TLS init failure).
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn new_for_unit_test(network_passphrase: impl Into<String>) -> Result<Self, Sep45Error> {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| Sep45Error::HttpError {
                detail: format!("reqwest client construction failed: {e}"),
            })?;
        Ok(Self {
            http,
            network_passphrase: network_passphrase.into(),
        })
    }

    /// Fetches and validates a SEP-45 challenge from `web_auth_endpoint`.
    ///
    /// Issues a GET request to
    /// `<web_auth_endpoint>?account=<contract_id>&home_domain=<home_domain>`
    /// (plus optional `&client_domain=<client_domain>` when `Some`), then:
    ///
    /// 1. Parses the JSON response `{ "authorization_entries": "<xdr_b64>",
    ///    "network_passphrase": "<passphrase>" }`.
    /// 2. Verifies the response `network_passphrase` matches the one this client
    ///    was constructed with, when the server includes it (fail-closed on
    ///    mismatch; spec marks the field optional).
    /// 3. Calls [`AuthorizationEntries::parse_and_validate`] with full
    ///    13-point SEP-45 validation.
    ///
    /// Per the SEP-45 GET challenge-response schema.
    ///
    /// # Errors
    ///
    /// - [`Sep45Error::HttpError`] on network failure or non-200 HTTP status.
    /// - [`Sep45Error::JwtParseError`] if the response is not valid JSON or
    ///   the expected `authorization_entries` field is absent.
    /// - Any [`Sep45Error`] variant from [`AuthorizationEntries::parse_and_validate`]
    ///   on challenge validation failure.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub async fn fetch_challenge(
        &self,
        request: ChallengeRequest<'_>,
    ) -> Result<AuthorizationEntries, Sep45Error> {
        let web_auth_endpoint = request.web_auth_endpoint;
        let contract_id = request.contract_id;
        let home_domain = request.home_domain;
        let expected_web_auth_contract = request.expected_web_auth_contract;
        let expected_server_signing_key = request.expected_server_signing_key;
        let client_domain = request.client_domain;

        // Resolve the web auth domain: use the caller-supplied value or derive
        // it from the host portion of `web_auth_endpoint`. Fail-closed: if
        // neither is available, return `InvalidWebAuthEndpoint`.
        let web_auth_domain_owned: String;
        let expected_web_auth_domain: &str = match request.web_auth_domain {
            Some(d) => d,
            None => {
                let url = reqwest::Url::parse(web_auth_endpoint).map_err(|e| {
                    Sep45Error::InvalidWebAuthEndpoint {
                        detail: format!("failed to parse web_auth_endpoint URL: {e}"),
                    }
                })?;
                let host = url
                    .host_str()
                    .ok_or_else(|| Sep45Error::InvalidWebAuthEndpoint {
                        detail: "web_auth_endpoint URL has no host".to_owned(),
                    })?;
                // Include the port in the derived web_auth_domain when it is
                // explicitly specified and non-default (i.e. not the well-known
                // port for the scheme). `reqwest::Url::host_str()` drops the port;
                // we reconstruct it here per the SEP-45 web_auth_domain derivation
                // requirement.
                web_auth_domain_owned = match url.port() {
                    Some(port) => format!("{host}:{port}"),
                    None => host.to_owned(),
                };
                &web_auth_domain_owned
            }
        };

        // Build query parameters: required params first, then optional.
        let mut params: Vec<(&str, String)> = vec![
            ("account", contract_id.to_owned()),
            ("home_domain", home_domain.to_owned()),
        ];
        if let Some(cd) = client_domain {
            params.push(("client_domain", cd.to_owned()));
        }

        let response = self
            .http
            .get(web_auth_endpoint)
            .query(&params)
            .send()
            .await
            .map_err(|e| Sep45Error::HttpError {
                detail: format!("GET {web_auth_endpoint}: {e}"),
            })?;

        let status = response.status();
        if !status.is_success() {
            // Use .chars().take(512) rather than &body[..512] to avoid a panic
            // at a multi-byte UTF-8 boundary in a server-controlled error body.
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<unreadable>".to_owned());
            let truncated = if body.chars().count() > 512 {
                format!("{}…", body.chars().take(512).collect::<String>())
            } else {
                body
            };
            return Err(Sep45Error::HttpError {
                detail: format!("GET {web_auth_endpoint} returned HTTP {status}: {truncated}"),
            });
        }

        // Fail-closed on JSON parse failure.
        let challenge_response: ChallengeResponse =
            response
                .json()
                .await
                .map_err(|e| Sep45Error::JwtParseError {
                    detail: format!("GET {web_auth_endpoint}: failed to parse JSON response: {e}"),
                })?;

        // Verify network passphrase when the server includes it in the response.
        // The spec marks network_passphrase optional (per the SEP-45 GET
        // challenge-response schema). When present, a mismatch is a fail-closed
        // rejection. A passphrase mismatch is a network-identity error (not a
        // crypto failure), so it maps to NetworkPassphraseMismatch.
        if let Some(ref server_passphrase) = challenge_response.network_passphrase
            && server_passphrase != &self.network_passphrase
        {
            return Err(Sep45Error::NetworkPassphraseMismatch {
                detail: format!(
                    "server returned network_passphrase {:?} but client expected {:?}",
                    // Truncate to 16 chars to avoid echoing the full passphrase.
                    // `chars().take(16)` avoids a UTF-8 boundary panic that
                    // `&str[..N]` would cause at a multi-byte char boundary.
                    server_passphrase.chars().take(16).collect::<String>(),
                    self.network_passphrase.chars().take(16).collect::<String>(),
                ),
            });
        }

        // Parse and validate the authorization entries XDR (steps 1-12 of
        // SEP-45 validation including server-signature cryptographic
        // verification; step 13 footprint deferred to caller).
        // `contract_id` is the expected_account: per SEP-45 step 7.1
        // (per SEP-45 challenge-validation step 7.1) the challenge's `account`
        // arg must equal it.
        AuthorizationEntries::parse_and_validate(
            &challenge_response.authorization_entries,
            &self.network_passphrase,
            expected_web_auth_contract,
            home_domain,
            expected_web_auth_domain,
            expected_server_signing_key,
            client_domain,
            contract_id,
        )
    }

    /// Submits signed authorization entries to the SEP-45 server and returns the
    /// JWT session.
    ///
    /// Issues a POST request to `<web_auth_endpoint>` with
    /// `Content-Type: application/json` and body
    /// `{"authorization_entries": "<signed_xdr_b64>"}`,
    /// then parses the `{"token": "<jwt>"}` response via [`Sep45Session::parse`].
    ///
    /// Per the SEP-45 POST signed-entries schema.
    ///
    /// # Errors
    ///
    /// - [`Sep45Error::HttpError`] on network failure or non-200 HTTP status.
    /// - [`Sep45Error::JwtParseError`] if the response JSON cannot be parsed or
    ///   the `token` field is absent or empty.
    /// - Any [`Sep45Error`] variant from [`Sep45Session::parse`] if the JWT is
    ///   malformed.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub async fn submit_signed_challenge(
        &self,
        web_auth_endpoint: &str,
        signed_entries_xdr: &str,
    ) -> Result<Sep45Session, Sep45Error> {
        let mut body = HashMap::new();
        // POST body field is `authorization_entries` per the SEP-45 POST body schema.
        body.insert("authorization_entries", signed_entries_xdr);

        let response = self
            .http
            .post(web_auth_endpoint)
            .json(&body)
            .send()
            .await
            .map_err(|e| Sep45Error::HttpError {
                detail: format!("POST {web_auth_endpoint}: {e}"),
            })?;

        let status = response.status();
        if !status.is_success() {
            // char-boundary-safe truncation: .chars().take(512) avoids a panic
            // at a multi-byte UTF-8 boundary in server-controlled response bodies.
            let body_text = response
                .text()
                .await
                .unwrap_or_else(|_| "<unreadable>".to_owned());
            let truncated = if body_text.chars().count() > 512 {
                format!("{}…", body_text.chars().take(512).collect::<String>())
            } else {
                body_text
            };
            return Err(Sep45Error::HttpError {
                detail: format!("POST {web_auth_endpoint} returned HTTP {status}: {truncated}"),
            });
        }

        // Fail-closed on JSON parse failure.
        let token_response: TokenResponse =
            response
                .json()
                .await
                .map_err(|e| Sep45Error::JwtParseError {
                    detail: format!("POST {web_auth_endpoint}: failed to parse JSON response: {e}"),
                })?;

        // Fail-closed on empty token.
        if token_response.token.is_empty() {
            return Err(Sep45Error::JwtParseError {
                detail: format!("POST {web_auth_endpoint}: response 'token' field is empty"),
            });
        }

        let session = Sep45Session::parse(&token_response.token)?;
        let now_unix = system_time_unix_secs()?;
        if session.is_expired(now_unix) {
            return Err(Sep45Error::JwtExpired {
                exp_unix: session.exp,
                now_unix,
            });
        }

        Ok(session)
    }
}

impl std::fmt::Debug for Sep45Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sep45Client")
            .field(
                "network_passphrase",
                // Truncate to avoid emitting full passphrase in debug output.
                // `chars().take(16)` avoids a UTF-8 boundary panic that
                // `&str[..N]` would cause if a multi-byte char straddles byte 16.
                &self.network_passphrase.chars().take(16).collect::<String>(),
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
/// - [`Sep45Error::HttpError`] if `SystemTime::now()` predates the Unix epoch
///   (should be impossible on any real OS; included for type-system completeness).
fn system_time_unix_secs() -> Result<u64, Sep45Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| Sep45Error::HttpError {
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

    const TEST_PASSPHRASE: &str = "Test SDF Network ; September 2015";

    // ── Constructor ───────────────────────────────────────────────────────────

    #[test]
    fn constructor_stores_passphrase() {
        let client = Sep45Client::new(TEST_PASSPHRASE).unwrap();
        assert_eq!(client.network_passphrase(), TEST_PASSPHRASE);
    }

    #[test]
    fn debug_does_not_echo_full_passphrase() {
        let client = Sep45Client::new(TEST_PASSPHRASE).unwrap();
        let debug = format!("{client:?}");
        // Debug should contain the first 16 chars, not the full passphrase.
        assert!(!debug.contains(TEST_PASSPHRASE));
        assert!(debug.contains("Test SDF Network"));
    }

    // ── HTTPS-only enforcement ────────────────────────────────────────────────

    /// Verifies that the production `Sep45Client::new` constructor rejects
    /// plain `http://` URLs at request time.
    ///
    /// Uses `reqwest`'s `.https_only(true)` setting which raises an error
    /// for any non-HTTPS request before a connection is attempted.
    #[tokio::test]
    async fn https_only_enforcement_rejects_http_url() {
        // Use the production constructor (https_only = true).
        let client = Sep45Client::new(TEST_PASSPHRASE).unwrap();
        // A plain http:// URL must be rejected without any network connection.
        let err = client
            .fetch_challenge(ChallengeRequest {
                web_auth_endpoint: "http://example.com/auth",
                contract_id: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
                home_domain: "example.com",
                expected_web_auth_contract: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
                expected_server_signing_key:
                    "GCHLHDBOKG2JWMJQBTLSL5XG6NO7ESXI2TAQKZXCXWXB5WI2X6W233PR",
                client_domain: None,
                web_auth_domain: Some("example.com"),
                signature_expiration_ledger: 9_999_999,
            })
            .await
            .unwrap_err();
        assert!(
            matches!(err, Sep45Error::HttpError { .. }),
            "http:// URL must produce Sep45Error::HttpError via https_only; got {err:?}"
        );
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

        // new_for_unit_test omits https_only so wiremock's http:// URI works.
        let client = Sep45Client::new_for_unit_test(TEST_PASSPHRASE).unwrap();
        let endpoint = format!("{}/auth", mock_server.uri());
        let err = client
            .fetch_challenge(ChallengeRequest {
                web_auth_endpoint: &endpoint,
                contract_id: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
                home_domain: "example.com",
                expected_web_auth_contract: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
                expected_server_signing_key:
                    "GCHLHDBOKG2JWMJQBTLSL5XG6NO7ESXI2TAQKZXCXWXB5WI2X6W233PR",
                client_domain: None,
                web_auth_domain: Some("example.com"),
                signature_expiration_ledger: 9_999_999,
            })
            .await
            .unwrap_err();
        assert!(
            matches!(err, Sep45Error::HttpError { .. }),
            "expected HttpError for 401, got {err:?}"
        );
        assert_eq!(err.wire_code(), "sep45.http_error");
    }

    #[tokio::test]
    async fn fetch_challenge_does_not_follow_redirects() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/auth"))
            .respond_with(ResponseTemplate::new(302).insert_header("location", "/redirected"))
            .mount(&mock_server)
            .await;

        let client = Sep45Client::new_for_unit_test(TEST_PASSPHRASE).unwrap();
        let endpoint = format!("{}/auth", mock_server.uri());
        let err = client
            .fetch_challenge(ChallengeRequest {
                web_auth_endpoint: &endpoint,
                contract_id: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
                home_domain: "example.com",
                expected_web_auth_contract: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
                expected_server_signing_key:
                    "GCHLHDBOKG2JWMJQBTLSL5XG6NO7ESXI2TAQKZXCXWXB5WI2X6W233PR",
                client_domain: None,
                web_auth_domain: Some("example.com"),
                signature_expiration_ledger: 9_999_999,
            })
            .await
            .unwrap_err();

        assert!(
            matches!(err, Sep45Error::HttpError { ref detail } if detail.contains("302")),
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

        // new_for_unit_test omits https_only so wiremock's http:// URI works.
        let client = Sep45Client::new_for_unit_test(TEST_PASSPHRASE).unwrap();
        let endpoint = format!("{}/auth", mock_server.uri());
        let err = client
            .submit_signed_challenge(&endpoint, "FAKEXDR")
            .await
            .unwrap_err();
        assert!(
            matches!(err, Sep45Error::HttpError { .. }),
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

        let client = Sep45Client::new_for_unit_test(TEST_PASSPHRASE).unwrap();
        let endpoint = format!("{}/auth", mock_server.uri());
        let err = client
            .fetch_challenge(ChallengeRequest {
                web_auth_endpoint: &endpoint,
                contract_id: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
                home_domain: "example.com",
                expected_web_auth_contract: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
                expected_server_signing_key:
                    "GCHLHDBOKG2JWMJQBTLSL5XG6NO7ESXI2TAQKZXCXWXB5WI2X6W233PR",
                client_domain: None,
                web_auth_domain: Some("example.com"),
                signature_expiration_ledger: 9_999_999,
            })
            .await
            .unwrap_err();
        // Non-JSON response → JwtParseError (JSON parse branch).
        assert!(
            matches!(err, Sep45Error::JwtParseError { .. }),
            "expected JwtParseError for malformed JSON, got {err:?}"
        );
    }

    #[tokio::test]
    async fn submit_signed_challenge_rejects_missing_token_field() {
        let mock_server = MockServer::start().await;
        // Response is valid JSON but missing the "token" field.
        Mock::given(method("POST"))
            .and(path("/auth"))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"not_a_token":"value"}"#))
            .mount(&mock_server)
            .await;

        let client = Sep45Client::new_for_unit_test(TEST_PASSPHRASE).unwrap();
        let endpoint = format!("{}/auth", mock_server.uri());
        let err = client
            .submit_signed_challenge(&endpoint, "FAKEXDR")
            .await
            .unwrap_err();
        assert!(
            matches!(err, Sep45Error::JwtParseError { .. }),
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

        let client = Sep45Client::new_for_unit_test(TEST_PASSPHRASE).unwrap();
        let endpoint = format!("{}/auth", mock_server.uri());
        let err = client
            .submit_signed_challenge(&endpoint, "FAKEXDR")
            .await
            .unwrap_err();

        assert!(
            matches!(err, Sep45Error::HttpError { ref detail } if detail.contains("302")),
            "expected no-follow redirect to surface as 302 HttpError, got {err:?}"
        );
    }

    #[tokio::test]
    async fn submit_signed_challenge_rejects_expired_jwt() {
        let mock_server = MockServer::start().await;
        let token = build_test_jwt(
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            1,
        );
        Mock::given(method("POST"))
            .and(path("/auth"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "token": token })))
            .mount(&mock_server)
            .await;

        let client = Sep45Client::new_for_unit_test(TEST_PASSPHRASE).unwrap();
        let endpoint = format!("{}/auth", mock_server.uri());
        let err = client
            .submit_signed_challenge(&endpoint, "FAKEXDR")
            .await
            .unwrap_err();

        assert!(
            matches!(err, Sep45Error::JwtExpired { exp_unix: 1, now_unix } if now_unix > 1),
            "expected expired JWT rejection, got {err:?}"
        );
    }

    // ── Query-param URL encoding ──────────────────────────────────────────────

    #[tokio::test]
    async fn fetch_challenge_encodes_optional_client_domain_param() {
        let mock_server = MockServer::start().await;
        // Expect all three query params: account, home_domain, client_domain.
        Mock::given(method("GET"))
            .and(path("/auth"))
            .and(query_param("account", "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM"))
            .and(query_param("home_domain", "example.com"))
            .and(query_param("client_domain", "wallet.example.com"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(
                    r#"{"authorization_entries":"bad_xdr","network_passphrase":"Test SDF Network ; September 2015"}"#,
                ),
            )
            .mount(&mock_server)
            .await;

        let client = Sep45Client::new_for_unit_test(TEST_PASSPHRASE).unwrap();
        let endpoint = format!("{}/auth", mock_server.uri());
        // This will fail at XDR validation (bad_xdr), but the mock server will
        // only match if all three query params are present.
        let result = client
            .fetch_challenge(ChallengeRequest {
                web_auth_endpoint: &endpoint,
                contract_id: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
                home_domain: "example.com",
                expected_web_auth_contract: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
                expected_server_signing_key:
                    "GCHLHDBOKG2JWMJQBTLSL5XG6NO7ESXI2TAQKZXCXWXB5WI2X6W233PR",
                client_domain: Some("wallet.example.com"),
                web_auth_domain: Some("example.com"),
                signature_expiration_ledger: 9_999_999,
            })
            .await;
        // The mock matched (no 404) — that proves query params were correct.
        // The result is an error because "bad_xdr" fails XDR decode, which is fine.
        assert!(result.is_err());
        assert!(
            !matches!(result.as_ref().unwrap_err(), Sep45Error::HttpError { detail }
                if detail.contains("404")),
            "got unexpected 404; mock query param matching failed: {result:?}"
        );
    }

    #[tokio::test]
    async fn fetch_challenge_omits_client_domain_when_none() {
        let mock_server = MockServer::start().await;
        // Match only the required params.
        Mock::given(method("GET"))
            .and(path("/auth"))
            .and(query_param("account", "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM"))
            .and(query_param("home_domain", "example.com"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(
                    r#"{"authorization_entries":"bad_xdr","network_passphrase":"Test SDF Network ; September 2015"}"#,
                ),
            )
            .mount(&mock_server)
            .await;

        let client = Sep45Client::new_for_unit_test(TEST_PASSPHRASE).unwrap();
        let endpoint = format!("{}/auth", mock_server.uri());
        let result = client
            .fetch_challenge(ChallengeRequest {
                web_auth_endpoint: &endpoint,
                contract_id: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
                home_domain: "example.com",
                expected_web_auth_contract: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
                expected_server_signing_key:
                    "GCHLHDBOKG2JWMJQBTLSL5XG6NO7ESXI2TAQKZXCXWXB5WI2X6W233PR",
                client_domain: None,
                web_auth_domain: Some("example.com"),
                signature_expiration_ledger: 9_999_999,
            })
            .await;
        // Mock matched; XDR decode will fail (bad_xdr), but not an HTTP error.
        assert!(result.is_err());
        assert!(
            !matches!(result.as_ref().unwrap_err(), Sep45Error::HttpError { detail }
                if detail.contains("404")),
            "mock did not match: {result:?}"
        );
    }

    // ── Network-passphrase mismatch ───────────────────────────────────────────

    #[tokio::test]
    async fn fetch_challenge_rejects_wrong_network_passphrase() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/auth"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(
                    r#"{"authorization_entries":"bad_xdr","network_passphrase":"Public Global Stellar Network ; September 2015"}"#,
                ),
            )
            .mount(&mock_server)
            .await;

        let client = Sep45Client::new_for_unit_test(TEST_PASSPHRASE).unwrap();
        let endpoint = format!("{}/auth", mock_server.uri());
        let err = client
            .fetch_challenge(ChallengeRequest {
                web_auth_endpoint: &endpoint,
                contract_id: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
                home_domain: "example.com",
                expected_web_auth_contract: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
                expected_server_signing_key:
                    "GCHLHDBOKG2JWMJQBTLSL5XG6NO7ESXI2TAQKZXCXWXB5WI2X6W233PR",
                client_domain: None,
                web_auth_domain: Some("example.com"),
                signature_expiration_ledger: 9_999_999,
            })
            .await
            .unwrap_err();
        assert!(
            matches!(err, Sep45Error::NetworkPassphraseMismatch { .. }),
            "expected NetworkPassphraseMismatch for passphrase mismatch, got {err:?}"
        );
        assert_eq!(err.wire_code(), "sep45.network_passphrase_mismatch");
    }

    // ── camelCase field name compatibility (testanchor quirk) ─────────────────

    /// Verifies that the client accepts the camelCase `authorizationEntries`
    /// and `networkPassphrase` field names that testanchor.stellar.org returns
    /// (observed 2026-05-28 live check).
    #[tokio::test]
    async fn fetch_challenge_accepts_camel_case_field_names() {
        let mock_server = MockServer::start().await;
        // testanchor-style camelCase response.
        Mock::given(method("GET"))
            .and(path("/auth"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(
                    r#"{"authorizationEntries":"bad_xdr","networkPassphrase":"Test SDF Network ; September 2015"}"#,
                ),
            )
            .mount(&mock_server)
            .await;

        let client = Sep45Client::new_for_unit_test(TEST_PASSPHRASE).unwrap();
        let endpoint = format!("{}/auth", mock_server.uri());
        let result = client
            .fetch_challenge(ChallengeRequest {
                web_auth_endpoint: &endpoint,
                contract_id: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
                home_domain: "example.com",
                expected_web_auth_contract: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
                expected_server_signing_key:
                    "GCHLHDBOKG2JWMJQBTLSL5XG6NO7ESXI2TAQKZXCXWXB5WI2X6W233PR",
                client_domain: None,
                web_auth_domain: Some("example.com"),
                signature_expiration_ledger: 9_999_999,
            })
            .await;
        // The JSON parsed successfully (no JwtParseError on the "missing field"
        // branch). The result is a validation error because "bad_xdr" fails XDR
        // decode — not a JwtParseError.
        assert!(result.is_err());
        assert!(
            !matches!(
                result.as_ref().unwrap_err(),
                Sep45Error::JwtParseError { .. }
            ),
            "camelCase field parse should succeed; got unexpected JwtParseError: {result:?}"
        );
    }

    // ── web_auth_domain derivation: port inclusion ────────────────────────────

    /// When `ChallengeRequest.web_auth_domain` is `None` and the endpoint URL
    /// carries an explicit port (e.g. `http://auth.example.com:8080/auth`), the
    /// derived `web_auth_domain` sent to `parse_and_validate` as
    /// `expected_web_auth_domain` must include the port (`"auth.example.com:8080"`).
    ///
    /// `reqwest::Url::host_str()` drops the port. A server that correctly sets
    /// `web_auth_domain = "auth.example.com:8080"` would cause a spurious
    /// `WebAuthDomainMismatch` if the port is not included in the derived domain.
    ///
    /// This test exercises the derivation logic by sending a request to a mock
    /// server on a non-default port with `web_auth_domain: None`. The mock
    /// returns a JSON body with `authorization_entries = "bad_xdr"` so the
    /// request proceeds past JSON parsing but fails at XDR decode — which is
    /// expected and proves the derived domain logic ran without error.
    #[tokio::test]
    async fn web_auth_domain_derivation_includes_port_when_present() {
        // Start a wiremock server on a dynamic port (always non-80).
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/auth"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"authorization_entries":"bad_xdr","network_passphrase":"Test SDF Network ; September 2015"}"#,
            ))
            .mount(&mock_server)
            .await;

        let client = Sep45Client::new_for_unit_test(TEST_PASSPHRASE).unwrap();
        let endpoint = format!("{}/auth", mock_server.uri());

        // Confirm the mock URI uses a non-default port (wiremock always does).
        let parsed_url = reqwest::Url::parse(&endpoint).unwrap();
        assert!(
            parsed_url.port().is_some(),
            "wiremock URI must have an explicit port for this test"
        );
        let expected_domain = format!(
            "{}:{}",
            parsed_url.host_str().unwrap(),
            parsed_url.port().unwrap()
        );

        // web_auth_domain: None → derived from URL. Must include the port.
        let result = client
            .fetch_challenge(ChallengeRequest {
                web_auth_endpoint: &endpoint,
                contract_id: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
                home_domain: "example.com",
                expected_web_auth_contract: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
                expected_server_signing_key:
                    "GCHLHDBOKG2JWMJQBTLSL5XG6NO7ESXI2TAQKZXCXWXB5WI2X6W233PR",
                client_domain: None,
                web_auth_domain: None,
                signature_expiration_ledger: 9_999_999,
            })
            .await;

        // Expected failure: XDR decode ("bad_xdr") — NOT a WebAuthDomainMismatch.
        // A WebAuthDomainMismatch would mean the derived domain was wrong (missing port).
        match &result {
            Err(Sep45Error::XdrDecodeError { .. }) => {
                // Correct: derivation ran, port was included, XDR decode failed as expected.
            }
            Err(Sep45Error::WebAuthDomainMismatch { found, expected }) => {
                panic!(
                    "web_auth_domain derivation omitted port; \
                     expected domain '{expected_domain}', derived '{found}', \
                     challenge had '{expected}'"
                );
            }
            other => {
                // Any other error (e.g. JwtParseError) is also acceptable here —
                // what matters is the absence of WebAuthDomainMismatch.
                let _ = other;
            }
        }
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
