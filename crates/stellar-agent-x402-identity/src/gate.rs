//! Counterparty-identity pre-payment gate for x402 Exact Stellar payments.
//!
//! # What this module does
//!
//! Provides [`resolve_and_verify_counterparty`], the SEP-10 counterparty-identity
//! gate that MUST run and succeed BEFORE any x402 payment is constructed.
//!
//! The gate performs five steps in order:
//!
//! 1. Fetch `https://<home_domain>/.well-known/stellar.toml` via
//!    [`stellar_agent_network::counterparty::fetch::fetch_stellar_toml`], which
//!    builds its own no-redirect + HTTPS-only + no-decompression client
//!    internally.
//! 2. Parse the body via
//!    [`stellar_agent_network::counterparty::parse_minimal_sep1`].
//! 3. Extract `WEB_AUTH_ENDPOINT` (→ [`IdentityError::WebAuthEndpointMissing`])
//!    and `SIGNING_KEY` (→ [`IdentityError::SigningKeyMissing`]).
//! 4. Assert `WEB_AUTH_ENDPOINT` host is `home_domain` or a subdomain — the
//!    **SSRF same-domain bind** (→ [`IdentityError::WebAuthEndpointHostMismatch`]).
//! 5. Run the SEP-10 ephemeral-key challenge/response via
//!    [`stellar_agent_sep10::ephemeral::auth_with_ephemeral_key`] →
//!    `Sep10Session` (→ [`IdentityError::Sep10AuthFailed`] on any failure).
//!
//! Any failure in steps 1–5 returns an [`IdentityError`] and **aborts before
//! any x402 payment is constructed**.  No `PaymentPayload`, no SAC transfer
//! auth-entry, no nonce is generated on failure.
//!
//! # No-redirect guarantee
//!
//! The production path fetches stellar.toml via
//! [`stellar_agent_network::counterparty::fetch::fetch_stellar_toml`], which
//! builds its own client configured with `redirect::Policy::none()`,
//! `https_only(true)`, `no_gzip()`, `no_brotli()`, `no_deflate()`, and
//! additionally rejects any 3xx at the status layer.  The gate does NOT accept a
//! caller-supplied `reqwest::Client` for the production toml fetch, removing the
//! foot-gun where a caller could supply an auto-follow client that silently
//! follows a 3xx to an attacker-chosen host.
//!
//! The SEP-10 client (`Sep10Client`) is similarly HTTPS-only (`https_only(true)`
//! configured on its internal `reqwest::ClientBuilder`).
//!
//! # SSRF same-domain bind
//!
//! The `WEB_AUTH_ENDPOINT` host is validated against `home_domain` using a
//! same-domain bind:
//!
//! ```text
//! host == home_domain || host.ends_with(&format!(".{home_domain}"))
//! ```
//!
//! The LEADING DOT prevents `evil-home_domain.com` from matching `home_domain.com`.
//! The `home_domain` itself is validated as a public FQDN (≥2 labels, not an IP,
//! valid LDH) BEFORE building the suffix pattern, providing defense-in-depth
//! against degenerate domains (e.g. `""` → `"."` that matches any host).
//!
//! # Abort-before-payment contract
//!
//! This function is the ONLY entry into the x402 identity gate.  Callers MUST
//! NOT call `stellar_agent_x402::exact::create_payment` if this function returns
//! `Err(...)`.  The gate is designed to be structurally incapable of partial
//! success — every error path returns before any payment-construction state is
//! created.

use tracing::{debug, warn};
use url::Url;

use stellar_agent_network::counterparty::{
    CounterpartyError, fetch::fetch_stellar_toml, parser::parse_minimal_sep1,
    validation::is_valid_ldh_home_domain,
};
use stellar_agent_sep10::Sep10Client;
use stellar_agent_sep10::ephemeral::auth_with_ephemeral_key;

use crate::error::{IdentityError, authority_hint};

// ─────────────────────────────────────────────────────────────────────────────
// VerifiedCounterpartySession
// ─────────────────────────────────────────────────────────────────────────────

/// Verified counterparty session produced by a successful identity gate run.
///
/// Contains the SEP-10 JWT Bearer token ready to include as the
/// `Authorization: Bearer <jwt>` HTTP companion header alongside the
/// `PAYMENT-SIGNATURE` header.
///
/// The JWT is the **HTTP-layer identity companion** to the x402 payment.  It is
/// NOT embedded in the Soroban transaction XDR, the SAC auth-entry, or the
/// payment memo — the x402 wire format (`ExactStellarPayloadV2 = { transaction }`)
/// has no identity slot.  The payer (wallet) returns both to the MCP host:
///
/// - `PAYMENT-SIGNATURE` header ← the x402 `PaymentPayload` (from `create_payment`)
/// - `Authorization: Bearer <jwt>` ← `VerifiedCounterpartySession.jwt` (from this fn)
pub struct VerifiedCounterpartySession {
    /// The SEP-10 JWT Bearer token.
    ///
    /// This is the `Authorization: Bearer <jwt>` value to include alongside
    /// the `PAYMENT-SIGNATURE` header in the HTTP request to the x402-protected
    /// resource.
    ///
    /// # Security
    ///
    /// NEVER log this value.  JWT material must not appear in structured logs,
    /// error messages, or trace spans.  The field is intentionally not
    /// `Debug`-printed in a way that exposes content.
    pub jwt: String,

    /// The `sub` (subject) claim from the SEP-10 JWT.
    ///
    /// This is the G-strkey of the ephemeral account used for the SEP-10
    /// challenge.  The ephemeral key is not the payment signer and is not
    /// persisted beyond this session.
    pub sub: String,

    /// The operator-supplied home domain, echoed back for operator display.
    ///
    /// Surfaced in the MCP tool output so the operator can inspect which domain
    /// was verified before approving the payment.
    pub home_domain: String,

    /// The verified home-domain's self-declared `ACCOUNTS` list from
    /// `stellar.toml`.
    ///
    /// These are the raw `ACCOUNTS` strings as declared in the home domain's
    /// `stellar.toml` (not re-validated as G-strkeys by this crate).  The list
    /// is populated from
    /// [`stellar_agent_network::counterparty::parser::MinimalSep1::accounts`]
    /// after a successful parse.
    ///
    /// # Semantics
    ///
    /// - **Non-empty**: the verified domain declared at least one account.
    ///   Comparing `payTo` against this list gives a best-effort anchoring
    ///   signal.
    /// - **Empty**: the domain's `stellar.toml` omitted the `ACCOUNTS` field
    ///   or declared an empty array.  Anchoring is "unknown" — absence does
    ///   NOT mean the destination is unowned by the domain; SEP-1 `ACCOUNTS`
    ///   does not reliably enumerate SAC payment destinations.
    ///
    /// # Security
    ///
    /// These strings are publicly declared by the home domain in a
    /// publicly-readable `stellar.toml`.  They are NOT secret.  They MAY be
    /// shown in operator-facing output.
    pub accounts: Vec<String>,
}

impl std::fmt::Debug for VerifiedCounterpartySession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // jwt: first-8-last-8 redaction (JWT material must not appear in logs
        // or debug output).
        // accounts: G-strkeys are public per SEP-1; rendered as count to keep
        // debug output stable regardless of how many entries the domain declares.
        f.debug_struct("VerifiedCounterpartySession")
            .field("jwt", &redact_jwt_for_debug(&self.jwt))
            .field("sub", &self.sub)
            .field("home_domain", &self.home_domain)
            .field("accounts_count", &self.accounts.len())
            .finish()
    }
}

fn redact_jwt_for_debug(jwt: &str) -> String {
    // chars()-based slicing so `Debug` never panics on a non-ASCII value. The
    // first-8-last-8 form is shown only when the hidden middle is strictly
    // larger than the 16 revealed characters; values of 32 characters or fewer
    // are fully redacted so a short token never reveals most of itself.
    let char_count = jwt.chars().count();
    if char_count <= 32 {
        return "<redacted>".to_owned();
    }
    let first: String = jwt.chars().take(8).collect();
    let last: String = jwt
        .chars()
        .rev()
        .take(8)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("{first}...{last}")
}

// ─────────────────────────────────────────────────────────────────────────────
// resolve_and_verify_counterparty — production entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Runs the SEP-10 counterparty-identity gate for an x402 payment.
///
/// Resolves `home_domain` → `stellar.toml` → `WEB_AUTH_ENDPOINT` + `SIGNING_KEY`
/// → SSRF same-domain bind → ephemeral SEP-10 challenge/response → JWT.
///
/// Any failure **aborts before any x402 payment is constructed** — no
/// `PaymentPayload` or SAC auth-entry is built on an error return.
///
/// # Client construction
///
/// The stellar.toml fetch goes through
/// [`stellar_agent_network::counterparty::fetch::fetch_stellar_toml`], which
/// builds a per-request HTTPS-only, no-redirect, no-decompression client
/// pinned to egress-filtered addresses (a DNS-rebinding + SSRF egress defence).
/// The gate does NOT accept a caller-supplied `reqwest::Client`, preventing a
/// silent 3xx-follow to an attacker-chosen host.  The SEP-10 client is also
/// built internally with `https_only(true)`.
///
/// # Arguments
///
/// - `home_domain` — the operator-supplied home domain for the x402-protected
///   resource.  Must be a valid lowercase LDH public FQDN; an invalid domain
///   returns [`IdentityError::HomeDomainInvalid`] before any network I/O.
/// - `network_passphrase` — Stellar network passphrase; passed to the
///   [`Sep10Client`] for challenge validation and signature-payload construction.
///
/// # Return
///
/// [`VerifiedCounterpartySession`] on success:
/// - `jwt` — the SEP-10 Bearer token, ready for `Authorization: Bearer <jwt>`.
/// - `sub` — the G-strkey of the ephemeral account (for operator display).
/// - `home_domain` — echoed from the input for operator display.
/// - `accounts` — the raw `ACCOUNTS` strings from the home domain's
///   `stellar.toml`; empty when the field is absent.
///
/// # Errors
///
/// - [`IdentityError::HomeDomainInvalid`] — `home_domain` fails LDH / ASCII /
///   length validation (caller-input error; no I/O attempted).
/// - [`IdentityError::HomeDomainUnresolvable`] — HTTPS GET to `stellar.toml`
///   failed (DNS, TCP, TLS, redirect, or non-2xx response).
/// - [`IdentityError::TomlFetchFailed`] — `stellar.toml` body could not be
///   parsed as valid SEP-1 TOML.
/// - [`IdentityError::WebAuthEndpointMissing`] — `WEB_AUTH_ENDPOINT` is absent
///   from the parsed `stellar.toml`.
/// - [`IdentityError::SigningKeyMissing`] — `SIGNING_KEY` is absent from the
///   parsed `stellar.toml`.
/// - [`IdentityError::WebAuthEndpointHostMismatch`] — the `WEB_AUTH_ENDPOINT`
///   host is not `home_domain` or a subdomain of it (SSRF same-domain bind
///   rejected).
/// - [`IdentityError::Sep10AuthFailed`] — the SEP-10 challenge/response cycle
///   failed (server signature mismatch, HTTP error, JWT parse failure, etc.).
///
/// # Panics
///
/// Never panics.
///
/// # Examples
///
/// ```no_run
/// use stellar_agent_x402_identity::gate::resolve_and_verify_counterparty;
///
/// # async fn example() -> Result<(), stellar_agent_x402_identity::IdentityError> {
/// let session = resolve_and_verify_counterparty(
///     "testanchor.stellar.org",
///     "Test SDF Network ; September 2015",
/// ).await?;
/// // Use session.jwt as Authorization: Bearer <jwt>
/// assert!(!session.jwt.is_empty());
/// assert_eq!(session.home_domain, "testanchor.stellar.org");
/// # Ok(())
/// # }
/// ```
pub async fn resolve_and_verify_counterparty(
    home_domain: &str,
    network_passphrase: &str,
) -> Result<VerifiedCounterpartySession, IdentityError> {
    // The production path fetches stellar.toml via `fetch_stellar_toml`, which
    // builds its own no-redirect / HTTPS-only client internally; no caller-side
    // client is needed.
    run_gate_with_override(home_domain, network_passphrase, None, None, None).await
}

// ─────────────────────────────────────────────────────────────────────────────
// Test seam — only available under test or test-helpers feature
// ─────────────────────────────────────────────────────────────────────────────

/// Test seam: runs the full gate against explicit base URLs instead of
/// synthesising `https://{home_domain}/...`.
///
/// This allows wiremock servers (which use plain HTTP on `127.0.0.1:PORT`,
/// a domain that fails the production LDH validator) to drive the gate
/// end-to-end through all five steps including the SEP-10 challenge/response.
///
/// **Production code MUST NOT call this function.**  The production path is
/// always [`resolve_and_verify_counterparty`].
///
/// # Arguments
///
/// - `home_domain` — the logical home domain used for SSRF same-domain bind
///   checking and the SEP-10 `home_domain` parameter.  Does NOT need to be a
///   valid LDH FQDN in test mode (LDH validation is bypassed).
/// - `network_passphrase` — Stellar network passphrase.
/// - `toml_base_url` — the base URL to fetch stellar.toml from (e.g.
///   `http://127.0.0.1:PORT`); the gate appends `/.well-known/stellar.toml`.
/// - `http` — caller-supplied `reqwest::Client` (allows HTTP for wiremock).
/// - `web_auth_override` — optional override for the WEB_AUTH_ENDPOINT parsed
///   from stellar.toml.  When `Some(url)`, the gate uses this URL for the
///   SEP-10 challenge instead of the TOML's `WEB_AUTH_ENDPOINT`.  This allows
///   tests to serve `https://...` in the TOML (passing parser validation) while
///   actually connecting to a plain-HTTP wiremock endpoint.  When `None`, the
///   TOML's `WEB_AUTH_ENDPOINT` is used as-is.
///
/// # Errors
///
/// Same variants as [`resolve_and_verify_counterparty`], except:
/// - `HomeDomainInvalid` is NOT returned (LDH check bypassed).
///
/// # Panics
///
/// Never panics.
#[cfg(any(test, feature = "test-helpers"))]
pub async fn resolve_and_verify_counterparty_at(
    home_domain: &str,
    network_passphrase: &str,
    toml_base_url: &str,
    http: &reqwest::Client,
    web_auth_override: Option<&str>,
) -> Result<VerifiedCounterpartySession, IdentityError> {
    run_gate_with_override(
        home_domain,
        network_passphrase,
        Some(http),
        Some(toml_base_url),
        web_auth_override,
    )
    .await
}

// ─────────────────────────────────────────────────────────────────────────────
// run_gate — shared implementation
// ─────────────────────────────────────────────────────────────────────────────

/// Internal gate runner shared by the production entry point and the test seam.
///
/// When `toml_base_url_override` is `None` (production path), synthesises
/// `https://{home_domain}/.well-known/stellar.toml` and validates the
/// home_domain as a valid LDH FQDN first.
///
/// When `toml_base_url_override` is `Some(base)` (test seam path), uses
/// `{base}/.well-known/stellar.toml` directly and bypasses LDH validation.
///
/// When `web_auth_endpoint_override` is `Some(url)`, overrides the parsed
/// WEB_AUTH_ENDPOINT for the SEP-10 challenge step.  This allows test
/// stellar.tomls to contain `https://` WEB_AUTH_ENDPOINT (passing parser
/// validation) while actually directing Sep10 calls to a plain-HTTP server.
/// Always `None` in production; `Some(...)` only in the test seam.
async fn run_gate_with_override(
    home_domain: &str,
    network_passphrase: &str,
    http: Option<&reqwest::Client>,
    toml_base_url_override: Option<&str>,
    web_auth_endpoint_override: Option<&str>,
) -> Result<VerifiedCounterpartySession, IdentityError> {
    // ── Step 1: Fetch stellar.toml ────────────────────────────────────────────
    let (body, toml_authority) = if let Some(base) = toml_base_url_override {
        // Test-seam path: use the provided base URL, bypass LDH validation.
        let toml_url = format!("{base}/.well-known/stellar.toml");
        let auth = authority_hint(&toml_url);
        debug!(authority = %auth, "x402-identity[test]: fetching stellar.toml at override URL");

        // Manually fetch from the override URL (not via fetch_stellar_toml which
        // enforces LDH validation and `https://` prefix). This test-only path
        // intentionally OMITS the `text/*` content-type check + 64 KiB body cap
        // that fetch_stellar_toml enforces on the production path — those
        // fetch-layer invariants are owned + tested in `stellar-agent-network`;
        // this seam exists only to exercise the gate orchestration.
        // The test seam always supplies an http client alongside the override.
        let Some(http) = http else {
            return Err(IdentityError::TomlFetchFailed {
                authority: auth.clone(),
                reason: "test-seam override requires an http client".to_owned(),
            });
        };
        let resp = http.get(&toml_url).send().await.map_err(|_e| {
            warn!(authority = %auth, "x402-identity[test]: stellar.toml fetch failed");
            IdentityError::HomeDomainUnresolvable {
                authority: auth.clone(),
            }
        })?;

        if !resp.status().is_success() {
            warn!(authority = %auth, status = %resp.status(), "x402-identity[test]: non-200 stellar.toml");
            return Err(IdentityError::HomeDomainUnresolvable {
                authority: auth.clone(),
            });
        }

        let text = resp
            .text()
            .await
            .map_err(|_| IdentityError::TomlFetchFailed {
                authority: auth.clone(),
                reason: "body read failed".to_owned(),
            })?;
        (text, auth)
    } else {
        // Production path: validate home_domain as LDH FQDN, then use
        // fetch_stellar_toml (which enforces HTTPS + no-redirect + cap).
        let toml_url = format!("https://{home_domain}/.well-known/stellar.toml");
        let auth = authority_hint(&toml_url);

        debug!(authority = %auth, "x402-identity: fetching stellar.toml");

        let body = fetch_stellar_toml(home_domain).await.map_err(|e| {
            warn!(authority = %auth, "x402-identity: stellar.toml fetch failed");
            match e {
                // HomeDomainInvalid = caller-input error; distinct from network failure.
                CounterpartyError::HomeDomainInvalid { detail } => {
                    IdentityError::HomeDomainInvalid { detail }
                }
                // FetchFailed = network / HTTP error → reachability failure.
                CounterpartyError::FetchFailed { .. } => IdentityError::HomeDomainUnresolvable {
                    authority: auth.clone(),
                },
                // Forward-compatibility fallback: `CounterpartyError` is
                // `#[non_exhaustive]`. For the current `fetch_stellar_toml`, only
                // `HomeDomainInvalid` and `FetchFailed` (handled above) are
                // produced; any future variant maps to a fetch failure.
                other => IdentityError::TomlFetchFailed {
                    authority: auth.clone(),
                    reason: other.to_string(),
                },
            }
        })?;
        (body, auth)
    };

    // ── Step 2: Parse stellar.toml ────────────────────────────────────────────
    let sep1 = parse_minimal_sep1(&body).map_err(|e| {
        warn!(authority = %toml_authority, "x402-identity: stellar.toml parse failed");
        IdentityError::TomlFetchFailed {
            authority: toml_authority.clone(),
            reason: e.to_string(),
        }
    })?;

    // ── Step 2 (cont.): Extract ACCOUNTS for payTo-anchoring signal ──────────
    // Extracted before the field moves below consume `sep1`.
    // Empty when stellar.toml omits ACCOUNTS; see VerifiedCounterpartySession::accounts
    // for semantics.
    let sep1_accounts = sep1.accounts.clone();

    // ── Step 3: Extract WEB_AUTH_ENDPOINT ────────────────────────────────────
    let web_auth_endpoint = sep1.web_auth_endpoint.ok_or_else(|| {
        warn!(home_domain = %home_domain, "x402-identity: stellar.toml missing WEB_AUTH_ENDPOINT");
        IdentityError::WebAuthEndpointMissing {
            home_domain: home_domain.to_owned(),
        }
    })?;

    // ── Step 3 (cont.): Extract SIGNING_KEY ──────────────────────────────────
    let signing_key = sep1.signing_key.ok_or_else(|| {
        warn!(home_domain = %home_domain, "x402-identity: stellar.toml missing SIGNING_KEY");
        IdentityError::SigningKeyMissing {
            home_domain: home_domain.to_owned(),
        }
    })?;

    // ── Step 4: SSRF same-domain bind ─────────────────────────────────────────
    // Validates WEB_AUTH_ENDPOINT host == home_domain or a subdomain.  Inlined
    // because the error type is crate-specific (IdentityError) and this crate
    // does not take an anchor crate dependency.
    // The home_domain FQDN guard before the suffix comparison defends against
    // degenerate domains (e.g. "" → "." that matches any host).
    //
    // The bind ALWAYS checks the TOML's WEB_AUTH_ENDPOINT (not the override),
    // so the test seam's SSRF tests still catch mismatches from the TOML value.
    validate_web_auth_endpoint_host(&web_auth_endpoint, home_domain)?;

    // ── Apply web_auth_endpoint_override (test seam only) ──────────────────
    // When the test seam provides a web_auth_override, use it for the Sep10
    // challenge instead of the TOML's WEB_AUTH_ENDPOINT.  This allows tests
    // to put `https://...` in the TOML (passing parser HTTPS validation) while
    // directing the Sep10 call to the wiremock's plain-HTTP endpoint.
    // The SSRF bind above already ran on the TOML value; the override is only
    // applied AFTER the bind check passes.
    let web_auth_endpoint = web_auth_endpoint_override
        .map(str::to_owned)
        .unwrap_or(web_auth_endpoint);

    // ── Step 5: SEP-10 ephemeral challenge/response ───────────────────────────
    // auth_with_ephemeral_key:
    //   1. Generates fresh SigningKey via OsRng (ZeroizeOnDrop on drop).
    //   2. Derives ephemeral account G-key (not on-chain; unfunded).
    //   3. fetch_challenge_verified: 13-point SEP-10 validation + server-key check.
    //   4. Signs challenge with ephemeral key.
    //   5. Submits → Sep10Session { jwt, sub, iss, exp, ... }.
    //   6. ephemeral_key drops → ZeroizeOnDrop zeroes key bytes.
    // The ephemeral key is not persisted, not funded, and not the payment signer.
    //
    // Test-seam path: when toml_base_url_override is Some(...) we are in test mode
    // and may need to reach a plain-HTTP wiremock server.  Use new_for_unit_test
    // which omits https_only(true).  This is safe because new_for_unit_test is
    // only compiled under cfg(any(test, feature = "test-helpers")).
    #[cfg(not(any(test, feature = "test-helpers")))]
    let sep10_client = Sep10Client::new(network_passphrase).map_err(|e| {
        warn!("x402-identity: Sep10Client::new failed: {e}");
        IdentityError::Sep10AuthFailed {
            reason: e.to_string(),
        }
    })?;
    #[cfg(any(test, feature = "test-helpers"))]
    let sep10_client = if toml_base_url_override.is_some() {
        // Test-seam: plain-HTTP client for wiremock.
        Sep10Client::new_for_unit_test(network_passphrase).map_err(|e| {
            warn!("x402-identity[test]: Sep10Client::new_for_unit_test failed: {e}");
            IdentityError::Sep10AuthFailed {
                reason: e.to_string(),
            }
        })?
    } else {
        Sep10Client::new(network_passphrase).map_err(|e| {
            warn!("x402-identity: Sep10Client::new failed: {e}");
            IdentityError::Sep10AuthFailed {
                reason: e.to_string(),
            }
        })?
    };

    debug!(
        authority = %authority_hint(&web_auth_endpoint),
        home_domain = %home_domain,
        "x402-identity: starting SEP-10 ephemeral auth",
    );

    let session = auth_with_ephemeral_key(
        &sep10_client,
        &web_auth_endpoint,
        home_domain,
        &signing_key,
        None, // web_auth_domain: default to the endpoint host
    )
    .await
    .map_err(|e| {
        // Sep10Error Display is redaction-safe (no key material, no JWT in errors).
        warn!(
            authority = %authority_hint(&web_auth_endpoint),
            home_domain = %home_domain,
            "x402-identity: SEP-10 auth failed",
        );
        IdentityError::Sep10AuthFailed {
            reason: e.to_string(),
        }
    })?;

    debug!(
        home_domain = %home_domain,
        // NEVER log session.jwt here — JWT material must not appear in logs.
        "x402-identity: SEP-10 auth succeeded; JWT obtained",
    );

    Ok(VerifiedCounterpartySession {
        jwt: session.jwt.clone(),
        sub: session.sub.clone(),
        home_domain: home_domain.to_owned(),
        // Carry the verified domain's declared accounts for downstream
        // payTo-anchoring checks.
        // Empty when stellar.toml omits ACCOUNTS — see field rustdoc.
        accounts: sep1_accounts,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// SSRF same-domain bind helper
// ─────────────────────────────────────────────────────────────────────────────

/// Strips the port from a host-or-host:port string.
///
/// Returns the host portion only (`"example.com"` from `"example.com"`,
/// `"127.0.0.1"` from `"127.0.0.1:8080"`).  If there is no `:`, returns the
/// input unchanged.  Used to normalise `home_domain` before comparing against
/// the URL's `host_str()` (which never includes the port).
fn strip_port(host_and_maybe_port: &str) -> &str {
    // IPv6 addresses are already handled by the URL parser (they appear as [::1]
    // in host_str(), not "::1:PORT").  For our purposes a simple rfind(':') is
    // sufficient because home_domain in production is always a DNS name (no ':')
    // and in the test seam is "127.0.0.1:PORT" (a simple IPv4:port).
    if let Some(colon_pos) = host_and_maybe_port.rfind(':') {
        let after = &host_and_maybe_port[colon_pos + 1..];
        // Only treat as port if everything after the colon is ASCII digits.
        if !after.is_empty() && after.bytes().all(|b| b.is_ascii_digit()) {
            return &host_and_maybe_port[..colon_pos];
        }
    }
    host_and_maybe_port
}

/// Returns `true` if `host` is a public FQDN suitable for the same-domain
/// suffix bind: a valid lowercase LDH domain with at least two labels, not an IP
/// address, and not an all-numeric dotted string.
///
/// A single-label host (e.g. `"com"`) or an IP/numeric host would make the
/// `".{host}"` suffix bind degenerate to a TLD-wide or always-true match, so
/// such hosts return `false` and the caller falls back to an exact-match bind.
fn is_public_fqdn(host: &str) -> bool {
    // Reject IP addresses.
    if host.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }
    // Reject purely numeric dotted strings.
    let all_labels_numeric = host
        .split('.')
        .all(|label| !label.is_empty() && label.bytes().all(|b| b.is_ascii_digit()));
    if all_labels_numeric {
        return false;
    }
    // Require at least two labels (an interior dot).
    if host.split('.').filter(|l| !l.is_empty()).count() < 2 {
        return false;
    }
    // Require valid LDH syntax.
    is_valid_ldh_home_domain(host)
}

/// Validates that `web_auth_endpoint` host is `home_domain` or a subdomain.
///
/// The `WEB_AUTH_ENDPOINT` is resolved from `stellar.toml` which is
/// attacker-influenced — a malicious operator could set `WEB_AUTH_ENDPOINT` to
/// an arbitrary host.  The bind prevents SSRF by requiring the endpoint host
/// to be the same registrable domain as `home_domain` or a subdomain.
///
/// # Bind logic
///
/// ```text
/// valid if: host == home_domain
///        || host.ends_with(&format!(".{home_domain}"))
/// ```
///
/// The LEADING DOT in `.{home_domain}` is load-bearing:
/// - `evil-example.com`.ends_with(`.example.com`) == `false` ← correct
/// - `auth.example.com`.ends_with(`.example.com`) == `true` ← correct
/// - `example.com` == `example.com` ← exact match covers root domain
///
/// # FQDN pre-validation of `home_domain`
///
/// Before building the suffix pattern, `home_domain` is validated as a public
/// FQDN via `is_public_fqdn` (rejects IP addresses and all-numeric hosts,
/// requires at least two labels, then defers to LDH validation).  An empty,
/// single-label, or IP-style domain would produce a degenerate suffix (e.g.
/// `""` → `"."` that matches
/// any host ending in `.`).  In the test-seam path the domain may be an IP
/// address; this falls back to a direct string match only.
///
/// # Errors
///
/// - [`IdentityError::WebAuthEndpointHostMismatch`] when the host does not
///   match (including when the URL is unparseable or has no host).
///
/// # Panics
///
/// Never panics.
pub(crate) fn validate_web_auth_endpoint_host(
    web_auth_endpoint: &str,
    home_domain: &str,
) -> Result<(), IdentityError> {
    let parsed =
        Url::parse(web_auth_endpoint).map_err(|_| IdentityError::WebAuthEndpointHostMismatch {
            endpoint_host: "<unparseable>".to_owned(),
            home_domain: home_domain.to_owned(),
        })?;

    let host = parsed
        .host_str()
        .ok_or_else(|| IdentityError::WebAuthEndpointHostMismatch {
            endpoint_host: "<no-host>".to_owned(),
            home_domain: home_domain.to_owned(),
        })?;

    // Strip trailing dot (RFC 1034 fully-qualified form) before comparison.
    let host = host.strip_suffix('.').unwrap_or(host);

    // Extract the host-only portion of home_domain for comparison.  In production
    // home_domain is always a pure hostname (no port).  In the test-seam path
    // home_domain may be "127.0.0.1:PORT"; the URL's host_str() returns "127.0.0.1"
    // (no port), so we must strip the port from home_domain before comparing.
    // Stripping is safe: if home_domain has no ':', strip_port returns it unchanged.
    let home_domain_host = strip_port(home_domain);

    // FQDN pre-validation before building the suffix pattern.
    // A single-label, IP-style, or all-numeric domain degenerates the suffix
    // check (e.g. a single-label "com" → ".com" would match ANY *.com host).
    // When home_domain is not a public FQDN (>= 2 labels, not an IP, not
    // all-numeric, valid LDH) — including the "127.0.0.1:PORT" test-seam case —
    // fall back to an exact-match-only bind so the suffix can never widen to a
    // whole TLD.
    if !is_public_fqdn(home_domain_host) {
        let is_direct_match = host == home_domain_host;
        if !is_direct_match {
            return Err(IdentityError::WebAuthEndpointHostMismatch {
                endpoint_host: host.to_owned(),
                home_domain: home_domain.to_owned(),
            });
        }
        return Ok(());
    }

    // Same-domain bind.
    // EXACT: host == home_domain_host
    // SUBDOMAIN: host.ends_with(".{home_domain_host}") (LEADING DOT is load-bearing)
    let subdomain_suffix = format!(".{home_domain_host}");
    let is_same_or_subdomain =
        host == home_domain_host || host.ends_with(subdomain_suffix.as_str());

    if !is_same_or_subdomain {
        return Err(IdentityError::WebAuthEndpointHostMismatch {
            endpoint_host: host.to_owned(),
            home_domain: home_domain.to_owned(),
        });
    }

    Ok(())
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

    #[test]
    fn debug_redacts_jwt() {
        let jwt = "header123.payload-middle-secret.signature789".to_owned();
        let session = VerifiedCounterpartySession {
            jwt: jwt.clone(),
            sub: "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY".to_owned(),
            home_domain: "example.com".to_owned(),
            accounts: vec![],
        };
        let debug = format!("{session:?}");

        assert!(!debug.contains(&jwt), "Debug must not expose full JWT");
        assert!(
            !debug.contains(&jwt[8..jwt.len() - 8]),
            "Debug must not expose JWT middle segment: {debug}"
        );
        assert!(
            debug.contains("header12...ature789"),
            "Debug must include first-8-last-8 JWT marker: {debug}"
        );
        assert!(debug.contains("example.com"));
    }

    /// `VerifiedCounterpartySession::accounts` is populated when constructed
    /// with a non-empty list.
    #[test]
    fn session_carries_accounts_field() {
        let accounts = vec![
            "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY".to_owned(),
            "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI".to_owned(),
        ];
        let session = VerifiedCounterpartySession {
            jwt: "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJHQSJ9.sig".to_owned(),
            sub: "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY".to_owned(),
            home_domain: "example.com".to_owned(),
            accounts: accounts.clone(),
        };
        assert_eq!(
            session.accounts, accounts,
            "session.accounts must carry the declared accounts"
        );
    }

    /// `VerifiedCounterpartySession::accounts` is an empty Vec when the domain
    /// declares no accounts.
    #[test]
    fn session_accounts_empty_when_none_declared() {
        let session = VerifiedCounterpartySession {
            jwt: "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJHQSJ9.sig".to_owned(),
            sub: "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY".to_owned(),
            home_domain: "example.com".to_owned(),
            accounts: vec![],
        };
        assert!(
            session.accounts.is_empty(),
            "session.accounts must be empty when domain declares no ACCOUNTS"
        );
    }

    /// Debug of a session with accounts shows the count, not the raw G-strkey
    /// list (stable output regardless of list size).
    ///
    /// Uses a distinct account key for `accounts` vs `sub` to verify that the
    /// accounts key does NOT appear in the debug output.
    #[test]
    fn debug_shows_accounts_count_not_raw_list() {
        // A distinct G-strkey for the accounts entry — different from sub so the
        // assertion below can reliably verify accounts are NOT printed verbatim.
        let accounts_key = "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI";
        let session = VerifiedCounterpartySession {
            jwt: "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJHQSJ9.signaturex".to_owned(),
            sub: "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY".to_owned(),
            home_domain: "example.com".to_owned(),
            accounts: vec![accounts_key.to_owned()],
        };
        let debug = format!("{session:?}");
        assert!(
            debug.contains("accounts_count: 1"),
            "Debug must show accounts_count, not raw list; got: {debug}"
        );
        // The accounts G-key must NOT appear verbatim (we show count only).
        // `sub` uses a different G-key so this assertion targets the accounts entry.
        assert!(
            !debug.contains(accounts_key),
            "Debug must NOT expose raw G-strkeys in accounts; got: {debug}"
        );
    }

    // ── validate_web_auth_endpoint_host (SSRF same-domain bind) ───────────────

    /// SSRF bind — exact match: endpoint host == home_domain → accepted.
    #[test]
    fn ssrf_bind_exact_match_accepted() {
        let result = validate_web_auth_endpoint_host("https://example.com/auth", "example.com");
        assert!(
            result.is_ok(),
            "exact host match must be accepted; got: {result:?}"
        );
    }

    /// SSRF bind — subdomain match: `auth.example.com` vs `example.com` → accepted.
    #[test]
    fn ssrf_bind_subdomain_accepted() {
        let result =
            validate_web_auth_endpoint_host("https://auth.example.com/auth", "example.com");
        assert!(
            result.is_ok(),
            "auth.example.com must be accepted as a subdomain of example.com; got: {result:?}"
        );
    }

    /// SSRF bind — multi-level subdomain: `sep10.auth.example.com` vs `example.com` → accepted.
    #[test]
    fn ssrf_bind_multi_level_subdomain_accepted() {
        let result =
            validate_web_auth_endpoint_host("https://sep10.auth.example.com/auth", "example.com");
        assert!(
            result.is_ok(),
            "multi-level subdomain must be accepted; got: {result:?}"
        );
    }

    /// SSRF bind adversarial: `evil-example.com` must NOT match `example.com`.
    ///
    /// The LEADING DOT in `.{home_domain}` prevents this bypass.
    /// `evil-example.com`.ends_with(`.example.com`) == `false` ← correct.
    #[test]
    fn ssrf_bind_evil_prefix_domain_rejected() {
        let result =
            validate_web_auth_endpoint_host("https://evil-example.com/auth", "example.com");
        assert!(
            matches!(
                result,
                Err(IdentityError::WebAuthEndpointHostMismatch { .. })
            ),
            "evil-example.com must NOT match example.com; got: {result:?}"
        );
    }

    /// SSRF bind adversarial: completely different host rejected.
    #[test]
    fn ssrf_bind_different_host_rejected() {
        let result = validate_web_auth_endpoint_host("https://attacker.org/auth", "example.com");
        assert!(
            matches!(
                result,
                Err(IdentityError::WebAuthEndpointHostMismatch { .. })
            ),
            "different host must be rejected; got: {result:?}"
        );
    }

    /// SSRF bind: trailing-dot host is stripped before comparison (RFC 1034 FQDN form).
    #[test]
    fn ssrf_bind_trailing_dot_host_normalised() {
        let result = validate_web_auth_endpoint_host("https://example.com./auth", "example.com");
        assert!(
            result.is_ok(),
            "trailing-dot host must be normalised and accepted; got: {result:?}"
        );
    }

    /// SSRF bind: unparseable URL is rejected (fail-closed).
    #[test]
    fn ssrf_bind_unparseable_url_rejected() {
        let result = validate_web_auth_endpoint_host("not-a-url", "example.com");
        assert!(
            matches!(
                result,
                Err(IdentityError::WebAuthEndpointHostMismatch { .. })
            ),
            "unparseable URL must be rejected; got: {result:?}"
        );
    }

    /// SSRF bind FQDN guard: empty home_domain degenerates suffix to "." — must
    /// reject any endpoint host that doesn't directly match.
    #[test]
    fn ssrf_bind_empty_home_domain_direct_match_only() {
        // An empty home_domain fails is_public_fqdn; falls back to
        // direct string match. "anything.com" != "" so must reject.
        let result = validate_web_auth_endpoint_host("https://anything.com/auth", "");
        assert!(
            matches!(
                result,
                Err(IdentityError::WebAuthEndpointHostMismatch { .. })
            ),
            "empty home_domain must reject non-matching endpoint; got: {result:?}"
        );
    }

    // ── SSRF FQDN guard — single-label home_domain falls back to exact match ──
    //
    // A single-label home_domain (e.g. "com") fails is_public_fqdn (< 2 labels)
    // and therefore falls back to exact-match-only.  Without this guard, the
    // suffix ".com" would match ANY *.com host.  The tests below verify:
    //
    // 1. A single-label home_domain with a different endpoint host is REJECTED.
    // 2. A genuine 2-label subdomain (auth.example.com / example.com) is still
    //    ACCEPTED via the suffix bind.

    /// SSRF guard: single-label home_domain "com" — endpoint "attacker.com"
    /// must be REJECTED (exact-match fallback; "attacker.com" != "com").
    ///
    /// Without the `is_public_fqdn` guard, the suffix `".com"` would match
    /// `"attacker.com".ends_with(".com")` — accepting any *.com host.
    #[test]
    fn ssrf_bind_single_label_home_domain_falls_back_to_exact_match() {
        let result = validate_web_auth_endpoint_host("https://attacker.com/auth", "com");
        assert!(
            matches!(
                result,
                Err(IdentityError::WebAuthEndpointHostMismatch { .. })
            ),
            "single-label home_domain 'com' must reject 'attacker.com' via exact-match fallback; got: {result:?}"
        );
    }

    /// SSRF guard: genuine 2-label subdomain auth.example.com / example.com
    /// is still accepted after the `is_public_fqdn` guard passes.
    #[test]
    fn ssrf_bind_two_label_subdomain_still_accepted_after_fqdn_guard() {
        let result =
            validate_web_auth_endpoint_host("https://auth.example.com/auth", "example.com");
        assert!(
            result.is_ok(),
            "auth.example.com must be accepted as a subdomain of example.com after FQDN guard; got: {result:?}"
        );
    }
}
