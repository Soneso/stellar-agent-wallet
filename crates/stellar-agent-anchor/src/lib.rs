//! SEP-24 interactive hand-off and SEP-6 discovery-only anchor client.
//!
//! # What this crate does
//!
//! Provides a production-ready, privacy-first anchor client covering:
//!
//! - **SEP-6 discovery** (`sep6` module): `GET {transfer_server}/info` ONLY.
//!   Decodes the anchor's capability set + `authentication_required` flags.
//!   Structurally incapable of calling `/deposit`, `/withdraw`, or any
//!   KYC-initiating endpoint.
//!
//! - **SEP-24 interactive hand-off** (`sep24` module): obtains the anchor's
//!   interactive deposit/withdraw URL via `POST .../transactions/{op}/interactive`
//!   (with SEP-10/-45 JWT auth) and returns it to the operator for browser
//!   hand-off.  The wallet NEVER opens/scrapes/follows the URL.
//!
//! # Primary consumers
//!
//! `stellar-agent-mcp` — the two MCP tools `stellar_sep6_deposit_info` and
//! `stellar_sep24_interactive_url`.
//!
//! # What this crate does NOT do
//!
//! - Does NOT call `/deposit`, `/withdraw`, `/deposit-exchange`,
//!   `/withdraw-exchange`, `/customer` (SEP-12), `/fee`, or `/transaction(s)`.
//! - Does NOT transmit any SEP-9 KYC field.
//! - Does NOT auto-open, scrape, or follow the SEP-24 interactive URL.
//! - Does NOT perform SEP-10/-45 authentication.  The caller obtains a JWT
//!   via `stellar-agent-sep10` or `stellar-agent-sep45` and passes the raw
//!   string to [`start_sep24_interactive`].  This crate does not depend on
//!   the SEP-10/-45 session types; the JWT is treated as an opaque `&str`.
//!
//! # Same-domain SSRF bind
//!
//! Every anchor endpoint fetch is preceded by a host-validation check (see
//! `ssrf` module): the resolved `TRANSFER_SERVER*` host must equal the
//! operator-typed anchor domain OR be a subdomain of it
//! (`host.ends_with(&format!(".{anchor_domain}"))`).
//! The LEADING DOT is load-bearing — it prevents `evil-anchor.org` from
//! matching `anchor.org`.
//!
//! The `anchor_domain` itself is validated as a public FQDN before the suffix
//! comparison so that an empty or invalid domain cannot degenerate the bind.
//!
//! # Sibling crates
//!
//! - `stellar-agent-sep10` — SEP-10 web authentication (caller obtains JWT).
//! - `stellar-agent-sep45` — SEP-45 Soroban web authentication (caller obtains JWT).
//! - `stellar-agent-network` — `stellar.toml` fetch + `MinimalSep1` parser
//!   (extended with `transfer_server` + `transfer_server_sep0024`).

#![warn(missing_docs)]

pub mod error;
pub mod sep24;
pub mod sep6;

// Internal modules — not part of the public API.
pub(crate) mod client;
// ssrf is pub(crate) in production; pub when test-helpers is enabled so
// integration tests can directly call assert_same_domain_or_https_fqdn.
#[cfg(not(any(test, feature = "test-helpers")))]
pub(crate) mod ssrf;
#[cfg(any(test, feature = "test-helpers"))]
pub mod ssrf;

/// Test helpers — exposed only under `test-helpers` feature or `#[cfg(test)]`.
///
/// Test-only public helpers are gated with
/// `#[cfg(any(test, feature = "test-helpers"))]` to keep them out of the
/// production API surface.
///
/// The `ssrf` module is made public under `test-helpers` (see `lib.rs`), so
/// integration tests can call
/// `stellar_agent_anchor::ssrf::assert_same_domain_or_https_fqdn` directly.
///
/// `AnchorClient::new_without_https_enforcement` is exposed here for wiremock
/// integration tests that target a local HTTP server.  Production code must
/// use `AnchorClient::new()`.
#[cfg(any(test, feature = "test-helpers"))]
pub mod test_helpers {
    // Re-exports the same-domain SSRF bind for adversarial integration tests.
    pub use crate::ssrf::assert_same_domain_or_https_fqdn;

    // Re-exports the test-only HTTP-capable constructor for wiremock tests.
    pub use crate::client::AnchorClient;
}

// Re-export the primary public surface.
pub use error::AnchorError;
pub use sep6::{AssetInfo, Features, Sep6Info, get_sep6_info};
pub use sep24::{Sep24InteractiveResult, Sep24Operation, Sep24Params, start_sep24_interactive};

/// Test-helper re-exports — available under `test-helpers` feature or `#[cfg(test)]`.
#[cfg(any(test, feature = "test-helpers"))]
pub use sep24::parse_interactive_response;
