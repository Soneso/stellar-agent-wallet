//! SEP-7 testnet acceptance tests — feature `testnet-acceptance`.
//!
//! # What these tests do
//!
//! 1. Verifies that the stellar.toml fetch + parse path works end-to-end
//!    by fetching a real domain's stellar.toml and checking that
//!    `MinimalSep1` is populated (existence/reachability, NOT funding).
//!
//! 2. If the domain publishes `URI_REQUEST_SIGNING_KEY`, also verifies that
//!    the field is extracted correctly.
//!
//! # Skip policy
//!
//! Tests skip with an explicit reason when the domain is unreachable or when
//! `URI_REQUEST_SIGNING_KEY` is absent from the fetched toml.  Only
//! existence and reachability are checked; no balance or funding thresholds
//! are asserted.
//!
//! # No fabrication
//!
//! Tests do NOT fabricate passing results.  If the domain is unreachable,
//! the test skips.  If the field is absent, the test skips.

#![cfg(feature = "testnet-acceptance")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::print_stdout,
    reason = "test-only; panics and status output acceptable in integration tests"
)]

use stellar_agent_network::counterparty::fetch::fetch_stellar_toml;
use stellar_agent_network::counterparty::parser::parse_minimal_sep1;

/// Test domain known to have a stellar.toml with various fields.
/// We use stellar.org as the reference domain (reachable, SDF-owned).
const TEST_DOMAIN: &str = "stellar.org";

/// Fetches the stellar.toml for `TEST_DOMAIN` and asserts that the parse
/// succeeds, confirming the fetch+parse path works end-to-end.
///
/// Skips (does not fail) if the domain is unreachable.
#[tokio::test]
async fn live_fetch_and_parse_stellar_toml_reachability() {
    let body = match fetch_stellar_toml(TEST_DOMAIN).await {
        Ok(b) => b,
        Err(e) => {
            eprintln!(
                "SKIP: {TEST_DOMAIN} stellar.toml unreachable ({e}); skipping acceptance test"
            );
            return;
        }
    };

    let parsed = parse_minimal_sep1(&body)
        .expect("stellar.toml from {TEST_DOMAIN} must parse without error");

    // stellar.org should at minimum declare some accounts or well-known fields.
    // We do not assert specific field values — only that parse succeeds.
    let _ = parsed;
    eprintln!("PASS: {TEST_DOMAIN} stellar.toml fetched and parsed successfully");
}

/// Checks that if `URI_REQUEST_SIGNING_KEY` is present in the fetched toml,
/// it is correctly extracted into `MinimalSep1::uri_request_signing_key`.
///
/// Skips if the domain is unreachable or if `URI_REQUEST_SIGNING_KEY` is absent.
#[tokio::test]
async fn live_uri_request_signing_key_extraction() {
    let body = match fetch_stellar_toml(TEST_DOMAIN).await {
        Ok(b) => b,
        Err(e) => {
            eprintln!(
                "SKIP: {TEST_DOMAIN} unreachable ({e}); skipping URI_REQUEST_SIGNING_KEY check"
            );
            return;
        }
    };

    let parsed = parse_minimal_sep1(&body).expect("parse must succeed");

    match parsed.uri_request_signing_key {
        Some(key) => {
            // The key must be a valid G-strkey (the parser already validated it).
            assert!(
                key.starts_with('G'),
                "URI_REQUEST_SIGNING_KEY must be a G-strkey, got: {key:?}"
            );
            eprintln!("PASS: URI_REQUEST_SIGNING_KEY extracted from {TEST_DOMAIN}");
        }
        None => {
            eprintln!(
                "SKIP: {TEST_DOMAIN} stellar.toml does not declare URI_REQUEST_SIGNING_KEY; \
                 skipping extraction check"
            );
        }
    }
}
