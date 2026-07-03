//! Live acceptance test for the SEP-10 counterparty-identity gate.
//!
//! Drives the production [`resolve_and_verify_counterparty`] against the SDF
//! testnet anchor (`testanchor.stellar.org`) over a live network connection,
//! exercising every gate step end-to-end: fetch `stellar.toml` -> parse ->
//! extract `WEB_AUTH_ENDPOINT` / `SIGNING_KEY` -> same-domain SSRF bind ->
//! SEP-10 ephemeral-key challenge/response -> verified JWT session.
//!
//! Gated behind the `testnet-acceptance` feature; if the anchor is unreachable
//! the test skips with a reason rather than failing.
//!
//! ```text
//! cargo test -p stellar-agent-x402-identity --features testnet-acceptance \
//!   --test sep10_gate_testnet_acceptance
//! ```

#![cfg(feature = "testnet-acceptance")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    reason = "test-only; panics, unwraps, and eprintln are acceptable in live acceptance tests"
)]

use stellar_agent_x402_identity::{IdentityError, resolve_and_verify_counterparty};

const HOME_DOMAIN: &str = "testanchor.stellar.org";
const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
const TOML_URL: &str = "https://testanchor.stellar.org/.well-known/stellar.toml";

/// Returns `true` if the anchor's `stellar.toml` is reachable.
async fn anchor_reachable() -> bool {
    let Ok(client) = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(12))
        .build()
    else {
        return false;
    };
    client
        .head(TOML_URL)
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}

/// Live gate: resolves the testnet anchor's identity via SEP-10 and yields a
/// JWT-bearing verified session.
///
/// The ephemeral SEP-10 key is unfunded and per-request; the JWT `sub` is the
/// ephemeral G-key. Reaching a verified session proves the gate's fetch ->
/// parse -> bind -> SEP-10 challenge/response/JWT-validation pipeline against a
/// real anchor.
#[tokio::test]
async fn live_gate_verifies_testanchor_identity() {
    if !anchor_reachable().await {
        eprintln!("[LIVE SKIP-WITH-REASON] {HOME_DOMAIN} unreachable; skipping live gate");
        return;
    }

    let result = resolve_and_verify_counterparty(HOME_DOMAIN, TESTNET_PASSPHRASE).await;

    match result {
        Ok(session) => {
            assert!(!session.jwt.is_empty(), "JWT must be non-empty");
            assert!(
                session.sub.starts_with('G') && session.sub.len() == 56,
                "sub must be a G-strkey, got {:?}",
                session.sub
            );
            assert_eq!(session.home_domain, HOME_DOMAIN);
            eprintln!(
                "[LIVE PASS] gate verified {HOME_DOMAIN}: sub={}...{}, jwt_len={}, accounts={}",
                &session.sub[..5],
                &session.sub[session.sub.len() - 5..],
                session.jwt.len(),
                session.accounts.len(),
            );
        }
        Err(IdentityError::HomeDomainUnresolvable { .. }) => {
            eprintln!("[LIVE SKIP-WITH-REASON] anchor became unreachable mid-flow; skipping");
        }
        Err(other) => {
            panic!("[LIVE FAIL] gate must verify the testnet anchor identity; got: {other}");
        }
    }
}
