//! Testnet acceptance tests for `stellar_x402_authenticated_payment` MCP tool.
//!
//! # Feature gate
//!
//! These tests are gated behind `testnet-acceptance` (mirrors the pattern in
//! `x402_create_payment_testnet_acceptance.rs`).  Under default `cargo test`
//! (no `--features testnet-acceptance`) the file compiles but all tests are
//! compiled-out.
//!
//! ```text
//! cargo test -p stellar-agent-mcp --features testnet-acceptance \
//!   --test x402_authenticated_payment_testnet_acceptance -- --nocapture
//! ```
//!
//! # Acceptance criteria
//!
//! ## Positive leg (testnet, feature-gated)
//!
//! - `stellar_x402_authenticated_payment` with `home_domain =
//!   "testanchor.stellar.org"` and a USDC-testnet `PaymentRequirements`
//!   produces `{ paymentSignature, authorization, payer, home_domain, payTo }`.
//! - `paymentSignature` decodes to a `PaymentPayload` with
//!   `x402Version == 2`, non-empty `payload.transaction`, `accepted.scheme ==
//!   "exact"`.
//! - `authorization` is a non-empty Bearer token (`Bearer ` prefix +
//!   3 dot-separated JWT segments).
//! - `home_domain` in the response equals `"testanchor.stellar.org"`.
//! - `payTo` matches the `PaymentRequirements.payTo` from the input.
//!
//! ## Negative leg (no live-anchor dependency; compiled under `testnet-acceptance`)
//!
//! These negatives have NO live-anchor / funding dependency (they abort
//! before any successful fetch), but — like the whole file — they are compiled
//! only under `--features testnet-acceptance`. The gate-level abort-before-payment
//! contract is ALSO covered always-on by the gate integration tests.
//!
//! - `home_domain = "unreachable.stellar.invalid"` (LDH-valid,
//!   not listening) returns `isError = true` with `error ==
//!   "identity.home_domain_unresolvable"` AND NO `paymentSignature` field.
//! - `home_domain = "UPPERCASE.COM"` (LDH-invalid) returns
//!   `isError = true` with `error == "identity.home_domain_invalid"` AND NO
//!   `paymentSignature` field.
//!
//! ## Positive-leg coverage note
//!
//! The positive post-gate assertions (paymentSignature decode, Bearer JWT,
//! payTo/network echo) execute ONLY on a USDC-funded account; on a CI
//! Friendbot account `create_payment` skips at simulate (no USDC trustline,
//! contract trustline-missing error) — so this run proves the SEP-10 identity
//! GATE live, while the post-gate payment assertions are exercised separately
//! by the `create_payment` acceptance test.
//! - Abort-before-payment: neither negative case produces a
//!   `paymentSignature` or `authorization` field — the gate aborts before
//!   `create_payment` is called.
//!
//! # Distinguishable skip reasons (positive leg)
//!
//! The positive testnet leg prints one of:
//! - `[SKIP-WITH-REASON] testanchor SEP-10 unavailable: ...`
//! - `[SKIP-WITH-REASON] testnet RPC unreachable: ...`
//! - `[SKIP-WITH-REASON] USDC trustline absent (Friendbot account)`
//!
//! Skip gates check existence/reachability, NOT funding thresholds.
//!
//! # Key discipline
//!
//! Fresh ed25519 keypair generated per test via `rand_core::OsRng`.  The keypair
//! is Friendbot-funded before use.  No committed `S...` seeds appear in source.

#![cfg(feature = "testnet-acceptance")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    reason = "test-only; panics, unwraps, and eprintln are acceptable in testnet acceptance tests"
)]

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use serial_test::serial;
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_mcp::server::{WalletServer, X402AuthenticatedPaymentArgs};
use stellar_agent_test_support::keyring_mock;
use stellar_agent_x402::wire::PaymentPayload;
use zeroize::Zeroizing;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";
const TESTNET_FRIENDBOT_URL: &str = "https://friendbot.stellar.org";
const TESTNET_CHAIN_ID: &str = "stellar:testnet";

/// SDF reference anchor with SEP-10 endpoint.
///
/// Confirmed to have `WEB_AUTH_ENDPOINT` + `SIGNING_KEY` in its `stellar.toml`.
/// This is the only live testnet anchor whose SEP-10 endpoint is a stable
/// CI-safe target.
const TESTANCHOR_HOME_DOMAIN: &str = "testanchor.stellar.org";

/// USDC SAC on testnet.
const USDC_TESTNET_SAC: &str = "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA";

/// Atomic amount: 0.0001 USDC = 1_000 atomic units (7 decimals).
///
/// Chosen to be small and unlikely to exceed any allowable range;
/// the test needs build→simulate but NOT on-chain submit.
const USDC_AMOUNT_ATOMIC: &str = "1000";

// ─────────────────────────────────────────────────────────────────────────────
// Helpers (mirrored from x402_create_payment_testnet_acceptance.rs)
// ─────────────────────────────────────────────────────────────────────────────

/// Generates a fresh ed25519 keypair using OS entropy.
///
/// Returns `(g_strkey, seed_bytes)`. Seed bytes are `Zeroizing`-wrapped so
/// they are zeroed on drop.
fn fresh_keypair() -> (String, Zeroizing<[u8; 32]>) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let g_strkey: String = stellar_strkey::ed25519::PublicKey(verifying_key.to_bytes())
        .to_string()
        .as_str()
        .to_owned();
    let seed = Zeroizing::new(signing_key.to_bytes());
    (g_strkey, seed)
}

/// Funds a testnet account via Friendbot.
///
/// Returns `Ok(())` if funding succeeded (2xx from Friendbot).
/// Returns `Err(reason)` if the HTTP request failed or returned non-2xx.
/// Does NOT panic — callers decide whether to skip or fail.
async fn try_fund_via_friendbot(g_strkey: &str) -> Result<(), String> {
    let url = format!("{TESTNET_FRIENDBOT_URL}?addr={g_strkey}");
    let resp = reqwest::get(&url)
        .await
        .map_err(|e| format!("Friendbot GET failed: {e}"))?;
    if resp.status().is_success() {
        Ok(())
    } else {
        Err(format!(
            "Friendbot returned {} for {g_strkey}",
            resp.status()
        ))
    }
}

/// Builds a `PaymentRequirements` JSON string for the given `pay_to` address.
///
/// Uses `areFeesSponsored: true` (matches the create_payment test pattern).
fn usdc_testnet_requirements(pay_to: &str) -> String {
    serde_json::json!({
        "scheme": "exact",
        "network": "stellar:testnet",
        "asset": USDC_TESTNET_SAC,
        "amount": USDC_AMOUNT_ATOMIC,
        "payTo": pay_to,
        "maxTimeoutSeconds": 300,
        "extra": { "areFeesSponsored": true }
    })
    .to_string()
}

/// Installs the keyring mock and registers `seed` under the given service.
///
/// Returns a built `WalletServer` using the registered signer with the testnet
/// RPC URL.
fn build_test_server(
    g_strkey: &str,
    seed: &Zeroizing<[u8; 32]>,
    signer_service: &str,
) -> WalletServer {
    keyring_mock::install().expect("mock keyring store init");

    let mut profile =
        Profile::builder_testnet(signer_service, g_strkey, "x402-auth-nonce-svc", "default")
            .with_noop_engine()
            .build();
    profile.rpc_url = TESTNET_RPC_URL.to_owned();

    // Store the signing key in the mock keyring under the profile's signer entry.
    let signer_ref = &profile.mcp_signer_default;
    let entry = keyring_core::Entry::new(&signer_ref.service, &signer_ref.account)
        .expect("keyring mock entry construction must succeed");
    let s_strkey = stellar_strkey::ed25519::PrivateKey::from_payload(seed.as_ref())
        .expect("32-byte seed must encode as S-strkey")
        .as_unredacted()
        .to_string();
    entry
        .set_password(&s_strkey)
        .expect("keyring mock set_password must succeed");

    WalletServer::new(profile).expect("WalletServer::new must succeed with mock keyring")
}

/// Extracts the first text item from a `CallToolResult`.
fn extract_text(result: rmcp::model::CallToolResult) -> String {
    result
        .content
        .into_iter()
        .find_map(|c| {
            if let rmcp::model::RawContent::Text(t) = c.raw {
                Some(t.text)
            } else {
                None
            }
        })
        .expect("result must contain a text content item")
}

// ─────────────────────────────────────────────────────────────────────────────
// NEGATIVE leg (always-runs, offline)
// Runs without testnet network (aborts before any successful fetch).
// ─────────────────────────────────────────────────────────────────────────────

/// Negative: unreachable domain aborts before payment.
///
/// `home_domain = "unreachable.stellar.invalid"` (LDH-valid, not listening)
/// must return `isError = true` with `error ==
/// "identity.home_domain_unresolvable"` and NO `paymentSignature`.
///
/// The gate aborts BEFORE `create_payment` is called — no transaction is
/// built/signed on failure (abort-before-payment contract).
///
/// This test has NO live-anchor / funding dependency: the domain is
/// unreachable by design (RFC 6761 `.invalid` → NXDOMAIN) and the identity
/// gate aborts immediately on the `stellar.toml` GET failing. (It is still
/// compiled under the file-level `testnet-acceptance` gate.)
#[tokio::test]
#[serial]
async fn a6f_neg1_unreachable_domain_aborts_before_payment() {
    let (g_strkey, seed) = fresh_keypair();
    // NOTE: No Friendbot funding — the gate aborts before any RPC call.
    let server = build_test_server(&g_strkey, &seed, "x402-auth-test-neg1");

    let requirements_json = usdc_testnet_requirements(&g_strkey);

    let result = server
        .call_stellar_x402_authenticated_payment(X402AuthenticatedPaymentArgs {
            payment_required: requirements_json,
            chain_id: TESTNET_CHAIN_ID.to_owned(),
            home_domain: "unreachable.stellar.invalid".to_owned(),
            address: None,
        })
        .await
        .expect("dispatch_gate must not raise ErrorData for a valid chain_id");

    // Must be an error result.
    assert_eq!(
        result.is_error,
        Some(true),
        "unreachable domain must return isError = true; got is_error = {:?}",
        result.is_error
    );

    let text = extract_text(result);
    let value: serde_json::Value =
        serde_json::from_str(&text).expect("error result must be valid JSON");

    // Error code must be the identity gate abort code — NOT an x402 error.
    // The business-error envelope nests the code at `error.code`.
    let error_code = value["error"]["code"]
        .as_str()
        .expect("error.code must be present and a string");
    assert_eq!(
        error_code, "identity.home_domain_unresolvable",
        "unreachable domain must abort with identity.home_domain_unresolvable; got: {value}"
    );

    // Abort-before-payment — no paymentSignature or authorization.
    assert!(
        value.get("paymentSignature").is_none(),
        "abort-before-payment: paymentSignature must NOT be present in the error response; got: {value:?}"
    );
    assert!(
        value.get("authorization").is_none(),
        "abort-before-payment: authorization must NOT be present in the error response; got: {value:?}"
    );

    eprintln!("PASS: unreachable domain aborts with error={error_code}, no paymentSignature");
}

/// Negative: invalid home_domain aborts before payment.
///
/// `home_domain = "UPPERCASE.COM"` (LDH-invalid — uppercase not permitted) must
/// return `isError = true` with `error == "identity.home_domain_invalid"` and
/// NO `paymentSignature`.
///
/// The gate aborts BEFORE any network I/O — `HomeDomainInvalid` is a caller-
/// input error (distinct from `HomeDomainUnresolvable`).
///
/// This test makes NO network contact (the LDH validator fires synchronously
/// before any HTTPS GET). It is still compiled under the file-level
/// `testnet-acceptance` gate.
#[tokio::test]
#[serial]
async fn a6f_neg2_invalid_home_domain_aborts_before_payment() {
    let (g_strkey, seed) = fresh_keypair();
    // NOTE: No Friendbot funding — the gate aborts before any network I/O.
    let server = build_test_server(&g_strkey, &seed, "x402-auth-test-neg2");

    let requirements_json = usdc_testnet_requirements(&g_strkey);

    let result = server
        .call_stellar_x402_authenticated_payment(X402AuthenticatedPaymentArgs {
            payment_required: requirements_json,
            chain_id: TESTNET_CHAIN_ID.to_owned(),
            home_domain: "UPPERCASE.COM".to_owned(), // uppercase LDH violation
            address: None,
        })
        .await
        .expect("dispatch_gate must not raise ErrorData for a valid chain_id");

    // Must be an error result.
    assert_eq!(
        result.is_error,
        Some(true),
        "invalid home_domain must return isError = true; got is_error = {:?}",
        result.is_error
    );

    let text = extract_text(result);
    let value: serde_json::Value =
        serde_json::from_str(&text).expect("error result must be valid JSON");

    // Error code must be the DISTINCT input-validation abort code.
    // The business-error envelope nests the code at `error.code`.
    let error_code = value["error"]["code"]
        .as_str()
        .expect("error.code must be present and a string");
    assert_eq!(
        error_code, "identity.home_domain_invalid",
        "invalid home_domain must abort with identity.home_domain_invalid (distinct from unresolvable); got: {value}"
    );

    // Abort-before-payment — no paymentSignature or authorization.
    assert!(
        value.get("paymentSignature").is_none(),
        "abort-before-payment: paymentSignature must NOT be present in the error response; got: {value:?}"
    );
    assert!(
        value.get("authorization").is_none(),
        "abort-before-payment: authorization must NOT be present in the error response; got: {value:?}"
    );

    // Also verify error codes are DISTINGUISHABLE from the unreachable-domain case.
    assert_ne!(
        error_code, "identity.home_domain_unresolvable",
        "invalid-domain error must be DISTINCT from unreachable-domain error"
    );

    eprintln!(
        "PASS: invalid home_domain aborts with error={error_code} (distinct from unresolvable), no paymentSignature"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// POSITIVE leg (testnet, gated)
// Requires live testanchor.stellar.org SEP-10 + live testnet RPC.
// ─────────────────────────────────────────────────────────────────────────────

/// Positive: full SEP-10 authenticated payment against testanchor.
///
/// Calls `stellar_x402_authenticated_payment` with `home_domain =
/// "testanchor.stellar.org"` + a USDC-testnet `PaymentRequirements`.
///
/// The PRODUCTION gate performs a REAL SEP-10 ephemeral auth against
/// testanchor's `WEB_AUTH_ENDPOINT` → JWT, then `create_payment` runs
/// build→simulate against testnet RPC.
///
/// Asserts:
/// - `paymentSignature` (base64; decodes to `PaymentPayload` with
///   `x402Version == 2` + `transaction`).
/// - `authorization` (non-empty; `Bearer <jwt>` with 3 dot-separated segments).
/// - `payer` matches the wallet address.
/// - `home_domain == "testanchor.stellar.org"`.
/// - `payTo` matches the input `PaymentRequirements.payTo`.
///
/// Skip-with-distinguishable-reason if:
/// - testanchor SEP-10 is unreachable (identity gate aborts; skip-reason logged).
/// - testnet RPC is unreachable (create_payment simulate fails; skip-reason logged).
/// - USDC trustline absent on Friendbot account (simulate returns the
///   trustline-missing contract error; skip-reason logged).
///
/// No balance checks; do NOT fabricate a pass.
#[tokio::test]
#[serial]
async fn a6f_positive_testanchor_sep10_authenticated_payment() {
    let (g_strkey, seed) = fresh_keypair();

    // Fund via Friendbot — if Friendbot is down, skip with reason.
    if let Err(reason) = try_fund_via_friendbot(&g_strkey).await {
        eprintln!("[SKIP-WITH-REASON] testnet RPC unreachable (Friendbot failed): {reason}");
        return;
    }
    eprintln!("funded {g_strkey} via Friendbot");

    let server = build_test_server(&g_strkey, &seed, "x402-auth-test-positive");

    // Use the payer's own address as payTo.
    let requirements_json = usdc_testnet_requirements(&g_strkey);

    let result = server
        .call_stellar_x402_authenticated_payment(X402AuthenticatedPaymentArgs {
            payment_required: requirements_json,
            chain_id: TESTNET_CHAIN_ID.to_owned(),
            home_domain: TESTANCHOR_HOME_DOMAIN.to_owned(),
            address: None,
        })
        .await
        .expect("dispatch_gate must not raise ErrorData for a valid chain_id");

    let is_err = result.is_error == Some(true);
    let text = extract_text(result);

    if is_err {
        let lc = text.to_lowercase();

        // testnet RPC / simulate skip (USDC trustline absent or simulate failure).
        // NOTE: checked BEFORE sep10_skip — `payment_build_failed` means SEP-10
        // succeeded but create_payment's simulate step failed (typically trustline
        // missing on a Friendbot-funded account).  This is the expected environment
        // skip for Friendbot accounts (existence/reachability, not funding amounts).
        let is_rpc_skip = lc.contains("trustline")
            || lc.contains("insufficient")
            || lc.contains("underfunded")
            || lc.contains("rpc simulate failed")
            || lc.contains("simulate returned error")
            || lc.contains("#13")
            || lc.contains("payment_build_failed")
            || lc.contains("payment build failed");

        if is_rpc_skip {
            eprintln!(
                "[SKIP-WITH-REASON] USDC trustline absent (Friendbot account) or simulate failed: {text}"
            );
            return;
        }

        // testanchor SEP-10 unavailable — identity gate aborted before payment.
        // Only matches when the error is NOT `payment_build_failed` (already handled above).
        let is_sep10_skip = lc.contains("sep-10")
            || lc.contains("sep10")
            || lc.contains("web_auth")
            || lc.contains("stellar.toml")
            || lc.contains("toml fetch")
            || lc.contains("home domain unreachable")
            || lc.contains("home domain is invalid")
            || lc.contains("signing_key")
            || lc.contains("web_auth_endpoint")
            || lc.contains("identity.home_domain")
            || lc.contains("identity.toml")
            || lc.contains("identity.signing")
            || lc.contains("identity.web_auth")
            || lc.contains("identity.sep10");

        if is_sep10_skip {
            eprintln!("[SKIP-WITH-REASON] testanchor SEP-10 unavailable: {text}");
            return;
        }

        panic!("[FAIL] authenticated_payment errored for a non-environment reason: {text}");
    }

    let value: serde_json::Value = serde_json::from_str(&text).expect("result must be valid JSON");

    // Response shape — all required fields present.
    assert!(
        value
            .get("paymentSignature")
            .and_then(|v| v.as_str())
            .is_some(),
        "paymentSignature must be present and a string; got {value:?}"
    );
    assert!(
        value
            .get("authorization")
            .and_then(|v| v.as_str())
            .is_some(),
        "authorization must be present and a string; got {value:?}"
    );
    assert_eq!(
        value.get("payer").and_then(|v| v.as_str()),
        Some(g_strkey.as_str()),
        "payer must match the wallet address"
    );
    assert_eq!(
        value.get("home_domain").and_then(|v| v.as_str()),
        Some(TESTANCHOR_HOME_DOMAIN),
        "home_domain must be echoed from the gate"
    );
    assert_eq!(
        value.get("payTo").and_then(|v| v.as_str()),
        Some(g_strkey.as_str()),
        "payTo must match the input PaymentRequirements.payTo"
    );
    assert_eq!(
        value.get("network").and_then(|v| v.as_str()),
        Some("stellar:testnet"),
        "network must be stellar:testnet"
    );

    // paymentSignature decodes to PaymentPayload with x402Version == 2.
    let payment_sig_b64 = value["paymentSignature"].as_str().unwrap();
    let payload_bytes = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD
            .decode(payment_sig_b64)
            .expect("paymentSignature must be valid standard base64")
    };
    let payload: PaymentPayload = serde_json::from_slice(&payload_bytes)
        .expect("paymentSignature must decode to PaymentPayload JSON");
    assert_eq!(payload.x402_version, 2, "x402Version must be 2");
    assert_eq!(
        payload.accepted.scheme, "exact",
        "accepted.scheme must be \"exact\""
    );
    assert!(
        !payload.payload.transaction.is_empty(),
        "payload.transaction must be non-empty base64"
    );

    // authorization is a Bearer token with 3 dot-separated JWT segments.
    let authorization = value["authorization"].as_str().unwrap();
    assert!(
        authorization.starts_with("Bearer "),
        "authorization must start with 'Bearer '; got: {authorization}"
    );
    let jwt_part = authorization.strip_prefix("Bearer ").unwrap();
    assert!(
        !jwt_part.is_empty(),
        "JWT part of authorization must be non-empty"
    );
    let segments: Vec<&str> = jwt_part.split('.').collect();
    assert_eq!(
        segments.len(),
        3,
        "JWT must have exactly 3 dot-separated segments; got {}: '{jwt_part}'",
        segments.len()
    );

    // home_domain and payTo already asserted above.

    eprintln!(
        "PASS: paymentSignature {} bytes, x402Version=2, Bearer JWT {} chars, \
         home_domain={TESTANCHOR_HOME_DOMAIN}",
        payment_sig_b64.len(),
        jwt_part.len()
    );
}
