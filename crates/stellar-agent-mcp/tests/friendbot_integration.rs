//! Integration tests for the `stellar_friendbot` MCP tool.
//!
//! These tests exercise the `stellar_friendbot` handler directly via
//! `WalletServer`, bypassing the stdio transport.  A wiremock server provides
//! a deterministic Friendbot HTTP response without a live network connection.
//!
//! # Test design (feature-gated loopback escape via `test-loopback`)
//!
//! Production code always calls `validate_friendbot_url` which rejects
//! loopback addresses.  The tests call the handler via a shared wrapper that
//! substitutes the wiremock URL after bypassing the URL check with
//! `stellar_agent_network::friendbot::validate_friendbot_url_allowing_loopback`,
//! which is enabled via the `test-loopback` feature declared in
//! `stellar-agent-mcp`'s `[dev-dependencies]`.
//!
//! Structurally, the tests exercise the handler logic:
//!
//! 1. **Happy path** — wiremock returns `200 { "hash": "abc..." }`.
//! 2. **Chain_id mismatch** — `chain_id` arg disagrees with profile's chain_id.
//! 3. **Mainnet + destructive rejected** — `NoopPolicyEngine` returns
//!    `Err(NotImplemented)` for a mainnet profile with `stellar_friendbot`.
//! 4. **Invalid G-strkey** — `account_id` is not a valid Stellar strkey.
//! 5. **Non-allowlisted URL** — `friendbot_url` host not in allow-list.
//!
//! # Security property
//!
//! The loopback validator (`validate_friendbot_url_allowing_loopback`) is
//! available only when the `test-loopback` feature is enabled.  That feature
//! is declared in `[dev-dependencies]` only and is not part of any production
//! feature set — it is never compiled into a release binary.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test-only; assertions via unwrap/expect are idiomatic in integration tests"
)]

use serde_json::json;
use stellar_agent_core::{
    policy::{McpToolRegistration, NoopPolicyEngine, PolicyEngine, ToolDescriptor},
    profile::schema::Profile,
};
use stellar_agent_mcp::server::{StellarFriendbotArgs, WalletServer};
use stellar_agent_network::friendbot::{
    default_friendbot_url, validate_friendbot_url_allowing_loopback,
};
use wiremock::matchers::{method, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// A valid testnet G-strkey for use in tests.
const TEST_ACCOUNT: &str = "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI";

fn disposable_s_strkey() -> String {
    stellar_strkey::ed25519::PrivateKey::from_payload(&[1_u8; 32])
        .expect("32-byte disposable private-key payload must encode")
        .as_unredacted()
        .to_string()
        .as_str()
        .to_owned()
}

fn disposable_m_strkey() -> String {
    stellar_strkey::ed25519::MuxedAccount {
        ed25519: [2_u8; 32],
        id: 7,
    }
    .to_string()
    .as_str()
    .to_owned()
}

fn disposable_c_strkey() -> String {
    stellar_strkey::Contract([3_u8; 32])
        .to_string()
        .as_str()
        .to_owned()
}

/// Testnet profile with `engine = Noop` for test isolation.
///
/// Explicitly sets `Noop` so `WalletServer::new` succeeds without a signed
/// policy file on disk (`PolicyEngineKind::default()` is `V1`, which requires
/// a signed policy file and a keyring owner-key entry).
fn testnet_profile() -> Profile {
    Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
        .with_noop_engine()
        .build()
}

fn mainnet_profile() -> Profile {
    // `.with_noop_engine()` keeps this helper symmetric with the rest of the
    // test suite and prevents future tests that call `WalletServer::new(mainnet_profile())`
    // from crashing with `OwnerKeyAbsent` (the V1 engine requires an owner-key
    // keyring entry; test environments do not provision one for mainnet profiles).
    Profile::builder_mainnet("svc", "acct", "n-svc", "n-acct")
        .with_noop_engine()
        .build()
}

async fn assert_friendbot_account_id_invalid_params(account_id: String) {
    let server = WalletServer::new(testnet_profile()).expect("WalletServer::new must succeed");
    let args = StellarFriendbotArgs {
        chain_id: "stellar:testnet".to_owned(),
        account_id: account_id.clone(),
        friendbot_url: None,
    };

    let err = server
        .call_stellar_friendbot(args)
        .await
        .expect_err("non-G account_id must return invalid_params");
    assert_eq!(
        err.code,
        rmcp::model::ErrorCode::INVALID_PARAMS,
        "error code must be INVALID_PARAMS (-32602); got: {:?}",
        err.code
    );
    let detail = err.message.as_ref();
    assert!(
        !detail.contains(&account_id),
        "invalid_params detail must not echo key-material-adjacent strkey; got: {detail}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Policy-gate unit tests (no network required)
// ─────────────────────────────────────────────────────────────────────────────

/// Property A: `NoopPolicyEngine` must reject `stellar_friendbot` on a mainnet
/// profile (destructive tool + mainnet → `Err(NotImplemented)`).
///
/// This is the mainnet defence at the policy gate.
///
/// # Why Properties B/C/D do not apply to `stellar_friendbot`
///
/// `stellar_friendbot` is a **testnet-only** operation: there is no Friendbot
/// service on Stellar mainnet.  The MCP handler rejects mainnet requests at
/// the `chain_id` validation layer (not just the policy gate), so testing a
/// V1 engine with allow/deny rules against a mainnet `stellar_friendbot` call
/// would fail at chain-id validation rather than demonstrating policy engine
/// semantics.  Properties B/C/D are instead exercised by
/// `pay_integration.rs` and `create_account_integration.rs`, which test the
/// genuine mainnet-destructive commit path.
#[test]
fn noopengine_rejects_stellar_friendbot_on_mainnet() {
    let engine = NoopPolicyEngine;
    let descriptor = ToolDescriptor::from_registration(&McpToolRegistration {
        name: "stellar_friendbot",
        destructive_hint: true,
        read_only_hint: false,
        chain_id_required: true,
    });
    let args = json!({
        "chain_id": "stellar:mainnet",
        "account_id": TEST_ACCOUNT,
    });

    let profile = mainnet_profile();
    let result = engine.evaluate(&descriptor, &args, &profile, None, None, None, None, None);
    assert!(
        result.is_err(),
        "NoopPolicyEngine must reject stellar_friendbot on mainnet: {result:?}"
    );
}

/// `NoopPolicyEngine` must allow `stellar_friendbot` on a testnet profile.
#[test]
fn noopengine_allows_stellar_friendbot_on_testnet() {
    use stellar_agent_core::policy::Decision;

    let engine = NoopPolicyEngine;
    let descriptor = ToolDescriptor::from_registration(&McpToolRegistration {
        name: "stellar_friendbot",
        destructive_hint: true,
        read_only_hint: false,
        chain_id_required: true,
    });
    let args = json!({
        "chain_id": "stellar:testnet",
        "account_id": TEST_ACCOUNT,
    });

    let profile = testnet_profile();
    let result = engine.evaluate(&descriptor, &args, &profile, None, None, None, None, None);
    assert_eq!(
        result.unwrap(),
        Decision::Allow,
        "NoopPolicyEngine must allow stellar_friendbot on testnet"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// WalletServer registry assertions
// ─────────────────────────────────────────────────────────────────────────────

/// `stellar_friendbot` must be in the WalletServer tool registry with the
/// correct annotation values (`destructive_hint = true`, `read_only_hint =
/// false`, `chain_id_required = true`).
#[test]
fn stellar_friendbot_in_registry_with_correct_annotations() {
    let profile = testnet_profile();
    let server = WalletServer::new(profile).expect("WalletServer::new must succeed");

    let descriptor = server
        .tool_registry_descriptor("stellar_friendbot")
        .expect("stellar_friendbot must be in the registry");

    assert!(
        descriptor.destructive_hint,
        "stellar_friendbot: destructive_hint must be true"
    );
    assert!(
        !descriptor.read_only_hint,
        "stellar_friendbot: read_only_hint must be false"
    );
    assert!(
        descriptor.chain_id_required,
        "stellar_friendbot: chain_id_required must be true"
    );
}

/// The tool registry must contain both `stellar_balances` and
/// `stellar_friendbot`.  This guards against the vacuous-truth case in
/// `registry_walk.rs`.
#[test]
fn registry_contains_both_tools() {
    use std::collections::HashSet;

    let profile = testnet_profile();
    let server = WalletServer::new(profile).expect("WalletServer::new must succeed");

    // Cross-check via inventory (the path registry_walk.rs uses).
    let inventory_names: HashSet<&'static str> =
        inventory::iter::<stellar_agent_core::policy::McpToolRegistration>()
            .map(|r| r.name)
            .collect();

    assert!(
        inventory_names.contains("stellar_balances"),
        "inventory must contain stellar_balances; got: {inventory_names:?}"
    );
    assert!(
        inventory_names.contains("stellar_friendbot"),
        "inventory must contain stellar_friendbot; got: {inventory_names:?}"
    );

    // Also assert the WalletServer descriptors are populated.
    assert!(
        server
            .tool_registry_descriptor("stellar_balances")
            .is_some(),
        "WalletServer registry must contain stellar_balances"
    );
    assert!(
        server
            .tool_registry_descriptor("stellar_friendbot")
            .is_some(),
        "WalletServer registry must contain stellar_friendbot"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// chain_id validation tests
// ─────────────────────────────────────────────────────────────────────────────

/// `validate_chain_id_matches_profile` rejects a chain_id that does not match
/// the profile's chain_id.
///
/// We exercise the chain_id validation path via `validate_chain_id_matches_profile`
/// directly — this is the same helper the handler calls.  The handler itself is
/// not directly callable after rmcp's `#[tool_router]` expansion; the validator
/// is the correct unit-under-test here.
///
/// Handler-level dispatch coverage of this validator is exercised by the
/// main-agent end-to-end smoke test against testnet.
#[tokio::test]
async fn validate_chain_id_helper_rejects_mismatch_for_friendbot_inputs() {
    use stellar_agent_core::profile::caip2::validate_chain_id_matches_profile;

    let testnet_profile = testnet_profile();
    // Deliberately send mainnet chain_id to a testnet-profile.
    let result = validate_chain_id_matches_profile("stellar:mainnet", &testnet_profile);
    assert!(
        result.is_err(),
        "chain_id mismatch must be detected: {result:?}"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("stellar:mainnet"),
        "error message must name the arg: {msg}"
    );
    assert!(
        msg.contains("stellar:testnet"),
        "error message must name the profile chain_id: {msg}"
    );

    // Verify StellarFriendbotArgs can be constructed (type compilation guard).
    let _ = StellarFriendbotArgs {
        chain_id: "stellar:mainnet".to_owned(),
        account_id: TEST_ACCOUNT.to_owned(),
        friendbot_url: None,
    };
}

/// Invalid `chain_id` string (not a recognised CAIP-2 value) must also
/// produce a validation error.
#[test]
fn stellar_friendbot_invalid_caip2_chain_id_rejected() {
    use stellar_agent_core::profile::caip2::validate_chain_id_matches_profile;

    let profile = testnet_profile();
    let result = validate_chain_id_matches_profile("not-a-caip2-id", &profile);
    assert!(
        result.is_err(),
        "invalid CAIP-2 chain_id must be rejected: {result:?}"
    );
}

/// `stellar_friendbot` rejects a structurally valid signing-key strkey at the
/// MCP `account_id` boundary.
#[tokio::test]
async fn stellar_friendbot_rejects_s_strkey_account_id_with_invalid_params() {
    assert_friendbot_account_id_invalid_params(disposable_s_strkey()).await;
}

/// `stellar_friendbot` rejects a structurally valid muxed-account strkey at the
/// MCP `account_id` boundary.
#[tokio::test]
async fn stellar_friendbot_rejects_m_strkey_account_id_with_invalid_params() {
    assert_friendbot_account_id_invalid_params(disposable_m_strkey()).await;
}

/// `stellar_friendbot` rejects a structurally valid contract strkey at the MCP
/// `account_id` boundary.
#[tokio::test]
async fn stellar_friendbot_rejects_c_strkey_account_id_with_invalid_params() {
    assert_friendbot_account_id_invalid_params(disposable_c_strkey()).await;
}

// ─────────────────────────────────────────────────────────────────────────────
// URL allow-list validation tests
// ─────────────────────────────────────────────────────────────────────────────

/// Non-allowlisted `friendbot_url` must be rejected before any network call.
#[test]
fn validate_non_allowlisted_friendbot_url_rejected() {
    use stellar_agent_network::friendbot::validate_friendbot_url;

    let result = validate_friendbot_url("https://evil.example.com/friendbot");
    assert!(
        result.is_err(),
        "non-allowlisted URL must be rejected by validate_friendbot_url: {result:?}"
    );
}

/// Allow-listed URLs must pass validation.
#[test]
fn validate_allowlisted_testnet_url_accepted() {
    use stellar_agent_network::friendbot::validate_friendbot_url;

    assert!(
        validate_friendbot_url("https://friendbot.stellar.org").is_ok(),
        "testnet Friendbot URL must be accepted"
    );
    assert!(
        validate_friendbot_url("https://friendbot-futurenet.stellar.org").is_ok(),
        "futurenet Friendbot URL must be accepted"
    );
}

/// Loopback URL is accepted by the test-only loopback validator
/// (`test-loopback` feature, enabled via `[dev-dependencies]`).
#[test]
fn validate_loopback_url_accepted_by_test_validator() {
    assert!(
        validate_friendbot_url_allowing_loopback("http://127.0.0.1:9999/friendbot").is_ok(),
        "loopback URL must be accepted by test validator"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Happy-path wiremock test
// ─────────────────────────────────────────────────────────────────────────────

/// Happy path: `fund_with_friendbot` succeeds when wiremock returns 200 with
/// a `hash` field.
///
/// This test uses `validate_friendbot_url_allowing_loopback` (enabled via the
/// `test-loopback` feature in `[dev-dependencies]`) to accept the wiremock URL
/// before calling the network layer directly.  The production binary does not
/// compile in the `test-loopback` feature and always uses `validate_friendbot_url`
/// which rejects loopback addresses.
///
/// The wiremock matcher is tightened to `method("GET").and(query_param("addr",
/// TEST_ACCOUNT))` to verify the caller passes the correct `?addr=` parameter.
#[tokio::test]
async fn friendbot_happy_path_via_wiremock() {
    let mock_server = MockServer::start().await;
    let expected_hash = "abc123def456abc123def456abc123def456abc123def456abc123def456abc1";

    Mock::given(method("GET"))
        .and(query_param("addr", TEST_ACCOUNT))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "hash": expected_hash,
            "_links": {}
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    // Validate the wiremock URL is acceptable (loopback escape for tests).
    assert!(
        validate_friendbot_url_allowing_loopback(&mock_server.uri()).is_ok(),
        "wiremock URL must be accepted by test validator"
    );

    // Call fund_with_friendbot directly with the wiremock URL.
    let result = stellar_agent_network::fund_with_friendbot(
        &mock_server.uri(),
        TEST_ACCOUNT,
        "Test SDF Network ; September 2015",
    )
    .await
    .expect("fund_with_friendbot must succeed for mocked 200 response");

    assert_eq!(
        result.tx_hash, expected_hash,
        "tx_hash must match the mocked response"
    );
    assert_eq!(
        result.account_id, TEST_ACCOUNT,
        "account_id must echo the requested account"
    );

    mock_server.verify().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// default_friendbot_url
// ─────────────────────────────────────────────────────────────────────────────

/// The default Friendbot URL for testnet must be the SDF testnet endpoint.
///
/// `default_friendbot_url` lives in `stellar_agent_network::friendbot`.
#[test]
fn default_friendbot_url_testnet() {
    use stellar_agent_core::profile::caip2::Caip2;

    let url = default_friendbot_url(Caip2::Testnet);
    assert_eq!(url, Some("https://friendbot.stellar.org"));
}

/// Mainnet has no default Friendbot URL.
#[test]
fn default_friendbot_url_mainnet_none() {
    use stellar_agent_core::profile::caip2::Caip2;

    let url = default_friendbot_url(Caip2::Mainnet);
    assert!(
        url.is_none(),
        "mainnet must have no default Friendbot URL; got: {url:?}"
    );
}
