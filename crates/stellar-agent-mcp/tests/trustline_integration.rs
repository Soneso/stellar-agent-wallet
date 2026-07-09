//! Full round-trip integration test for `stellar_trustline` and
//! `stellar_trustline_commit`.
//!
//! `stellar_trustline` has no offline simulate/commit integration coverage
//! elsewhere in this crate (`trustline.rs`'s own `#[cfg(test)]` module only
//! covers the pure `parse_denomination_input` helper). This file establishes
//! the success-path precedent already present for `stellar_pay` /
//! `stellar_create_account`: a wiremock RPC server provides deterministic
//! responses for the wallet source account, the pinned USDC issuer account
//! (for the clawback-gate flag fetch), and the classic-transaction submit
//! path, without a live Stellar network connection.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics and unwraps acceptable in integration tests"
)]

use serial_test::serial;
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_mcp::server::{StellarTrustlineArgs, StellarTrustlineCommitArgs, WalletServer};
use stellar_agent_test_support::keyring_mock;
use stellar_agent_test_support::xdr_fixtures::{
    account_entry_xdr_with_balance, account_ledger_key_xdr,
};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

mod common;

/// Pinned testnet USDC issuer (matches
/// `stellar_agent_stablecoin::resolve`'s testnet pin table).
const USDC_TESTNET_ISSUER: &str = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";

/// Testnet profile with `engine = Noop` and the given RPC URL for test isolation.
///
/// Explicitly sets `Noop` so `WalletServer::new` succeeds without a signed
/// policy file on disk: `PolicyEngineKind::default()` is `V1`, which requires
/// a signed policy file and a keyring owner-key entry.
fn testnet_profile_with_rpc(rpc_url: &str) -> Profile {
    let mut p = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
        .with_noop_engine()
        .build();
    p.rpc_url = rpc_url.to_owned();
    p
}

fn call_result_text(result: &rmcp::model::CallToolResult) -> &str {
    result
        .content
        .first()
        .and_then(|content| content.as_text())
        .map(|text| text.text.as_str())
        .unwrap_or("")
}

fn call_result_json(result: &rmcp::model::CallToolResult) -> serde_json::Value {
    serde_json::from_str(call_result_text(result)).expect("tool result must be JSON")
}

fn install_test_nonce_key(byte: u8) {
    use base64::Engine;
    use keyring_core::Entry;

    let nonce_key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([byte; 32]);
    Entry::new("n-svc", "n-acct")
        .expect("Entry::new")
        .set_password(&nonce_key_b64)
        .expect("set_password");
}

/// Derives the G-strkey for a 32-byte ed25519 seed.
fn gstrkey_for_seed(seed: [u8; 32]) -> String {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let vk = signing_key.verifying_key();
    stellar_strkey::ed25519::PublicKey(vk.to_bytes())
        .to_string()
        .to_string()
}

/// Derives the S-strkey (seed strkey) for a 32-byte ed25519 seed.
fn sstrkey_for_seed(seed: [u8; 32]) -> String {
    stellar_strkey::ed25519::PrivateKey(seed)
        .as_unredacted()
        .to_string()
        .to_string()
}

/// RPC responder for a full simulate → commit → submit round trip.
///
/// Serves the funded wallet-source account, the pinned USDC issuer account
/// (flags = 0: no clawback, no auth-required — the clawback gate proceeds
/// unconditionally), and the classic-transaction submit path. The SAME
/// source-account response is served on both the simulate fetch and the
/// commit re-fetch, so the rebuilt envelope is byte-identical to the
/// presented one (the divergence check passes).
struct TrustlineSubmitSuccessRpcResponder {
    source_key_xdr: String,
    source_xdr: String,
    issuer_key_xdr: String,
    issuer_xdr: String,
}

#[async_trait::async_trait]
impl Respond for TrustlineSubmitSuccessRpcResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let request_value = serde_json::from_slice::<serde_json::Value>(&request.body)
            .unwrap_or_else(|_| serde_json::json!({}));
        let req_id = request_value
            .get("id")
            .cloned()
            .unwrap_or_else(|| serde_json::json!(1));
        let method = request_value
            .get("method")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");

        let result = match method {
            "getLedgerEntries" => {
                let body = String::from_utf8_lossy(&request.body);
                if body.contains(&self.source_key_xdr) {
                    serde_json::json!({
                        "entries": [
                            {
                                "key": self.source_key_xdr,
                                "xdr": self.source_xdr,
                                "lastModifiedLedgerSeq": 1000
                            }
                        ],
                        "latestLedger": 1001
                    })
                } else if body.contains(&self.issuer_key_xdr) {
                    serde_json::json!({
                        "entries": [
                            {
                                "key": self.issuer_key_xdr,
                                "xdr": self.issuer_xdr,
                                "lastModifiedLedgerSeq": 1000
                            }
                        ],
                        "latestLedger": 1001
                    })
                } else {
                    serde_json::json!({ "entries": [], "latestLedger": 1001 })
                }
            }
            "sendTransaction" => serde_json::json!({
                "hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "status": "PENDING",
                "latestLedger": 1001,
                "latestLedgerCloseTime": "1234567890"
            }),
            "getTransaction" => serde_json::json!({
                "status": "SUCCESS",
                "ledger": 1005,
                "txHash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            }),
            _ => serde_json::json!({}),
        };

        ResponseTemplate::new(200)
            .set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": result,
            }))
            .insert_header("content-type", "application/json")
    }
}

/// End-to-end success path: `stellar_trustline` (simulate) with an explicit
/// `limit_stroops` — the decimal-string field this migration changed from
/// `i64` — mints a nonce; `stellar_trustline_commit` reuses the exact
/// `(nonce, expires_at_unix_ms, envelope_xdr)` triple, re-derives the same
/// decimal-string `limit_stroops` from the HMAC-bound envelope, signs via a
/// keyring-backed signer, and submits. Asserts the committed values, not just
/// that each phase in isolation accepts the new wire shape.
#[tokio::test]
#[serial]
async fn trustline_commit_full_round_trip_succeeds_with_string_encoded_limit() {
    keyring_mock::install().expect("mock keyring store init");
    install_test_nonce_key(210);

    // Fresh signer keypair; populates the mock keyring's default signer entry
    // ("svc", "acct" — matching `testnet_profile_with_rpc`'s
    // `Profile::builder_testnet("svc", "acct", ...)`) with its S-strkey.
    let seed = [0x44_u8; 32];
    let source_g = gstrkey_for_seed(seed);
    keyring_core::Entry::new("svc", "acct")
        .expect("Entry::new")
        .set_password(&sstrkey_for_seed(seed))
        .expect("set_password");

    let source_key_xdr = account_ledger_key_xdr(&source_g);
    // 10_000_000 XLM: comfortably covers the base reserve and fee.
    let source_xdr = account_entry_xdr_with_balance(&source_g, 100_000_000_000_000);
    let issuer_key_xdr = account_ledger_key_xdr(USDC_TESTNET_ISSUER);
    // Issuer account with flags = 0 (no clawback, no auth-required): the
    // clawback gate proceeds unconditionally.
    let issuer_xdr = account_entry_xdr_with_balance(USDC_TESTNET_ISSUER, 100_000_000_000_000);

    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(TrustlineSubmitSuccessRpcResponder {
            source_key_xdr,
            source_xdr,
            issuer_key_xdr,
            issuer_xdr,
        })
        .mount(&mock_server)
        .await;

    let profile = testnet_profile_with_rpc(&mock_server.uri());
    let server = WalletServer::new(profile).expect("WalletServer::new");

    // ── Simulate ───────────────────────────────────────────────────────────
    let simulate_args = StellarTrustlineArgs {
        chain_id: "stellar:testnet".to_owned(),
        from: source_g.clone(),
        asset: "USDC".to_owned(),
        limit_stroops: Some("1000000000".to_owned()), // 100 USDC at 7 decimals
        classic_base: None,
    };
    let sim_result = server
        .call_stellar_trustline(simulate_args.clone())
        .await
        .expect("simulate must not error");
    assert_ne!(sim_result.is_error, Some(true), "simulate must succeed");
    let sim_json = call_result_json(&sim_result);
    let sim_data = sim_json.get("data").expect("simulate success carries data");

    assert_eq!(
        sim_data.pointer("/simulation/operation/limit_stroops"),
        Some(&serde_json::json!("1000000000")),
        "simulate must report limit_stroops as a decimal string: {sim_data}"
    );
    assert_eq!(
        sim_data.pointer("/preview/limit_stroops"),
        Some(&serde_json::json!("1000000000")),
        "preview must report limit_stroops as a decimal string: {sim_data}"
    );

    let nonce = sim_data
        .get("nonce")
        .and_then(serde_json::Value::as_str)
        .expect("nonce present")
        .to_owned();
    let expires_at_unix_ms = sim_data
        .get("expires_at_unix_ms")
        .and_then(serde_json::Value::as_u64)
        .expect("expires_at_unix_ms present");
    let envelope_xdr = sim_data
        .get("envelope_xdr")
        .and_then(serde_json::Value::as_str)
        .expect("envelope_xdr present")
        .to_owned();

    // ── Commit ─────────────────────────────────────────────────────────────
    let commit_args = StellarTrustlineCommitArgs {
        chain_id: simulate_args.chain_id.clone(),
        from: simulate_args.from.clone(),
        nonce,
        expires_at_unix_ms,
        envelope_xdr,
        approval_nonce: None,
        approval_attestation: None,
    };
    let commit_result = server
        .call_stellar_trustline_commit(commit_args)
        .await
        .expect("commit must not error");
    let commit_json = call_result_json(&commit_result);
    assert_ne!(
        commit_result.is_error,
        Some(true),
        "commit must succeed, got: {commit_json}"
    );
    let commit_data = commit_json
        .get("data")
        .expect("commit success carries data");
    assert!(
        commit_data
            .get("tx_hash")
            .and_then(serde_json::Value::as_str)
            .is_some(),
        "committed response must carry tx_hash: {commit_data}"
    );
    assert_eq!(
        commit_data
            .get("ledger")
            .and_then(serde_json::Value::as_u64),
        Some(1005),
        "committed response must carry the submitted ledger: {commit_data}"
    );
}

/// WYSIWYS: the `limit_stroops` echoed in the `simulation`/`approval.summary`
/// blocks must be the PARSED value re-stringified in canonical form, not the
/// raw caller string verbatim. A caller passing a non-canonical decimal
/// string (leading zeros, an explicit `+` sign) must see the canonical form
/// echoed back — the same value the envelope actually signs — not the raw
/// string it supplied.
#[tokio::test]
#[serial]
async fn trustline_simulate_echoes_canonical_limit_stroops_not_raw_caller_string() {
    keyring_mock::install().expect("mock keyring store init");
    install_test_nonce_key(211);

    let seed = [0x46_u8; 32];
    let source_g = gstrkey_for_seed(seed);

    let source_key_xdr = account_ledger_key_xdr(&source_g);
    let source_xdr = account_entry_xdr_with_balance(&source_g, 100_000_000_000_000);
    let issuer_key_xdr = account_ledger_key_xdr(USDC_TESTNET_ISSUER);
    let issuer_xdr = account_entry_xdr_with_balance(USDC_TESTNET_ISSUER, 100_000_000_000_000);

    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(TrustlineSubmitSuccessRpcResponder {
            source_key_xdr,
            source_xdr,
            issuer_key_xdr,
            issuer_xdr,
        })
        .mount(&mock_server)
        .await;

    let profile = testnet_profile_with_rpc(&mock_server.uri());
    let server = WalletServer::new(profile).expect("WalletServer::new");

    // Non-canonical raw input: leading zeros + an explicit "+" sign. Parses
    // to the same i64 as "1000000000" but is NOT byte-identical to it.
    let simulate_args = StellarTrustlineArgs {
        chain_id: "stellar:testnet".to_owned(),
        from: source_g,
        asset: "USDC".to_owned(),
        limit_stroops: Some("+0001000000000".to_owned()),
        classic_base: None,
    };
    let sim_result = server
        .call_stellar_trustline(simulate_args)
        .await
        .expect("simulate must not error");
    assert_ne!(sim_result.is_error, Some(true), "simulate must succeed");
    let sim_json = call_result_json(&sim_result);
    let sim_data = sim_json.get("data").expect("simulate success carries data");

    assert_eq!(
        sim_data.pointer("/simulation/operation/limit_stroops"),
        Some(&serde_json::json!("1000000000")),
        "the echoed limit_stroops must be the canonical parsed form, not the raw \
         caller string '+0001000000000': {sim_data}"
    );
    assert_eq!(
        sim_data.pointer("/preview/limit_stroops"),
        Some(&serde_json::json!("1000000000")),
        "the preview's limit_stroops must also be canonical: {sim_data}"
    );
}

// ── Envelope-shape regression guard: nonce.mint_failed ───────────────────────

/// `stellar_trustline` returns the full documented business-error envelope
/// (`ok:false`, `error.code == "nonce.mint_failed"`, non-empty `request_id`,
/// `is_error == Some(true)`) when the nonce-key keyring entry is absent.
///
/// Forces the failure the cheapest honest way: a fresh mock keyring store
/// with NO key written at the profile's nonce coordinate — the source and
/// issuer account fetches (feeding the policy gate's `account_view`
/// wiring, and the clawback gate) succeed normally via
/// `TrustlineSubmitSuccessRpcResponder`, so the only failure is
/// `NonceMint::mint`'s keyring load inside the handler's own simulate path.
#[tokio::test]
#[serial]
async fn simulate_nonce_mint_failed_envelope_shape() {
    keyring_mock::install().expect("mock keyring store init");
    // Deliberately no `install_test_nonce_key(...)` call — the mock store
    // stays empty at the nonce coordinate.

    let seed = [0x45_u8; 32];
    let source_g = gstrkey_for_seed(seed);
    keyring_core::Entry::new("svc", "acct")
        .expect("Entry::new")
        .set_password(&sstrkey_for_seed(seed))
        .expect("set_password");

    let source_key_xdr = account_ledger_key_xdr(&source_g);
    let source_xdr = account_entry_xdr_with_balance(&source_g, 100_000_000_000_000);
    let issuer_key_xdr = account_ledger_key_xdr(USDC_TESTNET_ISSUER);
    let issuer_xdr = account_entry_xdr_with_balance(USDC_TESTNET_ISSUER, 100_000_000_000_000);

    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(TrustlineSubmitSuccessRpcResponder {
            source_key_xdr,
            source_xdr,
            issuer_key_xdr,
            issuer_xdr,
        })
        .mount(&mock_server)
        .await;

    let profile = testnet_profile_with_rpc(&mock_server.uri());
    let server = WalletServer::new(profile).expect("WalletServer::new");

    let simulate_args = StellarTrustlineArgs {
        chain_id: "stellar:testnet".to_owned(),
        from: source_g,
        asset: "USDC".to_owned(),
        limit_stroops: Some("1000000000".to_owned()),
        classic_base: None,
    };
    let result = server
        .call_stellar_trustline(simulate_args)
        .await
        .expect("handler must return a business-error result, not a protocol error");

    let (code, _message, _text) = common::assert_business_envelope(&result);
    assert_eq!(
        code, "nonce.mint_failed",
        "an absent nonce-key keyring entry must surface nonce.mint_failed"
    );
}

// ── Regression guard: `from` G-strkey validation runs before any RPC call ────

/// `stellar_trustline_commit` rejects a malformed `from` via the dedicated
/// `invalid_params` protocol error, WITHOUT attempting the source-account
/// fetch first.
///
/// `fetch_account` itself parses its account argument through the same
/// strkey check, so if the validation ran after the fetch, a malformed
/// `from` would instead surface as a redacted RPC-error business envelope
/// (`Ok(is_error: true)`) rather than this dedicated `Err`.
///
/// Builds a genuine, well-formed `envelope_xdr` via a real simulate call
/// (`decode_authoritative_args` must succeed for the flow to reach the `from`
/// check at all — it runs before the check), then commits with a MISMATCHED,
/// malformed `from` against a SEPARATE `WalletServer` pointed at an
/// unroutable RPC URL. `decode_authoritative_args` reads only `envelope_xdr`,
/// never `args.from`, so the mismatch does not block reaching the check.
/// Because that server's RPC URL is unroutable, an attempted source/issuer
/// account fetch would fail loudly (or hang) rather than silently succeed,
/// making "no RPC call happened before the check" load-bearing.
#[tokio::test]
#[serial]
async fn commit_rejects_invalid_from_strkey_before_any_rpc_call() {
    keyring_mock::install().expect("mock keyring store init");
    install_test_nonce_key(212);

    let seed = [0x47_u8; 32];
    let source_g = gstrkey_for_seed(seed);
    keyring_core::Entry::new("svc", "acct")
        .expect("Entry::new")
        .set_password(&sstrkey_for_seed(seed))
        .expect("set_password");

    let source_key_xdr = account_ledger_key_xdr(&source_g);
    let source_xdr = account_entry_xdr_with_balance(&source_g, 100_000_000_000_000);
    let issuer_key_xdr = account_ledger_key_xdr(USDC_TESTNET_ISSUER);
    let issuer_xdr = account_entry_xdr_with_balance(USDC_TESTNET_ISSUER, 100_000_000_000_000);

    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(TrustlineSubmitSuccessRpcResponder {
            source_key_xdr,
            source_xdr,
            issuer_key_xdr,
            issuer_xdr,
        })
        .mount(&mock_server)
        .await;

    let simulate_profile = testnet_profile_with_rpc(&mock_server.uri());
    let simulate_server = WalletServer::new(simulate_profile).expect("WalletServer::new");

    let sim_result = simulate_server
        .call_stellar_trustline(StellarTrustlineArgs {
            chain_id: "stellar:testnet".to_owned(),
            from: source_g,
            asset: "USDC".to_owned(),
            limit_stroops: Some("1000000000".to_owned()),
            classic_base: None,
        })
        .await
        .expect("simulate must not error");
    let sim_json = call_result_json(&sim_result);
    let sim_data = sim_json.get("data").expect("simulate success carries data");
    let envelope_xdr = sim_data
        .get("envelope_xdr")
        .and_then(serde_json::Value::as_str)
        .expect("simulate must surface envelope_xdr")
        .to_owned();
    let nonce = sim_data
        .get("nonce")
        .and_then(serde_json::Value::as_str)
        .expect("nonce present")
        .to_owned();
    let expires_at_unix_ms = sim_data
        .get("expires_at_unix_ms")
        .and_then(serde_json::Value::as_u64)
        .expect("expires_at_unix_ms present");

    // A fresh server with no keyring seeded and an unroutable RPC URL: any
    // step reaching the network or the keyring would fail loudly, not
    // silently proceed.
    let commit_profile = testnet_profile_with_rpc("http://198.51.100.1:1");
    let commit_server = WalletServer::new(commit_profile).expect("WalletServer::new");

    let commit_args = StellarTrustlineCommitArgs {
        chain_id: "stellar:testnet".to_owned(),
        from: "not-a-valid-g-strkey".to_owned(),
        nonce,
        expires_at_unix_ms,
        envelope_xdr,
        approval_nonce: None,
        approval_attestation: None,
    };
    let result = commit_server
        .call_stellar_trustline_commit(commit_args)
        .await;

    let err = result.expect_err(
        "a malformed `from` must return the dedicated invalid_params protocol error, \
         not a business-error envelope from a fetch attempt",
    );
    assert!(
        err.message.contains("invalid from"),
        "error message must name the invalid `from` field: {err:?}"
    );
}
