//! Integration tests for the `stellar_claim` and `stellar_claim_commit` MCP
//! tools.
//!
//! These tests exercise the handlers directly via `WalletServer`, bypassing the
//! stdio transport.  A wiremock server provides deterministic `getLedgerEntries`
//! responses without a live Stellar network connection.  The claim simulate step
//! resolves its fee from the profile default (`ClassicFeeChoice::ProfileDefault`),
//! so no `getFeeStats` RPC is issued — the mock only serves `getLedgerEntries`
//! for the claimable-balance entry and the source account.
//!
//! # Test coverage
//!
//! ## Simulate step (`stellar_claim`)
//!
//! 1. Happy path (native XLM, unconditional predicate, source is the claimant) —
//!    response is not an error and contains `envelope_xdr`, `nonce`,
//!    `expires_at_unix_ms`, and `preview`.
//! 2. Balance not found — empty `entries` for the claimable-balance key →
//!    `claim.balance_not_found`.
//! 3. Not a claimant — entry claimant is a different G-strkey than the source →
//!    `claim.not_claimant`.
//! 4. Predicate not satisfied — `BeforeAbsoluteTime` in the past →
//!    `claim.predicate_not_satisfied`.
//! 5. Approval-required — `RequireApproval` engine → non-error response carrying
//!    an `approval` block with `approval_nonce`, `expires_at_unix_ms`, and a
//!    `summary` object.
//!
//! ## Commit step (`stellar_claim_commit`)
//!
//! 6. Nonce replay — a genuine simulate-minted nonce is committed twice; the
//!    first commit records the nonce in the replay window (then fails at keyring
//!    signing because no signer key is provisioned for the source), the second
//!    returns `nonce.replayed`.
//! 7. Envelope divergence — a commit whose re-fetched account has a different
//!    sequence number than the presented envelope encodes rebuilds a
//!    non-matching envelope → `simulation.divergence`.
//! 8. Commit-phase entry-gone — the claimable-balance entry is present for the
//!    simulate re-fetch but absent for the commit re-fetch (stateful responder)
//!    → `claim.balance_not_found`.
//!
//! ## Scope note
//!
//! A full happy-path commit (mock keyring signer + `sendTransaction` /
//! `getTransaction` polling asserting `{tx_hash, ledger}`) is intentionally not
//! included here.  The sibling `pay_integration.rs` suite establishes no
//! submit-mocking precedent (its commit tests stop at the nonce/divergence
//! gates), so a full on-chain submit round-trip is disproportionate for an
//! offline unit-level file.  End-to-end submit coverage is provided by the CLI
//! three-stage tests and the live testnet acceptance suite.
//!
//! # Keyring isolation
//!
//! Every test installs the process-global mock keyring store before constructing
//! `WalletServer`; tests are serialised via `#[serial]` so they do not race on
//! the shared store.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    reason = "test-only; panics, unwraps, and measured output are acceptable in integration tests"
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use serial_test::serial;
use stellar_agent_claimable::id::BalanceId;
use stellar_agent_core::DEFAULT_CLASSIC_FEE_STROOPS;
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_mcp::server::{StellarClaimArgs, StellarClaimCommitArgs, WalletServer};
use stellar_agent_network::ClassicOpBuilder;
use stellar_agent_test_support::keyring_mock;
use stellar_agent_test_support::xdr_fixtures::{
    account_entry_xdr_with_seq, account_ledger_key_xdr,
};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

mod common;

use common::policy_mock::MockPolicyEngine;

// ─────────────────────────────────────────────────────────────────────────────
// Test key material and fixtures
// ─────────────────────────────────────────────────────────────────────────────

/// The claiming (source) account.  Reused from `stellar-agent-claimable`'s own
/// test constants so the claimant identity matches the entry claimant.
const SOURCE_G: &str = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";

/// A distinct well-formed G-strkey used as the "not a claimant" counterparty.
const OTHER_G: &str = "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL";

/// The claimable-balance amount (native XLM), in stroops.
const CLAIM_AMOUNT_STROOPS: i64 = 100_000_000;

/// A source-account native balance comfortably above base reserves + fee.
const SOURCE_BALANCE_STROOPS: i64 = 1_000_000_000;

/// The source-account sequence number used across simulate and commit.
const SOURCE_SEQ: i64 = 100;

/// Returns the deterministic test claimable-balance id (hash `0xAB` repeated).
fn test_balance_id() -> BalanceId {
    BalanceId::parse(&"ab".repeat(32)).expect("valid 64-hex balance id")
}

/// Builds the `LedgerKey::ClaimableBalance` XDR base64 for `id`, matching what
/// `fetch_claimable_balance_entry` sends to `getLedgerEntries`.
fn claim_key_xdr(id: &BalanceId) -> String {
    use stellar_xdr::{
        ClaimableBalanceId, Hash, LedgerKey, LedgerKeyClaimableBalance, Limits, WriteXdr,
    };
    let key = LedgerKey::ClaimableBalance(LedgerKeyClaimableBalance {
        balance_id: ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash(id.hash())),
    });
    key.to_xdr_base64(Limits::none())
        .expect("claimable-balance key XDR encode")
}

/// Builds a native-XLM `LedgerEntryData::ClaimableBalance` XDR base64 with a
/// single claimant carrying `predicate`.
fn claim_entry_xdr(
    id: &BalanceId,
    claimant_g: &str,
    predicate: stellar_xdr::ClaimPredicate,
    amount: i64,
) -> String {
    use stellar_xdr::{
        AccountId, Asset, ClaimableBalanceEntry, ClaimableBalanceEntryExt, ClaimableBalanceId,
        Claimant, ClaimantV0, Hash, LedgerEntryData, Limits, PublicKey, Uint256, VecM, WriteXdr,
    };
    let pk = stellar_strkey::ed25519::PublicKey::from_string(claimant_g).expect("valid G-strkey");
    let destination = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk.0)));
    let entry = ClaimableBalanceEntry {
        balance_id: ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash(id.hash())),
        claimants: VecM::try_from(vec![Claimant::ClaimantTypeV0(ClaimantV0 {
            destination,
            predicate,
        })])
        .expect("single-claimant vec"),
        asset: Asset::Native,
        amount,
        ext: ClaimableBalanceEntryExt::V0,
    };
    LedgerEntryData::ClaimableBalance(entry)
        .to_xdr_base64(Limits::none())
        .expect("claimable-balance entry XDR encode")
}

// ─────────────────────────────────────────────────────────────────────────────
// Server / profile helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Testnet profile with `engine = Noop` and the given RPC URL.
///
/// `Noop` is set explicitly so `WalletServer::new` succeeds without a signed
/// policy file on disk (`PolicyEngineKind::default()` is `V1`).
fn testnet_profile_with_rpc(rpc_url: &str) -> Profile {
    let mut p = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
        .with_noop_engine()
        .build();
    p.rpc_url = rpc_url.to_owned();
    p
}

/// Installs the deterministic HMAC key used by the nonce mint, under the same
/// keyring alias (`n-svc` / `n-acct`) the test profile carries.
fn install_test_nonce_key() {
    use base64::Engine as _;
    use keyring_core::Entry;

    let nonce_key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]);
    Entry::new("n-svc", "n-acct")
        .expect("Entry::new for nonce key")
        .set_password(&nonce_key_b64)
        .expect("set_password for nonce key");
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

fn simulate_args() -> StellarClaimArgs {
    StellarClaimArgs {
        chain_id: "stellar:testnet".to_owned(),
        balance_id: "ab".repeat(32),
        source_account: Some(SOURCE_G.to_owned()),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Wiremock responders
// ─────────────────────────────────────────────────────────────────────────────

/// Serves a fixed claimable-balance entry (or an empty result when
/// `entry_xdr` is `None`) and a fixed source account for `getLedgerEntries`.
struct ClaimRpcResponder {
    cb_key_xdr: String,
    entry_xdr: Option<String>,
    account_key_xdr: String,
    account_xdr: String,
}

fn ledger_entries_result(key: &str, xdr: &str) -> serde_json::Value {
    serde_json::json!({
        "entries": [{ "key": key, "xdr": xdr, "lastModifiedLedgerSeq": 1000 }],
        "latestLedger": 1001
    })
}

fn empty_ledger_entries_result() -> serde_json::Value {
    serde_json::json!({ "entries": [], "latestLedger": 1001 })
}

fn json_rpc_response(req_id: &serde_json::Value, result: &serde_json::Value) -> ResponseTemplate {
    ResponseTemplate::new(200)
        .set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": result,
        }))
        .insert_header("content-type", "application/json")
}

fn request_id_and_method(request: &Request) -> (serde_json::Value, String) {
    let value = serde_json::from_slice::<serde_json::Value>(&request.body)
        .unwrap_or_else(|_| serde_json::json!({}));
    let id = value
        .get("id")
        .cloned()
        .unwrap_or_else(|| serde_json::json!(1));
    let method = value
        .get("method")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_owned();
    (id, method)
}

#[async_trait]
impl Respond for ClaimRpcResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let (req_id, method) = request_id_and_method(request);
        let result = if method == "getLedgerEntries" {
            let body = String::from_utf8_lossy(&request.body);
            if body.contains(&self.cb_key_xdr) {
                match &self.entry_xdr {
                    Some(xdr) => ledger_entries_result(&self.cb_key_xdr, xdr),
                    None => empty_ledger_entries_result(),
                }
            } else if body.contains(&self.account_key_xdr) {
                ledger_entries_result(&self.account_key_xdr, &self.account_xdr)
            } else {
                empty_ledger_entries_result()
            }
        } else {
            serde_json::json!({})
        };
        json_rpc_response(&req_id, &result)
    }
}

/// Serves the claimable-balance entry on the FIRST `getLedgerEntries` query for
/// the entry key (the simulate re-fetch) and an empty result on every later
/// query (the commit re-fetch), while always serving the source account.
struct EntryGoneResponder {
    cb_key_xdr: String,
    entry_xdr: String,
    account_key_xdr: String,
    account_xdr: String,
    cb_hits: Arc<AtomicUsize>,
}

#[async_trait]
impl Respond for EntryGoneResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let (req_id, method) = request_id_and_method(request);
        let result = if method == "getLedgerEntries" {
            let body = String::from_utf8_lossy(&request.body);
            if body.contains(&self.cb_key_xdr) {
                let hit = self.cb_hits.fetch_add(1, Ordering::SeqCst);
                if hit == 0 {
                    ledger_entries_result(&self.cb_key_xdr, &self.entry_xdr)
                } else {
                    empty_ledger_entries_result()
                }
            } else if body.contains(&self.account_key_xdr) {
                ledger_entries_result(&self.account_key_xdr, &self.account_xdr)
            } else {
                empty_ledger_entries_result()
            }
        } else {
            serde_json::json!({})
        };
        json_rpc_response(&req_id, &result)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Simulate step
// ─────────────────────────────────────────────────────────────────────────────

/// Scenario 1: native XLM, unconditional predicate, source is the claimant →
/// non-error response with `envelope_xdr`, `nonce`, `expires_at_unix_ms`, and
/// `preview`.
#[tokio::test]
#[serial]
async fn simulate_happy_path_returns_envelope_nonce_and_preview() {
    keyring_mock::install().expect("mock keyring store init");
    install_test_nonce_key();

    let id = test_balance_id();
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ClaimRpcResponder {
            cb_key_xdr: claim_key_xdr(&id),
            entry_xdr: Some(claim_entry_xdr(
                &id,
                SOURCE_G,
                stellar_xdr::ClaimPredicate::Unconditional,
                CLAIM_AMOUNT_STROOPS,
            )),
            account_key_xdr: account_ledger_key_xdr(SOURCE_G),
            account_xdr: account_entry_xdr_with_seq(
                SOURCE_G,
                SOURCE_BALANCE_STROOPS,
                0,
                SOURCE_SEQ,
            ),
        })
        .mount(&mock_server)
        .await;

    let server =
        WalletServer::new(testnet_profile_with_rpc(&mock_server.uri())).expect("WalletServer::new");
    let result = server
        .call_stellar_claim(simulate_args())
        .await
        .expect("simulate should not error");

    assert_ne!(
        result.is_error,
        Some(true),
        "happy path must not be an error"
    );
    let json = call_result_json(&result);
    let data = json.get("data").expect("success envelope carries data");
    assert!(
        data.get("envelope_xdr")
            .and_then(serde_json::Value::as_str)
            .is_some(),
        "response must carry envelope_xdr, got: {json}"
    );
    assert!(
        data.get("nonce")
            .and_then(serde_json::Value::as_str)
            .is_some(),
        "response must carry nonce"
    );
    assert!(
        data.get("expires_at_unix_ms")
            .and_then(serde_json::Value::as_u64)
            .is_some(),
        "response must carry expires_at_unix_ms"
    );
    let preview = data.get("preview").expect("response must carry preview");
    assert_eq!(
        preview
            .get("amount_stroops")
            .and_then(serde_json::Value::as_i64),
        Some(CLAIM_AMOUNT_STROOPS)
    );
}

/// Scenario 2: empty `entries` for the claimable-balance key →
/// `claim.balance_not_found`.
#[tokio::test]
#[serial]
async fn simulate_balance_not_found() {
    keyring_mock::install().expect("mock keyring store init");
    install_test_nonce_key();

    let id = test_balance_id();
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ClaimRpcResponder {
            cb_key_xdr: claim_key_xdr(&id),
            entry_xdr: None,
            account_key_xdr: account_ledger_key_xdr(SOURCE_G),
            account_xdr: account_entry_xdr_with_seq(
                SOURCE_G,
                SOURCE_BALANCE_STROOPS,
                0,
                SOURCE_SEQ,
            ),
        })
        .mount(&mock_server)
        .await;

    let server =
        WalletServer::new(testnet_profile_with_rpc(&mock_server.uri())).expect("WalletServer::new");
    let result = server
        .call_stellar_claim(simulate_args())
        .await
        .expect("balance-not-found returns a tool-level error, not Err");

    assert_eq!(result.is_error, Some(true));
    assert!(
        call_result_text(&result).contains("claim.balance_not_found"),
        "response must contain claim.balance_not_found, got: {}",
        call_result_text(&result)
    );
}

/// Scenario 3: entry claimant is a different G-strkey than the source →
/// `claim.not_claimant`.
#[tokio::test]
#[serial]
async fn simulate_not_claimant() {
    keyring_mock::install().expect("mock keyring store init");
    install_test_nonce_key();

    let id = test_balance_id();
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ClaimRpcResponder {
            cb_key_xdr: claim_key_xdr(&id),
            entry_xdr: Some(claim_entry_xdr(
                &id,
                OTHER_G, // claimant is NOT the source
                stellar_xdr::ClaimPredicate::Unconditional,
                CLAIM_AMOUNT_STROOPS,
            )),
            account_key_xdr: account_ledger_key_xdr(SOURCE_G),
            account_xdr: account_entry_xdr_with_seq(
                SOURCE_G,
                SOURCE_BALANCE_STROOPS,
                0,
                SOURCE_SEQ,
            ),
        })
        .mount(&mock_server)
        .await;

    let server =
        WalletServer::new(testnet_profile_with_rpc(&mock_server.uri())).expect("WalletServer::new");
    let result = server
        .call_stellar_claim(simulate_args())
        .await
        .expect("not-claimant returns a tool-level error, not Err");

    assert_eq!(result.is_error, Some(true));
    assert!(
        call_result_text(&result).contains("claim.not_claimant"),
        "response must contain claim.not_claimant, got: {}",
        call_result_text(&result)
    );
}

/// Scenario 4: `BeforeAbsoluteTime` in the past → `claim.predicate_not_satisfied`.
#[tokio::test]
#[serial]
async fn simulate_predicate_not_satisfied() {
    keyring_mock::install().expect("mock keyring store init");
    install_test_nonce_key();

    let id = test_balance_id();
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ClaimRpcResponder {
            cb_key_xdr: claim_key_xdr(&id),
            entry_xdr: Some(claim_entry_xdr(
                &id,
                SOURCE_G,
                // Absolute unix-second deadline far in the past (1970-era).
                stellar_xdr::ClaimPredicate::BeforeAbsoluteTime(500),
                CLAIM_AMOUNT_STROOPS,
            )),
            account_key_xdr: account_ledger_key_xdr(SOURCE_G),
            account_xdr: account_entry_xdr_with_seq(
                SOURCE_G,
                SOURCE_BALANCE_STROOPS,
                0,
                SOURCE_SEQ,
            ),
        })
        .mount(&mock_server)
        .await;

    let server =
        WalletServer::new(testnet_profile_with_rpc(&mock_server.uri())).expect("WalletServer::new");
    let result = server
        .call_stellar_claim(simulate_args())
        .await
        .expect("predicate-not-satisfied returns a tool-level error, not Err");

    assert_eq!(result.is_error, Some(true));
    assert!(
        call_result_text(&result).contains("claim.predicate_not_satisfied"),
        "response must contain claim.predicate_not_satisfied, got: {}",
        call_result_text(&result)
    );
}

/// Scenario 5: `RequireApproval` engine → non-error response carrying an
/// `approval` block with `approval_nonce`, `expires_at_unix_ms`, and `summary`.
#[tokio::test]
#[serial]
async fn simulate_approval_required_returns_approval_block() {
    keyring_mock::install().expect("mock keyring store init");
    install_test_nonce_key();

    let id = test_balance_id();
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ClaimRpcResponder {
            cb_key_xdr: claim_key_xdr(&id),
            entry_xdr: Some(claim_entry_xdr(
                &id,
                SOURCE_G,
                stellar_xdr::ClaimPredicate::Unconditional,
                CLAIM_AMOUNT_STROOPS,
            )),
            account_key_xdr: account_ledger_key_xdr(SOURCE_G),
            account_xdr: account_entry_xdr_with_seq(
                SOURCE_G,
                SOURCE_BALANCE_STROOPS,
                0,
                SOURCE_SEQ,
            ),
        })
        .mount(&mock_server)
        .await;

    let mut server =
        WalletServer::new(testnet_profile_with_rpc(&mock_server.uri())).expect("WalletServer::new");
    server.set_policy_engine_for_test(Arc::new(MockPolicyEngine::require_approval()));

    let result = server
        .call_stellar_claim(simulate_args())
        .await
        .expect("approval-required simulate should not error");

    assert_ne!(
        result.is_error,
        Some(true),
        "approval-required simulate must be a success response, got: {}",
        call_result_text(&result)
    );
    let json = call_result_json(&result);
    let data = json.get("data").expect("success envelope carries data");
    let approval = data
        .get("approval")
        .expect("response must carry approval block");
    assert!(
        approval
            .get("approval_nonce")
            .and_then(serde_json::Value::as_str)
            .is_some(),
        "approval block must carry approval_nonce, got: {approval}"
    );
    assert!(
        approval
            .get("expires_at_unix_ms")
            .and_then(serde_json::Value::as_u64)
            .is_some(),
        "approval block must carry expires_at_unix_ms"
    );
    assert!(
        approval
            .get("summary")
            .map(serde_json::Value::is_object)
            .unwrap_or(false),
        "approval block must carry a summary object"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Commit step
// ─────────────────────────────────────────────────────────────────────────────

/// Extracts the `(nonce, expires_at_unix_ms, envelope_xdr)` triple from a
/// successful simulate response.
fn extract_commit_triple(result: &rmcp::model::CallToolResult) -> (String, u64, String) {
    let json = call_result_json(result);
    let data = json.get("data").expect("simulate success carries data");
    let nonce = data
        .get("nonce")
        .and_then(serde_json::Value::as_str)
        .expect("nonce present")
        .to_owned();
    let expires = data
        .get("expires_at_unix_ms")
        .and_then(serde_json::Value::as_u64)
        .expect("expires_at_unix_ms present");
    let envelope = data
        .get("envelope_xdr")
        .and_then(serde_json::Value::as_str)
        .expect("envelope_xdr present")
        .to_owned();
    (nonce, expires, envelope)
}

fn commit_args(
    nonce: String,
    expires_at_unix_ms: u64,
    envelope_xdr: String,
) -> StellarClaimCommitArgs {
    StellarClaimCommitArgs {
        chain_id: "stellar:testnet".to_owned(),
        balance_id: "ab".repeat(32),
        source_account: Some(SOURCE_G.to_owned()),
        nonce,
        expires_at_unix_ms,
        envelope_xdr,
        approval_nonce: None,
        approval_attestation: None,
    }
}

/// Scenario 6: a genuine simulate-minted nonce committed twice.  The first
/// commit records the nonce in the replay window before failing at keyring
/// signing (no signer key is provisioned for the source); the second commit
/// returns `nonce.replayed`.
#[tokio::test]
#[serial]
async fn commit_replayed_nonce_returns_replayed() {
    keyring_mock::install().expect("mock keyring store init");
    install_test_nonce_key();

    let id = test_balance_id();
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ClaimRpcResponder {
            cb_key_xdr: claim_key_xdr(&id),
            entry_xdr: Some(claim_entry_xdr(
                &id,
                SOURCE_G,
                stellar_xdr::ClaimPredicate::Unconditional,
                CLAIM_AMOUNT_STROOPS,
            )),
            account_key_xdr: account_ledger_key_xdr(SOURCE_G),
            account_xdr: account_entry_xdr_with_seq(
                SOURCE_G,
                SOURCE_BALANCE_STROOPS,
                0,
                SOURCE_SEQ,
            ),
        })
        .mount(&mock_server)
        .await;

    let server =
        WalletServer::new(testnet_profile_with_rpc(&mock_server.uri())).expect("WalletServer::new");

    let simulate = server
        .call_stellar_claim(simulate_args())
        .await
        .expect("simulate should succeed");
    let (nonce, expires, envelope) = extract_commit_triple(&simulate);

    // First commit: passes divergence + nonce HMAC (recording the nonce in the
    // replay window) and then fails at keyring signing because no signer key is
    // provisioned for the source.  The recorded nonce is what makes the second
    // call observable as a replay.
    let first = server
        .call_stellar_claim_commit(commit_args(nonce.clone(), expires, envelope.clone()))
        .await;
    match first {
        Ok(tool_result) => {
            assert_eq!(
                tool_result.is_error,
                Some(true),
                "first commit is expected to fail at keyring signing (is_error=true)"
            );
            assert!(
                !call_result_text(&tool_result).contains("nonce.replayed"),
                "first commit must not itself be a replay"
            );
        }
        Err(err) => {
            // A signing/submit failure surfaced as Err is also acceptable, so long
            // as it is not already a replay.
            assert!(
                !err.to_string().contains("nonce.replayed"),
                "first commit must not itself be a replay, got: {err}"
            );
        }
    }

    // Second commit with the SAME nonce: the replay window already contains it.
    let second = server
        .call_stellar_claim_commit(commit_args(nonce, expires, envelope))
        .await;
    let err = second.expect_err("replayed nonce must return Err");
    assert!(
        err.to_string().contains("nonce.replayed"),
        "second commit must return nonce.replayed, got: {err}"
    );
}

/// Scenario 7: a commit whose re-fetched account carries a different sequence
/// number than the presented envelope encodes rebuilds a non-matching envelope
/// → `simulation.divergence`.
///
/// The divergence check fires before nonce HMAC verification, so a
/// syntactically valid all-zero nonce is sufficient to reach it.
#[tokio::test]
#[serial]
async fn commit_envelope_divergence_on_account_sequence_mismatch() {
    keyring_mock::install().expect("mock keyring store init");
    install_test_nonce_key();

    let id = test_balance_id();

    // Build the presented envelope locally, pinned to SOURCE_SEQ.
    let profile = testnet_profile_with_rpc("http://127.0.0.1:1");
    let mut builder = ClassicOpBuilder::new(
        SOURCE_G,
        SOURCE_SEQ,
        &profile.network_passphrase,
        DEFAULT_CLASSIC_FEE_STROOPS,
    );
    builder
        .claim_claimable_balance(&id.to_hex64())
        .expect("claim op build");
    let presented_envelope = builder.build().expect("envelope build");

    // The commit re-fetch returns an account with a DIFFERENT sequence number,
    // forcing the rebuilt envelope to diverge from the presented one.
    let divergent_seq = SOURCE_SEQ + 999;
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ClaimRpcResponder {
            cb_key_xdr: claim_key_xdr(&id),
            entry_xdr: Some(claim_entry_xdr(
                &id,
                SOURCE_G,
                stellar_xdr::ClaimPredicate::Unconditional,
                CLAIM_AMOUNT_STROOPS,
            )),
            account_key_xdr: account_ledger_key_xdr(SOURCE_G),
            account_xdr: account_entry_xdr_with_seq(
                SOURCE_G,
                SOURCE_BALANCE_STROOPS,
                0,
                divergent_seq,
            ),
        })
        .mount(&mock_server)
        .await;

    let server =
        WalletServer::new(testnet_profile_with_rpc(&mock_server.uri())).expect("WalletServer::new");

    use base64::Engine as _;
    let zero_nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 48]);

    let result = server
        .call_stellar_claim_commit(commit_args(
            zero_nonce,
            3_000_000_000_000, // far future so expiry is not the failing gate
            presented_envelope,
        ))
        .await;
    let err = result.expect_err("account-sequence mismatch must return Err");
    assert!(
        err.to_string().contains("simulation.divergence"),
        "sequence mismatch must produce simulation.divergence, got: {err}"
    );
}

/// Scenario 8: the claimable-balance entry is present for the simulate re-fetch
/// but absent for the commit re-fetch → `claim.balance_not_found`.  The
/// re-fetch existence check fires before divergence and nonce verification, so
/// the genuine simulate-minted nonce is never the failing gate.
#[tokio::test]
#[serial]
async fn commit_entry_gone_returns_balance_not_found() {
    keyring_mock::install().expect("mock keyring store init");
    install_test_nonce_key();

    let id = test_balance_id();
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(EntryGoneResponder {
            cb_key_xdr: claim_key_xdr(&id),
            entry_xdr: claim_entry_xdr(
                &id,
                SOURCE_G,
                stellar_xdr::ClaimPredicate::Unconditional,
                CLAIM_AMOUNT_STROOPS,
            ),
            account_key_xdr: account_ledger_key_xdr(SOURCE_G),
            account_xdr: account_entry_xdr_with_seq(
                SOURCE_G,
                SOURCE_BALANCE_STROOPS,
                0,
                SOURCE_SEQ,
            ),
            cb_hits: Arc::new(AtomicUsize::new(0)),
        })
        .mount(&mock_server)
        .await;

    let server =
        WalletServer::new(testnet_profile_with_rpc(&mock_server.uri())).expect("WalletServer::new");

    // Simulate consumes the first entry query (entry present) and mints a nonce.
    let simulate = server
        .call_stellar_claim(simulate_args())
        .await
        .expect("simulate should succeed while the entry exists");
    let (nonce, expires, envelope) = extract_commit_triple(&simulate);

    // Commit re-fetch now sees an empty entry set → balance not found.
    let result = server
        .call_stellar_claim_commit(commit_args(nonce, expires, envelope))
        .await
        .expect("entry-gone at commit returns a tool-level error, not Err");

    assert_eq!(result.is_error, Some(true));
    assert!(
        call_result_text(&result).contains("claim.balance_not_found"),
        "commit re-fetch of a vanished entry must return claim.balance_not_found, got: {}",
        call_result_text(&result)
    );
}
