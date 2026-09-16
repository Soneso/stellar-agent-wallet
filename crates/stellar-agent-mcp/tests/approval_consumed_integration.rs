//! What a commit does to the approval it spends, and what the gate does with
//! the spent entry afterwards.
//!
//! A commit burns its nonce before the transaction is sent, so an approval
//! whose submission never confirms would otherwise be left live and attested
//! with nothing to say about it. The commit path replaces it with a tombstone
//! instead: the entry keeps its attestation, records the transaction it was
//! spent on, and makes the gate refuse a second commit under a code that says
//! so.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics acceptable in integration tests"
)]

use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine as _;
use serial_test::serial;
use stellar_agent_core::DEFAULT_CLASSIC_FEE_STROOPS;
use stellar_agent_core::approval::{
    ApprovalKind, ConsumedOutcome, DEFAULT_TTL_MS, PendingApproval, PendingApprovalStore,
    attestation::{compute_attestation, envelope_sha256},
    process_uid_for_attestation,
};
use stellar_agent_core::policy::v1::{
    AccountIdentityView, AccountReservesView, CounterpartyCacheView, Sep10SessionView,
    Sep45SessionView,
};
use stellar_agent_core::policy::{
    ApprovalRequest, Decision, PolicyEngine, PolicyError, ToolDescriptor,
};
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_mcp::server::{StellarPayCommitArgs, WalletServer};
use stellar_agent_network::{Asset, ClassicOpBuilder};
use stellar_agent_nonce::{NonceMint, ToolCatalogue};
use stellar_agent_test_support::keyring_mock;
use stellar_agent_test_support::xdr_fixtures::{
    account_entry_xdr_with_seq, account_ledger_key_xdr,
};
use tempfile::TempDir;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

mod common;

/// Source-account sequence the mocked ledger reports.
const SOURCE_SEQ: i64 = 100;
const DEST: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";
const AMOUNT_STROOPS: i64 = 100_000_000;

/// A policy engine that requires an operator approval for every dispatch,
/// which is what makes the attestation gate run.
struct RequireApprovalEngine;

impl PolicyEngine for RequireApprovalEngine {
    fn evaluate(
        &self,
        _tool: &ToolDescriptor,
        _args: &serde_json::Value,
        _profile: &Profile,
        _account_view: Option<&dyn AccountReservesView>,
        _identity_view: Option<&dyn AccountIdentityView>,
        _counterparty_cache: Option<&dyn CounterpartyCacheView>,
        _sep10_sessions: Option<&dyn Sep10SessionView>,
        _sep45_sessions: Option<&dyn Sep45SessionView>,
    ) -> Result<Decision, PolicyError> {
        Ok(Decision::RequireApproval(ApprovalRequest::new(
            "test-nonce".into(),
            120,
        )))
    }
}

/// Answers a submit as accepted and never confirms it, or refuses it outright.
struct TimeoutRpcResponder {
    account_key_xdr: String,
    account_xdr: String,
    /// When set, `sendTransaction` answers with the endpoint's own verdict on
    /// the transaction rather than accepting it for inclusion.
    refuse_send: bool,
}

/// A `TransactionResult` reporting `txINSUFFICIENT_FEE`, which is what a
/// definitive send-step refusal carries.
fn insufficient_fee_result_xdr() -> String {
    use stellar_xdr::{
        Limits, TransactionResult, TransactionResultExt, TransactionResultResult, WriteXdr,
    };
    TransactionResult {
        fee_charged: 0,
        result: TransactionResultResult::TxInsufficientFee,
        ext: TransactionResultExt::V0,
    }
    .to_xdr_base64(Limits::none())
    .expect("result XDR encode")
}

#[async_trait]
impl Respond for TimeoutRpcResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body = serde_json::from_slice::<serde_json::Value>(&request.body)
            .unwrap_or_else(|_| serde_json::json!({}));
        let req_id = body
            .get("id")
            .cloned()
            .unwrap_or_else(|| serde_json::json!(1));
        let rpc_method = body
            .get("method")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");

        let result = match rpc_method {
            "getNetwork" => common::EndpointNetwork::testnet().result(),
            "getLedgerEntries" => {
                let raw = String::from_utf8_lossy(&request.body);
                if raw.contains(&self.account_key_xdr) {
                    serde_json::json!({
                        "entries": [{
                            "key": self.account_key_xdr,
                            "xdr": self.account_xdr,
                            "lastModifiedLedgerSeq": 1000
                        }],
                        "latestLedger": 1001
                    })
                } else {
                    serde_json::json!({ "entries": [], "latestLedger": 1001 })
                }
            }
            "sendTransaction" if self.refuse_send => serde_json::json!({
                "hash": common::submitted_tx_hash(request),
                "status": "ERROR",
                "errorResultXdr": insufficient_fee_result_xdr(),
                "latestLedger": 1001,
                "latestLedgerCloseTime": "1234567890"
            }),
            "sendTransaction" => serde_json::json!({
                "hash": common::submitted_tx_hash(request),
                "status": "PENDING",
                "latestLedger": 1001,
                "latestLedgerCloseTime": "1234567890"
            }),
            "getTransaction" => serde_json::json!({
                "status": "NOT_FOUND",
                "latestLedger": 1002,
                "oldestLedger": 1,
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

fn gstrkey_for_seed(seed: [u8; 32]) -> String {
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
    format!(
        "{}",
        stellar_strkey::ed25519::PublicKey(signing.verifying_key().to_bytes())
    )
}

fn sstrkey_for_seed(seed: [u8; 32]) -> String {
    stellar_strkey::ed25519::PrivateKey(seed)
        .as_unredacted()
        .to_string()
        .to_string()
}

struct PayCommitCatalogue;

impl ToolCatalogue for PayCommitCatalogue {
    fn is_registered(&self, tool_name: &str) -> bool {
        tool_name == "stellar_pay_commit"
    }
}

/// Builds the envelope the commit path rebuilds from these arguments, so the
/// divergence check passes.
fn commit_envelope(source: &str, passphrase: &str) -> String {
    let mut builder =
        ClassicOpBuilder::new(source, SOURCE_SEQ, passphrase, DEFAULT_CLASSIC_FEE_STROOPS);
    builder
        .payment(
            DEST,
            stellar_agent_core::StellarAmount::from_stroops(AMOUNT_STROOPS),
            &Asset::Native,
        )
        .expect("payment op");
    builder.build().expect("envelope build")
}

fn commit_args(
    source: &str,
    envelope_xdr: &str,
    nonce: String,
    expiry: u64,
    approval: &str,
    attestation: &str,
) -> StellarPayCommitArgs {
    StellarPayCommitArgs {
        chain_id: "stellar:testnet".to_owned(),
        source: source.to_owned(),
        destination: DEST.to_owned(),
        amount: None,
        amount_in_stroops: Some(AMOUNT_STROOPS.to_string()),
        asset: "native".to_owned(),
        memo_text: None,
        memo_id: None,
        memo_hash_hex: None,
        memo_return_hex: None,
        nonce,
        expires_at_unix_ms: expiry,
        envelope_xdr: envelope_xdr.to_owned(),
        approval_nonce: Some(approval.to_owned()),
        approval_attestation: Some(attestation.to_owned()),
    }
}

/// A commit whose submission never confirms spends its approval and leaves a
/// tombstone that says so, and the gate refuses a second commit under it.
#[tokio::test]
#[serial]
async fn a_timed_out_commit_consumes_its_approval_and_the_gate_refuses_a_second() {
    exercise_approval_consumption(false).await;
}

/// A receipt blocks approval reuse while status repairs a failed tombstone write.
#[tokio::test]
#[serial]
async fn owed_approval_blocks_reuse_until_status_completes_consumption() {
    exercise_approval_consumption(true).await;
}

async fn exercise_approval_consumption(fail_once: bool) {
    let _data_root = common::isolated_data_root();
    keyring_mock::install().expect("mock keyring store init");

    let seed = [0x71_u8; 32];
    let source_g = gstrkey_for_seed(seed);
    keyring_core::Entry::new("svc", "acct-consumed")
        .expect("Entry::new")
        .set_password(&sstrkey_for_seed(seed))
        .expect("set_password");
    keyring_core::Entry::new("n-svc", "n-acct")
        .expect("Entry::new")
        .set_password(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0xC1_u8; 32]))
        .expect("set_password");

    let mock_server = MockServer::start().await;
    let held_store = Arc::new(std::sync::Mutex::new(None));

    let mut profile = Profile::builder_testnet("svc", "acct-consumed", "n-svc", "n-acct")
        .with_noop_engine()
        .build();
    profile.rpc_url = mock_server.uri();
    profile.submit_timeout_seconds = Some(1);
    common::install_test_audit_key(&mut profile);

    // The attestation key the gate verifies against.
    let attestation_key = [0xD2_u8; 32];
    keyring_core::Entry::new(
        &profile.attestation_key_id.service,
        &profile.attestation_key_id.account,
    )
    .expect("Entry::new")
    .set_password(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(attestation_key))
    .expect("set_password");

    let envelope_xdr = commit_envelope(&source_g, &profile.network_passphrase);

    // An attested approval for exactly this envelope.
    let now_unix_ms = stellar_agent_core::timefmt::now_unix_ms().expect("clock");
    let approval_dir = TempDir::new().expect("approval dir");
    let store_path = approval_dir.path().join("acct-consumed.toml");
    let process_uid = process_uid_for_attestation().expect("process uid");
    let entry = PendingApproval::new_payment_pending(
        envelope_xdr.clone(),
        envelope_xdr.as_bytes(),
        DEST.to_owned(),
        AMOUNT_STROOPS,
        "XLM".to_owned(),
        None,
        DEFAULT_CLASSIC_FEE_STROOPS,
        SOURCE_SEQ + 1,
        process_uid.clone(),
        DEFAULT_TTL_MS,
    )
    .expect("pending approval");
    let approval_nonce = entry.approval_nonce.clone();
    let blob = compute_attestation(
        &attestation_key,
        &approval_nonce,
        &envelope_sha256(envelope_xdr.as_bytes()),
        &process_uid,
    );
    let attestation_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(blob);
    {
        let mut store = PendingApprovalStore::open(store_path.clone()).expect("approval store");
        store.insert(entry, now_unix_ms).expect("insert");
        store
            .record_attestation(&approval_nonce, blob)
            .expect("record attestation");
    }

    let lock_path = store_path.clone();
    let hold = Arc::clone(&held_store);
    let responder = TimeoutRpcResponder {
        account_key_xdr: account_ledger_key_xdr(&source_g),
        account_xdr: account_entry_xdr_with_seq(&source_g, 100_000_000_000_000, 0, SOURCE_SEQ),
        refuse_send: false,
    };
    Mock::given(method("POST"))
        .respond_with(move |request: &Request| {
            let rpc: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            if fail_once && rpc["method"] == "sendTransaction" {
                *hold.lock().unwrap() =
                    Some(PendingApprovalStore::open(lock_path.clone()).unwrap());
            }
            responder.respond(request)
        })
        .mount(&mock_server)
        .await;

    let nonce_mint = NonceMint::from_profile(&profile).expect("NonceMint::from_profile");
    let now_ms = stellar_agent_core::timefmt::now_unix_ms().expect("clock");
    let expiry = now_ms + 60_000;
    let nonce = nonce_mint
        .mint(
            &PayCommitCatalogue,
            envelope_xdr.as_bytes(),
            now_ms,
            expiry,
            "stellar_pay_commit",
            "stellar:testnet",
        )
        .expect("mint")
        .to_base64();

    let mut server = WalletServer::new(profile).expect("WalletServer::new");
    server.set_policy_engine_for_test(Arc::new(RequireApprovalEngine));
    server.set_approval_dir_for_test(approval_dir.path().to_path_buf());

    let commit = server
        .call_stellar_pay_commit(commit_args(
            &source_g,
            &envelope_xdr,
            nonce,
            expiry,
            &approval_nonce,
            &attestation_b64,
        ))
        .await
        .expect("commit must not error");
    let json: serde_json::Value = serde_json::from_str(
        commit
            .content
            .first()
            .and_then(|c| c.as_text())
            .map(|t| t.text.as_str())
            .expect("the commit result must carry text"),
    )
    .expect("JSON");
    assert_eq!(
        json["error"]["code"], "submission.tx_timeout",
        "the submission must time out: {json}"
    );
    let tx_hash = json["error"]["details"]["tx_hash"]
        .as_str()
        .expect("the timeout reports its hash")
        .to_owned();

    drop(held_store.lock().unwrap().take());
    let receipts =
        stellar_agent_core::profile::receipt::ReceiptStore::open("acct-consumed").unwrap();
    let receipt = receipts.find_by_tx_hash(&tx_hash).unwrap().unwrap();
    assert_eq!(
        receipt.approval_nonce.as_deref(),
        Some(approval_nonce.as_str())
    );
    if fail_once {
        let store = PendingApprovalStore::open(store_path.clone()).unwrap();
        assert!(matches!(
            store.get(&approval_nonce).unwrap().kind,
            ApprovalKind::PaymentSimulated { .. }
        ));
        assert!(!receipt.approval_consumed);
    }

    // A second commit under the same approval is refused, under a code that
    // tells the agent the approval was already spent.
    let nonce2 = nonce_mint
        .mint(
            &PayCommitCatalogue,
            envelope_xdr.as_bytes(),
            now_ms + 1,
            expiry,
            "stellar_pay_commit",
            "stellar:testnet",
        )
        .expect("mint")
        .to_base64();
    let second = server
        .call_stellar_pay_commit(commit_args(
            &source_g,
            &envelope_xdr,
            nonce2,
            expiry,
            &approval_nonce,
            &attestation_b64,
        ))
        .await
        .expect("the second commit must not error");
    let (code, _message, text) = common::assert_business_envelope(&second);
    assert_eq!(
        code, "policy.approval_consumed",
        "a spent approval is refused under its own code: {text}"
    );
    if fail_once {
        use stellar_agent_mcp::server::StellarTransactionStatusArgs;
        for _ in 0..2 {
            let result = server
                .call_stellar_transaction_status(StellarTransactionStatusArgs {
                    chain_id: "stellar:testnet".to_owned(),
                    tx_hash: tx_hash.clone(),
                })
                .await
                .unwrap();
            assert_ne!(
                result.is_error,
                Some(true),
                "status must complete the owed transition: {result:?}"
            );
        }
        assert!(
            receipts
                .get(&receipt.envelope_hash)
                .unwrap()
                .unwrap()
                .approval_consumed
        );
    }

    // The approval is spent, not removed: the tombstone keeps the attestation
    // and names the transaction to reconcile.
    let store = PendingApprovalStore::open(store_path).expect("approval store");
    let tombstone = store
        .get(&approval_nonce)
        .expect("the approval entry must still be in the store");
    match &tombstone.kind {
        ApprovalKind::Consumed {
            original_kind_name,
            tx_hash: recorded,
            outcome,
        } => {
            assert_eq!(original_kind_name, "PaymentSimulated");
            assert_eq!(recorded, &tx_hash);
            assert_eq!(
                *outcome,
                ConsumedOutcome::Unknown,
                "the submission's outcome is not known"
            );
        }
        other => panic!("the approval must be a Consumed tombstone; got {other:?}"),
    }
    assert_eq!(
        tombstone.attestation_blob_b64.as_deref(),
        Some(attestation_b64.as_str()),
        "the attestation the submission was made under is retained, unchanged"
    );
    drop(store);
}

/// A commit the network refuses outright leaves its approval untouched.
///
/// Nothing was queued and no value moved, so the agent is expected to make a
/// fresh attempt. Tombstoning the approval would make that attempt refuse at
/// the gate with nothing to reconcile.
#[tokio::test]
#[serial]
async fn a_refused_commit_leaves_its_approval_untouched() {
    let _data_root = common::isolated_data_root();
    keyring_mock::install().expect("mock keyring store init");

    let seed = [0x75_u8; 32];
    let source_g = gstrkey_for_seed(seed);
    keyring_core::Entry::new("svc", "acct-rejected")
        .expect("Entry::new")
        .set_password(&sstrkey_for_seed(seed))
        .expect("set_password");
    keyring_core::Entry::new("n-svc", "n-acct")
        .expect("Entry::new")
        .set_password(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0xC5_u8; 32]))
        .expect("set_password");

    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(TimeoutRpcResponder {
            account_key_xdr: account_ledger_key_xdr(&source_g),
            account_xdr: account_entry_xdr_with_seq(&source_g, 100_000_000_000_000, 0, SOURCE_SEQ),
            refuse_send: true,
        })
        .mount(&mock_server)
        .await;

    let mut profile = Profile::builder_testnet("svc", "acct-rejected", "n-svc", "n-acct")
        .with_noop_engine()
        .build();
    profile.rpc_url = mock_server.uri();
    profile.submit_timeout_seconds = Some(1);
    common::install_test_audit_key(&mut profile);

    // The attestation key the gate verifies against.
    let attestation_key = [0xD5_u8; 32];
    keyring_core::Entry::new(
        &profile.attestation_key_id.service,
        &profile.attestation_key_id.account,
    )
    .expect("Entry::new")
    .set_password(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(attestation_key))
    .expect("set_password");

    let envelope_xdr = commit_envelope(&source_g, &profile.network_passphrase);

    // An attested approval for exactly this envelope.
    let now_unix_ms = stellar_agent_core::timefmt::now_unix_ms().expect("clock");
    let approval_dir = TempDir::new().expect("approval dir");
    let store_path = approval_dir.path().join("acct-rejected.toml");
    let process_uid = process_uid_for_attestation().expect("process uid");
    let entry = PendingApproval::new_payment_pending(
        envelope_xdr.clone(),
        envelope_xdr.as_bytes(),
        DEST.to_owned(),
        AMOUNT_STROOPS,
        "XLM".to_owned(),
        None,
        DEFAULT_CLASSIC_FEE_STROOPS,
        SOURCE_SEQ + 1,
        process_uid.clone(),
        DEFAULT_TTL_MS,
    )
    .expect("pending approval");
    let approval_nonce = entry.approval_nonce.clone();
    let blob = compute_attestation(
        &attestation_key,
        &approval_nonce,
        &envelope_sha256(envelope_xdr.as_bytes()),
        &process_uid,
    );
    let attestation_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(blob);
    {
        let mut store = PendingApprovalStore::open(store_path.clone()).expect("approval store");
        store.insert(entry, now_unix_ms).expect("insert");
        store
            .record_attestation(&approval_nonce, blob)
            .expect("record attestation");
    }

    let nonce_mint = NonceMint::from_profile(&profile).expect("NonceMint::from_profile");
    let now_ms = stellar_agent_core::timefmt::now_unix_ms().expect("clock");
    let expiry = now_ms + 60_000;
    let nonce = nonce_mint
        .mint(
            &PayCommitCatalogue,
            envelope_xdr.as_bytes(),
            now_ms,
            expiry,
            "stellar_pay_commit",
            "stellar:testnet",
        )
        .expect("mint")
        .to_base64();

    let mut server = WalletServer::new(profile).expect("WalletServer::new");
    server.set_policy_engine_for_test(Arc::new(RequireApprovalEngine));
    server.set_approval_dir_for_test(approval_dir.path().to_path_buf());

    let commit = server
        .call_stellar_pay_commit(commit_args(
            &source_g,
            &envelope_xdr,
            nonce,
            expiry,
            &approval_nonce,
            &attestation_b64,
        ))
        .await
        .expect("commit must not error");
    let json: serde_json::Value = serde_json::from_str(
        commit
            .content
            .first()
            .and_then(|c| c.as_text())
            .map(|t| t.text.as_str())
            .expect("the commit result must carry text"),
    )
    .expect("JSON");
    assert_eq!(
        json["error"]["code"], "submission.tx_malformed",
        "the network refused the bytes, which is not a timeout: {json}"
    );

    // The approval stands: no value moved, and the agent is expected to try
    // again under it.
    let store = PendingApprovalStore::open(store_path).expect("approval store");
    let entry = store
        .get(&approval_nonce)
        .expect("the approval entry must still be in the store");
    assert!(
        matches!(entry.kind, ApprovalKind::PaymentSimulated { .. }),
        "a refused send leaves the approval as it was; got {:?}",
        entry.kind
    );
    assert_eq!(
        entry.attestation_blob_b64.as_deref(),
        Some(attestation_b64.as_str()),
        "the attestation is unchanged"
    );
}
