//! What each commit tool records when its submission does not confirm.
//!
//! The record-before-send mechanism is one seam, but every commit tool builds
//! its own recorder and reports its own refusal. These pins run each tool
//! against an endpoint that accepts the send and never confirms it, and assert
//! the three records that make a timeout reconcilable: the receipt, the pending
//! audit row with no settled row beside it, and the full transaction hash on
//! the response.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration test; panics and unwraps are acceptable"
)]

use serial_test::serial;
use stellar_agent_claimable::id::BalanceId;
use stellar_agent_core::profile::receipt::{ReceiptStatus, ReceiptStore};
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_mcp::server::{
    Sep43SignAndSubmitTransactionArgs, StellarClaimArgs, StellarClaimCommitArgs,
    StellarCreateAccountArgs, StellarCreateAccountCommitArgs, StellarTransactionStatusArgs,
    StellarTrustlineArgs, StellarTrustlineCommitArgs, WalletServer,
};
use stellar_agent_test_support::keyring_mock;
use stellar_agent_test_support::xdr_fixtures::{
    account_entry_xdr_with_seq, account_ledger_key_xdr,
};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer};

mod common;

const SOURCE_BALANCE_STROOPS: i64 = 500_000_000_000;
/// The issuer the trustline verb resolves `USDC` to on testnet. Its ledger
/// entry has to be answerable: the clawback gate is fail-closed on the issuer's
/// flags.
const USDC_TESTNET_ISSUER: &str = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";
const SOURCE_SEQ: i64 = 42;

fn gstrkey_for_seed(seed: [u8; 32]) -> String {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    stellar_strkey::ed25519::PublicKey(signing_key.verifying_key().to_bytes())
        .to_string()
        .to_string()
}

fn sstrkey_for_seed(seed: [u8; 32]) -> String {
    stellar_strkey::ed25519::PrivateKey(seed)
        .as_unredacted()
        .to_string()
        .to_string()
}

fn install_test_nonce_key() {
    use base64::Engine as _;
    let nonce_key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]);
    keyring_core::Entry::new("n-svc", "n-acct")
        .expect("Entry::new for nonce key")
        .set_password(&nonce_key_b64)
        .expect("set_password for nonce key");
}

fn call_result_json(result: &rmcp::model::CallToolResult) -> serde_json::Value {
    let text = result
        .content
        .first()
        .and_then(|content| content.as_text())
        .map(|t| t.text.clone())
        .expect("result must carry text content");
    serde_json::from_str(&text).expect("result content must be JSON")
}

fn test_balance_id() -> BalanceId {
    BalanceId::parse(&"ab".repeat(32)).expect("valid 64-hex balance id")
}

fn claim_key_xdr(id: &BalanceId) -> String {
    use stellar_xdr::{
        ClaimableBalanceId, Hash, LedgerKey, LedgerKeyClaimableBalance, Limits, WriteXdr,
    };
    LedgerKey::ClaimableBalance(LedgerKeyClaimableBalance {
        balance_id: ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash(id.hash())),
    })
    .to_xdr_base64(Limits::none())
    .expect("claimable-balance key XDR encode")
}

fn claim_entry_xdr(id: &BalanceId, claimant_g: &str, amount: i64) -> String {
    use stellar_xdr::{
        AccountId, Asset, ClaimPredicate, ClaimableBalanceEntry, ClaimableBalanceEntryExt,
        ClaimableBalanceId, Claimant, ClaimantV0, Hash, LedgerEntryData, Limits, PublicKey,
        Uint256, VecM, WriteXdr,
    };
    let pk = stellar_strkey::ed25519::PublicKey::from_string(claimant_g).expect("valid G-strkey");
    let entry = ClaimableBalanceEntry {
        balance_id: ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash(id.hash())),
        claimants: VecM::try_from(vec![Claimant::ClaimantTypeV0(ClaimantV0 {
            destination: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk.0))),
            predicate: ClaimPredicate::Unconditional,
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

/// Seeds the signer key and returns `(profile, server, source G-strkey)` for a
/// profile whose submissions time out.
fn timeout_server(
    mock_uri: &str,
    account: &str,
    seed: [u8; 32],
) -> (Profile, WalletServer, String) {
    let source_g = gstrkey_for_seed(seed);
    keyring_core::Entry::new("svc", account)
        .expect("Entry::new")
        .set_password(&sstrkey_for_seed(seed))
        .expect("set_password");
    let profile = common::timeout_profile(mock_uri, account);
    let server = WalletServer::new(profile.clone()).expect("WalletServer::new");
    (profile, server, source_g)
}

/// Asserts the three records a timed-out commit leaves, and returns
/// `(tx_hash, envelope_hash)`.
fn assert_timeout_records(
    profile: &Profile,
    profile_name: &str,
    result: &rmcp::model::CallToolResult,
) -> (String, String) {
    let json = call_result_json(result);
    assert_eq!(
        json["error"]["code"], "submission.tx_timeout",
        "an accepted-but-unconfirmed submission reports a timeout: {json}"
    );
    let details = &json["error"]["details"];
    let tx_hash = details["tx_hash"]
        .as_str()
        .unwrap_or_else(|| panic!("the timeout carries the transaction hash: {json}"))
        .to_owned();
    assert_eq!(tx_hash.len(), 64, "the full hash travels as data: {json}");
    let envelope_hash = details["envelope_hash"]
        .as_str()
        .unwrap_or_else(|| panic!("the timeout carries the envelope hash: {json}"))
        .to_owned();
    assert_eq!(details["outcome"], "unknown");
    assert!(
        !json["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains(&tx_hash),
        "the message stays redacted: {json}"
    );

    let rows = common::audit_rows(profile);
    assert_eq!(
        common::rows_of_kind(&rows, "value_action_pending").len(),
        1,
        "exactly one pending row is written before the send: {rows:?}"
    );
    assert!(
        common::rows_of_kind(&rows, "value_action_submitted").is_empty(),
        "an unconfirmed submission writes no submitted row: {rows:?}"
    );

    let receipts = ReceiptStore::open(profile_name).expect("receipt store");
    let receipt = receipts
        .get(&envelope_hash)
        .expect("receipt store read")
        .expect("the submission is recorded");
    assert_eq!(receipt.status, ReceiptStatus::Pending);
    assert!(receipt.submitted, "the record says the bytes left");

    (tx_hash, envelope_hash)
}

// ─────────────────────────────────────────────────────────────────────────────
// stellar_claim_commit
// ─────────────────────────────────────────────────────────────────────────────

/// A timed-out claim leaves the record, and `stellar_transaction_status`
/// settles it once the chain has the transaction.
#[tokio::test]
#[serial]
async fn a_timed_out_claim_records_the_submission_and_reports_the_hash() {
    let _data_root = common::isolated_data_root();
    keyring_mock::install().expect("mock keyring store init");
    install_test_nonce_key();

    let seed = [0x71_u8; 32];
    let claimant_g = gstrkey_for_seed(seed);
    let id = test_balance_id();
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(common::TimeoutRpc::new(vec![
            (
                claim_key_xdr(&id),
                claim_entry_xdr(&id, &claimant_g, 5_000_000),
            ),
            (
                account_ledger_key_xdr(&claimant_g),
                account_entry_xdr_with_seq(&claimant_g, SOURCE_BALANCE_STROOPS, 0, SOURCE_SEQ),
            ),
        ]))
        .mount(&mock_server)
        .await;

    let (profile, server, _) = timeout_server(&mock_server.uri(), "acct-claim-record", seed);
    let profile_name = server.profile_name_for_approval();

    let sim = server
        .call_stellar_claim(StellarClaimArgs {
            chain_id: "stellar:testnet".to_owned(),
            balance_id: "ab".repeat(32),
            source_account: Some(claimant_g.clone()),
        })
        .await
        .expect("simulate must not error");
    let sim_json = call_result_json(&sim);
    assert_ne!(
        sim.is_error,
        Some(true),
        "simulate must succeed: {sim_json}"
    );
    let data = sim_json.get("data").expect("simulate carries data");

    let commit = server
        .call_stellar_claim_commit(StellarClaimCommitArgs {
            chain_id: "stellar:testnet".to_owned(),
            balance_id: "ab".repeat(32),
            source_account: Some(claimant_g),
            nonce: data["nonce"].as_str().expect("nonce").to_owned(),
            expires_at_unix_ms: data["expires_at_unix_ms"].as_u64().expect("expires"),
            envelope_xdr: data["envelope_xdr"].as_str().expect("envelope").to_owned(),
            approval_nonce: None,
            approval_attestation: None,
        })
        .await
        .expect("commit must not error");

    assert_timeout_records(&profile, &profile_name, &commit);
}

// ─────────────────────────────────────────────────────────────────────────────
// stellar_trustline_commit
// ─────────────────────────────────────────────────────────────────────────────

/// A timed-out trustline change leaves the record.
#[tokio::test]
#[serial]
async fn a_timed_out_trustline_records_the_submission_and_reports_the_hash() {
    let _data_root = common::isolated_data_root();
    keyring_mock::install().expect("mock keyring store init");
    install_test_nonce_key();

    let seed = [0x72_u8; 32];
    let source_g = gstrkey_for_seed(seed);
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(common::TimeoutRpc::new(vec![
            (
                account_ledger_key_xdr(&source_g),
                account_entry_xdr_with_seq(&source_g, SOURCE_BALANCE_STROOPS, 0, SOURCE_SEQ),
            ),
            (
                account_ledger_key_xdr(USDC_TESTNET_ISSUER),
                account_entry_xdr_with_seq(USDC_TESTNET_ISSUER, SOURCE_BALANCE_STROOPS, 0, 1),
            ),
        ]))
        .mount(&mock_server)
        .await;

    let (profile, server, _) = timeout_server(&mock_server.uri(), "acct-trustline-record", seed);
    let profile_name = server.profile_name_for_approval();

    let simulate_args = StellarTrustlineArgs {
        chain_id: "stellar:testnet".to_owned(),
        from: source_g.clone(),
        asset: "USDC".to_owned(),
        limit_stroops: Some("1000000000".to_owned()),
        classic_base: None,
    };
    let sim = server
        .call_stellar_trustline(simulate_args.clone())
        .await
        .expect("simulate must not error");
    let sim_json = call_result_json(&sim);
    assert_ne!(
        sim.is_error,
        Some(true),
        "simulate must succeed: {sim_json}"
    );
    let data = sim_json.get("data").expect("simulate carries data");

    let commit = server
        .call_stellar_trustline_commit(StellarTrustlineCommitArgs {
            chain_id: simulate_args.chain_id.clone(),
            from: simulate_args.from.clone(),
            nonce: data["nonce"].as_str().expect("nonce").to_owned(),
            expires_at_unix_ms: data["expires_at_unix_ms"].as_u64().expect("expires"),
            envelope_xdr: data["envelope_xdr"].as_str().expect("envelope").to_owned(),
            approval_nonce: None,
            approval_attestation: None,
        })
        .await
        .expect("commit must not error");

    assert_timeout_records(&profile, &profile_name, &commit);
}

// ─────────────────────────────────────────────────────────────────────────────
// stellar_create_account_commit
// ─────────────────────────────────────────────────────────────────────────────

/// A timed-out account creation leaves the record, and the settled row appears
/// once `stellar_transaction_status` reconciles it.
#[tokio::test]
#[serial]
async fn a_timed_out_create_account_records_the_submission_and_reports_the_hash() {
    let _data_root = common::isolated_data_root();
    keyring_mock::install().expect("mock keyring store init");
    install_test_nonce_key();

    let seed = [0x73_u8; 32];
    let source_g = gstrkey_for_seed(seed);
    let destination_g = gstrkey_for_seed([0x74_u8; 32]);
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(common::TimeoutRpc::new(vec![(
            account_ledger_key_xdr(&source_g),
            account_entry_xdr_with_seq(&source_g, SOURCE_BALANCE_STROOPS, 0, SOURCE_SEQ),
        )]))
        .mount(&mock_server)
        .await;

    let (profile, server, _) = timeout_server(&mock_server.uri(), "acct-create-record", seed);
    let profile_name = server.profile_name_for_approval();

    let sim = server
        .call_stellar_create_account(StellarCreateAccountArgs {
            chain_id: "stellar:testnet".to_owned(),
            source: source_g.clone(),
            destination: destination_g.clone(),
            starting_balance: serde_json::from_str(r#""2 XLM""#).unwrap(),
            classic_base: None,
        })
        .await
        .expect("simulate must not error");
    let sim_json = call_result_json(&sim);
    assert_ne!(
        sim.is_error,
        Some(true),
        "simulate must succeed: {sim_json}"
    );
    let data = sim_json.get("data").expect("simulate carries data");

    let commit = server
        .call_stellar_create_account_commit(StellarCreateAccountCommitArgs {
            chain_id: "stellar:testnet".to_owned(),
            source: source_g,
            destination: destination_g,
            starting_balance: serde_json::from_str(r#""2 XLM""#).unwrap(),
            nonce: data["nonce"].as_str().expect("nonce").to_owned(),
            expires_at_unix_ms: data["expires_at_unix_ms"].as_u64().expect("expires"),
            envelope_xdr: data["envelope_xdr"].as_str().expect("envelope").to_owned(),
            approval_nonce: None,
            approval_attestation: None,
        })
        .await
        .expect("commit must not error");

    let (tx_hash, envelope_hash) = assert_timeout_records(&profile, &profile_name, &commit);

    // The record is what makes a second attempt at the same sequence refuse,
    // and what `stellar_transaction_status` addresses.
    let status = server
        .call_stellar_transaction_status(StellarTransactionStatusArgs {
            chain_id: "stellar:testnet".to_owned(),
            tx_hash,
        })
        .await
        .expect("the status tool must not error");
    let status_json = call_result_json(&status);
    assert_eq!(
        status_json["data"]["record"]["envelope_hash"], envelope_hash,
        "the status tool addresses the record the commit wrote: {status_json}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// stellar_sep43_sign_and_submit_transaction
// ─────────────────────────────────────────────────────────────────────────────

/// A timed-out SEP-43 submission leaves the record its recovery protocol names.
///
/// The envelope is the caller's, so the policy engine sizes no value and no
/// spending-window reservation is taken. The receipt and the pending row are
/// what make the timeout reconcilable and the sequence protected, and the
/// tool's `status: "pending"` response contract is unchanged.
#[tokio::test]
#[serial]
async fn a_timed_out_sep43_submission_is_recorded_and_reconcilable() {
    let _data_root = common::isolated_data_root();
    keyring_mock::install().expect("mock keyring store init");
    install_test_nonce_key();

    let seed = [0x76_u8; 32];
    let envelope = stellar_agent_test_support::signed_envelope::SignedTestEnvelope::builder(seed)
        .sequence(SOURCE_SEQ + 1)
        .build();
    let source_g = envelope.source().to_owned();
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(common::TimeoutRpc::new(vec![(
            account_ledger_key_xdr(&source_g),
            account_entry_xdr_with_seq(&source_g, SOURCE_BALANCE_STROOPS, 0, SOURCE_SEQ),
        )]))
        .mount(&mock_server)
        .await;

    // The tool checks the loaded signing key against the profile's signer
    // account, so that account is the source's own address here.
    let (profile, server, _) = timeout_server(&mock_server.uri(), &source_g, seed);
    let profile_name = server.profile_name_for_approval();

    let result = server
        .call_stellar_sep43_sign_and_submit_transaction(Sep43SignAndSubmitTransactionArgs {
            chain_id: "stellar:testnet".to_owned(),
            transaction_xdr: envelope.envelope_xdr().to_owned(),
            network_passphrase: None,
            address: None,
        })
        .await
        .expect("the tool must not error");

    let json = call_result_json(&result);
    assert_eq!(
        json["data"]["status"], "pending",
        "the tool's response contract is unchanged: {json}"
    );
    let tx_hash = json["data"]["txHash"]
        .as_str()
        .unwrap_or_else(|| panic!("the pending response carries the hash: {json}"))
        .to_owned();

    // The record is keyed on the bytes that were sent, which carry the
    // signature the tool added.
    let signed_xdr = json["data"]["signedTxXdr"]
        .as_str()
        .unwrap_or_else(|| panic!("the response carries the signed envelope: {json}"));
    let envelope_hash = stellar_agent_network::envelope_hash_hex(signed_xdr);
    let receipts = ReceiptStore::open(&profile_name).expect("receipt store");
    let receipt = receipts
        .get(&envelope_hash)
        .expect("receipt store read")
        .expect("the submission is recorded");
    assert_eq!(receipt.status, ReceiptStatus::Pending);
    assert!(receipt.submitted, "the record says the bytes left");
    assert_eq!(receipt.source, source_g, "the record names the source");

    let rows = common::audit_rows(&profile);
    assert_eq!(
        common::rows_of_kind(&rows, "value_action_pending").len(),
        1,
        "a pending row is written before the send: {rows:?}"
    );

    // And `stellar_transaction_status` finds it.
    let status = server
        .call_stellar_transaction_status(StellarTransactionStatusArgs {
            chain_id: "stellar:testnet".to_owned(),
            tx_hash,
        })
        .await
        .expect("the status tool must not error");
    let status_json = call_result_json(&status);
    assert_eq!(
        status_json["data"]["record"]["envelope_hash"], envelope_hash,
        "the status tool addresses the record the tool wrote: {status_json}"
    );
}

/// A muxed transaction source reaches the send through the SEP-43 tool.
#[tokio::test]
#[serial]
async fn a_muxed_source_reaches_the_send_through_sep43() {
    let _data_root = common::isolated_data_root();
    keyring_mock::install().expect("mock keyring store init");
    install_test_nonce_key();

    let seed = [0x77_u8; 32];
    let envelope = stellar_agent_test_support::signed_envelope::SignedTestEnvelope::builder(seed)
        .sequence(SOURCE_SEQ + 1)
        .muxed_source_id(42)
        .build();
    let source_g = envelope.source().to_owned();
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(common::TimeoutRpc::new(vec![(
            account_ledger_key_xdr(&source_g),
            account_entry_xdr_with_seq(&source_g, SOURCE_BALANCE_STROOPS, 0, SOURCE_SEQ),
        )]))
        .mount(&mock_server)
        .await;

    let (_profile, server, _) = timeout_server(&mock_server.uri(), &source_g, seed);

    let result = server
        .call_stellar_sep43_sign_and_submit_transaction(Sep43SignAndSubmitTransactionArgs {
            chain_id: "stellar:testnet".to_owned(),
            transaction_xdr: envelope.envelope_xdr().to_owned(),
            network_passphrase: None,
            address: None,
        })
        .await
        .expect("the tool must not error");

    let json = call_result_json(&result);
    assert_eq!(
        json["data"]["status"], "pending",
        "a muxed source must not be refused before the send: {json}"
    );
}

/// A confirmed SEP-43 submission writes one settled row.
///
/// The tool carries its own contract in an opaque-action row naming what it
/// signed, and that row settles the pending row the recorder wrote. A second
/// row from the recorder would put one send in the log twice.
#[tokio::test]
#[serial]
async fn a_confirmed_sep43_submission_writes_one_settled_row() {
    let _data_root = common::isolated_data_root();
    keyring_mock::install().expect("mock keyring store init");
    install_test_nonce_key();

    let seed = [0x78_u8; 32];
    let envelope = stellar_agent_test_support::signed_envelope::SignedTestEnvelope::builder(seed)
        .sequence(SOURCE_SEQ + 1)
        .build();
    let source_g = envelope.source().to_owned();
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            common::TimeoutRpc::new(vec![(
                account_ledger_key_xdr(&source_g),
                account_entry_xdr_with_seq(&source_g, SOURCE_BALANCE_STROOPS, 0, SOURCE_SEQ),
            )])
            .confirming_in(1_001),
        )
        .mount(&mock_server)
        .await;

    let (profile, server, _) = timeout_server(&mock_server.uri(), &source_g, seed);

    let result = server
        .call_stellar_sep43_sign_and_submit_transaction(Sep43SignAndSubmitTransactionArgs {
            chain_id: "stellar:testnet".to_owned(),
            transaction_xdr: envelope.envelope_xdr().to_owned(),
            network_passphrase: None,
            address: None,
        })
        .await
        .expect("the tool must not error");

    let json = call_result_json(&result);
    assert_eq!(
        json["data"]["status"], "success",
        "the submission confirms: {json}"
    );

    let rows = common::audit_rows(&profile);
    let submitted = common::rows_of_kind(&rows, "value_action_submitted");
    assert_eq!(
        submitted.len(),
        1,
        "one confirmed send, one settled row: {rows:?}"
    );
    assert_eq!(
        submitted[0]["opaque_reason"], "raw_transaction_signature",
        "the row kept is the one carrying the tool's own contract: {rows:?}"
    );
    assert_eq!(
        common::rows_of_kind(&rows, "value_action_pending").len(),
        1,
        "the pending row is written once: {rows:?}"
    );

    // The row that survives has to close out the pending row. A settled row
    // that does not name the submission leaves it owed for good, and the
    // duplicate comes back the moment anyone reconciles the hash.
    let signed_xdr = json["data"]["signedTxXdr"]
        .as_str()
        .unwrap_or_else(|| panic!("the response carries the signed envelope: {json}"));
    let envelope_hash = stellar_agent_network::envelope_hash_hex(signed_xdr);
    assert_eq!(
        submitted[0]["envelope_hash"], envelope_hash,
        "the settled row names the submission it settles: {rows:?}"
    );
    assert_eq!(
        stellar_agent_core::audit_log::reader::value_action_settlement(
            &profile.audit_log_path,
            &envelope_hash
        ),
        stellar_agent_core::audit_log::reader::ValueActionSettlement::Settled,
        "the pending row is accounted for: {rows:?}"
    );

    // And reconciling the same transaction appends nothing.
    let tx_hash = json["data"]["txHash"]
        .as_str()
        .unwrap_or_else(|| panic!("the response carries the hash: {json}"))
        .to_owned();
    let status = server
        .call_stellar_transaction_status(StellarTransactionStatusArgs {
            chain_id: "stellar:testnet".to_owned(),
            tx_hash,
        })
        .await
        .expect("the status tool must not error");
    assert_ne!(status.is_error, Some(true), "reconciliation must succeed");
    let rows_after = common::audit_rows(&profile);
    assert_eq!(
        common::rows_of_kind(&rows_after, "value_action_submitted").len(),
        1,
        "reconciling a settled submission appends no second row: {rows_after:?}"
    );
}
