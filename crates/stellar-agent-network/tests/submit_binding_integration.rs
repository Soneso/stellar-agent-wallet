//! Signature-network binding at the submit layer.
//!
//! Every test drives `submit_transaction_and_wait` against a wiremock server
//! that answers `getNetwork`, `getLedgerEntries`, `sendTransaction` and
//! `getTransaction`, so the assertions cover the production call order rather
//! than the verification helper in isolation.
//!
//! Mocks share one endpoint and are disambiguated by JSON-RPC method via
//! `body_partial_json`; an unmatched method returns HTTP 404.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration test; panics/unwraps acceptable"
)]

use std::time::Duration;

use serde_json::json;
use stellar_agent_core::error::{NetworkError, ProtocolError, WalletError};
use stellar_agent_network::StellarRpcClient;
use stellar_agent_network::submit::submit_transaction_and_wait;
use stellar_agent_test_support::SubmissionEchoResponder;
use stellar_agent_test_support::signed_envelope::{
    MAINNET_PASSPHRASE, SignedTestEnvelope, TESTNET_PASSPHRASE, account_id_for_seed,
    get_network_result, public_key_for_seed,
};
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer};

const SOURCE_SEED: [u8; 32] = [17u8; 32];
const OP_SOURCE_SEED: [u8; 32] = [23u8; 32];
const FEE_SOURCE_SEED: [u8; 32] = [29u8; 32];
const OUTSIDER_SEED: [u8; 32] = [37u8; 32];

const SUBMIT_TIMEOUT: Duration = Duration::from_secs(10);

// ─────────────────────────────────────────────────────────────────────────────
// Mock harness
// ─────────────────────────────────────────────────────────────────────────────

/// Mounts a full happy-path RPC surface for `envelope`: the endpoint reports
/// `server_passphrase`, the ledger reports the envelope's accounts, and the
/// transaction lands in a ledger.
async fn mount_full_surface(server: &MockServer, envelope: &SignedTestEnvelope, passphrase: &str) {
    mount_method(
        server,
        "getNetwork",
        get_network_result(passphrase),
        "network identity probe",
    )
    .await;
    mount_method(
        server,
        "getLedgerEntries",
        envelope.ledger_entries_result(),
        "signer sets",
    )
    .await;
    mount_method(
        server,
        "sendTransaction",
        json!({
            "hash": envelope.tx_hash_hex(),
            "status": "PENDING",
            "latestLedger": 1000,
            "latestLedgerCloseTime": "1699999999"
        }),
        "send",
    )
    .await;
    mount_method(
        server,
        "getTransaction",
        json!({
            "status": "SUCCESS",
            "txHash": envelope.tx_hash_hex(),
            "ledger": 4567,
            "createdAt": "1700000000",
            "envelopeXdr": null,
            "resultXdr": null,
            "resultMetaXdr": null
        }),
        "confirm",
    )
    .await;
}

async fn mount_method(
    server: &MockServer,
    rpc_method: &str,
    result: serde_json::Value,
    label: &str,
) {
    // The submit-path methods answer with the hash of the transaction they
    // were handed, the way a real endpoint does; every other method answers
    // the fixed body.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({ "method": rpc_method })))
        .respond_with(SubmissionEchoResponder::new(result, TESTNET_PASSPHRASE))
        .named(label.to_owned())
        .mount(server)
        .await;
}

/// Submits `envelope` against `server` declaring the testnet passphrase.
async fn submit(server: &MockServer, envelope: &SignedTestEnvelope) -> Result<(), WalletError> {
    let client = StellarRpcClient::new(&server.uri()).unwrap();
    submit_transaction_and_wait(
        &client,
        envelope.envelope_xdr(),
        SUBMIT_TIMEOUT,
        TESTNET_PASSPHRASE,
        None,
        None,
    )
    .await
    .map(|_| ())
}

/// The JSON-RPC method names the server received, in order.
async fn received_methods(server: &MockServer) -> Vec<String> {
    server
        .received_requests()
        .await
        .expect("wiremock records requests")
        .iter()
        .map(|req| {
            let body: serde_json::Value =
                serde_json::from_slice(&req.body).expect("request body is JSON");
            body["method"]
                .as_str()
                .expect("JSON-RPC request carries a method")
                .to_owned()
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Binding: the passing shape
// ─────────────────────────────────────────────────────────────────────────────

/// An envelope signed by its own source account under the endpoint's network
/// is submitted.
#[tokio::test]
async fn signed_by_source_under_endpoint_network_submits() {
    let envelope = SignedTestEnvelope::for_source(SOURCE_SEED);
    let server = MockServer::start().await;
    mount_full_surface(&server, &envelope, TESTNET_PASSPHRASE).await;

    let result = submit(&server, &envelope).await;

    assert!(
        result.is_ok(),
        "an envelope bound to the endpoint's network must submit: {result:?}"
    );
}

/// A successful submit issues exactly `getNetwork`, `getLedgerEntries`,
/// `sendTransaction`, `getTransaction`, in that order.
///
/// The discriminating assertion is the sequence itself: the identity probe and
/// the signer fetch must both precede the send, or the send would go out
/// before either was known.
#[tokio::test]
async fn successful_submit_issues_probe_then_signers_then_send_then_poll() {
    let envelope = SignedTestEnvelope::for_source(SOURCE_SEED);
    let server = MockServer::start().await;
    mount_full_surface(&server, &envelope, TESTNET_PASSPHRASE).await;

    submit(&server, &envelope).await.expect("submit succeeds");

    assert_eq!(
        received_methods(&server).await,
        vec![
            "getNetwork",
            "getLedgerEntries",
            "sendTransaction",
            "getTransaction"
        ],
        "the probe and the signer fetch must both precede the send"
    );
}

/// A fee-bump whose outer and inner signatures are both made under the
/// endpoint's network is submitted.
#[tokio::test]
async fn fee_bump_signed_under_endpoint_network_submits() {
    let envelope = SignedTestEnvelope::builder(SOURCE_SEED)
        .fee_bump(FEE_SOURCE_SEED)
        .build();
    let server = MockServer::start().await;
    mount_full_surface(&server, &envelope, TESTNET_PASSPHRASE).await;

    let result = submit(&server, &envelope).await;

    assert!(
        result.is_ok(),
        "a fee-bump bound to the endpoint's network must submit: {result:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Binding: mainnet-signed refusals
// ─────────────────────────────────────────────────────────────────────────────

/// An envelope carrying an extra signature made under the mainnet network id
/// is refused, even though its other signature is valid for the endpoint.
#[tokio::test]
async fn added_mainnet_signature_refuses_envelope_signed_for_mainnet() {
    let envelope = SignedTestEnvelope::builder(SOURCE_SEED)
        .sign(SOURCE_SEED, TESTNET_PASSPHRASE)
        .sign(SOURCE_SEED, MAINNET_PASSPHRASE)
        .build();
    let server = MockServer::start().await;
    mount_full_surface(&server, &envelope, TESTNET_PASSPHRASE).await;

    let err = submit(&server, &envelope)
        .await
        .expect_err("a mainnet-bound signature must be refused");

    assert_eq!(err.code(), "network.envelope_signed_for_mainnet", "{err:?}");
    assert!(
        !received_methods(&server)
            .await
            .contains(&"sendTransaction".to_owned()),
        "the refusal must precede the send"
    );
}

/// A payment whose operation source signed for the endpoint's network, while
/// the transaction source signed for mainnet, is refused.
///
/// The discriminating assertion is that the transaction source's mainnet
/// signature is caught: a check that stopped at the first signature that
/// verifies would pass this envelope.
#[tokio::test]
async fn operation_source_testnet_with_tx_source_mainnet_refuses() {
    let source = account_id_for_seed(SOURCE_SEED);
    let envelope = SignedTestEnvelope::builder(SOURCE_SEED)
        .operation_source(OP_SOURCE_SEED)
        .sign(OP_SOURCE_SEED, TESTNET_PASSPHRASE)
        .sign(SOURCE_SEED, MAINNET_PASSPHRASE)
        .build();
    assert_eq!(envelope.account_ids().len(), 2, "two source accounts");
    assert_eq!(envelope.account_ids()[0], source);

    let server = MockServer::start().await;
    mount_full_surface(&server, &envelope, TESTNET_PASSPHRASE).await;

    let err = submit(&server, &envelope)
        .await
        .expect_err("a mainnet-bound transaction-source signature must be refused");

    assert_eq!(err.code(), "network.envelope_signed_for_mainnet", "{err:?}");
}

/// A fee-bump whose outer signature was made under the mainnet network id is
/// refused, while its inner signature is bound to the endpoint's network.
#[tokio::test]
async fn fee_bump_outer_signed_for_mainnet_refuses() {
    let envelope = SignedTestEnvelope::builder(SOURCE_SEED)
        .fee_bump(FEE_SOURCE_SEED)
        .sign(SOURCE_SEED, TESTNET_PASSPHRASE)
        .sign_outer(FEE_SOURCE_SEED, MAINNET_PASSPHRASE)
        .build();
    let server = MockServer::start().await;
    mount_full_surface(&server, &envelope, TESTNET_PASSPHRASE).await;

    let err = submit(&server, &envelope)
        .await
        .expect_err("a mainnet-bound outer signature must be refused");

    assert_eq!(err.code(), "network.envelope_signed_for_mainnet", "{err:?}");
}

// ─────────────────────────────────────────────────────────────────────────────
// Binding: unverifiable and unsigned refusals
// ─────────────────────────────────────────────────────────────────────────────

/// A signature by a key that is not a signer of any source account is refused
/// as unverifiable, and the reported hint is that signature's own.
#[tokio::test]
async fn signature_by_unknown_key_refuses_unverifiable() {
    let envelope = SignedTestEnvelope::builder(SOURCE_SEED)
        .sign(OUTSIDER_SEED, TESTNET_PASSPHRASE)
        .build();
    let server = MockServer::start().await;
    mount_full_surface(&server, &envelope, TESTNET_PASSPHRASE).await;

    let err = submit(&server, &envelope)
        .await
        .expect_err("a signature by an unknown key must be refused");

    assert_eq!(
        err.code(),
        "network.envelope_signature_unverifiable",
        "{err:?}"
    );
    let outsider = public_key_for_seed(OUTSIDER_SEED);
    let expected_hint = format!(
        "{:02x}{:02x}{:02x}{:02x}",
        outsider[28], outsider[29], outsider[30], outsider[31]
    );
    assert!(
        err.message().contains(&expected_hint),
        "the refusal must report the offending signature's hint {expected_hint}: {}",
        err.message()
    );
}

/// A signature that claims a gathered signer's hint but was produced by a
/// different key is refused.
///
/// The discriminating assertion is the refusal: the real signer is in the
/// candidate pool, so a check that ignored hints would accept this envelope.
#[tokio::test]
async fn signature_with_colliding_hint_of_wrong_key_refuses() {
    let source = account_id_for_seed(SOURCE_SEED);
    let extra = public_key_for_seed(OP_SOURCE_SEED);
    let stolen_hint: [u8; 4] = extra[28..32].try_into().unwrap();

    let envelope = SignedTestEnvelope::builder(SOURCE_SEED)
        .ed25519_signer(&source, OP_SOURCE_SEED)
        .sign_with_hint(SOURCE_SEED, TESTNET_PASSPHRASE, stolen_hint)
        .build();
    let server = MockServer::start().await;
    mount_full_surface(&server, &envelope, TESTNET_PASSPHRASE).await;

    let err = submit(&server, &envelope)
        .await
        .expect_err("a signature whose hint names a different signer must be refused");

    assert_eq!(
        err.code(),
        "network.envelope_signature_unverifiable",
        "{err:?}"
    );
}

/// An account whose only extra signer is a hash-x signer cannot answer for a
/// signature bearing that signer's hint: hash-x contributes no ed25519 key.
#[tokio::test]
async fn hash_x_signer_cannot_verify_a_signature_bearing_its_hint() {
    let source = account_id_for_seed(SOURCE_SEED);
    let outsider = public_key_for_seed(OUTSIDER_SEED);

    // The hash-x signer's key bytes are the outsider's public key, so the
    // outsider's signature carries a hint that matches a signer the account
    // really reports — one that no ed25519 verification can use.
    let envelope = SignedTestEnvelope::builder(SOURCE_SEED)
        .hash_x_signer(&source, outsider)
        .sign(OUTSIDER_SEED, TESTNET_PASSPHRASE)
        .build();
    let server = MockServer::start().await;
    mount_full_surface(&server, &envelope, TESTNET_PASSPHRASE).await;

    let err = submit(&server, &envelope)
        .await
        .expect_err("a hash-x signer cannot bind a signature to a network");

    assert_eq!(
        err.code(),
        "network.envelope_signature_unverifiable",
        "{err:?}"
    );
}

/// An envelope with no signatures is refused before the send, with its own
/// code rather than an unverifiable-signature report.
#[tokio::test]
async fn unsigned_envelope_refuses_envelope_unsigned() {
    let envelope = SignedTestEnvelope::builder(SOURCE_SEED).unsigned().build();
    let server = MockServer::start().await;
    mount_full_surface(&server, &envelope, TESTNET_PASSPHRASE).await;

    let err = submit(&server, &envelope)
        .await
        .expect_err("an unsigned envelope must be refused");

    assert_eq!(err.code(), "network.envelope_unsigned", "{err:?}");
    assert!(
        !received_methods(&server)
            .await
            .contains(&"sendTransaction".to_owned()),
        "the refusal must precede the send"
    );
}

/// An operation source that does not exist on the ledger is refused before the
/// send, turning an on-chain failure into a pre-send refusal.
#[tokio::test]
async fn absent_operation_source_refuses_account_not_found() {
    let op_source = account_id_for_seed(OP_SOURCE_SEED);
    let envelope = SignedTestEnvelope::builder(SOURCE_SEED)
        .operation_source(OP_SOURCE_SEED)
        .sign(SOURCE_SEED, TESTNET_PASSPHRASE)
        .sign(OP_SOURCE_SEED, TESTNET_PASSPHRASE)
        .absent_from_ledger(&op_source)
        .build();
    let server = MockServer::start().await;
    mount_full_surface(&server, &envelope, TESTNET_PASSPHRASE).await;

    let err = submit(&server, &envelope)
        .await
        .expect_err("an operation source absent from the ledger must be refused");

    assert_eq!(err.code(), "network.account_not_found", "{err:?}");
    assert!(
        !received_methods(&server)
            .await
            .contains(&"sendTransaction".to_owned()),
        "the refusal must precede the send"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Envelope shapes the binding check cannot cover
// ─────────────────────────────────────────────────────────────────────────────

/// A legacy V0 envelope is refused before any RPC call: it has no SEP-23
/// tagged-transaction form, so no payload can be built for it.
#[tokio::test]
async fn v0_envelope_refuses_before_any_rpc_call() {
    use stellar_xdr::{
        Limits, Memo, SequenceNumber, TransactionEnvelope, TransactionV0, TransactionV0Envelope,
        TransactionV0Ext, Uint256, WriteXdr,
    };

    let v0 = TransactionEnvelope::TxV0(TransactionV0Envelope {
        tx: TransactionV0 {
            source_account_ed25519: Uint256(public_key_for_seed(SOURCE_SEED)),
            fee: 100,
            seq_num: SequenceNumber(1),
            time_bounds: None,
            memo: Memo::None,
            operations: vec![].try_into().unwrap(),
            ext: TransactionV0Ext::V0,
        },
        signatures: vec![].try_into().unwrap(),
    });
    let v0_xdr = v0.to_xdr_base64(Limits::none()).unwrap();

    let server = MockServer::start().await;
    let envelope = SignedTestEnvelope::for_source(SOURCE_SEED);
    mount_full_surface(&server, &envelope, TESTNET_PASSPHRASE).await;

    let client = StellarRpcClient::new(&server.uri()).unwrap();
    let err = submit_transaction_and_wait(
        &client,
        &v0_xdr,
        SUBMIT_TIMEOUT,
        TESTNET_PASSPHRASE,
        None,
        None,
    )
    .await
    .expect_err("a V0 envelope must be refused");

    assert!(
        matches!(
            err,
            WalletError::Protocol(ProtocolError::XdrCodecFailed { ref detail })
                if detail.contains("legacy V0")
        ),
        "expected the legacy-V0 rejection, got: {err:?}"
    );
    assert!(
        received_methods(&server).await.is_empty(),
        "a V0 envelope must cost no round trip"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Endpoint identity
// ─────────────────────────────────────────────────────────────────────────────

/// An endpoint that reports the mainnet passphrase refuses the submit, whatever
/// the caller declared, and does so before the signer fetch.
#[tokio::test]
async fn endpoint_reporting_mainnet_refuses_mainnet_write_forbidden() {
    let envelope = SignedTestEnvelope::for_source(SOURCE_SEED);
    let server = MockServer::start().await;
    mount_full_surface(&server, &envelope, MAINNET_PASSPHRASE).await;

    let err = submit(&server, &envelope)
        .await
        .expect_err("a mainnet endpoint must be refused");

    assert!(
        matches!(
            err,
            WalletError::Network(NetworkError::MainnetWriteForbidden)
        ),
        "expected MainnetWriteForbidden, got: {err:?}"
    );
    assert_eq!(
        received_methods(&server).await,
        vec!["getNetwork"],
        "the refusal must precede the signer fetch and the send"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Accounts created by the transaction that names them
// ─────────────────────────────────────────────────────────────────────────────

/// Builds the CAP-33 sponsored-creation sandwich: the funder begins
/// sponsorship, creates `created`, and `created` ends the sponsorship as the
/// source of the third operation. Both keys sign.
///
/// Returns the signed envelope as base64 XDR.
fn sponsored_creation_sandwich(funder_seed: [u8; 32], created_seed: [u8; 32]) -> String {
    use ed25519_dalek::{Signer as _, SigningKey};
    use sha2::{Digest, Sha256};
    use stellar_xdr::{
        AccountId, BeginSponsoringFutureReservesOp, CreateAccountOp, DecoratedSignature, Hash,
        Limits, Memo, MuxedAccount, Operation, OperationBody, Preconditions, PublicKey,
        SequenceNumber, Signature, SignatureHint, Transaction, TransactionEnvelope, TransactionExt,
        TransactionSignaturePayload, TransactionSignaturePayloadTaggedTransaction,
        TransactionV1Envelope, Uint256, WriteXdr,
    };

    let funder = public_key_for_seed(funder_seed);
    let created = public_key_for_seed(created_seed);
    let created_account_id = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(created)));

    let operations = vec![
        Operation {
            source_account: None,
            body: OperationBody::BeginSponsoringFutureReserves(BeginSponsoringFutureReservesOp {
                sponsored_id: created_account_id.clone(),
            }),
        },
        Operation {
            source_account: None,
            body: OperationBody::CreateAccount(CreateAccountOp {
                destination: created_account_id,
                starting_balance: 0,
            }),
        },
        Operation {
            source_account: Some(MuxedAccount::Ed25519(Uint256(created))),
            body: OperationBody::EndSponsoringFutureReserves,
        },
    ];

    let tx = Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(funder)),
        fee: 300,
        seq_num: SequenceNumber(1),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: operations.try_into().unwrap(),
        ext: TransactionExt::V0,
    };

    let payload = TransactionSignaturePayload {
        network_id: Hash(Sha256::digest(TESTNET_PASSPHRASE.as_bytes()).into()),
        tagged_transaction: TransactionSignaturePayloadTaggedTransaction::Tx(tx.clone()),
    };
    let hash: [u8; 32] = Sha256::digest(payload.to_xdr(Limits::none()).unwrap()).into();

    let sign = |seed: [u8; 32]| {
        let key = SigningKey::from_bytes(&seed);
        let public = key.verifying_key().to_bytes();
        DecoratedSignature {
            hint: SignatureHint(public[28..32].try_into().unwrap()),
            signature: Signature(key.sign(&hash).to_bytes().to_vec().try_into().unwrap()),
        }
    };

    let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: vec![sign(funder_seed), sign(created_seed)]
            .try_into()
            .unwrap(),
    });

    envelope.to_xdr_base64(Limits::none()).unwrap()
}

/// The `getLedgerEntries` keys the server was asked for, as base64 XDR.
async fn requested_ledger_keys(server: &MockServer) -> Vec<String> {
    server
        .received_requests()
        .await
        .expect("wiremock records requests")
        .iter()
        .filter_map(|req| {
            let body: serde_json::Value = serde_json::from_slice(&req.body).ok()?;
            if body["method"].as_str()? != "getLedgerEntries" {
                return None;
            }
            Some(
                body["params"]["keys"]
                    .as_array()?
                    .iter()
                    .filter_map(|k| k.as_str().map(str::to_owned))
                    .collect::<Vec<String>>(),
            )
        })
        .flatten()
        .collect()
}

/// The base64 `LedgerKey::Account` XDR for `account_id`.
fn account_ledger_key_b64(account_id: &str) -> String {
    use stellar_xdr::{
        AccountId, LedgerKey, LedgerKeyAccount, Limits, PublicKey, Uint256, WriteXdr,
    };
    let bytes = stellar_strkey::ed25519::PublicKey::from_string(account_id)
        .unwrap()
        .0;
    LedgerKey::Account(LedgerKeyAccount {
        account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(bytes))),
    })
    .to_xdr_base64(Limits::none())
    .unwrap()
}

/// An operation source the same transaction creates is verified against its own
/// master key, without being demanded from the ledger.
///
/// The discriminating assertion is that the submit succeeds while the ledger
/// reports only the funder: a check that required every operation source to
/// have a ledger entry would refuse a sponsored-creation sandwich, which is a
/// transaction this wallet builds.
#[tokio::test]
async fn operation_source_created_by_the_transaction_verifies_against_its_master_key() {
    let funder_seed = SOURCE_SEED;
    let created_seed = OP_SOURCE_SEED;
    let envelope_xdr = sponsored_creation_sandwich(funder_seed, created_seed);
    let funder = account_id_for_seed(funder_seed);
    let created = account_id_for_seed(created_seed);

    let server = MockServer::start().await;
    mount_method(
        &server,
        "getNetwork",
        get_network_result(TESTNET_PASSPHRASE),
        "network identity probe",
    )
    .await;
    mount_method(
        &server,
        "getLedgerEntries",
        stellar_agent_test_support::signed_envelope::ledger_entries_result_for(&[&funder]),
        "signer sets",
    )
    .await;
    mount_method(
        &server,
        "sendTransaction",
        json!({
            "hash": "aa".repeat(32),
            "status": "PENDING",
            "latestLedger": 1000,
            "latestLedgerCloseTime": "1699999999"
        }),
        "send",
    )
    .await;
    mount_method(
        &server,
        "getTransaction",
        json!({
            "status": "SUCCESS",
            "txHash": "aa".repeat(32),
            "ledger": 4567,
            "createdAt": "1700000000",
            "envelopeXdr": null,
            "resultXdr": null,
            "resultMetaXdr": null
        }),
        "confirm",
    )
    .await;

    let client = StellarRpcClient::new(&server.uri()).unwrap();
    let result = submit_transaction_and_wait(
        &client,
        &envelope_xdr,
        SUBMIT_TIMEOUT,
        TESTNET_PASSPHRASE,
        None,
        None,
    )
    .await;

    assert!(
        result.is_ok(),
        "an account created by the transaction that names it as an operation \
         source must not be demanded from the ledger: {result:?}"
    );
    let requested = requested_ledger_keys(&server).await;
    assert!(
        requested.contains(&account_ledger_key_b64(&funder)),
        "the funder's signer set is read from the ledger"
    );
    assert!(
        !requested.contains(&account_ledger_key_b64(&created)),
        "an account the transaction creates must not be demanded from the ledger"
    );
}

/// A signature by the account the transaction creates, made under the mainnet
/// network id, is still refused.
///
/// Deriving the master key locally must not become a way past the binding
/// check for the very account that derivation covers.
#[tokio::test]
async fn created_operation_source_signed_for_mainnet_still_refuses() {
    use ed25519_dalek::{Signer as _, SigningKey};
    use sha2::{Digest, Sha256};
    use stellar_xdr::{
        DecoratedSignature, Hash, Limits, ReadXdr, Signature, SignatureHint, TransactionEnvelope,
        TransactionSignaturePayload, TransactionSignaturePayloadTaggedTransaction, WriteXdr,
    };

    let funder_seed = SOURCE_SEED;
    let created_seed = OP_SOURCE_SEED;
    let envelope_xdr = sponsored_creation_sandwich(funder_seed, created_seed);

    // Add a mainnet-bound signature by the created account to the sandwich.
    let mut envelope = TransactionEnvelope::from_xdr_base64(&envelope_xdr, Limits::none()).unwrap();
    let TransactionEnvelope::Tx(ref mut v1) = envelope else {
        panic!("the sandwich is a V1 envelope");
    };
    let mainnet_payload = TransactionSignaturePayload {
        network_id: Hash(Sha256::digest(MAINNET_PASSPHRASE.as_bytes()).into()),
        tagged_transaction: TransactionSignaturePayloadTaggedTransaction::Tx(v1.tx.clone()),
    };
    let mainnet_hash: [u8; 32] =
        Sha256::digest(mainnet_payload.to_xdr(Limits::none()).unwrap()).into();
    let key = SigningKey::from_bytes(&created_seed);
    let public = key.verifying_key().to_bytes();
    let mut signatures = v1.signatures.to_vec();
    signatures.push(DecoratedSignature {
        hint: SignatureHint(public[28..32].try_into().unwrap()),
        signature: Signature(
            key.sign(&mainnet_hash)
                .to_bytes()
                .to_vec()
                .try_into()
                .unwrap(),
        ),
    });
    v1.signatures = signatures.try_into().unwrap();
    let tampered = envelope.to_xdr_base64(Limits::none()).unwrap();

    let funder = account_id_for_seed(funder_seed);
    let server = MockServer::start().await;
    mount_method(
        &server,
        "getNetwork",
        get_network_result(TESTNET_PASSPHRASE),
        "network identity probe",
    )
    .await;
    mount_method(
        &server,
        "getLedgerEntries",
        stellar_agent_test_support::signed_envelope::ledger_entries_result_for(&[&funder]),
        "signer sets",
    )
    .await;

    let client = StellarRpcClient::new(&server.uri()).unwrap();
    let err = submit_transaction_and_wait(
        &client,
        &tampered,
        SUBMIT_TIMEOUT,
        TESTNET_PASSPHRASE,
        None,
        None,
    )
    .await
    .expect_err("a mainnet-bound signature by the created account must be refused");

    assert_eq!(err.code(), "network.envelope_signed_for_mainnet", "{err:?}");
}

/// A fee-bump whose outer transaction is signed and whose inner transaction is
/// not is refused as unsigned.
///
/// The discriminating assertion is the code: counting signatures across the
/// whole envelope rather than per signature set would let the outer signature
/// stand in for the missing inner one and pass this envelope through to the
/// network.
#[tokio::test]
async fn fee_bump_with_unsigned_inner_refuses_envelope_unsigned() {
    let envelope = SignedTestEnvelope::builder(SOURCE_SEED)
        .fee_bump(FEE_SOURCE_SEED)
        .unsigned()
        .sign_outer(FEE_SOURCE_SEED, TESTNET_PASSPHRASE)
        .build();
    let server = MockServer::start().await;
    mount_full_surface(&server, &envelope, TESTNET_PASSPHRASE).await;

    let err = submit(&server, &envelope)
        .await
        .expect_err("an unsigned inner transaction must be refused");

    assert_eq!(err.code(), "network.envelope_unsigned", "{err:?}");
    assert!(
        !received_methods(&server)
            .await
            .contains(&"sendTransaction".to_owned()),
        "the refusal must precede the send"
    );
}

/// An operation source created only by a LATER operation of the same
/// transaction is still demanded from the ledger, and refused when absent.
///
/// The account does not exist when the operation that names it as source
/// applies, because operations apply in order. The discriminating assertion is
/// `network.account_not_found`: dropping the strictly-earlier bound on the
/// creation search would treat this account as created and verify it against
/// its own master key, losing the pre-send refusal.
#[tokio::test]
async fn operation_source_created_by_a_later_operation_is_not_treated_as_created() {
    use ed25519_dalek::{Signer as _, SigningKey};
    use sha2::{Digest, Sha256};
    use stellar_xdr::{
        AccountId, Asset, CreateAccountOp, DecoratedSignature, Hash, Limits, Memo, MuxedAccount,
        Operation, OperationBody, PaymentOp, Preconditions, PublicKey, SequenceNumber, Signature,
        SignatureHint, Transaction, TransactionEnvelope, TransactionExt,
        TransactionSignaturePayload, TransactionSignaturePayloadTaggedTransaction,
        TransactionV1Envelope, Uint256, WriteXdr,
    };

    let funder = public_key_for_seed(SOURCE_SEED);
    let later = public_key_for_seed(OP_SOURCE_SEED);

    // Operation 0 is sourced by `later`; operation 1 creates it. Apply order
    // means operation 0 runs against a ledger where `later` does not exist.
    let operations = vec![
        Operation {
            source_account: Some(MuxedAccount::Ed25519(Uint256(later))),
            body: OperationBody::Payment(PaymentOp {
                destination: MuxedAccount::Ed25519(Uint256(funder)),
                asset: Asset::Native,
                amount: 1_000_000,
            }),
        },
        Operation {
            source_account: None,
            body: OperationBody::CreateAccount(CreateAccountOp {
                destination: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(later))),
                starting_balance: 10_000_000,
            }),
        },
    ];

    let tx = Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(funder)),
        fee: 200,
        seq_num: SequenceNumber(1),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: operations.try_into().unwrap(),
        ext: TransactionExt::V0,
    };

    let payload = TransactionSignaturePayload {
        network_id: Hash(Sha256::digest(TESTNET_PASSPHRASE.as_bytes()).into()),
        tagged_transaction: TransactionSignaturePayloadTaggedTransaction::Tx(tx.clone()),
    };
    let hash: [u8; 32] = Sha256::digest(payload.to_xdr(Limits::none()).unwrap()).into();
    let sign = |seed: [u8; 32]| {
        let key = SigningKey::from_bytes(&seed);
        let public = key.verifying_key().to_bytes();
        DecoratedSignature {
            hint: SignatureHint(public[28..32].try_into().unwrap()),
            signature: Signature(key.sign(&hash).to_bytes().to_vec().try_into().unwrap()),
        }
    };
    let envelope_xdr = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: vec![sign(SOURCE_SEED), sign(OP_SOURCE_SEED)]
            .try_into()
            .unwrap(),
    })
    .to_xdr_base64(Limits::none())
    .unwrap();

    let funder_id = account_id_for_seed(SOURCE_SEED);
    let server = MockServer::start().await;
    mount_method(
        &server,
        "getNetwork",
        get_network_result(TESTNET_PASSPHRASE),
        "network identity probe",
    )
    .await;
    mount_method(
        &server,
        "getLedgerEntries",
        stellar_agent_test_support::signed_envelope::ledger_entries_result_for(&[&funder_id]),
        "signer sets",
    )
    .await;

    let client = StellarRpcClient::new(&server.uri()).unwrap();
    let err = submit_transaction_and_wait(
        &client,
        &envelope_xdr,
        SUBMIT_TIMEOUT,
        TESTNET_PASSPHRASE,
        None,
        None,
    )
    .await
    .expect_err("an operation source created only later must be refused");

    assert_eq!(err.code(), "network.account_not_found", "{err:?}");
    assert!(
        requested_ledger_keys(&server)
            .await
            .contains(&account_ledger_key_b64(&account_id_for_seed(
                OP_SOURCE_SEED
            ))),
        "an account created only by a later operation must still be demanded \
         from the ledger"
    );
}
