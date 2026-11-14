//! Owner tests for muxed payment destinations in the network crate.
//!
//! Each owner test uses its own fixed destination key, so a temporary
//! mutation guarded on one key changes only that test's outcome.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics and unwraps are acceptable in unit tests"
)]

use stellar_agent_core::StellarAmount;
use stellar_agent_core::error::{ValidationError, WalletError};
use stellar_xdr::{
    AccountId, AlphaNum4, Asset as XdrAsset, AssetCode4, Hash, Limits, Memo, MuxedAccount,
    MuxedAccountMed25519, Operation, OperationBody, PaymentOp, Preconditions, PublicKey, ReadXdr,
    SequenceNumber, StringM, Transaction, TransactionEnvelope, TransactionExt,
    TransactionV1Envelope, Uint256, WriteXdr,
};

use crate::builder::{Asset, ClassicOpBuilder};
use crate::cross_check::MemoObservation;

const TESTNET: &str = "Test SDF Network ; September 2015";
const MAINNET: &str = "Public Global Stellar Network ; September 2015";
const SOURCE: &str = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";
const ISSUER: &str = "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL";

/// The `G...` strkey of `key`.
fn g(key: [u8; 32]) -> String {
    stellar_strkey::ed25519::PublicKey(key)
        .to_string()
        .as_str()
        .to_owned()
}

/// The `M...` strkey of `key` and `id`.
fn m(key: [u8; 32], id: u64) -> String {
    stellar_strkey::ed25519::MuxedAccount { ed25519: key, id }
        .to_string()
        .as_str()
        .to_owned()
}

/// The `C...` strkey of `bytes`.
fn c(bytes: [u8; 32]) -> String {
    stellar_strkey::Contract(bytes)
        .to_string()
        .as_str()
        .to_owned()
}

/// The `W...` strkey of `bytes` and `id`.
fn w(bytes: [u8; 32], id: u64) -> String {
    stellar_strkey::MuxedContract {
        contract_id: bytes,
        id,
    }
    .to_string()
    .as_str()
    .to_owned()
}

/// Builds a one-payment envelope and returns its base64 XDR.
fn pay(network: &str, destination: &str, asset: &Asset, memo: &Memo) -> String {
    let mut builder = ClassicOpBuilder::new(SOURCE, 41, network, 100);
    builder
        .payment(destination, StellarAmount::from_stroops(25_000_000), asset)
        .map(|_| ())
        .unwrap();
    builder.memo(memo).map(|_| ()).unwrap();
    builder.build().unwrap()
}

/// The payment operation and memo of an envelope.
fn decoded(xdr: &str) -> (PaymentOp, Memo) {
    let TransactionEnvelope::Tx(envelope) =
        TransactionEnvelope::from_xdr_base64(xdr, Limits::none()).unwrap()
    else {
        panic!("a v1 envelope");
    };
    let [operation] = envelope.tx.operations.as_slice() else {
        panic!("one operation");
    };
    let OperationBody::Payment(payment) = &operation.body else {
        panic!("a payment");
    };
    (payment.clone(), envelope.tx.memo.clone())
}

/// The refusal of a payment to `destination`.
fn payment_refusal(destination: &str) -> WalletError {
    let mut builder = ClassicOpBuilder::new(SOURCE, 41, TESTNET, 100);
    builder
        .payment(destination, StellarAmount::from_stroops(1), &Asset::Native)
        .map(|_| ())
        .expect_err("refused")
}

fn issued() -> Asset {
    Asset::Credit {
        code: "USDC".to_owned(),
        issuer: ISSUER.to_owned(),
    }
}

/// An M0 destination is muxed: the builder emits the `MuxedEd25519` arm
/// with the same key and ID zero on both networks, and C and W refuse.
#[test]
fn classic_m_zero_wire() {
    let key = [0xA1; 32];
    for network in [TESTNET, MAINNET] {
        for asset in [Asset::Native, issued()] {
            let (payment, _) = decoded(&pay(network, &m(key, 0), &asset, &Memo::None));
            assert_eq!(
                payment.destination,
                MuxedAccount::MuxedEd25519(MuxedAccountMed25519 {
                    id: 0,
                    ed25519: Uint256(key),
                }),
                "{network}: M0 stays muxed with ID zero"
            );
        }
    }
    for refused in [c([0xA1; 32]), w([0xA1; 32], 0), w([0xA1; 32], 17)] {
        assert!(matches!(
            payment_refusal(&refused),
            WalletError::Validation(ValidationError::AddressInvalid { .. })
        ));
    }
}

/// A nonzero ID survives: M17 and M-max keep the exact key and ID.
#[test]
fn classic_m_id_wire() {
    let key = [0xA2; 32];
    for network in [TESTNET, MAINNET] {
        for id in [17, u64::MAX] {
            let (payment, _) = decoded(&pay(network, &m(key, id), &Asset::Native, &Memo::None));
            let MuxedAccount::MuxedEd25519(muxed) = payment.destination else {
                panic!("{network}: M{id} must be muxed");
            };
            assert_eq!(muxed.id, id, "{network}: the ID is kept");
            assert_eq!(muxed.ed25519, Uint256(key), "{network}: the key is kept");
        }
    }
    // A second key keeps its own bytes and ID.
    let (payment, _) = decoded(&pay(TESTNET, &m([0xE2; 32], 18), &issued(), &Memo::None));
    assert_eq!(
        payment.destination,
        MuxedAccount::MuxedEd25519(MuxedAccountMed25519 {
            id: 18,
            ed25519: Uint256([0xE2; 32]),
        })
    );
}

/// The G payment envelope built directly from XDR types. The unsigned
/// envelope carries no network passphrase.
fn golden_g_envelope(destination: [u8; 32], asset: XdrAsset) -> String {
    let source = stellar_strkey::ed25519::PublicKey::from_string(SOURCE).unwrap();
    let operations = vec![Operation {
        source_account: None,
        body: OperationBody::Payment(PaymentOp {
            destination: MuxedAccount::Ed25519(Uint256(destination)),
            asset,
            amount: 25_000_000,
        }),
    }];
    TransactionEnvelope::Tx(TransactionV1Envelope {
        tx: Transaction {
            source_account: MuxedAccount::Ed25519(Uint256(source.0)),
            fee: 100,
            seq_num: SequenceNumber(42),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: operations.try_into().unwrap(),
            ext: TransactionExt::V0,
        },
        signatures: Vec::new().try_into().unwrap(),
    })
    .to_xdr_base64(Limits::none())
    .unwrap()
}

/// G is unchanged: G payment XDR equals the envelope built directly from
/// XDR types, for native and issued assets on both networks, and the decoded
/// policy arguments name the same G.
#[test]
fn plain_g_compatibility() {
    let key = [0xA3; 32];
    let issuer = stellar_strkey::ed25519::PublicKey::from_string(ISSUER).unwrap();
    let usdc = XdrAsset::CreditAlphanum4(AlphaNum4 {
        asset_code: AssetCode4(*b"USDC"),
        issuer: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(issuer.0))),
    });
    for network in [TESTNET, MAINNET] {
        assert_eq!(
            pay(network, &g(key), &Asset::Native, &Memo::None),
            golden_g_envelope(key, XdrAsset::Native),
            "{network}: native G payment bytes"
        );
        let built = pay(network, &g(key), &issued(), &Memo::None);
        assert_eq!(
            built,
            golden_g_envelope(key, usdc.clone()),
            "{network}: issued G payment bytes"
        );
        let args = stellar_agent_core::envelope_decode::decode_authoritative_args(
            &built,
            "stellar_pay_commit",
        )
        .unwrap();
        assert_eq!(args["destination"], g(key), "{network}: decoded G");
    }
}

/// An explicit memo on an M0 or M17 destination keeps the
/// address and the memo bytes; the ID never becomes the memo.
#[test]
fn muxed_explicit_memo() {
    let key = [0xA9; 32];
    let memos = [
        Memo::Text(StringM::try_from(b"deposit 9".to_vec()).unwrap()),
        Memo::Id(55),
        Memo::Hash(Hash([7; 32])),
        Memo::Return(Hash([8; 32])),
    ];
    for id in [0, 17] {
        for memo in &memos {
            let (payment, sent) = decoded(&pay(TESTNET, &m(key, id), &Asset::Native, memo));
            assert_eq!(&sent, memo, "M{id}: the explicit memo is sent as given");
            assert_eq!(
                payment.destination,
                MuxedAccount::MuxedEd25519(MuxedAccountMed25519 {
                    id,
                    ed25519: Uint256(key),
                }),
                "M{id}: the address keeps its ID beside the memo"
            );
        }
        let (_, sent) = decoded(&pay(TESTNET, &m(key, id), &Asset::Native, &Memo::None));
        assert_eq!(sent, Memo::None, "M{id}: no memo is derived from the ID");
    }
}

/// A server that answers every data-entry read with `config.memo_required`
/// holding `value` for `account`, or with no entry when `value` is `None`.
async fn data_entry_server(account: &str, value: Option<&[u8]>) -> wiremock::MockServer {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer};
    let server = MockServer::start().await;
    let entries = value.map_or_else(Vec::new, |value| {
        let pk = stellar_strkey::ed25519::PublicKey::from_string(account).unwrap();
        let account_id = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk.0)));
        let name: stellar_xdr::String64 = StringM::<64>::try_from(b"config.memo_required".to_vec())
            .unwrap()
            .into();
        let key = stellar_xdr::LedgerKey::Data(stellar_xdr::LedgerKeyData {
            account_id: account_id.clone(),
            data_name: name.clone(),
        });
        let data = stellar_xdr::LedgerEntryData::Data(stellar_xdr::DataEntry {
            account_id,
            data_name: name,
            data_value: value.to_vec().try_into().unwrap(),
            ext: stellar_xdr::DataEntryExt::V0,
        });
        vec![serde_json::json!({
            "key": key.to_xdr_base64(Limits::none()).unwrap(),
            "xdr": data.to_xdr_base64(Limits::none()).unwrap(),
            "lastModifiedLedgerSeq": 5,
        })]
    });
    Mock::given(method("POST"))
        .respond_with(stellar_agent_test_support::EchoIdResponder::new(
            serde_json::json!({ "entries": entries, "latestLedger": 6 }),
        ))
        .mount(&server)
        .await;
    server
}

/// Only SEP-29 is skipped. M0 and M17 without a memo make
/// zero data-entry requests and yield `NotRead`, even when the base account
/// sets the flag. G with flag `1` refuses, G without the flag reads it, and G
/// with an explicit memo reads nothing.
#[tokio::test(flavor = "current_thread")]
async fn muxed_sep29_exception() {
    let key = [0xA8; 32];
    let base = g(key);
    let required = data_entry_server(&base, Some(b"1")).await;
    let client = crate::client::StellarRpcClient::new(&required.uri()).unwrap();
    for id in [0, 17] {
        let observation = crate::sep29::check_memo_required(&client, &m(key, id), false)
            .await
            .unwrap();
        assert_eq!(observation, MemoObservation::NotRead, "M{id}");
    }
    assert!(
        required.received_requests().await.unwrap().is_empty(),
        "an M destination reads no data entry"
    );

    let refusal = crate::sep29::check_memo_required(&client, &base, false)
        .await
        .expect_err("G with flag 1 refuses");
    assert_eq!(refusal.code(), "validation.memo_required");
    assert_eq!(required.received_requests().await.unwrap().len(), 1);
    assert_eq!(
        crate::sep29::check_memo_required(&client, &base, true)
            .await
            .unwrap(),
        MemoObservation::NotRead,
        "an explicit memo reads nothing"
    );
    assert_eq!(required.received_requests().await.unwrap().len(), 1);

    let absent = data_entry_server(&base, None).await;
    let client = crate::client::StellarRpcClient::new(&absent.uri()).unwrap();
    assert_eq!(
        crate::sep29::check_memo_required(&client, &base, false)
            .await
            .unwrap(),
        MemoObservation::Read(false)
    );
    assert_eq!(absent.received_requests().await.unwrap().len(), 1);
}
