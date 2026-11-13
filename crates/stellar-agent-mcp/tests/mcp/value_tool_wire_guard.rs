//! Exact wire text of the six value tools on testnet without a business id,
//! key order and absent fields included.
//!
//! The four classic tools run their prepare and their commit against an
//! endpoint that confirms every send; both texts are pinned. The two x402
//! tools run against an endpoint that answers both simulations; their one
//! text is pinned. [`normalize`] masks the values that vary between
//! invocations.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only"
)]

use serde_json::{Value, json};
use serial_test::serial;
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_mcp::server::{
    StellarClaimArgs, StellarClaimCommitArgs, StellarCreateAccountArgs,
    StellarCreateAccountCommitArgs, StellarPayArgs, StellarPayCommitArgs, StellarTrustlineArgs,
    StellarTrustlineCommitArgs, WalletServer, X402AuthenticatedPaymentArgs, X402CreatePaymentArgs,
};
use stellar_agent_test_support::keyring_mock;
use stellar_agent_test_support::xdr_fixtures::{
    account_entry_xdr_with_seq, account_ledger_key_xdr,
};
use stellar_xdr::{
    AccountId, Asset, ClaimPredicate, ClaimableBalanceEntry, ClaimableBalanceEntryExt,
    ClaimableBalanceId, Claimant, ClaimantV0, Hash, HostFunction, LedgerEntryData, LedgerKey,
    LedgerKeyClaimableBalance, Limits, OperationBody, PublicKey, ReadXdr as _, ScAddress, ScVal,
    SorobanAddressCredentials, SorobanAuthorizationEntry, SorobanAuthorizedFunction,
    SorobanAuthorizedInvocation, SorobanCredentials, TransactionEnvelope, Uint256, VecM,
    WriteXdr as _,
};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

/// The ledger every classic submission confirms in.
const CONFIRM_LEDGER: u32 = 1005;
const SOURCE_BALANCE_STROOPS: i64 = 500_000_000_000;
const SOURCE_SEQ: i64 = 42;
/// The issuer the trustline tool resolves `USDC` to on testnet.
const USDC_TESTNET_ISSUER: &str = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";
/// The hash of the claimable balance the endpoint holds.
const BALANCE_ID_HEX64: &str = "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef";

/// SAC token contract the x402 payment transfers.
const ASSET: &str = "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA";
/// The x402 payment recipient.
const PAY_TO: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
/// A `SorobanTransactionData` body both simulations answer with.
const TRANSACTION_DATA: &str = "AAAAAAAAAAIAAAAGAAAAAcwD/nT9D7Dc2LxRdab+2vEUF8B+XoN7mQW21oxPT8ALAAAAFAAAAAEAAAAHy8vNUZ8vyZ2ybPHW0XbSrRtP7gEWsJ6zDzcfY9P8z88AAAABAAAABgAAAAHMA/50/Q+w3Ni8UXWm/trxFBfAfl6De5kFttaMT0/ACwAAABAAAAABAAAAAgAAAA8AAAAHQ291bnRlcgAAAAASAAAAAAAAAAAg4dbAxsGAGICfBG3iT2cKGYQ6hK4sJWzZ6or1C5v6GAAAAAEAHfKyAAAFiAAAAIgAAAAAAAAAAw==";
/// The x402 simulation and health ledger.
const X402_LEDGER: u32 = 1000;
/// Keyring service holding the x402 payer's secret.
const X402_SIGNER_SERVICE: &str = "x402-wire-guard-svc";

/// A tool text the guard pins.
#[derive(Clone, Copy, Debug)]
enum Text {
    PayPrepare,
    PayCommit,
    CreateAccountPrepare,
    CreateAccountCommit,
    TrustlinePrepare,
    TrustlineCommit,
    ClaimPrepare,
    ClaimCommit,
    X402CreatePayment,
    X402AuthenticatedPayment,
}

impl Text {
    fn expected(self) -> &'static str {
        match self {
            Self::PayPrepare => include_str!("value_tool_wire_guard/pay_prepare.json"),
            Self::PayCommit => include_str!("value_tool_wire_guard/pay_commit.json"),
            Self::CreateAccountPrepare => {
                include_str!("value_tool_wire_guard/create_account_prepare.json")
            }
            Self::CreateAccountCommit => {
                include_str!("value_tool_wire_guard/create_account_commit.json")
            }
            Self::TrustlinePrepare => include_str!("value_tool_wire_guard/trustline_prepare.json"),
            Self::TrustlineCommit => include_str!("value_tool_wire_guard/trustline_commit.json"),
            Self::ClaimPrepare => include_str!("value_tool_wire_guard/claim_prepare.json"),
            Self::ClaimCommit => include_str!("value_tool_wire_guard/claim_commit.json"),
            Self::X402CreatePayment => {
                include_str!("value_tool_wire_guard/x402_create_payment.json")
            }
            Self::X402AuthenticatedPayment => {
                include_str!("value_tool_wire_guard/x402_authenticated_payment.json")
            }
        }
    }
}

/// The keys whose values the host clock, a fresh random value, or a
/// generated id decides.
const VOLATILE_KEYS: &[&str] = &[
    "request_id",
    "nonce",
    "expires_at_unix_ms",
    "close_time_unix",
    "close_lag_seconds",
];

/// Masks the scalar values of [`VOLATILE_KEYS`] wherever they occur, and
/// leaves every other byte as the tool wrote it.
fn normalize(text: &str) -> String {
    fn collect(value: &Value, found: &mut Vec<(String, String)>) {
        match value {
            Value::Object(map) => {
                for (key, inner) in map {
                    match inner {
                        Value::String(_) | Value::Number(_)
                            if VOLATILE_KEYS.contains(&key.as_str()) =>
                        {
                            found.push((key.clone(), inner.to_string()));
                        }
                        _ => collect(inner, found),
                    }
                }
            }
            Value::Array(items) => items.iter().for_each(|item| collect(item, found)),
            _ => {}
        }
    }
    let value: Value = serde_json::from_str(text).unwrap();
    let mut found = Vec::new();
    collect(&value, &mut found);
    let mut masked = text.to_owned();
    for (key, rendered) in found {
        let placeholder = key.to_uppercase();
        masked = masked
            .replace(
                &format!("\"{key}\": {rendered}"),
                &format!("\"{key}\": \"{placeholder}\""),
            )
            .replace(
                &format!("\"{key}\":{rendered}"),
                &format!("\"{key}\":\"{placeholder}\""),
            );
    }
    masked
}

fn result_text(result: &rmcp::model::CallToolResult) -> String {
    assert_ne!(result.is_error, Some(true), "{result:?}");
    result
        .content
        .iter()
        .filter_map(|content| content.as_text().map(|text| text.text.clone()))
        .collect::<Vec<_>>()
        .join("")
}

fn assert_text(text: Text, result: &rmcp::model::CallToolResult) -> Value {
    let raw = result_text(result);
    let actual = normalize(&raw);
    assert_eq!(actual, text.expected(), "{text:?}: {actual}");
    serde_json::from_str(&raw).unwrap()
}

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
    let nonce_key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([9u8; 32]);
    keyring_core::Entry::new("n-svc", "n-acct")
        .expect("Entry::new for nonce key")
        .set_password(&nonce_key_b64)
        .expect("set_password for nonce key");
}

fn account_entry(account: &str) -> (String, String) {
    (
        account_ledger_key_xdr(account),
        account_entry_xdr_with_seq(account, SOURCE_BALANCE_STROOPS, 0, SOURCE_SEQ),
    )
}

/// The ledger key and entry of an unconditional native claimable balance
/// with id [`BALANCE_ID_HEX64`] whose one claimant is `claimant`.
fn claimable_entry(claimant: &str) -> (String, String) {
    let balance_id = ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash([0xef; 32]));
    let key = LedgerKey::ClaimableBalance(LedgerKeyClaimableBalance {
        balance_id: balance_id.clone(),
    })
    .to_xdr_base64(Limits::none())
    .unwrap();
    let pk = stellar_strkey::ed25519::PublicKey::from_string(claimant).unwrap();
    let entry = LedgerEntryData::ClaimableBalance(ClaimableBalanceEntry {
        balance_id,
        claimants: vec![Claimant::ClaimantTypeV0(ClaimantV0 {
            destination: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk.0))),
            predicate: ClaimPredicate::Unconditional,
        })]
        .try_into()
        .unwrap(),
        asset: Asset::Native,
        amount: 50_000_000,
        ext: ClaimableBalanceEntryExt::V0,
    })
    .to_xdr_base64(Limits::none())
    .unwrap();
    (key, entry)
}

/// A testnet server for the signer `seed` under keyring account `account`,
/// reading `entries` through an endpoint that confirms every send.
async fn classic_server(
    account: &str,
    seed: [u8; 32],
    entries: Vec<(String, String)>,
) -> (MockServer, WalletServer) {
    let _ = keyring_mock::install();
    install_test_nonce_key();
    keyring_core::Entry::new("svc", account)
        .unwrap()
        .set_password(&sstrkey_for_seed(seed))
        .unwrap();
    crate::common::store_signer_identity("svc", account, seed);
    let rpc = MockServer::start().await;
    Mock::given(method("POST"))
        .and(wiremock::matchers::body_partial_json(
            json!({ "method": "getLedgers" }),
        ))
        .respond_with(AgedLedgers)
        .with_priority(1)
        .mount(&rpc)
        .await;
    Mock::given(method("POST"))
        .respond_with(crate::common::TimeoutRpc::new(entries).confirming_in(CONFIRM_LEDGER))
        .mount(&rpc)
        .await;
    let profile = crate::common::testnet_profile_for_account(&rpc.uri(), account);
    (rpc, WalletServer::new(profile).unwrap())
}

/// The age, in seconds, of the latest ledger when the endpoint answers: inside
/// the readiness bound, and larger than any call takes.
const LEDGER_AGE_SECONDS: u64 = 30;

/// Answers `getLedgers` with a latest ledger that closed
/// [`LEDGER_AGE_SECONDS`] before the answer.
struct AgedLedgers;

impl Respond for AgedLedgers {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": body["id"],
            "result": crate::common::ledgers_result(LEDGER_AGE_SECONDS),
        }))
    }
}

/// The host clock in Unix seconds.
fn host_seconds() -> u64 {
    stellar_agent_core::timefmt::now_unix_ms().unwrap() / 1_000
}

/// The prepare's token, after checking its operational lag against the host
/// clock.
///
/// The endpoint answers with a close time [`LEDGER_AGE_SECONDS`] before its
/// answer, and the tool reads the host clock after that answer. The lag is
/// therefore at least that age, and the close time plus the lag is the tool's
/// reading: a second within `called`, the host clock before and after the
/// call.
fn prepared(data: &Value, called: (u64, u64)) -> (String, u64, String) {
    let data = &data["data"];
    let operational = &data["operational"];
    let close = operational["close_time_unix"].as_u64().unwrap();
    let lag = operational["close_lag_seconds"].as_u64().unwrap();
    assert!(
        lag >= LEDGER_AGE_SECONDS,
        "the lag covers the ledger's {LEDGER_AGE_SECONDS} s age: {data}"
    );
    assert!(
        (called.0..=called.1).contains(&(close + lag)),
        "the lag is the tool's clock minus the close time, within {called:?}: {data}"
    );
    (
        data["nonce"].as_str().unwrap().to_owned(),
        data["expires_at_unix_ms"].as_u64().unwrap(),
        data["envelope_xdr"].as_str().unwrap().to_owned(),
    )
}

#[tokio::test]
#[serial]
async fn pay_wire_text() {
    let _root = crate::common::isolated_data_root();
    let seed = [0xe4; 32];
    let source = gstrkey_for_seed(seed);
    let destination = gstrkey_for_seed([0xea; 32]);
    let (_rpc, server) = classic_server(
        "acct-pay-wire",
        seed,
        vec![account_entry(&source), account_entry(&destination)],
    )
    .await;
    let before = host_seconds();
    let prepare = server
        .call_stellar_pay(StellarPayArgs {
            chain_id: "stellar:testnet".to_owned(),
            source: source.clone(),
            destination: destination.clone(),
            amount: Some(serde_json::from_str(r#""1 XLM""#).unwrap()),
            amount_in_stroops: None,
            asset: "native".to_owned(),
            memo_text: None,
            memo_id: None,
            memo_hash_hex: None,
            memo_return_hex: None,
            classic_base: None,
            business_id: None,
        })
        .await
        .unwrap();
    let called = (before, host_seconds());
    let (nonce, expires_at_unix_ms, envelope_xdr) =
        prepared(&assert_text(Text::PayPrepare, &prepare), called);
    let commit = server
        .call_stellar_pay_commit(StellarPayCommitArgs {
            chain_id: "stellar:testnet".to_owned(),
            source,
            destination,
            amount: Some("1 XLM".to_owned()),
            amount_in_stroops: None,
            asset: "native".to_owned(),
            memo_text: None,
            memo_id: None,
            memo_hash_hex: None,
            memo_return_hex: None,
            nonce,
            expires_at_unix_ms,
            envelope_xdr,
            approval_nonce: None,
            approval_attestation: None,
            business_id: None,
        })
        .await
        .unwrap();
    assert_text(Text::PayCommit, &commit);
}

#[tokio::test]
#[serial]
async fn create_account_wire_text() {
    let _root = crate::common::isolated_data_root();
    let seed = [0xe5; 32];
    let source = gstrkey_for_seed(seed);
    let destination = gstrkey_for_seed([0xeb; 32]);
    let (_rpc, server) =
        classic_server("acct-create-wire", seed, vec![account_entry(&source)]).await;
    let before = host_seconds();
    let prepare = server
        .call_stellar_create_account(StellarCreateAccountArgs {
            chain_id: "stellar:testnet".to_owned(),
            source: source.clone(),
            destination: destination.clone(),
            starting_balance: serde_json::from_str(r#""2 XLM""#).unwrap(),
            classic_base: None,
            business_id: None,
        })
        .await
        .unwrap();
    let called = (before, host_seconds());
    let (nonce, expires_at_unix_ms, envelope_xdr) =
        prepared(&assert_text(Text::CreateAccountPrepare, &prepare), called);
    let commit = server
        .call_stellar_create_account_commit(StellarCreateAccountCommitArgs {
            chain_id: "stellar:testnet".to_owned(),
            source,
            destination,
            starting_balance: serde_json::from_str(r#""2 XLM""#).unwrap(),
            nonce,
            expires_at_unix_ms,
            envelope_xdr,
            approval_nonce: None,
            approval_attestation: None,
            business_id: None,
        })
        .await
        .unwrap();
    assert_text(Text::CreateAccountCommit, &commit);
}

#[tokio::test]
#[serial]
async fn trustline_wire_text() {
    let _root = crate::common::isolated_data_root();
    let seed = [0xe6; 32];
    let source = gstrkey_for_seed(seed);
    let (_rpc, server) = classic_server(
        "acct-trustline-wire",
        seed,
        vec![account_entry(&source), account_entry(USDC_TESTNET_ISSUER)],
    )
    .await;
    let before = host_seconds();
    let prepare = server
        .call_stellar_trustline(StellarTrustlineArgs {
            chain_id: "stellar:testnet".to_owned(),
            from: source.clone(),
            asset: "USDC".to_owned(),
            limit_stroops: Some("1000000000".to_owned()),
            classic_base: None,
            business_id: None,
        })
        .await
        .unwrap();
    let called = (before, host_seconds());
    let (nonce, expires_at_unix_ms, envelope_xdr) =
        prepared(&assert_text(Text::TrustlinePrepare, &prepare), called);
    let commit = server
        .call_stellar_trustline_commit(StellarTrustlineCommitArgs {
            chain_id: "stellar:testnet".to_owned(),
            from: source,
            nonce,
            expires_at_unix_ms,
            envelope_xdr,
            approval_nonce: None,
            approval_attestation: None,
            business_id: None,
        })
        .await
        .unwrap();
    assert_text(Text::TrustlineCommit, &commit);
}

#[tokio::test]
#[serial]
async fn claim_wire_text() {
    let _root = crate::common::isolated_data_root();
    let seed = [0xe7; 32];
    let claimant = gstrkey_for_seed(seed);
    let (_rpc, server) = classic_server(
        "acct-claim-wire",
        seed,
        vec![account_entry(&claimant), claimable_entry(&claimant)],
    )
    .await;
    let before = host_seconds();
    let prepare = server
        .call_stellar_claim(StellarClaimArgs {
            chain_id: "stellar:testnet".to_owned(),
            balance_id: BALANCE_ID_HEX64.to_owned(),
            source_account: Some(claimant.clone()),
            business_id: None,
        })
        .await
        .unwrap();
    let called = (before, host_seconds());
    let (nonce, expires_at_unix_ms, envelope_xdr) =
        prepared(&assert_text(Text::ClaimPrepare, &prepare), called);
    let commit = server
        .call_stellar_claim_commit(StellarClaimCommitArgs {
            chain_id: "stellar:testnet".to_owned(),
            balance_id: BALANCE_ID_HEX64.to_owned(),
            source_account: Some(claimant),
            nonce,
            expires_at_unix_ms,
            envelope_xdr,
            approval_nonce: None,
            approval_attestation: None,
            business_id: None,
        })
        .await
        .unwrap();
    assert_text(Text::ClaimCommit, &commit);
}

/// Answers the x402 flow: the identity check, the health read, the unsigned
/// simulation with the payer's authorization entry, and the signed
/// re-simulation with resource data.
#[derive(Clone)]
struct X402Rpc {
    payer: ScAddress,
}

fn rpc_result(id: &Value, result: &Value) -> ResponseTemplate {
    ResponseTemplate::new(200)
        .set_body_json(json!({"jsonrpc": "2.0", "id": id, "result": result}))
        .insert_header("content-type", "application/json")
}

impl Respond for X402Rpc {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        let id = body["id"].clone();
        match body["method"].as_str().unwrap() {
            "getNetwork" => {
                return rpc_result(
                    &id,
                    &json!({
                        "friendbotUrl": "https://friendbot.stellar.org",
                        "passphrase": "Test SDF Network ; September 2015",
                        "protocolVersion": 29,
                    }),
                );
            }
            "getHealth" => {
                return rpc_result(
                    &id,
                    &json!({
                        "status": "healthy", "latestLedger": X402_LEDGER, "oldestLedger": 1,
                        "ledgerRetentionWindow": 17_280,
                    }),
                );
            }
            "simulateTransaction" => {}
            other => panic!("the x402 flow sends no {other:?} request"),
        }
        let envelope = TransactionEnvelope::from_xdr_base64(
            body["params"]["transaction"].as_str().unwrap(),
            Limits::none(),
        )
        .unwrap();
        let TransactionEnvelope::Tx(transaction) = envelope else {
            panic!("the x402 flow builds a v1 envelope");
        };
        let OperationBody::InvokeHostFunction(host) = transaction.tx.operations[0].body.clone()
        else {
            panic!("the x402 flow builds an InvokeHostFunction operation");
        };
        let void = ScVal::Void.to_xdr_base64(Limits::none()).unwrap();
        if !host.auth.is_empty() {
            return rpc_result(
                &id,
                &json!({
                    "transactionData": TRANSACTION_DATA, "minResourceFee": "1000",
                    "results": [{"auth": [], "xdr": void}], "latestLedger": X402_LEDGER,
                }),
            );
        }
        let HostFunction::InvokeContract(invoke) = host.host_function else {
            panic!("the x402 flow invokes a contract");
        };
        let entry = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: self.payer.clone(),
                nonce: 7,
                signature_expiration_ledger: 0,
                signature: ScVal::Void,
            }),
            root_invocation: SorobanAuthorizedInvocation {
                function: SorobanAuthorizedFunction::ContractFn(invoke),
                sub_invocations: VecM::default(),
            },
        };
        rpc_result(
            &id,
            &json!({
                "transactionData": TRANSACTION_DATA, "minResourceFee": "1000",
                "results": [{
                    "auth": [entry.to_xdr_base64(Limits::none()).unwrap()],
                    "xdr": void,
                }],
                "latestLedger": X402_LEDGER,
            }),
        )
    }
}

/// A testnet server whose x402 payer is the signer `seed`, under the
/// profile `name`.
async fn x402_server(name: &str, seed: [u8; 32]) -> (MockServer, WalletServer) {
    let _ = keyring_mock::install();
    let payer = gstrkey_for_seed(seed);
    keyring_core::Entry::new(X402_SIGNER_SERVICE, &payer)
        .unwrap()
        .set_password(&sstrkey_for_seed(seed))
        .unwrap();
    crate::common::store_named_signer_identity(name, X402_SIGNER_SERVICE, &payer, seed);
    let mut profile =
        Profile::builder_testnet_named(name, X402_SIGNER_SERVICE, &payer, "n-svc", "n-acct")
            .with_noop_engine()
            .build();
    crate::common::install_test_audit_key(&mut profile);
    let pk = stellar_strkey::ed25519::PublicKey::from_string(&payer).unwrap();
    let rpc = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(X402Rpc {
            payer: ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk.0)))),
        })
        .mount(&rpc)
        .await;
    profile.rpc_url = rpc.uri();
    let mut server = WalletServer::new(profile).unwrap();
    server.set_x402_identity_session_for_test(
        "header.payload.signature".to_owned(),
        gstrkey_for_seed([0x01; 32]),
        Vec::new(),
    );
    (rpc, server)
}

fn payment_required() -> String {
    json!({
        "scheme": "exact", "network": "stellar:testnet", "asset": ASSET,
        "amount": "10000000", "payTo": PAY_TO, "maxTimeoutSeconds": 300,
        "extra": { "areFeesSponsored": true }
    })
    .to_string()
}

#[tokio::test]
#[serial]
async fn x402_create_payment_wire_text() {
    let _root = crate::common::isolated_data_root();
    let (_rpc, server) = x402_server("x402-create-wire", [0xe8; 32]).await;
    let result = server
        .call_stellar_x402_create_payment(X402CreatePaymentArgs {
            approval_nonce: None,
            approval_attestation: None,
            chain_id: "stellar:testnet".into(),
            address: None,
            payment_required: payment_required(),
            business_id: None,
        })
        .await
        .unwrap();
    assert_text(Text::X402CreatePayment, &result);
}

#[tokio::test]
#[serial]
async fn x402_authenticated_payment_wire_text() {
    let _root = crate::common::isolated_data_root();
    let (_rpc, server) = x402_server("x402-auth-wire", [0xe9; 32]).await;
    let result = server
        .call_stellar_x402_authenticated_payment(X402AuthenticatedPaymentArgs {
            chain_id: "stellar:testnet".into(),
            address: None,
            approval_nonce: None,
            approval_attestation: None,
            home_domain: "merchant.example".into(),
            payment_required: payment_required(),
            business_id: None,
        })
        .await
        .unwrap();
    assert_text(Text::X402AuthenticatedPayment, &result);
}
