//! `stellar_mpp_charge_commit` against the audit log's keyring-held tip anchor.
//!
//! The MPP commit path does not run the value-verb pre-flight: it writes its
//! authorization row through the strict emission helper and withholds the
//! credential when that write cannot be made. The anchor check therefore has to
//! sit where that helper acquires the writer, or a log rolled back under the
//! running server would take the row that proves the authorization and the
//! credential would go out anyway.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics and unwraps are acceptable in integration tests"
)]

mod common;

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serial_test::serial;
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_mcp::server::WalletServer;
use stellar_agent_mpp::{ChallengeInput, HttpRequestContext};
use stellar_agent_test_support::{StellarAgentHomeGuard, keyring_mock};
use stellar_xdr::{
    AccountId, HostFunction, Limits, OperationBody, PublicKey, ReadXdr, ScAddress, ScVal,
    SorobanAddressCredentials, SorobanAuthorizationEntry, SorobanAuthorizedFunction,
    SorobanAuthorizedInvocation, SorobanCredentials, TransactionEnvelope, Uint256, VecM, WriteXdr,
};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

/// SEP-41 token contract the challenge charges against.
const CONTRACT: &str = "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA";

/// Charge recipient.
const RECIPIENT: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";

/// Soroban transaction data the mocked simulation returns.
///
/// A real `SorobanTransactionData` body: the commit path decodes it and bounds
/// its size, so the value has to parse as the XDR type rather than stand in for
/// it. Its footprint describes some other contract entirely, which nothing on
/// this path reads.
const TRANSACTION_DATA: &str = "AAAAAAAAAAIAAAAGAAAAAcwD/nT9D7Dc2LxRdab+2vEUF8B+XoN7mQW21oxPT8ALAAAAFAAAAAEAAAAHy8vNUZ8vyZ2ybPHW0XbSrRtP7gEWsJ6zDzcfY9P8z88AAAABAAAABgAAAAHMA/50/Q+w3Ni8UXWm/trxFBfAfl6De5kFttaMT0/ACwAAABAAAAABAAAAAgAAAA8AAAAHQ291bnRlcgAAAAASAAAAAAAAAAAg4dbAxsGAGICfBG3iT2cKGYQ6hK4sJWzZ6or1C5v6GAAAAAEAHfKyAAAFiAAAAIgAAAAAAAAAAw==";

/// Profile name the whole suite serves under.
const PROFILE: &str = "mpp-anchor";

/// Keyring service holding the payer's secret.
const SIGNER_SERVICE: &str = "mpp-anchor-svc";

/// Simulation endpoint for the sponsored charge flow.
///
/// Answers `simulateTransaction` the way the network does for this charge: the
/// first call carries no authorization entry and is answered with the one the
/// host would require, the re-simulation of the signed envelope is answered with
/// no entries at all. The response is derived from the envelope in the request,
/// so an envelope that stopped matching what the tool built would fail the
/// caller's own validation rather than be waved through.
struct SponsoredSimulateResponder {
    payer: ScAddress,
}

#[async_trait]
impl Respond for SponsoredSimulateResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body = serde_json::from_slice::<serde_json::Value>(&request.body)
            .unwrap_or_else(|_| serde_json::json!({}));
        let req_id = body
            .get("id")
            .cloned()
            .unwrap_or_else(|| serde_json::json!(1));
        let envelope_b64 = body
            .get("params")
            .and_then(|params| params.get("transaction"))
            .and_then(serde_json::Value::as_str)
            .expect("simulateTransaction carries a transaction envelope");
        let envelope = TransactionEnvelope::from_xdr_base64(envelope_b64, Limits::none())
            .expect("the tool must send a decodable envelope");
        let TransactionEnvelope::Tx(transaction) = envelope else {
            panic!("the sponsored flow builds a v1 envelope");
        };
        let operation = transaction
            .tx
            .operations
            .first()
            .expect("one operation")
            .clone();
        let OperationBody::InvokeHostFunction(host) = operation.body else {
            panic!("the sponsored flow builds an InvokeHostFunction operation");
        };
        let HostFunction::InvokeContract(invoke) = host.host_function else {
            panic!("the sponsored flow invokes a contract");
        };

        let auth = if host.auth.is_empty() {
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
            vec![
                entry
                    .to_xdr_base64(Limits::none())
                    .expect("auth entry encodes"),
            ]
        } else {
            Vec::new()
        };

        ResponseTemplate::new(200)
            .set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "transactionData": TRANSACTION_DATA,
                    "minResourceFee": "1000",
                    "results": [{
                        "auth": auth,
                        "xdr": ScVal::Void
                            .to_xdr_base64(Limits::none())
                            .expect("ScVal::Void encodes"),
                    }],
                    "latestLedger": 1000,
                },
            }))
            .insert_header("content-type", "application/json")
    }
}

/// Derives the G-strkey for a 32-byte ed25519 seed.
fn gstrkey_for_seed(seed: [u8; 32]) -> String {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    stellar_strkey::ed25519::PublicKey(signing_key.verifying_key().to_bytes())
        .to_string()
        .to_string()
}

/// Derives the S-strkey for a 32-byte ed25519 seed.
fn sstrkey_for_seed(seed: [u8; 32]) -> String {
    stellar_strkey::ed25519::PrivateKey(seed)
        .as_unredacted()
        .to_string()
        .to_string()
}

/// The contract address form of a payer G-strkey.
fn payer_sc_address(payer: &str) -> ScAddress {
    let key = stellar_strkey::ed25519::PublicKey::from_string(payer).expect("payer G-strkey");
    ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(key.0))))
}

/// Seeds the nonce mint's HMAC key at the profile's nonce coordinate.
fn install_test_nonce_key(byte: u8) {
    keyring_core::Entry::new("n-svc", "n-acct")
        .expect("Entry::new")
        .set_password(&URL_SAFE_NO_PAD.encode([byte; 32]))
        .expect("set_password");
}

/// An HTTP `Payment` challenge for a fixed charge against [`CONTRACT`].
///
/// `round` distinguishes one charge from the next. The authorization store keys
/// a stored charge by the challenge it came from, so two rounds built from the
/// same challenge would resolve to one authorization and the second commit would
/// refuse as a replay before reaching anything this test is about.
fn challenge(round: u8) -> ChallengeInput {
    let request = serde_json::json!({
        "amount": "10000000",
        "currency": CONTRACT,
        "methodDetails": {"feePayer": true, "network": "stellar:testnet"},
        "recipient": RECIPIENT,
    });
    let encoded = URL_SAFE_NO_PAD.encode(
        stellar_agent_mpp::json::canonical_json(&request).expect("canonical challenge request"),
    );
    let context = HttpRequestContext::new(
        "https://merchant.example",
        "POST",
        &format!("https://merchant.example/checkout/{round}"),
        None,
        None,
    )
    .expect("valid request context");
    ChallengeInput::Http {
        www_authenticate: vec![format!(
            "Payment id=\"challenge-{round}\", realm=\"merchant.example\", \
             method=\"stellar\", intent=\"charge\", request={encoded}"
        )],
        selected_challenge_id: None,
        context,
    }
}

/// Extracts the envelope JSON from a tool result.
fn result_json(result: &rmcp::model::CallToolResult) -> serde_json::Value {
    let text = result
        .content
        .iter()
        .filter_map(|content| content.as_text().map(|text| text.text.clone()))
        .collect::<Vec<_>>()
        .join("");
    serde_json::from_str(&text).expect("tool results carry a JSON envelope")
}

/// Prepares one charge and commits it, returning the commit tool's result.
///
/// Each commit needs its own authorization and its own process-bound nonce, so
/// the prepare step runs per round.
async fn prepare_and_commit(
    server: &WalletServer,
    profile_name: &str,
    round: u8,
) -> rmcp::model::CallToolResult {
    let prepared = server
        .call_stellar_mpp_charge_prepare(profile_name.to_owned(), challenge(round))
        .await
        .expect("prepare must not error at the protocol layer");
    assert_ne!(
        prepared.is_error,
        Some(true),
        "prepare must succeed: {}",
        result_json(&prepared)
    );
    let prepared = result_json(&prepared);
    let data = prepared.get("data").expect("prepare success carries data");
    let authorization_id = data["authorization"]["authorization_id"]
        .as_str()
        .expect("authorization_id")
        .to_owned();
    let nonce = data["nonce"].as_str().expect("nonce").to_owned();
    let expires_at_unix_ms = data["nonce_expires_at_unix_ms"]
        .as_u64()
        .expect("nonce_expires_at_unix_ms");

    server
        .call_stellar_mpp_charge_commit(authorization_id, nonce, expires_at_unix_ms)
        .await
        .expect("commit must not error at the protocol layer")
}

/// Counts the rows in the audit log.
fn row_count(path: &std::path::Path) -> usize {
    std::fs::read_to_string(path)
        .expect("audit log exists")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count()
}

/// `stellar_mpp_charge_commit` refuses with `audit.tip_anchor_mismatch` when the
/// audit log is truncated underneath the writer the running server holds, and
/// appends nothing.
///
/// The registry caches one writer per profile for the server's lifetime, so a
/// check made only when that writer was opened would cover the first commit and
/// nothing after it. This drives two full charges: the first succeeds and leaves
/// the anchor naming the log, the log is then truncated on disk, and the second
/// must withhold its credential rather than append its authorization row to a
/// log that no longer contains the tip it anchored.
#[tokio::test]
#[serial]
async fn mpp_charge_commit_refuses_tip_anchor_mismatch_when_the_log_is_rolled_back() {
    let home = tempfile::tempdir().expect("temp home");
    let _home_guard = StellarAgentHomeGuard::new(home.path());
    keyring_mock::install().expect("mock keyring store init");
    install_test_nonce_key(240);

    let seed = [0x6c_u8; 32];
    let payer_g = gstrkey_for_seed(seed);
    keyring_core::Entry::new(SIGNER_SERVICE, &payer_g)
        .expect("Entry::new")
        .set_password(&sstrkey_for_seed(seed))
        .expect("set_password");

    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(SponsoredSimulateResponder {
            payer: payer_sc_address(&payer_g),
        })
        .mount(&mock_server)
        .await;

    let mut profile =
        Profile::builder_testnet_named(PROFILE, SIGNER_SERVICE, &payer_g, "n-svc", "n-acct")
            .with_noop_engine()
            .build();
    profile.rpc_url = mock_server.uri();
    common::install_test_audit_key(&mut profile);
    let audit_log_path = profile.audit_log_path.clone();
    let server = WalletServer::new(profile).expect("WalletServer::new");

    // Round one: a commit that succeeds, leaving the anchor naming the log.
    let first = prepare_and_commit(&server, PROFILE, 1).await;
    assert_ne!(
        first.is_error,
        Some(true),
        "the first commit must succeed so the anchor names a non-empty log: {}",
        result_json(&first)
    );
    let rows_before = row_count(&audit_log_path);
    assert!(
        rows_before > 0,
        "the first commit must have written its authorization row"
    );

    // Roll the log back underneath the writer the server is still holding.
    std::fs::write(&audit_log_path, b"").expect("truncate the audit log");

    let second = prepare_and_commit(&server, PROFILE, 2).await;
    let (code, _message, _text) = common::assert_business_envelope(&second);
    assert_eq!(
        code, "audit.tip_anchor_mismatch",
        "the commit must refuse under the code that names the rolled-back log, \
         not the uniform state refusal, got: {code}"
    );
    assert_eq!(
        row_count(&audit_log_path),
        0,
        "a refused commit must append no row to the rolled-back log"
    );
}

/// A sibling authorization reserves after evaluation and before accounting.
#[derive(Debug)]
struct CompetingAuthorization(
    stellar_agent_core::policy::v1::criteria::per_period_cap::PerPeriodCapCriterion,
);

impl stellar_agent_core::policy::v1::criteria::Criterion for CompetingAuthorization {
    fn kind(&self) -> &'static str {
        "per_period_cap"
    }

    fn evaluate(
        &self,
        ctx: &stellar_agent_core::policy::v1::EvalContext<'_>,
    ) -> Result<
        Option<stellar_agent_core::policy::DenyReason>,
        stellar_agent_core::policy::PolicyError,
    > {
        self.0.evaluate(ctx)
    }

    fn record_confirmed(
        &self,
        ctx: &stellar_agent_core::policy::v1::EvalContext<'_>,
    ) -> Result<
        Vec<stellar_agent_core::policy::v1::criteria::state_store::WindowEntry>,
        stellar_agent_core::policy::PolicyError,
    > {
        let entries = self.0.record_confirmed(ctx)?;
        stellar_agent_network::policy_state::PersistedWindowStore::for_profile(ctx.profile_name)
            .record_authorized(ctx.profile, &entries)
            .expect("the sibling authorization fits alone");
        Ok(entries)
    }
}

/// An accounting refusal withholds the credential and keeps its policy code.
#[tokio::test]
#[serial]
async fn mpp_accounting_cap_refusal_withholds_the_credential() {
    const PROFILE: &str = "mpp-admission";
    use stellar_agent_core::policy::Decision;
    use stellar_agent_core::policy::v1::PolicyEngineV1;
    use stellar_agent_core::policy::v1::criteria::per_period_cap::{PerPeriodCapCriterion, Window};
    use stellar_agent_core::policy::v1::criteria::state_store::{PolicyStateStore, StateKey};
    use stellar_agent_core::policy::v1::loader::{PolicyDocument, PolicyRule, RuleMatch, ScopeId};
    use stellar_agent_network::policy_state::PersistedWindowStore;
    let home = tempfile::tempdir().unwrap();
    let _home = StellarAgentHomeGuard::new(home.path());
    keyring_mock::install().unwrap();
    install_test_nonce_key(241);
    let seed = [0x6d; 32];
    let payer = gstrkey_for_seed(seed);
    keyring_core::Entry::new(SIGNER_SERVICE, &payer)
        .unwrap()
        .set_password(&sstrkey_for_seed(seed))
        .unwrap();
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(SponsoredSimulateResponder {
            payer: payer_sc_address(&payer),
        })
        .expect(1)
        .mount(&mock)
        .await;
    let mut profile =
        Profile::builder_testnet_named(PROFILE, SIGNER_SERVICE, &payer, "n-svc", "n-acct")
            .with_noop_engine()
            .build();
    profile.rpc_url = mock.uri();
    common::install_test_audit_key(&mut profile);
    let mut server = WalletServer::new(profile.clone()).unwrap();
    let engine = PolicyEngineV1::new(
        PolicyDocument {
            version: 1,
            scope: ScopeId::AllProfiles,
            signature: None,
            rules: vec![PolicyRule {
                r#match: RuleMatch {
                    tool: "*".into(),
                    chain: "*".into(),
                },
                criteria: vec![Box::new(CompetingAuthorization(
                    PerPeriodCapCriterion::new(
                        CONTRACT.into(),
                        Window::parse("1d").unwrap(),
                        15_000_000,
                    ),
                ))],
                decision: Decision::Allow,
                allow_opaque_signing: false,
            }],
        },
        PROFILE.into(),
    );
    server.set_policy_engine_for_test(std::sync::Arc::new(engine));
    let result = prepare_and_commit(&server, PROFILE, 3).await;
    let (code, _, _) = common::assert_business_envelope(&result);
    assert_eq!(code, "policy.deny.per_period_cap_exceeded");
    assert!(result_json(&result)["data"]["credential"].is_null());
    let window = PolicyStateStore::new();
    PersistedWindowStore::for_profile(PROFILE)
        .load_into(PROFILE, &profile, &window)
        .unwrap();
    let key = StateKey::new(
        PROFILE,
        1,
        &stellar_agent_core::policy::v1::value::asset_normalise(CONTRACT),
        86_400,
    );
    assert_eq!(
        window
            .query_window(&key, stellar_agent_core::timefmt::now_unix_ms().unwrap())
            .unwrap(),
        (10_000_000, 1)
    );
}

/// x402 admission precedes payment signing and signed RPC re-simulation.
#[tokio::test]
#[serial]
async fn x402_accounting_cap_refusal_withholds_the_payment_signature() {
    use stellar_agent_core::policy::Decision;
    use stellar_agent_core::policy::v1::PolicyEngineV1;
    use stellar_agent_core::policy::v1::criteria::per_period_cap::{PerPeriodCapCriterion, Window};
    use stellar_agent_core::policy::v1::criteria::state_store::{PolicyStateStore, StateKey};
    use stellar_agent_core::policy::v1::loader::{PolicyDocument, PolicyRule, RuleMatch, ScopeId};
    use stellar_agent_mcp::server::X402CreatePaymentArgs;
    use stellar_agent_network::policy_state::PersistedWindowStore;
    const PROFILE: &str = "x402-admission";
    let home = tempfile::tempdir().unwrap();
    let _home = StellarAgentHomeGuard::new(home.path());
    keyring_mock::install().unwrap();
    install_test_nonce_key(242);
    let seed = [0x6e; 32];
    let payer = gstrkey_for_seed(seed);
    keyring_core::Entry::new(SIGNER_SERVICE, &payer)
        .unwrap()
        .set_password(&sstrkey_for_seed(seed))
        .unwrap();
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(SponsoredSimulateResponder {
            payer: payer_sc_address(&payer),
        })
        .mount(&mock)
        .await;
    let mut profile =
        Profile::builder_testnet_named(PROFILE, SIGNER_SERVICE, &payer, "n-svc", "n-acct")
            .with_noop_engine()
            .build();
    profile.rpc_url = mock.uri();
    common::install_test_audit_key(&mut profile);
    let mut server = WalletServer::new(profile.clone()).unwrap();
    server.set_policy_engine_for_test(std::sync::Arc::new(PolicyEngineV1::new(
        PolicyDocument {
            version: 1,
            scope: ScopeId::AllProfiles,
            signature: None,
            rules: vec![PolicyRule {
                r#match: RuleMatch {
                    tool: "*".into(),
                    chain: "*".into(),
                },
                criteria: vec![Box::new(CompetingAuthorization(
                    PerPeriodCapCriterion::new(
                        CONTRACT.into(),
                        Window::parse("1d").unwrap(),
                        15_000_000,
                    ),
                ))],
                decision: Decision::Allow,
                allow_opaque_signing: false,
            }],
        },
        PROFILE.into(),
    )));
    let result = server
        .call_stellar_x402_create_payment(X402CreatePaymentArgs {
            chain_id: "stellar:testnet".into(),
            address: None,
            payment_required: serde_json::json!({
                "scheme": "exact", "network": "stellar:testnet", "asset": CONTRACT,
                "amount": "10000000", "payTo": RECIPIENT, "maxTimeoutSeconds": 300,
                "extra": { "areFeesSponsored": true }
            })
            .to_string(),
        })
        .await
        .unwrap();
    let (code, _, _) = common::assert_business_envelope(&result);
    assert_eq!(code, "policy.deny.per_period_cap_exceeded");
    assert!(
        mock.received_requests().await.unwrap().is_empty(),
        "accounting refuses before signing and RPC re-simulation"
    );
    assert!(result_json(&result)["data"]["paymentSignature"].is_null());
    let window = PolicyStateStore::new();
    PersistedWindowStore::for_profile(PROFILE)
        .load_into(PROFILE, &profile, &window)
        .unwrap();
    let key = StateKey::new(
        PROFILE,
        1,
        &stellar_agent_core::policy::v1::value::asset_normalise(CONTRACT),
        86_400,
    );
    assert_eq!(
        window
            .query_window(&key, stellar_agent_core::timefmt::now_unix_ms().unwrap())
            .unwrap(),
        (10_000_000, 1)
    );
}
