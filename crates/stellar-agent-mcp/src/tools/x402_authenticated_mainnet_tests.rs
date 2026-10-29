//! The authenticated x402 payment on an enabled mainnet profile.
//!
//! The tool rows drive `stellar_x402_authenticated_payment` end to end on the
//! real startup path: the primary and oracle hosts route to RPC doubles, and
//! the stellar.toml fetch and the SEP-10 requests go to a SEP-10 double
//! through the identity transport of the server. The signing-boundary rows
//! call the SEP-10 prepare step, the message resolver, the message consume
//! and the authorized completion directly, with proofs from the public
//! producers over the same on-disk state, so each refusal of the completion
//! runs against a receipt of a durably used record.
//!
//! The SEP-10 double serves a challenge for the requested account under a
//! configurable passphrase and verifies the posted signature with its own
//! payload hash under the mainnet passphrase before it answers a JWT.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only fixture construction and assertions"
)]

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use ed25519_dalek::{Signer as _, SigningKey};
use rmcp::model::CallToolResult;
use sha2::Digest as _;
use stellar_agent_core::approval::witness::ApprovalWitness;
use stellar_agent_core::approval::{PendingApproval, process_uid_for_attestation};
use stellar_agent_core::policy::v1::ValueClass;
use stellar_agent_core::profile::caip2::{MAINNET_PASSPHRASE, TESTNET_PASSPHRASE};
use stellar_agent_network::mainnet::MainnetConsumer;
use stellar_agent_network::mainnet::message::{MessageFacts, MessageUseReceipt};
use stellar_agent_sep10::Sep10Client;
use stellar_agent_sep10::ephemeral::{
    PreparedEphemeralAuth, complete_ephemeral_auth_authorized, corrupt_next_signature_for_test,
    prepare_ephemeral_auth, take_authorized_signings_for_test,
};
use stellar_xdr::{
    BytesM, DataValue, DecoratedSignature, Hash, Limits, ManageDataOp, Memo, MuxedAccount,
    Operation, OperationBody, Preconditions, ReadXdr as _, SequenceNumber, SignatureHint, String64,
    StringM, TimeBounds, TimePoint, Transaction, TransactionEnvelope, TransactionExt,
    TransactionSignaturePayload, TransactionSignaturePayloadTaggedTransaction,
    TransactionV1Envelope, Uint256, VecM, WriteXdr as _,
};

use crate::server::{WalletServer, X402AuthenticatedPaymentArgs};
use crate::tools::common::tests::mainnet::{
    Fixture, HookGuard, ReadOnlyDir, RpcControl, assert_names_the_transmitted_ledger,
    authorizations, mount_rpc, observe, put, refusals, routed_fixture_with, stored_approval, wire,
    x402_authorized_rows,
};
use crate::tools::common::{GatedApprovalKind, verify_attestation_subject_gate, x402_value_leg};

const TOOL: &str = "stellar_x402_authenticated_payment";
pub(super) const HOME: &str = "anchor.example.com";
/// The host of the web auth endpoint the identity transport points at.
const WEB_AUTH_DOMAIN: &str = "127.0.0.1";
const SEP10_REFUSAL: &str = "the mainnet authorization for this SEP-10 authentication was \
                             refused; no signed challenge was submitted";

// ─────────────────────────────────────────────────────────────────────────────
// SEP-10 double
// ─────────────────────────────────────────────────────────────────────────────

fn server_key() -> SigningKey {
    SigningKey::from_bytes(&[0x11; 32])
}

fn strkey(key: [u8; 32]) -> String {
    stellar_strkey::ed25519::PublicKey(key)
        .to_string()
        .to_string()
}

/// The SHA-256 of the `TransactionSignaturePayload` XDR of `tx` under
/// `passphrase`.
fn transaction_payload_hash(tx: &Transaction, passphrase: &str) -> [u8; 32] {
    let payload = TransactionSignaturePayload {
        network_id: Hash(sha2::Sha256::digest(passphrase.as_bytes()).into()),
        tagged_transaction: TransactionSignaturePayloadTaggedTransaction::Tx(tx.clone()),
    };
    sha2::Sha256::digest(payload.to_xdr(Limits::none()).unwrap()).into()
}

/// The payload hash of the V1 envelope `envelope` under `passphrase`,
/// computed without the SEP-10 crate.
fn envelope_payload_hash(envelope: &str, passphrase: &str) -> [u8; 32] {
    let TransactionEnvelope::Tx(v1) =
        TransactionEnvelope::from_xdr_base64(envelope, Limits::none()).unwrap()
    else {
        panic!("the challenge is a V1 envelope");
    };
    transaction_payload_hash(&v1.tx, passphrase)
}

/// A challenge for `client_key` under `passphrase`, signed by the server key
/// and by `extra_signatures` further keys with other hints.
fn challenge_xdr(client_key: [u8; 32], passphrase: &str, extra_signatures: usize) -> String {
    use base64::Engine as _;
    let server = server_key();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let name = |text: &str| -> String64 {
        StringM::<64>::try_from(text.as_bytes().to_vec())
            .unwrap()
            .into()
    };
    let value = |bytes: &[u8]| DataValue(BytesM::<64>::try_from(bytes.to_vec()).unwrap());
    let server_account = MuxedAccount::Ed25519(Uint256(server.verifying_key().to_bytes()));
    let nonce = base64::engine::general_purpose::STANDARD.encode([0x55u8; 48]);
    let operations: VecM<Operation, 100> = vec![
        Operation {
            source_account: Some(MuxedAccount::Ed25519(Uint256(client_key))),
            body: OperationBody::ManageData(ManageDataOp {
                data_name: name(&format!("{HOME} auth")),
                data_value: Some(value(nonce.as_bytes())),
            }),
        },
        Operation {
            source_account: Some(server_account.clone()),
            body: OperationBody::ManageData(ManageDataOp {
                data_name: name("web_auth_domain"),
                data_value: Some(value(WEB_AUTH_DOMAIN.as_bytes())),
            }),
        },
    ]
    .try_into()
    .unwrap();
    let tx = Transaction {
        source_account: server_account,
        fee: 100,
        seq_num: SequenceNumber(0),
        cond: Preconditions::Time(TimeBounds {
            min_time: TimePoint(now - 60),
            max_time: TimePoint(now + 900),
        }),
        memo: Memo::None,
        operations,
        ext: TransactionExt::V0,
    };
    let hash = transaction_payload_hash(&tx, passphrase);
    let hint = |key: &SigningKey| {
        SignatureHint(key.verifying_key().to_bytes()[28..32].try_into().unwrap())
    };
    let mut signatures = vec![DecoratedSignature {
        hint: hint(&server),
        signature: server.sign(&hash).to_bytes().to_vec().try_into().unwrap(),
    }];
    for index in 0..extra_signatures {
        let other = SigningKey::from_bytes(&[u8::try_from(index).unwrap() + 0x60; 32]);
        signatures.push(DecoratedSignature {
            hint: hint(&other),
            signature: other.sign(&hash).to_bytes().to_vec().try_into().unwrap(),
        });
    }
    TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: signatures.try_into().unwrap(),
    })
    .to_xdr_base64(Limits::none())
    .unwrap()
}

/// One challenge the double served: the account the GET named and the
/// envelope it answered with.
#[derive(Clone)]
struct Served {
    account: String,
    envelope: String,
}

/// What the SEP-10 double answers, switched by a test, and what it saw.
#[derive(Default)]
struct Sep10Control {
    /// Challenges are built under the testnet passphrase.
    testnet: AtomicBool,
    /// Challenges name this account instead of the requested one.
    other_account: Mutex<Option<[u8; 32]>>,
    /// Further decorated signatures beside the server's.
    extra_signatures: AtomicUsize,
    /// The POST answers 400 whatever it carries.
    post_fails: AtomicBool,
    /// The JWT names an account other than the served one.
    other_sub: AtomicBool,
    /// Every challenge served, in order.
    served: Mutex<Vec<Served>>,
    /// The POSTs whose client signature verified.
    verified_posts: AtomicUsize,
    /// Every JWT answered.
    tokens: Mutex<Vec<String>>,
}

impl Sep10Control {
    fn passphrase(&self) -> &'static str {
        if self.testnet.load(Ordering::SeqCst) {
            TESTNET_PASSPHRASE
        } else {
            MAINNET_PASSPHRASE
        }
    }

    fn last_served(&self) -> Served {
        self.served.lock().unwrap().last().cloned().unwrap()
    }
}

struct ChallengeResponder(Arc<Sep10Control>);

impl wiremock::Respond for ChallengeResponder {
    fn respond(&self, request: &wiremock::Request) -> wiremock::ResponseTemplate {
        let account = request
            .url
            .query_pairs()
            .find(|(name, _)| name == "account")
            .map(|(_, value)| value.into_owned())
            .unwrap();
        let requested = stellar_strkey::ed25519::PublicKey::from_string(&account)
            .unwrap()
            .0;
        let client = self.0.other_account.lock().unwrap().unwrap_or(requested);
        let passphrase = self.0.passphrase();
        let envelope = challenge_xdr(
            client,
            passphrase,
            self.0.extra_signatures.load(Ordering::SeqCst),
        );
        self.0.served.lock().unwrap().push(Served {
            account,
            envelope: envelope.clone(),
        });
        wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "transaction": envelope,
            "network_passphrase": passphrase,
        }))
    }
}

/// Verifies the client signature of a posted challenge against the served
/// account over the mainnet payload hash it computes itself, and answers a
/// JWT for that account, or 400.
struct JwtResponder(Arc<Sep10Control>);

impl wiremock::Respond for JwtResponder {
    fn respond(&self, request: &wiremock::Request) -> wiremock::ResponseTemplate {
        use base64::Engine as _;
        if self.0.post_fails.load(Ordering::SeqCst) {
            return wiremock::ResponseTemplate::new(400);
        }
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        let signed = body["transaction"].as_str().unwrap();
        let served = self.0.last_served();
        let key = stellar_strkey::ed25519::PublicKey::from_string(&served.account)
            .unwrap()
            .0;
        let hash = envelope_payload_hash(signed, MAINNET_PASSPHRASE);
        let TransactionEnvelope::Tx(v1) =
            TransactionEnvelope::from_xdr_base64(signed, Limits::none()).unwrap()
        else {
            return wiremock::ResponseTemplate::new(400);
        };
        let verifying = ed25519_dalek::VerifyingKey::from_bytes(&key).unwrap();
        let verified = v1.signatures.iter().any(|signature| {
            <[u8; 64]>::try_from(signature.signature.as_slice()).is_ok_and(|bytes| {
                verifying
                    .verify_strict(&hash, &ed25519_dalek::Signature::from_bytes(&bytes))
                    .is_ok()
            })
        });
        if !verified {
            return wiremock::ResponseTemplate::new(400);
        }
        self.0.verified_posts.fetch_add(1, Ordering::SeqCst);
        let sub = if self.0.other_sub.load(Ordering::SeqCst) {
            strkey([0x78; 32])
        } else {
            served.account
        };
        let claims = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
            serde_json::json!({
                "sub": sub,
                "iss": format!("https://{HOME}"),
                "iat": 0,
                "exp": 9_999_999_999_u64,
            })
            .to_string(),
        );
        let token = format!("header.{claims}.sig");
        self.0.tokens.lock().unwrap().push(token.clone());
        wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({ "token": token }))
    }
}

/// A SEP-10 server for `HOME`: its stellar.toml names a web auth endpoint on
/// `HOME`, and the identity transport sends the SEP-10 requests here.
pub(super) struct Sep10Double {
    server: wiremock::MockServer,
    control: Arc<Sep10Control>,
}

impl Sep10Double {
    async fn start() -> Self {
        use wiremock::Mock;
        use wiremock::matchers::{method, path};
        let server = wiremock::MockServer::start().await;
        let control = Arc::new(Sep10Control::default());
        Mock::given(method("GET"))
            .and(path("/.well-known/stellar.toml"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_string(format!(
                    "SIGNING_KEY = \"{}\"\nWEB_AUTH_ENDPOINT = \"https://{HOME}/auth\"\n",
                    strkey(server_key().verifying_key().to_bytes())
                )),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/auth"))
            .respond_with(ChallengeResponder(Arc::clone(&control)))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/auth"))
            .respond_with(JwtResponder(Arc::clone(&control)))
            .mount(&server)
            .await;
        Self { server, control }
    }

    fn endpoint(&self) -> String {
        format!("{}/auth", self.server.uri())
    }

    fn http() -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap()
    }

    /// Points the server's authorized identity gate at this double.
    fn install(&self, server: &mut WalletServer) {
        server.set_x402_identity_transport_for_test(
            self.server.uri(),
            Self::http(),
            Some(self.endpoint()),
        );
    }

    pub(super) async fn requests(&self) -> usize {
        self.server.received_requests().await.unwrap().len()
    }

    pub(super) async fn posts(&self) -> usize {
        self.server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|request| request.method == wiremock::http::Method::POST)
            .count()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Policy, ledger and audit helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Adds a rule for the authenticated tool, a copy of the x402 create rule,
/// edited by `edit`.
fn authenticated_policy_with(raw: &str, edit: impl FnOnce(&mut toml_edit::Table)) -> String {
    let mut doc = raw.parse::<toml_edit::DocumentMut>().unwrap();
    let rules = doc["rules"].as_array_of_tables_mut().unwrap();
    let mut rule = rules
        .iter()
        .find(|rule| rule["match"]["tool"].as_str() == Some("stellar_x402_create_payment"))
        .unwrap()
        .clone();
    rule["match"]["tool"] = toml_edit::value(TOOL);
    edit(&mut rule);
    rules.push(rule);
    doc.to_string()
}

fn authenticated_policy(raw: &str) -> String {
    authenticated_policy_with(raw, |_| {})
}

/// The authenticated policy with the token's cross-check threshold below the
/// fixture's payment, so the payment requires the oracle witness.
fn witness_required_policy(raw: &str) -> String {
    let token = stellar_strkey::Contract([3; 32]).to_string().to_string();
    let lowered = raw.replace(
        &format!("\"{token}\" = \"10000000000\""),
        &format!("\"{token}\" = \"5\""),
    );
    assert_ne!(lowered, raw, "the token threshold is in the fixture policy");
    authenticated_policy(&lowered)
}

/// The ledger records of `domain`.
fn records(f: &Fixture, domain: &str) -> Vec<serde_json::Value> {
    authorizations(f)
        .into_iter()
        .filter(|record| record["domain"] == domain)
        .collect()
}

/// The one Message record, which must be used.
fn used_message_record(f: &Fixture) -> serde_json::Value {
    let messages = records(f, "message");
    assert_eq!(messages.len(), 1, "{messages:?}");
    assert_eq!(messages[0]["state"], "used", "{messages:?}");
    messages[0].clone()
}

pub(super) fn signings() -> Vec<serde_json::Value> {
    take_authorized_signings_for_test()
        .into_iter()
        .map(|id| serde_json::to_value(id).unwrap())
        .collect()
}

fn audit_rows(f: &Fixture) -> Vec<serde_json::Value> {
    std::fs::read_to_string(&f.server.security_profile().audit_log_path)
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

/// The final envelope of a returned payment payload.
fn released_transaction(result: &serde_json::Value) -> String {
    use base64::Engine as _;
    let payload = base64::engine::general_purpose::STANDARD
        .decode(result["data"]["paymentSignature"].as_str().unwrap())
        .unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    payload["payload"]["transaction"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn approval_file_exists(f: &Fixture) -> bool {
    f.server
        .resolve_approval_dir()
        .unwrap()
        .join("operator.toml")
        .exists()
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool runs
// ─────────────────────────────────────────────────────────────────────────────

/// A mainnet server whose primary and oracle hosts route to their own RPC
/// doubles and whose identity gate uses the SEP-10 double.
pub(super) struct Run {
    pub(super) f: Fixture,
    _primary: wiremock::MockServer,
    _oracle: wiremock::MockServer,
    pub(super) control: Arc<RpcControl>,
    oracle_control: Arc<RpcControl>,
    pub(super) double: Sep10Double,
}

impl Run {
    pub(super) async fn new() -> Self {
        Self::with(|raw| authenticated_policy(&raw)).await
    }

    async fn with(policy: impl FnOnce(String) -> String) -> Self {
        let primary = wiremock::MockServer::start().await;
        let oracle = wiremock::MockServer::start().await;
        let mut f = routed_fixture_with(policy, |_| {}, &primary, &oracle);
        let control = mount_rpc(&f, &primary).await;
        let oracle_control = mount_rpc(&f, &oracle).await;
        let double = Sep10Double::start().await;
        double.install(&mut f.server);
        let _ = take_authorized_signings_for_test();
        Self {
            f,
            _primary: primary,
            _oracle: oracle,
            control,
            oracle_control,
            double,
        }
    }

    fn args(&self, home: &str, approval: Option<(&str, &str)>) -> X402AuthenticatedPaymentArgs {
        X402AuthenticatedPaymentArgs {
            payment_required: serde_json::to_string(&self.f.requirements()).unwrap(),
            chain_id: "stellar:mainnet".to_owned(),
            home_domain: home.to_owned(),
            address: None,
            approval_nonce: approval.map(|(nonce, _)| nonce.to_owned()),
            approval_attestation: approval.map(|(_, attestation)| attestation.to_owned()),
        }
    }

    async fn call_raw(&self, args: X402AuthenticatedPaymentArgs) -> CallToolResult {
        self.f
            .server
            .call_stellar_x402_authenticated_payment(args)
            .await
            .unwrap()
    }

    async fn call(&self, args: X402AuthenticatedPaymentArgs) -> serde_json::Value {
        wire(&self.call_raw(args).await)
    }

    /// Runs call 1 for `HOME` and attests its pending approval.
    pub(super) async fn prepare(&self) -> (String, String) {
        let prepared = self.call(self.args(HOME, None)).await;
        assert_eq!(prepared["ok"], true, "{prepared}");
        let nonce = prepared["data"]["approval"]["approval_nonce"]
            .as_str()
            .unwrap()
            .to_owned();
        let entry = stored_approval(&self.f, &nonce).unwrap();
        (nonce.clone(), self.f.attest(&entry))
    }

    /// Runs call 2 for `home` with the approval; the RPC histories then hold
    /// this call's requests only.
    pub(super) async fn pay(&self, home: &str, approval: &(String, String)) -> serde_json::Value {
        self.control.clear();
        self.oracle_control.clear();
        self.call(self.args(home, Some((&approval.0, &approval.1))))
            .await
    }

    fn simulations(&self) -> usize {
        self.control.count("simulateTransaction")
    }
}

/// Asserts the accepted payment of `run`: the response fields, the verified
/// SEP-10 POST, the signing under exactly the Message record, the three used
/// records of the chain, the `RequireApproval` audit row, the tombstone over
/// the final envelope, and a replay refused as consumed.
async fn assert_accepted(run: &Run, approval: &(String, String), result: &serde_json::Value) {
    assert_eq!(result["ok"], true, "{result}");
    let data = &result["data"];
    assert!(data["paymentSignature"].is_string(), "{result}");
    let tokens = run.double.control.tokens.lock().unwrap().clone();
    assert_eq!(tokens.len(), 1);
    assert_eq!(data["authorization"], format!("Bearer {}", tokens[0]));
    assert_eq!(data["home_domain"], HOME);
    assert_eq!(run.double.control.verified_posts.load(Ordering::SeqCst), 1);
    let message = used_message_record(&run.f);
    assert_eq!(message["consumer"], "x402_authenticated", "{message}");
    assert_eq!(signings(), [message["id"].clone()]);
    let intents = records(&run.f, "soroban");
    assert_eq!(intents.len(), 1, "{intents:?}");
    assert_eq!(intents[0]["state"], "used");
    assert_eq!(intents[0]["parent"], message["id"], "{intents:?}");
    let submits = records(&run.f, "x402_submit");
    assert_eq!(submits.len(), 1, "{submits:?}");
    assert_eq!(submits[0]["state"], "used");
    assert_eq!(submits[0]["parent"], intents[0]["id"], "{submits:?}");
    assert_eq!(authorizations(&run.f).len(), 3);
    let rows: Vec<_> = audit_rows(&run.f)
        .into_iter()
        .filter(|row| row["kind"] == "x402_payment_authorized")
        .collect();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0]["policy_decision"], "require_approval", "{rows:?}");
    let stored = stored_approval(&run.f, &approval.0).unwrap();
    let stellar_agent_core::approval::ApprovalKind::Consumed { tx_hash, .. } = &stored.kind else {
        panic!("the approval is tombstoned")
    };
    assert_eq!(
        *tx_hash,
        stellar_agent_core::hex::encode(
            &stellar_agent_core::approval::subject::approval_subject_classic(
                &released_transaction(result)
            )
        )
    );
    let replay = run.pay(HOME, approval).await;
    assert_eq!(
        replay["error"]["code"], "policy.approval_consumed",
        "{replay}"
    );
}

/// Call 1 writes one pending approval for the intent and the home domain with
/// the governing TTL of the gate outcome, and sends no request.
#[tokio::test]
#[serial_test::serial(keyring)]
async fn call_one_writes_the_pending_approval_without_a_request() {
    use stellar_agent_core::approval::ApprovalKind;
    let run = Run::new().await;
    let requirements = run.f.requirements();
    let clients = stellar_agent_network::client::constructions_on_this_thread();
    let result = run.call(run.args(HOME, None)).await;
    assert_eq!(result["ok"], true, "{result}");
    let data = result["data"].as_object().unwrap();
    assert_eq!(data.keys().collect::<Vec<_>>(), ["approval"], "{result}");
    let approval = &result["data"]["approval"];
    assert_eq!(approval["profile"], "operator");
    assert_eq!(approval["chain_id"], "stellar:mainnet");
    let entry = stored_approval(&run.f, approval["approval_nonce"].as_str().unwrap()).unwrap();
    let ApprovalKind::X402Payment {
        intent_digest,
        home_domain,
        ..
    } = &entry.kind
    else {
        panic!("wrong pending kind")
    };
    assert_eq!(home_domain.as_deref(), Some(HOME));
    assert_eq!(
        *intent_digest,
        stellar_agent_x402::exact::intent_digest(&requirements, run.f.envelope.source()).unwrap()
    );
    let outcome = run
        .f
        .server
        .dispatch_preparation(
            TOOL,
            &serde_json::json!({"chain_id":"stellar:mainnet", "home_domain":HOME}),
            "stellar:mainnet",
            ValueClass::single(x402_value_leg(&requirements, 10)),
        )
        .await
        .unwrap();
    let outcome = run
        .f
        .server
        .force_mainnet_confirmation(TOOL, outcome)
        .unwrap();
    assert_eq!(
        entry.expires_at_unix_ms - entry.created_at_unix_ms,
        outcome.governing_ttl_ms()
    );
    assert!(run.control.methods().is_empty());
    assert!(run.oracle_control.methods().is_empty());
    assert_eq!(run.double.requests().await, 0);
    assert_eq!(run.f.seed_reads.load(Ordering::SeqCst), 0);
    assert_eq!(
        clients,
        stellar_agent_network::client::constructions_on_this_thread()
    );
    assert!(authorizations(&run.f).is_empty());
}

/// A `minimum_reserve` criterion on the authenticated tool's rule fails
/// closed at call 1, before any account request and before an approval is
/// written.
#[tokio::test]
#[serial_test::serial(keyring)]
async fn call_one_fails_closed_under_a_minimum_reserve_rule() {
    let run = Run::with(|raw| {
        authenticated_policy_with(&raw, |rule| {
            let mut reserve = toml_edit::InlineTable::new();
            reserve.insert("kind", "minimum_reserve".into());
            reserve.insert("margin_stroops", 0.into());
            rule["criteria"].as_array_mut().unwrap().push(reserve);
        })
    })
    .await;
    let clients = stellar_agent_network::client::constructions_on_this_thread();
    let result = run.call_raw(run.args(HOME, None)).await;
    assert_eq!(
        crate::tools::common::assert_business_envelope(&result).0,
        "policy.engine_required"
    );
    assert_eq!(
        clients,
        stellar_agent_network::client::constructions_on_this_thread()
    );
    assert!(run.control.methods().is_empty());
    assert!(!approval_file_exists(&run.f));
}

/// Call 1 refuses a home domain that is not lowercase LDH before the approval
/// names it.
#[tokio::test]
#[serial_test::serial(keyring)]
async fn call_one_refuses_an_invalid_home_domain() {
    let run = Run::new().await;
    let result = run.call_raw(run.args("Anchor.Example.com", None)).await;
    assert_eq!(
        crate::tools::common::assert_business_envelope(&result).0,
        "identity.home_domain_invalid"
    );
    assert!(!approval_file_exists(&run.f));
    assert!(run.control.methods().is_empty());
    assert!(run.oracle_control.methods().is_empty());
    assert_eq!(run.double.requests().await, 0);
}

/// One approval argument without the other refuses before any request.
#[tokio::test]
#[serial_test::serial(keyring)]
async fn a_partial_approval_pair_refuses_without_a_request() {
    let run = Run::new().await;
    for (nonce, attestation) in [(Some("partial"), None), (None, Some("partial"))] {
        let mut args = run.args(HOME, None);
        args.approval_nonce = nonce.map(str::to_owned);
        args.approval_attestation = attestation.map(str::to_owned);
        let result = run.call_raw(args).await;
        assert_eq!(
            crate::tools::common::assert_business_envelope(&result).0,
            "policy.approval_required"
        );
    }
    assert!(!approval_file_exists(&run.f));
    assert!(run.control.methods().is_empty());
    assert_eq!(run.double.requests().await, 0);
}

/// Call 2 below the threshold signs the challenge under the Message record,
/// builds the payment as its Soroban child, and releases the payload after
/// the submission record is used and the approval is tombstoned. The oracle
/// answers its identity and its latest ledger, which bounds the ledger the
/// signature expiration derives from, and simulates nothing.
#[tokio::test]
#[serial_test::serial(keyring)]
async fn call_two_accepts_below_the_threshold() {
    let run = Run::new().await;
    let approval = run.prepare().await;
    let result = run.pay(HOME, &approval).await;
    assert_eq!(
        result["data"]["cross_check"]["status"], "not_required",
        "{result}"
    );
    assert_eq!(
        run.oracle_control.methods(),
        ["getNetwork", "getLatestLedger"],
        "the oracle's identity request and its latest ledger below the threshold"
    );
    assert_accepted(&run, &approval, &result).await;
}

/// Call 2 below the threshold refuses when the oracle's latest ledger trails
/// the primary's simulation by three ledgers: the primary's ledger is not
/// shown current. No payment authorization is signed or minted, and the reply
/// names no transmitted authorization.
#[tokio::test]
#[serial_test::serial(keyring)]
async fn call_two_refuses_a_lagging_oracle_below_the_threshold() {
    let run = Run::new().await;
    let approval = run.prepare().await;
    run.oracle_control
        .latest_ledger_behind
        .store(3, Ordering::SeqCst);
    let result = run.pay(HOME, &approval).await;
    assert_eq!(result["error"]["code"], "simulation.divergence", "{result}");
    let message = result["error"]["message"].as_str().unwrap();
    assert!(!message.contains("valid through ledger"), "{result}");
    assert!(
        result
            .get("data")
            .is_none_or(|data| data.get("paymentSignature").is_none())
    );
    assert_eq!(
        run.oracle_control.methods(),
        ["getNetwork", "getLatestLedger"]
    );
    assert_eq!(run.simulations(), 1, "no signed simulation");
    assert_eq!(run.f.seed_reads.load(Ordering::SeqCst), 0);
    assert!(records(&run.f, "soroban").is_empty());
    assert!(
        audit_rows(&run.f)
            .iter()
            .all(|row| row["kind"] != "x402_payment_authorized")
    );
}

/// Call 2 below the threshold, with the oracle two ledgers behind the
/// primary, signs the entry under the expiration ledger of the primary's
/// simulation ledger: ledger 100 plus the 12 ledgers of the 60-second
/// timeout. The `x402_payment_authorized` row records the same ledger.
#[tokio::test]
#[serial_test::serial(keyring)]
async fn call_two_derives_the_expiration_from_the_primary_ledger() {
    let run = Run::new().await;
    let approval = run.prepare().await;
    run.oracle_control
        .latest_ledger_behind
        .store(2, Ordering::SeqCst);
    let result = run.pay(HOME, &approval).await;
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(
        run.oracle_control.methods(),
        ["getNetwork", "getLatestLedger"]
    );
    assert_eq!(run.control.signed_expiration_ledgers(), [112]);
    let rows = x402_authorized_rows(&run.f);
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0]["signature_expiration_ledger"], 112, "{rows:?}");
}

/// A re-simulation failure after the transmit gate passed withholds the
/// payment, and the reply and the `x402_payment_authorized` row name the
/// signature expiration ledger of the entry the primary received.
#[tokio::test]
#[serial_test::serial(keyring)]
async fn a_resimulation_failure_names_the_transmitted_authorization() {
    let run = Run::new().await;
    let approval = run.prepare().await;
    run.control.resimulation_error.store(true, Ordering::SeqCst);
    let result = run.pay(HOME, &approval).await;
    assert_eq!(result["ok"], false, "{result}");
    assert_eq!(
        result["error"]["code"], "x402.payment_build_failed",
        "{result}"
    );
    let message = result["error"]["message"].as_str().unwrap();
    assert!(
        message.starts_with("RPC simulate failed: re-simulate returned error"),
        "{result}"
    );
    assert_names_the_transmitted_ledger(&run.f, &run.control, message);
    assert!(
        result
            .get("data")
            .is_none_or(|data| data.get("paymentSignature").is_none())
    );
    assert_eq!(run.simulations(), 2);
}

/// A pending approval that cannot be consumed after the release withholds
/// the payment at terminal approval, and the reply and the
/// `x402_payment_authorized` row name the signature expiration ledger of the
/// entry the primary received.
#[tokio::test]
#[serial_test::serial(keyring)]
async fn a_terminal_approval_failure_names_the_transmitted_authorization() {
    let run = Run::new().await;
    let approval = run.prepare().await;
    let guard = HookGuard::default();
    let hold = Arc::clone(&guard);
    let approvals = run.f.server.resolve_approval_dir().unwrap();
    run.control.on_request(move |method| {
        if method == "simulateTransaction" {
            let mut held = hold.lock().unwrap();
            if held.is_none() {
                *held = Some(ReadOnlyDir::new(&approvals));
            }
        }
    });
    let result = run.pay(HOME, &approval).await;
    drop(guard.lock().unwrap().take());
    assert_eq!(result["ok"], false, "{result}");
    let message = result["error"]["message"].as_str().unwrap();
    assert!(
        message.starts_with("payment withheld at terminal approval"),
        "{result}"
    );
    assert_names_the_transmitted_ledger(&run.f, &run.control, message);
    assert!(
        result
            .get("data")
            .is_none_or(|data| data.get("paymentSignature").is_none())
    );
}

/// Call 2 above the threshold obtains the oracle witness through the routed
/// oracle host and accepts as below it.
#[tokio::test]
#[serial_test::serial(keyring)]
async fn call_two_accepts_a_witness_required_payment() {
    let run = Run::with(|raw| witness_required_policy(&raw)).await;
    let approval = run.prepare().await;
    let result = run.pay(HOME, &approval).await;
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(
        run.oracle_control.methods(),
        ["getNetwork", "simulateTransaction"],
        "the oracle's identity request and its simulation of the payment"
    );
    assert_eq!(
        result["data"]["cross_check"]["status"], "passed",
        "{result}"
    );
    assert_accepted(&run, &approval, &result).await;
}

/// A rotated installation between the calls refuses call 2 with the restart
/// message before any SEP-10 request.
#[tokio::test]
#[serial_test::serial(keyring)]
async fn call_two_refuses_after_the_enablement_rotates() {
    use stellar_agent_core::profile::schema::mainnet_enablement_entry_ref;
    let run = Run::new().await;
    let approval = run.prepare().await;
    put(
        &mainnet_enablement_entry_ref(&run.f.server.profile.policy_window_state_key_id),
        "rotated-installation",
    );
    let result = run.pay(HOME, &approval).await;
    assert_eq!(
        result["error"]["code"], "network.mainnet_write_forbidden",
        "{result}"
    );
    assert!(
        result["error"]["message"]
            .as_str()
            .unwrap()
            .contains("enablement or policy changed, restart the server"),
        "{result}"
    );
    assert_eq!(run.double.requests().await, 0);
    assert!(authorizations(&run.f).is_empty());
}

/// Call 2 for another home domain fails the approval subject before any
/// SEP-10 request.
#[tokio::test]
#[serial_test::serial(keyring)]
async fn call_two_refuses_another_home_domain() {
    let run = Run::new().await;
    let approval = run.prepare().await;
    let result = run.pay("other.example.com", &approval).await;
    assert_eq!(
        result["error"]["code"], "policy.approval_required",
        "{result}"
    );
    assert_eq!(run.double.requests().await, 0);
    assert!(authorizations(&run.f).is_empty());
}

/// A challenge for another client account refuses before the mint, so the
/// approval stays unspent and a following call 2 accepts.
#[tokio::test]
#[serial_test::serial(keyring)]
async fn a_challenge_for_another_account_spends_no_approval() {
    let run = Run::new().await;
    let approval = run.prepare().await;
    *run.double.control.other_account.lock().unwrap() = Some([0x77; 32]);
    let result = run.pay(HOME, &approval).await;
    assert_eq!(
        result["error"]["code"], "network.mainnet_authorization_refused",
        "{result}"
    );
    assert_eq!(result["error"]["message"], SEP10_REFUSAL, "{result}");
    assert_eq!(run.double.posts().await, 0);
    assert!(authorizations(&run.f).is_empty());
    assert!(signings().is_empty());
    *run.double.control.other_account.lock().unwrap() = None;
    let accepted = run.pay(HOME, &approval).await;
    assert_eq!(accepted["ok"], true, "{accepted}");
    assert_eq!(used_message_record(&run.f)["state"], "used");
}

/// A SEP-10 failure after the Message consume keeps the record used, mints
/// no intent and releases nothing.
#[tokio::test]
#[serial_test::serial(keyring)]
async fn post_consume_sep10_failures_keep_the_message_record_used() {
    for other_sub in [false, true] {
        let run = Run::new().await;
        let approval = run.prepare().await;
        if other_sub {
            run.double.control.other_sub.store(true, Ordering::SeqCst);
        } else {
            run.double.control.post_fails.store(true, Ordering::SeqCst);
        }
        let result = run.pay(HOME, &approval).await;
        assert_eq!(
            result["error"]["code"], "identity.sep10_auth_failed",
            "{other_sub}: {result}"
        );
        assert!(result["data"].get("paymentSignature").is_none());
        let message = used_message_record(&run.f);
        assert!(records(&run.f, "soroban").is_empty(), "{other_sub}");
        assert_eq!(signings(), [message["id"].clone()], "{other_sub}");
        assert_eq!(run.double.posts().await, 1, "{other_sub}");
    }
}

/// A replay of call 2 after a post-consume failure refuses at the Message
/// mint, because the approval nonce already minted a record.
#[tokio::test]
#[serial_test::serial(keyring)]
async fn a_replay_after_a_post_consume_failure_refuses_the_reused_nonce() {
    let run = Run::new().await;
    let approval = run.prepare().await;
    run.double.control.post_fails.store(true, Ordering::SeqCst);
    let failed = run.pay(HOME, &approval).await;
    assert_eq!(
        failed["error"]["code"], "identity.sep10_auth_failed",
        "{failed}"
    );
    let _ = signings();
    run.double.control.post_fails.store(false, Ordering::SeqCst);
    let (capture, _guard) =
        stellar_agent_test_support::WarningCapture::capture(Some("stellar_agent"));
    let replay = run.pay(HOME, &approval).await;
    assert_eq!(
        replay["error"]["code"], "network.mainnet_authorization_refused",
        "{replay}"
    );
    assert_eq!(replay["error"]["message"], SEP10_REFUSAL, "{replay}");
    // The refusal is logged once, where it was refused, and nothing else
    // warns.
    let warnings = capture.seen();
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert_eq!(
        refusals(&capture),
        [(
            "resolve_message_sign".to_owned(),
            "approval_nonce_reused".to_owned()
        )]
    );
    assert_eq!(authorizations(&run.f).len(), 1);
    used_message_record(&run.f);
    assert!(signings().is_empty());
    assert_eq!(run.double.posts().await, 1, "only the failed call posted");
}

/// A fixed identity session refuses on a server with a mainnet context
/// before anything is decoded or requested.
#[tokio::test]
#[serial_test::serial(keyring)]
async fn the_session_seam_refuses_on_a_server_with_a_context() {
    let mut run = Run::new().await;
    run.f.server.set_x402_identity_session_for_test(
        "header.payload.sig".to_owned(),
        strkey([0x22; 32]),
        Vec::new(),
    );
    let result = run.call_raw(run.args(HOME, None)).await;
    assert_eq!(
        crate::tools::common::assert_business_envelope(&result).0,
        "network.mainnet_write_forbidden"
    );
    assert!(run.control.methods().is_empty());
    assert_eq!(run.double.requests().await, 0);
    assert!(!approval_file_exists(&run.f));
}

/// An anchor that fails from the transmit row on refuses with the audit code
/// at the transmit gate: the intent is invalidated before the signed
/// simulation, the Message record stays used, and nothing is released.
#[tokio::test]
#[serial_test::serial(keyring)]
async fn an_unavailable_anchor_at_the_transmit_gate_withholds_the_payment() {
    use stellar_agent_test_support::keyring_mock;
    let run = Run::new().await;
    let approval = run.prepare().await;
    let profile = run.f.server.security_profile();
    let anchor = stellar_agent_network::keyring::KeyringTipAnchorStore::new(
        &profile.audit_log_hash_chain_key_id,
        &profile.audit_log_path,
    )
    .anchor_entry_ref()
    .clone();
    observe(&run.f.on_seed_read, move || {
        keyring_mock::inject_error(
            &anchor.service,
            &anchor.account,
            keyring_core::Error::NoStorageAccess(std::io::Error::other("locked").into()),
        )
        .unwrap();
    });
    let result = run.pay(HOME, &approval).await;
    *run.f.on_seed_read.lock().unwrap() = None;
    assert_eq!(
        result["error"]["code"], "audit.chain_key_unavailable",
        "{result}"
    );
    assert!(result["data"].get("paymentSignature").is_none());
    used_message_record(&run.f);
    let intents = records(&run.f, "soroban");
    assert_eq!(intents.len(), 1, "{intents:?}");
    assert_eq!(intents[0]["state"], "invalidated");
    assert_eq!(intents[0]["invalidation"], "intent_pre_transmit_refused");
    assert!(records(&run.f, "x402_submit").is_empty());
    assert_eq!(run.simulations(), 1, "no signed simulation");
    assert_eq!(run.f.seed_reads.load(Ordering::SeqCst), 1);
}

// ─────────────────────────────────────────────────────────────────────────────
// Signing boundary
// ─────────────────────────────────────────────────────────────────────────────

/// A mainnet server, the SEP-10 double, and the fixture payment's intent.
struct Boundary {
    f: Fixture,
    double: Sep10Double,
    requirements: stellar_agent_x402::wire::PaymentRequirements,
    root: stellar_xdr::SorobanAuthorizedInvocation,
    network_id: [u8; 32],
}

impl Boundary {
    async fn new() -> Self {
        let f = Fixture::new(|raw| authenticated_policy(&raw));
        let double = Sep10Double::start().await;
        let requirements = f.requirements();
        let root =
            stellar_agent_x402::exact::payment_root(&requirements, f.envelope.source()).unwrap();
        let network_id = sha2::Sha256::digest(MAINNET_PASSPHRASE.as_bytes()).into();
        let _ = take_authorized_signings_for_test();
        Self {
            f,
            double,
            requirements,
            root,
            network_id,
        }
    }

    /// A fresh pending approval of the intent for `HOME`, attested by the
    /// operator and verified through the tool's gate.
    async fn approval(&self) -> (PendingApproval, ApprovalWitness) {
        let entry = PendingApproval::new_x402_pending(
            &self.network_id,
            &self.root,
            Some(HOME.to_owned()),
            process_uid_for_attestation().unwrap(),
            600_000,
        )
        .unwrap();
        let blob = self.f.attest(&entry);
        let outcome = self
            .f
            .server
            .dispatch_preparation(
                TOOL,
                &serde_json::json!({"chain_id":"stellar:mainnet", "home_domain":HOME}),
                "stellar:mainnet",
                ValueClass::single(x402_value_leg(&self.requirements, 10)),
            )
            .await
            .unwrap();
        let outcome = self
            .f
            .server
            .force_mainnet_confirmation(TOOL, outcome)
            .unwrap();
        let digest =
            stellar_agent_x402::exact::intent_digest(&self.requirements, self.f.envelope.source())
                .unwrap();
        let witness = verify_attestation_subject_gate(
            &self.f.server,
            &outcome,
            GatedApprovalKind::X402.expectation(
                stellar_agent_core::approval::subject::approval_subject_x402_authenticated(
                    &digest, HOME,
                ),
            ),
            Some(&entry.approval_nonce),
            Some(&blob),
            TOOL,
        )
        .await
        .unwrap()
        .unwrap();
        (entry, witness)
    }

    fn client(passphrase: &str) -> Sep10Client {
        Sep10Client::new_for_unit_test(passphrase).unwrap()
    }

    async fn prepare(&self, client: &Sep10Client) -> PreparedEphemeralAuth {
        prepare_ephemeral_auth(
            client,
            &self.double.endpoint(),
            HOME,
            &strkey(server_key().verifying_key().to_bytes()),
            WEB_AUTH_DOMAIN,
        )
        .await
        .unwrap()
    }

    fn intent(&self) -> stellar_agent_network::mainnet::resolve::SorobanIntent<'_> {
        stellar_agent_network::mainnet::resolve::SorobanIntent {
            consumer: MainnetConsumer::X402Authenticated,
            root_invocation: &self.root,
            network_id: self.network_id,
        }
    }

    fn store(&self) -> stellar_agent_network::policy_state::PersistedWindowStore {
        stellar_agent_network::policy_state::PersistedWindowStore::at_path(
            self.f.server.window_path.clone(),
        )
    }

    /// Mints and consumes the message authorization of `facts` under
    /// `approval`, through the public resolver and consume.
    fn receipt(&self, facts: &MessageFacts, approval: &ApprovalWitness) -> MessageUseReceipt {
        use stellar_agent_network::mainnet::resolve::{
            MessageSignRequest, consume_message_sign, resolve_message_sign,
        };
        let guard = self
            .f
            .server
            .mainnet_write_admission(MainnetConsumer::X402Authenticated)
            .unwrap();
        let store = self.store();
        let intent = self.intent();
        let audit = stellar_agent_network::mainnet::audit_readiness::audit_readiness(
            guard.context.profile(),
            "operator",
        )
        .unwrap();
        let authorization = resolve_message_sign(MessageSignRequest {
            context: guard.context,
            consumer: MainnetConsumer::X402Authenticated,
            intent: &intent,
            message: facts,
            policy: guard.policy,
            enablement: guard.enablement,
            approval,
            audit,
            store: &store,
        })
        .unwrap();
        consume_message_sign(guard.context, authorization, &store).unwrap()
    }

    /// Prepares on mainnet and returns the prepared value with the receipt of
    /// its facts.
    async fn prepared_with_receipt(&self) -> (PreparedEphemeralAuth, MessageUseReceipt) {
        let prepared = self.prepare(&Self::client(MAINNET_PASSPHRASE)).await;
        let (_, approval) = self.approval().await;
        let receipt = self.receipt(&prepared.message_facts(), &approval);
        (prepared, receipt)
    }

    async fn complete(
        &self,
        prepared: PreparedEphemeralAuth,
        receipt: &MessageUseReceipt,
    ) -> stellar_agent_sep10::Sep10Error {
        complete_ephemeral_auth_authorized(
            &Self::client(MAINNET_PASSPHRASE),
            prepared,
            MainnetConsumer::X402Authenticated,
            receipt,
        )
        .await
        .unwrap_err()
    }

    /// Asserts a completion refused at `precondition` before signing: the
    /// SEP-10 refusal, its one log line, no signing and no POST, and the
    /// Message record used.
    async fn assert_refused_before_signing(
        &self,
        error: &stellar_agent_sep10::Sep10Error,
        capture: &stellar_agent_test_support::WarningCapture,
        precondition: &str,
    ) {
        assert_eq!(
            error.wire_code(),
            "sep10.mainnet_authorization_refused",
            "{error:?}"
        );
        assert_eq!(
            refusals(capture),
            [(
                "complete_ephemeral_auth_authorized".to_owned(),
                precondition.to_owned()
            )]
        );
        assert!(signings().is_empty(), "{precondition}");
        assert_eq!(self.double.posts().await, 0, "{precondition}");
        used_message_record(&self.f);
    }
}

/// The completion refuses a receipt whose record expired before it signs.
#[tokio::test]
#[serial_test::serial(keyring)]
async fn the_sibling_refuses_an_expired_authorization() {
    let b = Boundary::new().await;
    let (prepared, receipt) = b.prepared_with_receipt().await;
    let expires = used_message_record(&b.f)["expires_ms"].as_u64().unwrap();
    let _clock = stellar_agent_network::mainnet::clock::set_now_ms_for_test(expires + 1);
    let (capture, _guard) =
        stellar_agent_test_support::WarningCapture::capture(Some("stellar_agent"));
    let error = b.complete(prepared, &receipt).await;
    b.assert_refused_before_signing(&error, &capture, "expired")
        .await;
}

/// The completion refuses a challenge that was validated under testnet, even
/// when the receipt binds the challenge's mainnet payload hash.
#[tokio::test]
#[serial_test::serial(keyring)]
async fn the_sibling_refuses_a_challenge_validated_under_testnet() {
    let b = Boundary::new().await;
    b.double.control.testnet.store(true, Ordering::SeqCst);
    let prepared = b.prepare(&Boundary::client(TESTNET_PASSPHRASE)).await;
    let served = b.double.control.last_served();
    let facts = MessageFacts {
        domain: prepared.message_domain(),
        content_digest: envelope_payload_hash(&served.envelope, MAINNET_PASSPHRASE),
        ephemeral_public_key: prepared.ephemeral_public_key(),
    };
    let (_, approval) = b.approval().await;
    let receipt = b.receipt(&facts, &approval);
    let (capture, _guard) =
        stellar_agent_test_support::WarningCapture::capture(Some("stellar_agent"));
    let error = b.complete(prepared, &receipt).await;
    b.assert_refused_before_signing(&error, &capture, "chain_not_mainnet")
        .await;
}

/// The completion refuses the receipt of another preparation.
#[tokio::test]
#[serial_test::serial(keyring)]
async fn the_sibling_refuses_the_receipt_of_another_preparation() {
    let b = Boundary::new().await;
    let client = Boundary::client(MAINNET_PASSPHRASE);
    let first = b.prepare(&client).await;
    let second = b.prepare(&client).await;
    let (first_entry, _) = b.approval().await;
    let (second_entry, second_approval) = b.approval().await;
    let receipt = b.receipt(&second.message_facts(), &second_approval);
    let (capture, _guard) =
        stellar_agent_test_support::WarningCapture::capture(Some("stellar_agent"));
    let error = b.complete(first, &receipt).await;
    b.assert_refused_before_signing(&error, &capture, "message_use_mismatch")
        .await;
    let all = authorizations(&b.f);
    assert_eq!(all.len(), 1, "{all:?}");
    assert_eq!(all[0]["approval_nonce"], second_entry.approval_nonce);
    assert_ne!(first_entry.approval_nonce, second_entry.approval_nonce);
}

/// The completion refuses a receipt whose content digest is not the prepared
/// challenge's, while its key and domains are the prepared ones.
#[tokio::test]
#[serial_test::serial(keyring)]
async fn the_sibling_refuses_a_receipt_with_another_digest() {
    let b = Boundary::new().await;
    let prepared = b.prepare(&Boundary::client(MAINNET_PASSPHRASE)).await;
    let prepared_facts = prepared.message_facts();
    let mut content_digest = prepared_facts.content_digest;
    content_digest[0] ^= 0xff;
    let facts = MessageFacts {
        content_digest,
        ..prepared_facts
    };
    let (entry, approval) = b.approval().await;
    let receipt = b.receipt(&facts, &approval);
    assert_eq!(
        receipt.ephemeral_public_key(),
        prepared.ephemeral_public_key()
    );
    assert_eq!(receipt.home_domain(), HOME);
    assert_ne!(receipt.content_digest(), prepared.content_digest());
    let (capture, _guard) =
        stellar_agent_test_support::WarningCapture::capture(Some("stellar_agent"));
    let error = b.complete(prepared, &receipt).await;
    b.assert_refused_before_signing(&error, &capture, "message_use_mismatch")
        .await;
    let all = authorizations(&b.f);
    assert_eq!(all.len(), 1, "{all:?}");
    assert_eq!(all[0]["approval_nonce"], entry.approval_nonce);
}

/// The completion refuses when the mainnet clock fails.
#[tokio::test]
#[serial_test::serial(keyring)]
async fn the_sibling_refuses_a_failing_clock() {
    let b = Boundary::new().await;
    let (prepared, receipt) = b.prepared_with_receipt().await;
    let _clock = stellar_agent_network::mainnet::clock::set_clock_error_for_test();
    let (capture, _guard) =
        stellar_agent_test_support::WarningCapture::capture(Some("stellar_agent"));
    let error = b.complete(prepared, &receipt).await;
    b.assert_refused_before_signing(&error, &capture, "clock_unavailable")
        .await;
}

/// A signature that fails its verification refuses after signing and before
/// the POST.
#[tokio::test]
#[serial_test::serial(keyring)]
async fn the_sibling_refuses_a_corrupted_signature() {
    let b = Boundary::new().await;
    let (prepared, receipt) = b.prepared_with_receipt().await;
    corrupt_next_signature_for_test();
    let (capture, _guard) =
        stellar_agent_test_support::WarningCapture::capture(Some("stellar_agent"));
    let error = b.complete(prepared, &receipt).await;
    assert_eq!(error.wire_code(), "sep10.mainnet_authorization_refused");
    assert_eq!(
        refusals(&capture),
        [(
            "complete_ephemeral_auth_authorized".to_owned(),
            "signature_invalid".to_owned()
        )]
    );
    assert_eq!(signings(), [serde_json::to_value(receipt.id()).unwrap()]);
    assert_eq!(b.double.posts().await, 0);
    used_message_record(&b.f);
}

/// A challenge that already holds twenty signatures cannot take the client
/// signature: the completion fails after signing and before the POST.
#[tokio::test]
#[serial_test::serial(keyring)]
async fn the_sibling_fails_to_attach_to_a_full_envelope() {
    let b = Boundary::new().await;
    b.double
        .control
        .extra_signatures
        .store(19, Ordering::SeqCst);
    let (prepared, receipt) = b.prepared_with_receipt().await;
    let error = b.complete(prepared, &receipt).await;
    assert!(
        matches!(
            &error,
            stellar_agent_sep10::Sep10Error::XdrDecodeError { detail }
                if detail.contains("VecM<20>")
        ),
        "{error:?}"
    );
    assert_eq!(signings(), [serde_json::to_value(receipt.id()).unwrap()]);
    assert_eq!(b.double.posts().await, 0);
    used_message_record(&b.f);
}

/// The identity gate refuses an approval created after the mainnet clock
/// before anything is minted or signed.
#[tokio::test]
#[serial_test::serial(keyring)]
async fn the_identity_gate_refuses_a_future_created_approval() {
    let b = Boundary::new().await;
    let (entry, approval) = b.approval().await;
    let _clock = stellar_agent_network::mainnet::clock::set_now_ms_for_test(
        entry.created_at_unix_ms - 8 * 24 * 60 * 60 * 1000,
    );
    let guard =
        b.f.server
            .mainnet_write_admission(MainnetConsumer::X402Authenticated)
            .unwrap();
    let store = b.store();
    let intent = b.intent();
    let audit = stellar_agent_network::mainnet::audit_readiness::audit_readiness(
        guard.context.profile(),
        "operator",
    )
    .unwrap();
    let error = stellar_agent_x402_identity::resolve_and_verify_counterparty_authorized_at(
        HOME,
        &b.double.server.uri(),
        &Sep10Double::http(),
        Some(&b.double.endpoint()),
        stellar_agent_x402_identity::MainnetIdentityInputs {
            context: guard.context,
            intent: &intent,
            policy: guard.policy,
            enablement: guard.enablement,
            approval: &approval,
            audit,
            store: &store,
        },
    )
    .await
    .unwrap_err();
    assert_eq!(error.wire_code(), "identity.mainnet_authorization_refused");
    assert_eq!(error.to_string(), SEP10_REFUSAL);
    assert!(authorizations(&b.f).is_empty());
    assert!(signings().is_empty());
    assert_eq!(b.double.posts().await, 0);
}

/// The identity inputs print the profile only: nothing of the approval, the
/// policy, the enablement, the audit or the store.
#[tokio::test]
#[serial_test::serial(keyring)]
async fn the_identity_inputs_print_the_profile_only() {
    let b = Boundary::new().await;
    let (entry, approval) = b.approval().await;
    let guard =
        b.f.server
            .mainnet_write_admission(MainnetConsumer::X402Authenticated)
            .unwrap();
    let store = b.store();
    let intent = b.intent();
    let audit = stellar_agent_network::mainnet::audit_readiness::audit_readiness(
        guard.context.profile(),
        "operator",
    )
    .unwrap();
    let inputs = stellar_agent_x402_identity::MainnetIdentityInputs {
        context: guard.context,
        intent: &intent,
        policy: guard.policy,
        enablement: guard.enablement,
        approval: &approval,
        audit,
        store: &store,
    };
    let printed = format!("{inputs:?}");
    assert_eq!(
        printed,
        format!(
            "MainnetIdentityInputs {{ profile: {:?}, .. }}",
            guard.context.profile_name()
        )
    );
    assert!(!printed.contains(&entry.approval_nonce), "{printed}");
}

/// The verified mainnet session prints the redacted session and the
/// receipt's redacted form: no JWT, no challenge envelope and no bound
/// digest.
#[tokio::test]
#[serial_test::serial(keyring)]
async fn the_mainnet_session_prints_no_jwt_and_no_envelope() {
    let b = Boundary::new().await;
    let (entry, approval) = b.approval().await;
    let guard =
        b.f.server
            .mainnet_write_admission(MainnetConsumer::X402Authenticated)
            .unwrap();
    let store = b.store();
    let intent = b.intent();
    let audit = stellar_agent_network::mainnet::audit_readiness::audit_readiness(
        guard.context.profile(),
        "operator",
    )
    .unwrap();
    let session = stellar_agent_x402_identity::resolve_and_verify_counterparty_authorized_at(
        HOME,
        &b.double.server.uri(),
        &Sep10Double::http(),
        Some(&b.double.endpoint()),
        stellar_agent_x402_identity::MainnetIdentityInputs {
            context: guard.context,
            intent: &intent,
            policy: guard.policy,
            enablement: guard.enablement,
            approval: &approval,
            audit,
            store: &store,
        },
    )
    .await
    .unwrap();
    assert_eq!(session.session().home_domain, HOME);
    let printed = format!("{session:?}");
    let (verified, receipt) = session.into_parts();
    assert_eq!(
        printed,
        format!("MainnetCounterpartySession {{ session: {verified:?}, receipt: {receipt:?} }}")
    );
    let jwt = b
        .double
        .control
        .tokens
        .lock()
        .unwrap()
        .last()
        .cloned()
        .unwrap();
    assert_eq!(verified.jwt, jwt);
    let envelope = b.double.control.last_served().envelope;
    let digest = stellar_agent_core::hex::encode(&receipt.content_digest());
    for hidden in [jwt, envelope, digest, entry.approval_nonce] {
        assert!(!printed.contains(&hidden), "{printed} holds {hidden}");
    }
}
