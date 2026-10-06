//! `stellar_mpp_charge_commit` against the audit log.
//!
//! The commit acquires the audit writer after it reads its approval and before
//! it loads the signing key, which drains any consent row queued beside the
//! running server. It then writes its authorization row through the strict
//! emission helper and withholds the credential when that write cannot be
//! made, so a log rolled back under the running server refuses the credential.
//! A failure in the sponsored commit writes a withheld row naming the side of
//! the signed re-simulation send.

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
    /// Runs when a signed re-simulation arrives, before it is answered.
    on_signed: Option<std::sync::Arc<dyn Fn() + Send + Sync>>,
    /// Answers the signed re-simulation with an RPC error.
    fail_signed: bool,
    /// Number of signed re-simulations received.
    signed_requests: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl SponsoredSimulateResponder {
    fn new(payer: ScAddress) -> Self {
        Self {
            payer,
            on_signed: None,
            fail_signed: false,
            signed_requests: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    fn on_signed(mut self, hook: std::sync::Arc<dyn Fn() + Send + Sync>) -> Self {
        self.on_signed = Some(hook);
        self
    }

    fn failing_signed(mut self) -> Self {
        self.fail_signed = true;
        self
    }
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
            self.signed_requests
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if let Some(hook) = &self.on_signed {
                hook();
            }
            if self.fail_signed {
                return ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {"error": "re-simulation trapped", "latestLedger": 1000},
                    }))
                    .insert_header("content-type", "application/json");
            }
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

/// CLI library orchestration and the MCP handler preserve identical authorization terms.
#[tokio::test]
#[serial]
async fn cli_and_mcp_authorization_fingerprint_and_preview_match() {
    use std::time::{Duration, UNIX_EPOCH};
    use stellar_agent_core::{
        approval::user_id::process_uid_for_attestation,
        profile::schema::KeyringEntryRef,
        timefmt::{format_rfc3339_utc, now_unix_ms},
    };
    use stellar_agent_mpp::{
        ApprovalDisposition, McpOperationKind, McpRequestContext, MppAuthorizationStore,
        StellarSponsoredRpc, persist_prepared_authorization, prepare_sponsored,
        select_and_validate,
    };

    const PROFILE_NAME: &str = "mpp-preview-parity";
    let home = tempfile::tempdir().expect("temp home");
    let _home_guard = StellarAgentHomeGuard::new(home.path());
    keyring_mock::install().expect("mock keyring");
    install_test_nonce_key(243);
    let payer = gstrkey_for_seed([0x6f; 32]);
    let rpc_server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(SponsoredSimulateResponder::new(payer_sc_address(&payer)))
        .expect(2)
        .mount(&rpc_server)
        .await;
    let mut profile =
        Profile::builder_testnet_named(PROFILE_NAME, SIGNER_SERVICE, &payer, "n-svc", "n-acct")
            .with_noop_engine()
            .build();
    profile.rpc_url = rpc_server.uri();
    common::install_test_audit_key(&mut profile);
    let server = WalletServer::new(profile.clone()).expect("wallet server");

    // An explicit expiry keeps both selections stable across clock ticks.
    let now_seconds = now_unix_ms().expect("clock") / 1_000;
    let now_unix = i64::try_from(now_seconds).expect("Unix seconds");
    let input = ChallengeInput::Mcp {
        challenges: vec![serde_json::json!({
            "id": "Challenge-Parity",
            "realm": " Merchant.Example ",
            "method": "stellar",
            "intent": "charge",
            "expires": format_rfc3339_utc(UNIX_EPOCH + Duration::from_secs(now_seconds + 120)),
            "request": {
                "amount": "10000000",
                "currency": CONTRACT,
                "recipient": RECIPIENT,
                "methodDetails": {"feePayer": true, "network": "stellar:testnet"},
            },
        })],
        selected_challenge_id: Some("Challenge-Parity".into()),
        context: McpRequestContext::from_params(
            " Merchant.Example ",
            McpOperationKind::Tool,
            " Checkout ",
            Some(&serde_json::json!({"quantity": 1, "sku": "Item-A"})),
        )
        .expect("MCP context"),
    };

    // The CLI decodes tagged JSON before these shared library calls.
    let cli_input = serde_json::from_value(
        stellar_agent_mpp::json::parse_strict_json(
            &serde_json::to_vec(&input).expect("tagged challenge JSON"),
        )
        .expect("strict JSON"),
    )
    .expect("typed CLI input");
    let selected = select_and_validate(&cli_input, now_unix).expect("CLI selection");
    let rpc = StellarSponsoredRpc::new(&profile.rpc_url).expect("CLI RPC");
    let prepared = prepare_sponsored(
        selected,
        &profile.mcp_signer_default.account,
        &profile.network_passphrase,
        &rpc,
    )
    .await
    .expect("CLI preparation");

    // Independent stores ensure each surface constructs its own preview.
    let generation = KeyringEntryRef::new("mpp-preview-parity-cli", "generation");
    keyring_core::Entry::new(&generation.service, &generation.account)
        .expect("generation entry")
        .set_password("0")
        .expect("initial generation");
    let cli_state =
        MppAuthorizationStore::at_path(home.path().join("cli.state"), [0x71; 32], generation);
    let cli_preview = persist_prepared_authorization(
        PROFILE_NAME,
        &profile.network_passphrase,
        &prepared,
        ApprovalDisposition::Allow,
        &process_uid_for_attestation().expect("process UID"),
        now_unix,
        &cli_state,
        None,
    )
    .expect("CLI preview");
    let mcp_result = server
        .call_stellar_mpp_charge_prepare(PROFILE_NAME.into(), input)
        .await
        .expect("MCP prepare");
    let mcp_envelope = result_json(&mcp_result);
    assert_ne!(mcp_result.is_error, Some(true), "{mcp_envelope}");
    let mcp_preview = &mcp_envelope["data"]["authorization"];
    assert_eq!(
        mcp_preview["authorization_fingerprint"], cli_preview.authorization_fingerprint,
        "CLI and MCP authorization fingerprints must match"
    );
    assert_eq!(
        mcp_preview,
        &serde_json::to_value(&cli_preview).expect("CLI preview JSON"),
        "CLI and MCP must agree on every serialized preview field"
    );
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
/// The first charge leaves a cached writer and an anchor naming the log.
/// Truncation on disk must make the second charge withhold its credential
/// because the log no longer contains the anchored tip.
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

    let mut profile =
        Profile::builder_testnet_named(PROFILE, SIGNER_SERVICE, &payer_g, "n-svc", "n-acct")
            .with_noop_engine()
            .build();
    common::install_test_audit_key(&mut profile);
    let audit_log_path = profile.audit_log_path.clone();

    // The rollback lands inside the signed re-simulation of round two: after
    // the commit's audit acquisition passed and before its delivery gate, so
    // the refusal has to come from the strict delivery-gate write.
    let armed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let rollback_armed = std::sync::Arc::clone(&armed);
    let rollback_path = audit_log_path.clone();
    let responder = SponsoredSimulateResponder::new(payer_sc_address(&payer_g)).on_signed(
        std::sync::Arc::new(move || {
            if rollback_armed.swap(false, std::sync::atomic::Ordering::SeqCst) {
                std::fs::write(&rollback_path, b"").expect("truncate the audit log");
            }
        }),
    );
    let signed_requests = std::sync::Arc::clone(&responder.signed_requests);
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(responder)
        .mount(&mock_server)
        .await;
    profile.rpc_url = mock_server.uri();
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

    // Roll the log back underneath the writer the server is still holding,
    // during the signed re-simulation of the second commit.
    armed.store(true, std::sync::atomic::Ordering::SeqCst);
    let signed_before = signed_requests.load(std::sync::atomic::Ordering::SeqCst);

    let second = prepare_and_commit(&server, PROFILE, 2).await;
    assert!(
        !armed.load(std::sync::atomic::Ordering::SeqCst),
        "the rollback must have run inside the signed re-simulation"
    );
    assert_eq!(
        signed_requests.load(std::sync::atomic::Ordering::SeqCst),
        signed_before + 1,
        "the second commit must reach its signed re-simulation, so the refusal \
         comes from the delivery gate"
    );
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
        .respond_with(SponsoredSimulateResponder::new(payer_sc_address(&payer)))
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
        .respond_with(SponsoredSimulateResponder::new(payer_sc_address(&payer)))
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

// ── Withheld-row stages ───────────────────────────────────────────────────────

/// One MPP server over a mock RPC: the payer, the profile, and the server.
struct MppFixture {
    _home: tempfile::TempDir,
    _home_guard: StellarAgentHomeGuard,
    _mock: MockServer,
    profile: Profile,
    server: WalletServer,
    signed_requests: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    payer: String,
}

/// Builds a server for `profile_name`. `seed_secret` decides whether the
/// payer's secret is in the keyring; without it the lazy signer fails at the
/// sign call.
async fn mpp_fixture(
    profile_name: &str,
    seed: [u8; 32],
    seed_secret: bool,
    configure: impl FnOnce(SponsoredSimulateResponder, &Profile) -> SponsoredSimulateResponder,
) -> MppFixture {
    let home = tempfile::tempdir().expect("temp home");
    let home_guard = StellarAgentHomeGuard::new(home.path());
    keyring_mock::install().expect("mock keyring");
    install_test_nonce_key(244);
    let payer = gstrkey_for_seed(seed);
    if seed_secret {
        keyring_core::Entry::new(SIGNER_SERVICE, &payer)
            .expect("Entry::new")
            .set_password(&sstrkey_for_seed(seed))
            .expect("set_password");
    }
    let mut profile =
        Profile::builder_testnet_named(profile_name, SIGNER_SERVICE, &payer, "n-svc", "n-acct")
            .with_noop_engine()
            .build();
    common::install_test_audit_key(&mut profile);
    let _ = std::fs::remove_file(&profile.audit_log_path);
    let responder = configure(
        SponsoredSimulateResponder::new(payer_sc_address(&payer)),
        &profile,
    );
    let signed_requests = std::sync::Arc::clone(&responder.signed_requests);
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(responder)
        .mount(&mock)
        .await;
    profile.rpc_url = mock.uri();
    let server = WalletServer::new(profile.clone()).expect("WalletServer::new");
    MppFixture {
        _home: home,
        _home_guard: home_guard,
        _mock: mock,
        profile,
        server,
        signed_requests,
        payer,
    }
}

/// The single `mpp_authorization_withheld` row in the log.
fn withheld_row(profile: &Profile) -> serde_json::Value {
    let rows = common::audit_rows(profile);
    let withheld = common::rows_of_kind(&rows, "mpp_authorization_withheld");
    assert_eq!(withheld.len(), 1, "one withheld row: {rows:?}");
    withheld[0].clone()
}

/// A failure at the sign call records `signing`: the key was used and the
/// signed entry never reached the RPC.
#[tokio::test]
#[serial]
async fn mpp_commit_failure_at_the_sign_call_records_signing() {
    let fixture = mpp_fixture("mpp-stage-signing", [0x71; 32], false, |r, _| r).await;
    let result = prepare_and_commit(&fixture.server, "mpp-stage-signing", 11).await;
    let (code, _, _) = common::assert_business_envelope(&result);
    assert_eq!(code, "mpp.signing_failed");
    assert_eq!(
        fixture
            .signed_requests
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "nothing signed reached the RPC"
    );
    let row = withheld_row(&fixture.profile);
    assert_eq!(row["failure_stage"], "signing");
    assert_eq!(row["key_access_began"], true);
}

/// A failure at the send records `resimulation`: the signed entry reached, or
/// may have reached, the RPC.
#[tokio::test]
#[serial]
async fn mpp_commit_failure_at_the_send_records_resimulation() {
    let fixture = mpp_fixture("mpp-stage-resim", [0x72; 32], true, |r, _| {
        r.failing_signed()
    })
    .await;
    let result = prepare_and_commit(&fixture.server, "mpp-stage-resim", 12).await;
    let (code, _, _) = common::assert_business_envelope(&result);
    assert_eq!(code, "mpp.simulation_failed");
    assert_eq!(
        fixture
            .signed_requests
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    let row = withheld_row(&fixture.profile);
    assert_eq!(row["failure_stage"], "resimulation");
    assert_eq!(row["key_access_began"], true);
}

/// A failure before the sign call records `pre_signing` with no key access.
///
/// The charge was prepared for one payer and is committed by a server whose
/// profile names another: the payer check refuses before the sign call.
#[tokio::test]
#[serial]
async fn mpp_commit_failure_before_the_sign_call_records_pre_signing() {
    let fixture = mpp_fixture("mpp-stage-pre", [0x73; 32], true, |r, _| r).await;
    let prepared = fixture
        .server
        .call_stellar_mpp_charge_prepare("mpp-stage-pre".to_owned(), challenge(13))
        .await
        .expect("prepare");
    assert_ne!(prepared.is_error, Some(true), "{}", result_json(&prepared));
    let prepared = result_json(&prepared);
    let data = &prepared["data"];

    // The same profile, the same audit log and state, another signer.
    let mut other = fixture.profile.clone();
    other.mcp_signer_default.account = gstrkey_for_seed([0x74; 32]);
    assert_ne!(other.mcp_signer_default.account, fixture.payer);
    let committing = WalletServer::new(other).expect("WalletServer::new");
    let result = committing
        .call_stellar_mpp_charge_commit(
            data["authorization"]["authorization_id"]
                .as_str()
                .expect("authorization_id")
                .to_owned(),
            data["nonce"].as_str().expect("nonce").to_owned(),
            data["nonce_expires_at_unix_ms"].as_u64().expect("expiry"),
        )
        .await
        .expect("commit");
    let (code, _, _) = common::assert_business_envelope(&result);
    assert_eq!(code, "mpp.signing_failed");
    assert_eq!(
        fixture
            .signed_requests
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    let row = withheld_row(&fixture.profile);
    assert_eq!(row["failure_stage"], "pre_signing");
    assert_eq!(row["key_access_began"], false);
}

/// A withheld row that cannot be written is logged at `error` with its code,
/// and the commit still answers with its primary error.
#[tokio::test]
#[serial]
async fn mpp_withheld_row_write_failure_is_logged_and_the_primary_error_returned() {
    use stellar_agent_test_support::CaptureWriter;

    let fixture = mpp_fixture("mpp-stage-logged", [0x75; 32], true, |r, profile| {
        let path = profile.audit_log_path.clone();
        r.failing_signed().on_signed(std::sync::Arc::new(move || {
            // Roll the log back so the withheld row's strict write refuses.
            std::fs::write(&path, b"").expect("truncate the audit log");
        }))
    })
    .await;
    // Anchor a non-empty log first, so the rollback is a mismatch.
    let anchor_row = stellar_agent_core::audit_log::AuditEntry::new_tool_invocation(
        stellar_agent_core::audit_log::NewToolInvocation::new(
            "test",
            "stellar:testnet",
            vec![],
            stellar_agent_core::audit_log::PolicyDecision::Allow,
            "anchor-row",
        ),
    );
    let access = stellar_agent_network::keyring::keyed_audit_access(
        &fixture.profile,
        "mpp-stage-logged",
        stellar_agent_core::audit_log::BindingCheck::Enforce,
    )
    .expect("audit access");
    stellar_agent_core::audit_log::AuditWriterRegistry::get_or_open_keyed(
        "mpp-stage-logged",
        &fixture.profile.audit_log_path,
        access,
    )
    .expect("writer")
    .lock()
    .expect("writer lock")
    .write_entry(anchor_row)
    .expect("anchor row");

    let capture = CaptureWriter::new();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(capture.clone())
        .with_ansi(false)
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);
    tracing::callsite::rebuild_interest_cache();
    let result = prepare_and_commit(&fixture.server, "mpp-stage-logged", 14).await;
    drop(guard);

    let (code, _, _) = common::assert_business_envelope(&result);
    assert_eq!(
        code, "mpp.simulation_failed",
        "the primary error is returned"
    );
    let logs = capture.captured_str();
    let line = logs
        .lines()
        .find(|line| line.contains("mpp_authorization_withheld"))
        .unwrap_or_else(|| panic!("the refused withheld row must be logged: {logs}"));
    assert!(line.contains("ERROR"), "logged at error: {line}");
    assert!(
        line.contains("audit.tip_anchor_mismatch"),
        "the log names the refusal's code: {line}"
    );
    assert!(line.contains("resimulation"), "and the stage: {line}");
}

/// A policy denial at the commit's dispatch gate answers its policy code even
/// when the profile has no audit key: the audit acquisition comes after it.
#[tokio::test]
#[serial]
async fn mpp_policy_denial_without_an_audit_key_answers_the_policy_code() {
    let mut fixture = mpp_fixture("mpp-stage-deny", [0x76; 32], true, |r, _| r).await;
    let prepared = fixture
        .server
        .call_stellar_mpp_charge_prepare("mpp-stage-deny".to_owned(), challenge(15))
        .await
        .expect("prepare");
    assert_ne!(prepared.is_error, Some(true), "{}", result_json(&prepared));
    let prepared = result_json(&prepared);
    let data = &prepared["data"];
    let coord = &fixture.profile.audit_log_hash_chain_key_id;
    keyring_core::Entry::new(&coord.service, &coord.account)
        .expect("Entry::new")
        .delete_credential()
        .expect("remove the audit key");
    fixture
        .server
        .set_policy_engine_for_test(std::sync::Arc::new(
            common::policy_mock::MockPolicyEngine::deny_no_matching_rule(),
        ));
    let result = fixture
        .server
        .call_stellar_mpp_charge_commit(
            data["authorization"]["authorization_id"]
                .as_str()
                .expect("authorization_id")
                .to_owned(),
            data["nonce"].as_str().expect("nonce").to_owned(),
            data["nonce_expires_at_unix_ms"].as_u64().expect("expiry"),
        )
        .await;
    let result = match result {
        Ok(result) => result,
        Err(error) => panic!("the denial is a business envelope, got {error:?}"),
    };
    let (code, _, _) = common::assert_business_envelope(&result);
    assert_eq!(code, "policy.deny.no_matching_rule");
}

// ── A consent row queued beside the running server ───────────────────────────

/// A consent row `stellar-agent approve` queued while this server held the
/// writer is in the log before the signed entry leaves the wallet.
///
/// The writer is cached in-process by an earlier keyed call. The row is queued
/// in the outbox and the attestation persisted after it. The commit's own
/// acquisition, after it reads the approval, drains the row. The mock's handler
/// for the signed re-simulation refuses unless the row is in the log.
#[tokio::test]
#[serial]
async fn mpp_commit_drains_a_queued_consent_row_before_the_signed_resimulation() {
    use stellar_agent_core::approval::{
        AttestationBinding, ConsentAudit, PendingApprovalStore, Surface, attest_and_persist,
    };
    use stellar_agent_core::audit_log::{AuditOutbox, AuditWriterRegistry};

    const NAME: &str = "mpp-consent-drain";
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen_in_handler = std::sync::Arc::clone(&seen);
    let mut fixture = mpp_fixture(NAME, [0x77; 32], true, |r, profile| {
        let path = profile.audit_log_path.clone();
        r.on_signed(std::sync::Arc::new(move || {
            let log = std::fs::read_to_string(&path).unwrap_or_default();
            seen_in_handler
                .lock()
                .unwrap()
                .push(log.contains(r#""kind":"approval_attested""#));
        }))
    })
    .await;
    let approvals = tempfile::tempdir().expect("approvals dir");
    fixture
        .server
        .set_approval_dir_for_test(approvals.path().to_path_buf());
    fixture
        .server
        .set_policy_engine_for_test(std::sync::Arc::new(
            common::policy_mock::MockPolicyEngine::require_approval(),
        ));
    let attestation_key = [0x5a_u8; 32];
    keyring_core::Entry::new(
        &fixture.profile.attestation_key_id.service,
        &fixture.profile.attestation_key_id.account,
    )
    .expect("Entry::new")
    .set_password(&URL_SAFE_NO_PAD.encode(attestation_key))
    .expect("seed attestation key");

    let prepared = fixture
        .server
        .call_stellar_mpp_charge_prepare(NAME.to_owned(), challenge(16))
        .await
        .expect("prepare");
    assert_ne!(prepared.is_error, Some(true), "{}", result_json(&prepared));
    let prepared = result_json(&prepared);
    let data = &prepared["data"];
    let approval_id = data["authorization"]["approval_id"]
        .as_str()
        .expect("the charge requires approval")
        .to_owned();

    // An earlier keyed call caches the writer in this process.
    let access = stellar_agent_network::keyring::keyed_audit_access(
        &fixture.profile,
        NAME,
        stellar_agent_core::audit_log::BindingCheck::Enforce,
    )
    .expect("access");
    let _cached =
        AuditWriterRegistry::get_or_open_keyed(NAME, &fixture.profile.audit_log_path, access)
            .expect("writer cached");

    // `approve --id` beside this server: queue the row, then persist.
    let store_path = approvals.path().join(format!("{NAME}.toml"));
    let mut store = PendingApprovalStore::open(store_path).expect("approval store");
    let entry = store.get(&approval_id).expect("pending entry").clone();
    let outbox = AuditOutbox::for_log(&fixture.profile.audit_log_path);
    attest_and_persist(
        &mut store,
        &entry,
        &attestation_key,
        &AttestationBinding::new(NAME, "stellar:testnet"),
        Surface::Cli,
        ConsentAudit::Outbox(&outbox),
        None,
        |_, _| Err("no grant".to_owned()),
    )
    .expect("approve");
    drop(store);
    assert!(
        !std::fs::read_to_string(&fixture.profile.audit_log_path)
            .unwrap_or_default()
            .contains(r#""kind":"approval_attested""#),
        "the row is queued, not yet in the log"
    );

    let result = fixture
        .server
        .call_stellar_mpp_charge_commit(
            data["authorization"]["authorization_id"]
                .as_str()
                .expect("authorization_id")
                .to_owned(),
            data["nonce"].as_str().expect("nonce").to_owned(),
            data["nonce_expires_at_unix_ms"].as_u64().expect("expiry"),
        )
        .await
        .expect("commit");
    assert_ne!(result.is_error, Some(true), "{}", result_json(&result));
    assert_eq!(
        *seen.lock().unwrap(),
        vec![true],
        "the consent row must be in the log when the signed entry reaches the RPC"
    );
}
