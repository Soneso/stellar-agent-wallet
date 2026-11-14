//! Outcome recovery through the configured endpoint pair.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration assertions"
)]

use serde_json::{Value, json};
use serial_test::serial;
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use stellar_agent_core::audit_log::tip_anchor::InMemoryTipAnchorStore;
use stellar_agent_core::audit_log::{AuditWriter, KeyedAuditAccess, TipAnchorStore};
use stellar_agent_core::mainnet::decision::AuthorityScope;
use stellar_agent_core::policy::pin::{self, Pin, PinScope};
use stellar_agent_core::policy::state_lock::WindowStoreLock;
use stellar_agent_core::policy::v1::criteria::state_store::{StateKey, WindowEntry, WindowLimit};
use stellar_agent_core::profile::caip2::{Caip2, MAINNET_PASSPHRASE};
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_network::StellarRpcClient;
use stellar_agent_network::mainnet::MainnetConsumer;
use stellar_agent_network::mainnet::clock::{TestClockGuard, set_now_ms_for_test};
use stellar_agent_network::mainnet::digest::BindingFacts;
use stellar_agent_network::policy_state::ledger::MintAuthority;
use stellar_agent_network::policy_state::*;
use stellar_agent_test_support::signed_envelope::{account_id_for_seed, get_network_result};
use stellar_agent_test_support::{EchoIdResponder, keyring_mock, rpc_request_count};
use stellar_xdr::WriteXdr;
use wiremock::matchers::{body_partial_json, method};
use wiremock::{Mock, MockServer};

const NOW: u64 = 1_800_000_000_000;

/// A classic envelope with fee cap `fee`, as base64 XDR.
fn envelope_text(fee: u32) -> String {
    stellar_xdr::TransactionEnvelope::Tx(stellar_xdr::TransactionV1Envelope {
        tx: stellar_xdr::Transaction {
            source_account: stellar_xdr::MuxedAccount::Ed25519(stellar_xdr::Uint256([1; 32])),
            fee,
            seq_num: stellar_xdr::SequenceNumber(7),
            cond: stellar_xdr::Preconditions::None,
            memo: stellar_xdr::Memo::None,
            operations: stellar_xdr::VecM::default(),
            ext: stellar_xdr::TransactionExt::V0,
        },
        signatures: stellar_xdr::VecM::default(),
    })
    .to_xdr_base64(stellar_xdr::Limits::none())
    .unwrap()
}

fn result_text(success: bool, fee: i64) -> String {
    stellar_xdr::TransactionResult {
        fee_charged: fee,
        result: if success {
            stellar_xdr::TransactionResultResult::TxSuccess(stellar_xdr::VecM::default())
        } else {
            stellar_xdr::TransactionResultResult::TxFailed(stellar_xdr::VecM::default())
        },
        ext: stellar_xdr::TransactionResultExt::V0,
    }
    .to_xdr_base64(stellar_xdr::Limits::none())
    .unwrap()
}

/// The transaction hash of operation `n`'s exposed attempt.
fn tx_hash(n: u8) -> [u8; 32] {
    [n; 32]
}

struct Fixture {
    _dir: tempfile::TempDir,
    _clock: TestClockGuard,
    profile: Profile,
    window: PersistedWindowStore,
    writer: Arc<Mutex<AuditWriter>>,
}

impl Fixture {
    /// `count` operations, each with one exposed unknown classic attempt of
    /// the fee-100 envelope and a native hold of 100.
    fn new(count: u8) -> Self {
        keyring_mock::install().unwrap();
        let clock = set_now_ms_for_test(NOW);
        let dir = tempfile::TempDir::new().unwrap();
        let source = account_id_for_seed([1; 32]);
        let mut profile = Profile::builder_mainnet_named(
            "outcomes",
            "https://rpc.example",
            "signer",
            &source,
            "nonce",
            "account",
        )
        .build();
        profile.audit_log_path = dir.path().join("audit.jsonl");
        let window = PersistedWindowStore::at_path(dir.path().join("state.window"));
        let lock = WindowStoreLock::acquire_for(window.path(), &profile.policy_window_state_key_id)
            .unwrap();
        pin::write_for_test(
            &lock,
            &PinScope::for_profile(window.path(), &profile),
            &Pin::new(7, [7; 32], [1; 32]).unwrap(),
        )
        .unwrap();
        drop(lock);
        let anchors: Arc<dyn TipAnchorStore> = Arc::new(InMemoryTipAnchorStore::new());
        let mut audit = AuditWriter::open(
            profile.audit_log_path.clone(),
            Some(KeyedAuditAccess::new(
                zeroize::Zeroizing::new([8; 32]),
                anchors,
            )),
        )
        .unwrap();
        for n in 1..=count {
            let opened = OperationRecorder::new(&window, &profile, &mut audit, "request")
                .open(&OpenRequest {
                    business_id: BusinessId::parse(&format!("outcome-{n}")).unwrap(),
                    tool: OperationTool::CliPay,
                    kind: OperationKind::Pay,
                    intent: IntentSlot::Canonical {
                        intent_digest: [n; 32],
                        intent: json!({"op":"pay","n":n}),
                    },
                    envelope_xdr: Some("AAAA".to_owned()),
                    prepared_decision: None,
                    rule_ttl_ms: None,
                })
                .unwrap();
            let OpenOutcome::New(handle) = opened else {
                panic!("new operation required")
            };
            let mint = MintRequest {
                chain: Caip2::Mainnet,
                consumer: MainnetConsumer::CliPay,
                binding: DomainBinding::Transaction {
                    unsigned_envelope_sha256: [n; 32],
                    tx_hash: tx_hash(n),
                    source: source.clone(),
                    sequence: 7,
                },
                policy_sequence: 7,
                policy_digest: [7; 32],
                authority: MintAuthority::Policy(PolicyAuthorityBinding {
                    policy_digest: [7; 32],
                    policy_sequence: 7,
                    rule_index: 0,
                    evaluated_at_ms: NOW,
                    governing_until_ms: NOW + 600_000,
                    scope: AuthorityScope::Classic,
                }),
                chain_deadline_ms: None,
                authorization_ttl_ms: 120_000,
                bindings: BindingFacts {
                    endpoint: None,
                    signer: [2; 32],
                    policy: [3; 32],
                    enablement: [4; 32],
                    witness: None,
                    reservation: None,
                    authority: [7; 32],
                    audit: [8; 32],
                },
                holds: vec![WindowEntry::new(
                    StateKey::new("outcomes", 0, "native", 86_400),
                    NOW,
                    100,
                    WindowLimit::Amount {
                        asset: "native".to_owned(),
                        window: "1d".to_owned(),
                        max_stroops: 10_000,
                    },
                )],
                parent: None,
                operation: None,
                native_reservation: Some(NativeReservation {
                    debit_stroops: 100,
                    fee_stroops: 100,
                }),
            };
            let started = OperationRecorder::new(&window, &profile, &mut audit, "request")
                .begin_attempt(
                    &handle,
                    &AttemptRequest {
                        envelope: Some(AttemptEnvelope {
                            xdr: "AAAA".to_owned(),
                            unsigned_envelope_sha256: [n; 32],
                        }),
                        authorization: AttemptAuthorization::Mint(Box::new(mint.clone())),
                        send_by_ms: NOW + 100_000,
                    },
                )
                .unwrap();
            let minted = started.minted.unwrap();
            recovery::claim_fixture_authorization(&window, &profile, &mint, &minted).unwrap();
            let mut recorder = OperationRecorder::new(&window, &profile, &mut audit, "request");
            recorder
                .expose(
                    handle.id(),
                    1,
                    &ExposureIdentity::Classic {
                        envelope_sha256: Sha256::digest(envelope_text(100)).into(),
                        tx_hash: tx_hash(n),
                        sequence: 7,
                        max_time: NOW / 1_000 + 3_600,
                        receipt: format!("{n:02x}").repeat(32),
                    },
                    Some(1),
                )
                .unwrap();
            recorder
                .transition(
                    handle.id(),
                    Some(1),
                    OperationState::SentOutcomeUnknown,
                    &TransitionEvidence::default(),
                )
                .unwrap();
            clock.set(NOW + u64::from(n));
        }
        Self {
            _dir: dir,
            _clock: clock,
            profile,
            window,
            writer: Arc::new(Mutex::new(audit)),
        }
    }

    fn wire(&self) -> Value {
        let bytes = std::fs::read(self.window.path()).unwrap();
        serde_json::from_slice(&bytes[32..]).unwrap()
    }

    fn records(&self) -> Vec<Value> {
        self.wire()["operations"]["records"]
            .as_array()
            .cloned()
            .unwrap_or_default()
    }

    async fn run(&self, primary: &MockServer, oracle: Option<&MockServer>) -> RecoveryReport {
        let primary = StellarRpcClient::new(&primary.uri()).unwrap();
        let oracle = oracle.map(|server| StellarRpcClient::new(&server.uri()).unwrap());
        recover_outcomes(
            &self.window,
            &self.profile,
            EndpointPair::from_clients(&primary, oracle.as_ref()),
            &self.writer,
            None,
        )
        .await
        .unwrap()
    }
}

/// An endpoint at `ledger` whose `getTransaction` answers `transaction`.
async fn endpoint(ledger: u32, transaction: Value) -> MockServer {
    let server = MockServer::start().await;
    let close = (NOW / 1_000).to_string();
    for (name, answer) in [
        ("getNetwork", get_network_result(MAINNET_PASSPHRASE)),
        (
            "getHealth",
            json!({"status":"healthy","latestLedger":ledger,"oldestLedger":1,"ledgerRetentionWindow":ledger,"latestLedgerCloseTime":close,"oldestLedgerCloseTime":1}),
        ),
        (
            "getLedgers",
            json!({
                "latestLedger":ledger,"latestLedgerCloseTime":close,"oldestLedger":1,
                "oldestLedgerCloseTime":1,"cursor":ledger.to_string(),
                "ledgers":[{"sequence":ledger,"ledgerCloseTime":close,"hash":"00".repeat(32),"headerXdr":"","metadataXdr":""}],
            }),
        ),
        ("getTransaction", transaction),
    ] {
        Mock::given(method("POST"))
            .and(body_partial_json(json!({"method":name})))
            .respond_with(EchoIdResponder::new(answer))
            .mount(&server)
            .await;
    }
    server
}

/// Answers `getTransaction` with a valid success for the requested hash,
/// after `delay`.
struct Inclusion {
    delay: std::time::Duration,
}

impl wiremock::Respond for Inclusion {
    fn respond(&self, request: &wiremock::Request) -> wiremock::ResponseTemplate {
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        let mut answer = included("SUCCESS", envelope_text(100), result_text(true, 70));
        answer["txHash"] = body["params"]["hash"].clone();
        wiremock::ResponseTemplate::new(200)
            .set_body_json(json!({"jsonrpc":"2.0","id":body["id"],"result":answer}))
            .set_delay(self.delay)
    }
}

/// An endpoint at `ledger` that answers every transaction as included after
/// `delay`.
async fn including(ledger: u32, delay: std::time::Duration) -> MockServer {
    let server = MockServer::start().await;
    let close = (NOW / 1_000).to_string();
    for (name, answer) in [
        ("getNetwork", get_network_result(MAINNET_PASSPHRASE)),
        (
            "getHealth",
            json!({"status":"healthy","latestLedger":ledger,"oldestLedger":1,"ledgerRetentionWindow":ledger,"latestLedgerCloseTime":close,"oldestLedgerCloseTime":1}),
        ),
        (
            "getLedgers",
            json!({
                "latestLedger":ledger,"latestLedgerCloseTime":close,"oldestLedger":1,
                "oldestLedgerCloseTime":1,"cursor":ledger.to_string(),
                "ledgers":[{"sequence":ledger,"ledgerCloseTime":close,"hash":"00".repeat(32),"headerXdr":"","metadataXdr":""}],
            }),
        ),
    ] {
        Mock::given(method("POST"))
            .and(body_partial_json(json!({"method":name})))
            .respond_with(EchoIdResponder::new(answer))
            .mount(&server)
            .await;
    }
    Mock::given(method("POST"))
        .and(body_partial_json(json!({"method":"getTransaction"})))
        .respond_with(Inclusion { delay })
        .mount(&server)
        .await;
    server
}

/// An endpoint at `ledger` whose transaction reads fail in transport.
async fn transaction_unreachable(ledger: u32) -> MockServer {
    let server = including(ledger, std::time::Duration::ZERO).await;
    server.reset().await;
    let close = (NOW / 1_000).to_string();
    for (name, answer) in [
        ("getNetwork", get_network_result(MAINNET_PASSPHRASE)),
        (
            "getHealth",
            json!({"status":"healthy","latestLedger":ledger,"oldestLedger":1,"ledgerRetentionWindow":ledger,"latestLedgerCloseTime":close,"oldestLedgerCloseTime":1}),
        ),
        (
            "getLedgers",
            json!({
                "latestLedger":ledger,"latestLedgerCloseTime":close,"oldestLedger":1,
                "oldestLedgerCloseTime":1,"cursor":ledger.to_string(),
                "ledgers":[{"sequence":ledger,"ledgerCloseTime":close,"hash":"00".repeat(32),"headerXdr":"","metadataXdr":""}],
            }),
        ),
    ] {
        Mock::given(method("POST"))
            .and(body_partial_json(json!({"method":name})))
            .respond_with(EchoIdResponder::new(answer))
            .mount(&server)
            .await;
    }
    Mock::given(method("POST"))
        .and(body_partial_json(json!({"method":"getTransaction"})))
        .respond_with(wiremock::ResponseTemplate::new(500))
        .mount(&server)
        .await;
    server
}

/// A transport failure of the oracle's transaction read keeps the
/// primary's successfully read answer as evidence and in the diagnostic,
/// and decides nothing.
#[tokio::test]
#[serial]
async fn recovery_partial_transaction_evidence_is_kept_without_a_decision() {
    let fx = Fixture::new(1);
    let primary = including(60, std::time::Duration::ZERO).await;
    let oracle = transaction_unreachable(61).await;
    let report = fx.run(&primary, Some(&oracle)).await;
    assert_eq!(report.evaluated, 1, "{report:?}");
    let record = &fx.records()[0];
    assert_eq!(record["state"], "sent_outcome_unknown", "{record}");
    let attempt = &record["attempts"][0];
    assert!(attempt["decision"].is_null(), "{record}");
    let outcomes: Vec<&Value> = attempt["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| !row["answer"]["outcome"].is_null())
        .collect();
    assert_eq!(outcomes.len(), 1, "{record}");
    assert_eq!(outcomes[0]["endpoint"], "primary");
    assert_eq!(
        outcomes[0]["answer"]["outcome"]["status"]["text"],
        "SUCCESS"
    );
    assert_eq!(
        attempt["recovery"]["diagnostic"]["text"],
        "endpoint_unreachable"
    );
}

/// Two attempts decided in one pass both commit: each decision binds the
/// generation of a fresh verified read, never the pass's first snapshot.
#[tokio::test]
#[serial]
async fn recovery_decisions_of_one_pass_bind_fresh_generations() {
    let fx = Fixture::new(2);
    let primary = including(60, std::time::Duration::ZERO).await;
    let oracle = including(61, std::time::Duration::ZERO).await;
    let report = fx.run(&primary, Some(&oracle)).await;
    assert_eq!(report.evaluated, 2, "{report:?}");
    for record in fx.records() {
        assert_eq!(record["state"], "succeeded", "{record}");
    }
}

/// An oracle whose transaction answer arrives after the pass deadline ends
/// the pass at the deadline, and the interrupted attempt keeps its state.
#[tokio::test]
#[serial]
async fn recovery_pass_ends_at_its_deadline_and_leaves_the_interrupted_attempt() {
    let fx = Fixture::new(1);
    let before = fx.records();
    let primary = including(60, std::time::Duration::ZERO).await;
    let oracle = including(61, std::time::Duration::from_secs(40)).await;
    let started = std::time::Instant::now();
    let report = fx.run(&primary, Some(&oracle)).await;
    let elapsed = started.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(25),
        "the pass ends at its 20-second deadline: {elapsed:?}"
    );
    assert_eq!(report.evaluated, 0, "{report:?}");
    assert_eq!(fx.records(), before, "the interrupted attempt is unchanged");
}

fn included(status: &str, envelope: impl Into<Value>, result: impl Into<Value>) -> Value {
    let (envelope, result) = (envelope.into(), result.into());
    json!({
        "status": status, "ledger": 40, "createdAt": "1799999990",
        "txHash": stellar_agent_core::hex::encode(&tx_hash(1)),
        "envelopeXdr": envelope, "resultXdr": result,
        "latestLedger": 60, "oldestLedger": 1,
    })
}

/// Only concurrence of the configured pair in one pass decides. The oracle
/// missing, a single endpoint's success, or a lagging absence leave the
/// attempt unknown, and each pass reads each identity once.
#[tokio::test]
#[serial]
async fn recovery_outcome_requires_the_configured_pair_in_one_pass() {
    let success = included("SUCCESS", envelope_text(100), result_text(true, 70));
    let fx = Fixture::new(1);
    let primary = endpoint(60, success.clone()).await;
    let report = fx.run(&primary, None).await;
    assert_eq!(report.evaluated, 0);
    assert_eq!(fx.records()[0]["state"], "sent_outcome_unknown");

    let lagging = endpoint(
        30,
        json!({"status":"NOT_FOUND","latestLedger":30,"oldestLedger":1}),
    )
    .await;
    fx.run(&primary, Some(&lagging)).await;
    assert_eq!(fx.records()[0]["state"], "sent_outcome_unknown");
    assert!(fx.records()[0]["attempts"][0]["decision"].is_null());

    let oracle = endpoint(61, success).await;
    let before = rpc_request_count(&primary, "getNetwork").await;
    let report = fx.run(&primary, Some(&oracle)).await;
    assert_eq!(report.evaluated, 1, "{report:?}");
    let record = &fx.records()[0];
    assert_eq!(record["state"], "succeeded", "{record}");
    assert!(record["attempts"][0]["decision"]["evidence_digest"].is_string());
    assert_eq!(rpc_request_count(&primary, "getNetwork").await - before, 1);
    assert_eq!(rpc_request_count(&oracle, "getNetwork").await, 1);
    let wire = fx.wire();
    let native: Vec<&Value> = wire["authorizations"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|auth| !auth["native_release"].is_null())
        .collect();
    assert_eq!(native.len(), 1);
    assert_eq!(native[0]["native_release"]["class"], "settled");
}

/// An agreed inclusion of another envelope at the attempt's hash closes
/// nothing and counts one disagreement.
#[tokio::test]
#[serial]
async fn recovery_consumed_sequence_without_original_envelope_stays_unknown() {
    let other = included("SUCCESS", envelope_text(101), result_text(true, 70));
    let fx = Fixture::new(1);
    let primary = endpoint(60, other.clone()).await;
    let oracle = endpoint(61, other).await;
    fx.run(&primary, Some(&oracle)).await;
    let record = &fx.records()[0];
    assert_eq!(record["state"], "sent_outcome_unknown", "{record}");
    assert!(record["attempts"][0]["decision"].is_null());
    assert_eq!(record["attempts"][0]["recovery"]["disagreements"], 1);
    assert_eq!(
        record["attempts"][0]["recovery"]["diagnostic"]["text"],
        "envelope_mismatch"
    );
    assert!(record["attempts"][0]["sequence_released"].is_null());
}

/// Five eligible attempts take four slots; the pass stays within its
/// separate 24 attempt and nine shared requests and sends no transaction
/// read twice.
#[tokio::test]
#[serial]
async fn recovery_combined_pass_limits_attempts_requests_refresh_and_deadline() {
    let fx = Fixture::new(5);
    let absent = json!({"status":"NOT_FOUND","latestLedger":60,"oldestLedger":1});
    let primary = endpoint(60, absent.clone()).await;
    let oracle = endpoint(61, absent).await;
    let started = std::time::Instant::now();
    let report = fx.run(&primary, Some(&oracle)).await;
    assert!(started.elapsed() < std::time::Duration::from_secs(20));
    assert_eq!(report.evaluated, 4);
    assert!(report.requests.attempt <= 24, "{report:?}");
    assert!(report.requests.shared <= 9, "{report:?}");
    assert!(report.requests.attempt + report.requests.shared <= 33);
    for server in [&primary, &oracle] {
        assert_eq!(rpc_request_count(server, "getTransaction").await, 4);
        assert_eq!(rpc_request_count(server, "getNetwork").await, 1);
    }
    let sent = primary.received_requests().await.unwrap().len()
        + oracle.received_requests().await.unwrap().len();
    assert_eq!(sent, report.requests.attempt + report.requests.shared);
}

/// The mainnet legacy stage settles nothing on a primary success or any
/// other answer and sends no request; recovery owns the decision.
#[tokio::test]
#[serial]
async fn recovery_mainnet_legacy_stage_settles_nothing_and_testnet_is_unchanged() {
    for answer in [
        included("SUCCESS", envelope_text(100), result_text(true, 70)),
        included("FAILED", envelope_text(100), result_text(false, 70)),
        json!({"status":"NOT_FOUND","latestLedger":60,"oldestLedger":1}),
    ] {
        let fx = Fixture::new(0);
        let source = account_id_for_seed([1; 32]);
        let hold = SubmissionHold {
            chain_scope: ChainScope::for_chain(fx.profile.chain_id),
            id: "b5".repeat(32),
            tx_hash: "b5".repeat(32),
            source,
            sequence: 5,
            max_time: NOW / 1_000 - 10,
            pending_since_ms: NOW - RECONCILE_MIN_AGE_MS,
            submission_ledger: 1,
            submission_anchor: None,
            operator_required: false,
        };
        fx.window
            .record_pending(
                &fx.profile,
                &[WindowEntry::new(
                    StateKey::new("outcomes", 0, "native", 86_400),
                    NOW,
                    500,
                    WindowLimit::Amount {
                        asset: "native".to_owned(),
                        window: "1d".to_owned(),
                        max_stroops: 10_000,
                    },
                )],
                &hold,
            )
            .unwrap();
        let primary = endpoint(60, answer.clone()).await;
        let oracle = endpoint(61, answer).await;
        let primary_client = StellarRpcClient::new(&primary.uri()).unwrap();
        let oracle_client = StellarRpcClient::new(&oracle.uri()).unwrap();
        let report = fx
            .window
            .reconcile_due(
                &fx.profile,
                &primary_client,
                Some(&oracle_client),
                None,
                NOW,
                RECONCILE_BUDGET,
            )
            .await
            .unwrap();
        assert_eq!(report.kept_pending, 1, "{report:?}");
        assert_eq!(report.confirmed, 0, "{report:?}");
        assert_eq!(report.rpc_calls, 0, "{report:?}");
        assert!(report.settled.is_empty());
        assert_eq!(
            fx.window.pending_reservations(&fx.profile).unwrap().len(),
            1
        );
        assert!(primary.received_requests().await.unwrap().is_empty());
        assert!(oracle.received_requests().await.unwrap().is_empty());
    }

    // A testnet profile keeps the legacy stage: its primary's success
    // confirms the reservation with one charged read.
    keyring_mock::install().unwrap();
    let _clock = set_now_ms_for_test(NOW);
    let dir = tempfile::TempDir::new().unwrap();
    let profile =
        Profile::builder_testnet_named("outcomes-testnet", "signer", "account", "nonce", "account")
            .build();
    let window = PersistedWindowStore::at_path(dir.path().join("testnet.window"));
    let hold = SubmissionHold {
        chain_scope: ChainScope::for_chain(profile.chain_id),
        id: "e5".repeat(32),
        tx_hash: "e5".repeat(32),
        source: account_id_for_seed([1; 32]),
        sequence: 5,
        max_time: 0,
        pending_since_ms: NOW - RECONCILE_MIN_AGE_MS,
        submission_ledger: 1,
        submission_anchor: None,
        operator_required: false,
    };
    window
        .record_pending(
            &profile,
            &[WindowEntry::new(
                StateKey::new("outcomes-testnet", 0, "native", 86_400),
                NOW,
                500,
                WindowLimit::Amount {
                    asset: "native".to_owned(),
                    window: "1d".to_owned(),
                    max_stroops: 10_000,
                },
            )],
            &hold,
        )
        .unwrap();
    let primary = endpoint(
        60,
        included("SUCCESS", envelope_text(100), result_text(true, 70)),
    )
    .await;
    let report = window
        .reconcile_due(
            &profile,
            &StellarRpcClient::new(&primary.uri()).unwrap(),
            None,
            None,
            NOW,
            RECONCILE_BUDGET,
        )
        .await
        .unwrap();
    assert_eq!(report.confirmed, 1, "{report:?}");
    assert_eq!(report.rpc_calls, 1, "{report:?}");
    assert_eq!(rpc_request_count(&primary, "getTransaction").await, 1);
}
