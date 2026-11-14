//! Recovery evidence through independent RPC endpoints.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration assertions"
)]

use serde_json::{Value, json};
use serial_test::serial;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use stellar_agent_core::audit_log::tip_anchor::InMemoryTipAnchorStore;
use stellar_agent_core::audit_log::{AuditWriter, KeyedAuditAccess, TipAnchorStore};
use stellar_agent_core::mainnet::decision::AuthorityScope;
use stellar_agent_core::policy::pin::{self, Pin, PinScope};
use stellar_agent_core::policy::state_lock::WindowStoreLock;
use stellar_agent_core::policy::v1::criteria::state_store::{StateKey, WindowEntry, WindowLimit};
use stellar_agent_core::profile::caip2::{Caip2, MAINNET_PASSPHRASE};
use stellar_agent_core::profile::receipt::{
    AttemptRef, BeginSubmissionOutcome, ReceiptStore, SequenceReleases,
};
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_network::StellarRpcClient;
use stellar_agent_network::mainnet::MainnetConsumer;
use stellar_agent_network::mainnet::clock::{TestClockGuard, set_now_ms_for_test};
use stellar_agent_network::mainnet::digest::BindingFacts;
use stellar_agent_network::policy_state::ledger::MintAuthority;
use stellar_agent_network::policy_state::*;
use stellar_agent_test_support::signed_envelope::{account_id_for_seed, get_network_result};
use stellar_agent_test_support::{EchoIdResponder, keyring_mock, rpc_request_count};
use wiremock::matchers::{body_partial_json, method};
use wiremock::{Mock, MockServer, Respond, ResponseTemplate};

const NOW: u64 = 1_800_000_000_000;

struct Fixture {
    _dir: tempfile::TempDir,
    _clock: TestClockGuard,
    profile: Profile,
    window: PersistedWindowStore,
    writer: Arc<Mutex<AuditWriter>>,
    receipts: ReceiptStore,
    id: OperationId,
    source: String,
}

impl Fixture {
    fn new(max_time: u64) -> Self {
        keyring_mock::install().unwrap();
        let clock = set_now_ms_for_test(NOW);
        let dir = tempfile::TempDir::new().unwrap();
        let source = account_id_for_seed([1; 32]);
        let mut profile = Profile::builder_mainnet_named(
            "recovery",
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
        let opened = OperationRecorder::new(&window, &profile, &mut audit, "request")
            .open(&OpenRequest {
                business_id: BusinessId::parse("recovery-1").unwrap(),
                tool: OperationTool::CliPay,
                kind: OperationKind::Pay,
                intent: IntentSlot::Canonical {
                    intent_digest: [1; 32],
                    intent: json!({"op":"pay"}),
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
                unsigned_envelope_sha256: [1; 32],
                tx_hash: [3; 32],
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
                StateKey::new("recovery", 0, "native", 86_400),
                NOW,
                100,
                WindowLimit::Amount {
                    asset: "native".to_owned(),
                    window: "1d".to_owned(),
                    max_stroops: 1_000,
                },
            )],
            parent: None,
            operation: None,
            native_reservation: None,
        };
        let started = OperationRecorder::new(&window, &profile, &mut audit, "request")
            .begin_attempt(
                &handle,
                &AttemptRequest {
                    envelope: Some(AttemptEnvelope {
                        xdr: "AAAA".to_owned(),
                        unsigned_envelope_sha256: [1; 32],
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
                    envelope_sha256: [2; 32],
                    tx_hash: [3; 32],
                    sequence: 7,
                    max_time,
                    receipt: "02".repeat(32),
                },
                None,
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
        let receipts = ReceiptStore::open_at(dir.path(), "recovery").unwrap();
        receipts
            .begin_submission(&"02".repeat(32), &"03".repeat(32), &source, 7, max_time, 1)
            .unwrap();
        Self {
            _dir: dir,
            _clock: clock,
            profile,
            window,
            writer: Arc::new(Mutex::new(audit)),
            receipts,
            id: handle.id(),
            source,
        }
    }

    fn wire(&self) -> Value {
        let bytes = std::fs::read(self.window.path()).unwrap();
        serde_json::from_slice(&bytes[32..]).unwrap()
    }

    fn record(&self) -> Value {
        self.wire()["operations"]["records"][0].clone()
    }

    async fn run(&self, endpoints: &Endpoints) -> RecoveryReport {
        let primary = StellarRpcClient::new(&endpoints.primary.uri()).unwrap();
        let oracle = StellarRpcClient::new(&endpoints.oracle.uri()).unwrap();
        recover_sequences(
            &self.window,
            &self.profile,
            EndpointPair::from_clients(&primary, Some(&oracle)),
            &self.writer,
            None,
        )
        .await
        .unwrap()
    }
}

struct Endpoints {
    primary: MockServer,
    oracle: MockServer,
    primary_history: Arc<AtomicBool>,
    oracle_history: Arc<AtomicBool>,
}

async fn endpoint(ledger: u32, close: u64, history: Arc<AtomicBool>) -> MockServer {
    let server = MockServer::start().await;
    for (name, answer) in [
        ("getNetwork", get_network_result(MAINNET_PASSPHRASE)),
        (
            "getHealth",
            json!({"status":"healthy","latestLedger":ledger,"oldestLedger":1,"ledgerRetentionWindow":ledger,"latestLedgerCloseTime":close,"oldestLedgerCloseTime":1}),
        ),
    ] {
        Mock::given(method("POST"))
            .and(body_partial_json(json!({"method":name})))
            .respond_with(EchoIdResponder::new(answer))
            .mount(&server)
            .await;
    }
    Mock::given(method("POST")).and(body_partial_json(json!({"method":"getLedgers"})))
        .respond_with(move |request: &wiremock::Request| {
            let request_body: Value = serde_json::from_slice(&request.body).unwrap();
            if request_body["params"]["pagination"]["limit"] == 1 && !history.load(Ordering::SeqCst) {
                return ResponseTemplate::new(500);
            }
            let start = request_body["params"]["startLedger"].as_u64().unwrap();
            assert!(start > 0 && start <= u64::from(ledger));
            EchoIdResponder::new(json!({
                "latestLedger":ledger,"latestLedgerCloseTime":close.to_string(),"oldestLedger":1,"oldestLedgerCloseTime":1,"cursor":ledger.to_string(),
                "ledgers":[{"sequence":start,"ledgerCloseTime":close.to_string(),"hash":"00".repeat(32),"headerXdr":"","metadataXdr":""}],
            })).respond(request)
        }).mount(&server).await;
    server
}

impl Endpoints {
    async fn new(close: u64) -> Self {
        let primary_history = Arc::new(AtomicBool::new(true));
        let oracle_history = Arc::new(AtomicBool::new(true));
        Self {
            primary: endpoint(12, close, Arc::clone(&primary_history)).await,
            oracle: endpoint(14, close, Arc::clone(&oracle_history)).await,
            primary_history,
            oracle_history,
        }
    }
}

#[tokio::test]
#[serial]
async fn recovery_two_post_expiry_ledgers_release_only_the_sequence() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let fx = Fixture::new(NOW / 1_000 - 1);
    let endpoints = Endpoints::new(NOW / 1_000).await;
    let before = fx.wire();
    let receipt = fx.receipts.all().unwrap();
    let report = fx.run(&endpoints).await;
    assert_eq!(
        report.requests,
        RecoveryRequests {
            attempt: 2,
            shared: 4
        }
    );
    let record = fx.record();
    let proof = record["attempts"][0]["sequence_released"].clone();
    assert_eq!(proof["primary_ledger"], 12);
    assert_eq!(proof["witness_ledger"], 12);
    assert_eq!(proof["min_close_time_ms"], NOW);
    assert_eq!(proof["released_at_ms"], NOW);
    assert!(proof["commit_id"].as_str().is_some());
    assert_eq!(record["state"], "sent_outcome_unknown");
    assert_eq!(fx.wire()["holds"], before["holds"]);
    assert_eq!(fx.wire()["authorizations"], before["authorizations"]);
    assert_eq!(fx.receipts.all().unwrap(), receipt);
    let log = std::fs::read_to_string(&fx.profile.audit_log_path).unwrap();
    assert!(log.contains(proof["commit_id"].as_str().unwrap()));
    let released: Vec<_> = log
        .lines()
        .filter_map(|line| {
            let entry: stellar_agent_core::audit_log::AuditEntry =
                serde_json::from_str(line).unwrap();
            match entry.event_kind {
                stellar_agent_core::audit_log::schema::EventKind::OperationEvidence {
                    sequence_released: true,
                    primary_ledger,
                    witness_ledger,
                    min_close_time_ms,
                    commit_id,
                    ..
                } => Some((primary_ledger, witness_ledger, min_close_time_ms, commit_id)),
                _ => None,
            }
        })
        .collect();
    assert_eq!(
        released,
        vec![(
            Some(12),
            Some(12),
            Some(NOW),
            proof["commit_id"].as_str().unwrap().to_owned()
        )]
    );
    assert!(log.contains("primary_ledger"));
    assert!(log.contains("oracle_ledger"));
    assert_eq!(fx.run(&endpoints).await.requests.attempt, 0);
    assert_eq!(fx.record()["attempts"][0]["sequence_released"], proof);
    assert_eq!(
        OperationStatus::new(&fx.window, &fx.profile)
            .view(&BusinessId::parse("recovery-1").unwrap())
            .unwrap()
            .unwrap()
            .operation_id,
        fx.id
    );
}

#[tokio::test]
#[serial]
async fn recovery_single_endpoint_refuses() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    for primary_fails in [false, true] {
        let fx = Fixture::new(NOW / 1_000 - 1);
        let endpoints = Endpoints::new(NOW / 1_000).await;
        if primary_fails {
            endpoints.primary_history.store(false, Ordering::SeqCst);
        } else {
            endpoints.oracle_history.store(false, Ordering::SeqCst);
        }
        fx.run(&endpoints).await;
        assert!(fx.record()["attempts"][0]["sequence_released"].is_null());
        assert_eq!(fx.record()["state"], "sent_outcome_unknown");
    }
}

#[tokio::test]
#[serial]
async fn recovery_two_not_found_without_coverage_keeps_hold() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let fx = Fixture::new(NOW / 1_000 + 20);
    let endpoints = Endpoints::new(NOW / 1_000).await;
    let before = fx.wire()["holds"].clone();
    fx.run(&endpoints).await;
    assert!(fx.record()["attempts"][0]["sequence_released"].is_null());
    assert_eq!(fx.wire()["holds"], before);
    assert_eq!(
        rpc_request_count(&endpoints.primary, "getTransaction").await,
        0
    );
    assert_eq!(
        rpc_request_count(&endpoints.oracle, "getLedgerEntries").await,
        0
    );
}

#[tokio::test]
#[serial]
async fn recovery_fresh_concurrence_ignores_saved_bounds() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let fx = Fixture::new(NOW / 1_000 - 1);
    let endpoints = Endpoints::new(NOW / 1_000).await;
    endpoints.oracle_history.store(false, Ordering::SeqCst);
    fx.run(&endpoints).await;
    assert_eq!(fx.record()["attempts"][0]["recovery"]["primary_upper"], 12);
    endpoints.primary_history.store(false, Ordering::SeqCst);
    endpoints.oracle_history.store(true, Ordering::SeqCst);
    fx.run(&endpoints).await;
    assert!(fx.record()["attempts"][0]["sequence_released"].is_null());
    endpoints.primary_history.store(true, Ordering::SeqCst);
    fx.run(&endpoints).await;
    assert!(fx.record()["attempts"][0]["sequence_released"].is_object());
}

#[tokio::test]
#[serial]
async fn recovery_receipt_claim_honors_sequence_release() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let fx = Fixture::new(NOW / 1_000 - 1);
    fx.run(&Endpoints::new(NOW / 1_000).await).await;
    let _lock =
        WindowStoreLock::acquire_for(fx.window.path(), &fx.profile.policy_window_state_key_id)
            .unwrap();
    let status = OperationStatus::new(&fx.window, &fx.profile);
    assert!(status.sequence_released(&AttemptRef::EnvelopeHash([2; 32])));
    assert!(matches!(
        fx.receipts
            .begin_submission_releasing(
                &"04".repeat(32),
                &"05".repeat(32),
                &fx.source,
                7,
                0,
                15,
                None,
                &status
            )
            .unwrap(),
        BeginSubmissionOutcome::Recorded
    ));
    assert!(matches!(
        fx.receipts
            .begin_submission_releasing(
                &"06".repeat(32),
                &"07".repeat(32),
                &fx.source,
                7,
                0,
                15,
                None,
                &status
            )
            .unwrap(),
        BeginSubmissionOutcome::DuplicateSequence(_)
    ));
}
