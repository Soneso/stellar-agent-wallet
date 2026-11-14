//! The refusals before the send that no deadline decides, and the record a
//! bound signed intent keeps when its send-by instant passes.
//!
//! A read that fails for a reason other than time keeps its own code: the
//! endpoint serves another network, refuses the credential, or holds no
//! source account. Nothing is sent and nothing is recorded. A bound signed
//! intent whose record outlasts its send-by instant is reported as rejected,
//! and its receipt, its pending audit row and its reservation stand.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration test; panics/unwraps acceptable"
)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::json;
use serial_test::serial;
use stellar_agent_core::audit_log::AuditWriter;
use stellar_agent_core::audit_log::schema::EventKind;
use stellar_agent_core::audit_log::test_helpers::verified_audit_entries;
use stellar_agent_core::audit_log::tip_anchor::{
    InMemoryTipAnchorStore, KeyedAuditAccess, TipAnchorStore,
};
use stellar_agent_core::error::WalletError;
use stellar_agent_core::policy::v1::criteria::state_store::{StateKey, WindowEntry, WindowLimit};
use stellar_agent_core::profile::receipt::{ReceiptStatus, ReceiptStore};
use stellar_agent_core::profile::schema::{KeyringEntryRef, Profile};
use stellar_agent_network::policy_state::PersistedWindowStore;
use stellar_agent_network::{
    IntentBinding, PreSendStage, SentByError, StellarRpcClient, SubmissionIntent,
    SubmissionOutcome, SubmissionRecorder, WalletSubmissionRecorder, envelope_hash_hex,
    submit_transaction_and_wait, submit_transaction_and_wait_sent_by,
};
use stellar_agent_test_support::keyring_mock;
use stellar_agent_test_support::signed_envelope::{
    SignedTestEnvelope, TESTNET_PASSPHRASE, get_network_result,
};
use stellar_agent_test_support::{EchoIdResponder, rpc_request_count};
use tempfile::TempDir;
use wiremock::matchers::{body_partial_json, method};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// The submission's own timeout: far beyond every answer these endpoints
/// give.
const TIMEOUT: Duration = Duration::from_secs(30);

/// A recorder that counts its pre-send records and keeps every outcome.
#[derive(Default)]
struct Counting {
    pre_sends: Mutex<usize>,
    outcomes: Mutex<Vec<SubmissionOutcome>>,
}

#[async_trait::async_trait]
impl SubmissionRecorder for Counting {
    async fn pre_send(&self, _intent: &SubmissionIntent) -> Result<(), WalletError> {
        *self.pre_sends.lock().unwrap() += 1;
        Ok(())
    }

    async fn outcome(&self, _intent: &SubmissionIntent, outcome: &SubmissionOutcome) {
        self.outcomes.lock().unwrap().push(outcome.clone());
    }
}

/// Mounts one answer for `rpc_method`.
async fn mount(server: &MockServer, rpc_method: &str, answer: impl wiremock::Respond + 'static) {
    Mock::given(method("POST"))
        .and(body_partial_json(json!({ "method": rpc_method })))
        .respond_with(answer)
        .mount(server)
        .await;
}

/// Mounts a `sendTransaction` answer that must never be asked for.
async fn mount_no_send(server: &MockServer) {
    Mock::given(method("POST"))
        .and(body_partial_json(json!({ "method": "sendTransaction" })))
        .respond_with(EchoIdResponder::new(json!({ "status": "PENDING" })))
        .expect(0)
        .named("nothing is sent")
        .mount(server)
        .await;
}

/// An endpoint on another network, one that refuses the credential, and one
/// that holds no source account each refuse under their own code, before
/// anything is recorded or sent.
#[tokio::test]
async fn read_failures_other_than_time_keep_their_codes() {
    let envelope = SignedTestEnvelope::for_source([0x41; 32]);
    let cases: [(&str, &str); 3] = [
        ("another network", "network.endpoint_network_mismatch"),
        ("a refused credential", "network.rpc_credential_refused"),
        ("a missing source account", "network.account_not_found"),
    ];
    for (case, code) in cases {
        let server = MockServer::start().await;
        match case {
            "another network" => {
                mount(
                    &server,
                    "getNetwork",
                    EchoIdResponder::new(get_network_result("Some Other Network ; 2015")),
                )
                .await;
            }
            "a refused credential" => {
                mount(&server, "getNetwork", ResponseTemplate::new(401)).await;
            }
            _ => {
                mount(
                    &server,
                    "getNetwork",
                    EchoIdResponder::new(get_network_result(TESTNET_PASSPHRASE)),
                )
                .await;
                mount(
                    &server,
                    "getLedgerEntries",
                    EchoIdResponder::new(json!({ "entries": [], "latestLedger": 1000 })),
                )
                .await;
            }
        }
        mount_no_send(&server).await;
        let recorder = Counting::default();
        let client = StellarRpcClient::new(&server.uri()).unwrap();

        let error = submit_transaction_and_wait(
            &client,
            envelope.envelope_xdr(),
            TIMEOUT,
            TESTNET_PASSPHRASE,
            None,
            Some(&recorder),
        )
        .await
        .expect_err(case);

        assert_eq!(error.code(), code, "{case}: {error:?}");
        assert_eq!(
            rpc_request_count(&server, "sendTransaction").await,
            0,
            "{case}: nothing is sent"
        );
        assert_eq!(*recorder.pre_sends.lock().unwrap(), 0, "{case}");
        assert!(
            recorder.outcomes.lock().unwrap().is_empty(),
            "{case}: nothing is recorded"
        );
        server.verify().await;
    }
}

/// How far ahead of the call the bound intent's send-by instant lies.
const SEND_BY: Duration = Duration::from_secs(1);

/// How long the bound record takes after it is written: past [`SEND_BY`].
const RECORD_DELAY: Duration = Duration::from_secs(2);

/// Binds by writing the wallet's plain record, then outlasts the send-by
/// instant; every outcome goes to the wallet's recorder.
struct SlowBinding<'a> {
    inner: WalletSubmissionRecorder<'a>,
    outcomes: Mutex<Vec<SubmissionOutcome>>,
}

#[async_trait::async_trait]
impl SubmissionRecorder for SlowBinding<'_> {
    async fn pre_send(&self, _intent: &SubmissionIntent) -> Result<(), WalletError> {
        panic!("a bound intent records through pre_send_bound")
    }

    async fn pre_send_bound(
        &self,
        intent: &SubmissionIntent,
        _binding: &IntentBinding<'_>,
    ) -> Result<(), WalletError> {
        self.inner.pre_send(intent).await?;
        tokio::time::sleep(RECORD_DELAY).await;
        Ok(())
    }

    async fn outcome(&self, intent: &SubmissionIntent, outcome: &SubmissionOutcome) {
        self.outcomes.lock().unwrap().push(outcome.clone());
        self.inner.outcome(intent, outcome).await;
    }
}

fn now_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

/// A bound signed intent whose record outlasts its send-by instant sends
/// nothing and is reported as rejected: the receipt stays pending, the
/// pending audit row stays open, and the reservation stands.
#[tokio::test]
#[serial]
async fn a_bound_intent_past_send_by_keeps_its_record() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    keyring_mock::install().unwrap();
    let name = "bound-record";
    let dir = TempDir::new().unwrap();
    let testnet_profile = |name: &str| {
        let mut profile = Profile::builder_testnet(name, "acct", "n-svc", "n-acct").build();
        profile.policy_window_state_key_id = KeyringEntryRef::default_policy_window_state_key(name);
        profile
    };
    let mut profile = testnet_profile(name);
    let audit_path = dir.path().join("audit").join("log.jsonl");
    profile.audit_log_path = audit_path.clone();
    let store = Arc::new(InMemoryTipAnchorStore::new());
    let audit = Arc::new(Mutex::new(
        AuditWriter::open(
            audit_path,
            Some(KeyedAuditAccess::new(
                zeroize::Zeroizing::new([0x6b; 32]),
                Arc::clone(&store) as Arc<dyn TipAnchorStore>,
            )),
        )
        .unwrap(),
    ));
    let receipts = ReceiptStore::open_at(&dir.path().join("receipts"), name).unwrap();
    let window = PersistedWindowStore::at_path(dir.path().join(format!("{name}.window")));

    // The exposure of an admitted intent with an identity, admitted in a
    // window and under a profile of its own: the submit layer sees only that
    // it is bound.
    let intent_profile = testnet_profile("intent");
    let intent_window = PersistedWindowStore::at_path(dir.path().join("intent.window"));
    let _clock = stellar_agent_network::mainnet::clock::set_now_ms_for_test(1000);
    let (plan, invocation) =
        stellar_agent_network::signed_intent::test_helpers::intent_fixture_plan(1, 60);
    let stellar_xdr::TransactionEnvelope::Tx(tx) = &invocation else {
        unreachable!()
    };
    let stellar_xdr::OperationBody::InvokeHostFunction(op) = &tx.tx.operations[0].body else {
        unreachable!()
    };
    let plan = plan
        .classify_purpose(&op.host_function, None)
        .unwrap()
        .with_envelope_max_ledger(100)
        .unwrap();
    let exposure = intent_window
        .admit_signed_intent(&intent_profile, &plan)
        .unwrap()
        .expose();
    assert!(exposure.intent_id().is_some(), "the intent is bound");
    drop(_clock);

    let recorder = SlowBinding {
        inner: WalletSubmissionRecorder::new(
            &profile,
            name,
            "stellar_pay_commit",
            Some("stellar:testnet".to_owned()),
            stellar_agent_core::audit_log::PolicyDecision::Allow,
            Vec::new(),
            vec![WindowEntry::new(
                StateKey::new(name, 1, "native", 86_400),
                now_ms(),
                500,
                WindowLimit::Amount {
                    asset: "native".to_owned(),
                    window: "1d".to_owned(),
                    max_stroops: 1_000_000,
                },
            )],
            receipts.clone(),
            window.clone(),
            Some(Arc::clone(&audit)),
            None,
            "test-request",
            now_ms(),
        ),
        outcomes: Mutex::new(Vec::new()),
    };

    let envelope = SignedTestEnvelope::for_source_with_sequence([0x42; 32], 2001);
    let server = MockServer::start().await;
    mount(
        &server,
        "getNetwork",
        EchoIdResponder::new(get_network_result(TESTNET_PASSPHRASE)),
    )
    .await;
    mount(
        &server,
        "getLedgerEntries",
        EchoIdResponder::new(envelope.ledger_entries_result()),
    )
    .await;
    mount_no_send(&server).await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let result = submit_transaction_and_wait_sent_by(
        &client,
        envelope.envelope_xdr(),
        tokio::time::Instant::now() + SEND_BY,
        TIMEOUT,
        TESTNET_PASSPHRASE,
        None,
        Some(&recorder),
        Some(&exposure),
    )
    .await;

    match result {
        Err(SentByError::Elapsed {
            stage: PreSendStage::Send,
            sent_tx_hash: None,
        }) => {}
        other => panic!("expected the send-by refusal before the send, got {other:?}"),
    }
    let outcomes = recorder.outcomes.lock().unwrap().clone();
    let [SubmissionOutcome::Rejected { code, .. }] = outcomes.as_slice() else {
        panic!("one rejected outcome: {outcomes:?}")
    };
    assert_eq!(code, "network.rpc_timeout");

    let hash = envelope_hash_hex(envelope.envelope_xdr());
    let receipt = receipts.get(&hash).unwrap().expect("the receipt stands");
    assert_eq!(receipt.status, ReceiptStatus::Pending);
    let kinds: Vec<EventKind> = verified_audit_entries(&audit)
        .into_iter()
        .filter(|entry| entry.envelope_hash.as_deref() == Some(hash.as_str()))
        .map(|entry| entry.event_kind)
        .collect();
    assert!(
        matches!(kinds.as_slice(), [EventKind::ValueActionPending { .. }]),
        "the pending row stays open: {kinds:?}"
    );
    assert!(
        window
            .pending_reservations(&profile)
            .unwrap()
            .iter()
            .any(|reservation| reservation.id == hash),
        "the reservation stands"
    );
    server.verify().await;
}
