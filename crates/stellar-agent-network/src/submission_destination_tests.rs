struct DestinationRecorderFixture {
    dir: tempfile::TempDir,
    profile: Profile,
    window: PersistedWindowStore,
    receipts: ReceiptStore,
}

impl DestinationRecorderFixture {
    fn new() -> Self {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut profile =
            Profile::builder_testnet_named("destinations", "s", "a", "n", "a").build();
        profile.audit_log_path = dir.path().join("audit.jsonl");
        let window = PersistedWindowStore::at_path(dir.path().join("state.window"));
        let receipts = ReceiptStore::open_at(dir.path(), "destinations").unwrap();
        Self {
            dir,
            profile,
            window,
            receipts,
        }
    }

    fn recorder(&self) -> WalletSubmissionRecorder<'_> {
        use stellar_agent_core::policy::v1::criteria::state_store::{
            StateKey, WindowEntry, WindowLimit,
        };
        WalletSubmissionRecorder::new(
            &self.profile,
            "destinations",
            "stellar_pay",
            Some("stellar:testnet".to_owned()),
            PolicyDecision::Allow,
            vec![],
            vec![WindowEntry::new(
                StateKey::new("destinations", 1, "native", 60),
                1000,
                7,
                WindowLimit::Amount {
                    asset: "native".to_owned(),
                    window: "1m".to_owned(),
                    max_stroops: 100,
                },
            )],
            self.receipts.clone(),
            self.window.clone(),
            None,
            None,
            "request",
            1000,
        )
    }

    fn intent(destinations: PaymentDestinations) -> SubmissionIntent {
        SubmissionIntent {
            chain_scope: crate::policy_state::ChainScope::for_chain(
                stellar_agent_core::profile::caip2::Caip2::Testnet,
            ),
            envelope_hash: "a1".repeat(32),
            tx_hash: "b1".repeat(32),
            source: "GSOURCE".to_owned(),
            sequence: 1,
            max_time: 0,
            submission_ledger: 1000,
            submission_anchor: None,
            send_by_ms: None,
            destinations,
        }
    }
}

#[test]
#[serial_test::serial]
fn the_claim_records_every_destination_shape() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    use crate::submit::destination_tests::*;
    let _clock = crate::mainnet::clock::set_now_ms_for_test(1000);
    for (envelope, expected) in [
        (differing_envelope(), destination_provenance()),
        (
            envelope_for_destinations(vec![
                payment(&muxed_destination(u64::MAX)),
                payment(&muxed_destination(u64::MAX)),
            ]),
            PaymentDestinations::Single(muxed_destination(u64::MAX)),
        ),
    ] {
        let fixture = DestinationRecorderFixture::new();
        let intent =
            DestinationRecorderFixture::intent(crate::submit::payment_destinations(&envelope));
        fixture.recorder().claim_receipt(&intent).unwrap();
        assert_eq!(
            fixture
                .receipts
                .get(&intent.envelope_hash)
                .unwrap()
                .unwrap()
                .destinations,
            expected
        );
    }
}

#[test]
#[serial_test::serial]
fn every_rebuilt_receipt_keeps_its_destination() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let fixture = DestinationRecorderFixture::new();
    let intent = DestinationRecorderFixture::intent(
        crate::submit::destination_tests::destination_provenance(),
    );
    for _ in 0..2 {
        fixture
            .recorder()
            .finalize_receipt(&intent, ReceiptStatus::Success, Some(1001));
        let receipt = fixture
            .receipts
            .get(&intent.envelope_hash)
            .unwrap()
            .unwrap();
        assert_eq!(receipt.destinations, intent.destinations);
        assert_eq!(receipt.status, ReceiptStatus::Success);
    }
}

#[tokio::test]
#[serial_test::serial]
async fn an_unusable_destination_is_recorded_as_absent() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let clock = crate::mainnet::clock::set_now_ms_for_test(1000);
    let fixture = DestinationRecorderFixture::new();
    let mut intent =
        DestinationRecorderFixture::intent(PaymentDestinations::Single("invalid".to_owned()));
    intent.max_time = 61;
    let sends = std::sync::atomic::AtomicUsize::new(0);
    crate::submit::destination_tests::recorded_send(&fixture.recorder(), &intent, &sends)
        .await
        .unwrap();
    assert_eq!(sends.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert!(
        fixture
            .receipts
            .get(&intent.envelope_hash)
            .unwrap()
            .unwrap()
            .submitted
    );
    assert_eq!(
        fixture
            .receipts
            .get(&intent.envelope_hash)
            .unwrap()
            .unwrap()
            .destinations,
        PaymentDestinations::None
    );
    let memory = stellar_agent_core::policy::v1::criteria::state_store::PolicyStateStore::new();
    fixture
        .window
        .load_into("destinations", &fixture.profile, &memory)
        .unwrap();
    let key = stellar_agent_core::policy::v1::criteria::state_store::StateKey::new(
        "destinations",
        1,
        "native",
        60,
    );
    assert_eq!(memory.query_window(&key, 1001).unwrap(), (7, 1));
    let bytes = std::fs::read(fixture.window.path()).unwrap();
    let wire: serde_json::Value = serde_json::from_slice(&bytes[32..]).unwrap();
    assert!(
        wire["entries"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|entry| entry["records"].as_array().unwrap())
            .all(|record| record.get("destinations").is_none())
    );
    assert!(fixture.dir.path().join("state.window").exists());
    clock.set(1_000_000);
    let client =
        crate::client::StellarRpcClient::new(crate::redact::rpc_error_fixtures::ENDPOINT).unwrap();
    let report = fixture
        .window
        .reconcile_due(
            &fixture.profile,
            &client,
            None,
            Some(&fixture.receipts),
            1_000_000,
            1,
        )
        .await
        .unwrap();
    assert_eq!(report.rpc_calls, 0);
    let held = fixture
        .window
        .pending_reservations(&fixture.profile)
        .unwrap();
    assert_eq!(held.len(), 0);
}

#[tokio::test]
#[serial_test::serial]
async fn a_crash_between_receipt_and_reservation_keeps_the_destination() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let _clock = crate::mainnet::clock::set_now_ms_for_test(1000);
    for cut in [1, 2] {
        let fixture = DestinationRecorderFixture::new();
        let intent = DestinationRecorderFixture::intent(
            crate::submit::destination_tests::destination_provenance(),
        );
        DESTINATION_RECORD_CUT.set(cut);
        let sends = std::sync::atomic::AtomicUsize::new(0);
        assert_eq!(
            crate::submit::destination_tests::recorded_send(&fixture.recorder(), &intent, &sends)
                .await
                .unwrap_err()
                .code(),
            "submission.record_unavailable"
        );
        assert_eq!(DESTINATION_RECORD_CUT.get(), 0);
        assert_eq!(sends.load(std::sync::atomic::Ordering::SeqCst), 0);
        let bytes = std::fs::read(fixture.window.path());
        let debit = bytes
            .ok()
            .map(|bytes| {
                let wire: serde_json::Value = serde_json::from_slice(&bytes[32..]).unwrap();
                wire["entries"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .flat_map(|entry| entry["records"].as_array().unwrap())
                    .map(|record| record["amount"].as_str().unwrap().parse::<i128>().unwrap())
                    .sum::<i128>()
            })
            .unwrap_or(0);
        assert_eq!(debit, if cut == 1 { 0 } else { 7 });
        let receipt = ReceiptStore::open_at(fixture.dir.path(), "destinations")
            .unwrap()
            .get(&intent.envelope_hash)
            .unwrap()
            .unwrap();
        assert_eq!(receipt.destinations, intent.destinations);
        assert!(!receipt.submitted);
        let held = fixture
            .window
            .pending_reservations(&fixture.profile)
            .unwrap();
        assert_eq!(held.len(), usize::from(cut == 2));
        if cut == 2 {
            assert_eq!(held[0].destinations, intent.destinations);
            std::fs::write(fixture.receipts.file_path().unwrap(), b"{}").unwrap();
            let server = wiremock::MockServer::start().await;
            wiremock::Mock::given(wiremock::matchers::method("POST"))
                .respond_with(|request: &wiremock::Request| {
                    let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
                    assert_eq!(body["method"], "getTransaction");
                    wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                        "jsonrpc": "2.0", "id": body["id"],
                        "result": {"status": "SUCCESS", "latestLedger": 1001, "oldestLedger": 1, "ledger": 1001, "createdAt": "1"}
                    }))
                }).expect(1).mount(&server).await;
            let client = crate::client::StellarRpcClient::new(&server.uri()).unwrap();
            fixture
                .window
                .reconcile_one(
                    &fixture.profile,
                    &client,
                    None,
                    Some(&fixture.receipts),
                    &held[0].id,
                    1000,
                )
                .await
                .unwrap();
            let restored = fixture.receipts.get(&held[0].id).unwrap().unwrap();
            assert_eq!(restored.destinations, intent.destinations);
        }
    }
}
