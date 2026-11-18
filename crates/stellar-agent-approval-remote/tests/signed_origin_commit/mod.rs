use super::*;
use stellar_agent_core::approval::{
    mainnet_fixtures::{
        ALLOWED_DESTINATION, ENABLEMENT_NONCE, ENDPOINT_HOST, policy_body_with_origin,
    },
    witness::{ApprovalExpectation, ApprovedKind, verify_approval},
};
use stellar_agent_network::{
    MainnetEndpointFlags, NetworkContext, signing::test_doubles::CountingSigner,
};
use stellar_agent_test_support::SignedTestEnvelope;

/// A mainnet payment envelope to a muxed destination, valid for two minutes.
fn envelope() -> SignedTestEnvelope {
    SignedTestEnvelope::builder([42; 32])
        .network_passphrase(stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE)
        .time_bounds(0, now() / 1000 + 120)
        .sequence(2)
        .amount_stroops(10)
        .muxed_destination_id(7)
        .unsigned()
        .build()
}

/// Consent crosses a counter-only restart, busy admission and assertion replay.
pub(super) async fn consent(origin: &str) -> Fixture {
    let mut f = Fixture::new();
    let envelope = envelope();
    let rp = url::Url::parse(origin)
        .unwrap()
        .host_str()
        .unwrap()
        .to_owned();
    f.leaf = pinned_leaf(&rp, &rcgen::PKCS_ECDSA_P256_SHA256);
    std::fs::write(f.files.path().join("cert.pem"), f.leaf.chain_pem()).unwrap();
    std::fs::write(f.files.path().join("key.pem"), &f.leaf.key_pem).unwrap();
    let mut profile = f
        .fixture
        .authority()
        .load_current()
        .unwrap()
        .profile()
        .clone();
    profile.remote_approval.as_mut().unwrap().rp_id = rp;
    profile.mcp_signer_default.account = envelope.source().to_owned();
    profile
        .providers
        .get_or_insert_with(Default::default)
        .primary = Some(
        stellar_agent_core::profile::schema::PrimaryProviderRecord::new("primary", ENDPOINT_HOST),
    );
    stellar_agent_core::profile::loader::save_to_dir(
        f.fixture.name(),
        &profile,
        &f.fixture.home().join("profiles"),
    )
    .unwrap();
    let public = ed25519_dalek::SigningKey::from_bytes(&[42; 32])
        .verifying_key()
        .to_bytes();
    let identity =
        stellar_agent_core::profile::schema::signer_identity_entry_ref(&profile.mcp_signer_default);
    keyring_core::Entry::new(&identity.service, &identity.account)
        .unwrap()
        .set_password(
            &stellar_agent_core::profile::signer_identity::SignerIdentityRecord::signed_for_test(
                public,
                f.fixture.name(),
                &profile,
                &ed25519_dalek::SigningKey::from_bytes(&[11; 32]),
            )
            .render()
            .unwrap(),
        )
        .unwrap();
    let body = policy_body_with_origin(
        f.fixture.name(),
        ENDPOINT_HOST,
        f.fixture.sequence() + 1,
        &[&fixture_authenticator()],
        Some((origin, &f.leaf.pin)),
    )
    .replace(ALLOWED_DESTINATION, envelope.destination());
    f.fixture.write_signed(&body);
    f.entry = PendingApproval::new_payment_pending(
        envelope.envelope_xdr().to_owned(),
        envelope.envelope_xdr().as_bytes(),
        envelope.destination().to_owned(),
        10,
        "XLM".to_owned(),
        None,
        100,
        2,
        stellar_agent_core::approval::process_uid_for_attestation().unwrap(),
        600_000,
    )
    .unwrap();
    PendingApprovalStore::open(f.fixture.store_path())
        .unwrap()
        .insert(f.entry.clone(), now())
        .unwrap();
    stellar_agent_core::audit_log::AuditWriterRegistry::remove_for_test(f.fixture.name());
    for key in [
        &profile.policy_window_state_key_id,
        &profile.audit_log_hash_chain_key_id,
    ] {
        stellar_agent_network::keyring::rotate_keyring_secret_32(&key.service, &key.account)
            .unwrap();
    }
    f.audit = Some(
        stellar_agent_network::mainnet::audit_readiness::audit_readiness(
            &profile,
            f.fixture.name(),
        )
        .unwrap()
        .writer()
        .clone(),
    );
    let nonce = &f.entry.approval_nonce;
    let startup = f.fixture.current_policy().digest();
    let mut handle = f.listen(true).await.unwrap();
    let mut browser = Browser::new(handle.local_addr(), origin);
    browser.login(1).await;
    let (csrf, old) = browser.assertion(nonce, 2).await;
    assert_eq!(
        browser
            .action(nonce, &csrf, "assertion", &old)
            .await
            .status(),
        StatusCode::OK
    );
    let verified = handle
        .take_completion()
        .unwrap()
        .await_presence(Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(verified.sign_count(), 2);
    let counter_only = f.counter_bytes();
    assert!(f.stored().mainnet_presence.is_none());
    assert!(f.stored().attestation_blob_b64.is_none());
    drop(verified);
    handle.shutdown().await.unwrap();

    let handle = f.listen(false).await.unwrap();
    let mut browser = Browser::new(handle.local_addr(), origin);
    browser.login(3).await;
    let page = browser.page(nonce).await;
    let replay = browser
        .action(nonce, page["csrf"].as_str().unwrap(), "assertion", &old)
        .await;
    assert_eq!(replay.status(), StatusCode::CONFLICT);
    assert_eq!(
        replay.json::<Value>().await.unwrap()["error"],
        "approval.presence_consumed"
    );
    assert!(f.stored().mainnet_presence.is_none());
    assert_ne!(f.counter_bytes(), counter_only);
    let (csrf, assertion) = browser.assertion(nonce, 4).await;
    let before = f.counter_bytes();
    let writer = policy_writer(&f);
    assert_busy(
        browser.action(nonce, &csrf, "assertion", &assertion).await,
        "consent",
    )
    .await;
    assert_eq!(f.counter_bytes(), before);
    assert!(f.stored().mainnet_presence.is_none());
    drop(writer);
    let response = browser.action(nonce, &csrf, "assertion", &assertion).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.json::<Value>().await.unwrap()["status"],
        "attested"
    );
    let persisted = std::fs::read(f.fixture.store_path()).unwrap();
    let counters = f.counter_bytes();
    let replay = browser.action(nonce, &csrf, "assertion", &assertion).await;
    assert_eq!(replay.status(), StatusCode::CONFLICT);
    assert_eq!(
        replay.json::<Value>().await.unwrap()["error"],
        "approval.presence_consumed"
    );
    assert_eq!(std::fs::read(f.fixture.store_path()).unwrap(), persisted);
    assert_eq!(f.counter_bytes(), counters);
    handle.shutdown().await.unwrap();
    let entry = f.stored();
    assert_eq!(entry.attestation_version, 5);
    let receipt = entry
        .mainnet_presence
        .as_ref()
        .expect("receipt persists with v5");
    assert_eq!(receipt.version(), 2);
    assert_eq!(receipt.expected_origin(), origin);
    assert_eq!(
        receipt.cert_spki_sha256_hex(),
        Some(hex::encode(f.leaf.pin).as_str())
    );
    assert_eq!(
        receipt.listener_policy_digest_hex(),
        Some(hex::encode(startup).as_str())
    );
    f.entry = entry;
    for _ in 0..2 {
        verify(&f, now()).unwrap();
        assert_eq!(f.counter_bytes(), counters);
    }
    let consents = std::fs::read_to_string(f.fixture.audit_path())
        .unwrap()
        .lines()
        .filter(|line| serde_json::from_str::<Value>(line).unwrap()["kind"] == "approval_attested")
        .count();
    assert_eq!(consents, 1, "one durable consent after retries and restart");
    f
}

fn verify(
    f: &Fixture,
    at: u64,
) -> Result<stellar_agent_core::approval::witness::ApprovalWitness, stellar_agent_core::WalletError>
{
    let store = PendingApprovalStore::open(f.fixture.store_path()).unwrap();
    let entry = &f.entry;
    let blob: [u8; 32] = B64
        .decode(entry.attestation_blob_b64.as_ref().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    verify_approval(
        &store,
        f.fixture.profile(),
        f.fixture.name(),
        &entry.approval_nonce,
        &blob,
        &ApprovalExpectation {
            kind: ApprovedKind::Payment,
            subject: stellar_agent_core::approval::mainnet_consent_subject(
                entry,
                &f.fixture.binding(),
            )
            .unwrap(),
        },
        &f.fixture.current_policy(),
        at,
    )
}

pub(super) fn check_times(f: &Fixture) {
    let entry = f.stored();
    let receipt = entry.mainnet_presence.as_ref().unwrap();
    let counters = f.counter_bytes();
    assert_eq!(
        verify(f, receipt.verified_at_unix_ms() - 1)
            .unwrap_err()
            .code(),
        "approval.presence_invalid"
    );
    assert_eq!(
        verify(f, entry.expires_at_unix_ms + 1).unwrap_err().code(),
        "approval.expired"
    );
    let after_challenge = receipt.expires_at_unix_ms() + 1;
    assert!(after_challenge < entry.expires_at_unix_ms);
    verify(f, after_challenge).unwrap();
    assert_eq!(
        f.counter_bytes(),
        counters,
        "stored verification never updates counters"
    );
}

struct Rpc {
    uri: String,
    requests: Arc<Mutex<Vec<Value>>>,
    stop: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}

impl Rpc {
    async fn start(envelope: &SignedTestEnvelope) -> Self {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = requests.clone();
        let ledger = envelope.ledger_entries_result();
        let app = axum::Router::new().route("/", axum::routing::post(move |axum::Json(body): axum::Json<Value>| {
            let ledger = ledger.clone();
            let seen = seen.clone();
            async move {
                seen.lock().unwrap().push(body.clone());
                let result = match body["method"].as_str().unwrap() {
                    "getNetwork" => stellar_agent_test_support::signed_envelope::get_network_result(stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE),
                    "getLedgerEntries" => {
                        let mut result = ledger;
                        let keys = body["params"]["keys"].as_array().unwrap();
                        result["entries"].as_array_mut().unwrap().retain(|entry| keys.contains(&entry["key"]));
                        result
                    }
                    "getHealth" => json!({"status":"healthy","latestLedger":100,"oldestLedger":1,"ledgerRetentionWindow":100}),
                    "getLatestLedger" => json!({"id":"00".repeat(32),"protocolVersion":23,"sequence":100}),
                    "getLedgers" => json!({"latestLedger":100,"oldestLedger":1,"latestLedgerCloseTime":(now()/1000).to_string(),"oldestLedgerCloseTime":1,"cursor":"100","ledgers":[]}),
                    "sendTransaction" => json!({"hash":stellar_agent_test_support::send_transaction_hash_hex(&body,stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE),"status":"PENDING","latestLedger":100,"latestLedgerCloseTime":"1234567890"}),
                    "getTransaction" => json!({"status":"SUCCESS","ledger":101,"txHash":body["params"]["hash"],"createdAt":(now()/1000).to_string()}),
                    method => panic!("unexpected fixture RPC {method}"),
                };
                axum::Json(json!({"jsonrpc":"2.0","id":body["id"],"result":result}))
            }
        }));
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let uri = format!("http://{}", listener.local_addr().unwrap());
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = stopped.await;
                })
                .await
                .unwrap();
        });
        Self {
            uri,
            requests,
            stop,
            task,
        }
    }

    fn submissions(&self) -> usize {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|request| request["method"] == "sendTransaction")
            .count()
    }

    async fn shutdown(self) {
        self.stop.send(()).unwrap();
        self.task.await.unwrap();
    }
}

/// The mainnet decision the signed policy makes for the payment envelope
/// `envelope_xdr`, from which the commit's approval authority is built.
fn payment_decision(
    policy: &stellar_agent_core::mainnet::verified_policy::VerifiedPolicy,
    profile: &stellar_agent_core::profile::schema::Profile,
    envelope_xdr: &str,
) -> stellar_agent_core::mainnet::decision::MainnetDecision {
    use stellar_agent_core::mainnet::decision::{
        EvaluationScope, MainnetEvaluationRequest, evaluate_mainnet,
    };
    use stellar_agent_core::policy::{McpToolRegistration, ToolDescriptor, ToolValueKind};
    let mut descriptor = ToolDescriptor::from_registration(&McpToolRegistration {
        name: "stellar_pay",
        destructive_hint: true,
        read_only_hint: false,
        chain_id_required: true,
        value_kind: ToolValueKind::MovesValue,
    });
    descriptor.chain_id = profile.chain_id.caip2_str().to_owned();
    let args = stellar_agent_core::envelope_decode::decode_authoritative_args(
        envelope_xdr,
        "stellar_pay_commit",
    )
    .unwrap();
    evaluate_mainnet(
        policy,
        EvaluationScope::Classic,
        now(),
        MainnetEvaluationRequest {
            chain_id: profile.chain_id.caip2_str(),
            tool: &descriptor,
            args: &args,
            profile,
            value: None,
            account_view: None,
            identity_view: None,
            counterparty_cache: None,
            sep10_sessions: None,
            sep45_sessions: None,
        },
    )
    .unwrap()
}

pub(super) async fn commit(f: &Fixture) {
    use stellar_agent_core::{
        audit_log::PolicyDecision,
        envelope_decode::decode_authoritative_args,
        mainnet::{
            decision::{EvaluationScope, MainnetEvaluationRequest, evaluate_mainnet},
            enablement::verify_enablement,
        },
        policy::{McpToolRegistration, ToolDescriptor, ToolValueKind},
        profile::{
            name::{ProfileNameSource, ResolvedProfileName},
            receipt::ReceiptStore,
        },
    };
    use stellar_agent_network::{
        keyring::{EnrolledRole, enrolled_signer},
        mainnet::{
            MainnetConsumer,
            audit_readiness::audit_readiness,
            authority::MainnetAuthority,
            resolve::{TxSignRequest, resolve_tx_sign},
        },
        policy_state::PersistedWindowStore,
        signing::envelope_signing::attach_signature_authorized,
        submission_record::{ApprovalTombstone, WalletSubmissionRecorder},
        submit::{MainnetSubmitGrant, submit_authorized_transaction_and_wait},
    };
    let current = f.fixture.authority().load_current().unwrap();
    let profile = current.profile();
    let entry = f.stored();
    let unsigned = match &entry.kind {
        stellar_agent_core::approval::ApprovalKind::PaymentSimulated {
            envelope_xdr_b64, ..
        } => envelope_xdr_b64,
        other => panic!("payment fixture: {other:?}"),
    };
    let rpc = Rpc::start(&envelope()).await;
    let signing = CountingSigner::new([42; 32]);
    let context = NetworkContext::mainnet_write(
        profile,
        &ResolvedProfileName::from_flag(f.fixture.name()),
        &f.fixture.home().join("profiles"),
        MainnetEndpointFlags::default(),
    );
    if !stellar_agent_core::build_info::MAINNET_WRITE {
        assert_eq!(
            context.unwrap_err().code(),
            "network.mainnet_write_forbidden"
        );
        assert_eq!(signing.sign_calls(), 0);
        assert_eq!(rpc.submissions(), 0);
        assert!(f.stored().mainnet_presence.is_some());
        stellar_agent_core::audit_log::AuditWriterRegistry::remove_for_test(f.fixture.name());
        rpc.shutdown().await;
        return;
    }
    let context = context
        .unwrap()
        .with_test_transport_routes(&[(ENDPOINT_HOST, &rpc.uri)]);
    let client = context.primary_client().unwrap();
    let approval = verify(f, now()).unwrap();
    let mut tool = ToolDescriptor::from_registration(&McpToolRegistration {
        name: "stellar_pay",
        destructive_hint: true,
        read_only_hint: false,
        chain_id_required: true,
        value_kind: ToolValueKind::MovesValue,
    });
    tool.chain_id = profile.chain_id.caip2_str().to_owned();
    let args = decode_authoritative_args(unsigned, "stellar_pay_commit").unwrap();
    let decision = evaluate_mainnet(
        current.policy(),
        EvaluationScope::Classic,
        now(),
        MainnetEvaluationRequest {
            chain_id: profile.chain_id.caip2_str(),
            tool: &tool,
            args: &args,
            profile,
            value: None,
            account_view: None,
            identity_view: None,
            counterparty_cache: None,
            sep10_sessions: None,
            sep45_sessions: None,
        },
    )
    .unwrap();
    MainnetAuthority::from_decision(&decision, Some(&approval)).unwrap();
    let counters = f.counter_bytes();
    let enablement = verify_enablement(
        current.policy(),
        f.fixture.name(),
        ProfileNameSource::Flag,
        profile,
        &f.fixture.home().join("profiles"),
        &|_| Ok(ENABLEMENT_NONCE.to_owned()),
    )
    .unwrap();
    let public = ed25519_dalek::SigningKey::from_bytes(&[42; 32])
        .verifying_key()
        .to_bytes();
    let signer = enrolled_signer(
        f.fixture.name(),
        &f.fixture.home().join("profiles"),
        profile,
        EnrolledRole::Agent,
        &public,
        &current.policy().owner(),
    )
    .unwrap();
    let window = PersistedWindowStore::for_profile(f.fixture.name());
    let audit = audit_readiness(profile, f.fixture.name()).unwrap();
    let writer = audit.writer().clone();
    // Every approval mint names its durable record: the producer opens it
    // for the payment's operation and the consent step commits the consent.
    let link = {
        use stellar_agent_network::operation_entry::{
            commit_consent, consent_completion, pending_approval_facts, unsigned_envelope_sha256,
        };
        use stellar_agent_network::policy_state::{
            ApprovalRecorder, BusinessId, ConsentRow, IntentSlot, OpenOutcome, OpenRequest,
            OperationKind, OperationLink, OperationRecorder, OperationTool,
        };
        let subject = stellar_agent_core::approval::mainnet_consent_subject(
            &entry,
            &stellar_agent_core::approval::AttestationBinding::new(
                f.fixture.name(),
                profile.chain_id.caip2_str(),
            ),
        )
        .unwrap();
        let ttl = entry.expires_at_unix_ms - entry.created_at_unix_ms;
        let mut guard = writer.lock().unwrap();
        let OpenOutcome::New(handle) =
            OperationRecorder::new(&window, profile, &mut *guard, "open")
                .open(&OpenRequest {
                    business_id: BusinessId::parse(&entry.approval_nonce).unwrap(),
                    tool: OperationTool::CliPay,
                    kind: OperationKind::Pay,
                    intent: IntentSlot::Envelope {
                        intent_digest: subject,
                        unsigned_envelope_sha256: unsigned_envelope_sha256(unsigned),
                        max_time: 0,
                    },
                    envelope_xdr: Some(unsigned.clone()),
                    prepared_decision: None,
                    rule_ttl_ms: Some(ttl),
                })
                .unwrap()
        else {
            panic!("a fresh payment opens its operation")
        };
        ApprovalRecorder::new(&window, profile, &mut *guard, "pending")
            .open_pending(
                handle.id(),
                &pending_approval_facts(&entry, &handle, ApprovedKind::Payment, subject, ttl),
                stellar_agent_core::audit_log::PolicyDecision::RequireApproval,
            )
            .unwrap();
        drop(guard);
        let admission = f.fixture.authority().admit().unwrap();
        let store = PendingApprovalStore::open(f.fixture.store_path()).unwrap();
        let completion = consent_completion(
            &store,
            &window,
            profile,
            f.fixture.name(),
            &entry.approval_nonce,
            current.policy(),
            ConsentRow::Written,
            &admission,
        )
        .unwrap();
        drop(store);
        drop(admission);
        commit_consent(&window, profile, &completion).unwrap();
        OperationLink {
            operation_id: handle.id(),
            attempt_index: 1,
        }
    };
    let decision = payment_decision(current.policy(), profile, unsigned);
    let authorization = resolve_tx_sign(TxSignRequest {
        context: &context,
        consumer: MainnetConsumer::CliPay,
        unsigned_envelope_xdr: unsigned,
        client: &client,
        probe_deadline: Duration::from_secs(2),
        witness: None,
        signer: &signer,
        policy: current.policy(),
        enablement: &enablement,
        authority: &MainnetAuthority::from_decision(&decision, Some(&approval)).unwrap(),
        audit,
        store: &window,
        operation: Some(link),
        restriction: None,
        sac_payment_context: None,
    })
    .await
    .unwrap();
    let signed = attach_signature_authorized(
        unsigned,
        &signing,
        context.network_passphrase(),
        MainnetConsumer::CliPay,
        &authorization,
    )
    .await
    .unwrap();
    let recorder = WalletSubmissionRecorder::new_authorized(
        profile,
        f.fixture.name(),
        "stellar_pay",
        Some("stellar:mainnet".to_owned()),
        PolicyDecision::RequireApproval,
        vec![],
        &authorization,
        ReceiptStore::open(f.fixture.name()).unwrap(),
        window,
        Some(writer),
        None,
        "signed-origin-commit",
        now(),
    )
    .with_approval(Some(ApprovalTombstone {
        store_dir: f.fixture.home().join("approvals"),
        profile_name: f.fixture.name().to_owned(),
        approval_nonce: entry.approval_nonce.clone(),
    }));
    submit_authorized_transaction_and_wait(
        &client,
        None,
        &signed,
        Duration::from_secs(5),
        context.network_passphrase(),
        None,
        &recorder,
        MainnetConsumer::CliPay,
        MainnetSubmitGrant::Tx(authorization),
    )
    .await
    .unwrap();
    assert_eq!(signing.sign_calls(), 1);
    assert_eq!(rpc.submissions(), 1);
    assert!(
        matches!(
            f.stored().kind,
            stellar_agent_core::approval::ApprovalKind::Consumed { .. }
        ),
        "submission consumes the approval"
    );
    assert_eq!(f.counter_bytes(), counters);
    assert_eq!(
        verify(f, now()).unwrap_err().code(),
        "approval.consumed",
        "a consumed approval stays consumed"
    );
    assert_eq!(signing.sign_calls(), 1);
    assert_eq!(rpc.submissions(), 1);
    stellar_agent_core::audit_log::AuditWriterRegistry::remove_for_test(f.fixture.name());
    rpc.shutdown().await;
}
