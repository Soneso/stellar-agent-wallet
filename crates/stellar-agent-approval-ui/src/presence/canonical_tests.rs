use super::*;
use crate::decision::{ConsentRowSource, IntentLookup};
use stellar_agent_core::approval::{
    IntentAsset, IntentBase, IntentPayload, MemoFact, subject::SubjectKind,
};

struct Lookup {
    nonce: String,
    intent: Mutex<Option<ClassicIntent>>,
}

impl IntentLookup for Lookup {
    fn lookup(
        &self,
        nonce: &str,
        _: &CurrentMainnetApprovalPolicy,
    ) -> Result<Option<ClassicIntent>, WalletError> {
        if nonce != self.nonce {
            return Err(failure(Failure::PresenceChanged));
        }
        Ok(self.intent.lock().unwrap().clone())
    }
}

fn canonical_entry(
    fixture: &MainnetConsentFixture,
    kind: usize,
) -> (PendingApproval, ClassicIntent) {
    use stellar_agent_core::approval::fixtures;
    let (mut entry, payment) = fixture.intent_payment(120_000);
    let source = payment.base().source().to_owned();
    let destination =
        stellar_agent_core::approval::mainnet_fixtures::ALLOWED_DESTINATION.to_owned();
    let uid = entry.process_uid.clone();
    let payload = match kind {
        0 => payment.payload().clone(),
        1 => {
            let envelope = fixtures::envelope(
                &source,
                stellar_xdr::OperationBody::CreateAccount(stellar_xdr::CreateAccountOp {
                    destination: stellar_xdr::AccountId(
                        stellar_xdr::PublicKey::PublicKeyTypeEd25519(stellar_xdr::Uint256([0; 32])),
                    ),
                    starting_balance: 53,
                }),
                stellar_xdr::Memo::None,
                100,
                7,
            );
            entry = PendingApproval::new_payment_pending(
                envelope.clone(),
                envelope.as_bytes(),
                destination.clone(),
                53,
                "XLM".into(),
                None,
                100,
                7,
                uid,
                120_000,
            )
            .unwrap();
            IntentPayload::CreateAccount {
                destination,
                starting_balance_stroops: 53,
            }
        }
        2 => {
            entry = fixtures::trustline_pending(
                &source,
                "UsD",
                &destination,
                Some(0),
                100,
                7,
                uid,
                120_000,
            );
            IntentPayload::Trustline {
                issuer: destination,
                code: "UsD".into(),
                limit_stroops: 0,
            }
        }
        _ => {
            entry =
                fixtures::claim_pending(&source, [9; 32], Some(("XLM", 71)), 100, 7, uid, 120_000);
            IntentPayload::Claim {
                balance_id: format!("00000000{}", "09".repeat(32)),
                claimant: source.clone(),
                asset: IntentAsset::Native,
                amount_stroops: 71,
            }
        }
    };
    entry.subject_kind = SubjectKind::IntentDigest;
    let memo = if kind == 0 {
        payment.base().memo().clone()
    } else {
        MemoFact::None
    };
    let intent = ClassicIntent::new(
        IntentBase::new(
            stellar_agent_core::approval::presence::MAINNET_CHAIN_ID.into(),
            source,
            fixture.current_policy().digest(),
            500,
            memo,
        )
        .unwrap(),
        payload,
    )
    .unwrap();
    (entry, intent)
}

struct Routes {
    fixture: MainnetConsentFixture,
    entry: PendingApproval,
    intent: ClassicIntent,
    lookup: Arc<Lookup>,
    recording: Arc<crate::tests::RecordingConsent>,
    router: Router,
    session: HttpsSession,
    completion: Option<PresenceCompletion>,
    signed: bool,
    context: Arc<DecisionContext>,
}

impl Routes {
    fn new(signed: bool, one_shot: bool, kind: usize) -> Self {
        let mut fixture = MainnetConsentFixture::new("canonical-routes");
        if signed {
            fixture
                .sign_signed_origin_policy(&[&fixture_authenticator()], &SIGNED_CERT_SPKI_SHA256);
        }
        let (entry, intent) = canonical_entry(&fixture, kind);
        PendingApprovalStore::open(fixture.store_path())
            .unwrap()
            .insert(entry.clone(), now_ms().unwrap())
            .unwrap();
        let lookup = Arc::new(Lookup {
            nonce: entry.approval_nonce.clone(),
            intent: Mutex::new(Some(intent.clone())),
        });
        let recording = Arc::new(crate::tests::RecordingConsent::default());
        let context = Arc::new(
            Harness::context_of(&fixture)
                .with_intent_lookup(lookup.clone())
                .with_consent_recording(recording.clone()),
        );
        let (gate, session) = HttpsSessionGate::open();
        let config = MainnetPresenceConfig {
            entry: entry.clone(),
            intent: Some(intent.clone()),
            context: context.context.clone(),
            authority: fixture.authority(),
            store_path: fixture.store_path(),
            page_identity: PageIdentity::neutral(),
        };
        let (router, completion) = if signed {
            signed_origin_consent(
                if one_shot {
                    SignedOriginMode::OneShot(Box::new(config))
                } else {
                    SignedOriginMode::Inbox {
                        context: context.clone(),
                        page_identity: PageIdentity::neutral(),
                    }
                },
                ListenerIdentity::capture(&fixture.current_policy()).unwrap(),
                SIGNED_ORIGIN,
                Arc::new(gate),
            )
            .unwrap()
            .into_parts()
        } else {
            let (sender, receiver) = oneshot::channel();
            let state = Arc::new(PresenceState {
                auth: Arc::new(gate),
                context: context.context.clone(),
                authority: fixture.authority(),
                store_path: fixture.store_path(),
                identity: Arc::new(PageIdentity::neutral()),
                origin: MainnetConsentFixture::origin(),
                site: Site::Loopback,
                challenges: Mutex::new(HashMap::new()),
                mode: if one_shot {
                    Mode::OneShot {
                        nonce: entry.approval_nonce.clone(),
                        intent: config.intent.map(Box::new),
                        expires_at: entry.expires_at_unix_ms,
                        completion: Mutex::new(Some(sender)),
                    }
                } else {
                    Mode::Inbox(context.clone())
                },
            });
            if one_shot {
                check_presented(&state, &entry).unwrap();
            }
            (
                routes(state.clone()).route(
                    "/approval/{nonce}",
                    get(detail_get::<HttpsSessionGate>).with_state(state),
                ),
                one_shot.then_some(PresenceCompletion(receiver)),
            )
        };
        Self {
            fixture,
            entry,
            intent,
            lookup,
            recording,
            router,
            session,
            completion,
            signed,
            context,
        }
    }

    async fn send(&self, action: Option<&str>, body: serde_json::Value) -> Response {
        let nonce = &self.entry.approval_nonce;
        let path = action.map_or_else(
            || format!("/approval/{nonce}"),
            |action| format!("/approval/{nonce}/{action}"),
        );
        let mut request = Request::builder()
            .method(if action.is_some() { "POST" } else { "GET" })
            .uri(path);
        for (name, value) in self.session.headers(nonce) {
            request = request.header(name, value);
        }
        self.router
            .clone()
            .oneshot(request.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap()
    }

    async fn post(&self, action: &str, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
        let response = self.send(Some(action), body).await;
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 65536).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    fn assertion(&self, options: &serde_json::Value) -> serde_json::Value {
        let challenge = URL_SAFE_NO_PAD
            .decode(options["challenge"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let origin = if self.signed {
            SIGNED_ORIGIN.to_owned()
        } else {
            MainnetConsentFixture::origin()
        };
        let assertion = fixture_authenticator().assert(
            challenge,
            &origin,
            options["rp_id"].as_str().unwrap(),
            5,
            0,
        );
        json!({"request_id": options["request_id"], "credential_id_b64url": URL_SAFE_NO_PAD.encode(assertion.credential_id), "authenticator_data_b64url": URL_SAFE_NO_PAD.encode(assertion.authenticator_data), "client_data_json_b64url": URL_SAFE_NO_PAD.encode(assertion.client_data_json), "signature_der_b64url": URL_SAFE_NO_PAD.encode(assertion.signature_der)})
    }
}

#[tokio::test]
#[serial_test::serial]
async fn canonical_routes_share_stored_intent_and_recover() {
    for refuse in [false, true] {
        let h = Routes::new(false, false, 0);
        h.recording
            .refuse
            .store(refuse, std::sync::atomic::Ordering::SeqCst);
        let policy = h.fixture.current_policy();
        let presence = h.fixture.intent_presence(&h.entry, &policy, &h.intent);
        let path = h.fixture.store_path();
        let entry = h.entry.clone();
        let name = h.fixture.name().to_owned();
        let writer = h.context.audit_writer.clone();
        crate::decision::wait_hook::install(move || {
            let binding = stellar_agent_core::approval::AttestationBinding::new(
                &name,
                stellar_agent_core::approval::presence::MAINNET_CHAIN_ID,
            );
            stellar_agent_core::approval::attest_and_persist(
                &mut PendingApprovalStore::open(path).unwrap(),
                &entry,
                &stellar_agent_core::approval::mainnet_fixtures::ATTESTATION_KEY,
                &binding,
                stellar_agent_core::approval::Surface::Serve,
                stellar_agent_core::approval::ConsentAudit::Writer(&mut writer.lock().unwrap()),
                stellar_agent_core::approval::ConsentAuthorization::Mainnet {
                    presence,
                    policy: &policy,
                },
                |_, _| unreachable!(),
            )
            .unwrap();
        });
        for attempt in 0..2 {
            let presence =
                h.fixture
                    .intent_presence(&h.entry, &h.fixture.current_policy(), &h.intent);
            let outcome = crate::decision::apply_decision(
                &h.context,
                crate::decision::Decision::Approve {
                    nonce: h.entry.approval_nonce.clone(),
                    shown_view_digest: Some(
                        stellar_agent_core::approval::approval_view_digest(
                            &h.entry,
                            &h.fixture.binding(),
                        )
                        .unwrap(),
                    ),
                },
                crate::decision::RequestIdentity::Mainnet(presence),
            );
            assert!(
                if refuse {
                    matches!(outcome, crate::decision::Outcome::Unavailable)
                } else if attempt == 1 {
                    matches!(
                        outcome,
                        crate::decision::Outcome::PresenceRefused {
                            code: "approval.presence_consumed",
                            ..
                        }
                    )
                } else {
                    matches!(
                        outcome,
                        crate::decision::Outcome::AlreadyResolved {
                            attestation: Some(_)
                        }
                    )
                },
                "raced and repeated canonical outcomes: {outcome:?}"
            );
            assert_eq!(
                h.recording.calls().len(),
                attempt + 1,
                "raced and repeated paths complete before exposing a blob"
            );
            assert_eq!(
                h.recording.calls().last().unwrap().1,
                ConsentRowSource::Recovered
            );
        }
        assert_eq!(attested_rows(&h.fixture), 1);
    }
    for signed in [false, true] {
        for one_shot in [false, true] {
            for kind in 0..4 {
                let mut h = Routes::new(signed, one_shot, kind);
                let (status, html) = page_text(h.send(None, json!({})).await).await;
                assert_eq!(status, StatusCode::OK, "canonical page: {html}");
                assert!(
                    html.contains("<dt>Fee at most (stroops)</dt><dd>500</dd>"),
                    "canonical fee bound"
                );
                assert!(!html.contains("Simulated seq num"), "no ephemeral sequence");
                let page =
                    crate::operator_enroll::test_support::island(&html, "presence-data").unwrap();
                let digest = hex::encode(
                    mainnet_intent_consent_view_digest(
                        &h.entry,
                        &h.fixture.binding(),
                        &h.fixture.current_policy(),
                        Some(&h.intent),
                    )
                    .unwrap(),
                );
                assert_eq!(
                    page["consent_view_digest"], digest,
                    "page binds stored intent"
                );
                let (status, options) = h
                    .post("challenge", json!({"consent_view_digest": digest}))
                    .await;
                assert_eq!(status, StatusCode::OK, "canonical challenge: {options}");
                let assertion = h.assertion(&options);
                let (status, response) = h.post("assertion", assertion.clone()).await;
                assert_eq!(status, StatusCode::OK, "canonical assertion: {response}");
                if let Some(completion) = h.completion.take() {
                    let presence = completion
                        .await_presence(Instant::now() + std::time::Duration::from_secs(1))
                        .await
                        .unwrap();
                    let policy = h.fixture.current_policy();
                    let mut store = PendingApprovalStore::open(h.fixture.store_path()).unwrap();
                    stellar_agent_core::approval::attest_and_persist(
                        &mut store,
                        &h.entry,
                        &stellar_agent_core::approval::mainnet_fixtures::ATTESTATION_KEY,
                        &h.fixture.binding(),
                        stellar_agent_core::approval::Surface::Cli,
                        stellar_agent_core::approval::ConsentAudit::Writer(
                            &mut h.context.audit_writer.lock().unwrap(),
                        ),
                        stellar_agent_core::approval::ConsentAuthorization::Mainnet {
                            presence,
                            policy: &policy,
                        },
                        |_, _| unreachable!(),
                    )
                    .unwrap();
                } else {
                    assert_eq!(
                        h.recording.calls(),
                        [(h.entry.approval_nonce.clone(), ConsentRowSource::Written)],
                        "fresh completion precedes success"
                    );
                    let (_, repeated) = h.post("assertion", assertion).await;
                    assert_eq!(
                        repeated["error"], "approval.presence_consumed",
                        "consumed retry retains outcome"
                    );
                    assert_eq!(
                        h.recording.calls().last().unwrap().1,
                        ConsentRowSource::Recovered
                    );
                    let (_, stored) = page_text(h.send(None, json!({})).await).await;
                    let blob = PendingApprovalStore::open(h.fixture.store_path())
                        .unwrap()
                        .get(&h.entry.approval_nonce)
                        .unwrap()
                        .attestation_blob_b64
                        .clone()
                        .unwrap();
                    assert!(
                        stored.contains(&blob),
                        "stored page completes canonical consent"
                    );
                    h.recording
                        .refuse
                        .store(true, std::sync::atomic::Ordering::SeqCst);
                    let (_, refused) = page_text(h.send(None, json!({})).await).await;
                    assert!(!refused.contains(&blob), "completion refusal hides blob");
                }
                let policy = h.fixture.current_policy();
                let admission = h.fixture.authority().admit().unwrap();
                let store = PendingApprovalStore::open(h.fixture.store_path()).unwrap();
                let entry = store.get(&h.entry.approval_nonce).unwrap();
                assert_eq!(entry.attestation_version, 6, "both sites persist V6");
                let proof = URL_SAFE_NO_PAD
                    .decode(entry.attestation_blob_b64.as_ref().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap();
                let witness =
                    stellar_agent_core::approval::witness::verify_intent_consent_admitted(
                        &store,
                        h.fixture.profile(),
                        h.fixture.name(),
                        &entry.approval_nonce,
                        &proof,
                        &h.intent,
                        &policy,
                        now_ms().unwrap(),
                        &admission,
                    )
                    .expect("V6 and intent receipt independently verify");
                assert_eq!(witness.subject(), *h.intent.digest().as_bytes());
                assert_eq!(
                    attested_rows(&h.fixture),
                    1,
                    "recovery writes no second row"
                );
            }
        }
    }
}

#[tokio::test]
#[serial_test::serial]
async fn canonical_routes_refuse_missing_and_changed_intent() {
    for signed in [false, true] {
        for stage in ["challenge", "assertion"] {
            for changed in ["amount", "memo", "bound", "missing"] {
                let h = Routes::new(signed, false, 0);
                let (_, html) = page_text(h.send(None, json!({})).await).await;
                let page =
                    crate::operator_enroll::test_support::island(&html, "presence-data").unwrap();
                let (_, options) = h
                    .post(
                        "challenge",
                        json!({"consent_view_digest": page["consent_view_digest"]}),
                    )
                    .await;
                let base = h.intent.base();
                let intent = if changed == "missing" {
                    None
                } else {
                    let payload = if changed == "amount" {
                        IntentPayload::Pay {
                            destination:
                                stellar_agent_core::approval::mainnet_fixtures::ALLOWED_DESTINATION
                                    .into(),
                            asset: IntentAsset::Native,
                            amount_stroops: 11,
                        }
                    } else {
                        h.intent.payload().clone()
                    };
                    Some(
                        ClassicIntent::new(
                            IntentBase::new(
                                base.chain_id().into(),
                                base.source().into(),
                                *base.policy_digest(),
                                if changed == "bound" { 499 } else { 500 },
                                if changed == "memo" {
                                    MemoFact::Id(17)
                                } else {
                                    base.memo().clone()
                                },
                            )
                            .unwrap(),
                            payload,
                        )
                        .unwrap(),
                    )
                };
                *h.lookup.intent.lock().unwrap() = intent;
                let request = if stage == "challenge" {
                    json!({"consent_view_digest": page["consent_view_digest"]})
                } else {
                    h.assertion(&options)
                };
                let (_, refused) = h.post(stage, request).await;
                assert_eq!(
                    refused["error"], "approval.presence_changed",
                    "{stage} refuses changed {changed}"
                );
                assert!(h.recording.calls().is_empty(), "refusal commits no consent");
                assert_eq!(attested_rows(&h.fixture), 0);
            }
        }
    }
}
