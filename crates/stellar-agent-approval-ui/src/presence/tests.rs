#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "synthetic consent assertions"
)]
use super::*;
use axum::{
    body::{Body, to_bytes},
    http::Request,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use stellar_agent_core::approval::mainnet_fixtures::MainnetConsentFixture;
use stellar_agent_test_support::webauthn::fixture_authenticator;
use tower::ServiceExt as _;

struct Harness {
    fixture: MainnetConsentFixture,
    entry: PendingApproval,
    state: Arc<PresenceState>,
    cookie: String,
    session: SessionState,
}
impl Harness {
    fn new() -> Self {
        Self::named("presence")
    }
    fn named(name: &str) -> Self {
        let fixture = MainnetConsentFixture::new(name);
        let entry = fixture.payment(600_000);
        let mut store = PendingApprovalStore::open(fixture.store_path()).unwrap();
        store.insert(entry.clone(), now_ms().unwrap()).unwrap();
        drop(store);
        let ctx = Arc::new(Self::context_of(&fixture));
        let token = OpaqueToken::generate();
        let hex = token.to_hex();
        let mut auth = AuthState::new(token, SessionPurpose::Inbox);
        let session = auth.exchange_bootstrap(&hex, Instant::now()).unwrap();
        let cookie = auth
            .set_cookie_value(&session)
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let state = PresenceState::inbox(
            Arc::new(Mutex::new(auth)),
            ctx,
            Arc::new(PageIdentity::neutral()),
            4100,
        )
        .unwrap();
        Self {
            fixture,
            entry,
            state,
            cookie,
            session,
        }
    }
    /// The decision context of the fixture's mainnet inbox.
    fn context_of(fixture: &MainnetConsentFixture) -> DecisionContext {
        DecisionContext::new(
            ApprovalContext::from_profile(fixture.name(), fixture.profile()),
            fixture.store_path(),
            fixture.profile().attestation_key_id.clone(),
            stellar_agent_core::profile::owner_key::OwnerKeyContext::for_profile(
                fixture.name(),
                fixture.profile(),
            ),
            Arc::new(Mutex::new(fixture.audit_writer())),
            None,
        )
        .with_mainnet_authority(fixture.authority())
    }
    fn digest(&self) -> String {
        hex::encode(
            mainnet_consent_view_digest(
                &self.entry,
                &self.fixture.binding(),
                &self.fixture.current_policy(),
            )
            .unwrap(),
        )
    }
    async fn post(
        &self,
        action: &str,
        body: serde_json::Value,
        omit: &str,
    ) -> (StatusCode, serde_json::Value) {
        post_for(
            &self.state,
            (&self.session, &self.cookie),
            &self.entry.approval_nonce,
            action,
            body,
            omit,
        )
        .await
    }

    async fn challenge(&self) -> serde_json::Value {
        let (status, body) = self
            .post(
                "challenge",
                json!({"consent_view_digest": self.digest()}),
                "",
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }
    fn signed(&self, options: &serde_json::Value, flags: u8) -> serde_json::Value {
        signed(options, &self.state.origin, flags)
    }
    fn replace_entry(&mut self, entry: PendingApproval) {
        let mut store = PendingApprovalStore::open(self.fixture.store_path()).unwrap();
        assert!(store.remove(&self.entry.approval_nonce).unwrap());
        store.insert(entry.clone(), now_ms().unwrap()).unwrap();
        self.entry = entry;
    }
    fn one_shot(&mut self) -> oneshot::Receiver<Result<VerifiedMainnetPresence, WalletError>> {
        self.one_shot_until(self.entry.expires_at_unix_ms)
    }
    /// Turns the listener into the ceremony of this entry, open until
    /// `expires_at` (unix ms), and returns its completion.
    fn one_shot_until(
        &mut self,
        expires_at: u64,
    ) -> oneshot::Receiver<Result<VerifiedMainnetPresence, WalletError>> {
        let (sender, receiver) = oneshot::channel();
        Arc::get_mut(&mut self.state).unwrap().mode = Mode::OneShot {
            nonce: self.entry.approval_nonce.clone(),
            expires_at,
            completion: Mutex::new(Some(sender)),
        };
        receiver
    }
    fn decision(&self) -> Arc<DecisionContext> {
        match &self.state.mode {
            Mode::Inbox(context) => context.clone(),
            Mode::OneShot { .. } => unreachable!("an inbox harness"),
        }
    }
    fn no_consent(&self) {
        assert!(
            PendingApprovalStore::open(self.fixture.store_path())
                .unwrap()
                .get(&self.entry.approval_nonce)
                .unwrap()
                .attestation_blob_b64
                .is_none()
        );
    }
}
async fn post_for(
    state: &Arc<PresenceState>,
    (session, cookie): (&SessionState, &str),
    nonce: &str,
    action: &str,
    body: serde_json::Value,
    omit: &str,
) -> (StatusCode, serde_json::Value) {
    let mut request = Request::builder()
        .method("POST")
        .uri(format!("/approval/{nonce}/{action}"));
    for (key, value) in [
        ("host", "localhost:4100".to_owned()),
        ("origin", "http://localhost:4100".to_owned()),
        ("cookie", cookie.to_owned()),
        ("x-session-proof", session.session_proof.to_hex()),
        (
            "x-stellar-approval-csrf",
            compute_csrf(&session.csrf_key, nonce),
        ),
        ("content-type", "application/json".to_owned()),
    ] {
        if key != omit {
            let value = if key == "host" && omit == "hostile-host" {
                "hostile.example:4100".to_owned()
            } else {
                value
            };
            request = request.header(key, value);
        }
    }
    let router = layers(routes(state.clone()), "127.0.0.1:4100".parse().unwrap());
    let response = router
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 16384).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or_default())
}
fn signed(options: &serde_json::Value, origin: &str, flags: u8) -> serde_json::Value {
    let challenge = URL_SAFE_NO_PAD
        .decode(options["challenge"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let assertion = fixture_authenticator().assert(challenge, origin, "localhost", flags, 1);
    json!({"request_id": options["request_id"], "credential_id_b64url": URL_SAFE_NO_PAD.encode(assertion.credential_id),
        "authenticator_data_b64url": URL_SAFE_NO_PAD.encode(assertion.authenticator_data), "client_data_json_b64url": URL_SAFE_NO_PAD.encode(assertion.client_data_json), "signature_der_b64url": URL_SAFE_NO_PAD.encode(assertion.signature_der)})
}

#[tokio::test]
#[serial_test::serial]
async fn mainnet_challenge_requires_session_csrf_and_proof() {
    let h = Harness::new();
    for (header, expected) in [
        ("cookie", 404),
        ("origin", 403),
        ("x-session-proof", 403),
        ("x-stellar-approval-csrf", 403),
        ("host", 421),
        ("hostile-host", 421),
    ] {
        let (status, _) = h
            .post(
                "challenge",
                json!({"consent_view_digest": h.digest()}),
                header,
            )
            .await;
        assert_eq!(status.as_u16(), expected, "{header}");
        assert!(h.state.challenges.lock().unwrap().is_empty());
    }
    let options = h.challenge().await;
    assert_eq!(options["rp_id"], "localhost");
    h.no_consent();
    for timeout in [
        crate::auth::SESSION_IDLE_TIMEOUT,
        crate::auth::SESSION_ABSOLUTE_TIMEOUT,
    ] {
        let h = Harness::new();
        {
            let mut auth = h.state.auth.lock().unwrap();
            let session = auth.session.as_mut().unwrap();
            session.created_at -= timeout;
            if timeout == crate::auth::SESSION_IDLE_TIMEOUT {
                session.last_activity_at -= timeout;
            }
        }
        for _ in 0..2 {
            let mut headers = HeaderMap::new();
            headers.insert("cookie", h.cookie.parse().unwrap());
            assert_eq!(
                require_session(&h.state.auth, &headers)
                    .err()
                    .unwrap()
                    .status(),
                StatusCode::NOT_FOUND
            );
            assert_eq!(
                h.post("challenge", json!({"consent_view_digest": h.digest()}), "")
                    .await
                    .0,
                StatusCode::NOT_FOUND
            );
        }
        assert!(h.state.challenges.lock().unwrap().is_empty());
        h.no_consent();
    }
}

#[tokio::test]
#[serial_test::serial]
async fn mainnet_challenge_refuses_a_changed_rendered_view() {
    for one_shot in [false, true] {
        for change in ["envelope", "created", "expiry", "policy", "malformed"] {
            let mut h = Harness::new();
            let completion = one_shot.then(|| h.one_shot());
            let rendered = detail(&h.state, &h.session, &h.entry.approval_nonce);
            let html = String::from_utf8(
                to_bytes(rendered.into_body(), 65536)
                    .await
                    .unwrap()
                    .to_vec(),
            )
            .unwrap();
            let data =
                crate::operator_enroll::test_support::island(&html, "presence-data").unwrap();
            let mut digest = data["consent_view_digest"].as_str().unwrap().to_owned();
            match change {
                "policy" => h.fixture.sign_policy(&[&fixture_authenticator()]),
                "malformed" => digest = "not-a-digest".to_owned(),
                _ => {
                    let mut entry = h.entry.clone();
                    match change {
                        "envelope" => {
                            entry.kind = stellar_agent_core::approval::fixtures::payment_pending(
                                stellar_agent_core::approval::mainnet_fixtures::ALLOWED_DESTINATION,
                                stellar_agent_core::approval::mainnet_fixtures::ALLOWED_DESTINATION,
                                "XLM",
                                20,
                                Some("replacement"),
                                100,
                                7,
                                process_uid_for_attestation().unwrap(),
                                600_000,
                            )
                            .kind;
                        }
                        "created" => entry.created_at_unix_ms -= 1,
                        "expiry" => entry.expires_at_unix_ms -= 1,
                        _ => unreachable!(),
                    }
                    h.replace_entry(entry);
                }
            }
            let (status, body) = h
                .post("challenge", json!({"consent_view_digest": digest}), "")
                .await;
            assert_eq!(status, StatusCode::CONFLICT, "{change} {body}");
            assert_eq!(body["error"], "approval.presence_changed", "{change}");
            assert!(h.state.challenges.lock().unwrap().is_empty());
            h.no_consent();
            let options = h.challenge().await;
            let (status, body) = h.post("assertion", h.signed(&options, 5), "").await;
            assert_eq!(status, StatusCode::OK, "{change} {body}");
            if let Some(completion) = completion {
                assert_eq!(
                    completion.await.unwrap().unwrap().approval_nonce(),
                    h.entry.approval_nonce
                );
                h.no_consent();
            }
        }
    }
}

#[tokio::test]
#[serial_test::serial]
async fn mainnet_assertion_challenge_is_single_use() {
    let h = Harness::new();
    let options = h.challenge().await;
    let bad = h.signed(&options, 1);
    assert_eq!(
        h.post("assertion", bad, "").await.1["error"],
        "approval.presence_invalid"
    );
    let valid = h.signed(&options, 5);
    assert_eq!(
        h.post("assertion", valid, "").await.1["error"],
        "approval.presence_consumed"
    );
    h.no_consent();
    let expired = issue_mainnet_presence(
        &h.entry,
        &h.fixture.binding(),
        &h.fixture.current_policy(),
        &h.state.origin,
        now_ms().unwrap(),
        Instant::now() - std::time::Duration::from_secs(121),
    )
    .unwrap();
    let expired_options = serde_json::to_value(expired.options()).unwrap();
    h.state.challenges.lock().unwrap().insert(
        (
            h.session.session_id.to_hex(),
            h.entry.approval_nonce.clone(),
        ),
        Challenge {
            pending: expired,
            view_digest: h.digest(),
        },
    );
    assert_eq!(
        h.post("assertion", h.signed(&expired_options, 5), "")
            .await
            .1["error"],
        "approval.presence_expired"
    );
    let restarted = h.challenge().await;
    h.state.challenges.lock().unwrap().clear();
    assert_eq!(
        h.post("assertion", h.signed(&restarted, 5), "").await.1["error"],
        "approval.presence_consumed"
    );
    let replaced = h.challenge().await;
    let current = h.challenge().await;
    assert_eq!(
        h.post("assertion", h.signed(&replaced, 5), "").await.1["error"],
        "approval.presence_consumed"
    );
    assert_eq!(
        h.post("cancel", json!({"reason": "operator_cancel"}), "")
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        h.post("assertion", h.signed(&current, 5), "").await.1["error"],
        "approval.presence_consumed"
    );
    let options = h.challenge().await;
    let valid = h.signed(&options, 5);
    let (first, second) = tokio::join!(
        h.post("assertion", valid.clone(), ""),
        h.post("assertion", valid, "")
    );
    assert_eq!(
        [first.0, second.0]
            .iter()
            .filter(|&&s| s == StatusCode::OK)
            .count(),
        1
    );
    assert_eq!(
        std::fs::read_to_string(h.fixture.audit_path())
            .unwrap()
            .matches("approval_attested")
            .count(),
        1
    );
    drop(h);
    let h = Harness::new();
    let token = OpaqueToken::generate();
    let token_hex = token.to_hex();
    let mut auth = AuthState::new(token, SessionPurpose::Inbox);
    let second_session = auth.exchange_bootstrap(&token_hex, Instant::now()).unwrap();
    let second_cookie = auth
        .set_cookie_value(&second_session)
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let second = PresenceState::inbox(
        Arc::new(Mutex::new(auth)),
        h.decision(),
        h.state.identity.clone(),
        4100,
    )
    .unwrap();
    let first_options = h.challenge().await;
    let first_assertion = h.signed(&first_options, 5);
    assert_eq!(
        post_for(
            &second,
            (&second_session, &second_cookie),
            &h.entry.approval_nonce,
            "assertion",
            first_assertion.clone(),
            ""
        )
        .await
        .1["error"],
        "approval.presence_consumed"
    );
    let other = h.fixture.payment(600_000);
    assert_eq!(
        post_for(
            &h.state,
            (&h.session, &h.cookie),
            &other.approval_nonce,
            "assertion",
            first_assertion.clone(),
            ""
        )
        .await
        .1["error"],
        "approval.presence_consumed"
    );
    let (status, second_options) = post_for(
        &second,
        (&second_session, &second_cookie),
        &h.entry.approval_nonce,
        "challenge",
        json!({"consent_view_digest": h.digest()}),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (first, second) = tokio::join!(
        h.post("assertion", first_assertion, ""),
        post_for(
            &second,
            (&second_session, &second_cookie),
            &h.entry.approval_nonce,
            "assertion",
            h.signed(&second_options, 5),
            ""
        )
    );
    assert_eq!(
        [first.0, second.0]
            .iter()
            .filter(|&&status| status == StatusCode::OK)
            .count(),
        1
    );
    assert_eq!(
        std::fs::read_to_string(h.fixture.audit_path())
            .unwrap()
            .matches("approval_attested")
            .count(),
        1
    );
}

#[tokio::test]
#[serial_test::serial]
async fn mainnet_local_approve_route_requires_assertion() {
    let h = Harness::new();
    let outcome = apply_decision(
        &h.decision(),
        Decision::Approve {
            nonce: h.entry.approval_nonce.clone(),
            shown_view_digest: Some(approval_view_digest(&h.entry, &h.fixture.binding()).unwrap()),
        },
        RequestIdentity::Local,
    );
    assert!(matches!(
        outcome,
        crate::Outcome::PresenceRefused {
            code: "approval.presence_required",
            ..
        }
    ));
    h.no_consent();
    let router = layers(
        routes(h.state.clone()).route(
            "/approval/{nonce}/approve",
            post(stale_approve).with_state(h.state.clone()),
        ),
        "127.0.0.1:4100".parse().unwrap(),
    );
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/approval/{}/approve", h.entry.approval_nonce))
                .header("host", "localhost:4100")
                .header("origin", &h.state.origin)
                .header("cookie", &h.cookie)
                .header("x-session-proof", h.session.session_proof.to_hex())
                .header(
                    "x-stellar-approval-csrf",
                    compute_csrf(&h.session.csrf_key, &h.entry.approval_nonce),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    h.no_consent();
    let options = h.challenge().await;
    let (status, body) = h.post("assertion", h.signed(&options, 5), "").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "attested");
    let store = PendingApprovalStore::open(h.fixture.store_path()).unwrap();
    let blob = URL_SAFE_NO_PAD
        .decode(body["attestation"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let stellar_agent_core::approval::ApprovalKind::PaymentSimulated {
        envelope_xdr_b64, ..
    } = &h.entry.kind
    else {
        unreachable!()
    };
    let expected = stellar_agent_core::approval::witness::ApprovalExpectation {
        kind: stellar_agent_core::approval::witness::ApprovedKind::Payment,
        subject: stellar_agent_core::approval::subject::approval_subject_classic(envelope_xdr_b64),
    };
    stellar_agent_core::approval::witness::verify_approval(
        &store,
        h.fixture.profile(),
        h.fixture.name(),
        &h.entry.approval_nonce,
        &blob,
        &expected,
        &h.fixture.current_policy(),
        now_ms().unwrap(),
    )
    .unwrap();
}

#[tokio::test]
#[serial_test::serial]
async fn mainnet_wait_releases_pending_lock() {
    let fixture = MainnetConsentFixture::new("listener");
    let entry = fixture.payment(600_000);
    let mut store = PendingApprovalStore::open(fixture.store_path()).unwrap();
    store.insert(entry.clone(), now_ms().unwrap()).unwrap();
    drop(store);
    let mut handle = start_mainnet_presence(MainnetPresenceConfig {
        entry: entry.clone(),
        context: ApprovalContext::from_profile(fixture.name(), fixture.profile()),
        authority: fixture.authority(),
        store_path: fixture.store_path(),
        page_identity: PageIdentity::neutral(),
    })
    .await
    .unwrap();
    let client =
        test_support::PresenceClient::connect(handle.bootstrap_url(), &entry.approval_nonce)
            .await
            .unwrap();
    let options = client.challenge().await.unwrap().json();
    let mut store = PendingApprovalStore::open(fixture.store_path()).unwrap();
    let other = fixture.payment(600_000);
    store.insert(other.clone(), now_ms().unwrap()).unwrap();
    let mut replacement = entry.clone();
    replacement.expires_at_unix_ms -= 1;
    assert!(store.remove(&entry.approval_nonce).unwrap());
    store
        .insert(replacement.clone(), now_ms().unwrap())
        .unwrap();
    drop(store);
    let response = client
        .post("assertion", &signed(&options, &client.origin(), 5))
        .await
        .unwrap();
    assert_eq!(response.status, 409);
    assert_eq!(response.json()["error"], "approval.presence_changed");
    let store = PendingApprovalStore::open(fixture.store_path()).unwrap();
    assert_eq!(
        store.get(&entry.approval_nonce).unwrap().expires_at_unix_ms,
        replacement.expires_at_unix_ms
    );
    assert!(store.get(&other.approval_nonce).is_some());
    drop(store);
    client
        .post("cancel", &json!({"reason": "operator_cancel"}))
        .await
        .unwrap();
    assert_eq!(
        handle
            .await_presence(Instant::now() + std::time::Duration::from_secs(1))
            .await
            .unwrap_err()
            .code(),
        "approval.presence_canceled"
    );
    handle.shutdown().await.unwrap();
    assert!(
        PendingApprovalStore::open(fixture.store_path())
            .unwrap()
            .get(&entry.approval_nonce)
            .unwrap()
            .attestation_blob_b64
            .is_none()
    );
}

#[tokio::test]
#[serial_test::serial]
async fn mainnet_policy_revocation_during_ceremony_refuses() {
    let mut fixture = MainnetConsentFixture::new("listener-revocation");
    let entry = fixture.payment(600_000);
    let mut store = PendingApprovalStore::open(fixture.store_path()).unwrap();
    store.insert(entry.clone(), now_ms().unwrap()).unwrap();
    drop(store);
    let mut handle = start_mainnet_presence(MainnetPresenceConfig {
        entry: entry.clone(),
        context: ApprovalContext::from_profile(fixture.name(), fixture.profile()),
        authority: fixture.authority(),
        store_path: fixture.store_path(),
        page_identity: PageIdentity::neutral(),
    })
    .await
    .unwrap();
    let client =
        test_support::PresenceClient::connect(handle.bootstrap_url(), &entry.approval_nonce)
            .await
            .unwrap();
    let options = client.challenge().await.unwrap().json();
    let replacement = stellar_agent_test_support::webauthn::TestAuthenticator::from_seed(
        [0x33; 32],
        vec![0x77; 32],
    );
    fixture.sign_policy(&[&replacement]);
    let response = client
        .post("assertion", &signed(&options, &client.origin(), 5))
        .await
        .unwrap();
    assert_eq!(response.status, 409);
    assert_eq!(response.json()["error"], "approval.presence_changed");
    assert!(
        PendingApprovalStore::open(fixture.store_path())
            .unwrap()
            .get(&entry.approval_nonce)
            .unwrap()
            .mainnet_presence
            .is_none()
    );
    assert_eq!(
        client
            .post("cancel", &json!({"reason": "operator_cancel"}))
            .await
            .unwrap()
            .status,
        200
    );
    assert_eq!(
        handle
            .await_presence(Instant::now() + std::time::Duration::from_secs(1))
            .await
            .unwrap_err()
            .code(),
        "approval.presence_canceled"
    );
    handle.shutdown().await.unwrap();
}

#[tokio::test]
#[serial_test::serial]
async fn mainnet_x402_presence_binds_the_authoritative_intent() {
    use sha2::Digest as _;
    use stellar_xdr::{
        AccountId, ContractId, Hash, InvokeContractArgs, PublicKey, ScAddress, ScVal,
        SorobanAuthorizedFunction, SorobanAuthorizedInvocation, Uint256,
    };
    for home in [None, Some("merchant.example".to_owned())] {
        let account = |byte| {
            ScVal::Address(ScAddress::Account(AccountId(
                PublicKey::PublicKeyTypeEd25519(Uint256([byte; 32])),
            )))
        };
        let root = SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                contract_address: ScAddress::Contract(ContractId(Hash([3; 32]))),
                function_name: "transfer".try_into().unwrap(),
                args: vec![account(4), account(5), ScVal::from(10_i128)]
                    .try_into()
                    .unwrap(),
            }),
            sub_invocations: vec![].try_into().unwrap(),
        };
        let entry = PendingApproval::new_x402_pending(
            &sha2::Sha256::digest(
                stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE.as_bytes(),
            )
            .into(),
            &root,
            home.clone(),
            process_uid_for_attestation().unwrap(),
            600_000,
        )
        .unwrap();
        for change in ["invocation", "home", "amount", "recipient"] {
            let mut h = Harness::new();
            h.replace_entry(entry.clone());
            let page = detail(&h.state, &h.session, &h.entry.approval_nonce);
            let html = String::from_utf8(to_bytes(page.into_body(), 65536).await.unwrap().to_vec())
                .unwrap();
            let stellar_agent_core::approval::ApprovalKind::X402Payment {
                intent_digest,
                payee,
                ..
            } = &h.entry.kind
            else {
                unreachable!()
            };
            assert!(html.contains(&hex::encode(intent_digest)));
            assert!(html.contains(payee));
            assert!(html.contains("<dt>Amount (token base units)</dt><dd>10</dd>"));
            if let Some(home) = &home {
                assert!(html.contains(home));
            }
            let options = h.challenge().await;
            let mut changed_root = root.clone();
            let SorobanAuthorizedFunction::ContractFn(function) = &mut changed_root.function else {
                unreachable!()
            };
            match change {
                "invocation" => {
                    function.contract_address = ScAddress::Contract(ContractId(Hash([9; 32])))
                }
                "amount" => {
                    function.args = vec![account(4), account(5), ScVal::from(11_i128)]
                        .try_into()
                        .unwrap()
                }
                "recipient" => {
                    function.args = vec![account(4), account(6), ScVal::from(10_i128)]
                        .try_into()
                        .unwrap()
                }
                _ => {}
            }
            let changed_home = if change == "home" {
                Some("changed.example".to_owned())
            } else {
                home.clone()
            };
            let mut replacement = PendingApproval::new_x402_pending(
                &sha2::Sha256::digest(
                    stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE.as_bytes(),
                )
                .into(),
                &changed_root,
                changed_home,
                entry.process_uid.clone(),
                600_000,
            )
            .unwrap();
            replacement.approval_nonce = entry.approval_nonce.clone();
            replacement.created_at_unix_ms = entry.created_at_unix_ms;
            replacement.expires_at_unix_ms = entry.expires_at_unix_ms;
            h.replace_entry(replacement);
            let (status, body) = h.post("assertion", h.signed(&options, 5), "").await;
            assert_eq!(status, StatusCode::CONFLICT, "{change} {body}");
            assert_eq!(body["error"], "approval.presence_changed");
            h.no_consent();
            let options = h.challenge().await;
            let (status, body) = h.post("assertion", h.signed(&options, 5), "").await;
            assert_eq!(status, StatusCode::OK, "{change} {body}");
        }
        let fixture = MainnetConsentFixture::new("listener-x402");
        let mut store = PendingApprovalStore::open(fixture.store_path()).unwrap();
        store.insert(entry.clone(), now_ms().unwrap()).unwrap();
        drop(store);
        let mut handle = start_mainnet_presence(MainnetPresenceConfig {
            entry: entry.clone(),
            context: ApprovalContext::from_profile(fixture.name(), fixture.profile()),
            authority: fixture.authority(),
            store_path: fixture.store_path(),
            page_identity: PageIdentity::neutral(),
        })
        .await
        .unwrap();
        let client =
            test_support::PresenceClient::connect(handle.bootstrap_url(), &entry.approval_nonce)
                .await
                .unwrap();
        let options = client.challenge().await.unwrap().json();
        assert_eq!(
            client
                .post("assertion", &signed(&options, &client.origin(), 5))
                .await
                .unwrap()
                .status,
            200
        );
        let presence = handle
            .await_presence(Instant::now() + std::time::Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(presence.approval_nonce(), entry.approval_nonce);
        handle.shutdown().await.unwrap();
    }
}

/// The page body of `response` as text.
async fn page_text(response: Response) -> (StatusCode, String) {
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 262_144).await.unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

/// A ceremony's bootstrap lands on the consent page of its one entry under
/// the consent storage key; the inbox's presence state serves no bootstrap.
#[tokio::test]
#[serial_test::serial]
async fn one_shot_bootstrap_lands_on_the_consent_page() {
    let mut h = Harness::new();
    let token = OpaqueToken::generate();
    let token_hex = token.to_hex();
    let inbox_token = OpaqueToken::generate();
    let inbox_hex = inbox_token.to_hex();
    Arc::get_mut(&mut h.state).unwrap().auth = Arc::new(Mutex::new(AuthState::new(
        inbox_token,
        SessionPurpose::Inbox,
    )));
    assert_eq!(
        bootstrap(State(h.state.clone()), Path(inbox_hex))
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    Arc::get_mut(&mut h.state).unwrap().auth = Arc::new(Mutex::new(AuthState::new(
        token,
        SessionPurpose::MainnetPresence,
    )));
    let _completion = h.one_shot();
    let (status, html) = page_text(bootstrap(State(h.state.clone()), Path(token_hex)).await).await;
    assert_eq!(status, StatusCode::OK);
    let island =
        crate::operator_enroll::test_support::island(&html, "session-bootstrap-data").unwrap();
    assert_eq!(
        island["next"],
        format!("/approval/{}", h.entry.approval_nonce)
    );
    assert_eq!(
        island["storageKey"],
        "stellar-agent-mainnet-presence-session-proof"
    );
    assert_eq!(h.entry.approval_nonce.len(), 22);
}

/// A ceremony's cancel completes its command with the refusal of the
/// reason: the browser-unavailable reason with the browser-required
/// refusal, and any reason after the entry's deadline with expiry.
#[tokio::test]
#[serial_test::serial]
async fn one_shot_cancel_completes_with_the_reason_or_expiry() {
    for (reason, status, code) in [
        (
            "browser_unavailable",
            "browser_unavailable",
            "approval.presence_browser_required",
        ),
        ("operator_cancel", "canceled", "approval.presence_canceled"),
        (
            "authenticator_canceled",
            "canceled",
            "approval.presence_canceled",
        ),
    ] {
        let mut h = Harness::new();
        let completion = h.one_shot();
        let (http, body) = h.post("cancel", json!({"reason": reason}), "").await;
        assert_eq!(http, StatusCode::OK, "{reason} {body}");
        assert_eq!(body["status"], status, "{reason}");
        assert_eq!(
            completion.await.unwrap().unwrap_err().code(),
            code,
            "{reason}"
        );
        h.no_consent();
    }
    for reason in ["browser_unavailable", "operator_cancel"] {
        let mut h = Harness::new();
        let completion = h.one_shot_until(now_ms().unwrap() - 1);
        let (http, body) = h.post("cancel", json!({"reason": reason}), "").await;
        assert_eq!(http, StatusCode::CONFLICT, "{reason} {body}");
        assert_eq!(body["error"], "approval.presence_expired", "{reason}");
        assert_eq!(
            completion.await.unwrap().unwrap_err().code(),
            "approval.presence_expired",
            "{reason}"
        );
        h.no_consent();
    }
}

/// The ceremony listener starts only for the entry the store holds: a
/// presented entry whose consent view differs refuses with a changed entry,
/// a policy that cannot be verified with the policy refusal, and an
/// unreadable store with the unavailable refusal.
#[tokio::test]
#[serial_test::serial]
async fn start_refusals_keep_their_codes() {
    let fixture = MainnetConsentFixture::new("start-refusals");
    let entry = fixture.payment(600_000);
    let mut store = PendingApprovalStore::open(fixture.store_path()).unwrap();
    store.insert(entry.clone(), now_ms().unwrap()).unwrap();
    drop(store);
    let config = |entry: &PendingApproval, store_path: PathBuf| MainnetPresenceConfig {
        entry: entry.clone(),
        context: ApprovalContext::from_profile(fixture.name(), fixture.profile()),
        authority: fixture.authority(),
        store_path,
        page_identity: PageIdentity::neutral(),
    };
    let refusal = |result: Result<MainnetPresenceHandle, ServeStartError>| match result {
        Err(ServeStartError::Presence(refusal)) => refusal,
        other => panic!("expected a presence refusal, got {other:?}"),
    };
    let mut presented = entry.clone();
    presented.expires_at_unix_ms -= 1;
    assert_eq!(
        refusal(start_mainnet_presence(config(&presented, fixture.store_path())).await),
        PresenceStartRefusal::Changed
    );
    let mut other = entry.clone();
    other.approval_nonce = "BBBBBBBBBBBBBBBBBBBBBB".to_owned();
    assert_eq!(
        refusal(start_mainnet_presence(config(&other, fixture.store_path())).await),
        PresenceStartRefusal::Changed
    );
    let error = refusal(start_mainnet_presence(config(&entry, fixture.home().to_path_buf())).await);
    assert_eq!(error, PresenceStartRefusal::Unavailable);
    assert_eq!(error.failure().code(), "approval.presence_unavailable");
    let policy = std::fs::read(fixture.policy_path()).unwrap();
    std::fs::write(fixture.policy_path(), b"version = 2\n").unwrap();
    let error = refusal(start_mainnet_presence(config(&entry, fixture.store_path())).await);
    assert_eq!(error, PresenceStartRefusal::PolicyUnavailable);
    assert_eq!(
        ServeStartError::Presence(error).to_string(),
        error.failure().to_string()
    );
    assert_eq!(
        ServeStartError::Presence(error)
            .presence_failure()
            .unwrap()
            .code(),
        "approval.presence_policy_unavailable"
    );
    std::fs::write(fixture.policy_path(), policy).unwrap();
    let mut handle = start_mainnet_presence(config(&entry, fixture.store_path()))
        .await
        .unwrap();
    handle.shutdown().await.unwrap();
}

/// A listener on `[::1]:P` for a port P that is free on `127.0.0.1` when
/// this returns.
fn ipv6_competitor() -> (std::net::TcpListener, u16) {
    for _ in 0..64 {
        let listener = std::net::TcpListener::bind("[::1]:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return (listener, port);
        }
    }
    panic!("no port free on 127.0.0.1 among 64 held on ::1");
}

/// A competitor holding `[::1]` on the ceremony's port makes the start
/// refuse before any token exists: the pair binder runs with no token
/// generated, the refusal names the IPv6 family, and no token is generated
/// after it.
#[tokio::test]
#[serial_test::serial]
async fn presence_refuses_when_ipv6_is_held_and_mints_no_token() {
    let fixture = MainnetConsentFixture::new("pair-refusal");
    let entry = fixture.payment(600_000);
    let mut store = PendingApprovalStore::open(fixture.store_path()).unwrap();
    store.insert(entry.clone(), now_ms().unwrap()).unwrap();
    drop(store);
    let (_competitor, port) = ipv6_competitor();
    let before = crate::auth::tokens_generated_on_this_thread();
    let at_bind = Arc::new(Mutex::new(None));
    let record = Arc::clone(&at_bind);
    let result = start_mainnet_presence_with(
        MainnetPresenceConfig {
            entry: entry.clone(),
            context: ApprovalContext::from_profile(fixture.name(), fixture.profile()),
            authority: fixture.authority(),
            store_path: fixture.store_path(),
            page_identity: PageIdentity::neutral(),
        },
        move || {
            *record.lock().unwrap() = Some(crate::auth::tokens_generated_on_this_thread());
            LoopbackPair::bind(port)
        },
    )
    .await;
    let error = match result {
        Err(error) => error,
        Ok(_) => panic!("presence must refuse while [::1]:{port} is held"),
    };
    assert_eq!(
        error.loopback_pair(),
        Some(&PairBindError::PortUnavailable {
            port,
            family: crate::LoopbackFamily::V6,
            kind: std::io::ErrorKind::AddrInUse,
        })
    );
    assert!(error.presence_failure().is_none());
    assert_eq!(
        *at_bind.lock().unwrap(),
        Some(before),
        "the pair is bound before any token is generated"
    );
    assert_eq!(
        crate::auth::tokens_generated_on_this_thread(),
        before,
        "a refused start generates no token"
    );
    assert!(
        std::net::TcpListener::bind(("127.0.0.1", port)).is_ok(),
        "the refused start releases its IPv4 listener"
    );
}

/// The session the bootstrap opens over `127.0.0.1` is the session the
/// listener serves over `[::1]`: the challenge and the assertion sent there
/// complete the command's wait, and shutdown closes both addresses.
#[tokio::test]
#[serial_test::serial]
async fn presence_serves_one_session_on_both_families() {
    let fixture = MainnetConsentFixture::new("pair-session");
    let entry = fixture.payment(600_000);
    let mut store = PendingApprovalStore::open(fixture.store_path()).unwrap();
    store.insert(entry.clone(), now_ms().unwrap()).unwrap();
    drop(store);
    let mut handle = start_mainnet_presence(MainnetPresenceConfig {
        entry: entry.clone(),
        context: ApprovalContext::from_profile(fixture.name(), fixture.profile()),
        authority: fixture.authority(),
        store_path: fixture.store_path(),
        page_identity: PageIdentity::neutral(),
    })
    .await
    .unwrap();
    let client =
        test_support::PresenceClient::connect(handle.bootstrap_url(), &entry.approval_nonce)
            .await
            .unwrap();
    let port: u16 = handle
        .bootstrap_url()
        .strip_prefix("http://localhost:")
        .and_then(|rest| rest.split('/').next())
        .unwrap()
        .parse()
        .unwrap();
    let ipv6 = SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, port));
    let client = client.at(ipv6);
    let challenge = client.challenge().await.unwrap();
    assert_eq!(challenge.status, 200, "{}", challenge.body);
    let options = challenge.json();
    let response = client
        .post("assertion", &signed(&options, &client.origin(), 5))
        .await
        .unwrap();
    assert_eq!(response.status, 200, "{}", response.body);
    let presence = handle
        .await_presence(Instant::now() + std::time::Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(presence.approval_nonce(), entry.approval_nonce);
    handle.shutdown().await.unwrap();
    for addr in [SocketAddr::from(([127, 0, 0, 1], port)), ipv6] {
        assert!(
            tokio::net::TcpStream::connect(addr).await.is_err(),
            "{addr} closed after shutdown"
        );
    }
}

/// Every presence refusal answers its code in one body shape with the
/// status of its kind, and a failure that is not one is a server error.
#[test]
fn refusal_statuses_follow_the_variant() {
    use stellar_agent_core::ApprovalFailure as F;
    for (failure, status) in [
        (F::PresenceRequired, StatusCode::FORBIDDEN),
        (F::PresenceInvalid, StatusCode::FORBIDDEN),
        (F::PresenceBrowserRequired, StatusCode::FORBIDDEN),
        (F::PresenceCanceled, StatusCode::FORBIDDEN),
        (F::MainnetRemoteUnsupported, StatusCode::FORBIDDEN),
        (F::ListenerPolicyStale, StatusCode::FORBIDDEN),
        (F::OriginSignedRemote, StatusCode::FORBIDDEN),
        (F::PresenceExpired, StatusCode::CONFLICT),
        (F::PresenceConsumed, StatusCode::CONFLICT),
        (F::PresenceChanged, StatusCode::CONFLICT),
        (
            F::PresencePolicyUnavailable,
            StatusCode::SERVICE_UNAVAILABLE,
        ),
        (F::PresenceUnavailable, StatusCode::SERVICE_UNAVAILABLE),
    ] {
        let code = failure.code();
        assert_eq!(refusal_status(&failure), status, "{code}");
        assert_eq!(refusal_status_of_code(code), status, "{code}");
        let crate::Outcome::PresenceRefused {
            code: refused,
            message,
        } = crate::decision::presence_refusal(&WalletError::Approval(failure)).unwrap()
        else {
            unreachable!()
        };
        assert_eq!(refused, code);
        let response = outcome_to_response(crate::Outcome::PresenceRefused {
            code: refused,
            message,
        });
        assert_eq!(response.status(), status, "{code}");
    }
    assert_eq!(
        refusal_status(&F::NotFound {
            detail: String::new()
        }),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        refusal_status_of_code("approval.not_found"),
        StatusCode::INTERNAL_SERVER_ERROR
    );
}

/// The consent page keeps the inbox detail route's entry outcomes: an
/// unknown entry is the not-found page with 404, and an expired, rejected
/// or spent entry is its detail card with its notice and no passkey
/// consent; the inbox still offers the reject the detail route offers.
/// Only the inbox, which has a reject route, promises rejection after
/// expiry; the one-shot ceremony points an expired request at a new one.
#[tokio::test]
#[serial_test::serial]
async fn mainnet_detail_keeps_entry_outcomes() {
    use stellar_agent_core::approval::ConsumedOutcome;
    for one_shot in [false, true] {
        let mode = if one_shot { "one-shot" } else { "inbox" };
        let mut h = Harness::new();
        let _completion = one_shot.then(|| h.one_shot());
        let (status, html) = page_text(detail(&h.state, &h.session, &h.entry.approval_nonce)).await;
        assert_eq!(status, StatusCode::OK, "{mode}");
        assert!(html.contains("presence-approve"), "{mode}");
        assert_eq!(
            html.matches(stellar_agent_loopback_http::brand::BRAND_STYLE)
                .count(),
            1
        );
        assert_eq!(html.contains("only be rejected"), !one_shot, "{mode}");

        let missing = if one_shot {
            let mut store = PendingApprovalStore::open(h.fixture.store_path()).unwrap();
            assert!(store.remove(&h.entry.approval_nonce).unwrap());
            drop(store);
            h.entry.approval_nonce.clone()
        } else {
            "AAAAAAAAAAAAAAAAAAAAAA".to_owned()
        };
        let (status, html) = page_text(detail(&h.state, &h.session, &missing)).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{mode}");
        assert!(html.contains("Approval not found"), "{mode} {html}");

        for outcome in ["expired", "rejected", "consumed"] {
            let mut h = Harness::new();
            if outcome == "expired" {
                let entry = h.fixture.payment(1);
                let mut store = PendingApprovalStore::open(h.fixture.store_path()).unwrap();
                assert!(store.remove(&h.entry.approval_nonce).unwrap());
                store.insert(entry.clone(), now_ms().unwrap()).unwrap();
                drop(store);
                h.entry = entry;
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            let _completion = one_shot.then(|| h.one_shot());
            let mut store = PendingApprovalStore::open(h.fixture.store_path()).unwrap();
            match outcome {
                "rejected" => {
                    assert!(
                        store
                            .reject(&h.entry.approval_nonce, now_ms().unwrap(), 3_600_000)
                            .unwrap()
                    );
                }
                "consumed" => {
                    assert!(
                        store
                            .consume(
                                &h.entry.approval_nonce,
                                &"ab".repeat(32),
                                ConsumedOutcome::Confirmed
                            )
                            .unwrap()
                    );
                }
                _ => {}
            }
            drop(store);
            let (status, html) =
                page_text(detail(&h.state, &h.session, &h.entry.approval_nonce)).await;
            assert_eq!(status, StatusCode::OK, "{mode} {outcome} {html}");
            let notice = match outcome {
                "expired" if one_shot => {
                    "This request has expired. Restart the command for a new request."
                }
                "expired" => "This request has expired. It can only be rejected now.",
                "rejected" => "This request was rejected. Nothing was signed.",
                _ => "This approval was already spent on a submission.",
            };
            assert!(html.contains(notice), "{mode} {outcome}");
            assert_eq!(
                html.contains("only be rejected"),
                !one_shot && outcome == "expired",
                "{mode} {outcome}"
            );
            assert!(!html.contains("presence-approve"), "{mode} {outcome}");
            assert!(!html.contains("approve-btn"), "{mode} {outcome}");
            assert_eq!(
                html.contains("reject-btn"),
                !one_shot && outcome == "expired",
                "{mode} {outcome}"
            );
            h.no_consent();
        }
    }
}

/// The consent actions answer a settled or missing entry with the inbox
/// decision routes' entry outcomes, never with a presence refusal: an
/// unknown entry is not found, an expired one expired, and a rejected or
/// spent one already resolved, each with 200 and no challenge issued.
#[tokio::test]
#[serial_test::serial]
async fn mainnet_actions_keep_entry_outcomes() {
    use stellar_agent_core::approval::ConsumedOutcome;
    for one_shot in [false, true] {
        let mode = if one_shot { "one-shot" } else { "inbox" };
        for (outcome, status) in [
            ("missing", "not_found"),
            ("expired", "expired"),
            ("rejected", "already_resolved"),
            ("consumed", "already_resolved"),
        ] {
            let mut h = Harness::new();
            if outcome == "expired" {
                h.replace_entry(h.fixture.payment(1));
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            let _completion = one_shot.then(|| h.one_shot());
            let mut store = PendingApprovalStore::open(h.fixture.store_path()).unwrap();
            match outcome {
                "missing" => assert!(store.remove(&h.entry.approval_nonce).unwrap()),
                "rejected" => assert!(
                    store
                        .reject(&h.entry.approval_nonce, now_ms().unwrap(), 3_600_000)
                        .unwrap()
                ),
                "consumed" => assert!(
                    store
                        .consume(
                            &h.entry.approval_nonce,
                            &"ab".repeat(32),
                            ConsumedOutcome::Confirmed
                        )
                        .unwrap()
                ),
                _ => {}
            }
            drop(store);
            let (http, body) = h
                .post("challenge", json!({"consent_view_digest": h.digest()}), "")
                .await;
            assert_eq!(http, StatusCode::OK, "{mode} {outcome} {body}");
            assert_eq!(body["status"], status, "{mode} {outcome} {body}");
            assert!(body.get("challenge").is_none(), "{mode} {outcome}");
            if outcome == "missing" {
                assert!(
                    PendingApprovalStore::open(h.fixture.store_path())
                        .unwrap()
                        .get(&h.entry.approval_nonce)
                        .is_none(),
                    "{mode}"
                );
            } else {
                h.no_consent();
            }
        }
    }
}

/// A policy rotation while a decision waits on the attestation key refuses
/// the consent. The compare-only load after the waits admits the rotated
/// policy, a validly signed higher sequence. Core then compares that policy
/// with the one the presence was verified under, and the receipt names the
/// replaced policy; either mismatch answers
/// `approval.presence_policy_unavailable`, and nothing is recorded.
#[tokio::test]
#[serial_test::serial]
async fn mainnet_decision_rereads_the_policy_after_its_waits() {
    let mut h = Harness::new();
    let path = h.fixture.policy_path();
    let current = std::fs::read(&path).unwrap();
    h.fixture.sign_policy(&[&fixture_authenticator()]);
    let rotated = std::fs::read(&path).unwrap();
    std::fs::write(&path, &current).unwrap();
    let options = h.challenge().await;
    let assertion = h.signed(&options, 5);
    let fired = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let hook_fired = fired.clone();
    crate::decision::wait_hook::install(move || {
        std::fs::write(&path, &rotated).unwrap();
        hook_fired.store(true, std::sync::atomic::Ordering::SeqCst);
    });
    let (status, body) = h.post("assertion", assertion, "").await;
    assert!(fired.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(
        body["error"], "approval.presence_policy_unavailable",
        "{body}"
    );
    h.no_consent();
    assert!(
        PendingApprovalStore::open(h.fixture.store_path())
            .unwrap()
            .get(&h.entry.approval_nonce)
            .unwrap()
            .mainnet_presence
            .is_none()
    );
    assert!(
        !std::fs::read_to_string(h.fixture.audit_path())
            .unwrap_or_default()
            .contains("approval_attested")
    );
}

/// A mainnet inbox started on an ephemeral port issues challenges for the
/// origin of the port it bound: an assertion for that origin records the
/// consent, one for another port is refused.
#[tokio::test]
#[serial_test::serial]
async fn inbox_presence_origin_carries_the_bound_port() {
    let inbox = MainnetInbox::start("inbox-origin").await;
    let port = inbox.handle.local_addr().port();
    let client = inbox.client().await;
    assert_eq!(client.origin(), format!("http://localhost:{port}"));
    assert_eq!(client.data()["mode"], "inbox");
    let options = client.challenge().await.unwrap().json();
    let other = format!("http://localhost:{}", port.wrapping_add(1));
    let refused = client
        .post("assertion", &signed(&options, &other, 5))
        .await
        .unwrap();
    assert_eq!(refused.status, 403, "{}", refused.body);
    assert_eq!(refused.json()["error"], "approval.presence_invalid");
    assert!(inbox.entry().attestation_blob_b64.is_none());
    let options = client.challenge().await.unwrap().json();
    let accepted = client
        .post(
            "assertion",
            &signed(&options, &format!("http://localhost:{port}"), 5),
        )
        .await
        .unwrap();
    assert_eq!(accepted.status, 200, "{}", accepted.body);
    assert_eq!(accepted.json()["status"], "attested");
    assert!(inbox.entry().attestation_blob_b64.is_some());
    inbox.handle.shutdown().await.unwrap();
}

/// Rejecting on the mainnet inbox page rejects the entry and discards its
/// outstanding challenge, so an assertion over that challenge finds none,
/// and the rejection records no consent and no presence.
#[tokio::test]
#[serial_test::serial]
async fn mainnet_inbox_reject_discards_the_challenge() {
    let inbox = MainnetInbox::start("inbox-reject").await;
    let client = inbox.client().await;
    let options = client.challenge().await.unwrap().json();
    let rejected = client.post("reject", &json!({})).await.unwrap();
    assert_eq!(rejected.status, 200, "{}", rejected.body);
    assert_eq!(rejected.json()["status"], "rejected");
    let late = client
        .post("assertion", &signed(&options, &client.origin(), 5))
        .await
        .unwrap();
    assert_eq!(late.status, 409, "{}", late.body);
    assert_eq!(late.json()["error"], "approval.presence_consumed");
    let entry = inbox.entry();
    assert!(matches!(
        entry.kind,
        stellar_agent_core::approval::ApprovalKind::Rejected { .. }
    ));
    assert!(entry.attestation_blob_b64.is_none());
    assert!(entry.mainnet_presence.is_none());
    assert!(
        !std::fs::read_to_string(inbox.fixture.audit_path())
            .unwrap_or_default()
            .contains("approval_attested")
    );
    inbox.handle.shutdown().await.unwrap();
}

/// A mainnet inbox served by [`crate::start_serve`] on an ephemeral
/// loopback port over a fresh fixture with one pending payment.
struct MainnetInbox {
    fixture: MainnetConsentFixture,
    nonce: String,
    handle: crate::ServeHandle,
}
impl MainnetInbox {
    async fn start(name: &str) -> Self {
        let fixture = MainnetConsentFixture::new(name);
        let entry = fixture.payment(600_000);
        let mut store = PendingApprovalStore::open(fixture.store_path()).unwrap();
        store.insert(entry.clone(), now_ms().unwrap()).unwrap();
        drop(store);
        let (sender, _receiver) = tokio::sync::mpsc::unbounded_channel();
        let handle = crate::start_serve(crate::ServeConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            Harness::context_of(&fixture),
            sender,
            false,
        ))
        .await
        .unwrap();
        Self {
            fixture,
            nonce: entry.approval_nonce,
            handle,
        }
    }
    /// A browser session that bootstrapped into the inbox and opened the
    /// entry's consent page.
    async fn client(&self) -> test_support::PresenceClient {
        test_support::PresenceClient::connect_inbox(&self.handle.bootstrap_url(), &self.nonce)
            .await
            .unwrap()
    }
    /// The stored entry.
    fn entry(&self) -> PendingApproval {
        PendingApprovalStore::open(self.fixture.store_path())
            .unwrap()
            .get(&self.nonce)
            .unwrap()
            .clone()
    }
}

/// A payment intent of `amount_stroops` to the fixture destination.
fn payment_intent(amount_stroops: &str) -> stellar_agent_core::approval::ClassicIntent {
    serde_json::from_value(json!({
        "base": {
            "chain_id": "stellar:mainnet",
            "source": "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY",
            "policy_digest": "11".repeat(32),
            "fee_bound_stroops": "300",
            "memo": "none",
        },
        "payload": {"pay": {
            "destination": stellar_agent_core::approval::mainnet_fixtures::ALLOWED_DESTINATION,
            "asset": "native",
            "amount_stroops": amount_stroops,
        }},
    }))
    .unwrap()
}

/// The intent-aware page builder renders the intent and carries the intent
/// consent view digest in its island; a page for a changed intent carries
/// another digest; the consent verifies only through the intent-aware path;
/// and the inbox handlers pass no intent and keep their legacy page.
#[tokio::test]
#[serial_test::serial]
async fn mainnet_page_binds_the_rendered_intent() {
    use stellar_agent_core::approval::{
        PresenceListener, issue_mainnet_intent_presence, mainnet_intent_consent_view_digest,
    };
    let h = Harness::new();
    let nonce = h.entry.approval_nonce.clone();
    let policy = h.fixture.current_policy();
    let binding = h.fixture.binding();
    let intent = payment_intent("10");
    let changed = payment_intent("11");
    let (status, html) =
        page_text(render_detail(&h.state, &h.session, &nonce, Some(&intent)).unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    let island = crate::operator_enroll::test_support::island(&html, "presence-data").unwrap();
    let digest = hex::encode(
        mainnet_intent_consent_view_digest(&h.entry, &binding, &policy, Some(&intent)).unwrap(),
    );
    assert_eq!(island["consent_view_digest"], digest);
    assert_ne!(digest, h.digest());
    assert!(html.contains("<dt>Fee at most (stroops)</dt><dd>300</dd>"));
    assert!(!html.contains("Simulated seq num"));

    let (_, changed_html) =
        page_text(render_detail(&h.state, &h.session, &nonce, Some(&changed)).unwrap()).await;
    let changed_island =
        crate::operator_enroll::test_support::island(&changed_html, "presence-data").unwrap();
    assert_ne!(changed_island["consent_view_digest"], digest);
    let (status, body) = h
        .post("challenge", json!({"consent_view_digest": digest}), "")
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], "approval.presence_changed");
    assert!(h.state.challenges.lock().unwrap().is_empty());

    let (status, legacy) = page_text(detail(&h.state, &h.session, &nonce)).await;
    assert_eq!(status, StatusCode::OK);
    let legacy_island =
        crate::operator_enroll::test_support::island(&legacy, "presence-data").unwrap();
    assert_eq!(legacy_island["consent_view_digest"], h.digest());
    assert!(legacy.contains("Simulated seq num"));
    assert!(!legacy.contains("Fee at most"));

    let pending = issue_mainnet_intent_presence(
        &h.entry,
        &binding,
        &policy,
        PresenceListener::Loopback(&h.state.origin),
        Some(&intent),
        now_ms().unwrap(),
        Instant::now(),
    )
    .unwrap();
    let assertion = MainnetConsentFixture::sign_issued(&fixture_authenticator(), &pending);
    let presence = verify_mainnet_presence(
        pending,
        MainnetConsentFixture::input(&assertion),
        now_ms().unwrap(),
        Instant::now(),
    )
    .unwrap();
    let outcome = apply_decision(
        &h.decision(),
        Decision::Approve {
            nonce,
            shown_view_digest: Some(approval_view_digest(&h.entry, &binding).unwrap()),
        },
        RequestIdentity::Mainnet(presence),
    );
    assert!(
        matches!(
            outcome,
            crate::Outcome::PresenceRefused {
                code: "approval.presence_invalid",
                ..
            }
        ),
        "{outcome:?}"
    );
    h.no_consent();
}

// ── Signed origin ───────────────────────────────────────────────────────────

use stellar_agent_core::approval::mainnet_fixtures::{
    SIGNED_CERT_SPKI_SHA256, SIGNED_ORIGIN, SIGNED_RP_ID,
};
use stellar_agent_loopback_http::signed_origin::{SignedHostLayer, SignedOriginLayer};
use test_support::{HttpsSession, HttpsSessionGate};

/// The `Host` a browser sends to [`SIGNED_ORIGIN`].
const SIGNED_AUTHORITY: &str = "approve.example.invalid:8443";

/// The inbox consent routes of a signed-origin listener over a fixture whose
/// policy signs [`SIGNED_ORIGIN`], behind the signed-origin layers, with one
/// pending payment and one HTTPS session.
struct SignedOrigin {
    fixture: MainnetConsentFixture,
    entry: PendingApproval,
    context: Arc<DecisionContext>,
    router: Router,
    session: HttpsSession,
}

impl SignedOrigin {
    fn new(name: &str) -> Self {
        Self::with_revocation(name, None)
    }

    fn with_revocation(
        name: &str,
        access: Option<Arc<dyn crate::decision::RevocationAccess>>,
    ) -> Self {
        let mut fixture = MainnetConsentFixture::new(name);
        fixture.sign_signed_origin_policy(&[&fixture_authenticator()], &SIGNED_CERT_SPKI_SHA256);
        let entry = fixture.payment(600_000);
        let mut store = PendingApprovalStore::open(fixture.store_path()).unwrap();
        store.insert(entry.clone(), now_ms().unwrap()).unwrap();
        drop(store);
        let identity = ListenerIdentity::capture(&fixture.current_policy()).unwrap();
        let (gate, session) = HttpsSessionGate::open();
        let context = Harness::context_of(&fixture);
        let context = Arc::new(match access {
            Some(access) => context.with_revocation_access(access),
            None => context,
        });
        let (router, completion) = signed_origin_consent(
            SignedOriginMode::Inbox {
                context: context.clone(),
                page_identity: PageIdentity::neutral(),
            },
            identity,
            SIGNED_ORIGIN,
            Arc::new(gate),
        )
        .unwrap()
        .into_parts();
        assert!(completion.is_none());
        let router = router
            .layer(SignedOriginLayer::new(SIGNED_ORIGIN))
            .layer(SignedHostLayer::new(SIGNED_ORIGIN));
        Self {
            fixture,
            entry,
            context,
            router,
            session,
        }
    }

    fn nonce(&self) -> &str {
        &self.entry.approval_nonce
    }

    /// One request about the entry from this session's page.
    async fn send(&self, method: &str, path: &str, body: Option<&serde_json::Value>) -> Response {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("host", SIGNED_AUTHORITY)
            .header("origin", SIGNED_ORIGIN)
            .header("content-type", "application/json");
        for (name, value) in self.session.headers(self.nonce()) {
            request = request.header(name, value);
        }
        let body = body.map_or_else(Body::empty, |body| Body::from(body.to_string()));
        self.router
            .clone()
            .oneshot(request.body(body).unwrap())
            .await
            .unwrap()
    }

    async fn post(
        &self,
        action: &str,
        body: &serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let response = self
            .send(
                "POST",
                &format!("/approval/{}/{action}", self.nonce()),
                Some(body),
            )
            .await;
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 16384).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap_or_default())
    }

    /// The island of the entry's consent page.
    async fn page(&self) -> serde_json::Value {
        let response = self
            .send("GET", &format!("/approval/{}", self.nonce()), None)
            .await;
        let (status, html) = page_text(response).await;
        assert_eq!(status, StatusCode::OK, "{html}");
        crate::operator_enroll::test_support::island(&html, "presence-data").unwrap()
    }

    /// A challenge for the page's consent view.
    async fn challenge(&self) -> serde_json::Value {
        let page = self.page().await;
        let (status, options) = self
            .post(
                "challenge",
                &json!({"consent_view_digest": page["consent_view_digest"]}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{options}");
        options
    }

    /// The fixture credential's assertion over `options` at the signed
    /// origin and relying party.
    fn signed(options: &serde_json::Value, counter: u32) -> serde_json::Value {
        let challenge = URL_SAFE_NO_PAD
            .decode(options["challenge"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let assertion = fixture_authenticator().assert(
            challenge,
            SIGNED_ORIGIN,
            SIGNED_RP_ID,
            stellar_agent_test_support::webauthn::FLAG_UP
                | stellar_agent_test_support::webauthn::FLAG_UV,
            counter,
        );
        json!({"request_id": options["request_id"], "credential_id_b64url": URL_SAFE_NO_PAD.encode(assertion.credential_id),
            "authenticator_data_b64url": URL_SAFE_NO_PAD.encode(assertion.authenticator_data), "client_data_json_b64url": URL_SAFE_NO_PAD.encode(assertion.client_data_json), "signature_der_b64url": URL_SAFE_NO_PAD.encode(assertion.signature_der)})
    }

    fn stored(&self) -> PendingApproval {
        PendingApprovalStore::open(self.fixture.store_path())
            .unwrap()
            .get(self.nonce())
            .unwrap()
            .clone()
    }

    /// The rows of `kind` in the fixture's audit log.
    fn rows(&self, kind: &str) -> Vec<serde_json::Value> {
        std::fs::read_to_string(self.fixture.audit_path())
            .unwrap_or_default()
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .filter(|row| row["kind"] == kind)
            .collect()
    }
}

/// An attested entry shows no revocation control, although its durable
/// lookup reports a live, unconsented record.
#[tokio::test]
#[serial_test::serial]
async fn signed_revocation_control_requires_a_pending_entry() {
    let access = Arc::new(crate::tests::CountingRevocations::new());
    let so = SignedOrigin::with_revocation("revoke-attested", Some(access));
    let options = so.challenge().await;
    let (status, body) = so
        .post("assertion", &SignedOrigin::signed(&options, 1))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(so.stored().attestation_blob_b64.is_some());
    let (status, page) = page_text(
        so.send("GET", &format!("/approval/{}", so.nonce()), None)
            .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{page}");
    for marker in [
        "id=\"revoke-btn\"",
        "id=\"revoke-data\"",
        "/static/revoke.js",
    ] {
        assert!(!page.contains(marker), "{marker}");
    }
}

#[tokio::test]
#[serial_test::serial]
async fn revocation_authentication_matrix() {
    use std::sync::atomic::Ordering;
    let access = Arc::new(crate::tests::CountingRevocations::new());
    let so = SignedOrigin::with_revocation("revoke-proof", Some(access.clone()));
    let (_, page) = page_text(
        so.send("GET", &format!("/approval/{}", so.nonce()), None)
            .await,
    )
    .await;
    for marker in [
        "id=\"revoke-btn\"",
        "id=\"revoke-data\"",
        "/static/revoke.js",
        "/static/revoke.css",
    ] {
        assert!(page.contains(marker), "{marker}");
    }
    for (path, content) in [
        ("/static/revoke.js", crate::web::REVOKE_JS),
        ("/static/revoke.css", crate::web::REVOKE_CSS),
    ] {
        let (status, body) = page_text(so.send("GET", path, None).await).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.as_bytes(), content);
    }
    let before = std::fs::read(so.fixture.store_path()).unwrap();
    let initial = access.calls.load(Ordering::SeqCst);
    let (status, _) = so.post("revoke", &json!({})).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(access.calls.load(Ordering::SeqCst), initial);
    let options = so.challenge().await;
    let assertion = SignedOrigin::signed(&options, 1);
    let initial = access.calls.load(Ordering::SeqCst);
    let (status, body) = so.post("revoke", &assertion).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["view"]["state"], "revoked");
    assert_eq!(access.calls.load(Ordering::SeqCst), initial + 2);
    let (status, _) = so.post("revoke", &assertion).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(access.calls.load(Ordering::SeqCst), initial + 2);
    assert_eq!(std::fs::read(so.fixture.store_path()).unwrap(), before);
    assert!(so.rows("approval_rejected").is_empty());
    assert!(so.rows("approval_attested").is_empty());
}

/// The signed-origin inbox issues at the signed relying party and origin.
/// It records consent on the remote surface with a mainnet passkey approver
/// and a receipt naming the listener.
#[tokio::test]
#[serial_test::serial]
async fn signed_origin_consent_attributes_the_remote_surface() {
    let so = SignedOrigin::new("signed-surface");
    let page = so.page().await;
    assert_eq!(page["mode"], "inbox");
    assert_eq!(page["signed_origin"], true);
    let options = so.challenge().await;
    assert_eq!(options["rp_id"], SIGNED_RP_ID);
    let (status, body) = so
        .post("assertion", &SignedOrigin::signed(&options, 3))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "attested");
    let entry = so.stored();
    assert!(entry.attestation_blob_b64.is_some());
    assert!(matches!(
        entry.attested_approver,
        Some(stellar_agent_core::approval::AttestedApprover::MainnetPasskey { .. })
    ));
    let receipt = entry.mainnet_presence.unwrap();
    assert_eq!(receipt.expected_origin(), SIGNED_ORIGIN);
    assert_eq!(
        receipt.cert_spki_sha256_hex(),
        Some(hex::encode(SIGNED_CERT_SPKI_SHA256).as_str())
    );
    let rows = so.rows("approval_attested");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["origin"], "serve-remote");
    assert_eq!(rows[0]["mainnet_presence"]["rp_id"], SIGNED_RP_ID);
    assert_eq!(
        rows[0]["mainnet_presence"]["webauthn_origin"],
        SIGNED_ORIGIN
    );
}

/// A signed-origin ceremony completes for its selected entry without consent persistence.
#[tokio::test]
#[serial_test::serial]
async fn signed_origin_one_shot_completes_without_persisting_consent() {
    let mut so = SignedOrigin::new("signed-one-shot");
    let identity = ListenerIdentity::capture(&so.fixture.current_policy()).unwrap();
    let (gate, session) = HttpsSessionGate::open();
    let (router, completion) = signed_origin_consent(
        SignedOriginMode::OneShot(Box::new(MainnetPresenceConfig {
            entry: so.entry.clone(),
            context: ApprovalContext::from_profile(so.fixture.name(), so.fixture.profile()),
            authority: so.fixture.authority(),
            store_path: so.fixture.store_path(),
            page_identity: PageIdentity::neutral(),
        })),
        identity,
        SIGNED_ORIGIN,
        Arc::new(gate),
    )
    .unwrap()
    .into_parts();
    so.router = router
        .layer(SignedOriginLayer::new(SIGNED_ORIGIN))
        .layer(SignedHostLayer::new(SIGNED_ORIGIN));
    so.session = session;
    let page = so.page().await;
    assert_eq!(page["mode"], "one_shot");
    assert_eq!(page["signed_origin"], true);
    let options = so.challenge().await;
    assert_eq!(options["rp_id"], SIGNED_RP_ID);
    let (status, body) = so
        .post("assertion", &SignedOrigin::signed(&options, 3))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "presence_verified");
    assert_eq!(body["request_id"], options["request_id"]);
    let presence = completion
        .unwrap()
        .await_presence(Instant::now() + std::time::Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(presence.approval_nonce(), so.nonce());
    assert_eq!(
        presence.request_id(),
        options["request_id"].as_str().unwrap()
    );
    assert!(so.stored().attestation_blob_b64.is_none());
    assert!(so.stored().mainnet_presence.is_none());
    assert!(so.rows("approval_attested").is_empty());
    assert!(so.rows("approval_rejected").is_empty());
}

/// A policy signed again with another pin for the same origin, before a
/// fresh challenge, refuses the challenge as stale and mints nothing.
#[tokio::test]
#[serial_test::serial]
async fn signed_origin_resign_before_challenge_refuses_stale_listener() {
    let mut so = SignedOrigin::new("signed-stale");
    so.fixture
        .sign_signed_origin_policy(&[&fixture_authenticator()], &[0xcd; 32]);
    let page = so.page().await;
    assert_eq!(page["signed_origin"], true);
    let (status, body) = so
        .post(
            "challenge",
            &json!({"consent_view_digest": page["consent_view_digest"]}),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "approval.listener_policy_stale");
    assert_eq!(
        body["message"],
        "The approval listener serves an earlier owner-signed mainnet policy; restart it under the current policy."
    );
    assert!(body.get("challenge").is_none());
    let (status, body) = so
        .post(
            "assertion",
            &json!({"request_id": "00000000-0000-4000-8000-000000000000", "credential_id_b64url": "AA",
                "authenticator_data_b64url": "AA", "client_data_json_b64url": "AA", "signature_der_b64url": "AA"}),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], "approval.presence_consumed");
    assert!(so.stored().attestation_blob_b64.is_none());
    assert!(so.rows("approval_attested").is_empty());
}

/// Under a policy that names an approval origin, the local inbox and the
/// command ceremony refuse to start. A loopback challenge after a policy
/// re-sign also refuses. Each refusal carries `approval.origin_signed_remote`
/// and its message.
#[tokio::test]
#[serial_test::serial]
async fn local_inbox_refuses_consent_under_signed_origin() {
    const MESSAGE: &str =
        "The owner-signed policy serves mainnet consent at its approval origin; approve there.";
    {
        let mut fixture = MainnetConsentFixture::new("local-refusal-start");
        let entry = fixture.payment(600_000);
        let mut store = PendingApprovalStore::open(fixture.store_path()).unwrap();
        store.insert(entry.clone(), now_ms().unwrap()).unwrap();
        drop(store);
        fixture.sign_signed_origin_policy(&[&fixture_authenticator()], &SIGNED_CERT_SPKI_SHA256);

        let start = crate::start_serve(crate::ServeConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            Harness::context_of(&fixture),
            tokio::sync::mpsc::unbounded_channel().0,
            false,
        ))
        .await;
        let Err(error) = start else {
            panic!("the local inbox started under a signed origin");
        };
        assert_eq!(
            error.presence_failure().map(|failure| failure.code()),
            Some("approval.origin_signed_remote")
        );
        assert_eq!(error.to_string(), MESSAGE);

        let start = start_mainnet_presence(MainnetPresenceConfig {
            entry: entry.clone(),
            context: ApprovalContext::from_profile(fixture.name(), fixture.profile()),
            authority: fixture.authority(),
            store_path: fixture.store_path(),
            page_identity: PageIdentity::neutral(),
        })
        .await;
        let Err(ServeStartError::Presence(refusal)) = start else {
            panic!("the command ceremony started under a signed origin");
        };
        assert_eq!(refusal, PresenceStartRefusal::OriginSignedRemote);
        assert_eq!(refusal.failure().code(), "approval.origin_signed_remote");
        assert_eq!(refusal.failure().to_string(), MESSAGE);
        assert_eq!(refusal_status(&refusal.failure()), StatusCode::FORBIDDEN);
        assert!(
            PendingApprovalStore::open(fixture.store_path())
                .unwrap()
                .get(&entry.approval_nonce)
                .unwrap()
                .attestation_blob_b64
                .is_none()
        );
    }

    let mut h = Harness::named("local-refusal");
    assert_eq!(h.challenge().await["rp_id"], "localhost");
    h.fixture
        .sign_signed_origin_policy(&[&fixture_authenticator()], &SIGNED_CERT_SPKI_SHA256);
    h.state.challenges.lock().unwrap().clear();
    let (status, body) = h
        .post("challenge", json!({"consent_view_digest": h.digest()}), "")
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "approval.origin_signed_remote");
    assert_eq!(body["message"], MESSAGE);
    assert!(h.state.challenges.lock().unwrap().is_empty());
    let (status, page) = page_text(detail(&h.state, &h.session, &h.entry.approval_nonce)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{page}");
    assert!(page.contains("approval.origin_signed_remote"), "{page}");
    h.no_consent();
}

/// A signed presence for another nonce refuses direct rejection and leaves both entries pending.
#[test]
#[serial_test::serial]
fn signed_origin_reject_nonce_mismatch_is_binding_mismatch() {
    let so = SignedOrigin::new("signed-reject-nonce");
    let other = so.fixture.payment(600_000);
    assert_ne!(other.approval_nonce, so.nonce());
    let mut store = PendingApprovalStore::open(so.fixture.store_path()).unwrap();
    store.insert(other.clone(), now_ms().unwrap()).unwrap();
    drop(store);
    let policy = so.fixture.current_policy();
    let identity = ListenerIdentity::capture(&policy).unwrap();
    let pending = issue_mainnet_intent_presence(
        &other,
        &so.fixture.binding(),
        &policy,
        PresenceListener::SignedOrigin(&identity),
        None,
        now_ms().unwrap(),
        Instant::now(),
    )
    .unwrap();
    let assertion = MainnetConsentFixture::sign_issued(&fixture_authenticator(), &pending);
    let presence = verify_mainnet_presence(
        pending,
        MainnetConsentFixture::input(&assertion),
        now_ms().unwrap(),
        Instant::now(),
    )
    .unwrap();
    assert_eq!(
        apply_decision(
            &so.context,
            Decision::Reject {
                nonce: so.nonce().to_owned(),
            },
            RequestIdentity::SignedOrigin(presence),
        ),
        crate::Outcome::BindingMismatch
    );
    let store = PendingApprovalStore::open(so.fixture.store_path()).unwrap();
    for expected in [&so.entry, &other] {
        let entry = store.get(&expected.approval_nonce).unwrap();
        assert_eq!(entry.kind, expected.kind);
        assert!(entry.attestation_blob_b64.is_none());
        assert!(entry.mainnet_presence.is_none());
    }
    assert!(so.rows("approval_rejected").is_empty());
    assert!(so.rows("approval_rejected_remote").is_empty());
    assert!(so.rows("approval_attested").is_empty());
}

/// Revoking the challenge credential refuses both decisions without a row or tombstone.
#[tokio::test]
#[serial_test::serial]
async fn signed_origin_reject_refuses_a_revoked_credential() {
    for action in ["reject", "approve"] {
        let mut so = SignedOrigin::new("signed-revoked");
        let options = so.challenge().await;
        let policy = so.fixture.current_policy();
        let identity = ListenerIdentity::capture(&policy).unwrap();
        let pending = issue_mainnet_intent_presence(
            &so.entry,
            &so.fixture.binding(),
            &policy,
            PresenceListener::SignedOrigin(&identity),
            None,
            now_ms().unwrap(),
            Instant::now(),
        )
        .unwrap();
        let assertion = MainnetConsentFixture::sign_issued(&fixture_authenticator(), &pending);
        let presence = verify_mainnet_presence(
            pending,
            MainnetConsentFixture::input(&assertion),
            now_ms().unwrap(),
            Instant::now(),
        )
        .unwrap();
        let other = stellar_agent_test_support::webauthn::TestAuthenticator::from_seed(
            [0x33; 32],
            vec![0x44; 16],
        );
        so.fixture
            .sign_signed_origin_policy(&[&other], &SIGNED_CERT_SPKI_SHA256);
        let (status, body) = if action == "reject" {
            so.post(action, &SignedOrigin::signed(&options, 4)).await
        } else {
            let response = outcome_to_response(apply_decision(
                &so.context,
                Decision::Approve {
                    nonce: so.nonce().to_owned(),
                    shown_view_digest: Some(
                        approval_view_digest(&so.entry, &so.fixture.binding()).unwrap(),
                    ),
                },
                RequestIdentity::SignedOrigin(presence),
            ));
            let status = response.status();
            let bytes = to_bytes(response.into_body(), 16384).await.unwrap();
            (status, serde_json::from_slice(&bytes).unwrap())
        };
        assert_eq!(status, StatusCode::FORBIDDEN, "{action}: {body}");
        assert_eq!(body["error"], "approval.listener_policy_stale");
        assert!(!matches!(
            so.stored().kind,
            stellar_agent_core::approval::ApprovalKind::Rejected { .. }
        ));
        assert!(so.stored().attestation_blob_b64.is_none());
        assert!(so.rows("approval_rejected").is_empty());
        assert!(so.rows("approval_attested").is_empty());
    }
}

/// A pin change after challenge issuance refuses rejection without a row or tombstone.
#[tokio::test]
#[serial_test::serial]
async fn signed_origin_reject_refuses_after_a_pin_change() {
    let mut so = SignedOrigin::new("signed-reject-pin");
    let options = so.challenge().await;
    so.fixture
        .sign_signed_origin_policy(&[&fixture_authenticator()], &[0xcd; 32]);
    let (status, body) = so.post("reject", &SignedOrigin::signed(&options, 4)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "approval.listener_policy_stale");
    assert!(!matches!(
        so.stored().kind,
        stellar_agent_core::approval::ApprovalKind::Rejected { .. }
    ));
    assert!(so.stored().attestation_blob_b64.is_none());
    assert!(so.rows("approval_rejected").is_empty());
    assert!(so.rows("approval_attested").is_empty());
}

/// A signed-origin rejection with the session and CSRF value but no
/// assertion refuses and leaves the entry pending. An assertion verified
/// under the policy key rejects, records no consent and drops the challenge.
#[tokio::test]
#[serial_test::serial]
async fn signed_origin_reject_requires_an_action_assertion() {
    let so = SignedOrigin::new("signed-reject");
    for body in [json!({}), json!({"reason": "operator_cancel"})] {
        let (status, refused) = so.post("reject", &body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{refused}");
        assert_eq!(refused["error"], "approval.presence_invalid");
    }
    let options = so.challenge().await;
    let mut wrong = SignedOrigin::signed(&options, 4);
    wrong["request_id"] = json!("00000000-0000-4000-8000-000000000000");
    let (status, refused) = so.post("reject", &wrong).await;
    assert_eq!(status, StatusCode::CONFLICT, "{refused}");
    assert_eq!(refused["error"], "approval.presence_consumed");
    let entry = so.stored();
    assert!(!matches!(
        entry.kind,
        stellar_agent_core::approval::ApprovalKind::Rejected { .. }
    ));
    assert!(so.rows("approval_rejected").is_empty());

    let options = so.challenge().await;
    let assertion = SignedOrigin::signed(&options, 5);
    let (status, body) = so.post("reject", &assertion).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "rejected");
    let entry = so.stored();
    assert!(matches!(
        entry.kind,
        stellar_agent_core::approval::ApprovalKind::Rejected { .. }
    ));
    assert!(entry.attestation_blob_b64.is_none());
    let rows = so.rows("approval_rejected");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["origin"], "serve-remote");
    assert!(so.rows("approval_attested").is_empty());
    let (status, late) = so.post("assertion", &assertion).await;
    assert_eq!(status, StatusCode::CONFLICT, "{late}");
    assert_eq!(late["error"], "approval.presence_consumed");
}
