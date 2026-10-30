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
    h.challenge().await;
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
