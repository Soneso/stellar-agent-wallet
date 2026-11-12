//! Signed-origin consent through the real HTTPS listener and software assertions.
#![cfg(feature = "test-helpers")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "listener assertions"
)]

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use reqwest::{Client, Response, StatusCode};
use serde_json::{Value, json};
use std::{
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};
use stellar_agent_approval_remote::{
    RemoteServeConfig, RemoteServeHandle, RemoteServeStartError, start_remote_serve,
    test_helpers::{PinnedLeaf, pinned_leaf},
    tls,
};
use stellar_agent_approval_ui::{DecisionContext, MainnetPresenceConfig, PageIdentity};
use stellar_agent_core::approval::{
    ApprovalContext, PendingApproval, PendingApprovalStore, RemoteApprovalAuthority,
    mainnet_fixtures::{MainnetConsentFixture, SIGNED_ORIGIN, SIGNED_RP_ID},
};
use stellar_agent_test_support::{
    keyring_mock,
    webauthn::{TestAuthenticator, fixture_authenticator},
};

struct Fixture {
    fixture: MainnetConsentFixture,
    entry: PendingApproval,
    leaf: PinnedLeaf,
    files: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        Self::with_attestation_key_hook(None)
    }

    /// A fixture whose keyring runs `hook` before every read of the profile's
    /// attestation key. The hooked store replaces the plain one before the
    /// fixture seeds its keys.
    fn with_attestation_key_hook(hook: Option<Arc<dyn Fn() + Send + Sync>>) -> Self {
        let files = tempfile::tempdir().unwrap();
        let leaf = pinned_leaf(SIGNED_RP_ID, &rcgen::PKCS_ECDSA_P256_SHA256);
        std::fs::write(files.path().join("cert.pem"), leaf.chain_pem()).unwrap();
        std::fs::write(files.path().join("key.pem"), &leaf.key_pem).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(
                files.path().join("key.pem"),
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
        let mut fixture = MainnetConsentFixture::with_profile("signed-listener", |profile| {
            if let Some(hook) = hook {
                let key = &profile.attestation_key_id;
                keyring_mock::install_with_read_hooks(vec![keyring_mock::ReadHook::new(
                    &key.service,
                    &key.account,
                    hook,
                )])
                .unwrap();
            }
            profile.remote_approval = Some(serde_json::from_value(json!({
                "enabled": true, "bind": "127.0.0.1:0", "rp_id": SIGNED_RP_ID,
                "cert_path": files.path().join("cert.pem"), "key_path": files.path().join("key.pem")
            })).unwrap());
        });
        fixture.sign_signed_origin_policy(&[&fixture_authenticator()], &leaf.pin);
        let entry = fixture.payment(600_000);
        PendingApprovalStore::open(fixture.store_path())
            .unwrap()
            .insert(entry.clone(), now())
            .unwrap();
        Self {
            fixture,
            entry,
            leaf,
            files,
        }
    }

    async fn config(&self, one_shot: bool) -> Result<RemoteServeConfig, RemoteServeStartError> {
        let profile = self
            .fixture
            .authority()
            .load_current()
            .unwrap()
            .profile()
            .clone();
        let remote = profile.remote_approval.as_ref().unwrap();
        let context = ApprovalContext::from_profile(self.fixture.name(), &profile);
        let decision = DecisionContext::new(
            context.clone(),
            self.fixture.store_path(),
            profile.attestation_key_id.clone(),
            stellar_agent_core::profile::owner_key::OwnerKeyContext::for_profile(
                self.fixture.name(),
                &profile,
            ),
            Arc::new(Mutex::new(self.fixture.audit_writer())),
            None,
        )
        .with_mainnet_authority(self.fixture.authority());
        let config = RemoteServeConfig::from_profile(
            remote.bind.parse().unwrap(),
            remote,
            RemoteApprovalAuthority::for_profile(self.fixture.name()).unwrap(),
            decision,
        )
        .await?;
        Ok(if one_shot {
            config.with_one_shot(MainnetPresenceConfig {
                entry: self.entry.clone(),
                context,
                authority: self.fixture.authority(),
                store_path: self.fixture.store_path(),
                page_identity: PageIdentity::neutral(),
            })
        } else {
            config
        })
    }

    async fn listen(&self, one_shot: bool) -> Result<RemoteServeHandle, RemoteServeStartError> {
        start_remote_serve(self.config(one_shot).await?).await
    }

    async fn start(&self, one_shot: bool) -> (RemoteServeHandle, Browser) {
        let handle = self.listen(one_shot).await.unwrap();
        assert_eq!(handle.public_origin(), SIGNED_ORIGIN);
        let browser = Browser::new(handle.local_addr(), SIGNED_ORIGIN);
        browser.assert_leaf(&self.leaf.cert_pem).await;
        (handle, browser)
    }

    fn edit_remote(&self, edit: impl FnOnce(&mut Value)) {
        let mut profile =
            serde_json::to_value(self.fixture.authority().load_current().unwrap().profile())
                .unwrap();
        edit(&mut profile["remote_approval"]);
        let profile: stellar_agent_core::profile::schema::Profile =
            serde_json::from_value(profile).unwrap();
        // The profile writer preserves the installed path selected by the fixture.
        stellar_agent_core::profile::loader::save_to_dir(
            self.fixture.name(),
            &profile,
            &self.fixture.home().join("profiles"),
        )
        .unwrap();
    }

    fn stored(&self) -> PendingApproval {
        PendingApprovalStore::open(self.fixture.store_path())
            .unwrap()
            .get(&self.entry.approval_nonce)
            .unwrap()
            .clone()
    }

    fn counter_bytes(&self) -> Vec<u8> {
        std::fs::read(
            RemoteApprovalAuthority::for_profile(self.fixture.name())
                .unwrap()
                .credentials_path(),
        )
        .unwrap()
    }
}

struct Browser {
    client: Client,
    address: SocketAddr,
    origin: String,
    cookie: String,
}
impl Browser {
    fn new(address: SocketAddr, origin: &str) -> Self {
        Self {
            client: Client::builder()
                .danger_accept_invalid_certs(true)
                .tls_info(true)
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            address,
            origin: origin.to_owned(),
            cookie: String::new(),
        }
    }
    fn request(&self, method: &str, path: &str) -> reqwest::RequestBuilder {
        self.client
            .request(
                method.parse().unwrap(),
                format!("https://{}{path}", self.address),
            )
            .header("host", self.origin.trim_start_matches("https://"))
            .header("origin", &self.origin)
            .header("cookie", &self.cookie)
    }
    async fn assert_leaf(&self, pem: &str) {
        let response = self
            .request("GET", "/")
            .header("connection", "close")
            .send()
            .await
            .unwrap();
        let actual = response
            .extensions()
            .get::<reqwest::tls::TlsInfo>()
            .unwrap()
            .peer_certificate()
            .unwrap();
        let encoded: String = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        let expected = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap();
        assert_eq!(actual, expected);
    }
    async fn login_with(&mut self, auth: &TestAuthenticator, count: u32) -> StatusCode {
        let options: Value = self
            .request("POST", "/login/challenge")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let assertion = auth.assert(
            B64.decode(options["challenge"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
            &self.origin,
            SIGNED_RP_ID,
            5,
            count,
        );
        let body = json!({"assertion": {"id": B64.encode(assertion.credential_id), "response": {
            "authenticator_data": B64.encode(assertion.authenticator_data), "client_data_json": B64.encode(assertion.client_data_json), "signature": B64.encode(assertion.signature_der)
        }}});
        let response = self
            .request("POST", "/login/assertion")
            .json(&body)
            .send()
            .await
            .unwrap();
        if response.status() == StatusCode::OK {
            let cookie = response.headers()["set-cookie"].to_str().unwrap();
            assert!(cookie.contains("HttpOnly; Secure; SameSite=Strict"));
            self.cookie = cookie.split(';').next().unwrap().to_owned();
        }
        response.status()
    }
    async fn login(&mut self, count: u32) {
        assert_eq!(
            self.login_with(&fixture_authenticator(), count).await,
            StatusCode::OK
        );
    }
    async fn page(&self, nonce: &str) -> Value {
        let response = self
            .request("GET", &format!("/approval/{nonce}"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        island(&response.text().await.unwrap(), "presence-data")
    }
    async fn action(&self, nonce: &str, csrf: &str, action: &str, body: &Value) -> Response {
        self.request("POST", &format!("/approval/{nonce}/{action}"))
            .header("x-stellar-approval-csrf", csrf)
            .json(body)
            .send()
            .await
            .unwrap()
    }
    async fn assertion(&self, nonce: &str, count: u32) -> (String, Value) {
        let page = self.page(nonce).await;
        let csrf = page["csrf"].as_str().unwrap().to_owned();
        let response = self
            .action(
                nonce,
                &csrf,
                "challenge",
                &json!({"consent_view_digest": page["consent_view_digest"]}),
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let options: Value = response.json().await.unwrap();
        assert_eq!(options["rp_id"], SIGNED_RP_ID);
        let assertion = fixture_authenticator().assert(
            B64.decode(options["challenge"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
            &self.origin,
            SIGNED_RP_ID,
            5,
            count,
        );
        (
            csrf,
            json!({"request_id": options["request_id"], "credential_id_b64url": B64.encode(assertion.credential_id), "authenticator_data_b64url": B64.encode(assertion.authenticator_data), "client_data_json_b64url": B64.encode(assertion.client_data_json), "signature_der_b64url": B64.encode(assertion.signature_der)}),
        )
    }
}
fn now() -> u64 {
    stellar_agent_core::timefmt::now_unix_ms().unwrap()
}
fn island(html: &str, id: &str) -> Value {
    let after = html.split(&format!("id=\"{id}\"")).nth(1).unwrap();
    serde_json::from_str(
        after
            .split_once('>')
            .unwrap()
            .1
            .split("</script>")
            .next()
            .unwrap(),
    )
    .unwrap()
}

#[tokio::test]
#[serial_test::serial]
async fn signed_origin_consent_attributes_the_remote_surface() {
    let f = Fixture::new();
    let (handle, mut browser) = f.start(false).await;
    browser.login(1).await;
    let nonce = &f.entry.approval_nonce;
    let (csrf, assertion) = browser.assertion(nonce, 2).await;
    let response = browser.action(nonce, &csrf, "assertion", &assertion).await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "{}",
        response.text().await.unwrap()
    );
    let entry = f.stored();
    assert_eq!(entry.attestation_version, 5);
    assert!(entry.attestation_blob_b64.is_some());
    assert_eq!(
        entry.process_uid,
        stellar_agent_core::approval::process_uid_for_attestation().unwrap()
    );
    assert!(matches!(
        entry.attested_approver,
        Some(stellar_agent_core::approval::AttestedApprover::MainnetPasskey { .. })
    ));
    let receipt = entry.mainnet_presence.unwrap();
    assert_eq!(receipt.expected_origin(), SIGNED_ORIGIN);
    assert_eq!(
        receipt.cert_spki_sha256_hex(),
        Some(hex::encode(f.leaf.pin).as_str())
    );
    assert_eq!(serde_json::to_value(receipt).unwrap()["version"], 2);
    let rows: Vec<Value> = std::fs::read_to_string(f.fixture.audit_path())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .filter(|row: &Value| row["kind"] == "approval_attested")
        .collect();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["origin"], "serve-remote");
    handle.shutdown().await.unwrap();
}

#[tokio::test]
#[serial_test::serial]
async fn signed_origin_serves_at_a_nondefault_port() {
    for origin in [SIGNED_ORIGIN, "https://approve.example.invalid"] {
        let f = Fixture::new();
        if origin != SIGNED_ORIGIN {
            let body = stellar_agent_core::approval::mainnet_fixtures::policy_body_with_origin(
                f.fixture.name(),
                stellar_agent_core::approval::mainnet_fixtures::ENDPOINT_HOST,
                f.fixture.sequence() + 1,
                &[&fixture_authenticator()],
                Some((origin, &f.leaf.pin)),
            );
            f.fixture.write_signed(&body);
        }
        let handle = f.listen(false).await.unwrap();
        assert_eq!(handle.public_origin(), origin);
        assert_ne!(handle.local_addr().port(), 8443);
        let mut browser = Browser::new(handle.local_addr(), origin);
        assert_eq!(
            browser.request("GET", "/").send().await.unwrap().status(),
            StatusCode::OK
        );
        browser.login(1).await;
        assert_eq!(
            browser.page(&f.entry.approval_nonce).await["signed_origin"],
            true
        );
        let mut request = browser.request("GET", "/").build().unwrap();
        request.headers_mut().insert(
            "host",
            format!("{}:{}", SIGNED_RP_ID, handle.local_addr().port())
                .parse()
                .unwrap(),
        );
        let bad = browser.client.execute(request).await.unwrap();
        assert_eq!(bad.status(), StatusCode::MISDIRECTED_REQUEST);
        handle.shutdown().await.unwrap();
    }
}

#[tokio::test]
#[serial_test::serial]
async fn signed_origin_refuses_profile_and_header_substitution() {
    let f = Fixture::new();
    let mut config = f.config(false).await.unwrap();
    config.rp_id = "foreign.example".into();
    assert_eq!(
        start_remote_serve(config)
            .await
            .unwrap_err()
            .into_wallet_error()
            .code(),
        "approval.origin_profile_mismatch"
    );
    f.edit_remote(|remote| remote["rp_id"] = json!("foreign.example"));
    let mut config = f.config(false).await.unwrap();
    config.rp_id = SIGNED_RP_ID.to_owned();
    assert_eq!(
        start_remote_serve(config)
            .await
            .unwrap_err()
            .into_wallet_error()
            .code(),
        "approval.origin_profile_mismatch"
    );
    f.edit_remote(|remote| remote["rp_id"] = json!(SIGNED_RP_ID));
    let (handle, browser) = f.start(false).await;
    for (header, value, expected) in [
        ("host", SIGNED_RP_ID, 421),
        ("host", "foreign.example", 421),
        ("origin", "https://foreign.example", 403),
    ] {
        let mut request = browser
            .request("POST", "/login/challenge")
            .header("forwarded", "host=approve.example.invalid:8443;proto=https")
            .header("x-forwarded-host", "approve.example.invalid:8443")
            .header("x-forwarded-proto", "https")
            .build()
            .unwrap();
        request.headers_mut().insert(
            reqwest::header::HeaderName::from_bytes(header.as_bytes()).unwrap(),
            value.parse().unwrap(),
        );
        let response = browser.client.execute(request).await.unwrap();
        assert_eq!(response.status().as_u16(), expected);
    }
    let response = browser
        .client
        .post(format!("https://{}/login/challenge", handle.local_addr()))
        .header("host", "approve.example.invalid:8443")
        .header("x-forwarded-proto", "https")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(f.stored().attestation_blob_b64.is_none());
    handle.shutdown().await.unwrap();
}

#[tokio::test]
#[serial_test::serial]
async fn signed_origin_refuses_missing_pem_without_fallback() {
    for field in ["cert_path", "key_path"] {
        for problem in [
            "absent",
            "missing",
            "unreadable",
            "denied",
            "malformed",
            "mismatched",
        ] {
            if (problem == "denied" && !cfg!(unix))
                || (problem == "mismatched" && field == "cert_path")
            {
                continue;
            }
            let f = Fixture::new();
            let address = std::net::TcpListener::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap();
            f.edit_remote(|remote| remote["bind"] = json!(address.to_string()));
            f.edit_remote(|remote| match problem {
                "absent" => {
                    remote.as_object_mut().unwrap().remove(field);
                }
                "missing" => remote[field] = json!(f.files.path().join("missing.pem")),
                "unreadable" => remote[field] = json!(f.files.path()),
                "denied" => {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt as _;
                        std::fs::set_permissions(
                            remote[field].as_str().unwrap(),
                            std::fs::Permissions::from_mode(0o000),
                        )
                        .unwrap();
                    }
                }
                "mismatched" => {
                    let other = pinned_leaf(SIGNED_RP_ID, &rcgen::PKCS_ECDSA_P256_SHA256);
                    std::fs::write(f.files.path().join("key.pem"), other.key_pem).unwrap();
                }
                _ => {
                    std::fs::write(
                        f.files.path().join(if field == "cert_path" {
                            "cert.pem"
                        } else {
                            "key.pem"
                        }),
                        "bad PEM",
                    )
                    .unwrap();
                }
            });
            let error = f.listen(false).await.unwrap_err().into_wallet_error();
            assert_eq!(error.code(), "approve.remote_tls_unavailable", "{error}");
            assert!(error.to_string().contains(field), "{error}");
            assert!(std::net::TcpListener::bind(address).is_ok());
            let held = std::net::TcpListener::bind(address).unwrap();
            let error = f.listen(false).await.unwrap_err().into_wallet_error();
            assert_eq!(
                error.code(),
                "approve.remote_tls_unavailable",
                "TLS refusal precedes bind: {error}"
            );
            drop(held);
            let (default_cert, default_key) = tls::tls_file_paths(f.fixture.name()).unwrap();
            assert!(!default_cert.exists() && !default_key.exists());
        }
    }
}

#[tokio::test]
#[serial_test::serial]
async fn signed_origin_refuses_cert_pin_mismatch() {
    let f = Fixture::new();
    let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let other = pinned_leaf(SIGNED_RP_ID, &rcgen::PKCS_ECDSA_P256_SHA256);
    let mut config = f.config(false).await.unwrap();
    config.bind_addr = held.local_addr().unwrap();
    config.tls.cert_pem = other.chain_pem().into_bytes();
    config.tls.key_pem = other.key_pem.into_bytes();
    assert_eq!(
        start_remote_serve(config)
            .await
            .unwrap_err()
            .into_wallet_error()
            .code(),
        "approval.cert_pin_mismatch"
    );
    f.edit_remote(|remote| remote["bind"] = json!(held.local_addr().unwrap().to_string()));
    std::fs::write(f.files.path().join("cert.pem"), other.cert_pem).unwrap();
    assert_eq!(
        f.listen(false)
            .await
            .unwrap_err()
            .into_wallet_error()
            .code(),
        "approval.cert_pin_mismatch"
    );
}

#[cfg(unix)]
#[tokio::test]
#[serial_test::serial]
async fn signed_origin_keeps_key_permission_refusal() {
    use std::os::unix::fs::PermissionsExt as _;
    let f = Fixture::new();
    std::fs::set_permissions(
        f.files.path().join("key.pem"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let error = f.listen(false).await.unwrap_err();
    assert!(matches!(
        error,
        stellar_agent_approval_remote::RemoteServeStartError::Tls(
            tls::TlsProvisionError::KeyPermissionsTooOpen { .. }
        )
    ));
    let error = error.into_wallet_error();
    assert_eq!(error.code(), "internal.unexpected_state");
    assert!(
        error
            .to_string()
            .contains("approve.remote_tls_provision_failed")
    );
}

#[tokio::test]
#[serial_test::serial]
async fn signed_origin_resign_before_challenge_refuses_stale_listener() {
    for changed_pin in [false, true] {
        let mut f = Fixture::new();
        let (handle, mut browser) = f.start(false).await;
        browser.login(1).await;
        let nonce = &f.entry.approval_nonce;
        let page = browser.page(nonce).await;
        f.fixture.sign_signed_origin_policy(
            &[&fixture_authenticator()],
            &if changed_pin { [3; 32] } else { f.leaf.pin },
        );
        let response = browser
            .action(
                nonce,
                page["csrf"].as_str().unwrap(),
                "challenge",
                &json!({"consent_view_digest": page["consent_view_digest"]}),
            )
            .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body: Value = response.json().await.unwrap();
        assert_eq!(body["error"], "approval.listener_policy_stale");
        assert!(body.get("challenge").is_none());
        assert!(f.stored().attestation_blob_b64.is_none());
        handle.shutdown().await.unwrap();
    }
}

/// The bound on every wait of [`ReadBarrier`]; reaching it fails the test.
const BARRIER_WAIT: Duration = Duration::from_secs(30);

/// A one-shot barrier at the attestation key read. Once armed, the first read
/// reports "entered" and waits for a release; later reads pass through.
struct ReadBarrier {
    armed: AtomicBool,
    calls: AtomicUsize,
    entered: Mutex<mpsc::Sender<()>>,
    release: Mutex<mpsc::Receiver<()>>,
    timed_out: Mutex<Option<&'static str>>,
}

impl ReadBarrier {
    /// The barrier with the controller's ends: the "entered" receiver and the
    /// release sender.
    fn new() -> (Arc<Self>, mpsc::Receiver<()>, mpsc::Sender<()>) {
        let (entered, entered_rx) = mpsc::channel();
        let (release_tx, release) = mpsc::channel();
        let barrier = Arc::new(Self {
            armed: AtomicBool::new(false),
            calls: AtomicUsize::new(0),
            entered: Mutex::new(entered),
            release: Mutex::new(release),
            timed_out: Mutex::new(None),
        });
        (barrier, entered_rx, release_tx)
    }

    fn on_read(&self) {
        if !self.armed.load(Ordering::SeqCst) || self.calls.fetch_add(1, Ordering::SeqCst) != 0 {
            return;
        }
        let _ = self.entered.lock().unwrap().send(());
        if self
            .release
            .lock()
            .unwrap()
            .recv_timeout(BARRIER_WAIT)
            .is_err()
        {
            *self.timed_out.lock().unwrap() = Some("the hooked key read awaits the release");
        }
    }
}

/// The controller thread, joined when the test leaves on any path, including
/// a panic.
struct Controller(Option<std::thread::JoinHandle<Result<(), String>>>);

impl Controller {
    fn finish(mut self) -> Result<(), String> {
        self.0.take().unwrap().join().unwrap()
    }
}

impl Drop for Controller {
    fn drop(&mut self) {
        if let Some(thread) = self.0.take() {
            let _ = thread.join();
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial_test::serial]
async fn signed_origin_persistence_refuses_a_stale_listener() {
    let (barrier, entered_rx, release_tx) = ReadBarrier::new();
    let hook = Arc::clone(&barrier);
    let f = Fixture::with_attestation_key_hook(Some(Arc::new(move || hook.on_read())));
    let handle = f.listen(false).await.unwrap();
    let mut browser = Browser::new(handle.local_addr(), SIGNED_ORIGIN);
    browser.login(1).await;
    let nonce = f.entry.approval_nonce.clone();
    let (csrf, assertion) = browser.assertion(&nonce, 2).await;
    let policy = f.fixture.current_policy();
    let body = stellar_agent_core::approval::mainnet_fixtures::policy_body_with_origin(
        f.fixture.name(),
        stellar_agent_core::approval::mainnet_fixtures::ENDPOINT_HOST,
        policy.sequence() + 1,
        &[&fixture_authenticator()],
        Some((SIGNED_ORIGIN, &f.leaf.pin)),
    );
    let text = stellar_agent_core::approval::mainnet_fixtures::signed_policy_text(
        &body,
        &ed25519_dalek::SigningKey::from_bytes(&[11; 32]),
    );
    let policy_path = f.fixture.policy_path();
    // The attestation key loads after the consent-view comparison and before
    // the persistence reload, so the newer policy is visible only there.
    let controller = Controller(Some(std::thread::spawn(move || -> Result<(), String> {
        entered_rx
            .recv_timeout(BARRIER_WAIT)
            .map_err(|_| "the request reaches the attestation key read".to_owned())?;
        std::fs::write(&policy_path, &text).map_err(|error| error.to_string())?;
        if std::fs::read_to_string(&policy_path).map_err(|error| error.to_string())? != text {
            return Err("the newer policy is written completely".to_owned());
        }
        release_tx
            .send(())
            .map_err(|_| "the hooked key read receives the release".to_owned())
    })));
    barrier.armed.store(true, Ordering::SeqCst);
    let response = tokio::time::timeout(
        BARRIER_WAIT,
        browser.action(&nonce, &csrf, "assertion", &assertion),
    )
    .await
    .unwrap_or_else(|_| panic!("barrier wait timed out: the assertion response arrives"));
    let fired = barrier.calls.load(Ordering::SeqCst);
    if let Err(wait) = controller.finish() {
        panic!("barrier wait timed out or failed: {wait}");
    }
    if let Some(wait) = *barrier.timed_out.lock().unwrap() {
        panic!("barrier wait timed out: {wait}");
    }
    assert_eq!(fired, 1, "the hook fires once before the response arrives");
    let status = response.status();
    let text = response.text().await.unwrap();
    assert_eq!(status, StatusCode::FORBIDDEN, "{text}");
    let body: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(body["error"], "approval.listener_policy_stale", "{text}");
    let counters = String::from_utf8(f.counter_bytes()).unwrap();
    let counts: Vec<u32> = counters
        .lines()
        .filter_map(|line| line.trim().strip_prefix("sign_count = "))
        .map(|value| value.parse().unwrap())
        .collect();
    assert_eq!(
        counts,
        [2],
        "the verified assertion advances the counter: {counters}"
    );
    assert!(f.stored().attestation_blob_b64.is_none());
    assert!(
        !std::fs::read_to_string(f.fixture.audit_path())
            .unwrap()
            .contains("\"kind\":\"approval_attested\"")
    );
    handle.shutdown().await.unwrap();
}

#[tokio::test]
#[serial_test::serial]
async fn sign_counter_create_check_update_matrix() {
    for count in [0, 1] {
        let f = Fixture::new();
        let (handle, mut browser) = f.start(false).await;
        let created = now();
        browser.login(count).await;
        let bytes = f.counter_bytes();
        let text = String::from_utf8(bytes.clone()).unwrap();
        for expected in [
            "policy-credential",
            "source = \"policy\"",
            SIGNED_RP_ID,
            &fixture_authenticator().credential_id_b64url(),
            &fixture_authenticator().public_key_sec1_b64url(),
        ] {
            assert!(text.contains(expected), "{text}");
        }
        let timestamp: u64 = text
            .lines()
            .find_map(|line| line.strip_prefix("registered_at_unix_ms = "))
            .unwrap()
            .parse()
            .unwrap();
        assert!(timestamp >= created && timestamp <= now());
        assert_eq!(
            browser.login_with(&fixture_authenticator(), count).await,
            if count == 0 {
                StatusCode::OK
            } else {
                StatusCode::BAD_REQUEST
            }
        );
        assert_eq!(f.counter_bytes(), bytes);
        let (csrf, assertion) = browser.assertion(&f.entry.approval_nonce, count).await;
        let response = browser
            .action(&f.entry.approval_nonce, &csrf, "assertion", &assertion)
            .await;
        assert_eq!(
            response.status(),
            if count == 0 {
                StatusCode::OK
            } else {
                StatusCode::FORBIDDEN
            }
        );
        if count != 0 {
            assert!(f.stored().attestation_blob_b64.is_none());
            assert_eq!(f.counter_bytes(), bytes);
            let (csrf, assertion) = browser.assertion(&f.entry.approval_nonce, 2).await;
            assert_eq!(
                browser
                    .action(&f.entry.approval_nonce, &csrf, "assertion", &assertion)
                    .await
                    .status(),
                StatusCode::OK
            );
        }
        let counter = f.counter_bytes();
        let store = PendingApprovalStore::open(f.fixture.store_path()).unwrap();
        let entry = store.get(&f.entry.approval_nonce).unwrap();
        let blob: [u8; 32] = B64
            .decode(entry.attestation_blob_b64.as_ref().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let expected = stellar_agent_core::approval::witness::ApprovalExpectation {
            kind: stellar_agent_core::approval::witness::ApprovedKind::Payment,
            subject: stellar_agent_core::approval::mainnet_consent_subject(
                entry,
                &f.fixture.binding(),
            )
            .unwrap(),
        };
        for _ in 0..2 {
            let witness = stellar_agent_core::approval::witness::verify_approval(
                &store,
                f.fixture.profile(),
                f.fixture.name(),
                &f.entry.approval_nonce,
                &blob,
                &expected,
                &f.fixture.current_policy(),
                now(),
            )
            .unwrap();
            assert_eq!(witness.subject(), expected.subject);
            assert_eq!(f.counter_bytes(), counter);
        }
        drop(store);
        handle.shutdown().await.unwrap();
    }
}

#[tokio::test]
#[serial_test::serial]
async fn one_shot_listener_serves_only_the_selected_id() {
    let f = Fixture::new();
    let other = f.fixture.payment(600_000);
    PendingApprovalStore::open(f.fixture.store_path())
        .unwrap()
        .insert(other.clone(), now())
        .unwrap();
    let (handle, mut browser) = f.start(true).await;
    browser.login(1).await;
    browser.page(&f.entry.approval_nonce).await;
    for prefix in ["approval", "approvals"] {
        let response = browser
            .request("GET", &format!("/{prefix}/{}", other.approval_nonce))
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            if prefix == "approvals" {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::CONFLICT
            }
        );
        assert!(!response.text().await.unwrap().contains("presence-data"));
    }
    let csrf = {
        let session = handle.session_for_test();
        let session = session.lock().unwrap();
        stellar_agent_approval_remote::session::compute_csrf(
            &session.as_ref().unwrap().csrf_key,
            &other.approval_nonce,
        )
    };
    let digest = stellar_agent_core::approval::mainnet_consent_view_digest(
        &other,
        &f.fixture.binding(),
        &f.fixture.current_policy(),
    )
    .unwrap();
    for action in ["challenge", "assertion", "reject", "decision", "cancel"] {
        let body = match action {
            "challenge" => json!({"consent_view_digest": hex::encode(digest)}),
            "cancel" => json!({"reason": "operator_cancel"}),
            _ => json!({}),
        };
        let response = browser
            .action(&other.approval_nonce, &csrf, action, &body)
            .await;
        assert_eq!(
            response.status(),
            if matches!(action, "reject" | "decision") {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::CONFLICT
            },
            "{action}"
        );
    }
    for path in ["/inbox", "/pending.json"] {
        let body = browser
            .request("GET", path)
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(body.contains(&f.entry.approval_nonce));
        assert!(!body.contains(&other.approval_nonce));
    }
    let store = PendingApprovalStore::open(f.fixture.store_path()).unwrap();
    assert_eq!(
        store
            .get(&other.approval_nonce)
            .unwrap()
            .attestation_blob_b64,
        None
    );
    drop(store);
    handle.shutdown().await.unwrap();
}

#[tokio::test]
#[serial_test::serial]
async fn one_shot_refuses_busy_socket() {
    let f = Fixture::new();
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut config = f.config(true).await.unwrap();
    config.bind_addr = socket.local_addr().unwrap();
    let error = start_remote_serve(config)
        .await
        .unwrap_err()
        .into_wallet_error();
    assert_eq!(error.code(), "approval.listener_busy");
    assert!(error.to_string().contains("running inbox"));
}

#[tokio::test]
#[serial_test::serial]
async fn signed_origin_restart_uses_new_policy_and_certificate() {
    let mut f = Fixture::new();
    let (handle, mut browser) = f.start(false).await;
    browser.login(1).await;
    let replacement = pinned_leaf(SIGNED_RP_ID, &rcgen::PKCS_ECDSA_P256_SHA256);
    std::fs::write(f.files.path().join("cert.pem"), replacement.chain_pem()).unwrap();
    std::fs::write(f.files.path().join("key.pem"), &replacement.key_pem).unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    Browser::new(handle.local_addr(), SIGNED_ORIGIN)
        .assert_leaf(&f.leaf.cert_pem)
        .await;
    let (csrf, assertion) = browser.assertion(&f.entry.approval_nonce, 2).await;
    assert_eq!(
        browser
            .action(&f.entry.approval_nonce, &csrf, "assertion", &assertion)
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        f.stored().mainnet_presence.unwrap().cert_spki_sha256_hex(),
        Some(hex::encode(f.leaf.pin).as_str())
    );
    handle.shutdown().await.unwrap();
    f.fixture
        .sign_signed_origin_policy(&[&fixture_authenticator()], &replacement.pin);
    f.leaf = replacement;
    f.entry = f.fixture.payment(600_000);
    PendingApprovalStore::open(f.fixture.store_path())
        .unwrap()
        .insert(f.entry.clone(), now())
        .unwrap();
    let (handle, mut browser) = f.start(false).await;
    browser.login(3).await;
    let (csrf, assertion) = browser.assertion(&f.entry.approval_nonce, 4).await;
    assert_eq!(
        browser
            .action(&f.entry.approval_nonce, &csrf, "assertion", &assertion)
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        f.stored().mainnet_presence.unwrap().cert_spki_sha256_hex(),
        Some(hex::encode(f.leaf.pin).as_str())
    );
    handle.shutdown().await.unwrap();
}

#[tokio::test]
#[serial_test::serial]
async fn testnet_remote_tls_selection_keeps_the_default_path() {
    let f = Fixture::new();
    let mut config = f.fixture.profile().remote_approval.clone().unwrap();
    let (explicit, _) = tls::select_tls(f.fixture.name(), &config, None)
        .await
        .unwrap();
    assert_eq!(explicit.cert_pem, f.leaf.chain_pem().into_bytes());
    let (default_cert, default_key) = tls::tls_file_paths(f.fixture.name()).unwrap();
    assert!(!default_cert.exists() && !default_key.exists());
    for field in ["cert_path", "key_path"] {
        let mut partial = config.clone();
        if field == "cert_path" {
            partial.cert_path = None;
        } else {
            partial.key_path = None;
        }
        let error = tls::select_tls(f.fixture.name(), &partial, None)
            .await
            .unwrap_err()
            .wallet_error();
        assert_eq!(error.code(), "approve.remote_tls_unavailable");
        assert!(error.to_string().contains(field));
        assert!(!default_cert.exists() && !default_key.exists());
    }
    config.cert_path = None;
    config.key_path = None;
    let (generated, _) = tls::select_tls(f.fixture.name(), &config, None)
        .await
        .unwrap();
    let loaded = tls::provision_or_load(f.fixture.name(), &config.rp_id).unwrap();
    assert_eq!(generated.cert_pem, loaded.cert_pem);
    assert_eq!(generated.key_pem, loaded.key_pem);
    assert_ne!(generated.cert_pem, explicit.cert_pem);
}

#[tokio::test]
#[serial_test::serial]
async fn signed_login_advances_once_and_session_reads_compare_only() {
    let mut f = Fixture::new();
    let (handle, mut browser) = f.start(false).await;
    let coordinate = stellar_agent_core::profile::schema::policy_pin_entry_ref(
        &f.fixture.profile().policy_window_state_key_id,
    );
    let read_pin = || {
        keyring_core::Entry::new(&coordinate.service, &coordinate.account)
            .unwrap()
            .get_password()
            .unwrap()
    };
    let before = read_pin();
    f.fixture
        .sign_signed_origin_policy(&[&fixture_authenticator()], &f.leaf.pin);
    let options: Value = browser
        .request("POST", "/login/challenge")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let issued = read_pin();
    assert_eq!(
        serde_json::from_str::<Value>(&issued).unwrap()["sequence"]
            .as_u64()
            .unwrap(),
        serde_json::from_str::<Value>(&before).unwrap()["sequence"]
            .as_u64()
            .unwrap()
            + 1
    );
    f.fixture
        .sign_signed_origin_policy(&[&fixture_authenticator()], &f.leaf.pin);
    let assertion = fixture_authenticator().assert(
        B64.decode(options["challenge"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
        SIGNED_ORIGIN,
        SIGNED_RP_ID,
        5,
        1,
    );
    let response = browser
        .request("POST", "/login/assertion")
        .json(&json!({
            "assertion": {"id": B64.encode(assertion.credential_id), "response": {
                "authenticator_data": B64.encode(assertion.authenticator_data),
                "client_data_json": B64.encode(assertion.client_data_json),
                "signature": B64.encode(assertion.signature_der)
            }}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    browser.cookie = response.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    assert_eq!(read_pin(), issued, "login POST compares without advancing");
    for path in ["/static/app.js", "/inbox", "/pending.json"] {
        assert_eq!(
            browser.request("GET", path).send().await.unwrap().status(),
            StatusCode::OK
        );
        assert_eq!(
            read_pin(),
            issued,
            "session and inbox reads compare without advancing"
        );
    }
    handle.shutdown().await.unwrap();
}

#[tokio::test]
#[serial_test::serial]
async fn signed_origin_trust_comes_from_policy_alone() {
    let mut f = Fixture::new();
    let (handle, mut browser) = f.start(false).await;
    browser.login(1).await;
    f.edit_remote(|remote| remote["allowed_credentials"] = json!(["foreign-credential"]));
    let authority = RemoteApprovalAuthority::for_profile(f.fixture.name()).unwrap();
    let foreign = TestAuthenticator::from_seed([0x22; 32], vec![0x5a; 16]);
    stellar_agent_core::approval::OperatorApprovalCredentialStore::new(
        authority.credentials_path().to_path_buf(),
    )
    .enroll(stellar_agent_core::approval::OperatorApprovalCredential {
        credential_id_b64url: fixture_authenticator().credential_id_b64url(),
        public_key_sec1_b64: foreign.public_key_sec1_b64url(),
        rp_id: SIGNED_RP_ID.to_owned(),
        label: "conflicting enrollment".to_owned(),
        registered_at_unix_ms: now(),
        sign_count: Some(99),
        source: Default::default(),
    })
    .unwrap();
    browser.login(2).await;
    let foreign = TestAuthenticator::from_seed([0x22; 32], vec![0x5a; 16]);
    assert_eq!(
        browser.login_with(&foreign, 3).await,
        StatusCode::BAD_REQUEST
    );
    f.fixture.sign_signed_origin_policy(
        &[&TestAuthenticator::from_seed([0x22; 32], vec![0x6b; 16])],
        &f.leaf.pin,
    );
    assert_eq!(
        browser.login_with(&fixture_authenticator(), 3).await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        browser
            .request("GET", "/inbox")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    handle.shutdown().await.unwrap();
}

#[tokio::test]
#[serial_test::serial]
async fn remote_consent_gate_checks_live_session_and_page_csrf() {
    let f = Fixture::new();
    let (handle, mut browser) = f.start(false).await;
    for path in [
        "/static/mainnet-presence.js",
        "/static/app.js",
        "/static/app-shared.js",
    ] {
        assert_eq!(
            browser.request("GET", path).send().await.unwrap().status(),
            StatusCode::NOT_FOUND
        );
    }
    browser.login(1).await;
    let old_cookie = browser.cookie.clone();
    let page = browser.page(&f.entry.approval_nonce).await;
    let body = json!({"consent_view_digest": page["consent_view_digest"]});
    for (header, csrf) in [
        ("x-stellar-approval-csrf", "wrong"),
        (
            "x-stellar-remote-approval-csrf",
            page["csrf"].as_str().unwrap(),
        ),
    ] {
        let response = browser
            .request(
                "POST",
                &format!("/approval/{}/challenge", f.entry.approval_nonce),
            )
            .header(header, csrf)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
    browser.login(2).await;
    let mut request = browser
        .request("GET", "/static/mainnet-presence.js")
        .build()
        .unwrap();
    request
        .headers_mut()
        .insert("cookie", old_cookie.parse().unwrap());
    let response = browser.client.execute(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let response = browser
        .action(
            &f.entry.approval_nonce,
            page["csrf"].as_str().unwrap(),
            "challenge",
            &body,
        )
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(f.stored().attestation_blob_b64.is_none());
    {
        use stellar_agent_approval_remote::session::{SESSION_ABSOLUTE_TTL, SessionState};
        let state = handle.session_for_test();
        let mut guard = state.lock().unwrap();
        let session = guard.as_ref().unwrap();
        let mut expired = SessionState::generate_at(
            &session.credential_id_b64url,
            Instant::now() - SESSION_ABSOLUTE_TTL - Duration::from_secs(1),
        );
        expired.session_id = session.session_id.clone();
        expired.csrf_key = session.csrf_key;
        *guard = Some(expired);
    }
    assert_eq!(
        browser
            .request("GET", "/static/mainnet-presence.js")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    assert!(f.stored().attestation_blob_b64.is_none());
    handle.shutdown().await.unwrap();
}

#[tokio::test]
#[serial_test::serial]
async fn signed_origin_reject_requires_an_action_assertion() {
    let f = Fixture::new();
    let (handle, mut browser) = f.start(false).await;
    browser.login(1).await;
    let nonce = &f.entry.approval_nonce;
    let (csrf, assertion) = browser.assertion(nonce, 2).await;
    let before = f.counter_bytes();
    assert_eq!(
        browser
            .action(nonce, &csrf, "reject", &json!({}))
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(f.counter_bytes(), before);
    assert!(!matches!(
        f.stored().kind,
        stellar_agent_core::approval::ApprovalKind::Rejected { .. }
    ));
    let response = browser.action(nonce, &csrf, "reject", &assertion).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(matches!(
        f.stored().kind,
        stellar_agent_core::approval::ApprovalKind::Rejected { .. }
    ));
    assert_ne!(f.counter_bytes(), before);
    let after = f.counter_bytes();
    assert_ne!(
        browser
            .action(nonce, &csrf, "reject", &assertion)
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(f.counter_bytes(), after);
    handle.shutdown().await.unwrap();
}

#[tokio::test]
#[serial_test::serial]
async fn signed_origin_login_continues_to_the_selected_id() {
    let f = Fixture::new();
    let (mut handle, mut browser) = f.start(true).await;
    let nonce = &f.entry.approval_nonce;
    let response = browser
        .request("GET", &format!("/approvals/{nonce}"))
        .send()
        .await
        .unwrap();
    let html = response.text().await.unwrap();
    assert_eq!(
        island(&html, "login-destination")["destination"],
        format!("/approval/{nonce}")
    );
    assert!(html.contains("/static/signed-login.js"));
    assert!(!html.contains("/bootstrap/"));
    browser.login(1).await;
    let response = browser
        .request("GET", &format!("/approvals/{nonce}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.headers()["location"], format!("/approval/{nonce}"));
    let (csrf, assertion) = browser.assertion(nonce, 2).await;
    assert_eq!(
        browser
            .action(nonce, &csrf, "assertion", &assertion)
            .await
            .status(),
        StatusCode::OK
    );
    let presence = handle
        .take_completion()
        .unwrap()
        .await_presence(Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(presence.approval_nonce(), nonce);
    assert!(f.stored().attestation_blob_b64.is_none());
    let address = handle.local_addr();
    handle.shutdown().await.unwrap();
    assert!(std::net::TcpListener::bind(address).is_ok());
}

#[test]
fn public_remote_approval_docs_cover_signed_origin_and_counters() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let cases: &[(&str, &str, &[&str])] = &[
        (
            "CHANGELOG.md",
            "### Added",
            &["TLS", "counters", "restart", "HTTPS"],
        ),
        (
            "crates/stellar-agent-approval-remote/src/lib.rs",
            "",
            &[
                "policy credentials",
                "counter",
                "commit",
                "reload",
                "one entry",
            ],
        ),
        (
            "crates/stellar-agent-approval-remote/src/tls.rs",
            "",
            &[
                "configured paths",
                "SPKI",
                "fingerprint",
                "public CA",
                "private CA",
                "reload",
                "proxies",
            ],
        ),
        (
            "crates/stellar-agent-core/src/approval/presence.rs",
            "",
            &["Localhost", "strict increase", "commit"],
        ),
        (
            "SECURITY.md",
            "## Scope notes for the current alpha",
            &["SPKI", "counters", "zero", "HTTPS", "display"],
        ),
        (
            "docs/remote-approval.md",
            "## Trust model",
            &[
                "approval.mainnet_remote_unsupported",
                "version 5",
                "version 2",
            ],
        ),
        (
            "docs/remote-approval.md",
            "### The `[remote_approval]` profile block",
            &[
                "cert_path",
                "key_path",
                "absolute",
                "working directory",
                "incomplete",
            ],
        ),
        (
            "docs/remote-approval.md",
            "## Signed-origin mainnet consent",
            &[
                "SPKI",
                "fingerprint",
                "allowlist",
                "zero",
                "commit",
                "public-CA",
                "private CA",
                "proxies",
                "restart",
                "reload",
                "approve.remote_tls_unavailable",
                "approval.cert_pin_mismatch",
                "approval.origin_profile_mismatch",
                "--confirm-remote-exposure",
                "--no-open",
                "stderr",
                "token",
                "interruption",
                "approval.listener_busy",
            ],
        ),
        (
            "docs/remote-approval.md",
            "## Starting the testnet listener",
            &["absent", "provisions"],
        ),
        (
            "docs/profiles.md",
            "#### Approval origin configuration",
            &[
                "cert_path",
                "key_path",
                "absolute",
                "working directory",
                "SPKI",
                "allowlist",
                "zero",
                "commit",
                "restart",
                "local-only",
            ],
        ),
        (
            "docs/profiles.md",
            "#### Approval credentials",
            &["HTTPS", "display"],
        ),
        (
            "docs/profiles.md",
            "### Policy and setup diagnostics",
            &[
                "approve.remote_tls_unavailable",
                "approval.cert_pin_mismatch",
                "approval.origin_profile_mismatch",
                "approval.listener_busy",
            ],
        ),
        (
            "docs/cli-reference/index.md",
            "## Mainnet write behavior",
            &["HTTPS", "display"],
        ),
        (
            "docs/cli-reference/profile-and-governance.md",
            "## `approve`",
            &["signed approval origin"],
        ),
        (
            "docs/cli-reference/profile-and-governance.md",
            "### `approve --id <NONCE> --profile <name>`",
            &["stderr"],
        ),
        (
            "docs/cli-reference/profile-and-governance.md",
            "### `approve serve --remote`",
            &[
                "approval.mainnet_remote_unsupported",
                "cert_path",
                "key_path",
                "working directory",
                "counters",
                "restart",
                "--confirm-remote-exposure",
                "--no-open",
                "stderr",
                "interruption",
                "approval.listener_busy",
            ],
        ),
        (
            "docs/concepts.md",
            "### The attestation",
            &[
                "version 2",
                "counters",
                "zero",
                "commit",
                "HTTPS",
                "display",
            ],
        ),
        (
            "docs/getting-started.md",
            "## Mainnet configurations and scope",
            &["HTTPS", "display"],
        ),
        (
            "docs/mcp.md",
            "### Classic mainnet authorization",
            &["signed approval origin"],
        ),
        (
            "docs/mcp.md",
            "#### Mainnet x402 calls",
            &["HTTPS", "local inbox"],
        ),
        (
            "docs/maintainers/security-internals.md",
            "#### Mainnet presence consent",
            &[
                "SPKI",
                "forwarded",
                "counters",
                "webauthn_assertion_invalid",
                "approval.presence_invalid",
                "restart",
                "HTTPS",
                "display",
            ],
        ),
        (
            "skills/stellar-agent-wallet/SKILL.md",
            "",
            &["signed-origin HTTPS"],
        ),
        (
            "skills/stellar-agent-wallet/references/approvals-and-audit.md",
            "### Classic mainnet confirmation",
            &["HTTPS", "display"],
        ),
        (
            "skills/stellar-agent-wallet/references/profiles-and-keys.md",
            "#### Approval origin configuration",
            &[
                "cert_path",
                "key_path",
                "absolute",
                "working directory",
                "SPKI",
                "allowlist",
                "zero",
                "commit",
                "restart",
                "local-only",
            ],
        ),
        (
            "skills/stellar-agent-wallet/references/profiles-and-keys.md",
            "#### Approval credentials",
            &["HTTPS", "display"],
        ),
        (
            "skills/stellar-agent-wallet/references/cli-reference.md",
            "### Mainnet write behavior",
            &["HTTPS", "display"],
        ),
        (
            "skills/stellar-agent-wallet/references/cli-reference.md",
            "### `approve serve --remote`",
            &[
                "approval.mainnet_remote_unsupported",
                "cert_path",
                "key_path",
                "working directory",
                "counters",
                "restart",
                "--confirm-remote-exposure",
                "--no-open",
                "stderr",
                "interruption",
                "approval.listener_busy",
            ],
        ),
        (
            "skills/stellar-agent-wallet/references/protocols.md",
            "### `stellar_x402_create_payment`",
            &["HTTPS"],
        ),
        (
            "skills/stellar-agent-wallet/references/troubleshooting.md",
            "### Policy and setup diagnostics",
            &[
                "approve.remote_tls_unavailable",
                "approval.cert_pin_mismatch",
                "approval.origin_profile_mismatch",
                "approval.listener_busy",
            ],
        ),
        (
            "crates/stellar-agent-approval-remote/README.md",
            "",
            &[
                "policy credentials",
                "counter",
                "commit",
                "cert_path",
                "key_path",
                "SPKI",
                "fingerprint",
                "public CA",
                "private CA",
                "restart",
                "proxies",
                "--no-open",
                "token",
                "one entry",
                "approval.listener_busy",
            ],
        ),
    ];
    for (path, heading, tokens) in cases {
        let text = std::fs::read_to_string(root.join(path)).unwrap();
        let section = if heading.is_empty() {
            if path.ends_with(".rs") {
                text.lines()
                    .take_while(|line| line.starts_with("//!") || line.is_empty())
                    .collect::<Vec<_>>()
                    .join("\n")
            } else {
                text.clone()
            }
        } else {
            let (_, tail) = text
                .split_once(heading)
                .unwrap_or_else(|| panic!("{path}: missing section {heading}"));
            tail.lines()
                .skip(1)
                .take_while(|line| !line.starts_with('#'))
                .collect::<Vec<_>>()
                .join("\n")
        }
        .to_ascii_lowercase();
        for token in *tokens {
            assert!(
                section.contains(&token.to_ascii_lowercase()),
                "{path}: {heading}: missing {token}"
            );
        }
        assert!(
            !text.contains("no listener in this release serves"),
            "{path}"
        );
        assert!(
            !text.contains("They grant no runtime remote approval support"),
            "{path}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial_test::serial]
async fn signed_origin_concurrent_counters_keep_the_highest_value() {
    let f = Fixture::new();
    let (handle, mut first) = f.start(false).await;
    first.login(1).await;
    let mut second = Browser::new(handle.local_addr(), SIGNED_ORIGIN);
    let auth = fixture_authenticator();
    let (a, b) = tokio::join!(first.login_with(&auth, 2), second.login_with(&auth, 3));
    assert!(a == StatusCode::OK || a == StatusCode::BAD_REQUEST);
    assert_eq!(b, StatusCode::OK);
    let counters = String::from_utf8(f.counter_bytes()).unwrap();
    assert_eq!(counters.matches("sign_count = ").count(), 1);
    assert!(counters.contains("sign_count = 3"));
    handle.shutdown().await.unwrap();
}

#[tokio::test]
#[serial_test::serial]
async fn approval_link_path_serves_the_id() {
    let f = Fixture::new();
    let (handle, mut browser) = f.start(true).await;
    let path = format!("/approvals/{}", f.entry.approval_nonce);
    let html = browser
        .request("GET", &path)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(
        island(&html, "login-destination")["destination"],
        format!("/approval/{}", f.entry.approval_nonce)
    );
    assert!(!html.contains("/bootstrap/") && !html.contains("?token="));
    browser.login(1).await;
    let response = browser.request("GET", &path).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = response.headers()["location"].to_str().unwrap();
    assert_eq!(location, format!("/approval/{}", f.entry.approval_nonce));
    let page = browser
        .request("GET", location)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(
        island(&page, "presence-data")["nonce"],
        f.entry.approval_nonce
    );
    handle.shutdown().await.unwrap();
}
