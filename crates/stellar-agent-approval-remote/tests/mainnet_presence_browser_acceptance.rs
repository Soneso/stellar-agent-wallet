//! Offline browser acceptance of enrollment and mainnet consent.
//!
//! One headless Chromium with a CDP virtual authenticator enrolls an approval
//! credential, then drives both consent listeners: the mainnet inbox, where
//! a verified assertion records the consent, and a command's one-shot
//! ceremony, where the private bootstrap URL lands on the consent page and a
//! verified assertion completes the command's wait.
//!
//! The HTTPS cases run through the acceptance runner, which installs its
//! test certificate authority for Chromium alone. Chromium loads a page the
//! authority issued and refuses the signed consent listener when another
//! authority issued its leaf, and that refusal stores nothing. A credential
//! enrolled at the signed origin then consents there once, while an
//! assertion made at another origin, a page of another RP, and the local
//! inbox under the signed policy record nothing.
#![cfg(feature = "operator-enroll-browser-acceptance")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::too_many_lines,
    reason = "browser acceptance assertions"
)]
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chromiumoxide::{
    browser::{Browser, BrowserConfig},
    cdp::browser_protocol::web_authn::{
        AddVirtualAuthenticatorParams, AuthenticatorProtocol, AuthenticatorTransport, EnableParams,
        SetUserVerifiedParams, VirtualAuthenticatorOptions,
    },
};
use futures::StreamExt as _;
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use stellar_agent_approval_ui::{
    DecisionContext, MainnetPresenceConfig, PageIdentity, ServeConfig,
    operator_enroll::start_mainnet_approval_enroll, start_mainnet_presence, start_serve,
};
use stellar_agent_core::approval::{
    ApprovalContext, PendingApprovalStore, mainnet_fixtures::MainnetConsentFixture,
};

#[path = "common/trusted_browser.rs"]
mod trusted_browser;

/// The consent recording of a profile whose entries no durable record names,
/// as `approve serve` completes them: every consent completes and nothing is
/// written.
struct NoDurableRecords;

impl stellar_agent_approval_ui::decision::ConsentRecording for NoDurableRecords {
    fn precheck(
        &self,
        _: &stellar_agent_core::approval::PendingApproval,
    ) -> Result<(), stellar_agent_core::error::WalletError> {
        Ok(())
    }

    fn publishes(&self, _: stellar_agent_core::approval::witness::ApprovedKind) -> bool {
        false
    }

    fn complete(
        &self,
        _: stellar_agent_approval_ui::decision::VerifiedConsent,
        _: stellar_agent_approval_ui::decision::ConsentRowSource,
    ) -> Result<(), stellar_agent_core::error::WalletError> {
        Ok(())
    }
}

async fn text(page: &chromiumoxide::Page, expression: &str) -> String {
    page.evaluate(expression)
        .await
        .unwrap()
        .into_value()
        .unwrap()
}
/// The page's refusal when the authenticator declines user verification: the
/// browser rejects the assertion request and the page cancels the ceremony.
const UV_OFF_REFUSAL: &str = "Mainnet consent is canceled; no approval is recorded.";

/// Counts every WebAuthn assertion request and every POST the page sends.
/// Installed before any navigation, so it wraps the page's own globals.
const DRIVER_COUNTER: &str = r"(() => {
  window.__presenceDriverCalls = 0;
  const credentials = navigator.credentials;
  if (credentials && credentials.get) {
    const get = credentials.get.bind(credentials);
    credentials.get = function (options) {
      window.__presenceDriverCalls += 1;
      return get(options);
    };
  }
  const fetch = window.fetch.bind(window);
  window.fetch = function (input, init) {
    if (init && String(init.method).toUpperCase() === 'POST') {
      window.__presenceDriverCalls += 1;
    }
    return fetch(input, init);
  };
})();";

/// Waits for the consent page script to wire its handlers, then checks that
/// loading the page started no ceremony and sent no request.
async fn wait_ready_without_ceremony(page: &chromiumoxide::Page) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while text(
        page,
        "document.documentElement.getAttribute('data-presence') || ''",
    )
    .await
        != "ready"
    {
        assert!(Instant::now() < deadline, "consent page script is ready");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let calls: u64 = page
        .evaluate("window.__presenceDriverCalls")
        .await
        .unwrap()
        .into_value()
        .unwrap();
    assert_eq!(calls, 0, "page load starts no ceremony");
}

async fn wait_path(page: &chromiumoxide::Page, path: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while text(page, "window.location.pathname").await != path {
        assert!(Instant::now() < deadline, "bootstrap lands on {path}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn click(page: &chromiumoxide::Page, selector: &str) {
    page.find_element(selector)
        .await
        .unwrap()
        .click()
        .await
        .unwrap();
}

async fn wait_text(page: &chromiumoxide::Page, id: &str, needle: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let value = text(
            page,
            &format!("document.getElementById('{id}')?.textContent || ''"),
        )
        .await;
        if value.contains(needle) {
            return value;
        }
        assert!(
            Instant::now() < deadline,
            "page does not show {needle}: {value}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial_test::serial]
#[ignore = "requires installed Chromium and loopback sockets"]
async fn mainnet_presence_page_drives_real_webauthn() {
    let fixture = MainnetConsentFixture::new("browser");
    let profile = tempfile::tempdir().unwrap();
    let mut builder = BrowserConfig::builder()
        .no_sandbox()
        .user_data_dir(profile.path())
        .arg("--disable-background-networking")
        .arg("--disable-component-update")
        .arg("--disable-sync")
        .arg("--no-first-run");
    if let Some(path) = std::env::var_os("CHROMIUM").or_else(|| std::env::var_os("CHROME")) {
        builder = builder.chrome_executable(path);
    }
    let (mut browser, mut handler) = Browser::launch(builder.build().unwrap())
        .await
        .expect("installed Chromium launches");
    let task = tokio::spawn(async move { while handler.next().await.is_some() {} });
    let page = browser.new_page("about:blank").await.unwrap();
    page.evaluate_on_new_document(DRIVER_COUNTER).await.unwrap();
    page.execute(EnableParams::default()).await.unwrap();
    let options = VirtualAuthenticatorOptions::builder()
        .protocol(AuthenticatorProtocol::Ctap2)
        .transport(AuthenticatorTransport::Internal)
        .has_user_verification(true)
        .is_user_verified(true)
        .has_resident_key(true)
        .automatic_presence_simulation(true)
        .build()
        .unwrap();
    let authenticator = page
        .execute(AddVirtualAuthenticatorParams::new(options))
        .await
        .unwrap()
        .result
        .authenticator_id;
    let mut enrollment = start_mainnet_approval_enroll(
        fixture.name().to_owned(),
        Some("browser".to_owned()),
        PageIdentity::neutral(),
    )
    .await
    .unwrap();
    page.goto(enrollment.enroll_url()).await.unwrap();
    page.find_element("#enroll-btn")
        .await
        .unwrap()
        .click()
        .await
        .unwrap();
    let staged = enrollment
        .await_completion(Duration::from_secs(30))
        .await
        .unwrap();
    wait_text(&page, "status", "Awaiting confirmation").await;
    let code = text(
        &page,
        "document.getElementById('confirmation-code').textContent",
    )
    .await;
    let credential = staged
        .confirm(&code, Instant::now())
        .unwrap()
        .into_mainnet_policy_credential()
        .unwrap();
    enrollment.shutdown().await.unwrap();
    let raw = fixture.policy_body(2, &[]).replace(
        "approval_credentials = [\n]",
        &format!(
            "approval_credentials = [{}]",
            credential.policy_entry_toml()
        ),
    );
    fixture.write_signed(&raw);
    let entry = fixture.payment(600_000);
    let mut store = PendingApprovalStore::open(fixture.store_path()).unwrap();
    store
        .insert(
            entry.clone(),
            stellar_agent_core::timefmt::now_unix_ms().unwrap(),
        )
        .unwrap();
    drop(store);
    let context = DecisionContext::new(
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
    .with_consent_recording(Arc::new(NoDurableRecords));
    let (count, _receiver) = tokio::sync::mpsc::unbounded_channel();
    let handle = start_serve(ServeConfig::new(
        "127.0.0.1:0".parse().unwrap(),
        context,
        count,
        false,
    ))
    .await
    .unwrap();
    page.goto(handle.bootstrap_url()).await.unwrap();
    wait_path(&page, "/inbox").await;
    page.goto(format!(
        "http://localhost:{}/approval/{}",
        handle.local_addr().port(),
        entry.approval_nonce
    ))
    .await
    .unwrap();
    wait_ready_without_ceremony(&page).await;
    let body = text(&page, "document.body.textContent").await;
    assert!(body.contains(stellar_agent_core::approval::mainnet_fixtures::ALLOWED_DESTINATION));
    assert!(body.contains("0.000001"), "{body}");
    assert!(body.contains("approved"), "{body}");
    assert!(
        PendingApprovalStore::open(fixture.store_path())
            .unwrap()
            .get(&entry.approval_nonce)
            .unwrap()
            .mainnet_presence
            .is_none()
    );
    page.execute(SetUserVerifiedParams::new(authenticator.clone(), false))
        .await
        .unwrap();
    click(&page, "#presence-approve").await;
    wait_text(&page, "presence-result", UV_OFF_REFUSAL).await;
    assert!(
        PendingApprovalStore::open(fixture.store_path())
            .unwrap()
            .get(&entry.approval_nonce)
            .unwrap()
            .attestation_blob_b64
            .is_none()
    );
    page.reload().await.unwrap();
    page.execute(SetUserVerifiedParams::new(authenticator, true))
        .await
        .unwrap();
    wait_ready_without_ceremony(&page).await;
    click(&page, "#presence-approve").await;
    wait_text(&page, "presence-result", "Status: attested").await;
    let store = PendingApprovalStore::open(fixture.store_path()).unwrap();
    let record = store.get(&entry.approval_nonce).unwrap();
    assert!(record.mainnet_presence.is_some());
    let blob = URL_SAFE_NO_PAD
        .decode(record.attestation_blob_b64.as_ref().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let expectation = stellar_agent_core::approval::witness::ApprovalExpectation {
        kind: stellar_agent_core::approval::witness::ApprovedKind::Payment,
        subject: stellar_agent_core::approval::mainnet_consent_subject(&entry, &fixture.binding())
            .unwrap(),
    };
    stellar_agent_core::approval::witness::verify_approval(
        &store,
        fixture.profile(),
        fixture.name(),
        &entry.approval_nonce,
        &blob,
        &expectation,
        &fixture.current_policy(),
        stellar_agent_core::timefmt::now_unix_ms().unwrap(),
    )
    .unwrap();
    assert_eq!(
        std::fs::read_to_string(fixture.audit_path())
            .unwrap()
            .matches("approval_attested")
            .count(),
        1
    );
    drop(store);
    handle.shutdown().await.unwrap();

    let ceremony = fixture.payment(600_000);
    let mut store = PendingApprovalStore::open(fixture.store_path()).unwrap();
    store
        .insert(
            ceremony.clone(),
            stellar_agent_core::timefmt::now_unix_ms().unwrap(),
        )
        .unwrap();
    drop(store);
    let mut presence = start_mainnet_presence(MainnetPresenceConfig {
        intent: None,
        entry: ceremony.clone(),
        context: ApprovalContext::from_profile(fixture.name(), fixture.profile()),
        authority: fixture.authority(),
        store_path: fixture.store_path(),
        page_identity: PageIdentity::neutral(),
    })
    .await
    .unwrap();
    page.goto(presence.bootstrap_url()).await.unwrap();
    wait_path(&page, &format!("/approval/{}", ceremony.approval_nonce)).await;
    wait_ready_without_ceremony(&page).await;
    assert!(
        page.find_element("#presence-reject").await.is_err(),
        "a command's ceremony offers cancel, not reject"
    );
    page.find_element("#presence-cancel").await.unwrap();
    click(&page, "#presence-approve").await;
    wait_text(&page, "presence-result", "Presence verified").await;
    let verified = presence
        .await_presence(Instant::now() + Duration::from_secs(10))
        .await
        .unwrap();
    assert_eq!(verified.approval_nonce(), ceremony.approval_nonce);
    let store = PendingApprovalStore::open(fixture.store_path()).unwrap();
    let record = store.get(&ceremony.approval_nonce).unwrap();
    assert!(
        record.attestation_blob_b64.is_none() && record.mainnet_presence.is_none(),
        "the command, not the ceremony, records the consent"
    );
    drop(store);
    presence.shutdown().await.unwrap();
    browser.close().await.unwrap();
    task.abort();
}

/// Records the RP each WebAuthn assertion request names and the client data
/// of the assertion the browser returns. Installed before any navigation.
const ASSERTION_RECORDER: &str = r"(() => {
  const credentials = navigator.credentials;
  if (!credentials || !credentials.get) { return; }
  const get = credentials.get.bind(credentials);
  credentials.get = function (options) {
    window.__presenceRpId = options && options.publicKey ? options.publicKey.rpId : null;
    return get(options).then(function (assertion) {
      window.__presenceClient = JSON.parse(new TextDecoder().decode(assertion.response.clientDataJSON));
      return assertion;
    });
  };
})();";

/// Requests a consent challenge for `nonce` from the open consent page with
/// the page's own CSRF value and session proof, and returns the status and
/// the JSON reply.
fn challenge_script(nonce: &str) -> String {
    format!(
        "(async () => {{ const d = JSON.parse(document.getElementById('presence-data').textContent);\
         const r = await fetch('/approval/{nonce}/challenge', {{ method: 'POST', credentials: 'same-origin',\
         headers: {{ 'Content-Type': 'application/json', 'X-Stellar-Approval-CSRF': d.csrf,\
         'X-Session-Proof': window.sessionStorage.getItem(d.storageKey) || '' }},\
         body: JSON.stringify({{ consent_view_digest: d.consent_view_digest }}) }});\
         return {{ status: r.status, body: await r.json() }}; }})()"
    )
}

/// Runs `navigator.credentials.get` in the current page over `options`, a
/// challenge reply of the signed listener, and returns the assertion in the
/// consent page's wire form, or the name of the browser's error.
fn get_script(options: &serde_json::Value) -> String {
    format!(
        "(async () => {{ const o = {options};\
         const dec = v => Uint8Array.from(atob(v.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));\
         const enc = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');\
         try {{ const a = await navigator.credentials.get({{ publicKey: {{ challenge: dec(o.challenge), rpId: o.rp_id,\
           allowCredentials: o.allow_credentials.map(id => ({{ type: 'public-key', id: dec(id) }})),\
           userVerification: 'required', timeout: 10000 }} }});\
           return {{ request_id: o.request_id, credential_id_b64url: enc(a.rawId),\
             authenticator_data_b64url: enc(a.response.authenticatorData),\
             client_data_json_b64url: enc(a.response.clientDataJSON),\
             signature_der_b64url: enc(a.response.signature) }};\
         }} catch (e) {{ return {{ error: e.name }}; }} }})()"
    )
}

/// Posts `assertion` for `nonce` from the open consent page and returns the
/// status and the JSON reply.
fn assertion_script(nonce: &str, assertion: &serde_json::Value) -> String {
    format!(
        "(async () => {{ const d = JSON.parse(document.getElementById('presence-data').textContent);\
         const r = await fetch('/approval/{nonce}/assertion', {{ method: 'POST', credentials: 'same-origin',\
         headers: {{ 'Content-Type': 'application/json', 'X-Stellar-Approval-CSRF': d.csrf }},\
         body: JSON.stringify({assertion}) }});\
         return {{ status: r.status, body: await r.json() }}; }})()"
    )
}

/// Inserts a fresh payment approval into the fixture's store.
fn insert_payment(
    fixture: &MainnetConsentFixture,
) -> stellar_agent_core::approval::PendingApproval {
    let entry = fixture.payment(600_000);
    PendingApprovalStore::open(fixture.store_path())
        .unwrap()
        .insert(
            entry.clone(),
            stellar_agent_core::timefmt::now_unix_ms().unwrap(),
        )
        .unwrap();
    entry
}

/// Starts the signed-origin consent listener of the fixture's profile under
/// its current policy.
async fn signed_listener(
    fixture: &MainnetConsentFixture,
) -> stellar_agent_approval_remote::RemoteServeHandle {
    let current = fixture.authority().load_current().unwrap();
    let profile = current.profile();
    let remote = profile.remote_approval.as_ref().unwrap();
    let decision = DecisionContext::new(
        ApprovalContext::from_profile(fixture.name(), profile),
        fixture.store_path(),
        profile.attestation_key_id.clone(),
        stellar_agent_core::profile::owner_key::OwnerKeyContext::for_profile(
            fixture.name(),
            profile,
        ),
        Arc::new(Mutex::new(fixture.audit_writer())),
        None,
    )
    .with_mainnet_authority(fixture.authority())
    .with_consent_recording(Arc::new(NoDurableRecords));
    let config = stellar_agent_approval_remote::RemoteServeConfig::from_profile(
        remote.bind.parse().unwrap(),
        remote,
        stellar_agent_core::approval::RemoteApprovalAuthority::for_profile(fixture.name()).unwrap(),
        decision,
    )
    .await
    .unwrap();
    stellar_agent_approval_remote::start_remote_serve(config)
        .await
        .unwrap()
}

/// The bytes of the profile's credential counter file, empty when absent.
fn counter_bytes(fixture: &MainnetConsentFixture) -> Vec<u8> {
    let path = stellar_agent_core::approval::RemoteApprovalAuthority::for_profile(fixture.name())
        .unwrap()
        .credentials_path()
        .to_path_buf();
    std::fs::read(path).unwrap_or_default()
}

/// The trust controls of this suite. Positive: Chromium loads a page whose
/// leaf the runner's test authority issued, through ordinary certificate
/// validation. Negative: the signed consent listener serving a leaf from an
/// authority Chromium does not hold fails certificate verification, its
/// approval link never loads, and the store records nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial_test::serial]
#[ignore = "requires Chromium and the acceptance runner's test authority"]
async fn signed_origin_browser_trusts_only_the_test_authority() {
    let trust = trusted_browser::BrowserTrust::from_runner();
    let chromium = trusted_browser::launch(&trust).await;
    let page = chromium.browser.new_page("about:blank").await.unwrap();
    trusted_browser::assert_trusted_page_loads(&page, &trust.trusted()).await;

    let port = trusted_browser::free_port();
    let fixture = trusted_browser::signed_fixture(
        "browser-trust",
        port,
        &trust.untrusted(),
        &trust.untrusted_pin(),
        &[&stellar_agent_test_support::webauthn::fixture_authenticator()],
    );
    let entry = insert_payment(&fixture);
    let handle = signed_listener(&fixture).await;
    let link = format!(
        "{}/approvals/{}",
        trusted_browser::origin_at(port),
        entry.approval_nonce
    );
    trusted_browser::assert_authority_refused(&page, &link).await;
    let stored = PendingApprovalStore::open(fixture.store_path())
        .unwrap()
        .get(&entry.approval_nonce)
        .unwrap()
        .clone();
    assert!(stored.attestation_blob_b64.is_none() && stored.mainnet_presence.is_none());
    assert!(
        counter_bytes(&fixture).is_empty(),
        "no sign-in reached the counters"
    );
    handle.shutdown().await.unwrap();
    chromium.close().await;
}

/// A credential the browser creates at the signed origin consents there
/// once, through the public approval link. The same browser's assertion made
/// at another origin of that RP, a page of another RP, and the local inbox
/// running under the signed policy record nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial_test::serial]
#[ignore = "requires Chromium and the acceptance runner's test authority"]
async fn signed_origin_browser_consent_and_foreign_origin_refusal() {
    use stellar_agent_core::approval::mainnet_fixtures::SIGNED_RP_ID;
    use trusted_browser::{click, eval_json, navigate, timed, wait_for};

    let trust = trusted_browser::BrowserTrust::from_runner();
    let pin = trust.trusted_pin();
    let port = trusted_browser::free_port();
    let origin = trusted_browser::origin_at(port);
    let software = stellar_agent_test_support::webauthn::fixture_authenticator();
    let fixture = trusted_browser::signed_fixture(
        "signed-browser",
        port,
        &trust.trusted(),
        &pin,
        &[&software],
    );
    let chromium = trusted_browser::launch(&trust).await;
    let (page, authenticator) = trusted_browser::authenticator_page(&chromium.browser).await;
    timed(
        "the driver counter",
        page.evaluate_on_new_document(DRIVER_COUNTER),
    )
    .await
    .unwrap();
    timed(
        "the assertion recorder",
        page.evaluate_on_new_document(ASSERTION_RECORDER),
    )
    .await
    .unwrap();

    // The local inbox starts under a local policy and keeps its open page.
    fixture.write_signed(&fixture.policy_body(fixture.sequence() + 2, &[&software]));
    let local_entry = insert_payment(&fixture);
    let context = DecisionContext::new(
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
    .with_consent_recording(Arc::new(NoDurableRecords));
    let local = start_serve(ServeConfig::new(
        "127.0.0.1:0".parse().unwrap(),
        context,
        tokio::sync::mpsc::unbounded_channel().0,
        false,
    ))
    .await
    .unwrap();
    let local_page = timed("the local page", chromium.browser.new_page("about:blank"))
        .await
        .unwrap();
    navigate(&local_page, &local.bootstrap_url()).await;
    wait_for(&local_page, "window.location.pathname", "/inbox").await;
    navigate(
        &local_page,
        &format!(
            "http://localhost:{}/approval/{}",
            local.local_addr().port(),
            local_entry.approval_nonce
        ),
    )
    .await;
    wait_for(
        &local_page,
        "document.documentElement.getAttribute('data-presence') || ''",
        "ready",
    )
    .await;

    // Input events reach the foreground tab only; the local page stays open
    // behind the authenticator's page.
    timed("the authenticator page to front", page.bring_to_front())
        .await
        .unwrap();

    // Enrollment at the signed origin of a bootstrap policy; the owner then
    // signs the exported credential into the policy.
    trusted_browser::sign_origin_policy(&fixture, 3, port, &pin, &[&software], &[]);
    let approval_origin = fixture
        .current_policy()
        .mainnet()
        .unwrap()
        .approval_origin
        .clone()
        .unwrap();
    assert_eq!(approval_origin.as_str(), origin);
    let mut enrollment = stellar_agent_approval_remote::enroll_listener::start_signed_enrollment(
        stellar_agent_approval_remote::enroll_listener::SignedEnrollmentConfig::new(
            fixture.name(),
            fixture.profile().clone(),
            approval_origin,
            pin,
            Duration::from_secs(300),
        ),
        |_| {},
    )
    .await
    .unwrap();
    let code = enrollment.enrollment_code().to_owned();
    let (staged, shown) =
        trusted_browser::enroll_in_browser(&page, &mut enrollment, &code, "signed").await;
    let credential = staged
        .confirm(&shown, Instant::now())
        .unwrap()
        .into_mainnet_policy_credential()
        .unwrap();
    enrollment.shutdown().await.unwrap();
    trusted_browser::sign_origin_policy(
        &fixture,
        4,
        port,
        &pin,
        &[],
        &[credential.policy_entry_toml()],
    );

    // The running local page refuses consent under the signed policy.
    let refusal = eval_json(&local_page, &challenge_script(&local_entry.approval_nonce)).await;
    assert_eq!(
        refusal["body"]["error"], "approval.origin_signed_remote",
        "{refusal}"
    );
    let stored = PendingApprovalStore::open(fixture.store_path())
        .unwrap()
        .get(&local_entry.approval_nonce)
        .unwrap()
        .clone();
    assert!(stored.attestation_blob_b64.is_none() && stored.mainnet_presence.is_none());
    local.shutdown().await.unwrap();
    timed("closing the local page", local_page.close())
        .await
        .unwrap();

    // Consent at the signed origin through the public approval link.
    let entry = insert_payment(&fixture);
    let foreign_entry = insert_payment(&fixture);
    let handle = signed_listener(&fixture).await;
    assert_eq!(handle.public_origin(), origin);
    navigate(
        &page,
        &format!("{origin}/approvals/{}", entry.approval_nonce),
    )
    .await;
    click(&page, "#login-btn").await;
    wait_for(
        &page,
        "window.location.pathname",
        &format!("/approval/{}", entry.approval_nonce),
    )
    .await;
    wait_ready_without_ceremony(&page).await;
    let body = text(&page, "document.body.textContent").await;
    assert!(body.contains(stellar_agent_core::approval::mainnet_fixtures::ALLOWED_DESTINATION));
    assert!(body.contains("0.000001"), "{body}");
    timed(
        "user verification off",
        page.execute(SetUserVerifiedParams::new(authenticator.clone(), false)),
    )
    .await
    .unwrap();
    click(&page, "#presence-approve").await;
    wait_text(&page, "presence-result", UV_OFF_REFUSAL).await;
    assert!(
        PendingApprovalStore::open(fixture.store_path())
            .unwrap()
            .get(&entry.approval_nonce)
            .unwrap()
            .attestation_blob_b64
            .is_none()
    );
    timed("the reload", page.reload()).await.unwrap();
    timed(
        "user verification on",
        page.execute(SetUserVerifiedParams::new(authenticator, true)),
    )
    .await
    .unwrap();
    wait_ready_without_ceremony(&page).await;
    click(&page, "#presence-approve").await;
    wait_text(&page, "presence-result", "Status: attested").await;
    assert_eq!(
        eval_json(&page, "window.__presenceRpId").await,
        SIGNED_RP_ID
    );
    let client = eval_json(&page, "window.__presenceClient").await;
    assert_eq!(client["origin"], origin.as_str());
    assert_eq!(client["type"], "webauthn.get");

    let store = PendingApprovalStore::open(fixture.store_path()).unwrap();
    let record = store.get(&entry.approval_nonce).unwrap();
    assert_eq!(record.attestation_version, 5);
    let receipt = record.mainnet_presence.as_ref().unwrap();
    assert_eq!(receipt.version(), 2);
    assert_eq!(receipt.expected_origin(), origin);
    assert_eq!(
        receipt.cert_spki_sha256_hex(),
        Some(hex::encode(pin).as_str())
    );
    assert_eq!(
        receipt.listener_policy_digest_hex(),
        Some(receipt.policy_digest_hex())
    );
    assert!(receipt.names_policy(&fixture.current_policy()));
    assert_eq!(
        receipt.credential_id_b64url(),
        credential.credential_id_b64url()
    );
    let blob = URL_SAFE_NO_PAD
        .decode(record.attestation_blob_b64.as_ref().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let expectation = stellar_agent_core::approval::witness::ApprovalExpectation {
        kind: stellar_agent_core::approval::witness::ApprovedKind::Payment,
        subject: stellar_agent_core::approval::mainnet_consent_subject(&entry, &fixture.binding())
            .unwrap(),
    };
    stellar_agent_core::approval::witness::verify_approval(
        &store,
        fixture.profile(),
        fixture.name(),
        &entry.approval_nonce,
        &blob,
        &expectation,
        &fixture.current_policy(),
        stellar_agent_core::timefmt::now_unix_ms().unwrap(),
    )
    .unwrap();
    drop(store);
    let attested = |audit: &str| -> Vec<serde_json::Value> {
        audit
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .filter(|row: &serde_json::Value| row["kind"] == "approval_attested")
            .collect()
    };
    let rows = attested(&std::fs::read_to_string(fixture.audit_path()).unwrap());
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["origin"], "serve-remote");

    // A genuine assertion over a live challenge, made at another origin of
    // the same RP, then posted through the authenticated signed page.
    let other = trusted_browser::serve_page(&trust.trusted()).await;
    navigate(
        &page,
        &format!("{origin}/approval/{}", foreign_entry.approval_nonce),
    )
    .await;
    wait_ready_without_ceremony(&page).await;
    let options = eval_json(&page, &challenge_script(&foreign_entry.approval_nonce)).await;
    assert_eq!(options["status"], 200, "{options}");
    let counters = counter_bytes(&fixture);
    let pending = std::fs::read(fixture.store_path()).unwrap();
    let audit = std::fs::read_to_string(fixture.audit_path()).unwrap();
    let foreign_origin = format!("https://{SIGNED_RP_ID}:{}", other.port);
    navigate(&page, &format!("{foreign_origin}/")).await;
    let assertion = eval_json(&page, &get_script(&options["body"])).await;
    assert!(assertion.get("error").is_none(), "{assertion}");
    assert_eq!(
        eval_json(&page, "window.__presenceClient.origin").await,
        foreign_origin.as_str()
    );
    navigate(
        &page,
        &format!("{origin}/approval/{}", foreign_entry.approval_nonce),
    )
    .await;
    wait_ready_without_ceremony(&page).await;
    let refused = eval_json(
        &page,
        &assertion_script(&foreign_entry.approval_nonce, &assertion),
    )
    .await;
    assert_eq!(
        refused["body"]["error"], "approval.presence_invalid",
        "{refused}"
    );
    assert_eq!(counter_bytes(&fixture), counters);
    assert_eq!(std::fs::read(fixture.store_path()).unwrap(), pending);
    let after = std::fs::read_to_string(fixture.audit_path()).unwrap();
    assert_eq!(attested(&after).len(), attested(&audit).len());

    // A page of another RP cannot request an assertion for the signed RP.
    navigate(
        &page,
        &format!("https://{}:{}/", trusted_browser::FOREIGN_HOST, other.port),
    )
    .await;
    let other_rp = eval_json(&page, &get_script(&options["body"])).await;
    assert_eq!(other_rp["error"], "SecurityError", "{other_rp}");
    assert_eq!(counter_bytes(&fixture), counters);

    handle.shutdown().await.unwrap();
    drop(other);
    chromium.close().await;
}
