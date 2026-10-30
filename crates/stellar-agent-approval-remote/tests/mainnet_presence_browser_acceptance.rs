//! Offline browser acceptance of enrollment and mainnet consent.
//!
//! One headless Chromium with a CDP virtual authenticator enrolls an approval
//! credential, then drives both consent listeners: the mainnet inbox, where
//! a verified assertion records the consent, and a command's one-shot
//! ceremony, where the private bootstrap URL lands on the consent page and a
//! verified assertion completes the command's wait.
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
    .with_mainnet_authority(fixture.authority());
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
