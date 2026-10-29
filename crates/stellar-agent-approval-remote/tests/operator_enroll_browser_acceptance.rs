//! Browser-driven acceptance for the interactive operator-enrollment
//! ceremony (`stellar_agent_approval_ui::operator_enroll`).
//!
//! Unlike the sibling `*_testnet_acceptance` suites in this crate, this one
//! has NO testnet/RPC dependency: the interactive enrollment server is
//! purely loopback HTTP with no blockchain interaction. It shares the
//! Chromium/CDP dependency the sibling suites document, which is why it
//! lives in this crate's test dir per the CDP harness and `chromiumoxide`
//! dev-dependency already established here (rather than in
//! `stellar-agent-approval-ui`, which has no CDP harness of its own).
//!
//! # Flow
//!
//! 1. `start_operator_enroll_server` binds a real loopback listener against
//!    a throwaway `OperatorApprovalCredentialStore`.
//! 2. A headless Chromium (chromiumoxide) is launched; the CDP WebAuthn
//!    domain is enabled with an empty virtual authenticator (no credential
//!    pre-seeded) — mirroring the sibling suites' authenticator setup
//!    exactly (CTAP2, resident key, automatic presence simulation).
//! 3. The browser navigates to `handle.enroll_url()` — the SAME method the
//!    CLI uses, so this suite exercises the exact URL an operator would
//!    open: a `localhost`-hostnamed `/bootstrap/{token}` link whose response
//!    sets the session cookie and returns the bootstrap page. The shipped
//!    `/static/session-bootstrap.js` stores the session proof in the tab's
//!    `sessionStorage` and replaces the location with `/enroll`, so the
//!    ceremony below runs with the cookie and the proof a real operator's
//!    tab holds.
//! 4. Types a label into `#label-input`, clicks `#enroll-btn`: the page
//!    requests the server's registration challenge, and a REAL
//!    `navigator.credentials.create()` runs over it through the shipped
//!    `/static/operator-enroll.js`, so the virtual authenticator generates
//!    its own credential id and P-256 keypair, exactly as a hardware key
//!    would, and returns its own `clientDataJSON` and `attestationObject`.
//! 5. `handle.await_completion` resolves once the server has verified the
//!    registration and staged the credential. The page shows its
//!    confirmation code, and the credential store is still empty: nothing
//!    is enrolled before the terminal confirmation.
//! 6. The code the page shows is typed at the confirmation step the CLI
//!    runs (`PendingOperatorEnrollment::confirm`), which persists the
//!    staged credential.
//! 7. Rigorous cross-check (the part a DOM-only assertion cannot provide):
//!    `WebAuthn.getCredentials` returns the virtual authenticator's own
//!    record of what it just created — the STORED SEC1 public key must
//!    equal the public key derived from the PKCS#8 private key CDP
//!    returns, and the STORED sign count must EXACTLY equal CDP's own
//!    `signCount`, which the server reads from the authenticator data
//!    inside the attestation object.
//! 8. A raw second `POST /enroll/credential` carrying no session cookie
//!    confirms the session gate refuses it (`404`) before the completion
//!    latch is even consulted; the bootstrap token was already consumed by
//!    step 3's navigation, so a fresh out-of-browser client cannot establish
//!    a second session against this server run to probe the latch itself —
//!    that is covered by the in-process `operator_enroll::router_tests`.
//!
//! Negative paths (`post_wrong_csrf_...`, `post_duplicate_credential_id_...`)
//! drive the real HTTP surface directly (no browser needed for those, each
//! performing its own bootstrap exchange for the session cookie and proof) to
//! confirm CSRF rejection and the duplicate-id refusal hold against a real
//! TCP listener, not only the in-process router tests. Their registrations
//! come from a software authenticator with a real P-256 key.
//!
//! # Cross-port isolation
//!
//! Browsers scope cookies by host, not by port, so any other service on the
//! same loopback host receives the wallet's session cookie when the browser
//! visits it. The session proof lives in `sessionStorage`, which is scoped
//! to the full origin, port included. `cross_port_cookie_does_not_authorize_*`
//! show both halves against a real Chromium: a second loopback service
//! receives the cookie, its page cannot read the proof, and the cookie plus a
//! valid CSRF value without the proof can neither request a registration
//! challenge, enroll a credential nor decide an approval, while the
//! operator's own tab still can.
//!
//! # Gate
//!
//! ```text
//! cargo test -p stellar-agent-approval-remote --features operator-enroll-browser-acceptance \
//!   --test operator_enroll_browser_acceptance -- --ignored
//! ```
//!
//! # Prerequisites
//!
//! - `CHROMIUM` or `chromium`/`chromium-browser`/`google-chrome` on `PATH`,
//!   or the `CHROME` environment variable pointing to the executable
//!   (`operator_enroll_browser_confirms_then_persists_credential` and the
//!   `cross_port_cookie_does_not_authorize_*` tests).

#![cfg(feature = "operator-enroll-browser-acceptance")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics and unwraps are acceptable in acceptance tests"
)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use chromiumoxide::browser::{Browser, BrowserConfig};
use chromiumoxide::cdp::browser_protocol::web_authn::{
    AddVirtualAuthenticatorParams, AuthenticatorProtocol, AuthenticatorTransport, EnableParams,
    GetCredentialsParams, VirtualAuthenticatorOptions,
};
use chromiumoxide::cdp::js_protocol::runtime::EvaluateParams;
use futures::StreamExt as _;
use p256::SecretKey;
use p256::elliptic_curve::sec1::ToEncodedPoint as _;
use p256::pkcs8::DecodePrivateKey as _;
use serial_test::serial;
use stellar_agent_approval_ui::operator_enroll::test_support::{
    EnrollmentClient, SoftwareRegistrar,
};
use stellar_agent_approval_ui::operator_enroll::{
    OperatorEnrollHandle, PendingOperatorEnrollment, start_operator_enroll_server,
};
use stellar_agent_approval_ui::{DecisionContext, ServeConfig, start_serve};
use stellar_agent_core::approval::operator_credentials::{
    OperatorApprovalCredential, OperatorApprovalCredentialStore,
};
use stellar_agent_core::approval::{
    ApprovalContext, ApprovalKind, DEFAULT_TTL_MS, PendingApprovalStore, fixtures,
    process_uid_for_attestation,
};
use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_core::profile::owner_key::OwnerKeyContext;
use stellar_agent_core::profile::schema::{KeyringEntryRef, Profile};
use stellar_agent_core::timefmt;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

// ─────────────────────────────────────────────────────────────────────────────
// RAII guards
// ─────────────────────────────────────────────────────────────────────────────

/// RAII guard that kills the `chromiumoxide::Browser` subprocess on drop —
/// mirrors the sibling suites' `BrowserGuard`.
struct BrowserGuard(Option<Browser>);

impl Drop for BrowserGuard {
    fn drop(&mut self) {
        if let Some(mut browser) = self.0.take() {
            tokio::task::block_in_place(|| {
                let _ = tokio::runtime::Handle::current().block_on(browser.kill());
            });
        }
    }
}

/// RAII guard that shuts down the operator-enroll server on drop.
struct OperatorEnrollGuard(Option<OperatorEnrollHandle>);

impl Drop for OperatorEnrollGuard {
    #[allow(
        clippy::print_stderr,
        reason = "diagnostic output in test RAII guard; non-fatal shutdown error"
    )]
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            let result = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(handle.shutdown())
            });
            if let Err(e) = result {
                eprintln!(
                    "stellar-agent test: operator-enroll server shutdown error (non-fatal): {e}"
                );
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Browser launch
// ─────────────────────────────────────────────────────────────────────────────

/// Launches a headless Chromium. See the sibling suites' `launch_chromium`
/// for the full rationale (no `--disable-web-security`, `.no_sandbox()` for
/// CI's restricted user namespaces).
async fn launch_chromium() -> (Browser, chromiumoxide::Handler, TempDir) {
    // chromiumoxide's default profile directory is one fixed path under the
    // temp dir, shared by every launch on the host and never cleared, so
    // cookies, virtual-authenticator credentials and other browser state
    // would carry from one suite into the next. Each launch gets its own
    // directory, removed when the returned guard drops.
    let profile = tempfile::Builder::new()
        .prefix("stellar-agent-chromium-")
        .tempdir()
        .expect("profile directory must be created");
    let config = BrowserConfig::builder()
        .no_sandbox()
        .user_data_dir(profile.path())
        .build()
        .expect("BrowserConfig must build");
    assert_eq!(
        config.user_data_dir.as_deref(),
        Some(profile.path()),
        "the browser must run in its own profile directory"
    );
    let (browser, handler) = Browser::launch(config)
        .await
        .expect("Chromium must launch; ensure chromium/google-chrome is on PATH");
    (browser, handler, profile)
}

/// Adds an empty virtual authenticator to `page` and returns its id.
/// Mirrors the sibling suites' `add_virtual_authenticator` exactly.
async fn add_virtual_authenticator(
    page: &chromiumoxide::Page,
) -> chromiumoxide::cdp::browser_protocol::web_authn::AuthenticatorId {
    let auth_options = VirtualAuthenticatorOptions::builder()
        .protocol(AuthenticatorProtocol::Ctap2)
        .transport(AuthenticatorTransport::Internal)
        .has_user_verification(true)
        .is_user_verified(true)
        .has_resident_key(true)
        .automatic_presence_simulation(true)
        .build()
        .expect("VirtualAuthenticatorOptions must build");

    page.execute(AddVirtualAuthenticatorParams::new(auth_options))
        .await
        .expect("addVirtualAuthenticator must succeed")
        .result
        .authenticator_id
        .clone()
}

// ─────────────────────────────────────────────────────────────────────────────
// DOM helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Builds an `EvaluateParams` expression requesting `returnByValue: true` —
/// see the sibling suites' `evaluate_by_value` for why this matters.
fn evaluate_by_value(expression: &str) -> EvaluateParams {
    EvaluateParams::builder()
        .expression(expression)
        .return_by_value(true)
        .build()
        .expect("EvaluateParams must build")
}

/// Polls `#status`'s text content until it contains `needle`, or panics
/// after `deadline`.
async fn poll_status_contains(page: &chromiumoxide::Page, needle: &str, deadline: Instant) {
    loop {
        let text: String = page
            .evaluate(evaluate_by_value(
                "(function(){var el = document.getElementById('status'); \
                 return el ? el.textContent : '';})()",
            ))
            .await
            .expect("evaluate must not error")
            .into_value()
            .expect("evaluate result must deserialise as String");
        if text.contains(needle) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "#status never contained {needle:?} within the deadline; last text: {text:?}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// The confirmation code the page shows in `#confirmation-code`, or the
/// empty string while the element is hidden.
async fn displayed_code(page: &chromiumoxide::Page) -> String {
    page.evaluate(evaluate_by_value(
        "(function(){var el = document.getElementById('confirmation-code'); \
         return el && !el.hidden ? el.textContent : '';})()",
    ))
    .await
    .expect("evaluate must not error")
    .into_value()
    .expect("evaluate result must deserialise as String")
}

/// Awaits the registration the page posts to the server behind `guard` and
/// returns the staged credential, after asserting that the page shows a
/// well-formed confirmation code and that `store` is still empty.
async fn staged_from_page(
    guard: &mut OperatorEnrollGuard,
    page: &chromiumoxide::Page,
    store: &OperatorApprovalCredentialStore,
) -> (PendingOperatorEnrollment, String) {
    let pending = guard
        .0
        .as_mut()
        .expect("handle must be present")
        .await_completion(Duration::from_secs(30))
        .await
        .expect("the page's registration must verify within 30s");
    poll_status_contains(
        page,
        "Awaiting confirmation",
        Instant::now() + Duration::from_secs(5),
    )
    .await;
    let code = displayed_code(page).await;
    let groups: Vec<&str> = code.split('-').collect();
    assert_eq!(groups.len(), 4, "the page shows four groups: {code:?}");
    assert!(
        groups
            .iter()
            .all(|g| g.len() == 4 && g.bytes().all(|b| b.is_ascii_hexdigit())),
        "each group holds four hex digits: {code:?}"
    );
    assert!(
        store.list().expect("store must be readable").is_empty(),
        "nothing is enrolled before the terminal confirmation"
    );
    (pending, code)
}

// ─────────────────────────────────────────────────────────────────────────────
// CDP binary decoding
// ─────────────────────────────────────────────────────────────────────────────

/// Decodes a CDP `binary`-typed field (base64 per the DevTools Protocol
/// spec) leniently: tries standard base64 first (padding auto-corrected),
/// falls back to URL-safe. Test-only parsing of already-trusted CDP output.
fn decode_cdp_binary(bin: &chromiumoxide::Binary) -> Vec<u8> {
    let s: &str = bin.as_ref();
    let padded = match s.len() % 4 {
        0 => s.to_owned(),
        n => format!("{s}{}", "=".repeat(4 - n)),
    };
    STANDARD
        .decode(&padded)
        .or_else(|_| URL_SAFE.decode(s))
        .expect("CDP binary field must decode as base64 (standard or url-safe)")
}

// ─────────────────────────────────────────────────────────────────────────────
// The main acceptance test
// ─────────────────────────────────────────────────────────────────────────────

/// Drives the real interactive enrollment ceremony through a headless
/// Chromium end to end: the server stages the verified registration, the
/// page shows its code, nothing is stored until that code is confirmed, and
/// the persisted credential matches the virtual authenticator's own record.
/// A second POST without a session is refused on the same server.
///
/// `flavor = "multi_thread"` is required for `tokio::task::block_in_place`
/// (used by both RAII guards), mirroring the sibling suites.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
#[ignore = "requires chromium and explicit --ignored flag"]
async fn operator_enroll_browser_confirms_then_persists_credential() {
    let dir = TempDir::new().expect("tempdir");
    let store_path = dir.path().join("default.toml");

    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let handle = start_operator_enroll_server(
        store_path.clone(),
        "default",
        bind_addr,
        None,
        stellar_agent_approval_ui::PageIdentity::neutral(),
    )
    .await
    .expect("start_operator_enroll_server must succeed");
    let url = handle.enroll_url();
    let mut enroll_guard = OperatorEnrollGuard(Some(handle));

    // The profile directory outlives the browser guard declared below, so it
    // is removed after the browser has been killed.
    let (browser, mut handler, _profile) = launch_chromium().await;
    let handler_task = tokio::spawn(async move {
        loop {
            if handler.next().await.is_none() {
                break;
            }
        }
    });
    let mut browser_guard = BrowserGuard(Some(browser));
    let page = browser_guard
        .0
        .as_mut()
        .expect("browser must be alive")
        .new_page("about:blank")
        .await
        .expect("new page must open");

    page.execute(EnableParams::default())
        .await
        .expect("WebAuthn domain must enable");
    let authenticator_id = add_virtual_authenticator(&page).await;

    page.goto(&url)
        .await
        .expect("navigation to the enrollment page must succeed");

    let label_input = page
        .find_element("#label-input")
        .await
        .expect("#label-input must be present on the rendered enrollment page");
    label_input.focus().await.expect("label input must focus");
    label_input
        .type_str("acceptance-test-laptop")
        .await
        .expect("typing the label must succeed");

    let enroll_btn = page
        .find_element("#enroll-btn")
        .await
        .expect("#enroll-btn must be present on the rendered enrollment page");
    enroll_btn
        .click()
        .await
        .expect("enroll button click must succeed");

    // The server stages the verified registration and the page shows its
    // code; the store stays empty until the operator types that code.
    let store = OperatorApprovalCredentialStore::new(store_path.clone());
    let (pending, code) = staged_from_page(&mut enroll_guard, &page, &store).await;
    assert_eq!(pending.label(), "acceptance-test-laptop");

    // The operator types the displayed code at the terminal.
    let enrolled = pending
        .confirm(&code, std::time::Instant::now())
        .expect("the displayed code confirms the staged credential")
        .persist(&store)
        .expect("the confirmed credential persists");

    // ── Rigorous cross-check ────────────────────────────────────────────
    let credentials = page
        .execute(GetCredentialsParams::new(authenticator_id.clone()))
        .await
        .expect("getCredentials must succeed")
        .result
        .credentials
        .clone();
    assert_eq!(
        credentials.len(),
        1,
        "exactly one credential must exist in the virtual authenticator after one enrollment"
    );
    let cdp_cred = &credentials[0];

    let cdp_cred_id_bytes = decode_cdp_binary(&cdp_cred.credential_id);
    let cdp_privkey_der = decode_cdp_binary(&cdp_cred.private_key);
    let cdp_sign_count =
        u32::try_from(cdp_cred.sign_count).expect("CDP sign_count must fit in u32");

    let secret_key = SecretKey::from_pkcs8_der(&cdp_privkey_der)
        .expect("CDP's returned private key must parse as a valid PKCS#8 P-256 key");
    let derived_pubkey_point = secret_key.public_key().to_encoded_point(false);
    let derived_pubkey_bytes = derived_pubkey_point.as_bytes();

    let listed = store.list().expect("store must be readable");
    assert_eq!(listed.len(), 1, "exactly one credential is enrolled");
    let stored = listed.into_iter().next().expect("one credential");
    assert_eq!(
        stored, enrolled,
        "the store holds the record persist returned"
    );
    assert_eq!(stored.label, "acceptance-test-laptop");

    let stored_cred_id_bytes = URL_SAFE_NO_PAD
        .decode(&stored.credential_id_b64url)
        .expect("stored credential id must be valid base64url");
    let stored_pubkey_bytes = URL_SAFE_NO_PAD
        .decode(&stored.public_key_sec1_b64)
        .expect("stored public key must be valid base64url");

    assert_eq!(
        stored_cred_id_bytes, cdp_cred_id_bytes,
        "the stored credential id must equal the virtual authenticator's own credential id"
    );
    assert_eq!(
        stored_pubkey_bytes, derived_pubkey_bytes,
        "the stored SEC1 public key must equal the public key derived from CDP's PKCS#8 \
         private key — this validates the page's SPKI-to-SEC1 extraction against ground truth"
    );
    assert_eq!(stored.rp_id, "localhost");
    assert_eq!(
        stored.sign_count,
        Some(cdp_sign_count),
        "the stored sign_count must EXACTLY equal CDP's own signCount — this validates the \
         server's reading of the authenticator data inside the attestation object against \
         ground truth, not merely that some value was stored"
    );

    // ── Session gate refuses an unauthenticated second POST ─────────────
    // The bootstrap token was already consumed by the initial navigation, so
    // a fresh out-of-browser HTTP client cannot establish a second session
    // against this server run. A POST carrying no session cookie 404s at the
    // session gate before the completion latch is even consulted; the
    // latch's own `already_completed` semantics (a well-formed second POST
    // WITH a valid session and CSRF) are covered by the in-process
    // `operator_enroll::router_tests`, which run with an established
    // session.
    let port = enroll_guard
        .0
        .as_ref()
        .expect("handle must be present")
        .local_addr()
        .port();
    let base = format!("http://127.0.0.1:{port}");
    let resp = reqwest::Client::new()
        .post(format!("{base}/enroll/credential"))
        .header("Host", format!("127.0.0.1:{port}"))
        .header("Origin", &base)
        .json(&synthetic_valid_body(200, port))
        .send()
        .await
        .expect("POST must complete");
    assert_eq!(resp.status().as_u16(), 404);

    let listed = store.list().expect("store must be readable");
    assert_eq!(
        listed.len(),
        1,
        "the refused unauthenticated second POST must not have persisted a second credential"
    );

    drop(enroll_guard);
    handler_task.abort();
}

// ─────────────────────────────────────────────────────────────────────────────
// Negative paths against the real HTTP surface (no browser needed)
// ─────────────────────────────────────────────────────────────────────────────

/// A well-formed registration body from a software authenticator seeded with
/// `seed`, over a challenge the server never issued, for requests the server
/// must refuse before it reads the body.
fn synthetic_valid_body(seed: u8, port: u16) -> serde_json::Value {
    SoftwareRegistrar::new([seed; 32], vec![seed; 16])
        .builder(&[seed; 32], &format!("http://localhost:{port}"))
        .label("synthetic")
        .json()
}

/// Parses the JSON data island `id` in a served page, as the offline
/// template tests do, applied here to a real HTTP response body.
fn extract_island(html: &str, id: &str) -> serde_json::Value {
    let open = format!(r#"<script type="application/json" id="{id}">"#);
    let start = html.find(&open).expect("data island opening tag present") + open.len();
    let rest = &html[start..];
    let end = rest
        .find("</script>")
        .expect("data island closing tag present");
    serde_json::from_str(&rest[..end]).expect("data island must be valid JSON")
}

/// Extracts `csrfToken` from the `#enroll-data` JSON data island in a
/// rendered `/enroll` page.
fn extract_csrf(html: &str) -> String {
    extract_island(html, "enroll-data")["csrfToken"]
        .as_str()
        .expect("csrfToken must be a string")
        .to_owned()
}

/// A `reqwest::Client` that does not auto-follow redirects, so every
/// response, the bootstrap exchange's `Set-Cookie` included, is observed
/// directly. It mirrors the helper of the same name in `stellar-agent-mcp`'s
/// `approve_serve_testnet_acceptance` for the sibling approval-inbox server's
/// identical gate.
fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("reqwest client")
}

/// The session a bootstrap exchange establishes: the `name=value` cookie
/// header and the session proof the bootstrap page hands its script.
struct Session {
    cookie: String,
    proof: String,
}

/// Performs the one-time bootstrap exchange against `127.0.0.1:{port}` and
/// returns the session cookie and the session proof. Bootstrap is a `GET`, so
/// only the Host allowlist applies (it accepts the loopback IP); the Origin
/// allowlist guards state-changing methods only.
async fn bootstrap_session(
    client: &reqwest::Client,
    port: u16,
    bootstrap_token_hex: &str,
) -> Session {
    let resp = client
        .get(format!(
            "http://127.0.0.1:{port}/bootstrap/{bootstrap_token_hex}"
        ))
        .header("Host", format!("127.0.0.1:{port}"))
        .send()
        .await
        .expect("bootstrap GET must succeed");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "bootstrap exchange must return the session bootstrap page"
    );
    let cookie = resp
        .headers()
        .get(reqwest::header::SET_COOKIE)
        .expect("bootstrap must set a session cookie")
        .to_str()
        .expect("cookie header is ASCII")
        .split(';')
        .next()
        .expect("cookie header carries a name=value pair")
        .trim()
        .to_owned();
    let page = resp.text().await.expect("bootstrap body is text");
    let island = extract_island(&page, "session-bootstrap-data");
    assert_eq!(island["next"], "/enroll");
    let proof = island["proof"]
        .as_str()
        .expect("the bootstrap page carries the session proof")
        .to_owned();
    Session { cookie, proof }
}

#[tokio::test]
#[serial]
#[ignore = "part of the operator-enroll browser acceptance suite; run via --include-ignored"]
async fn post_wrong_csrf_is_refused_over_real_server() {
    let dir = TempDir::new().expect("tempdir");
    let store_path = dir.path().join("default.toml");
    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let handle = start_operator_enroll_server(
        store_path,
        "default",
        bind_addr,
        None,
        stellar_agent_approval_ui::PageIdentity::neutral(),
    )
    .await
    .expect("start must succeed");
    let port = handle.local_addr().port();
    let base = format!("http://127.0.0.1:{port}");

    let client = http_client();
    let Session { cookie, proof } =
        bootstrap_session(&client, port, handle.bootstrap_token_hex()).await;

    let resp = client
        .post(format!("{base}/enroll/credential"))
        .header("Host", format!("127.0.0.1:{port}"))
        .header("Origin", &base)
        .header(reqwest::header::COOKIE, &cookie)
        .header("x-stellar-approval-csrf", "f".repeat(64))
        .header("x-session-proof", &proof)
        .json(&synthetic_valid_body(1, port))
        .send()
        .await
        .expect("POST must complete");
    assert_eq!(resp.status().as_u16(), 403);
    let body: serde_json::Value = resp.json().await.expect("body must be JSON");
    assert_eq!(body["error"], "csrf_invalid");

    handle.shutdown().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
#[ignore = "part of the operator-enroll browser acceptance suite; run via --include-ignored"]
async fn post_duplicate_credential_id_is_refused_over_real_server() {
    let dir = TempDir::new().expect("tempdir");
    let store_path = dir.path().join("default.toml");

    // A real registration whose credential ID is already enrolled.
    let duplicate = SoftwareRegistrar::new([9u8; 32], vec![9u8; 16]);
    let store = OperatorApprovalCredentialStore::new(store_path.clone());
    let seeded = OperatorApprovalCredential {
        credential_id_b64url: duplicate.credential_id_b64url(),
        public_key_sec1_b64: URL_SAFE_NO_PAD.encode(duplicate.public_key_sec1()),
        rp_id: "localhost".to_owned(),
        label: "pre-existing".to_owned(),
        registered_at_unix_ms: 1,
        sign_count: None,
    };
    store.enroll(seeded.clone()).expect("pre-seed must succeed");

    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let handle = start_operator_enroll_server(
        store_path.clone(),
        "default",
        bind_addr,
        None,
        stellar_agent_approval_ui::PageIdentity::neutral(),
    )
    .await
    .expect("start must succeed");
    let mut guard = OperatorEnrollGuard(Some(handle));
    let (addr, token) = {
        let handle = guard.0.as_ref().expect("handle present");
        (handle.local_addr(), handle.bootstrap_token_hex().to_owned())
    };
    let client = EnrollmentClient::connect(addr, &token)
        .await
        .expect("bootstrap, page and CSRF over the real listener");

    // The verified registration of an enrolled ID is refused before it is
    // staged, and the store is unchanged.
    let (reply, _) = client
        .register(&duplicate, "attempted-duplicate")
        .await
        .expect("POST must complete");
    assert_eq!(reply.status, 409, "{}", reply.body);
    assert_eq!(reply.json()["error"], "duplicate_credential_id");
    assert_eq!(store.list().expect("store readable"), vec![seeded.clone()]);

    // The latch is not consumed: a distinct credential is staged, not
    // enrolled, and enrolls once its code is confirmed.
    let distinct = SoftwareRegistrar::new([77u8; 32], vec![77u8; 16]);
    let (reply, code) = client
        .register(&distinct, "distinct")
        .await
        .expect("second POST must complete");
    assert_eq!(
        reply.status, 200,
        "the latch must not be consumed by a duplicate-id failure: {}",
        reply.body
    );
    assert_eq!(reply.json()["status"], "awaiting_confirmation");
    assert_eq!(store.list().expect("store readable"), vec![seeded.clone()]);
    let pending = guard
        .0
        .as_mut()
        .expect("handle present")
        .await_completion(Duration::from_secs(5))
        .await
        .expect("the distinct registration is staged");
    let enrolled = pending
        .confirm(&code, std::time::Instant::now())
        .expect("the page's code confirms the staged credential")
        .persist(&store)
        .expect("the confirmed credential persists");
    assert_eq!(
        enrolled.credential_id_b64url,
        distinct.credential_id_b64url()
    );
    assert_eq!(
        store.list().expect("store readable"),
        vec![seeded, enrolled]
    );

    drop(guard);
}

// ─────────────────────────────────────────────────────────────────────────────
// Cross-port isolation
// ─────────────────────────────────────────────────────────────────────────────

/// `sessionStorage` key the inbox bootstrap stores its proof under.
const INBOX_PROOF_KEY: &str = "stellar-agent-approval-session-proof";

/// `sessionStorage` key the enrollment bootstrap stores its proof under.
const ENROLL_PROOF_KEY: &str = "stellar-agent-operator-enroll-session-proof";

/// A plain HTTP service on another loopback port, standing in for any local
/// service the operator's browser visits. It serves one static page for every
/// request and records each request head it receives, so the test can read
/// the cookies the browser sent it.
struct OtherPortService {
    port: u16,
    heads: Arc<StdMutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for OtherPortService {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl OtherPortService {
    async fn start() -> Self {
        let listener =
            tokio::net::TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
                .await
                .expect("the other loopback service must bind");
        let port = listener.local_addr().expect("bound address").port();
        let heads = Arc::new(StdMutex::new(Vec::new()));
        let recorded = Arc::clone(&heads);
        let task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let recorded = Arc::clone(&recorded);
                tokio::spawn(async move {
                    let mut head = Vec::new();
                    let mut buf = [0u8; 4096];
                    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                        match stream.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => head.extend_from_slice(&buf[..n]),
                        }
                        if head.len() > 64 * 1024 {
                            return;
                        }
                    }
                    recorded
                        .lock()
                        .unwrap()
                        .push(String::from_utf8_lossy(&head).into_owned());
                    let body = "<!DOCTYPE html><html><head><meta charset=\"utf-8\">\
                                <title>other service</title></head>\
                                <body><p>another local service</p></body></html>";
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        Self { port, heads, task }
    }

    /// The `name=value` pair of the first cookie whose name starts with
    /// `prefix` among the cookies the browser sent this service.
    fn received_cookie(&self, prefix: &str) -> Option<String> {
        self.heads.lock().unwrap().iter().find_map(|head| {
            head.lines()
                .filter_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.trim()
                        .eq_ignore_ascii_case("cookie")
                        .then(|| value.trim().to_owned())
                })
                .flat_map(|value| {
                    value
                        .split(';')
                        .map(|pair| pair.trim().to_owned())
                        .collect::<Vec<_>>()
                })
                .find(|pair| pair.starts_with(prefix))
        })
    }

    /// Every request head the service received, joined.
    fn all_heads(&self) -> String {
        self.heads.lock().unwrap().join("\n")
    }
}

/// Polls `expression` (which must evaluate to a string) until it returns
/// `expected`, or panics after `deadline`.
async fn poll_eval_equals(
    page: &chromiumoxide::Page,
    expression: &str,
    expected: &str,
    deadline: Instant,
) {
    loop {
        let value: String = page
            .evaluate(evaluate_by_value(expression))
            .await
            .expect("evaluate must not error")
            .into_value()
            .expect("evaluate result must deserialise as String");
        if value == expected {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{expression} never returned {expected:?} within the deadline; last value: {value:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// The session proof the current page's origin holds under `key`, or the
/// empty string when it holds none.
async fn stored_proof(page: &chromiumoxide::Page, key: &str) -> String {
    page.evaluate(evaluate_by_value(&format!(
        "(function(){{var v = window.sessionStorage.getItem({key:?}); \
         return v === null ? '' : v;}})()"
    )))
    .await
    .expect("evaluate must not error")
    .into_value()
    .expect("evaluate result must deserialise as String")
}

/// How many `sessionStorage` items the current page's origin holds.
async fn session_storage_len(page: &chromiumoxide::Page) -> String {
    page.evaluate(evaluate_by_value("String(window.sessionStorage.length)"))
        .await
        .expect("evaluate must not error")
        .into_value()
        .expect("evaluate result must deserialise as String")
}

/// Starts Chromium and opens one blank page; the returned guard kills the
/// browser, the task drives its CDP handler, and the directory is its
/// profile.
async fn browser_with_page() -> (
    BrowserGuard,
    chromiumoxide::Page,
    tokio::task::JoinHandle<()>,
    TempDir,
) {
    let (browser, mut handler, profile) = launch_chromium().await;
    let handler_task = tokio::spawn(async move {
        loop {
            if handler.next().await.is_none() {
                break;
            }
        }
    });
    let mut browser_guard = BrowserGuard(Some(browser));
    let page = browser_guard
        .0
        .as_mut()
        .expect("browser must be alive")
        .new_page("about:blank")
        .await
        .expect("new page must open");
    (browser_guard, page, handler_task, profile)
}

/// A service on another loopback port receives the enrollment session cookie
/// from the operator's browser, but its page cannot read the session proof,
/// and the cookie plus a valid CSRF value without the proof can neither
/// request a registration challenge nor post a credential. The operator's own
/// tab then registers, and its credential enrolls once the displayed code is
/// confirmed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
#[ignore = "requires chromium and explicit --ignored flag"]
async fn cross_port_cookie_does_not_authorize_enrollment() {
    let dir = TempDir::new().expect("tempdir");
    let store_path = dir.path().join("default.toml");
    let handle = start_operator_enroll_server(
        store_path.clone(),
        "default",
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        None,
        stellar_agent_approval_ui::PageIdentity::neutral(),
    )
    .await
    .expect("start_operator_enroll_server must succeed");
    let url = handle.enroll_url();
    let port = handle.local_addr().port();
    let mut enroll_guard = OperatorEnrollGuard(Some(handle));
    let other = OtherPortService::start().await;
    assert_ne!(other.port, port);

    let (browser_guard, page, handler_task, _profile) = browser_with_page().await;
    page.execute(EnableParams::default())
        .await
        .expect("WebAuthn domain must enable");
    add_virtual_authenticator(&page).await;

    // The operator opens the enrollment link; the bootstrap page stores the
    // proof in this tab and moves on to /enroll.
    page.goto(&url).await.expect("bootstrap navigation");
    let deadline = Instant::now() + Duration::from_secs(10);
    poll_eval_equals(&page, "window.location.pathname", "/enroll", deadline).await;
    let proof = stored_proof(&page, ENROLL_PROOF_KEY).await;
    assert_eq!(proof.len(), 64, "the operator's tab must hold the proof");

    // The same tab visits the other service on the same host.
    page.goto(&format!("http://localhost:{}/", other.port))
        .await
        .expect("navigation to the other service");
    poll_eval_equals(&page, "document.title", "other service", deadline).await;
    let stolen = other
        .received_cookie("stellar_agent_operator_enroll_session_")
        .unwrap_or_else(|| {
            panic!(
                "the browser must send the host-scoped session cookie to the other port; \
                 received: {}",
                other.all_heads()
            )
        });
    assert_eq!(stored_proof(&page, ENROLL_PROOF_KEY).await, "");
    assert_eq!(session_storage_len(&page).await, "0");
    assert!(!other.all_heads().contains(&proof));

    // The other service replays the cookie: it can read the enrollment page
    // and its CSRF value, but cannot enroll without the proof.
    let base = format!("http://127.0.0.1:{port}");
    let client = http_client();
    let page_html = client
        .get(format!("{base}/enroll"))
        .header(reqwest::header::COOKIE, &stolen)
        .send()
        .await
        .expect("GET /enroll must complete")
        .text()
        .await
        .expect("body must be readable");
    let csrf = extract_csrf(&page_html);
    assert!(!page_html.contains(&proof));
    for (path, body) in [
        ("/enroll/challenge", serde_json::json!({})),
        ("/enroll/credential", synthetic_valid_body(3, port)),
    ] {
        for attempt in [None, Some("f".repeat(64))] {
            let mut request = client
                .post(format!("{base}{path}"))
                .header("Origin", &base)
                .header(reqwest::header::COOKIE, &stolen)
                .header("x-stellar-approval-csrf", &csrf)
                .json(&body);
            if let Some(wrong) = &attempt {
                request = request.header("x-session-proof", wrong);
            }
            let resp = request.send().await.expect("POST must complete");
            assert_eq!(resp.status().as_u16(), 403, "{path} {attempt:?}");
            let refusal: serde_json::Value = resp.json().await.expect("body must be JSON");
            assert_eq!(
                refusal["error"], "session_proof_invalid",
                "{path} {attempt:?}"
            );
        }
    }
    let store = OperatorApprovalCredentialStore::new(store_path.clone());
    assert!(store.list().expect("store must be readable").is_empty());

    // The operator's tab still holds the proof and enrolls.
    page.goto(&format!("http://localhost:{port}/enroll"))
        .await
        .expect("navigation back to the enrollment page");
    assert_eq!(stored_proof(&page, ENROLL_PROOF_KEY).await, proof);
    let label_input = page
        .find_element("#label-input")
        .await
        .expect("#label-input must be present");
    label_input.focus().await.expect("label input must focus");
    label_input
        .type_str("cross-port-operator")
        .await
        .expect("typing the label must succeed");
    page.find_element("#enroll-btn")
        .await
        .expect("#enroll-btn must be present")
        .click()
        .await
        .expect("enroll button click must succeed");
    let (pending, code) = staged_from_page(&mut enroll_guard, &page, &store).await;
    let confirmed = pending
        .confirm(&code, std::time::Instant::now())
        .expect("the displayed code confirms the staged credential")
        .persist(&store)
        .expect("the confirmed credential persists");
    let enrolled = store.list().expect("store must be readable");
    assert_eq!(enrolled, vec![confirmed]);
    assert_eq!(enrolled[0].label, "cross-port-operator");

    drop(enroll_guard);
    drop(browser_guard);
    handler_task.abort();
}

/// A service on another loopback port receives the approval-inbox session
/// cookie from the operator's browser, but its page cannot read the session
/// proof, and the cookie plus a valid CSRF value without the proof can neither
/// approve nor reject; neither the store nor the audit log changes. The
/// operator's own tab then approves.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
#[ignore = "requires chromium and explicit --ignored flag"]
async fn cross_port_cookie_does_not_authorize_decision() {
    stellar_agent_test_support::keyring_mock::install().expect("mock keyring store init");
    let dir = TempDir::new().expect("tempdir");
    let store_path = dir.path().join("default.toml");
    let audit_path = dir.path().join("audit.log");
    let service = "stellar-agent-attestation-cross-port";
    keyring_core::Entry::new(service, "default")
        .expect("keyring entry")
        .set_password(&URL_SAFE_NO_PAD.encode([0x5Au8; 32]))
        .expect("attestation key stored");

    let entry = fixtures::payment_pending(
        "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY",
        "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL",
        "XLM",
        2_500_000,
        None,
        100,
        1_234_567,
        process_uid_for_attestation().expect("uid on test host"),
        DEFAULT_TTL_MS,
    );
    let nonce = entry.approval_nonce.clone();
    PendingApprovalStore::open(store_path.clone())
        .expect("store opens")
        .insert(entry, timefmt::now_unix_ms().expect("clock"))
        .expect("entry inserted");

    let ctx = DecisionContext::new(
        ApprovalContext::from_profile(
            "cross-port-test",
            &Profile::builder_testnet("svc", "default", "nonce", "default").build(),
        ),
        store_path.clone(),
        KeyringEntryRef::new(service, "default"),
        OwnerKeyContext::for_profile_name("cross-port-test"),
        Arc::new(StdMutex::new(
            AuditWriter::open(audit_path.clone(), None).expect("audit writer"),
        )),
        None,
    );
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel::<usize>();
    let serve = start_serve(ServeConfig::new(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        ctx,
        tx,
        false,
    ))
    .await
    .expect("start_serve must succeed");
    let port = serve.local_addr().port();
    let base = format!("http://127.0.0.1:{port}");
    let other = OtherPortService::start().await;
    assert_ne!(other.port, port);

    let (browser_guard, page, handler_task, _profile) = browser_with_page().await;

    // The operator opens the inbox link; the bootstrap page stores the proof
    // in this tab and moves on to /inbox.
    page.goto(&serve.bootstrap_url())
        .await
        .expect("bootstrap navigation");
    let deadline = Instant::now() + Duration::from_secs(10);
    poll_eval_equals(&page, "window.location.pathname", "/inbox", deadline).await;
    let proof = stored_proof(&page, INBOX_PROOF_KEY).await;
    assert_eq!(proof.len(), 64, "the operator's tab must hold the proof");

    // The same tab visits the other service on the same host.
    page.goto(&format!("http://127.0.0.1:{}/", other.port))
        .await
        .expect("navigation to the other service");
    poll_eval_equals(&page, "document.title", "other service", deadline).await;
    let stolen = other
        .received_cookie("stellar_agent_approval_session_")
        .unwrap_or_else(|| {
            panic!(
                "the browser must send the host-scoped session cookie to the other port; \
                 received: {}",
                other.all_heads()
            )
        });
    assert_eq!(stored_proof(&page, INBOX_PROOF_KEY).await, "");
    assert_eq!(session_storage_len(&page).await, "0");
    assert!(!other.all_heads().contains(&proof));

    // The other service replays the cookie: it can read the detail page and
    // its CSRF value, but can neither approve nor reject without the proof.
    let client = http_client();
    let detail = client
        .get(format!("{base}/approval/{nonce}"))
        .header(reqwest::header::COOKIE, &stolen)
        .send()
        .await
        .expect("detail GET must complete");
    assert_eq!(detail.status().as_u16(), 200);
    let detail_html = detail.text().await.expect("detail body is text");
    assert!(!detail_html.contains(&proof));
    let csrf = extract_island(&detail_html, "approval-data")["csrf"]
        .as_str()
        .expect("detail page surfaces the CSRF value")
        .to_owned();
    let store_before = std::fs::read(&store_path).expect("store readable");
    let audit_before = std::fs::read(&audit_path).ok();
    for action in ["approve", "reject"] {
        for attempt in [None, Some("f".repeat(64))] {
            let mut request = client
                .post(format!("{base}/approval/{nonce}/{action}"))
                .header(reqwest::header::ORIGIN, &base)
                .header(reqwest::header::COOKIE, &stolen)
                .header("X-Stellar-Approval-CSRF", &csrf);
            if let Some(wrong) = &attempt {
                request = request.header("X-Session-Proof", wrong);
            }
            let resp = request.send().await.expect("POST must complete");
            assert_eq!(resp.status().as_u16(), 403, "{action} {attempt:?}");
            let body: serde_json::Value = resp.json().await.expect("body must be JSON");
            assert_eq!(
                body["error"], "session_proof_invalid",
                "{action} {attempt:?}"
            );
        }
    }
    assert_eq!(
        std::fs::read(&store_path).expect("store readable"),
        store_before
    );
    assert_eq!(std::fs::read(&audit_path).ok(), audit_before);

    // The operator's tab still holds the proof and approves.
    page.goto(&format!("{base}/approval/{nonce}"))
        .await
        .expect("navigation to the detail page");
    assert_eq!(stored_proof(&page, INBOX_PROOF_KEY).await, proof);
    page.find_element("#approve-btn")
        .await
        .expect("#approve-btn must be present")
        .click()
        .await
        .expect("approve button click must succeed");
    poll_eval_equals(
        &page,
        "document.documentElement.getAttribute('data-state') || ''",
        "ok",
        Instant::now() + Duration::from_secs(10),
    )
    .await;
    {
        let store = PendingApprovalStore::open(store_path.clone()).expect("store opens");
        let decided = store.get(&nonce).expect("entry present");
        assert!(matches!(
            decided.kind,
            ApprovalKind::PaymentSimulated { .. }
        ));
        assert!(
            decided.attestation_blob_b64.is_some(),
            "the operator's approve must mint the attestation"
        );
    }

    drop(browser_guard);
    handler_task.abort();
    serve.shutdown().await.expect("serve shutdown");
}
