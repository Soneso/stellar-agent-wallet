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
//!    open: a `localhost`-hostnamed `/bootstrap/{token}` link that
//!    303-redirects to `/enroll` and sets the session cookie. chromiumoxide
//!    follows the redirect and persists the cookie automatically, so the
//!    ceremony proceeds unchanged from the browser's perspective.
//! 4. Types a label into `#label-input`, clicks `#enroll-btn` — a REAL
//!    `navigator.credentials.create()` runs through the shipped
//!    `/static/operator-enroll.js`, so the virtual authenticator generates
//!    its own credential id and P-256 keypair, exactly as a hardware key
//!    would.
//! 5. `handle.await_completion` resolves once the POST persists the
//!    credential; the page's `#status` text is polled to confirm the
//!    shipped frontend also reflects success, not just the backend.
//! 6. Rigorous cross-check (the part a DOM-only assertion cannot provide):
//!    `WebAuthn.getCredentials` returns the virtual authenticator's own
//!    record of what it just created — the STORED SEC1 public key must
//!    equal the public key derived from the PKCS#8 private key CDP
//!    returns, and the STORED sign count must EXACTLY equal CDP's own
//!    `signCount` — not merely "both present", an equality that only holds
//!    if the shipped JS's `getAuthenticatorData()`-based extraction (see
//!    `operator-enroll.js`) reads the real authenticator data correctly.
//! 7. A raw second `POST /enroll/credential` carrying no session cookie
//!    confirms the session gate refuses it (`404`) before the completion
//!    latch is even consulted; the bootstrap token was already consumed by
//!    step 3's navigation, so a fresh out-of-browser client cannot establish
//!    a second session against this server run to probe the latch itself —
//!    that is covered by the in-process `operator_enroll::router_tests`.
//!
//! Negative paths (`post_wrong_csrf_...`, `post_duplicate_credential_id_...`)
//! drive the real HTTP surface directly (no browser needed for those, each
//! performing its own bootstrap → session-cookie exchange) to confirm CSRF
//! rejection and the duplicate-id refusal hold against a real TCP listener,
//! not only the in-process router tests.
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
//!   (`operator_enroll_browser_creates_and_persists_credential` only).

#![cfg(feature = "operator-enroll-browser-acceptance")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics and unwraps are acceptable in acceptance tests"
)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
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
use stellar_agent_approval_ui::operator_enroll::start_operator_enroll_server;
use stellar_agent_core::approval::operator_credentials::{
    OperatorApprovalCredential, OperatorApprovalCredentialStore,
};
use tempfile::TempDir;

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
struct OperatorEnrollGuard(
    Option<stellar_agent_approval_ui::operator_enroll::OperatorEnrollHandle>,
);

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
async fn launch_chromium() -> (Browser, chromiumoxide::Handler) {
    let config = BrowserConfig::builder()
        .no_sandbox()
        .build()
        .expect("BrowserConfig must build");
    Browser::launch(config)
        .await
        .expect("Chromium must launch; ensure chromium/google-chrome is on PATH")
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
/// Chromium end to end, cross-checks the persisted credential against the
/// virtual authenticator's own record, and confirms the single-use latch
/// refuses a second successful-shape POST on the same server.
///
/// `flavor = "multi_thread"` is required for `tokio::task::block_in_place`
/// (used by both RAII guards), mirroring the sibling suites.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
#[ignore = "requires chromium and explicit --ignored flag"]
async fn operator_enroll_browser_creates_and_persists_credential() {
    let dir = TempDir::new().expect("tempdir");
    let store_path = dir.path().join("default.toml");

    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let handle = start_operator_enroll_server(store_path.clone(), "default", bind_addr, None)
        .await
        .expect("start_operator_enroll_server must succeed");
    let url = handle.enroll_url();
    let mut enroll_guard = OperatorEnrollGuard(Some(handle));

    let (browser, mut handler) = launch_chromium().await;
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

    // The Rust-side signal is authoritative: it resolves only after the
    // POST handler's synchronous `store.enroll` call returns Ok, i.e. the
    // credential is durably persisted before this await returns.
    let mut enroll_handle_opt = enroll_guard.0.take();
    {
        let enroll_handle = enroll_handle_opt
            .as_mut()
            .expect("handle must be present before first await");
        enroll_handle
            .await_completion(Duration::from_secs(30))
            .await
            .expect("the ceremony must complete within 30s");
    }
    enroll_guard.0 = enroll_handle_opt;

    // The shipped frontend must ALSO reflect success — not just the backend.
    poll_status_contains(&page, "Enrolled", Instant::now() + Duration::from_secs(5)).await;

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

    let store = OperatorApprovalCredentialStore::new(store_path.clone());
    let stored = store
        .list()
        .expect("store must be readable")
        .into_iter()
        .next()
        .expect("exactly one credential must have been enrolled");

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
         shipped JS's getAuthenticatorData()-based extraction against ground truth, not merely \
         that some value was stored"
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
        .json(&synthetic_valid_body(200))
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

fn synthetic_valid_body(seed: u8) -> serde_json::Value {
    let mut pubkey = vec![seed; 65];
    pubkey[0] = 0x04;
    serde_json::json!({
        "credential_id_b64url": URL_SAFE_NO_PAD.encode([seed; 16]),
        "public_key_sec1_b64": URL_SAFE_NO_PAD.encode(pubkey),
        "label": "synthetic",
        "sign_count": 1,
    })
}

/// Extracts `csrfToken` from the `#enroll-data` JSON data island in a
/// rendered `/enroll` page — mirrors the offline template tests' island
/// parsing, applied here to a real HTTP response body.
fn extract_csrf(html: &str) -> String {
    let open = r#"<script type="application/json" id="enroll-data">"#;
    let start = html.find(open).expect("data island opening tag present") + open.len();
    let rest = &html[start..];
    let end = rest
        .find("</script>")
        .expect("data island closing tag present");
    let value: serde_json::Value =
        serde_json::from_str(&rest[..end]).expect("data island must be valid JSON");
    value["csrfToken"]
        .as_str()
        .expect("csrfToken must be a string")
        .to_owned()
}

/// A `reqwest::Client` that does not auto-follow redirects, so the bootstrap
/// exchange's `303 See Other` + `Set-Cookie` can be observed directly —
/// mirrors `stellar-agent-mcp`'s `approve_serve_testnet_acceptance` helper of
/// the same name for the sibling approval-inbox server's identical gate.
fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("reqwest client")
}

/// Performs the one-time bootstrap exchange against `127.0.0.1:{port}` and
/// returns the `name=value` session-cookie header. Bootstrap is a `GET`, so
/// only the Host allowlist applies (it accepts the loopback IP); the Origin
/// allowlist guards state-changing methods only.
async fn bootstrap_session(
    client: &reqwest::Client,
    port: u16,
    bootstrap_token_hex: &str,
) -> String {
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
        reqwest::StatusCode::SEE_OTHER,
        "bootstrap exchange must redirect to /enroll"
    );
    assert_eq!(
        resp.headers().get(reqwest::header::LOCATION).unwrap(),
        "/enroll"
    );
    let set_cookie = resp
        .headers()
        .get(reqwest::header::SET_COOKIE)
        .expect("bootstrap must set a session cookie")
        .to_str()
        .expect("cookie header is ASCII");
    set_cookie
        .split(';')
        .next()
        .expect("cookie header carries a name=value pair")
        .trim()
        .to_owned()
}

#[tokio::test]
#[serial]
#[ignore = "part of the operator-enroll browser acceptance suite; run via --include-ignored"]
async fn post_wrong_csrf_is_refused_over_real_server() {
    let dir = TempDir::new().expect("tempdir");
    let store_path = dir.path().join("default.toml");
    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let handle = start_operator_enroll_server(store_path, "default", bind_addr, None)
        .await
        .expect("start must succeed");
    let port = handle.local_addr().port();
    let base = format!("http://127.0.0.1:{port}");

    let client = http_client();
    let cookie = bootstrap_session(&client, port, handle.bootstrap_token_hex()).await;

    let resp = client
        .post(format!("{base}/enroll/credential"))
        .header("Host", format!("127.0.0.1:{port}"))
        .header("Origin", &base)
        .header(reqwest::header::COOKIE, &cookie)
        .header("x-stellar-approval-csrf", "f".repeat(64))
        .json(&synthetic_valid_body(1))
        .send()
        .await
        .expect("POST must complete");
    assert_eq!(resp.status().as_u16(), 403);
    let body: serde_json::Value = resp.json().await.expect("body must be JSON");
    assert_eq!(body["error"], "csrf_invalid");

    handle.shutdown().await.ok();
}

#[tokio::test]
#[serial]
#[ignore = "part of the operator-enroll browser acceptance suite; run via --include-ignored"]
async fn post_duplicate_credential_id_is_refused_over_real_server() {
    let dir = TempDir::new().expect("tempdir");
    let store_path = dir.path().join("default.toml");

    let seed_store = OperatorApprovalCredentialStore::new(store_path.clone());
    seed_store
        .enroll(OperatorApprovalCredential {
            credential_id_b64url: URL_SAFE_NO_PAD.encode([9u8; 16]),
            public_key_sec1_b64: {
                let mut b = vec![9u8; 65];
                b[0] = 0x04;
                URL_SAFE_NO_PAD.encode(b)
            },
            rp_id: "localhost".to_owned(),
            label: "pre-existing".to_owned(),
            registered_at_unix_ms: 1,
            sign_count: None,
        })
        .expect("pre-seed must succeed");

    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let handle = start_operator_enroll_server(store_path.clone(), "default", bind_addr, None)
        .await
        .expect("start must succeed");
    let port = handle.local_addr().port();
    let base = format!("http://127.0.0.1:{port}");

    let client = http_client();
    let cookie = bootstrap_session(&client, port, handle.bootstrap_token_hex()).await;

    let page_html = client
        .get(format!("{base}/enroll"))
        .header("Host", format!("127.0.0.1:{port}"))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .expect("GET /enroll must succeed")
        .text()
        .await
        .expect("body must be readable");
    let csrf = extract_csrf(&page_html);

    // Same credential id as the pre-seeded entry: refused as a duplicate.
    let dup_pubkey = {
        let mut b = vec![9u8; 65];
        b[0] = 0x04;
        URL_SAFE_NO_PAD.encode(b)
    };
    let dup_body = serde_json::json!({
        "credential_id_b64url": URL_SAFE_NO_PAD.encode([9u8; 16]),
        "public_key_sec1_b64": dup_pubkey,
        "label": "attempted-duplicate",
        "sign_count": 1,
    });
    let resp = client
        .post(format!("{base}/enroll/credential"))
        .header("Host", format!("127.0.0.1:{port}"))
        .header("Origin", &base)
        .header(reqwest::header::COOKIE, &cookie)
        .header("x-stellar-approval-csrf", &csrf)
        .json(&dup_body)
        .send()
        .await
        .expect("POST must complete");
    assert_eq!(resp.status().as_u16(), 409);
    let body: serde_json::Value = resp.json().await.expect("body must be JSON");
    assert_eq!(body["error"], "duplicate_credential_id");

    // The latch must still be available: a distinct id still succeeds.
    let resp2 = client
        .post(format!("{base}/enroll/credential"))
        .header("Host", format!("127.0.0.1:{port}"))
        .header("Origin", &base)
        .header(reqwest::header::COOKIE, &cookie)
        .header("x-stellar-approval-csrf", &csrf)
        .json(&synthetic_valid_body(77))
        .send()
        .await
        .expect("second POST must complete");
    assert_eq!(
        resp2.status().as_u16(),
        200,
        "the latch must not be consumed by a duplicate-id failure"
    );

    handle.shutdown().await.ok();
}
