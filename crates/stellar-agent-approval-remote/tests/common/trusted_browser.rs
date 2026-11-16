//! Headless Chromium that validates HTTPS against the acceptance runner's
//! test certificate authority, and the signed-origin fixtures its cases share.
//!
//! The runner prepares one private directory per attempt and names it in
//! [`TRUST_DIR_VAR`]: a trusted chain and key for [`SIGNED_RP_ID`] and
//! [`FOREIGN_HOST`], the leaf's SubjectPublicKeyInfo pin, an untrusted chain
//! for the same names with its pin, and NSS databases below `home/` whose
//! only anchor is the trusted authority. Only the Chromium child runs with
//! that `HOME`. The browser keeps certificate errors fatal through
//! `respect_https_errors()`, and a resolver rule maps both names to
//! loopback, so URL, SNI, Host, RP and the signed origin stay the signed
//! ones. Every browser step has a deadline, so a stalled page fails its
//! test with the step's name.
#![allow(
    dead_code,
    reason = "each browser suite uses its own part of the shared fixture"
)]
#![allow(
    clippy::panic,
    reason = "a failed trust control or setup fails its test"
)]

use std::{
    future::Future,
    net::SocketAddr,
    path::PathBuf,
    time::{Duration, Instant},
};

use chromiumoxide::{
    Element, Page,
    browser::{Browser, BrowserConfig},
    cdp::{
        browser_protocol::web_authn::{
            AddVirtualAuthenticatorParams, AuthenticatorId, AuthenticatorProtocol,
            AuthenticatorTransport, EnableParams, VirtualAuthenticatorOptions,
        },
        js_protocol::runtime::EvaluateParams,
    },
};
use futures::StreamExt as _;
use stellar_agent_approval_remote::enroll_listener::SignedEnrollmentHandle;
use stellar_agent_approval_ui::operator_enroll::PendingOperatorEnrollment;
use stellar_agent_core::approval::mainnet_fixtures::{
    ENDPOINT_HOST, MainnetConsentFixture, SIGNED_RP_ID, policy_body_with_origin,
};
use stellar_agent_test_support::webauthn::TestAuthenticator;

/// The variable that names the runner's trust directory.
pub const TRUST_DIR_VAR: &str = "STELLAR_AGENT_BROWSER_TRUST_DIR";

/// The second DNS name of the test leaves, a host outside the signed RP.
pub const FOREIGN_HOST: &str = "foreign.example.invalid";

/// The deadline of one browser step.
const STEP: Duration = Duration::from_secs(20);

/// Awaits `step`, failing the test with `what` when it outlasts [`STEP`].
pub async fn timed<T>(what: &str, step: impl Future<Output = T>) -> T {
    tokio::time::timeout(STEP, step)
        .await
        .unwrap_or_else(|_| panic!("{what} did not finish within {STEP:?}"))
}

/// The text Chromium reports for a leaf from an authority it does not trust.
pub const AUTHORITY_INVALID: &str = "ERR_CERT_AUTHORITY_INVALID";

/// The certificate material of one runner attempt.
pub struct BrowserTrust {
    dir: PathBuf,
}

/// One certificate chain and its key, as a listener loads them.
pub struct Chain {
    /// The leaf, then its authority.
    pub chain: PathBuf,
    /// The leaf's private key, mode `0600`.
    pub key: PathBuf,
}

impl BrowserTrust {
    /// The material the runner prepared.
    ///
    /// # Panics
    ///
    /// Panics off Linux, when [`TRUST_DIR_VAR`] is unset, or when a file is
    /// missing: these cases then fail instead of passing without trust.
    pub fn from_runner() -> Self {
        if cfg!(not(target_os = "linux")) {
            panic!(
                "the HTTPS browser cases trust their test authority through NSS databases, \
                 which only Linux Chromium reads"
            );
        }
        let dir = std::env::var_os(TRUST_DIR_VAR).map_or_else(
            || {
                panic!(
                    "{TRUST_DIR_VAR} is unset: run this suite through \
                     .github/scripts/run-testnet-acceptance.sh, which prepares the test authority"
                )
            },
            PathBuf::from,
        );
        for name in [
            "trusted-chain.pem",
            "trusted-key.pem",
            "trusted.pin",
            "untrusted-chain.pem",
            "untrusted-key.pem",
            "untrusted.pin",
            "home/.pki/nssdb/cert9.db",
        ] {
            assert!(dir.join(name).is_file(), "{TRUST_DIR_VAR} lacks {name}");
        }
        Self { dir }
    }

    /// The chain whose authority the browser trusts.
    pub fn trusted(&self) -> Chain {
        self.chain("trusted")
    }

    /// A chain for the same name from an authority the browser does not hold.
    pub fn untrusted(&self) -> Chain {
        self.chain("untrusted")
    }

    /// The trusted leaf's SubjectPublicKeyInfo pin, as the runner derives it
    /// with openssl, independently of the listener's extraction.
    pub fn trusted_pin(&self) -> [u8; 32] {
        self.pin("trusted.pin")
    }

    /// The untrusted leaf's pin, derived the same way.
    pub fn untrusted_pin(&self) -> [u8; 32] {
        self.pin("untrusted.pin")
    }

    fn pin(&self, name: &str) -> [u8; 32] {
        let text = std::fs::read_to_string(self.dir.join(name)).unwrap();
        hex::decode(text.trim()).unwrap().try_into().unwrap()
    }

    fn chain(&self, name: &str) -> Chain {
        Chain {
            chain: self.dir.join(format!("{name}-chain.pem")),
            key: self.dir.join(format!("{name}-key.pem")),
        }
    }
}

/// A launched Chromium whose handler task and profile live as long as it.
pub struct TrustedChromium {
    pub browser: Browser,
    handler: tokio::task::JoinHandle<()>,
    _profile: tempfile::TempDir,
}

impl TrustedChromium {
    /// Closes the browser and stops its handler task.
    pub async fn close(mut self) {
        self.browser.close().await.unwrap();
        self.handler.abort();
    }
}

/// Launches Chromium with a fresh profile, the runner's NSS home, fatal
/// certificate errors, and the signed name mapped to loopback.
pub async fn launch(trust: &BrowserTrust) -> TrustedChromium {
    let profile = tempfile::Builder::new()
        .prefix("stellar-agent-chromium-")
        .tempdir()
        .unwrap();
    let home = trust.dir.join("home");
    let mut builder = BrowserConfig::builder()
        .no_sandbox()
        .respect_https_errors()
        .user_data_dir(profile.path())
        .env("HOME", home.to_string_lossy())
        // chromiumoxide prefixes each key with `--` itself.
        .arg((
            "host-resolver-rules",
            format!("MAP {SIGNED_RP_ID} 127.0.0.1, MAP {FOREIGN_HOST} 127.0.0.1").as_str(),
        ))
        .arg("disable-background-networking")
        .arg("disable-component-update")
        .arg("disable-sync")
        .arg("no-first-run");
    if let Some(path) = std::env::var_os("CHROMIUM").or_else(|| std::env::var_os("CHROME")) {
        builder = builder.chrome_executable(path);
    }
    let (browser, mut handler) = Browser::launch(builder.build().unwrap())
        .await
        .expect("installed Chromium launches");
    let handler = tokio::spawn(async move { while handler.next().await.is_some() {} });
    TrustedChromium {
        browser,
        handler,
        _profile: profile,
    }
}

/// What one navigation reached.
#[derive(Debug)]
pub enum Navigation {
    /// The document loaded; its body text.
    Loaded(String),
    /// Chromium refused the navigation with this error text.
    Refused(String),
}

/// Navigates `page` to `url` and reports what it reached.
pub async fn navigate(page: &Page, url: &str) -> Navigation {
    match timed(&format!("navigation to {url}"), page.goto(url)).await {
        Ok(_) => {
            let body = eval_json(page, "document.body ? document.body.innerText : ''").await;
            let body = body.as_str().unwrap_or_default().to_owned();
            if body.contains(AUTHORITY_INVALID) {
                Navigation::Refused(body)
            } else {
                Navigation::Loaded(body)
            }
        }
        Err(error) => Navigation::Refused(error.to_string()),
    }
}

/// Asserts that Chromium loads [`PLAIN_PAGE`] from a page that `chain`
/// serves at the signed name.
pub async fn assert_trusted_page_loads(page: &Page, chain: &Chain) {
    let served = serve_page(chain).await;
    match navigate(page, &format!("https://{SIGNED_RP_ID}:{}/", served.port)).await {
        Navigation::Loaded(body) => assert!(body.contains(PLAIN_PAGE), "{body}"),
        Navigation::Refused(error) => panic!("the test authority's leaf is refused: {error}"),
    }
}

/// Asserts that Chromium refuses `url` for its untrusted authority.
pub async fn assert_authority_refused(page: &Page, url: &str) {
    match navigate(page, url).await {
        Navigation::Refused(text) => assert!(
            text.contains(AUTHORITY_INVALID),
            "the refusal names the authority: {text}"
        ),
        Navigation::Loaded(body) => panic!("an untrusted authority loaded {url}: {body}"),
    }
}

/// The text of the page [`serve_page`] serves.
pub const PLAIN_PAGE: &str = "plain test page";

/// An HTTPS page on a loopback port, served with one test chain until drop.
pub struct PlainPage {
    pub port: u16,
    handle: axum_server::Handle<SocketAddr>,
}

impl Drop for PlainPage {
    fn drop(&mut self) {
        self.handle.shutdown();
    }
}

/// Serves [`PLAIN_PAGE`] at `/` over TLS with `chain`, on a fresh port.
pub async fn serve_page(chain: &Chain) -> PlainPage {
    let config = axum_server::tls_rustls::RustlsConfig::from_pem_file(&chain.chain, &chain.key)
        .await
        .unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let router = axum::Router::new().route(
        "/",
        axum::routing::get(|| async {
            axum::response::Html(format!(
                "<!doctype html><title>page</title><p>{PLAIN_PAGE}</p>"
            ))
        }),
    );
    let handle = axum_server::Handle::new();
    let server = axum_server::tls_rustls::from_tcp_rustls(listener, config)
        .unwrap()
        .handle(handle.clone());
    tokio::spawn(async move { server.serve(router.into_make_service()).await });
    PlainPage { port, handle }
}

/// A loopback port that is free now, for a listener and its signed origin.
pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// The signed origin at `port`.
pub fn origin_at(port: u16) -> String {
    format!("https://{SIGNED_RP_ID}:{port}")
}

/// A mainnet fixture whose `[remote_approval]` table binds loopback `port`
/// and serves `chain`, under a policy signed at the next sequence with the
/// signed origin at `port`, `pin`, and `credentials`.
pub fn signed_fixture(
    name: &str,
    port: u16,
    chain: &Chain,
    pin: &[u8; 32],
    credentials: &[&TestAuthenticator],
) -> MainnetConsentFixture {
    let bind = SocketAddr::from(([127, 0, 0, 1], port));
    let fixture = MainnetConsentFixture::with_profile(name, |profile| {
        profile.remote_approval = Some(
            serde_json::from_value(serde_json::json!({
                "enabled": true, "bind": bind.to_string(), "rp_id": SIGNED_RP_ID,
                "cert_path": chain.chain, "key_path": chain.key,
            }))
            .unwrap(),
        );
    });
    sign_origin_policy(&fixture, 1, port, pin, credentials, &[]);
    fixture
}

/// Signs, at the fixture's sequence plus `step`, a policy with the signed
/// origin at `port`, `pin`, the software `credentials`, and the policy
/// `entries` of browser-created credentials.
pub fn sign_origin_policy(
    fixture: &MainnetConsentFixture,
    step: i64,
    port: u16,
    pin: &[u8; 32],
    credentials: &[&TestAuthenticator],
    entries: &[String],
) {
    let origin = origin_at(port);
    let body = policy_body_with_origin(
        fixture.name(),
        ENDPOINT_HOST,
        fixture.sequence() + step,
        credentials,
        Some((&origin, pin)),
    );
    let extra: String = entries
        .iter()
        .map(|entry| format!("    {entry},\n"))
        .collect();
    fixture.write_signed(&body.replacen(
        "approval_credentials = [\n",
        &format!("approval_credentials = [\n{extra}"),
        1,
    ));
}

/// Opens a blank page with an enabled WebAuthn domain and one user-verifying
/// virtual authenticator. The page's target owns the authenticator, so a
/// case navigates this one page between origins.
pub async fn authenticator_page(browser: &Browser) -> (Page, AuthenticatorId) {
    let page = timed("a new page", browser.new_page("about:blank"))
        .await
        .unwrap();
    timed("the WebAuthn domain", page.execute(EnableParams::default()))
        .await
        .unwrap();
    let options = VirtualAuthenticatorOptions::builder()
        .protocol(AuthenticatorProtocol::Ctap2)
        .transport(AuthenticatorTransport::Internal)
        .has_user_verification(true)
        .is_user_verified(true)
        .has_resident_key(true)
        .automatic_presence_simulation(true)
        .build()
        .unwrap();
    let id = timed(
        "the virtual authenticator",
        page.execute(AddVirtualAuthenticatorParams::new(options)),
    )
    .await
    .unwrap()
    .result
    .authenticator_id
    .clone();
    (page, id)
}

/// The JSON value of `expression`, awaiting a returned promise.
pub async fn eval_json(page: &Page, expression: &str) -> serde_json::Value {
    try_eval_json(page, expression).await.unwrap()
}

async fn try_eval_json(
    page: &Page,
    expression: &str,
) -> Result<serde_json::Value, chromiumoxide::error::CdpError> {
    let params = EvaluateParams::builder()
        .expression(expression)
        .await_promise(true)
        .return_by_value(true)
        .build()
        .unwrap();
    let result = timed(
        &format!("evaluation of {expression}"),
        page.evaluate(params),
    )
    .await?;
    Ok(result.into_value().unwrap_or(serde_json::Value::Null))
}

/// Polls `expression` until it yields the string `wanted`. An evaluation
/// that meets a document replaced by navigation counts as not yet.
pub async fn wait_for(page: &Page, expression: &str, wanted: &str) {
    let deadline = Instant::now() + STEP;
    loop {
        let value = try_eval_json(page, expression)
            .await
            .unwrap_or(serde_json::Value::Null);
        if value.as_str() == Some(wanted) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{expression} never became {wanted}: {value}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// The element `selector` names in the current document. A lookup that
/// races a navigation's document replacement retries until [`STEP`].
pub async fn element(page: &Page, selector: &str) -> Element {
    let deadline = Instant::now() + STEP;
    loop {
        match timed(
            &format!("lookup of {selector}"),
            page.find_element(selector),
        )
        .await
        {
            Ok(element) => return element,
            Err(error) => assert!(
                Instant::now() < deadline,
                "{selector} is not in the page: {error}"
            ),
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Clicks `selector` with a trusted input event.
pub async fn click(page: &Page, selector: &str) {
    let target = element(page, selector).await;
    timed(&format!("click on {selector}"), target.click())
        .await
        .unwrap();
}

/// Types `text` into the input `selector`.
pub async fn type_into(page: &Page, selector: &str, text: &str) {
    let input = element(page, selector).await;
    timed(&format!("focus of {selector}"), input.click())
        .await
        .unwrap();
    timed(&format!("typing into {selector}"), input.type_str(text))
        .await
        .unwrap();
}

/// Drives the signed enrollment page in `page`: types the terminal's
/// enrollment `code` into the shipped code form, creates the passkey through
/// the page's own WebAuthn registration with `label`, and returns the staged
/// credential with the confirmation code the page shows.
pub async fn enroll_in_browser(
    page: &Page,
    handle: &mut SignedEnrollmentHandle,
    code: &str,
    label: &str,
) -> (PendingOperatorEnrollment, String) {
    let Navigation::Loaded(_) = navigate(page, &handle.enroll_url()).await else {
        panic!("the signed enrollment page does not load");
    };
    type_into(page, "#code-input", code).await;
    click(page, "#code-btn").await;
    wait_for(
        page,
        "document.getElementById('enroll-btn') ? 'registration' : ''",
        "registration",
    )
    .await;
    type_into(page, "#label-input", label).await;
    click(page, "#enroll-btn").await;
    let pending = handle
        .await_completion_until(Instant::now() + STEP)
        .await
        .expect("the browser registration verifies at the signed origin");
    wait_for(
        page,
        "(function(){var e=document.getElementById('confirmation-code');\
         return e && !e.hidden ? 'shown' : '';})()",
        "shown",
    )
    .await;
    let shown = eval_json(
        page,
        "document.getElementById('confirmation-code').textContent",
    )
    .await;
    (pending, shown.as_str().unwrap().to_owned())
}
