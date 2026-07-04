//! Testnet acceptance: the shipped remote-approval browser frontend drives a
//! real payment approve decision through to `stellar_pay_commit`, entirely
//! through the real HTML/JS pages served over TLS.
//!
//! This is the class of test that a Rust-only unit suite cannot provide: the
//! `stellar-agent-approval-remote` crate's own tests exercise the HTTP
//! handlers directly, never the browser-rendered pages or the shipped
//! `/static/login.js` / `/static/app.js` glue. This suite drives a headless
//! Chromium against the real TLS listener and asserts the ENTIRE surface is
//! functional: login page -> passkey login ceremony -> inbox -> detail page
//! -> per-action passkey ceremony -> attested commit -> on-chain inclusion.
//!
//! # Flow
//!
//! 1. `stellar_pay` (under a `RequireApproval` policy) parks a real payment
//!    approval against funded testnet accounts — the same production path
//!    `approve_serve_testnet_acceptance.rs` exercises for the loopback server.
//! 2. `start_remote_serve` binds the real TLS listener on loopback with
//!    `rp_id = "localhost"` and a real `rcgen` self-signed certificate, with
//!    an EMPTY credential allowlist — enrollment does not require one, and
//!    the real allowlist can only be known once the credential the
//!    enrollment ceremony produces exists.
//! 3. A headless Chromium (chromiumoxide) is launched; the CDP WebAuthn
//!    domain is enabled with an empty virtual authenticator (no credential
//!    pre-seeded).
//! 4. The browser drives the SHIPPED enrollment page: `GET /enroll`, click
//!    "Create passkey" — this runs a REAL `navigator.credentials.create()`
//!    through `/static/enroll.js`, so the virtual authenticator generates
//!    its own credential id and P-256 keypair, exactly as a hardware key
//!    would. The page displays the resulting credential id and SEC1 public
//!    key; this test reads those two DOM-rendered values and enrolls them
//!    into a fresh `OperatorApprovalCredentialStore` — the exact store
//!    `stellar-agent-cli`'s `approve operator enroll` writes to, using
//!    EXACTLY the values the page displayed, mirroring the CLI's write
//!    rather than re-deriving them independently.
//! 5. The first listener is torn down and a second is started with the
//!    now-enrolled credential id in its allowlist — mirroring real
//!    operation, where `allowed_credentials` is read once at listener
//!    startup from the profile, and an operator who enrolls a new credential
//!    must add its id to the profile and restart `approve serve --remote`
//!    for the allowlist to take effect.
//! 6. The SAME browser session (the virtual authenticator persists across
//!    navigations) drives the complete shipped decision flow against the
//!    second listener: `GET /`, click "Sign in with passkey" (login.js's
//!    ceremony, signing with the credential the /enroll ceremony just
//!    created), navigate to `/inbox`, click the parked entry's link, land on
//!    the detail page, click Approve (app.js's per-action ceremony).
//! 7. Assertions: the rendered result surfaces the attestation blob (which
//!    independently verifies against the attestation key); the audit log
//!    carries an `ApprovalAttestedRemote` row with the correct operator
//!    pseudonym; `stellar_pay_commit` with that attestation submits and
//!    confirms on-chain, and the destination balance increases by exactly
//!    the committed amount.
//!
//! # Gate
//!
//! ```text
//! cargo test -p stellar-agent-approval-remote --features testnet-acceptance \
//!   --test remote_approval_browser_testnet_acceptance -- --ignored
//! ```
//!
//! # Prerequisites
//!
//! - `CHROMIUM` or `chromium`/`chromium-browser`/`google-chrome` on `PATH`, or
//!   the `CHROME` environment variable pointing to the executable.
//! - Active testnet connectivity (Friendbot + Soroban RPC).

#![cfg(feature = "testnet-acceptance")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics and unwraps are acceptable in testnet acceptance tests"
)]
#![allow(
    unsafe_code,
    reason = "test-only STELLAR_AGENT_HOME override for isolated TLS cert storage, matching stellar_agent_approval_remote::tls's own test convention"
)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chromiumoxide::browser::{Browser, BrowserConfig};
use chromiumoxide::cdp::browser_protocol::web_authn::{
    AddVirtualAuthenticatorParams, AuthenticatorProtocol, AuthenticatorTransport, EnableParams,
    VirtualAuthenticatorOptions,
};
use chromiumoxide::cdp::js_protocol::runtime::EvaluateParams;
use ed25519_dalek::SigningKey;
use futures::StreamExt as _;
use rand_core::OsRng;
use serial_test::serial;
use sha2::{Digest as _, Sha256};
use stellar_agent_approval_remote::{RemoteServeConfig, provision_or_load, start_remote_serve};
use stellar_agent_approval_ui::DecisionContext;
use stellar_agent_core::approval::operator_credentials::{
    OperatorApprovalCredential, OperatorApprovalCredentialStore,
};
use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_core::policy::v1::{
    AccountIdentityView, AccountReservesView, CounterpartyCacheView, Sep10SessionView,
    Sep45SessionView,
};
use stellar_agent_core::policy::{
    ApprovalRequest, Decision as PolicyDecision, PolicyEngine, PolicyError, ToolDescriptor,
};
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_core::timefmt;
use stellar_agent_mcp::server::{StellarPayArgs, StellarPayCommitArgs, WalletServer};
use stellar_agent_network::{StellarRpcClient, fetch_account};
use stellar_agent_test_support::keyring_mock;
use tempfile::TempDir;
use zeroize::Zeroizing;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";
const TESTNET_FRIENDBOT_URL: &str = "https://friendbot.stellar.org";
const TESTNET_CHAIN_ID: &str = "stellar:testnet";
const FEE_STROOPS: u32 = 100_000;
const PAYMENT_STROOPS: i64 = 10_000_000; // 1 XLM

/// `"localhost"` is the correct loopback RP-ID per WebAuthn Level 2 §5.1.2;
/// IP literals are rejected by browsers (and by
/// `config_validate::validate_rp_id`). The listener binds `127.0.0.1`, which
/// resolves from `localhost` on any standard host.
const TEST_RP_ID: &str = "localhost";

// ─────────────────────────────────────────────────────────────────────────────
// RequireApproval policy engine — forces stellar_pay to park a pending entry
// ─────────────────────────────────────────────────────────────────────────────

struct RequireApprovalEngine;

impl PolicyEngine for RequireApprovalEngine {
    fn evaluate(
        &self,
        _tool: &ToolDescriptor,
        _args: &serde_json::Value,
        _profile: &Profile,
        _account_view: Option<&dyn AccountReservesView>,
        _identity_view: Option<&dyn AccountIdentityView>,
        _counterparty_cache: Option<&dyn CounterpartyCacheView>,
        _sep10_sessions: Option<&dyn Sep10SessionView>,
        _sep45_sessions: Option<&dyn Sep45SessionView>,
    ) -> Result<PolicyDecision, PolicyError> {
        Ok(PolicyDecision::RequireApproval(ApprovalRequest::new(
            "remote-approval-browser-testnet-acceptance".into(),
            600,
        )))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Testnet helpers
// ─────────────────────────────────────────────────────────────────────────────

fn fresh_keypair() -> (String, Zeroizing<[u8; 32]>) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let g_strkey = stellar_strkey::ed25519::PublicKey(signing_key.verifying_key().to_bytes())
        .to_string()
        .as_str()
        .to_owned();
    (g_strkey, Zeroizing::new(signing_key.to_bytes()))
}

async fn fund_via_friendbot(g_strkey: &str) {
    let url = format!("{TESTNET_FRIENDBOT_URL}?addr={g_strkey}");
    let resp = reqwest::get(&url)
        .await
        .expect("Friendbot HTTP request must succeed");
    assert!(
        resp.status().is_success(),
        "Friendbot must return 2xx for {g_strkey}; got {}",
        resp.status()
    );
}

async fn wait_until_queryable(g_strkey: &str) {
    let client = StellarRpcClient::new(TESTNET_RPC_URL).expect("RPC client");
    for _ in 0..30 {
        if fetch_account(&client, g_strkey, &[]).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("funded account {g_strkey} did not become RPC-queryable in time");
}

async fn native_balance_stroops(g_strkey: &str) -> i64 {
    let client = StellarRpcClient::new(TESTNET_RPC_URL).expect("RPC client");
    let view = fetch_account(&client, g_strkey, &[])
        .await
        .expect("fetch_account must succeed for a funded, queryable account");
    view.balances
        .iter()
        .find(|b| b.asset.asset_type == "native")
        .map(|b| b.balance_stroops().expect("native balance parses"))
        .unwrap_or(0)
}

fn result_json(result: &rmcp::model::CallToolResult) -> serde_json::Value {
    let text = result
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.as_str())
        .expect("tool result must carry text content");
    serde_json::from_str(text).expect("tool result text must be valid JSON")
}

fn seed_keyring(profile: &Profile, seed: &Zeroizing<[u8; 32]>, attestation_key: &[u8; 32]) {
    let signer_ref = &profile.mcp_signer_default;
    let s_strkey = stellar_strkey::ed25519::PrivateKey::from_payload(seed.as_ref())
        .expect("32-byte seed encodes as S-strkey")
        .as_unredacted()
        .to_string();
    keyring_core::Entry::new(&signer_ref.service, &signer_ref.account)
        .expect("signer keyring entry")
        .set_password(&s_strkey)
        .expect("set signing key");

    let nonce_ref = &profile.mcp_nonce_key_alias;
    let nonce_key_b64 = URL_SAFE_NO_PAD.encode([0x42u8; 32]);
    keyring_core::Entry::new(&nonce_ref.service, &nonce_ref.account)
        .expect("nonce keyring entry")
        .set_password(&nonce_key_b64)
        .expect("set nonce key");

    let attest_ref = &profile.attestation_key_id;
    let attest_key_b64 = URL_SAFE_NO_PAD.encode(attestation_key);
    keyring_core::Entry::new(&attest_ref.service, &attest_ref.account)
        .expect("attestation keyring entry")
        .set_password(&attest_key_b64)
        .expect("set attestation key");
}

// ─────────────────────────────────────────────────────────────────────────────
// RAII guards
// ─────────────────────────────────────────────────────────────────────────────

/// RAII guard that shuts down the remote-approval server on drop.
///
/// Mirrors `stellar-agent-smart-account`'s `BridgeGuard`:
/// `RemoteServeHandle::shutdown` is async; the guard drives it synchronously
/// via `tokio::task::block_in_place` + `Handle::current().block_on(...)`,
/// which is permitted only on a multi-thread runtime.
struct RemoteServeGuard(Option<stellar_agent_approval_remote::RemoteServeHandle>);

impl Drop for RemoteServeGuard {
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
                    "stellar-agent test: remote-approval server shutdown error (non-fatal): {e}"
                );
            }
        }
    }
}

/// RAII guard that kills the `chromiumoxide::Browser` subprocess on drop —
/// see `stellar-agent-smart-account`'s identical `BrowserGuard`.
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

// ─────────────────────────────────────────────────────────────────────────────
// Browser launch
// ─────────────────────────────────────────────────────────────────────────────

/// Launches a headless Chromium for the remote-approval ceremony.
///
/// # TLS cert-error acceptance — builder default, not a launch flag
///
/// The listener presents a real but self-signed `rcgen` certificate.
/// chromiumoxide's `BrowserConfigBuilder` defaults `ignore_https_errors` to
/// `true` (`NetworkManager` issues `Security.setIgnoreCertificateErrors(true)`
/// over CDP as part of target attach) — this is the "browser builder's
/// cert-error setting" the crate exposes; no `--ignore-certificate-errors`
/// (or similar) launch-flag string is used or needed. `.respect_https_errors()`
/// is deliberately NOT called here.
///
/// # No `--disable-web-security`
///
/// As in the sibling WebAuthn acceptance test, this flag is never used: it
/// would suppress the very origin checks this suite exists to exercise.
///
/// # Sandbox
///
/// `.no_sandbox()` (a typed builder method, not a raw arg string) is required
/// under CI's restricted user namespaces; custom flags must go through typed
/// builder methods or dash-less `args` keys, since chromiumoxide renders each
/// `args` key as `--{key}`.
async fn launch_chromium() -> (Browser, chromiumoxide::Handler) {
    let config = BrowserConfig::builder()
        .no_sandbox()
        .build()
        .expect("BrowserConfig must build");
    assert!(
        config.user_data_dir.is_none(),
        "BrowserConfig.user_data_dir must be None (ephemeral)"
    );
    Browser::launch(config)
        .await
        .expect("Chromium must launch; ensure chromium/google-chrome is on PATH")
}

// ─────────────────────────────────────────────────────────────────────────────
// Remote-serve wiring
// ─────────────────────────────────────────────────────────────────────────────

/// Starts the remote-approval TLS listener against the same store + key the
/// `WalletServer` parked the pending entry under, with `allowed_credentials`
/// as its allowlist.
///
/// Takes the full allowlist (rather than a single id) because this suite
/// starts the listener TWICE: once with an empty allowlist for the
/// enrollment ceremony (which needs none), and again with the
/// just-enrolled credential id once it is known — mirroring how
/// `allowed_credentials` is read once at real listener startup and requires
/// a restart to pick up a newly enrolled credential.
async fn start_remote_serve_for_profile(
    server: &WalletServer,
    profile: &Profile,
    approval_dir: &TempDir,
    operator_credentials_path: std::path::PathBuf,
    allowed_credentials: Vec<String>,
) -> stellar_agent_approval_remote::RemoteServeHandle {
    let profile_name = server.profile_name_for_approval();
    let store_path = approval_dir.path().join(format!("{profile_name}.toml"));
    let audit_path = approval_dir.path().join("audit.log");
    let audit_writer = Arc::new(StdMutex::new(
        AuditWriter::open(audit_path, None).expect("audit writer open"),
    ));
    let ctx = DecisionContext::new(
        profile_name,
        store_path,
        profile.attestation_key_id.clone(),
        audit_writer,
        None,
    );

    let tls = provision_or_load("remote-approval-browser-testnet-acceptance", TEST_RP_ID)
        .expect("TLS cert must provision");

    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let config = RemoteServeConfig::new(
        bind_addr,
        TEST_RP_ID,
        allowed_credentials,
        ctx,
        operator_credentials_path,
        tls,
    );
    start_remote_serve(config)
        .await
        .expect("start_remote_serve must succeed")
}

/// Returns the audit log path for a `DecisionContext` built the same way
/// `start_remote_serve_for_profile` builds its own — kept in lockstep by
/// construction (both derive the path from `approval_dir`).
fn audit_log_path(approval_dir: &TempDir) -> std::path::PathBuf {
    approval_dir.path().join("audit.log")
}

// ─────────────────────────────────────────────────────────────────────────────
// DOM helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Builds an `EvaluateParams` expression that explicitly requests
/// `returnByValue: true`. Passing a bare `&str` to `Page::evaluate` routes
/// through `is_likely_js_function`'s heuristic, which — depending on the
/// exact expression shape — can select the `Runtime.callFunctionOn` path
/// instead of `Runtime.evaluate`, and only the latter defaults to returning
/// a JSON value chromiumoxide can deserialise. Building the params directly
/// removes that ambiguity for every DOM-inspection call this suite makes.
fn evaluate_by_value(expression: &str) -> EvaluateParams {
    EvaluateParams::builder()
        .expression(expression)
        .return_by_value(true)
        .build()
        .expect("EvaluateParams must build")
}

/// Polls `page` for a non-empty attestation `<textarea>` value inside
/// `#result`, or panics after `deadline`. There is no early-return-ok path:
/// every branch either yields the value or a test-failing panic.
async fn poll_attestation_textarea(page: &chromiumoxide::Page, deadline: Instant) -> String {
    loop {
        // Returns `''` (never `null`/`undefined`) when the textarea is
        // absent: CDP's `RemoteObject` omits the `value` field entirely for
        // `null`/`undefined` results even with `returnByValue: true`, which
        // `EvaluationResult::into_value` cannot deserialise at all — an
        // empty string always carries a real `value` field.
        let value: String = page
            .evaluate(evaluate_by_value(
                "(function(){var ta = document.querySelector('#result textarea'); \
                 return ta ? ta.value : '';})()",
            ))
            .await
            .expect("evaluate must not error")
            .into_value()
            .expect("evaluate result must deserialise as String");
        if !value.is_empty() {
            return value;
        }
        assert!(
            Instant::now() < deadline,
            "attestation textarea did not populate within the deadline — the approve ceremony \
             did not complete through the real browser frontend"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Polls the enrollment page's two result `<textarea>`s
/// (`#cred-id-output`, `#pubkey-output`) until both populate, returning
/// their values, or panics after `deadline`. Mirrors
/// [`poll_attestation_textarea`]'s never-null-return discipline.
async fn poll_enroll_output(page: &chromiumoxide::Page, deadline: Instant) -> (String, String) {
    loop {
        let cred_id: String = page
            .evaluate(evaluate_by_value(
                "(function(){var el = document.getElementById('cred-id-output'); \
                 return el ? el.value : '';})()",
            ))
            .await
            .expect("evaluate must not error")
            .into_value()
            .expect("evaluate result must deserialise as String");
        let pubkey: String = page
            .evaluate(evaluate_by_value(
                "(function(){var el = document.getElementById('pubkey-output'); \
                 return el ? el.value : '';})()",
            ))
            .await
            .expect("evaluate must not error")
            .into_value()
            .expect("evaluate result must deserialise as String");
        if !cred_id.is_empty() && !pubkey.is_empty() {
            return (cred_id, pubkey);
        }
        assert!(
            Instant::now() < deadline,
            "the enrollment page's credential id / public key outputs did not populate within \
             the deadline — the real navigator.credentials.create() ceremony did not complete \
             through the shipped /static/enroll.js"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Polls `page.url()` until it ends with `suffix`, or panics after
/// `deadline` with the `#status` element's current text (if any) so a
/// failed ceremony's actual error message is visible in the test failure
/// rather than just "did not navigate".
async fn wait_for_url_ending(page: &chromiumoxide::Page, suffix: &str, deadline: Instant) {
    loop {
        let url = page
            .url()
            .await
            .expect("page URL must be readable")
            .unwrap_or_default();
        if url.ends_with(suffix) {
            return;
        }
        if Instant::now() >= deadline {
            let status: Option<String> = page
                .evaluate(evaluate_by_value(
                    "(function(){var s = document.getElementById('status'); \
                     return s ? s.innerText : '';})()",
                ))
                .await
                .ok()
                .and_then(|r| r.into_value::<String>().ok());
            panic!(
                "navigation to a URL ending in {suffix:?} did not occur within the deadline; \
                 last seen URL: {url:?}; #status text: {status:?}"
            );
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Reads the `#result` panel's status line, asserting it reports `attested`.
async fn assert_result_status_attested(page: &chromiumoxide::Page) {
    let status: String = page
        .evaluate(evaluate_by_value(
            "(function(){var r = document.getElementById('result'); \
             var p = r ? r.querySelector('p') : null; return p ? p.innerText : '';})()",
        ))
        .await
        .expect("evaluate must not error")
        .into_value()
        .expect("evaluate result must deserialise as String");
    assert!(
        status.contains("attested"),
        "the rendered #result status line must report 'attested'; got: {status:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Main acceptance test
// ─────────────────────────────────────────────────────────────────────────────

/// Full remote-approval browser acceptance: park a real payment approval,
/// serve it over the real TLS listener, drive the SHIPPED frontend
/// (`/static/login.js`, `/static/app.js`) through a headless Chromium with a
/// seeded CDP virtual authenticator, and commit the resulting attestation
/// on-chain.
///
/// `flavor = "multi_thread"` is required so `tokio::task::block_in_place`
/// (used by both RAII guards) is permitted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
#[ignore = "requires testnet, chromium, and explicit --ignored flag"]
async fn remote_approval_browser_drives_real_payment_commit() {
    keyring_mock::install().expect("mock keyring store init");

    let (payer_g, payer_seed) = fresh_keypair();
    let (dest_g, _dest_seed) = fresh_keypair();
    fund_via_friendbot(&payer_g).await;
    fund_via_friendbot(&dest_g).await;
    wait_until_queryable(&payer_g).await;
    wait_until_queryable(&dest_g).await;

    let dest_balance_before = native_balance_stroops(&dest_g).await;

    let attestation_key = [0x33u8; 32];
    let approval_dir = TempDir::new().expect("approval temp dir");
    let tls_home_dir = TempDir::new().expect("TLS home temp dir");
    let operator_credentials_path = approval_dir.path().join("operator_credentials.toml");

    // Isolated TLS cert storage: `provision_or_load`'s STELLAR_AGENT_HOME
    // override only compiles under `cfg(test)` or `test-helpers` — both
    // active for this crate under the `testnet-acceptance` feature.
    //
    // RAII guard ensures the env var is cleared even if this test panics
    // partway through (otherwise a panic here leaks it for the rest of the
    // process's lifetime, affecting any sibling test that reads it) —
    // mirrors the `ProxyGuard` pattern used for the same class of problem in
    // `stellar-agent-smart-account`'s `list_rules_no_indexer_call_mock.rs`.
    struct StellarAgentHomeGuard;
    impl Drop for StellarAgentHomeGuard {
        fn drop(&mut self) {
            unsafe {
                std::env::remove_var("STELLAR_AGENT_HOME");
            }
        }
    }
    let _stellar_agent_home_guard = StellarAgentHomeGuard;
    unsafe {
        std::env::set_var("STELLAR_AGENT_HOME", tls_home_dir.path());
    }

    let mut profile =
        Profile::builder_testnet("stellar-agent", &payer_g, "stellar-agent-nonce", &payer_g)
            .with_noop_engine()
            .build();
    profile.rpc_url = TESTNET_RPC_URL.to_owned();
    seed_keyring(&profile, &payer_seed, &attestation_key);

    let mut server = WalletServer::new(profile.clone()).expect("WalletServer::new");
    server.set_approval_dir_for_test(approval_dir.path().to_path_buf());
    server.set_policy_engine_for_test(Arc::new(RequireApprovalEngine));

    // ── 1. Simulate under RequireApproval: parks a real pending entry ───────
    let sim = server
        .call_stellar_pay(StellarPayArgs {
            chain_id: TESTNET_CHAIN_ID.to_owned(),
            source: payer_g.clone(),
            destination: dest_g.clone(),
            amount: Some(serde_json::from_str(r#""1 XLM""#).expect("amount")),
            amount_in_stroops: None,
            asset: "native".to_owned(),
            memo_text: None,
            memo_id: None,
            memo_hash_hex: None,
            memo_return_hex: None,
            classic_base: Some(FEE_STROOPS.to_string()),
        })
        .await
        .expect("simulate must succeed against funded accounts");
    let sim_json = result_json(&sim);
    assert!(
        sim_json["ok"].as_bool().unwrap_or(false),
        "simulate envelope must be ok: {sim_json}"
    );
    let envelope_xdr = sim_json["data"]["envelope_xdr"]
        .as_str()
        .expect("simulate must surface envelope_xdr")
        .to_owned();
    let nonce = sim_json["data"]["nonce"]
        .as_str()
        .expect("simulate must surface nonce")
        .to_owned();
    let expires_at_unix_ms = sim_json["data"]["expires_at_unix_ms"]
        .as_u64()
        .expect("simulate must surface expires_at_unix_ms");
    let approval_nonce = sim_json["data"]["approval"]["approval_nonce"]
        .as_str()
        .expect("RequireApproval simulate must surface an approval_nonce")
        .to_owned();

    // ── 2. Start the TLS listener for the enrollment ceremony ───────────────
    //
    // A WebAuthn credential is bound to its rp.id at creation, so the
    // enrollment page has to be served from the real TLS origin, not run
    // separately. The allowlist is empty: enrollment does not need one, and
    // the real allowlist can only be known once the ceremony below produces
    // a credential id.
    let enroll_handle = start_remote_serve_for_profile(
        &server,
        &profile,
        &approval_dir,
        operator_credentials_path.clone(),
        Vec::new(),
    )
    .await;
    let enroll_base_url = format!("https://{TEST_RP_ID}:{}", enroll_handle.local_addr().port());

    // ── 3. Launch Chromium, enable WebAuthn, add an EMPTY virtual authenticator ──
    //
    // No credential is pre-seeded: the enrollment ceremony below (a real
    // `navigator.credentials.create()` call through the shipped
    // `/static/enroll.js`) makes the authenticator generate its own
    // credential id and P-256 keypair, exactly as a hardware key would.
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

    let auth_options = VirtualAuthenticatorOptions::builder()
        .protocol(AuthenticatorProtocol::Ctap2)
        .transport(AuthenticatorTransport::Internal)
        .has_user_verification(true)
        .is_user_verified(true)
        // Discoverable/resident: neither `login.js` nor `app.js` sends
        // `allowCredentials`, so the authenticator must be able to resolve a
        // credential for the RP without one — exactly the single-operator
        // posture the remote-approval session model documents.
        .has_resident_key(true)
        .automatic_presence_simulation(true)
        .build()
        .expect("VirtualAuthenticatorOptions must build");

    page.execute(AddVirtualAuthenticatorParams::new(auth_options))
        .await
        .expect("addVirtualAuthenticator must succeed");

    // ── 4. Drive the SHIPPED enrollment page: create a real passkey ─────────
    page.goto(&format!("{enroll_base_url}/enroll"))
        .await
        .expect("navigation to the enrollment page must succeed");

    let enroll_btn = page
        .find_element("#enroll-btn")
        .await
        .expect("#enroll-btn must be present on the rendered enrollment page");
    enroll_btn
        .click()
        .await
        .expect("enroll button click must succeed");

    let enroll_deadline = Instant::now() + Duration::from_secs(30);
    let (credential_id_b64url, pubkey_b64url) = poll_enroll_output(&page, enroll_deadline).await;

    // ── 5. Enroll the PAGE-CREATED credential — the CLI-equivalent write ────
    //
    // Uses EXACTLY the values `/static/enroll.js` displayed, the same values
    // an operator would copy into `approve operator enroll` — this also
    // independently validates the page's SPKI-to-SEC1 extraction, since
    // `OperatorApprovalCredentialStore::enroll` rejects a malformed public
    // key.
    let op_store = OperatorApprovalCredentialStore::new(operator_credentials_path.clone());
    op_store
        .enroll(OperatorApprovalCredential {
            credential_id_b64url: credential_id_b64url.clone(),
            public_key_sec1_b64: pubkey_b64url,
            rp_id: TEST_RP_ID.to_owned(),
            label: "test-browser-authenticator".to_owned(),
            registered_at_unix_ms: timefmt::now_unix_ms().expect("clock read"),
            sign_count: None,
        })
        .expect("operator credential enrollment must succeed with the page-displayed values");

    // ── 6. Restart the listener with the now-known allowlist ────────────────
    //
    // Mirrors real operation: `allowed_credentials` is read once at listener
    // startup from the profile; after enrolling a new credential the
    // operator adds its id to the profile and restarts `approve serve
    // --remote` for the allowlist to take effect. The virtual authenticator
    // (and its just-created credential) persists across this navigation —
    // WebAuthn scopes a credential to its rp_id, not the full origin, so it
    // remains usable against the new listener's different port.
    drop(RemoteServeGuard(Some(enroll_handle)));
    let handle = start_remote_serve_for_profile(
        &server,
        &profile,
        &approval_dir,
        operator_credentials_path,
        vec![credential_id_b64url.clone()],
    )
    .await;
    let base_url = format!("https://{TEST_RP_ID}:{}", handle.local_addr().port());
    let _serve_guard = RemoteServeGuard(Some(handle));

    // ── 7. Drive the SHIPPED frontend: login ─────────────────────────────────
    page.goto(&base_url)
        .await
        .expect("navigation to the login page must succeed");

    let login_btn = page
        .find_element("#login-btn")
        .await
        .expect("#login-btn must be present on the rendered login page");
    login_btn
        .click()
        .await
        .expect("login button click must succeed");

    // login.js navigates to /inbox on success; poll for that navigation
    // rather than chromiumoxide's `wait_for_navigation()`, which can resolve
    // on frame-lifecycle events unrelated to an actual URL change.
    let login_deadline = Instant::now() + Duration::from_secs(30);
    wait_for_url_ending(&page, "/inbox", login_deadline).await;

    // ── 8. Drive the SHIPPED frontend: inbox -> detail ───────────────────────
    let entry_selector = format!(r#"a[href="/approval/{approval_nonce}"]"#);
    let entry_link = page
        .find_element(&entry_selector)
        .await
        .unwrap_or_else(|_| {
            panic!(
                "the parked approval's link ({entry_selector}) must be rendered in the real \
                 inbox page by app.js"
            )
        });
    entry_link
        .click()
        .await
        .expect("inbox entry link click must succeed");
    let detail_deadline = Instant::now() + Duration::from_secs(15);
    wait_for_url_ending(
        &page,
        &format!("/approval/{approval_nonce}"),
        detail_deadline,
    )
    .await;

    // ── 9. Drive the SHIPPED frontend: the per-action passkey ceremony ───────
    let approve_btn = page
        .find_element("#approve-btn")
        .await
        .expect("#approve-btn must be present on the rendered detail page");
    approve_btn
        .click()
        .await
        .expect("approve button click must succeed");

    let ceremony_deadline = Instant::now() + Duration::from_secs(60);
    let attestation_b64 = poll_attestation_textarea(&page, ceremony_deadline).await;
    assert_result_status_attested(&page).await;

    // Independently verify the browser-surfaced blob against the attestation
    // key — never trust the rendered DOM without cross-checking the crypto.
    let envelope_sha256 = stellar_agent_core::approval::envelope_sha256(envelope_xdr.as_bytes());
    let uid = stellar_agent_core::approval::process_uid_for_attestation()
        .expect("process uid on test host");
    let attestation_bytes: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&attestation_b64)
        .expect("attestation decodes as base64")
        .try_into()
        .expect("attestation is 32 bytes");
    assert!(
        stellar_agent_core::approval::verify_attestation(
            &attestation_key,
            &approval_nonce,
            &envelope_sha256,
            &uid,
            &attestation_bytes,
        ),
        "the browser-surfaced attestation must verify against the attestation key"
    );

    // ── 10. Audit log carries an ApprovalAttestedRemote row with a pseudonym ──
    let audit_path = audit_log_path(&approval_dir);
    let audit_text = std::fs::read_to_string(&audit_path).expect("audit log must be readable");
    let expected_pseudonym = {
        let digest = Sha256::digest(credential_id_b64url.as_bytes());
        hex::encode(&digest[..4])
    };
    let found_remote_row = audit_text.lines().any(|line| {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            return false;
        };
        value["kind"] == "approval_attested_remote"
            && value["operator_credential_id_redacted"] == expected_pseudonym
    });
    assert!(
        found_remote_row,
        "the audit log must contain an ApprovalAttestedRemote row with the expected operator \
         pseudonym {expected_pseudonym:?}; log contents:\n{audit_text}"
    );

    // Tear down the browser + server before the on-chain commit — the
    // remote-approval surface's job ends at surfacing the attestation.
    handler_task.abort();
    drop(browser_guard);
    drop(_serve_guard);

    // ── 11. Commit on-chain with the browser-minted attestation ───────────────
    let commit = server
        .call_stellar_pay_commit(StellarPayCommitArgs {
            chain_id: TESTNET_CHAIN_ID.to_owned(),
            source: payer_g.clone(),
            destination: dest_g.clone(),
            amount: Some(serde_json::from_str(r#""1 XLM""#).expect("amount")),
            amount_in_stroops: None,
            asset: "native".to_owned(),
            memo_text: None,
            memo_id: None,
            memo_hash_hex: None,
            memo_return_hex: None,
            nonce,
            expires_at_unix_ms,
            envelope_xdr,
            approval_nonce: Some(approval_nonce),
            approval_attestation: Some(attestation_b64),
        })
        .await
        .expect("commit must pass the gate and submit on-chain");
    let commit_json = result_json(&commit);
    assert!(
        commit_json["ok"].as_bool().unwrap_or(false),
        "commit envelope must be ok (submitted on-chain): {commit_json}"
    );
    let tx_hash = commit_json["data"]["tx_hash"]
        .as_str()
        .expect("commit must report an on-chain tx_hash");
    assert_eq!(tx_hash.len(), 64, "tx_hash must be a 32-byte hex digest");
    assert!(
        commit_json["data"]["ledger"].as_u64().unwrap_or(0) > 0,
        "commit must report the ledger it was included in: {commit_json}"
    );

    // ── 12. On-chain effect: the destination actually received the payment ──
    let dest_balance_after = native_balance_stroops(&dest_g).await;
    assert_eq!(
        dest_balance_after,
        dest_balance_before + PAYMENT_STROOPS,
        "destination balance must increase by exactly the committed payment"
    );

    // `_stellar_agent_home_guard` clears STELLAR_AGENT_HOME here (normal
    // return) or on unwind if an earlier assertion panicked.
}
