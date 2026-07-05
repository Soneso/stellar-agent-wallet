//! Testnet acceptance test for the WebAuthn passkey signing path.
//!
//! Exercises the full WebAuthn browser-handoff ceremony against testnet:
//!
//! 1. Deploy a fresh smart account with a delegated ed25519 signer (bootstrap rule).
//! 2. Deploy the OZ WebAuthn verifier WASM (from `stellar_agent_smart_account::webauthn_verifier`)
//!    to testnet via `deployment::deploy_webauthn_verifier`.
//! 3. Start the WebAuthn bridge with `start_bridge_with_pubkey_lookup` (wired
//!    to a `PasskeysRegistryPubkeyLookup` so `/approve/<nonce>/assertion` can
//!    resolve the registered credential pubkey for `pre_verify_assertion`).
//! 4. Launch a headless Chromium via `chromiumoxide::Browser::launch`.
//! 5. Enable the WebAuthn CDP domain; add a virtual authenticator (CTAP2 / internal transport /
//!    user-verification). The virtual authenticator generates its own keypair internally.
//! 6. Navigate the browser to `http://localhost:<port>/register/<nonce>`.  The page's JS calls
//!    `navigator.credentials.create()` and the virtual authenticator generates the P-256 keypair
//!    internally without the private key ever crossing the CDP wire.
//! 7. Poll `CredentialsManager::poll_registration` until the bridge POST handler records the
//!    `RegistrationInput` (credential ID + public key + transports).
//! 8. Read the stored `CredentialMetadata` from the passkeys registry.
//! 9. Install a context rule with `Signer::External(verifier_addr, pubkey_data)` via
//!    `ContextRuleManager::install_rule` (pubkey_data = pubkey_65_bytes || credential_id per OZ
//!    `canonicalize_key` at `verifiers/webauthn.rs:373-377`).
//! 10. Call `CredentialsManager::sign_with_passkey_rule` which:
//!     a. Inserts a `SignWithPasskey` approval entry.
//!     b. Returns the approval URL.
//! 11. Navigate the chromiumoxide browser to the approval URL (the bridge's
//!     `GET /approve/<nonce>` page).  The page's JS calls `startAuthentication()`
//!     and the virtual authenticator completes the ceremony.
//! 12. The bridge POST handler records the assertion; the poll loop picks it up.
//! 13. Assert `SignWithPasskeyOutcome::Signed { .. }` is returned.
//! 14. Tear down the browser and bridge.
//!
//! # Audit compliance
//!
//! - Defence: private key NEVER crosses the CDP wire; `addCredential` /
//!   PKCS#8 injection is NOT used.  The virtual authenticator generates the
//!   P-256 keypair internally during `navigator.credentials.create()`.
//! - Defence: no `user_data_dir` is set on `BrowserConfig`; chromiumoxide
//!   defaults to an ephemeral path under `std::env::temp_dir()`.  Asserted
//!   at construction.
//! - Defence: `BrowserGuard` drives `browser.kill()` in its `Drop` impl
//!   via `tokio::task::block_in_place` + `Handle::current().block_on(...)`.
//!   `BridgeGuard::drop` uses the same pattern for `handle.shutdown()`.
//!   Both guards require `flavor = "multi_thread"` on the outer test so
//!   `block_in_place` is permitted (current_thread runtimes reject it and
//!   `Handle::current().block_on()` panics when called from inside a
//!   current_thread context).
//! - Defence: all `page.goto()` calls go through `goto_loopback()` which
//!   parses the URL structurally and rejects non-loopback hosts including the
//!   userinfo-bypass attack `http://localhost:3000@evil.com/`.
//! - The Chromium launch args do NOT include `--disable-web-security` or
//!   `--allow-insecure-localhost`; these flags suppress WebAuthn origin checks
//!   and must not be present in a valid test of the user-facing surface.
//!   `http://localhost` is a W3C Secure Context exempt from HTTPS and does
//!   not need these flags.
//!
//! # Gate
//!
//! Compiled only under `--features testnet-integration`.  All tests in this
//! file are additionally marked `#[ignore]` so that bare `cargo test --features
//! testnet-integration` does not run them unintentionally; use:
//!
//! ```text
//! cargo test --features testnet-integration \
//!   --test smart_account_rules_webauthn_testnet_acceptance -- --ignored
//! ```
//!
//! # Prerequisites
//!
//! - `CHROMIUM` or `chromium`/`chromium-browser`/`google-chrome` on `PATH`, or
//!   the `CHROME` environment variable pointing to the executable.
//! - Active testnet connectivity (Friendbot + Soroban RPC).
//!
//! # Canonical format
//!
//! The `pubkey_data` concatenation format (`pubkey_65_bytes || credential_id_bytes`)
//! is canonical per OpenZeppelin's `canonicalize_key` in the stellar-contracts
//! WebAuthn verifier.

#![cfg(feature = "testnet-integration")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics are acceptable in integration tests"
)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chromiumoxide::browser::{Browser, BrowserConfig};
use chromiumoxide::cdp::browser_protocol::web_authn::{
    AddVirtualAuthenticatorParams, AuthenticatorProtocol, AuthenticatorTransport, EnableParams,
    VirtualAuthenticatorOptions,
};
use ed25519_dalek::SigningKey;
use futures::StreamExt as _;
use rand_core::OsRng;
use stellar_agent_core::approval::store::PendingApprovalStore;
use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_core::observability::is_loopback_http_url;
use stellar_agent_core::smart_account::rule_id::ContextRuleId;
use stellar_agent_network::{Signer, SoftwareSigningKey};
use stellar_agent_smart_account::deployment::{
    DeployerKeypair, DeploymentArgs, ResolvedFeePerOp, deploy_smart_account,
    deploy_webauthn_verifier,
};
use stellar_agent_smart_account::managers::credentials::{
    AddPasskeyOutcome, CredentialsManager, SignWithPasskeyOutcome,
};
use stellar_agent_smart_account::managers::rules::RuleContext;
use stellar_agent_smart_account::managers::rules::{
    ContextRuleDefinition, ContextRuleManager, ContextRuleManagerConfig, ContextRuleSignerInput,
    parse_c_strkey_to_smart_account, parse_g_strkey_to_signer_address,
};
use stellar_agent_smart_account::verifiers::VerifierRegistry;
use stellar_agent_smart_account::webauthn_verifier::WEBAUTHN_VERIFIER_WASM_SHA256;
use tempfile::TempDir;
use tokio::sync::Mutex;
use uuid::Uuid;
use zeroize::Zeroizing;

const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";
const TESTNET_FRIENDBOT_URL: &str = "https://friendbot.stellar.org";
const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
const CHAIN_ID: &str = "stellar:testnet";

/// RP-ID for the test ceremony.
///
/// `"localhost"` is the correct loopback RP-ID per WebAuthn Level 2 §5.1.2.
/// IP literals (e.g. `"127.0.0.1"`) are NOT valid RP-IDs and will be
/// rejected by browsers.  The bridge binds to loopback and the origin
/// `http://localhost:<port>` satisfies the RP-ID domain binding rule.
const TEST_RP_ID: &str = "localhost";

/// Generates a fresh UUID-v4 request-id string for forensic correlation.
fn rid() -> String {
    Uuid::new_v4().to_string()
}

/// Funds an account via testnet Friendbot.
async fn fund_via_friendbot(g_strkey: &str) {
    let url = format!("{TESTNET_FRIENDBOT_URL}?addr={g_strkey}");
    let resp = reqwest::get(&url)
        .await
        .expect("Friendbot HTTP request must succeed");
    assert!(
        resp.status().is_success(),
        "Friendbot must return 200 for {g_strkey}; got {}",
        resp.status()
    );
}

/// Generates a fresh ed25519 keypair.
fn fresh_ed25519_signer() -> (String, Box<dyn Signer + Send + Sync>) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let g_strkey = format!(
        "{}",
        stellar_strkey::ed25519::PublicKey(verifying_key.to_bytes())
    );
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(signing_key.to_bytes());
    let signer: Box<dyn Signer + Send + Sync> =
        Box::new(SoftwareSigningKey::new_from_zeroizing(seed));
    (g_strkey, signer)
}

/// Generates a fresh deployer keypair.
fn fresh_deployer_keypair() -> (String, DeployerKeypair) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let g_strkey = format!(
        "{}",
        stellar_strkey::ed25519::PublicKey(verifying_key.to_bytes())
    );
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(signing_key.to_bytes());
    let signer: Box<dyn Signer + Send + Sync> =
        Box::new(SoftwareSigningKey::new_from_zeroizing(seed));
    let deployer = DeployerKeypair::SecretEnv {
        var_name: "testnet-webauthn-acceptance-generated".to_owned(),
        signer,
    };
    (g_strkey, deployer)
}

/// Constructs a `ContextRuleManager` against testnet.
fn fresh_rule_manager() -> ContextRuleManager {
    ContextRuleManager::new(ContextRuleManagerConfig::new(
        TESTNET_RPC_URL.to_owned(),
        TESTNET_PASSPHRASE.to_owned(),
        Duration::from_secs(120),
        CHAIN_ID.to_owned(),
    ))
    .expect("ContextRuleManager construction must succeed")
}

/// Deploys a fresh smart account.  Returns the deployed C-strkey.
async fn deploy_fresh_smart_account(initial_signer_g: &str) -> String {
    let (deployer_g, deployer) = fresh_deployer_keypair();
    fund_via_friendbot(&deployer_g).await;

    let mut salt = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut OsRng, &mut salt);

    let args = DeploymentArgs {
        deployer,
        initial_signer: initial_signer_g.to_owned(),
        salt,
        network_passphrase: TESTNET_PASSPHRASE.to_owned(),
        rpc_url: TESTNET_RPC_URL.to_owned(),
        timeout: Duration::from_secs(120),
        fee: ResolvedFeePerOp {
            stroops: 1_000_000,
            percentile_label: "explicit".to_owned(),
        },
        dry_run: false,
        genesis_signer_scval_override: None,
    };
    deploy_smart_account(args, None)
        .await
        .expect("smart-account deployment must succeed on testnet")
        .smart_account
}

/// Deploys the OZ WebAuthn verifier WASM and writes the resulting C-strkey
/// to a temporary `VerifierRegistry`.  Returns the verifier C-strkey.
///
/// This helper is the single-deploy variant. Callers needing multiple distinct
/// verifier deploys on the same network should use
/// `stellar_agent_test_support::verifier_registry::fresh_verifier_registry_tempdir`
/// to derive per-deploy isolated registry paths.
async fn deploy_verifier_to_temp_registry(registry_path: &Path) -> String {
    let (deployer_g, deployer) = fresh_deployer_keypair();
    fund_via_friendbot(&deployer_g).await;

    use stellar_agent_smart_account::deployment::WebAuthnVerifierDeployArgs;

    let args = WebAuthnVerifierDeployArgs {
        deployer,
        network_passphrase: TESTNET_PASSPHRASE.to_owned(),
        rpc_url: TESTNET_RPC_URL.to_owned(),
        timeout: Duration::from_secs(120),
        fee: ResolvedFeePerOp {
            stroops: 1_000_000,
            percentile_label: "explicit".to_owned(),
        },
        dry_run: false,
        registry_path_override: Some(registry_path.to_path_buf()),
    };
    let result = deploy_webauthn_verifier(args, None)
        .await
        .expect("WebAuthn verifier deployment must succeed on testnet");

    // `deploy_webauthn_verifier` already records the deployed verifier into the
    // override registry and persists it (deploy_webauthn_verifier.rs step 13).
    // Re-open the persisted registry and verify the entry round-trips to the
    // returned address and the vendored WASM hash; recording again here would
    // return `AlreadyRecorded` by design, not `Recorded`.
    let registry =
        VerifierRegistry::open_at(registry_path.to_path_buf()).expect("registry open must succeed");
    let entry = registry
        .webauthn_verifier_for(TESTNET_PASSPHRASE)
        .expect("deploy must have persisted a verifier entry for testnet");
    assert_eq!(
        entry.address, result.verifier_address,
        "persisted verifier address must match the deployed address"
    );
    assert_eq!(
        entry.wasm_sha256, WEBAUTHN_VERIFIER_WASM_SHA256,
        "persisted verifier WASM hash must match the vendored hash"
    );

    result.verifier_address
}

// ─────────────────────────────────────────────────────────────────────────────
// RAII guards
// ─────────────────────────────────────────────────────────────────────────────

/// RAII guard that shuts down a `BridgeHandle` on drop.
///
/// # Drop behaviour
///
/// Uses `tokio::task::block_in_place` + `Handle::current().block_on(...)` to
/// drive the async `shutdown()` future from a sync `Drop` implementation.
/// `block_in_place` is permitted only on multi-thread runtimes; the enclosing
/// `#[tokio::test(flavor = "multi_thread", ...)]` attribute satisfies this
/// constraint (`block_on` inside a current_thread runtime panics).
///
/// On shutdown error (timeout / join failed) a diagnostic is printed to stderr;
/// the guard does not propagate the error — the OS reclaims the socket on
/// process exit.
struct BridgeGuard(Option<stellar_agent_webauthn_bridge::BridgeHandle>);

impl Drop for BridgeGuard {
    #[allow(
        clippy::print_stderr,
        reason = "diagnostic output in test RAII guard; non-fatal shutdown error"
    )]
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            // block_in_place: yield the current worker thread to the OS so the
            // blocking call cannot starve the rest of the multi-thread runtime.
            // Handle::current().block_on drives the future synchronously on the
            // thread that block_in_place hands us.
            let result = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(handle.shutdown())
            });
            if let Err(e) = result {
                // Non-fatal: the OS reclaims the socket on process exit.
                eprintln!("stellar-agent test: bridge shutdown error (non-fatal): {e}");
            }
        }
    }
}

/// RAII guard that kills a `chromiumoxide::Browser` subprocess on drop.
///
/// Prevents orphaned Chromium processes when the test panics between browser
/// launch and teardown.
///
/// # Drop behaviour
///
/// `Browser::kill()` is async.  The guard drives it synchronously via
/// `tokio::task::block_in_place` + `Handle::current().block_on(...)`.
/// `block_in_place` is permitted only on multi-thread runtimes; the enclosing
/// `#[tokio::test(flavor = "multi_thread", ...)]` satisfies this constraint
/// (`Handle::current().block_on(...)` panics inside a current_thread runtime
/// because the scheduler is already running on that thread).
///
/// The CDP handler task MUST be aborted before this guard drops to avoid a
/// race where the handler tries to send CDP commands to the killed process.
struct BrowserGuard(Option<Browser>);

impl BrowserGuard {
    /// Wraps `browser` in a `BrowserGuard`.
    fn new(browser: Browser) -> Self {
        Self(Some(browser))
    }
}

impl Drop for BrowserGuard {
    fn drop(&mut self) {
        if let Some(mut browser) = self.0.take() {
            // block_in_place: yield the current worker thread so the blocking
            // call does not starve the multi-thread runtime's other tasks.
            tokio::task::block_in_place(|| {
                // Best-effort kill; ignore the result — the OS reclaims on exit.
                let _ = tokio::runtime::Handle::current().block_on(browser.kill());
            });
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Browser launch helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Launches a headless Chromium browser for the WebAuthn ceremony.
///
/// The sandbox is disabled via the builder's `no_sandbox()` (which passes
/// `--no-sandbox` and `--disable-setuid-sandbox`): CI runners restrict the
/// unprivileged user namespaces Chromium's zygote sandbox needs, and with the
/// sandbox left on the launch aborts there with "No usable sandbox!" (SIGABRT).
/// The browser only ever navigates to the loopback bridge, so nothing untrusted
/// runs in the unsandboxed renderer. Custom flags must go through the builder's
/// typed methods or as dash-less `args` keys — chromiumoxide renders each arg
/// key as `--{key}`, so a dash-prefixed string produces a `----`-mangled flag
/// that Chromium silently ignores. The CDP virtual authenticator needs no
/// extra flags.
///
/// # No `--disable-web-security` or `--allow-insecure-localhost`
///
/// These flags MUST NOT be used:
///
/// - `--disable-web-security` disables Same-Origin-Policy and CORS enforcement,
///   which also suppresses WebAuthn origin checks.  A test that passes only with
///   SOP disabled does NOT exercise the user-facing surface.
/// - `--allow-insecure-localhost` is redundant when the bridge URL uses
///   `http://localhost:<port>` (not `http://127.0.0.1:<port>`): WebAuthn Level 2
///   §6.1 + W3C Secure Contexts §3.2 exempt `http://localhost` from the HTTPS
///   requirement; no flag-disablement is needed.
/// - The bridge URL is formatted as `http://localhost:<port>/...` (not
///   `http://127.0.0.1:<port>/...`) so the browser origin exactly matches the
///   RP-ID `"localhost"`, satisfying WebAuthn §5.1.2 without disabling security.
///
/// # Ephemeral user-data-dir hardening
///
/// `user_data_dir` is intentionally NOT set on `BrowserConfig`.  chromiumoxide
/// defaults to `std::env::temp_dir()/chromiumoxide-runner` — an ephemeral
/// path removed on process exit.  The Chromium virtual-authenticator writes
/// credentials to `<user-data-dir>/Default/Web Data` (SQLite); using a stable
/// dir would leak the private-key material across runs.
///
/// This function asserts `config.user_data_dir.is_none()` before launching so
/// that an accidental `.user_data_dir(...)` call on the builder panics at launch
/// time rather than silently writing credentials to a stable path.
async fn launch_chromium() -> (Browser, chromiumoxide::Handler) {
    // NOTE: --disable-web-security and --allow-insecure-localhost are
    // intentionally absent.  See the "No --disable-web-security" section above.
    let config = BrowserConfig::builder()
        .no_sandbox()
        .build()
        .expect("BrowserConfig must build");

    // Assert ephemeral user-data-dir: `None` means chromiumoxide picks
    // `std::env::temp_dir()/chromiumoxide-runner`, preventing credential leakage
    // across runs.
    assert!(
        config.user_data_dir.is_none(),
        "BrowserConfig.user_data_dir must be None (ephemeral); \
         a caller accidentally set user_data_dir() on the builder"
    );

    Browser::launch(config)
        .await
        .expect("Chromium must launch; ensure chromium/google-chrome is on PATH")
}

/// Error returned by [`goto_loopback`] when the target URL is rejected.
#[derive(Debug)]
enum GotoError {
    /// The URL failed to parse.
    Parse(url::ParseError),
    /// The URL has no host component.
    NoHost,
    /// The resolved host is not a loopback address.
    NonLoopbackHost { host: String },
    /// The scheme is not `http`.
    NonHttpScheme { scheme: String },
    /// The chromiumoxide navigation call returned an error.
    Navigation(chromiumoxide::error::CdpError),
}

impl std::fmt::Display for GotoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse(e) => write!(f, "URL parse error: {e}"),
            Self::NoHost => write!(f, "URL has no host component"),
            Self::NonLoopbackHost { host } => {
                write!(f, "goto_loopback rejects non-loopback host: {host:?}")
            }
            Self::NonHttpScheme { scheme } => {
                write!(f, "goto_loopback requires http scheme; got {scheme:?}")
            }
            Self::Navigation(e) => write!(f, "CDP navigation error: {e}"),
        }
    }
}

impl std::error::Error for GotoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Parse(e) => Some(e),
            Self::Navigation(e) => Some(e),
            Self::NoHost | Self::NonLoopbackHost { .. } | Self::NonHttpScheme { .. } => None,
        }
    }
}

/// Navigates `page` to `url`, asserting structural loopback enforcement.
///
/// # Loopback defence
///
/// This function MUST be used for all `page.goto()` calls in this test file.
/// Calling `page.goto()` directly bypasses the loopback enforcement.
///
/// # Why structural parsing
///
/// Prefix string matching is bypassable: `http://localhost:3000@evil.com/`
/// starts with `"http://localhost:"` but `url::Url::parse` resolves the host
/// to `evil.com` (the `localhost:3000` portion is consumed as `user:pass`
/// userinfo).  This function uses `url::Url::parse` and checks `host_str()`
/// to defend against userinfo-bypass, hostname-suffix attacks (e.g.
/// `http://127.0.0.1.evil.com/`), and HTTPS-localhost variants alike.
///
/// # Errors
///
/// Returns [`GotoError`] if:
/// - `url` does not parse as a valid URL,
/// - the scheme is not `http`,
/// - the host is absent or is not `"127.0.0.1"` / `"localhost"` / `"[::1]"`
///   (the `url` crate returns IPv6 `host_str()` values in bracketed form),
/// - the chromiumoxide navigation call fails.
async fn goto_loopback(page: &chromiumoxide::Page, url: &str) -> Result<(), GotoError> {
    let parsed = url::Url::parse(url).map_err(GotoError::Parse)?;

    // Require plain `http` — the bridge serves plaintext loopback only.
    if parsed.scheme() != "http" {
        return Err(GotoError::NonHttpScheme {
            scheme: parsed.scheme().to_owned(),
        });
    }

    let host = parsed.host_str().ok_or(GotoError::NoHost)?;
    if !is_loopback_http_url(url) {
        return Err(GotoError::NonLoopbackHost {
            host: host.to_owned(),
        });
    }

    page.goto(url).await.map_err(GotoError::Navigation)?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Main acceptance test
// ─────────────────────────────────────────────────────────────────────────────

/// WebAuthn passkey signing testnet acceptance.
///
/// Full register → install-rule → sign → verify chain against testnet with a
/// chromiumoxide-driven CDP virtual authenticator.
///
/// # Acceptance criteria
///
/// 1. The WebAuthn verifier WASM deploys successfully to testnet.
/// 2. A context rule with `External(verifier, pubkey_data)` can be
///    installed on-chain using the public key obtained from the registration
///    ceremony (no private-key material on the CDP wire).
/// 3. `CredentialsManager::sign_with_passkey_rule` returns
///    `SignWithPasskeyOutcome::Signed { .. }` when the virtual authenticator
///    completes the ceremony via the bridge's `/approve/<nonce>` page.
/// 4. The compact 64-byte `WebAuthnAssertion.signature_compact` field
///    is present and non-zero.
///
/// # Audit compliance
///
/// - Hardening: registration ceremony drives `navigator.credentials.create()`
///   via the bridge's `/register/<nonce>` page; the CDP `WebAuthn.addCredential`
///   command with a PKCS#8 private-key parameter is NOT used.
/// - Hardening: `BrowserConfig.user_data_dir` is `None` (asserted in
///   `launch_chromium()`).
/// - Hardening: `BrowserGuard::drop` kills the subprocess.
/// - Hardening: `goto_loopback` wraps all `page.goto()` calls.
///
/// `flavor = "multi_thread"` is required so that `tokio::task::block_in_place`
/// (used in `BridgeGuard::drop` and `BrowserGuard::drop`) is permitted.
/// On a `current_thread` runtime `block_in_place` panics with
/// "can call blocking only when running on the multi-threaded runtime".
/// Separately, `Handle::current().block_on(...)` inside a `current_thread`
/// runtime panics with "Cannot start a runtime from within a runtime".
/// Two worker threads: one for the test task, one free for the handler loop.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires testnet, chromium, and explicit --ignored flag"]
async fn webauthn_passkey_signing_testnet_acceptance() {
    // ── Temporary directories ─────────────────────────────────────────────────
    let tmp = TempDir::new().expect("tempdir must be created");
    let passkeys_dir = tmp.path().join("passkeys");
    let approvals_dir = tmp.path().join("approvals");
    let verifier_registry_path = tmp.path().join("networks.toml");
    std::fs::create_dir_all(&passkeys_dir).expect("passkeys dir must be created");
    std::fs::create_dir_all(&approvals_dir).expect("approvals dir must be created");

    // ── Deploy WebAuthn verifier WASM to testnet ──────────────────────────────
    let verifier_address = deploy_verifier_to_temp_registry(&verifier_registry_path).await;
    let verifier_sc_addr =
        parse_c_strkey_to_smart_account(&verifier_address).expect("verifier C-strkey must parse");

    // ── Deploy smart account ──────────────────────────────────────────────────
    let (signer_g, signer_box) = fresh_ed25519_signer();
    fund_via_friendbot(&signer_g).await;
    let smart_account_strkey = deploy_fresh_smart_account(&signer_g).await;
    let smart_account = parse_c_strkey_to_smart_account(&smart_account_strkey)
        .expect("deployed C-strkey must parse");

    // ── Start bridge ──────────────────────────────────────────────────────────
    let approval_path = approvals_dir.join("default.toml");
    let store = Arc::new(Mutex::new(
        PendingApprovalStore::open(approval_path).expect("approval store must open"),
    ));
    let bridge_bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    // This is a SIGNING-flow testnet acceptance test; it must wire
    // `PasskeysRegistryPubkeyLookup` so the `/approve/<nonce>/assertion`
    // handler can resolve the registered credential's SEC1 pubkey before running
    // `pre_verify_assertion`. Using `start_bridge_register_only` here would
    // silently 4xx every approval POST.
    let pubkey_lookup: std::sync::Arc<dyn stellar_agent_webauthn_bridge::ApprovalPubkeyLookup> =
        std::sync::Arc::new(
            stellar_agent_webauthn_bridge::PasskeysRegistryPubkeyLookup::new(
                passkeys_dir.clone(),
                "default",
                "localhost",
            ),
        );
    let bridge_handle = stellar_agent_webauthn_bridge::start_bridge_with_pubkey_lookup(
        Arc::clone(&store),
        bridge_bind,
        pubkey_lookup,
    )
    .await
    .expect("bridge must start");
    let bridge_addr = bridge_handle.local_addr();
    let _bridge_guard = BridgeGuard(Some(bridge_handle));

    // ── Launch Chromium browser ───────────────────────────────────────────────
    //
    // Wrapped in `BrowserGuard` for RAII subprocess kill on drop.
    // `launch_chromium()` asserts ephemeral `user_data_dir`.
    let (browser, mut handler) = launch_chromium().await;

    // Drive the CDP handler loop in a background task.
    let handler_task = tokio::spawn(async move {
        loop {
            if handler.next().await.is_none() {
                break;
            }
        }
    });

    // Wrap browser in RAII guard.
    let mut browser_guard = BrowserGuard::new(browser);

    // Open a new page.
    let page = browser_guard
        .0
        .as_mut()
        .expect("browser must be alive")
        .new_page("about:blank")
        .await
        .expect("new page must open");

    // ── Enable WebAuthn domain and add virtual authenticator ──────────────────
    //
    // The virtual authenticator generates its own P-256 keypair internally
    // during `navigator.credentials.create()`.  No private-key bytes cross the
    // CDP wire — this invariant is satisfied by construction.
    page.execute(EnableParams::default())
        .await
        .expect("WebAuthn domain must enable");

    let auth_options = VirtualAuthenticatorOptions::builder()
        .protocol(AuthenticatorProtocol::Ctap2)
        .transport(AuthenticatorTransport::Internal)
        .has_user_verification(true)
        .is_user_verified(true)
        .has_resident_key(false)
        .automatic_presence_simulation(true)
        .build()
        .expect("VirtualAuthenticatorOptions must build");

    page.execute(AddVirtualAuthenticatorParams::new(auth_options))
        .await
        .expect("addVirtualAuthenticator must succeed");

    // ── W-REG: Drive registration ceremony via bridge ─────────────────────────
    //
    // Navigate to `/register/<nonce>`.  The bridge HTML page's glue.js calls
    // `navigator.credentials.create()` with the RP-ID and user-handle from the
    // approval entry.  The virtual authenticator generates the P-256 keypair
    // internally and returns the attestation object to the page.  The page's
    // fetch POST to `/register/<nonce>/credential` delivers the credential ID
    // and uncompressed SEC1 public key to the bridge, which records them in the
    // approval store.  `poll_registration` then picks up the `RegistrationInput`
    // and writes `CredentialMetadata` to the passkeys registry.
    //
    // Private-key bytes NEVER cross the CDP wire.
    let creds_manager = CredentialsManager::new(
        passkeys_dir.clone(),
        "default",
        TEST_RP_ID,
        Some(Arc::clone(&store)),
    );

    // Prepare the registration entry and obtain the registration URL.
    let credential_name = "test-passkey-c10";
    let reg_handle = creds_manager
        .prepare_registration(credential_name, bridge_addr, None)
        .await
        .expect("prepare_registration must succeed");

    // Navigate to the registration URL (structural loopback check).
    goto_loopback(&page, &reg_handle.url)
        .await
        .expect("registration URL must be a loopback http URL");

    // Poll the store for the registration to complete.  The bridge POST handler
    // writes the RegistrationInput once the JS ceremony is done.
    //
    // Audit writer is provided so audit emission fires on every terminal outcome
    // (registered, timeout, user_canceled, entry_missing).
    let reg_deadline = Instant::now() + Duration::from_secs(60);
    let audit_log_path = tmp.path().join("audit").join("default.jsonl");
    let mut reg_audit = AuditWriter::open(audit_log_path.clone(), None)
        .expect("registration AuditWriter must open");

    let reg_outcome = creds_manager
        .poll_registration(
            credential_name,
            &reg_handle.nonce,
            reg_deadline,
            Some(&mut reg_audit),
        )
        .await
        .expect("poll_registration must not error");
    let metadata = match reg_outcome {
        AddPasskeyOutcome::Registered { metadata } => metadata,
        other => panic!("W-REG: expected Registered; got {other:?}"),
    };
    assert_eq!(
        metadata.rp_id, TEST_RP_ID,
        "registered credential rp_id must match TEST_RP_ID"
    );
    assert!(
        !metadata.credential_id_b64url.is_empty(),
        "credential_id_b64url must be non-empty after registration"
    );
    assert!(
        !metadata.public_key_sec1_b64.is_empty(),
        "public_key_sec1_b64 must be non-empty after registration"
    );

    // ── Install context rule with External passkey signer ─────────────────────
    //
    // pubkey_data = pubkey_65_bytes || credential_id_bytes.
    // Canonical per OpenZeppelin's `canonicalize_key` in the stellar-contracts
    // WebAuthn verifier.
    //
    // The public key was obtained from the registration ceremony (via the
    // RegistrationInput recorded by the bridge POST handler) — no PKCS#8 /
    // private key injection was used.
    let credential_id_bytes = URL_SAFE_NO_PAD
        .decode(&metadata.credential_id_b64url)
        .expect("credential_id_b64url must decode");
    let pubkey_bytes = URL_SAFE_NO_PAD
        .decode(&metadata.public_key_sec1_b64)
        .expect("public_key_sec1_b64 must decode");
    assert_eq!(
        pubkey_bytes.len(),
        65,
        "public key must be 65 bytes (SEC1 uncompressed P-256)"
    );
    assert_eq!(
        pubkey_bytes[0], 0x04,
        "public key must start with 0x04 (uncompressed marker)"
    );

    let mut pubkey_data = Vec::with_capacity(65 + credential_id_bytes.len());
    pubkey_data.extend_from_slice(&pubkey_bytes);
    pubkey_data.extend_from_slice(&credential_id_bytes);

    let rule_manager = fresh_rule_manager();
    let signer_addr =
        parse_g_strkey_to_signer_address(&signer_g).expect("signer G-strkey must parse");

    let definition = ContextRuleDefinition::new(
        RuleContext::Default,
        // OZ MAX_NAME_SIZE = 20 bytes.
        "c10-webauthn".to_owned(),
        None,
        vec![
            // Delegated fallback signer so the bootstrap rule can authorise.
            ContextRuleSignerInput::Delegated {
                address: signer_addr,
            },
            // External WebAuthn signer.
            ContextRuleSignerInput::External {
                verifier: verifier_sc_addr,
                pubkey_data: pubkey_data.clone(),
            },
        ],
        vec![],
    );

    let auth_rule_ids = vec![ContextRuleId::new(0)]; // bootstrap rule
    let webauthn_install_out = rule_manager
        .install_rule(
            smart_account.clone(),
            definition,
            auth_rule_ids,
            signer_box.as_ref(),
            None,
            rid(),
            false, // accept_mutable_verifier
            false, // accept_unknown_verifier
        )
        .await
        .expect("install_rule with External WebAuthn signer must succeed on testnet");
    let webauthn_rule_id = webauthn_install_out.rule_id;
    assert!(
        webauthn_rule_id != 0,
        "installed rule_id must differ from bootstrap rule; got {webauthn_rule_id}"
    );

    // ── Drive signing ceremony ────────────────────────────────────────────────
    //
    // Build a synthetic 32-byte auth digest for the test.  In production this
    // comes from `compute_auth_digest` (stellar-agent-core), but the signing
    // manager accepts any 32-byte value.
    let mut auth_digest = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut OsRng, &mut auth_digest);

    // Intercept the approval URL so we can navigate the browser to it.
    let (url_tx, url_rx) = tokio::sync::oneshot::channel::<String>();
    let url_tx = std::sync::Mutex::new(Some(url_tx));

    let signing_deadline = Duration::from_secs(60);

    // Spawn the signing poll loop in a background task.  The poll loop blocks
    // until the ceremony completes or the deadline elapses.
    //
    // `sign_with_passkey_rule` does not accept an `audit_writer` parameter;
    // PasskeyAssertion audit emission is sourced from the SignersManager's shared
    // Arc<Mutex<AuditWriter>>.  This test passes `None` for `signers_manager`
    // (divergence check skipped for the WebAuthn ceremony acceptance path; no
    // baseline established in this test).  No PasskeyAssertion audit row is
    // emitted when signers_manager is None.
    let signing_task = {
        let creds_manager = creds_manager.clone();
        let bridge_addr_clone = bridge_addr;
        // Clone the smart account strkey so it can be moved into the
        // `'static` async task closure.
        let smart_account_strkey_clone = smart_account_strkey.clone();
        tokio::spawn(async move {
            creds_manager
                .sign_with_passkey_rule(
                    credential_name,
                    // Supply real smart account so the audit trail is meaningful.
                    &smart_account_strkey_clone,
                    &auth_digest,
                    vec![webauthn_rule_id],
                    None, // test-only: divergence check skipped; no PasskeyAssertion emit
                    bridge_addr_clone,
                    signing_deadline,
                    move |url| {
                        if let Some(tx) = url_tx.lock().expect("mutex not poisoned").take() {
                            let _ = tx.send(url.to_owned());
                        }
                    },
                    true, // accept_single_verifier: bypass diversification (webauthn test; no baseline)
                )
                .await
        })
    };

    // Wait for the approval URL from the signing task.
    let approve_url = tokio::time::timeout(Duration::from_secs(10), url_rx)
        .await
        .expect("URL delivery must not time out")
        .expect("URL oneshot must not be dropped");

    // Navigate to the approval URL (structural loopback check).
    // The bridge's HTML + glue.js calls `startAuthentication()` and the
    // virtual authenticator completes the ceremony.
    goto_loopback(&page, &approve_url)
        .await
        .expect("approval URL must be a loopback http URL");

    // Wait for the signing task to complete (the bridge POST handler writes
    // the assertion to the store; the poll loop picks it up).
    let outcome = tokio::time::timeout(Duration::from_secs(60), signing_task)
        .await
        .expect("signing task must complete within 60 s")
        .expect("signing task must not panic");

    // ── Assertions ────────────────────────────────────────────────────────────

    // Outcome must be Signed.
    let (assertion, cred_metadata) = match outcome.expect("sign_with_passkey_rule must not error") {
        SignWithPasskeyOutcome::Signed {
            signature_bytes,
            credential_metadata,
        } => (signature_bytes, credential_metadata),
        other => panic!("expected Signed; got {other:?}"),
    };

    // Compact signature must be 64 bytes and non-zero.
    assert_eq!(
        assertion.signature_compact.len(),
        64,
        "compact signature must be 64 bytes"
    );
    assert!(
        assertion.signature_compact.iter().any(|&b| b != 0),
        "compact signature must not be all-zero"
    );
    assert_eq!(
        cred_metadata.credential_name, credential_name,
        "credential_name must round-trip"
    );
    assert_eq!(
        cred_metadata.rp_id, TEST_RP_ID,
        "credential rp_id must match TEST_RP_ID"
    );

    // ── Tear down ─────────────────────────────────────────────────────────────
    //
    // Abort the CDP handler task before dropping the browser to avoid a race
    // where the handler attempts to send CDP commands to the killed process.
    handler_task.abort();
    // Drop the BrowserGuard and BridgeGuard — RAII kills the browser and shuts
    // down the bridge via the current tokio runtime.
    drop(browser_guard);
    // `_bridge_guard` drops here as well.
}

// ─────────────────────────────────────────────────────────────────────────────
// goto_loopback unit tests
// ─────────────────────────────────────────────────────────────────────────────

/// Validates the `goto_loopback` structural URL-parsing logic in isolation.
///
/// These tests do NOT launch a browser.  They exercise the same parsing path
/// that `goto_loopback` uses: `url::Url::parse(url)?.host_str()`.
///
/// # Why structural parsing matters
///
/// Prefix string matching is bypassable via the URL userinfo separator `@`.
/// All tests here exercise the `url::Url::parse` + `host_str()` path used by
/// the production helper.
#[cfg(test)]
mod goto_loopback_tests {
    use stellar_agent_core::observability::is_loopback_http_url;

    /// Mirror of the acceptance logic: parse URL, check scheme, check host.
    fn check_loopback(url: &str) -> Result<(), String> {
        let parsed = url::Url::parse(url).map_err(|e| format!("parse: {e}"))?;
        if parsed.scheme() != "http" {
            return Err(format!("scheme must be http; got {:?}", parsed.scheme()));
        }
        let host = parsed.host_str().ok_or_else(|| "no host".to_owned())?;
        if is_loopback_http_url(url) {
            Ok(())
        } else {
            Err(format!("non-loopback host: {host:?}"))
        }
    }

    #[test]
    fn goto_loopback_rejects_external_url() {
        assert!(
            check_loopback("https://evil.example.com/steal").is_err(),
            "https external URL must be rejected"
        );
        assert!(
            check_loopback("http://attacker.example.com/").is_err(),
            "http external URL must be rejected"
        );
    }

    #[test]
    fn goto_loopback_accepts_127_0_0_1() {
        check_loopback("http://127.0.0.1:3000/register/nonce")
            .expect("127.0.0.1 URL must be accepted");
    }

    #[test]
    fn goto_loopback_accepts_localhost() {
        check_loopback("http://localhost:3000/approve/nonce")
            .expect("localhost URL must be accepted");
    }

    #[test]
    fn goto_loopback_accepts_ipv6_loopback() {
        check_loopback("http://[::1]:3000/approve/nonce")
            .expect("IPv6 loopback URL must be accepted");
    }

    #[test]
    fn goto_loopback_rejects_https_localhost() {
        // Only HTTP is accepted (bridge serves plaintext loopback only).
        assert!(
            check_loopback("https://localhost:3000/approve/nonce").is_err(),
            "https://localhost must be rejected (bridge is HTTP only)"
        );
    }

    /// Regression guard: `http://localhost:3000@evil.com/` starts with
    /// `"http://localhost:"` but `url::Url::parse` resolves host to `evil.com`
    /// (userinfo separator `@` consumes `localhost:3000` as `user:pass`).
    #[test]
    fn goto_loopback_rejects_userinfo_bypass_attack() {
        let url = "http://localhost:3000@evil.com/path";
        let err = check_loopback(url).expect_err("userinfo-bypass attack must be rejected");
        assert!(
            err.contains("evil.com"),
            "error must name the actual resolved host; got: {err}"
        );
    }

    /// `http://127.0.0.1.evil.com/` contains the loopback address as a
    /// prefix of the hostname — structural parsing correctly rejects it.
    #[test]
    fn goto_loopback_rejects_hostname_prefix_attack() {
        let err = check_loopback("http://127.0.0.1.evil.com/")
            .expect_err("hostname-suffix attack must be rejected");
        assert!(
            err.contains("127.0.0.1.evil.com"),
            "error must name the actual resolved host; got: {err}"
        );
    }

    /// `http://evil.com:3000@localhost/` — port-of-userinfo edge case.
    /// Structural parsing resolves host to `localhost` — this is actually
    /// accepted because the host IS localhost.  This tests that the userinfo
    /// field is stripped correctly (the authority is `evil.com:3000@localhost`,
    /// host is `localhost`).
    #[test]
    fn goto_loopback_accepts_localhost_when_userinfo_is_external() {
        // url::Url resolves authority `evil.com:3000@localhost` as
        // user=evil.com, password=3000, host=localhost.
        // The structural check passes because host IS "localhost".
        // This is the correct outcome: the *navigation destination* is localhost.
        check_loopback("http://evil.com:3000@localhost/").expect(
            "host=localhost with external userinfo must be accepted (destination is localhost)",
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BrowserGuard unit test
// ─────────────────────────────────────────────────────────────────────────────

/// Validates that a `None`-holding `BrowserGuard` drops without panicking.
///
/// A full fixture-leak test (verifying the Chromium process is killed) is
/// provided by the `#[ignore]` testnet acceptance test above, which launches a
/// real browser.  This unit test validates the struct layout and Drop behaviour
/// when the inner `Option` is `None`.
#[cfg(test)]
mod browser_guard_tests {
    use super::BrowserGuard;

    #[test]
    fn browser_guard_none_drops_cleanly() {
        let guard = BrowserGuard(None);
        drop(guard);
    }
}
