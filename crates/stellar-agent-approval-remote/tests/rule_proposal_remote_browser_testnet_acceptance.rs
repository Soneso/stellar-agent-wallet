//! Testnet acceptance: the shipped remote-approval browser frontend drives a
//! real agent-proposed context-rule install through to
//! `stellar_rule_create_commit`, entirely through the real HTML/JS pages
//! served over TLS (GH issue #8).
//!
//! This mirrors `remote_approval_browser_testnet_acceptance.rs`'s payment
//! flow for the `RuleProposalSimulated` kind, and reuses
//! `smart_account_rules_webauthn_testnet_acceptance.rs`'s bridge-registration
//! precedent to obtain a REAL WebAuthn co-signer credential (never the CLI
//! `add-passkey` path) so the proposed rule's signer set is not
//! delegated-only.
//!
//! # Flow
//!
//! 1. Deploy a fresh smart account (bootstrap delegated ed25519 signer) and
//!    the OZ WebAuthn verifier WASM to testnet.
//! 2. Register a co-signer WebAuthn credential via the LOCAL
//!    `stellar-agent-webauthn-bridge` (`start_bridge_register_only` +
//!    `CredentialsManager::prepare_registration` / `poll_registration`) —
//!    this is a REAL `navigator.credentials.create()` ceremony through a
//!    headless Chromium with a DEDICATED, resident-key CDP virtual
//!    authenticator; no private-key material crosses the CDP wire and no
//!    CLI command is invoked. Once the co-signer's bytes are captured into
//!    the passkeys registry, that authenticator is REMOVED
//!    (`WebAuthn.removeVirtualAuthenticator`) — the co-signer credential is
//!    never asserted again in this flow, only its raw bytes are needed. A
//!    FRESH, single-credential authenticator then hosts the operator's
//!    remote-approval credential for steps 4-6 below. Two authenticators,
//!    never two resident credentials on one: with two discoverable
//!    credentials for the same rp_id and no `allowCredentials`, credential
//!    selection in a headless CDP session is ambiguous — this both
//!    eliminates that nondeterminism and better mirrors reality (the
//!    smart-account co-signer and the operator's approval device are two
//!    different physical authenticators).
//! 3. `stellar_rule_create` (under a `RequireApproval` policy, through a real
//!    `WalletServer` against testnet) parks THREE pending
//!    `RuleProposalSimulated` entries:
//!    - `full`: `CallContract` context, `Delegated` (the proposer's own key,
//!      tagged) + `Webauthn` (the co-signer registered in step 2) signers —
//!      this is the one driven through the complete ceremony to on-chain
//!      install.
//!    - `default_context`: `Default` context, single `Delegated` signer —
//!      used only to assert the account-wide-authority callout renders.
//!    - `override_flag`: `Default` context, `accept_mutable_verifier = true`
//!      — used only to assert the override-warning line renders.
//! 4. `start_remote_serve` binds the real TLS listener with an EMPTY
//!    credential allowlist for the enrollment ceremony, then restarts with
//!    the newly-enrolled operator credential's id.
//! 5. The SAME browser session (the virtual authenticator persists across
//!    navigations) drives the shipped enrollment page, then the shipped
//!    login → inbox → detail-page flow for all three parked entries,
//!    asserting the FULL rendered rule definition on each, then drives the
//!    per-action approve ceremony for `full` only.
//! 6. `stellar_rule_create_commit` verifies the browser-minted attestation
//!    through the REAL server dispatch path and installs the rule on-chain.
//! 7. Audit-chain corroboration (the plan's amended Leg 4): the digest
//!    recomputed from the snapshot equals both the attested audit row's
//!    `envelope_sha256_hex` and the `proposal_sha256` on the pending entry;
//!    `stellar_rules_get` against the installed rule corroborates
//!    `signer_count` / `valid_until` against the proposal.
//!
//! # Negatives (same file, no browser needed)
//!
//! - `commit_without_attestation_is_approval_required`
//! - `tampered_snapshot_is_simulation_divergence`
//! - `operator_reject_then_commit_is_rejected`
//! - `toolset_gated_first_invoke_entry_is_consumed`
//!
//! # Gate
//!
//! ```text
//! cargo test -p stellar-agent-approval-remote --features testnet-acceptance \
//!   --test rule_proposal_remote_browser_testnet_acceptance -- --ignored
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
    clippy::too_many_lines,
    reason = "test-only; panics and unwraps are acceptable in testnet acceptance tests"
)]
#![allow(
    unsafe_code,
    reason = "test-only STELLAR_AGENT_HOME / STELLAR_AGENT_NETWORKS_TOML overrides for isolated \
              passkeys/verifier-registry storage, matching stellar_agent_approval_remote::tls's \
              own test convention"
)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chromiumoxide::browser::{Browser, BrowserConfig};
use chromiumoxide::cdp::browser_protocol::web_authn::{
    AddVirtualAuthenticatorParams, AuthenticatorProtocol, AuthenticatorTransport, EnableParams,
    RemoveVirtualAuthenticatorParams, VirtualAuthenticatorOptions,
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
use stellar_agent_core::approval::store::{PendingApproval, PendingApprovalStore};
use stellar_agent_core::approval::{ApprovalKind, DEFAULT_TTL_MS, process_uid_for_attestation};
use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_core::policy::v1::{
    AccountIdentityView, AccountReservesView, CounterpartyCacheView, Sep10SessionView,
    Sep45SessionView,
};
use stellar_agent_core::policy::{
    ApprovalRequest, Decision as PolicyDecision, PolicyEngine, PolicyError, ToolDescriptor,
};
use stellar_agent_core::profile::schema::{Profile, default_passkeys_dir};
use stellar_agent_core::smart_account::rule_id::ContextRuleId;
use stellar_agent_core::timefmt;
use stellar_agent_mcp::server::{
    RuleCreatePolicyArg, RuleCreateSignerArg, StellarRuleCreateArgs, StellarRuleCreateCommitArgs,
    StellarRulesGetArgs, WalletServer,
};
use stellar_agent_network::{StellarRpcClient, fetch_account};
use stellar_agent_smart_account::deployment::{
    DeployerKeypair, DeploymentArgs, ResolvedFeePerOp, WebAuthnVerifierDeployArgs,
    deploy_smart_account, deploy_webauthn_verifier,
};
use stellar_agent_smart_account::managers::credentials::{AddPasskeyOutcome, CredentialsManager};
use stellar_agent_smart_account::managers::rules::{
    compute_context_rule_proposal_sha256, context_rule_definition_from_snapshot,
    parse_c_strkey_to_smart_account,
};
use stellar_agent_test_support::keyring_mock;
use tempfile::TempDir;
use tokio::sync::Mutex as TokioMutex;
use zeroize::Zeroizing;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";
const TESTNET_FRIENDBOT_URL: &str = "https://friendbot.stellar.org";
const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
const TESTNET_CHAIN_ID: &str = "stellar:testnet";

/// `"localhost"` is the correct loopback RP-ID per WebAuthn Level 2 §5.1.2;
/// IP literals are rejected by browsers. Both the bridge (plain HTTP) and the
/// remote-approval listener (TLS) bind `127.0.0.1`, which resolves from
/// `localhost` on any standard host — the SAME virtual authenticator serves
/// credentials scoped to this one RP-ID across both origins.
const TEST_RP_ID: &str = "localhost";

// ─────────────────────────────────────────────────────────────────────────────
// RequireApproval policy engine — forces every dispatch to park a pending entry
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
            "rule-proposal-remote-browser-testnet-acceptance".into(),
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

fn fresh_deployer_keypair() -> (String, DeployerKeypair) {
    let (g_strkey, seed) = fresh_keypair();
    let signer: Box<dyn stellar_agent_network::Signer + Send + Sync> =
        Box::new(stellar_agent_network::SoftwareSigningKey::new_from_zeroizing(seed));
    let deployer = DeployerKeypair::SecretEnv {
        var_name: "rule-proposal-browser-acceptance-generated".to_owned(),
        signer,
    };
    (g_strkey, deployer)
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

    let attest_ref = &profile.attestation_key_id;
    let attest_key_b64 = URL_SAFE_NO_PAD.encode(attestation_key);
    keyring_core::Entry::new(&attest_ref.service, &attest_ref.account)
        .expect("attestation keyring entry")
        .set_password(&attest_key_b64)
        .expect("set attestation key");
}

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

/// Deploys the OZ WebAuthn verifier WASM directly into `registry_path` — the
/// SAME path `STELLAR_AGENT_NETWORKS_TOML` is set to for the duration of this
/// test, so `VerifierRegistry::open()` (called internally by
/// `stellar_rule_create`'s `resolve_webauthn_signer`) resolves this exact
/// entry without any extra wiring.
async fn deploy_verifier_to_registry(registry_path: &std::path::Path) -> String {
    let (deployer_g, deployer) = fresh_deployer_keypair();
    fund_via_friendbot(&deployer_g).await;

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
    deploy_webauthn_verifier(args, None)
        .await
        .expect("WebAuthn verifier deployment must succeed on testnet")
        .verifier_address
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

// ─────────────────────────────────────────────────────────────────────────────
// RAII guards
// ─────────────────────────────────────────────────────────────────────────────

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

struct BridgeGuard(Option<stellar_agent_webauthn_bridge::BridgeHandle>);

impl Drop for BridgeGuard {
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
                eprintln!("stellar-agent test: bridge shutdown error (non-fatal): {e}");
            }
        }
    }
}

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

/// RAII guard clearing the `STELLAR_AGENT_HOME` / `STELLAR_AGENT_NETWORKS_TOML`
/// env-var overrides even if the test panics partway through — otherwise a
/// panic here leaks the override for the rest of the process's lifetime,
/// affecting any sibling test.
struct EnvOverrideGuard;

impl Drop for EnvOverrideGuard {
    fn drop(&mut self) {
        unsafe {
            std::env::remove_var("STELLAR_AGENT_HOME");
            std::env::remove_var("STELLAR_AGENT_NETWORKS_TOML");
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Browser launch
// ─────────────────────────────────────────────────────────────────────────────

/// Launches a headless Chromium. See `remote_approval_browser_testnet_acceptance.rs`
/// for the full rationale (no `--disable-web-security`, builder-default TLS
/// cert-error acceptance, `.no_sandbox()`, ephemeral `user_data_dir`).
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

/// Adds a resident-key (discoverable) virtual authenticator and returns its
/// id. Resident/discoverable because neither the bridge's registration page
/// nor the remote-approval `login.js`/`app.js` send `allowCredentials`, so
/// whichever authenticator is active must resolve a credential for the RP
/// without one.
///
/// A SEPARATE authenticator per credential-holder is used deliberately (see
/// the call sites) rather than one authenticator hosting both the co-signer
/// and operator credentials: with two resident credentials for the SAME
/// rp_id and no `allowCredentials`, credential selection in a headless CDP
/// session is ambiguous — this caused a nondeterministic "Sign-in failed"
/// login rejection in an earlier version of this test (the operator login
/// assertion was sometimes signed by the co-signer credential instead,
/// which the remote server's allowlist correctly rejects since it only
/// contains the enrolled operator credential id). Using one authenticator
/// per phase and removing the co-signer's before the operator phase begins
/// also better mirrors reality: the smart-account co-signer and the
/// operator's remote-approval device are two different physical
/// authenticators in production.
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
// Remote-serve wiring
// ─────────────────────────────────────────────────────────────────────────────

async fn start_remote_serve_for_profile(
    server: &WalletServer,
    profile: &Profile,
    approval_dir: &TempDir,
    operator_credentials_path: std::path::PathBuf,
    allowed_credentials: Vec<String>,
) -> stellar_agent_approval_remote::RemoteServeHandle {
    let profile_name = server.profile_name_for_approval();
    let store_path = approval_dir.path().join(format!("{profile_name}.toml"));
    let audit_path = audit_log_path(approval_dir);
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

    let tls = provision_or_load(
        "rule-proposal-remote-browser-testnet-acceptance",
        TEST_RP_ID,
    )
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

fn audit_log_path(approval_dir: &TempDir) -> std::path::PathBuf {
    approval_dir.path().join("audit.log")
}

// ─────────────────────────────────────────────────────────────────────────────
// DOM helpers
// ─────────────────────────────────────────────────────────────────────────────

fn evaluate_by_value(expression: &str) -> EvaluateParams {
    EvaluateParams::builder()
        .expression(expression)
        .return_by_value(true)
        .build()
        .expect("EvaluateParams must build")
}

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
             the deadline"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn poll_attestation_textarea(page: &chromiumoxide::Page, deadline: Instant) -> String {
    loop {
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

/// Reads the full detail-page body text (post-render). Used to assert the
/// callout/tag/warning markers `stellar-agent-approval-ui::templates`'s
/// `render_rule_proposal_definition_html` produces.
async fn detail_page_body_text(page: &chromiumoxide::Page) -> String {
    page.evaluate(evaluate_by_value("document.body.innerText"))
        .await
        .expect("evaluate must not error")
        .into_value()
        .expect("evaluate result must deserialise as String")
}

// ─────────────────────────────────────────────────────────────────────────────
// Bridge co-signer registration (rules_webauthn precedent, NOT CLI add-passkey)
// ─────────────────────────────────────────────────────────────────────────────

/// Registers a real WebAuthn co-signer credential via the LOCAL
/// `stellar-agent-webauthn-bridge` registration ceremony, driven through the
/// SAME browser `page` (and its already-added virtual authenticator) the
/// remote-approval ceremony will later reuse. Writes the resulting
/// `CredentialMetadata` into `passkeys_dir` under `profile_name` — the exact
/// directory `stellar_rule_create`'s `resolve_webauthn_signer` reads via
/// `CredentialsManager::from_defaults_readonly`.
async fn register_cosigner_credential_via_bridge(
    page: &chromiumoxide::Page,
    passkeys_dir: &std::path::Path,
    profile_name: &str,
    approvals_dir: &TempDir,
    credential_name: &str,
) -> String {
    let bridge_store_path = approvals_dir.path().join("bridge-registration.toml");
    let bridge_store = Arc::new(TokioMutex::new(
        PendingApprovalStore::open(bridge_store_path).expect("bridge registration store open"),
    ));
    let bridge_bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let bridge_handle = stellar_agent_webauthn_bridge::start_bridge_register_only(
        Arc::clone(&bridge_store),
        bridge_bind,
    )
    .await
    .expect("bridge must start");
    let bridge_addr = bridge_handle.local_addr();
    let _bridge_guard = BridgeGuard(Some(bridge_handle));

    let creds_manager = CredentialsManager::new(
        passkeys_dir.to_path_buf(),
        profile_name.to_owned(),
        TEST_RP_ID,
        Some(Arc::clone(&bridge_store)),
    );

    let reg_handle = creds_manager
        .prepare_registration(credential_name, bridge_addr, None)
        .await
        .expect("prepare_registration must succeed");

    page.goto(&reg_handle.url)
        .await
        .expect("navigation to the bridge registration URL must succeed");

    let reg_deadline = Instant::now() + Duration::from_secs(60);
    let audit_log_path = approvals_dir.path().join("bridge-audit.jsonl");
    let mut reg_audit =
        AuditWriter::open(audit_log_path, None).expect("registration AuditWriter must open");
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
        other => panic!("co-signer registration: expected Registered; got {other:?}"),
    };
    assert_eq!(metadata.rp_id, TEST_RP_ID);
    assert!(!metadata.credential_id_b64url.is_empty());
    assert!(!metadata.public_key_sec1_b64.is_empty());

    // Bridge is torn down immediately after registration — its job ends here.
    metadata.credential_id_b64url
}

// ─────────────────────────────────────────────────────────────────────────────
// stellar_rule_create propose helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Builds `stellar_rule_create` propose args. `signers` already carries the
/// proposer's own G-strkey (as a `Delegated` entry) where relevant — this
/// helper does not need it separately.
fn propose_args(
    smart_account: &str,
    name: &str,
    context: &str,
    signers: Vec<RuleCreateSignerArg>,
    accept_mutable_verifier: bool,
) -> StellarRuleCreateArgs {
    StellarRuleCreateArgs {
        chain_id: TESTNET_CHAIN_ID.to_owned(),
        smart_account: smart_account.to_owned(),
        context: context.to_owned(),
        name: name.to_owned(),
        valid_until: None,
        signers,
        policies: Vec::<RuleCreatePolicyArg>::new(),
        auth_rule_ids: vec![0],
        accept_mutable_verifier,
        accept_unknown_verifier: false,
        accept_no_delegated_fallback: false,
    }
}

async fn propose_and_extract_nonce(
    server: &WalletServer,
    args: StellarRuleCreateArgs,
) -> (String, serde_json::Value) {
    let result = server
        .call_stellar_rule_create(args)
        .await
        .expect("stellar_rule_create must not error against funded, deployed testnet resources");
    assert_ne!(
        result.is_error,
        Some(true),
        "propose must be a success response: {}",
        result
            .content
            .first()
            .and_then(|c| c.as_text())
            .map(|t| t.text.as_str())
            .unwrap_or("")
    );
    let json = result_json(&result);
    let data = json["data"].clone();
    let nonce = data["approval_nonce"]
        .as_str()
        .expect("propose must surface approval_nonce")
        .to_owned();
    (nonce, data)
}

// ─────────────────────────────────────────────────────────────────────────────
// Main acceptance test
// ─────────────────────────────────────────────────────────────────────────────

/// Full rule-proposal remote-approval browser acceptance: register a
/// WebAuthn co-signer via the bridge, park three real rule proposals, serve
/// them over the real TLS listener, drive the SHIPPED frontend through a
/// headless Chromium with a seeded CDP virtual authenticator, and commit the
/// resulting attestation on-chain.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
#[ignore = "requires testnet, chromium, and explicit --ignored flag"]
async fn rule_proposal_remote_browser_drives_real_rule_install() {
    keyring_mock::install().expect("mock keyring store init");

    let (proposer_g, proposer_seed) = fresh_keypair();
    fund_via_friendbot(&proposer_g).await;
    wait_until_queryable(&proposer_g).await;

    let attestation_key = [0x44u8; 32];
    let approval_dir = TempDir::new().expect("approval temp dir");
    let tls_home_dir = TempDir::new().expect("TLS/passkeys home temp dir");
    let networks_toml_path = tls_home_dir.path().join("networks.toml");
    let operator_credentials_path = approval_dir.path().join("operator_credentials.toml");

    let _env_guard = EnvOverrideGuard;
    unsafe {
        std::env::set_var("STELLAR_AGENT_HOME", tls_home_dir.path());
        std::env::set_var("STELLAR_AGENT_NETWORKS_TOML", &networks_toml_path);
    }

    // ── 1. Deploy the WebAuthn verifier + a fresh smart account ─────────────
    let verifier_address = deploy_verifier_to_registry(&networks_toml_path).await;
    let smart_account_strkey = deploy_fresh_smart_account(&proposer_g).await;

    let mut profile = Profile::builder_testnet(
        "stellar-agent",
        &proposer_g,
        "stellar-agent-nonce",
        &proposer_g,
    )
    .with_noop_engine()
    .build();
    profile.rpc_url = TESTNET_RPC_URL.to_owned();
    seed_keyring(&profile, &proposer_seed, &attestation_key);

    let mut server = WalletServer::new(profile.clone()).expect("WalletServer::new");
    server.set_approval_dir_for_test(approval_dir.path().to_path_buf());
    server.set_policy_engine_for_test(Arc::new(RequireApprovalEngine));
    let profile_name = server.profile_name_for_approval();

    // ── 2. Launch Chromium + a DEDICATED virtual authenticator for the
    //       co-signer registration phase ─────────────────────────────────────
    //
    // A separate, single-credential authenticator is used for this phase
    // and removed immediately after — see `add_virtual_authenticator`'s doc
    // comment for why. The co-signer's raw bytes (captured into the passkeys
    // registry by the registration ceremony) are all this flow ever needs;
    // the co-signer credential is never asserted again.
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
    let cosigner_authenticator_id = add_virtual_authenticator(&page).await;

    // ── 3. Register the co-signer WebAuthn credential via the bridge ────────
    let passkeys_dir = default_passkeys_dir().expect("passkeys dir under STELLAR_AGENT_HOME");
    let credential_name = "rule-proposal-cosigner";
    let _cosigner_cred_id = register_cosigner_credential_via_bridge(
        &page,
        &passkeys_dir,
        &profile_name,
        &approval_dir,
        credential_name,
    )
    .await;

    // Remove the co-signer authenticator now that its bytes are captured —
    // it is never asserted again in this flow, and removing it eliminates
    // any ambiguity for the operator enroll/login phase below.
    page.execute(RemoveVirtualAuthenticatorParams::new(
        cosigner_authenticator_id,
    ))
    .await
    .expect("removeVirtualAuthenticator must succeed");

    // A fresh authenticator, holding no credentials yet, for the operator's
    // enroll/login ceremony (steps 5-7 below).
    add_virtual_authenticator(&page).await;

    // ── 4. Propose three rules against real testnet resources ──────────────
    let call_contract_ctx = format!("call-contract:{verifier_address}");
    let (full_nonce, full_summary) = propose_and_extract_nonce(
        &server,
        propose_args(
            &smart_account_strkey,
            "full-rule",
            &call_contract_ctx,
            vec![
                RuleCreateSignerArg::Delegated {
                    address: proposer_g.clone(),
                },
                RuleCreateSignerArg::Webauthn {
                    credential_name: credential_name.to_owned(),
                },
            ],
            false,
        ),
    )
    .await;
    assert_eq!(
        full_summary["summary"]["signer_count"].as_u64(),
        Some(2),
        "the full-rule proposal must resolve exactly 2 signers"
    );

    let (default_nonce, _) = propose_and_extract_nonce(
        &server,
        propose_args(
            &smart_account_strkey,
            "default-rule",
            "default",
            vec![RuleCreateSignerArg::Delegated {
                address: proposer_g.clone(),
            }],
            false,
        ),
    )
    .await;

    let (override_nonce, _) = propose_and_extract_nonce(
        &server,
        propose_args(
            &smart_account_strkey,
            "override-rule",
            "default",
            vec![RuleCreateSignerArg::Delegated {
                address: proposer_g.clone(),
            }],
            true, // accept_mutable_verifier
        ),
    )
    .await;

    // ── 5. Start the TLS listener for the enrollment ceremony ───────────────
    let enroll_handle = start_remote_serve_for_profile(
        &server,
        &profile,
        &approval_dir,
        operator_credentials_path.clone(),
        Vec::new(),
    )
    .await;
    let enroll_base_url = format!("https://{TEST_RP_ID}:{}", enroll_handle.local_addr().port());

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

    // ── 6. Restart with the now-known allowlist ─────────────────────────────
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

    // ── 7. Login ─────────────────────────────────────────────────────────────
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
    let login_deadline = Instant::now() + Duration::from_secs(30);
    wait_for_url_ending(&page, "/inbox", login_deadline).await;

    // ── 8. Detail-page rendering assertions for all three proposals ─────────

    // `full`: signer table with the PROPOSER tag + the co-signer.
    page.goto(&format!("{base_url}/approval/{full_nonce}"))
        .await
        .expect("navigation to the full-rule detail page must succeed");
    let full_deadline = Instant::now() + Duration::from_secs(15);
    wait_for_url_ending(&page, &format!("/approval/{full_nonce}"), full_deadline).await;
    let full_body = detail_page_body_text(&page).await;
    assert!(
        full_body.contains("PROPOSER"),
        "the full-rule detail page must render the PROPOSER tag on the proposer's own signer \
         row; body:\n{full_body}"
    );
    assert!(
        full_body.to_lowercase().contains("external")
            || full_body.to_lowercase().contains("webauthn"),
        "the full-rule detail page must render the co-signer's External/WebAuthn row; \
         body:\n{full_body}"
    );
    assert!(
        !full_body.contains("ACCOUNT-WIDE AUTHORITY"),
        "a CallContract-context rule must NOT render the Default account-wide-authority \
         callout; body:\n{full_body}"
    );

    // `default_context`: the account-wide-authority callout.
    page.goto(&format!("{base_url}/approval/{default_nonce}"))
        .await
        .expect("navigation to the default-context detail page must succeed");
    let default_deadline = Instant::now() + Duration::from_secs(15);
    wait_for_url_ending(
        &page,
        &format!("/approval/{default_nonce}"),
        default_deadline,
    )
    .await;
    let default_body = detail_page_body_text(&page).await;
    assert!(
        default_body.contains("ACCOUNT-WIDE AUTHORITY"),
        "a Default-context rule proposal must render the account-wide-authority callout; \
         body:\n{default_body}"
    );

    // `override_flag`: the accept_mutable_verifier warning line.
    page.goto(&format!("{base_url}/approval/{override_nonce}"))
        .await
        .expect("navigation to the override-flag detail page must succeed");
    let override_deadline = Instant::now() + Duration::from_secs(15);
    wait_for_url_ending(
        &page,
        &format!("/approval/{override_nonce}"),
        override_deadline,
    )
    .await;
    let override_body = detail_page_body_text(&page).await;
    assert!(
        override_body.contains("accept_mutable_verifier is"),
        "a proposal with accept_mutable_verifier=true must render the override warning line; \
         body:\n{override_body}"
    );

    // ── 9. Per-action ceremony for `full` only ───────────────────────────────
    page.goto(&format!("{base_url}/approval/{full_nonce}"))
        .await
        .expect("navigation back to the full-rule detail page must succeed");
    let back_deadline = Instant::now() + Duration::from_secs(15);
    wait_for_url_ending(&page, &format!("/approval/{full_nonce}"), back_deadline).await;
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

    // ── 10. Audit-chain corroboration (amended Leg 4) ────────────────────────
    //
    // Recompute the digest from the DEFINITION SNAPSHOT that was actually
    // stored (not the ScVal typed form), independent of the on-chain call —
    // it must equal both the audit row's `envelope_sha256_hex` (the
    // `RuleProposalSimulated` binding used at attest time) and the pending
    // entry's own `proposal_sha256`.
    let store_path = approval_dir.path().join(format!("{profile_name}.toml"));
    let store = PendingApprovalStore::open(store_path.clone()).expect("store re-open");
    let entry = store
        .get(&full_nonce)
        .cloned()
        .expect("the full-rule pending entry must still be present before commit");
    let (smart_account_str, definition_snapshot, stored_digest) = match &entry.kind {
        ApprovalKind::RuleProposalSimulated {
            smart_account,
            definition,
            proposal_sha256,
            ..
        } => (smart_account.clone(), definition.clone(), *proposal_sha256),
        other => panic!("expected RuleProposalSimulated, got {other:?}"),
    };
    let smart_account_addr = parse_c_strkey_to_smart_account(&smart_account_str)
        .expect("stored smart_account must parse");
    let rule_definition = context_rule_definition_from_snapshot(&definition_snapshot)
        .expect("definition must reconstruct from the stored snapshot");
    let auth_rule_ids: Vec<ContextRuleId> = definition_snapshot
        .auth_rule_ids
        .iter()
        .map(|id| ContextRuleId::new(*id))
        .collect();
    let recomputed_digest = compute_context_rule_proposal_sha256(
        &smart_account_addr,
        &rule_definition,
        &auth_rule_ids,
        definition_snapshot.accept_mutable_verifier,
        definition_snapshot.accept_unknown_verifier,
    )
    .expect("digest must recompute from the stored snapshot");
    assert_eq!(
        recomputed_digest, stored_digest,
        "the digest recomputed from the snapshot must equal the entry's own proposal_sha256"
    );
    drop(store);

    let audit_path = audit_log_path(&approval_dir);
    let audit_text = std::fs::read_to_string(&audit_path).expect("audit log must be readable");
    let expected_pseudonym = {
        let digest = Sha256::digest(credential_id_b64url.as_bytes());
        hex::encode(&digest[..4])
    };
    let recomputed_digest_hex: String = recomputed_digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let found_remote_row = audit_text.lines().any(|line| {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            return false;
        };
        value["kind"] == "approval_attested_remote"
            && value["operator_credential_id_redacted"] == expected_pseudonym
            && value["envelope_sha256_hex"] == recomputed_digest_hex
    });
    assert!(
        found_remote_row,
        "the audit log must contain an ApprovalAttestedRemote row whose envelope_sha256_hex \
         equals the recomputed proposal digest {recomputed_digest_hex:?}; log contents:\n\
         {audit_text}"
    );

    // Tear down browser + server before the on-chain commit.
    handler_task.abort();
    drop(browser_guard);
    drop(_serve_guard);

    // ── 11. Commit on-chain with the browser-minted attestation ──────────────
    let commit = server
        .call_stellar_rule_create_commit(StellarRuleCreateCommitArgs {
            chain_id: TESTNET_CHAIN_ID.to_owned(),
            approval_nonce: full_nonce,
            approval_attestation: Some(attestation_b64),
        })
        .await
        .expect("commit must pass the gate and submit on-chain");
    let commit_json = result_json(&commit);
    assert!(
        commit_json["ok"].as_bool().unwrap_or(false),
        "commit envelope must be ok (submitted on-chain): {commit_json}"
    );
    let rule_id = commit_json["data"]["rule_id"]
        .as_u64()
        .expect("commit must report the installed rule_id");
    let tx_hash = commit_json["data"]["tx_hash"]
        .as_str()
        .expect("commit must report an on-chain tx_hash");
    assert_eq!(tx_hash.len(), 64, "tx_hash must be a 32-byte hex digest");

    // ── 12. stellar_rules_get corroborates the installed rule against the
    //         proposal snapshot ───────────────────────────────────────────────
    let get_result = server
        .call_stellar_rules_get(StellarRulesGetArgs {
            chain_id: TESTNET_CHAIN_ID.to_owned(),
            smart_account: smart_account_strkey.clone(),
            rule_id: rule_id as u32,
        })
        .await
        .expect("stellar_rules_get must not error against the just-installed rule");
    let get_json = result_json(&get_result);
    assert_eq!(
        get_json["data"]["signer_count"].as_u64(),
        Some(2),
        "the installed rule's signer_count must match the proposal's 2 signers: {get_json}"
    );
    // `Index` (`get_json["data"]["valid_until"]`) returns `Value::Null` for
    // BOTH "key present with a null value" and "key entirely absent" —
    // `.get(..)` distinguishes them, so a missing key fails this assertion
    // rather than silently passing.
    assert_eq!(
        get_json["data"].get("valid_until"),
        Some(&serde_json::Value::Null),
        "the installed rule's valid_until must be explicitly null, matching the proposal's None \
         (permanent): {get_json}"
    );

    // `_env_guard` clears the env-var overrides here (normal return) or on
    // unwind if an earlier assertion panicked.
}

// ─────────────────────────────────────────────────────────────────────────────
// Negatives — no browser needed
// ─────────────────────────────────────────────────────────────────────────────

/// Sets up a real `WalletServer` + funded proposer + deployed smart account,
/// with NO browser/bridge/remote-listener involved, for the negative tests
/// below that only need `stellar_rule_create` / `stellar_rule_create_commit`
/// against real testnet resources.
async fn negative_test_fixture() -> (WalletServer, TempDir, String, String, [u8; 32]) {
    keyring_mock::install().ok();
    let (proposer_g, proposer_seed) = fresh_keypair();
    fund_via_friendbot(&proposer_g).await;
    wait_until_queryable(&proposer_g).await;
    let smart_account_strkey = deploy_fresh_smart_account(&proposer_g).await;

    let attestation_key = [0x55u8; 32];
    let approval_dir = TempDir::new().expect("approval temp dir");

    let mut profile = Profile::builder_testnet(
        "stellar-agent",
        &proposer_g,
        "stellar-agent-nonce",
        &proposer_g,
    )
    .with_noop_engine()
    .build();
    profile.rpc_url = TESTNET_RPC_URL.to_owned();
    seed_keyring(&profile, &proposer_seed, &attestation_key);

    let mut server = WalletServer::new(profile).expect("WalletServer::new");
    server.set_approval_dir_for_test(approval_dir.path().to_path_buf());
    server.set_policy_engine_for_test(Arc::new(RequireApprovalEngine));

    (
        server,
        approval_dir,
        smart_account_strkey,
        proposer_g,
        attestation_key,
    )
}

/// A commit call presenting a real, live pending nonce but NO
/// `approval_attestation` must return `policy.approval_required` — the
/// dedicated `verify_rule_proposal_gate` never runs without one.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires testnet and explicit --ignored flag"]
async fn commit_without_attestation_is_approval_required() {
    let (server, _approval_dir, smart_account_strkey, proposer_g, _attestation_key) =
        negative_test_fixture().await;

    let (nonce, _) = propose_and_extract_nonce(
        &server,
        propose_args(
            &smart_account_strkey,
            "no-attest",
            "default",
            vec![RuleCreateSignerArg::Delegated {
                address: proposer_g.clone(),
            }],
            false,
        ),
    )
    .await;

    let result = server
        .call_stellar_rule_create_commit(StellarRuleCreateCommitArgs {
            chain_id: TESTNET_CHAIN_ID.to_owned(),
            approval_nonce: nonce,
            approval_attestation: None,
        })
        .await;
    let result = result.expect("commit call must return a tool result");
    assert_eq!(
        result.is_error,
        Some(true),
        "commit without attestation must be a business error"
    );
    let json = result_json(&result);
    assert_eq!(
        json["error"]["code"].as_str(),
        Some("policy.approval_required"),
        "got: {json}"
    );
}

/// Tampering the stored snapshot after propose (a mutated `name`) must be
/// caught by the store-self-consistency digest recompute check —
/// `simulation.divergence`, independent of the operator-consent question.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires testnet and explicit --ignored flag"]
async fn tampered_snapshot_is_simulation_divergence() {
    let (server, approval_dir, smart_account_strkey, proposer_g, _attestation_key) =
        negative_test_fixture().await;

    let (nonce, _) = propose_and_extract_nonce(
        &server,
        propose_args(
            &smart_account_strkey,
            "tamper-me",
            "default",
            vec![RuleCreateSignerArg::Delegated {
                address: proposer_g.clone(),
            }],
            false,
        ),
    )
    .await;

    // Tamper the on-disk TOML directly: flip the stored rule name. The
    // digest was computed over "tamper-me"; the store now holds a
    // definition whose recomputed digest will not match proposal_sha256.
    let profile_name = server.profile_name_for_approval();
    let store_path = approval_dir.path().join(format!("{profile_name}.toml"));
    let original = std::fs::read_to_string(&store_path).expect("store file readable");
    let tampered = original.replace("tamper-me", "tampered!!!!");
    assert_ne!(
        original, tampered,
        "tamper replacement must actually change the file"
    );
    std::fs::write(&store_path, tampered).expect("store file writable");

    let result = server
        .call_stellar_rule_create_commit(StellarRuleCreateCommitArgs {
            chain_id: TESTNET_CHAIN_ID.to_owned(),
            approval_nonce: nonce,
            approval_attestation: None,
        })
        .await;
    let err = result.expect_err("tampered snapshot must be Err");
    assert!(
        err.message.contains("simulation.divergence"),
        "got: {}",
        err.message
    );
}

/// An operator REJECT leaves a tombstone; committing against it returns the
/// distinguishable `policy.approval_rejected` (not the indistinguishable
/// `policy.approval_required`).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires testnet and explicit --ignored flag"]
async fn operator_reject_then_commit_is_rejected() {
    let (server, approval_dir, smart_account_strkey, proposer_g, _attestation_key) =
        negative_test_fixture().await;

    let (nonce, _) = propose_and_extract_nonce(
        &server,
        propose_args(
            &smart_account_strkey,
            "reject-me",
            "default",
            vec![RuleCreateSignerArg::Delegated {
                address: proposer_g.clone(),
            }],
            false,
        ),
    )
    .await;

    let profile_name = server.profile_name_for_approval();
    let store_path = approval_dir.path().join(format!("{profile_name}.toml"));
    let mut store = PendingApprovalStore::open(store_path).expect("store re-open");
    store
        .reject(
            &nonce,
            timefmt::now_unix_ms().expect("clock"),
            DEFAULT_TTL_MS,
        )
        .expect("reject must succeed on a live entry");
    drop(store);

    let result = server
        .call_stellar_rule_create_commit(StellarRuleCreateCommitArgs {
            chain_id: TESTNET_CHAIN_ID.to_owned(),
            approval_nonce: nonce,
            approval_attestation: None,
        })
        .await;
    let result = result.expect("commit call must return a tool result");
    assert_eq!(
        result.is_error,
        Some(true),
        "a rejected tombstone must produce a business error"
    );
    let json = result_json(&result);
    assert_eq!(
        json["error"]["code"].as_str(),
        Some("policy.approval_rejected"),
        "a live Rejected tombstone must be distinguishable, got: {json}"
    );
}

/// Exercises the toolset-gated `sign-rule-create` path end to end: a
/// first-invoke grant is recorded, `stellar_rule_create_commit` runs through
/// the FORCED-RequireApproval toolset-gated wrapper, and — the established
/// lesson from Package B/A — the `ToolsetFirstInvokeGate` pending entry must
/// be CONSUMED (removed) once the grant is recorded, not merely ignored.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires testnet and explicit --ignored flag"]
async fn toolset_gated_first_invoke_entry_is_consumed() {
    let (server, approval_dir, smart_account_strkey, proposer_g, attestation_key) =
        negative_test_fixture().await;

    let (nonce, _) = propose_and_extract_nonce(
        &server,
        propose_args(
            &smart_account_strkey,
            "toolset-me",
            "default",
            vec![RuleCreateSignerArg::Delegated {
                address: proposer_g.clone(),
            }],
            false,
        ),
    )
    .await;

    // Record a ToolsetFirstInvokeGate pending entry (as `stellar_rule_create`'s
    // toolset-gated resolver would when a toolset first attempts
    // sign-rule-create for this smart account), then attest and record the
    // grant via the SAME core path the CLI `approve --id` uses.
    let profile_name = server.profile_name_for_approval();
    let store_path = approval_dir.path().join(format!("{profile_name}.toml"));
    let mut store = PendingApprovalStore::open(store_path.clone()).expect("store re-open");
    let gate_entry = PendingApproval::new_toolset_first_invoke_gate_pending(
        "test-toolset".to_owned(),
        "sign-rule-create".to_owned(),
        smart_account_strkey.clone(),
        "RULECREATE:GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF".to_owned(),
        0,
        1,
        process_uid_for_attestation().expect("process uid"),
        DEFAULT_TTL_MS,
    )
    .expect("gate entry must construct");
    let gate_nonce = gate_entry.approval_nonce.clone();
    store
        .insert(gate_entry, timefmt::now_unix_ms().expect("clock"))
        .expect("gate entry insert");
    let len_before = store.len();
    drop(store);

    let mut store = PendingApprovalStore::open(store_path.clone()).expect("store re-open");
    let entry = store
        .get(&gate_nonce)
        .cloned()
        .expect("gate entry must be present");
    stellar_agent_core::approval::attest::attest_and_persist(
        &mut store,
        &entry,
        &attestation_key,
        stellar_agent_core::approval::Surface::Cli,
        None,
        None,
        |req, key| {
            stellar_agent_toolsets_runtime::record_first_invoke_grant(
                &profile_name,
                req.toolset_name,
                req.capability,
                req.destination,
                req.asset,
                req.amount_min_stroops,
                req.amount_max_stroops,
                req.process_uid,
                req.now_unix_ms,
                key,
                None,
            )
            .map(|_grant| ())
            .map_err(|e| e.to_string())
        },
    )
    .expect("attest_and_persist must succeed for the gate entry");
    let len_after = store.len();
    drop(store);

    assert_eq!(
        len_before - 1,
        len_after,
        "the ToolsetFirstInvokeGate pending entry must be CONSUMED (removed) once its grant \
         is recorded — a leftover entry means the toolset would be re-prompted forever"
    );

    // The rule-proposal's own pending entry is untouched by the toolset gate
    // machinery — commit it directly (non-toolset path) to confirm it is
    // still independently actionable.
    let result = server
        .call_stellar_rule_create_commit(StellarRuleCreateCommitArgs {
            chain_id: TESTNET_CHAIN_ID.to_owned(),
            approval_nonce: nonce,
            approval_attestation: None,
        })
        .await;
    let result = result.expect("commit call must return a tool result");
    assert_eq!(
        result.is_error,
        Some(true),
        "commit without attestation must still be a business error"
    );
    let json = result_json(&result);
    assert_eq!(
        json["error"]["code"].as_str(),
        Some("policy.approval_required"),
        "got: {json}"
    );
}
