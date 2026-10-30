//! Bridge-local smoke test for the passkey-registration path.
//!
//! Validates the end-to-end registration flow using a REAL `start_bridge_register_only`
//! instance (port `0` loopback) with the SAME `Arc<tokio::sync::Mutex<
//! PendingApprovalStore>>` shared between the bridge and a `CredentialsManager`.
//!
//! # What this covers
//!
//! - `prepare_registration` URL uses the nonce verbatim (base64url, NOT
//!   hex-encoded); `GET /register/{nonce}` returns 200.
//! - The manager and bridge share the SAME store Arc; the bridge POST of a
//!   response verified against the entry's challenge populates the entry;
//!   `poll_registration` observes it without a second `open()` call.
//! - Polling stages the registration and writes nothing; only
//!   `confirm_registration` with the page's confirmation code puts the
//!   credential into the registry.
//!
//! # Test sequence (happy path)
//!
//! 1. Open a `PendingApprovalStore` in a temp dir; wrap in `Arc<Mutex<>>`.
//! 2. Start a real `start_bridge_register_only` bound to `127.0.0.1:0`.
//! 3. Construct a `CredentialsManager` pointing at the same `Arc<Mutex<>>`.
//! 4. Call `prepare_registration` → get `RegistrationHandle { nonce, url }`.
//! 5. `GET {url}` via `reqwest` → assert 200 + HTML.
//! 6. Read the CSRF token and the registration challenge from the shared store.
//! 7. `POST /register/{nonce}/credential` with a software registrar's response
//!    over that challenge → assert 200 + `{"status":"recorded"}`.
//! 8. `poll_registration` with a short deadline → assert `AwaitingConfirmation`
//!    and an empty registry.
//! 9. `confirm_registration` with the passkey-domain code of the registrar's
//!    credential → the metadata; `show` + `list` return the new entry with
//!    the registrar's key.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration smoke test"
)]

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use base64::{
    Engine as _, engine::general_purpose::STANDARD, engine::general_purpose::URL_SAFE_NO_PAD,
};
use reqwest::{Client, StatusCode};
use stellar_agent_approval_ui::operator_enroll::test_support::SoftwareRegistrar;
use stellar_agent_core::approval::webauthn_registration::{
    ConfirmationCode, PASSKEY_REGISTRATION_CODE_DOMAIN,
};
use stellar_agent_core::approval::{ApprovalKind, store::PendingApprovalStore};
use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_smart_account::managers::credentials::{AddPasskeyOutcome, CredentialsManager};
use tempfile::TempDir;
use tokio::sync::Mutex;

use stellar_agent_webauthn_bridge::PageIdentity;
use stellar_agent_webauthn_bridge::start_bridge_register_only;

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Open an `Arc<Mutex<PendingApprovalStore>>` backed by a temp file.
///
/// Returns the Arc and the `TempDir` guard.  The caller must keep the `TempDir`
/// alive for the duration of the test.
fn open_shared_store(dir: &TempDir) -> Arc<Mutex<PendingApprovalStore>> {
    let approval_dir = dir.path().join("approvals");
    std::fs::create_dir_all(&approval_dir).unwrap();
    let path = approval_dir.join("smoke-test.toml");
    let store = PendingApprovalStore::open(path).expect("PendingApprovalStore::open in tempdir");
    Arc::new(Mutex::new(store))
}

/// Build a `reqwest::Client` with redirect-following disabled (so 3xx does not
/// mask the bridge's actual status code).
fn no_redirect_client() -> Client {
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("reqwest::Client")
}

// ─────────────────────────────────────────────────────────────────────────────
// Happy-path bridge smoke test
// ─────────────────────────────────────────────────────────────────────────────

/// End-to-end bridge smoke: prepare → GET → POST credential → poll.
///
/// Validates: nonce verbatim in URL, shared-store (no double-open), and
/// `public_key_sec1_b64` populated after poll.
#[tokio::test]
async fn bridge_registration_happy_path() {
    // ── 1. Shared store ───────────────────────────────────────────────────
    let dir = TempDir::new().expect("TempDir");
    let shared_store = open_shared_store(&dir);

    // ── 2. Start real bridge (port 0 loopback) ────────────────────────────
    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let bridge_handle = start_bridge_register_only(
        Arc::clone(&shared_store),
        bind_addr,
        PageIdentity::neutral(),
    )
    .await
    .expect("start_bridge_register_only must succeed on loopback port 0");
    let local_addr = bridge_handle.local_addr();

    // ── 3. CredentialsManager with the SAME shared store ─────────────────
    let passkeys_dir = dir.path().join("passkeys");
    // Use "localhost" as the RP-ID per WebAuthn Level 2 §5.1.2: IP literals
    // are forbidden as rpId.  The bridge binds to 127.0.0.1 but the origin
    // exposed to the browser is http://localhost:<port> (the URL rewrite
    // in prepare_registration / sign_with_passkey_rule).  This test exercises
    // direct HTTP (no browser WebAuthn API), so the rp_id in the approval entry
    // only matters for structural validation — "localhost" is always correct here.
    let mgr = CredentialsManager::new(
        passkeys_dir,
        "smoke-profile",
        "localhost",
        Some(Arc::clone(&shared_store)),
    );

    // ── 4. prepare_registration ───────────────────────────────────────────
    let credential_name = "smoke-key";
    let handle = mgr
        .prepare_registration(credential_name, local_addr, None)
        .await
        .expect("prepare_registration must succeed");

    let nonce = handle.nonce.clone();
    let reg_url = handle.url.clone();

    // Regression guard: the URL must contain the nonce verbatim (base64url),
    // NOT hex-encoded.  A hex-encoded nonce would be 44 chars (2 per byte of
    // the 22-char base64url string) and would never match the store's exact key.
    assert!(
        reg_url.contains(&nonce),
        "registration URL must contain nonce verbatim (base64url); url={reg_url}, nonce={nonce}"
    );
    // URL is formatted as http://localhost:<port>/... (not the raw
    // bind address) so the browser origin matches the RP-ID "localhost" per
    // WebAuthn Level 2 §5.1.2.  Direct-HTTP callers still reach the bridge via
    // the Host header; the URL rewrite only affects browser origin.
    let expected_prefix = format!("http://localhost:{}/register/", local_addr.port());
    assert!(
        reg_url.starts_with(&expected_prefix),
        "registration URL must point to bridge /register/ path with localhost; got: {reg_url}"
    );

    // ── 5. GET registration page ──────────────────────────────────────────
    let client = no_redirect_client();
    let resp = client
        .get(&reg_url)
        .header("Host", local_addr.to_string())
        .send()
        .await
        .expect("GET registration page");

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "GET {reg_url} must return 200; got {}",
        resp.status()
    );
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        content_type.contains("text/html"),
        "GET /register/{{nonce}} must return HTML; content-type: {content_type}"
    );
    // Consume the body so the connection is released cleanly.
    let _body_text = resp.text().await.expect("response body");

    // ── 6. Read CSRF token and challenge from shared store ────────────────
    //
    // The same Arc is used; no second open() is needed.
    let (csrf_hex, challenge) = {
        let guard = shared_store.lock().await;
        let entry = guard
            .get(&nonce)
            .expect("entry must exist after prepare_registration");
        match &entry.kind {
            ApprovalKind::RegisterPasskey {
                csrf_token,
                registration_challenge: Some(challenge),
                ..
            } => (hex::encode(csrf_token), *challenge),
            other => panic!(
                "expected RegisterPasskey with a challenge, got: {:?}",
                std::mem::discriminant(other)
            ),
        }
    };

    // ── 7. POST the registrar's credential to bridge ──────────────────────
    //
    // Wire shape mirrors `wire::RegistrationResponseJSON`: base64url `id`,
    // `rawId`, `clientDataJSON` and `attestationObject`, and the SEC1 key in
    // standard base64. The client data names the entry's challenge and the
    // page origin `http://localhost:<port>`.
    let registrar = SoftwareRegistrar::new([0x11; 32], vec![0xa5; 16]);
    let builder = registrar.builder(
        &challenge,
        &format!("http://localhost:{}", local_addr.port()),
    );
    let credential_id_b64 = registrar.credential_id_b64url();

    let post_url = format!("http://{local_addr}/register/{nonce}/credential");
    let payload = serde_json::json!({
        "id": credential_id_b64,
        "rawId": credential_id_b64,
        "type": "public-key",
        "response": {
            "clientDataJSON": URL_SAFE_NO_PAD.encode(builder.client_data_json()),
            "attestationObject": URL_SAFE_NO_PAD.encode(builder.attestation_object()),
            "publicKeySec1B64": STANDARD.encode(registrar.public_key_sec1()),
            "transports": ["internal"]
        }
    });

    let post_resp = client
        .post(&post_url)
        .header("Host", local_addr.to_string())
        .header("Origin", format!("http://{local_addr}"))
        .header("X-Stellar-Approval-CSRF", csrf_hex)
        .json(&payload)
        .send()
        .await
        .expect("POST /register/{nonce}/credential");

    assert_eq!(
        post_resp.status(),
        StatusCode::OK,
        "POST /register/{{nonce}}/credential must return 200; got {}",
        post_resp.status()
    );
    let post_body: serde_json::Value = post_resp.json().await.expect("POST response JSON");
    assert_eq!(
        post_body,
        serde_json::json!({"status": "recorded"}),
        "POST response body must be {{\"status\":\"recorded\"}}"
    );

    // The shared store must now carry registration_input.
    {
        let guard = shared_store.lock().await;
        let entry = guard
            .get(&nonce)
            .expect("entry must still exist after POST");
        match &entry.kind {
            ApprovalKind::RegisterPasskey {
                registration_input, ..
            } => {
                assert!(
                    registration_input.is_some(),
                    "registration_input must be populated after bridge POST"
                );
            }
            other => panic!(
                "expected RegisterPasskey arm, got: {:?}",
                std::mem::discriminant(other)
            ),
        }
    }

    // ── 8. poll_registration stages the bridge-submitted credential ──────
    let audit_path = dir.path().join("smoke-profile-audit.jsonl");
    let mut writer = AuditWriter::open(audit_path, None).expect("unkeyed audit writer");
    let deadline = Instant::now() + Duration::from_secs(5);
    let outcome = mgr
        .poll_registration(credential_name, &nonce, deadline, &mut writer)
        .await
        .expect("poll_registration must not return Err");
    let pending = match outcome {
        AddPasskeyOutcome::AwaitingConfirmation { pending } => pending,
        other => panic!("expected AddPasskeyOutcome::AwaitingConfirmation, got: {other:?}"),
    };
    assert_eq!(pending.credential_name(), credential_name);
    assert!(
        mgr.list().expect("list").is_empty(),
        "nothing is registered before the code is confirmed"
    );

    // ── 9. confirm_registration with the page's code registers it ─────────
    let code = ConfirmationCode::compute(
        PASSKEY_REGISTRATION_CODE_DOMAIN,
        &challenge,
        registrar.credential_id(),
        &registrar.public_key_sec1(),
    )
    .display();
    let metadata = mgr
        .confirm_registration(pending, &code, Instant::now(), &mut writer)
        .expect("the page's code confirms the registration");
    assert_eq!(metadata.credential_name, credential_name);
    assert_eq!(metadata.rp_id, "localhost");
    assert_eq!(
        metadata.credential_id_b64url,
        registrar.credential_id_b64url()
    );
    let decoded = URL_SAFE_NO_PAD
        .decode(&metadata.public_key_sec1_b64)
        .expect("public_key_sec1_b64 must be valid base64url");
    assert_eq!(decoded, registrar.public_key_sec1());

    let shown = mgr
        .show(credential_name)
        .expect("show must find the newly registered credential");
    assert_eq!(shown, metadata);

    let creds = mgr.list().expect("list must succeed after registration");
    assert_eq!(
        creds.len(),
        1,
        "expected exactly one credential, got: {creds:?}"
    );
    assert_eq!(creds[0].credential_name, credential_name);

    // ── Shutdown bridge cleanly ───────────────────────────────────────────
    bridge_handle.shutdown().await.expect("bridge shutdown");
}

// ─────────────────────────────────────────────────────────────────────────────
// URL-nonce regression: hex-encoded nonce returns 404
// ─────────────────────────────────────────────────────────────────────────────

/// Regression guard: a hex-encoded nonce must return 404.
///
/// The store key is the base64url nonce. A hex-encoded form of the same nonce
/// (`hex::encode(nonce)`) is a different string and must not match any entry,
/// so `GET /register/{hex}` returns 404.
#[tokio::test]
async fn bridge_get_hex_encoded_nonce_returns_404() {
    let dir = TempDir::new().expect("TempDir");
    let shared_store = open_shared_store(&dir);

    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let bridge_handle = start_bridge_register_only(
        Arc::clone(&shared_store),
        bind_addr,
        PageIdentity::neutral(),
    )
    .await
    .expect("start_bridge_register_only");
    let local_addr = bridge_handle.local_addr();

    let passkeys_dir = dir.path().join("passkeys");
    let mgr = CredentialsManager::new(
        passkeys_dir,
        "smoke-profile-2",
        "localhost",
        Some(Arc::clone(&shared_store)),
    );

    // prepare_registration inserts the entry under the verbatim nonce.
    let handle = mgr
        .prepare_registration("regression-key", local_addr, None)
        .await
        .expect("prepare_registration");
    let nonce = &handle.nonce;

    // Request the HEX form of the nonce — bridge must return 404 because the
    // entry is stored under the verbatim base64url nonce, NOT the hex form.
    let hex_nonce = hex::encode(nonce.as_bytes());
    let hex_url = format!("http://{local_addr}/register/{hex_nonce}");

    let client = no_redirect_client();
    let resp = client
        .get(&hex_url)
        .header("Host", local_addr.to_string())
        .send()
        .await
        .expect("GET hex-encoded nonce");

    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "hex-encoded nonce must return 404; URL was {hex_url}"
    );

    bridge_handle.shutdown().await.expect("bridge shutdown");
}
