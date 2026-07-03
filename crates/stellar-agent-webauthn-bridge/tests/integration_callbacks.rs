//! Integration tests for the WebAuthn bridge callback handlers.
//!
//! Tests cover:
//!
//! - `GET /healthz` — readiness route.
//! - `GET /register/<nonce>` — 200 HTML, 404 not-found, 404 expired, 400
//!   wrong-kind.
//! - `POST /register/<nonce>/credential` — CSRF enforcement, 200 recorded.
//! - `GET /approve/<nonce>` — 200 HTML, 404 not-found.
//! - `POST /approve/<nonce>/assertion` — CSRF enforcement.
//! - `POST /approve/<nonce>/cancel` — CSRF enforcement, 204 on removal.
//! - `GET /static/webauthn.js` — 200 + vendored `@simplewebauthn/browser`
//!   13.3.0 UMD bundle (byte count, version marker, `Cache-Control: no-store`).
//! - `GET /static/glue.js` — 200 + wallet-authored DOM/fetch glue (CSRF
//!   header POST pattern + `SimpleWebAuthnBrowser.start*` invocations).
//! - `SecurityHeadersLayer` — 5 headers present on all responses.
//! - `OriginHeaderAllowlistLayer` — POST rejected on wrong Origin.
//!
//! # State construction
//!
//! Each test calls `start_test_bridge()` which builds a fully wired bridge
//! backed by a `tempfile::TempDir`-isolated `PendingApprovalStore` wrapped in
//! `Arc<tokio::sync::Mutex<…>>`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration test file"
)]

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::{Client, StatusCode};
use sha2::{Digest, Sha256};
use stellar_agent_core::approval::{
    generate_csrf_token,
    store::{PendingApproval, PendingApprovalStore},
};
use tempfile::TempDir;
use tokio::sync::Mutex;

use stellar_agent_webauthn_bridge::{
    ApprovalPubkeyLookup, ApprovalPubkeyLookupError, BridgeHandle, start_bridge_with_pubkey_lookup,
};

// ─────────────────────────────────────────────────────────────────────────────
// Test helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Return a `reqwest::Client` with redirect following disabled (so 3xx chains
/// don't mask the actual bridge response status codes).
fn client() -> Client {
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("reqwest client")
}

/// Start a bridge backed by a fresh temp-dir store.
///
/// Returns `(BridgeHandle, Arc<Mutex<PendingApprovalStore>>, TempDir)`.  The
/// caller MUST hold the `TempDir` until the bridge has been shut down to
/// avoid deleting the backing file under the server task.
async fn start_test_bridge() -> (BridgeHandle, Arc<Mutex<PendingApprovalStore>>, TempDir) {
    start_test_bridge_with_lookup(Arc::new(TestPubkeyLookup::missing())).await
}

/// Start a bridge with an explicit approval pubkey lookup.
async fn start_test_bridge_with_lookup(
    pubkey_lookup: Arc<dyn ApprovalPubkeyLookup>,
) -> (BridgeHandle, Arc<Mutex<PendingApprovalStore>>, TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("test.toml");
    let store = PendingApprovalStore::open(path).expect("open store");
    let store = Arc::new(Mutex::new(store));

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let handle = start_bridge_with_pubkey_lookup(Arc::clone(&store), addr, pubkey_lookup)
        .await
        .expect("start_bridge_register_only");

    (handle, store, dir)
}

#[derive(Debug)]
struct TestPubkeyLookup {
    credential_id: Vec<u8>,
    pubkey: Option<[u8; 65]>,
}

impl TestPubkeyLookup {
    fn hit(credential_id: Vec<u8>, pubkey: [u8; 65]) -> Self {
        Self {
            credential_id,
            pubkey: Some(pubkey),
        }
    }

    fn missing() -> Self {
        Self {
            credential_id: Vec::new(),
            pubkey: None,
        }
    }
}

impl ApprovalPubkeyLookup for TestPubkeyLookup {
    fn public_key_sec1_for_credential_id(
        &self,
        credential_id: &[u8],
    ) -> Result<Option<[u8; 65]>, ApprovalPubkeyLookupError> {
        if credential_id == self.credential_id {
            Ok(self.pubkey)
        } else {
            Ok(None)
        }
    }
}

/// Current Unix time in milliseconds, for `PendingApprovalStore::insert`.
fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Construct a minimal valid `SignWithPasskey` entry and insert it into the store.
///
/// Returns `(nonce, csrf_bytes)`.
async fn insert_sign_with_passkey(store: &Arc<Mutex<PendingApprovalStore>>) -> (String, [u8; 32]) {
    let csrf = generate_csrf_token();
    let entry = PendingApproval::new_passkey_pending(
        [0xab_u8; 32],               // auth_digest
        vec![0x01_u8; 16],           // credential_id (16 bytes, valid)
        "CAAAA...BBBBB".to_string(), // smart_account_redacted
        vec![1_u32],                 // rule_ids
        csrf,
        "localhost".to_string(), // rp_id (per WebAuthn Level 2 §5.1.2)
        "test-proc-uid".to_string(),
        300_000, // ttl_ms: 5 minutes
    )
    .expect("new_passkey_pending");

    let nonce = entry.approval_nonce.clone();
    store
        .lock()
        .await
        .insert(entry, now_unix_ms())
        .expect("insert");
    (nonce, csrf)
}

fn valid_assertion_fixture(auth_digest: &[u8; 32]) -> ([u8; 65], Vec<u8>, Vec<u8>, Vec<u8>) {
    use p256::SecretKey;
    use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
    use p256::elliptic_curve::sec1::ToEncodedPoint as _;

    const SECRET_KEY_SEED: [u8; 32] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ];

    let secret_key = SecretKey::from_slice(&SECRET_KEY_SEED).expect("test secret key");
    let signing_key = SigningKey::from(&secret_key);
    let pubkey_point = secret_key.public_key().to_encoded_point(false);
    let mut pubkey = [0u8; 65];
    pubkey.copy_from_slice(pubkey_point.as_bytes());

    let challenge_b64 = URL_SAFE_NO_PAD.encode(auth_digest);
    let client_data_json = format!(
        r#"{{"type":"webauthn.get","challenge":"{challenge_b64}","origin":"http://localhost","crossOrigin":false}}"#
    )
    .into_bytes();

    let mut authenticator_data = vec![0u8; 37];
    authenticator_data[..32].copy_from_slice(&Sha256::digest("localhost"));
    authenticator_data[32] = 0x01 | 0x04 | 0x08 | 0x10;

    let client_hash = Sha256::digest(&client_data_json);
    let mut sig_payload = Vec::with_capacity(authenticator_data.len() + 32);
    sig_payload.extend_from_slice(&authenticator_data);
    sig_payload.extend_from_slice(&client_hash);
    let digest = Sha256::digest(&sig_payload);

    let signature: Signature = signing_key.sign_prehash(&digest).expect("test signature");
    let signature = signature.normalize_s().unwrap_or(signature);
    let signature_der = signature.to_der().as_bytes().to_vec();

    (pubkey, authenticator_data, client_data_json, signature_der)
}

/// Construct a minimal valid `RegisterPasskey` entry and insert it into the store.
///
/// Returns `(nonce, csrf_bytes)`.
async fn insert_register_passkey(store: &Arc<Mutex<PendingApprovalStore>>) -> (String, [u8; 32]) {
    let csrf = generate_csrf_token();
    let entry = PendingApproval::new_register_passkey_pending(
        "CAAAA...BBBBB".to_string(),
        vec![1_u32],
        csrf,
        "localhost".to_string(),
        [0xcc_u8; 32], // user_handle
        "test-proc-uid".to_string(),
        300_000,
    )
    .expect("new_register_passkey_pending");

    let nonce = entry.approval_nonce.clone();
    store
        .lock()
        .await
        .insert(entry, now_unix_ms())
        .expect("insert");
    (nonce, csrf)
}

/// Construct a minimal valid `PaymentSimulated` entry and insert it into the store.
///
/// Used by wrong-kind tests on bridge passkey routes: PaymentSimulated entries
/// are NOT cancellable through the bridge (they have a CLI-side cancel path).
///
/// Returns the nonce string.
async fn insert_payment_simulated(store: &Arc<Mutex<PendingApprovalStore>>) -> String {
    let envelope_xdr_b64 = "AAAA".to_string();
    let envelope_xdr_bytes = b"dummy-envelope-bytes";
    let entry = PendingApproval::new_payment_pending(
        envelope_xdr_b64,
        envelope_xdr_bytes,
        "GAAAA...BBBBB".to_string(),
        1_000_000,
        "XLM".to_string(),
        None,
        100,
        42,
        "test-proc-uid".to_string(),
        300_000,
    )
    .expect("new_payment_pending");

    let nonce = entry.approval_nonce.clone();
    store
        .lock()
        .await
        .insert(entry, now_unix_ms())
        .expect("insert");
    nonce
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /healthz
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn healthz_returns_200() {
    let (handle, _store, _dir) = start_test_bridge().await;
    let local = handle.local_addr();
    let url = format!("http://{local}/healthz");

    let resp = client()
        .get(&url)
        .header("Host", local.to_string())
        .send()
        .await
        .expect("GET /healthz");

    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body, serde_json::json!({"status": "ok"}));

    handle.shutdown().await.expect("shutdown");
}

// ─────────────────────────────────────────────────────────────────────────────
// Security headers present on all responses
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn security_headers_present_on_200() {
    let (handle, _store, _dir) = start_test_bridge().await;
    let local = handle.local_addr();
    let url = format!("http://{local}/healthz");

    let resp = client()
        .get(&url)
        .header("Host", local.to_string())
        .send()
        .await
        .expect("GET /healthz");

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok()),
        Some("no-store"),
        "Cache-Control must be no-store"
    );
    assert!(
        resp.headers().contains_key("content-security-policy"),
        "Content-Security-Policy must be present"
    );
    assert_eq!(
        resp.headers()
            .get("x-frame-options")
            .and_then(|v| v.to_str().ok()),
        Some("DENY"),
        "X-Frame-Options must be DENY"
    );
    assert_eq!(
        resp.headers()
            .get("referrer-policy")
            .and_then(|v| v.to_str().ok()),
        Some("no-referrer"),
        "Referrer-Policy must be no-referrer"
    );

    handle.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn security_headers_present_on_404() {
    let (handle, _store, _dir) = start_test_bridge().await;
    let local = handle.local_addr();
    let url = format!("http://{local}/nonexistent/route");

    let resp = client()
        .get(&url)
        .header("Host", local.to_string())
        .send()
        .await
        .expect("GET /nonexistent/route");

    assert_eq!(resp.status().as_u16(), 404);
    assert!(
        resp.headers().contains_key("content-security-policy"),
        "CSP must be present on 404 responses"
    );
    assert!(
        resp.headers().contains_key("cache-control"),
        "Cache-Control must be present on 404 responses"
    );

    handle.shutdown().await.expect("shutdown");
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /register/<nonce>
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn register_get_returns_200_html_for_valid_entry() {
    let (handle, store, _dir) = start_test_bridge().await;
    let local = handle.local_addr();
    let (nonce, _csrf) = insert_register_passkey(&store).await;

    let url = format!("http://{local}/register/{nonce}");
    let resp = client()
        .get(&url)
        .header("Host", local.to_string())
        .send()
        .await
        .expect("GET /register/<nonce>");

    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.starts_with("text/html"),
        "response must be HTML, got: {ct}"
    );

    let body = resp.text().await.expect("body text");
    assert!(
        body.contains("webauthn-options"),
        "page must contain the webauthn-options data island"
    );
    assert!(
        body.contains("/static/webauthn.js"),
        "page must reference the webauthn.js bundle"
    );

    handle.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn register_get_returns_404_for_unknown_nonce() {
    let (handle, _store, _dir) = start_test_bridge().await;
    let local = handle.local_addr();
    let url = format!("http://{local}/register/definitely-not-a-real-nonce");

    let resp = client()
        .get(&url)
        .header("Host", local.to_string())
        .send()
        .await
        .expect("GET /register/bad-nonce");

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["error"], "approval_not_found");

    handle.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn register_get_returns_400_for_wrong_kind_entry() {
    let (handle, store, _dir) = start_test_bridge().await;
    let local = handle.local_addr();
    let (nonce, _csrf) = insert_sign_with_passkey(&store).await;

    // This nonce is SignWithPasskey, not RegisterPasskey.
    let url = format!("http://{local}/register/{nonce}");
    let resp = client()
        .get(&url)
        .header("Host", local.to_string())
        .send()
        .await
        .expect("GET /register/<sign-with-passkey-nonce>");

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["error"], "approval_kind_mismatch");

    handle.shutdown().await.expect("shutdown");
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /register/<nonce>/credential
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn register_post_rejects_missing_csrf() {
    let (handle, store, _dir) = start_test_bridge().await;
    let local = handle.local_addr();
    let (nonce, _csrf) = insert_register_passkey(&store).await;

    let url = format!("http://{local}/register/{nonce}/credential");
    // JSON key names follow the @simplewebauthn/browser 13.x wire contract.
    // clientDataJSON uses uppercase JSON per the WebAuthn spec (explicit rename in wire.rs).
    let payload = serde_json::json!({
        "id": "AAAA",
        "rawId": "AAAA",
        "type": "public-key",
        "response": {
            "clientDataJSON": "AAAA",
            "attestationObject": "AAAA",
            "publicKeySec1B64": "AAAA"
        }
    });

    let resp = client()
        .post(&url)
        .header("Host", local.to_string())
        .header("Origin", format!("http://{local}"))
        .json(&payload)
        .send()
        .await
        .expect("POST /register/<nonce>/credential");

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["error"], "csrf_invalid");

    handle.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn register_post_rejects_wrong_csrf() {
    let (handle, store, _dir) = start_test_bridge().await;
    let local = handle.local_addr();
    let (nonce, _correct_csrf) = insert_register_passkey(&store).await;

    let wrong_csrf = hex::encode([0x00_u8; 32]);
    let url = format!("http://{local}/register/{nonce}/credential");
    let payload = serde_json::json!({
        "id": "AAAA",
        "rawId": "AAAA",
        "type": "public-key",
        "response": {
            "clientDataJSON": "AAAA",
            "attestationObject": "AAAA",
            "publicKeySec1B64": "AAAA"
        }
    });

    let resp = client()
        .post(&url)
        .header("Host", local.to_string())
        .header("Origin", format!("http://{local}"))
        .header("X-Stellar-Approval-CSRF", wrong_csrf)
        .json(&payload)
        .send()
        .await
        .expect("POST /register/<nonce>/credential");

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["error"], "csrf_invalid");

    handle.shutdown().await.expect("shutdown");
}

/// Happy path: POST /register/<nonce>/credential with valid CSRF + valid
/// payload records the RegistrationInput into the approval-store entry.
#[tokio::test]
async fn register_post_records_valid_credential() {
    use base64::{
        Engine as _, engine::general_purpose::STANDARD, engine::general_purpose::URL_SAFE_NO_PAD,
    };
    use stellar_agent_core::approval::ApprovalKind;

    let (handle, store, _dir) = start_test_bridge().await;
    let local = handle.local_addr();
    let (nonce, csrf) = insert_register_passkey(&store).await;
    let csrf_hex = hex::encode(csrf);

    // Construct a valid 16-byte credential_id (CTAP2 minimum) base64url-encoded.
    let credential_id_bytes: [u8; 16] = [0x42; 16];
    let credential_id_b64 = URL_SAFE_NO_PAD.encode(credential_id_bytes);
    // Construct a valid 65-byte SEC1 uncompressed P-256 pubkey
    // (`0x04 || X (32 bytes) || Y (32 bytes)`); X+Y are dummy bytes here —
    // the validator only checks length + the 0x04 marker, not on-curve.
    let mut pubkey_sec1 = [0u8; 65];
    pubkey_sec1[0] = 0x04;
    for (i, byte) in pubkey_sec1.iter_mut().enumerate().skip(1) {
        *byte = i as u8;
    }
    let pubkey_b64 = STANDARD.encode(pubkey_sec1);

    let url = format!("http://{local}/register/{nonce}/credential");
    // attestationObject is base64url WITHOUT padding per @simplewebauthn/browser
    // 13.x wire contract; the handler decodes via URL_SAFE_NO_PAD.
    let payload = serde_json::json!({
        "id": credential_id_b64,
        "rawId": credential_id_b64,
        "type": "public-key",
        "response": {
            "clientDataJSON": "ZHVtbXk",
            "attestationObject": "ZHVtbXk",
            "publicKeySec1B64": pubkey_b64,
            "transports": ["internal", "usb"]
        }
    });

    let resp = client()
        .post(&url)
        .header("Host", local.to_string())
        .header("Origin", format!("http://{local}"))
        .header("X-Stellar-Approval-CSRF", csrf_hex)
        .json(&payload)
        .send()
        .await
        .expect("POST /register/<nonce>/credential");

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "expected 200 for valid registration POST, got {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body, serde_json::json!({"status": "recorded"}));

    // Verify the entry now carries registration_input.
    let guard = store.lock().await;
    let entry = guard.get(&nonce).expect("entry still present");
    match &entry.kind {
        ApprovalKind::RegisterPasskey {
            registration_input, ..
        } => {
            assert!(
                registration_input.is_some(),
                "registration_input must be populated after successful POST"
            );
        }
        other => panic!(
            "expected RegisterPasskey arm, got: {:?}",
            std::mem::discriminant(other)
        ),
    }
    drop(guard);

    handle.shutdown().await.expect("shutdown");
}

/// Wrong-kind: POST /register/<nonce>/credential on a SignWithPasskey entry
/// must return the generic error (400 + approval_not_found), NEVER
/// approval_kind_mismatch (which is the GET-path discriminator).
#[tokio::test]
async fn register_post_returns_400_for_wrong_kind_entry() {
    let (handle, store, _dir) = start_test_bridge().await;
    let local = handle.local_addr();
    // Insert a SignWithPasskey entry; POST to /register/ is wrong-kind.
    let (nonce, csrf) = insert_sign_with_passkey(&store).await;
    let csrf_hex = hex::encode(csrf);

    let url = format!("http://{local}/register/{nonce}/credential");
    let payload = serde_json::json!({
        "id": "AAAAAAAAAAAAAAAAAAAAAAAA",
        "rawId": "AAAAAAAAAAAAAAAAAAAAAAAA",
        "type": "public-key",
        "response": {
            "clientDataJSON": "AAAA",
            "attestationObject": "AAAA",
            "publicKeySec1B64": "AAAA"
        }
    });

    let resp = client()
        .post(&url)
        .header("Host", local.to_string())
        .header("Origin", format!("http://{local}"))
        .header("X-Stellar-Approval-CSRF", csrf_hex)
        .json(&payload)
        .send()
        .await
        .expect("POST /register/<nonce>/credential");

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(
        body["error"], "approval_not_found",
        "POST wrong-kind MUST collapse to generic approval_not_found \
         (not approval_kind_mismatch — that's GET-only)"
    );

    handle.shutdown().await.expect("shutdown");
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /approve/<nonce>
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn approve_get_returns_200_html_for_valid_entry() {
    let (handle, store, _dir) = start_test_bridge().await;
    let local = handle.local_addr();
    let (nonce, _csrf) = insert_sign_with_passkey(&store).await;

    let url = format!("http://{local}/approve/{nonce}");
    let resp = client()
        .get(&url)
        .header("Host", local.to_string())
        .send()
        .await
        .expect("GET /approve/<nonce>");

    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.starts_with("text/html"),
        "response must be HTML, got: {ct}"
    );

    let body = resp.text().await.expect("body text");
    assert!(
        body.contains("webauthn-options"),
        "page must contain the webauthn-options data island"
    );

    handle.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn approve_get_returns_404_for_unknown_nonce() {
    let (handle, _store, _dir) = start_test_bridge().await;
    let local = handle.local_addr();
    let url = format!("http://{local}/approve/no-such-nonce");

    let resp = client()
        .get(&url)
        .header("Host", local.to_string())
        .send()
        .await
        .expect("GET /approve/bad-nonce");

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["error"], "approval_not_found");

    handle.shutdown().await.expect("shutdown");
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /approve/<nonce>/assertion
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn approve_assertion_post_rejects_missing_csrf() {
    let (handle, store, _dir) = start_test_bridge().await;
    let local = handle.local_addr();
    let (nonce, _csrf) = insert_sign_with_passkey(&store).await;

    let url = format!("http://{local}/approve/{nonce}/assertion");
    // JSON key names follow the @simplewebauthn/browser 13.x wire contract.
    let payload = serde_json::json!({
        "id": "AAAA",
        "rawId": "AAAA",
        "type": "public-key",
        "response": {
            "clientDataJSON": "AAAA",
            "authenticatorData": "AAAA",
            "signature": "AAAA"
        }
    });

    let resp = client()
        .post(&url)
        .header("Host", local.to_string())
        .header("Origin", format!("http://{local}"))
        .json(&payload)
        .send()
        .await
        .expect("POST /approve/<nonce>/assertion");

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["error"], "csrf_invalid");

    handle.shutdown().await.expect("shutdown");
}

/// Wrong-CSRF on POST /approve/<nonce>/assertion returns 403 + csrf_invalid.
#[tokio::test]
async fn approve_assertion_post_rejects_wrong_csrf() {
    let (handle, store, _dir) = start_test_bridge().await;
    let local = handle.local_addr();
    let (nonce, _correct_csrf) = insert_sign_with_passkey(&store).await;

    let wrong_csrf = hex::encode([0x00_u8; 32]);
    let url = format!("http://{local}/approve/{nonce}/assertion");
    let payload = serde_json::json!({
        "id": "AAAA",
        "rawId": "AAAA",
        "type": "public-key",
        "response": {
            "clientDataJSON": "AAAA",
            "authenticatorData": "AAAA",
            "signature": "AAAA"
        }
    });

    let resp = client()
        .post(&url)
        .header("Host", local.to_string())
        .header("Origin", format!("http://{local}"))
        .header("X-Stellar-Approval-CSRF", wrong_csrf)
        .json(&payload)
        .send()
        .await
        .expect("POST /approve/<nonce>/assertion");

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["error"], "csrf_invalid");

    handle.shutdown().await.expect("shutdown");
}

/// Happy path: POST /approve/<nonce>/assertion with valid CSRF + valid
/// payload records the AssertionInput into the approval-store entry.
///
/// The bridge resolves the registered public key from the injected lookup and
/// runs the full `pre_verify_assertion` pipeline before recording the assertion.
#[tokio::test]
async fn approve_assertion_post_records_valid_assertion() {
    let auth_digest = [0xab_u8; 32];
    let credential_id = vec![0x01_u8; 16];
    let (pubkey, authenticator_data, client_data_json, signature_der) =
        valid_assertion_fixture(&auth_digest);
    let (handle, store, _dir) = start_test_bridge_with_lookup(Arc::new(TestPubkeyLookup::hit(
        credential_id.clone(),
        pubkey,
    )))
    .await;
    let local = handle.local_addr();
    // insert_sign_with_passkey creates an entry with credential_id = [0x01; 16].
    let (nonce, csrf) = insert_sign_with_passkey(&store).await;
    let csrf_hex = hex::encode(csrf);
    let credential_id_b64 = URL_SAFE_NO_PAD.encode(&credential_id);

    let url = format!("http://{local}/approve/{nonce}/assertion");
    let payload = serde_json::json!({
        "id": credential_id_b64,
        "rawId": credential_id_b64,
        "type": "public-key",
        "response": {
            "clientDataJSON": URL_SAFE_NO_PAD.encode(&client_data_json),
            "authenticatorData": URL_SAFE_NO_PAD.encode(&authenticator_data),
            "signature": URL_SAFE_NO_PAD.encode(&signature_der)
        }
    });

    let resp = client()
        .post(&url)
        .header("Host", local.to_string())
        .header("Origin", format!("http://{local}"))
        .header("X-Stellar-Approval-CSRF", csrf_hex)
        .json(&payload)
        .send()
        .await
        .expect("POST /approve/<nonce>/assertion");

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "expected 200 for valid assertion POST, got {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body, serde_json::json!({"status": "recorded"}));

    // Verify the store-side effect: the assertion was recorded on the entry.
    {
        let guard = store.lock().await;
        let entry = guard
            .get(&nonce)
            .expect("entry still present after assertion");
        assert!(
            entry.passkey_assertion.is_some(),
            "valid assertion POST must record passkey_assertion on the entry"
        );
    }

    handle.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn approve_assertion_post_rejects_missing_pubkey_lookup_record() {
    let auth_digest = [0xab_u8; 32];
    let credential_id = vec![0x01_u8; 16];
    let (_pubkey, authenticator_data, client_data_json, signature_der) =
        valid_assertion_fixture(&auth_digest);
    let (handle, store, _dir) =
        start_test_bridge_with_lookup(Arc::new(TestPubkeyLookup::missing())).await;
    let local = handle.local_addr();
    let (nonce, csrf) = insert_sign_with_passkey(&store).await;
    let csrf_hex = hex::encode(csrf);
    let credential_id_b64 = URL_SAFE_NO_PAD.encode(&credential_id);

    let url = format!("http://{local}/approve/{nonce}/assertion");
    let payload = serde_json::json!({
        "id": credential_id_b64,
        "rawId": credential_id_b64,
        "type": "public-key",
        "response": {
            "clientDataJSON": URL_SAFE_NO_PAD.encode(&client_data_json),
            "authenticatorData": URL_SAFE_NO_PAD.encode(&authenticator_data),
            "signature": URL_SAFE_NO_PAD.encode(&signature_der)
        }
    });

    let resp = client()
        .post(&url)
        .header("Host", local.to_string())
        .header("Origin", format!("http://{local}"))
        .header("X-Stellar-Approval-CSRF", csrf_hex)
        .json(&payload)
        .send()
        .await
        .expect("POST /approve/<nonce>/assertion");

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["error"], "webauthn_assertion_invalid");
    assert!(
        store
            .lock()
            .await
            .get(&nonce)
            .expect("approval entry")
            .passkey_assertion
            .is_none(),
        "missing pubkey record must not silently record an assertion"
    );

    handle.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn approve_assertion_post_rejects_wrong_origin() {
    let (handle, store, _dir) = start_test_bridge().await;
    let local = handle.local_addr();
    let (nonce, _csrf) = insert_sign_with_passkey(&store).await;

    let url = format!("http://{local}/approve/{nonce}/assertion");
    let payload = serde_json::json!({
        "id": "AAAA",
        "rawId": "AAAA",
        "type": "public-key",
        "response": {
            "clientDataJSON": "AAAA",
            "authenticatorData": "AAAA",
            "signature": "AAAA"
        }
    });

    let resp = client()
        .post(&url)
        .header("Host", local.to_string())
        .header("Origin", "http://attacker.example:8080")
        .json(&payload)
        .send()
        .await
        .expect("POST /approve/<nonce>/assertion with wrong origin");

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["error"], "origin_header_rejected");

    handle.shutdown().await.expect("shutdown");
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /approve/<nonce>/cancel
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn approve_cancel_rejects_missing_csrf() {
    let (handle, store, _dir) = start_test_bridge().await;
    let local = handle.local_addr();
    let (nonce, _csrf) = insert_sign_with_passkey(&store).await;

    let url = format!("http://{local}/approve/{nonce}/cancel");
    let resp = client()
        .post(&url)
        .header("Host", local.to_string())
        .header("Origin", format!("http://{local}"))
        .send()
        .await
        .expect("POST /approve/<nonce>/cancel");

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["error"], "csrf_invalid");

    handle.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn approve_cancel_returns_204_for_unknown_nonce() {
    // Idempotent cancel — unknown nonce returns 204 (already absent).
    let (handle, _store, _dir) = start_test_bridge().await;
    let local = handle.local_addr();
    let csrf_hex = hex::encode(generate_csrf_token());

    let url = format!("http://{local}/approve/no-such-nonce/cancel");
    let resp = client()
        .post(&url)
        .header("Host", local.to_string())
        .header("Origin", format!("http://{local}"))
        .header("X-Stellar-Approval-CSRF", csrf_hex)
        .send()
        .await
        .expect("POST /approve/no-such-nonce/cancel");

    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    handle.shutdown().await.expect("shutdown");
}

/// Wrong-kind: `POST /approve/<nonce>/cancel` on a `PaymentSimulated` entry
/// MUST return `204 No Content` — identical to the not-found path — so neither
/// status code nor body discriminates "exists as non-passkey kind" from
/// "non-existent". This locks the status-code-oracle elimination on top of the
/// body collapse. The PaymentSimulated entry is NOT removed by the bridge — the
/// CLI-side cancel path remains authoritative for that kind.
#[tokio::test]
async fn approve_cancel_on_payment_simulated_returns_204_without_remove() {
    let (handle, store, _dir) = start_test_bridge().await;
    let local = handle.local_addr();
    let nonce = insert_payment_simulated(&store).await;
    // Use a syntactically-valid CSRF (the wrong-kind arm short-circuits BEFORE
    // CSRF compare so the value is irrelevant — but the header MUST decode or
    // the request stops earlier with a 403).
    let csrf_hex = hex::encode([0u8; 32]);

    let url = format!("http://{local}/approve/{nonce}/cancel");
    let resp = client()
        .post(&url)
        .header("Host", local.to_string())
        .header("Origin", format!("http://{local}"))
        .header("X-Stellar-Approval-CSRF", csrf_hex)
        .send()
        .await
        .expect("POST /approve/<nonce>/cancel");

    assert_eq!(
        resp.status(),
        StatusCode::NO_CONTENT,
        "wrong-kind cancel must return 204 (status-code indistinguishability)"
    );
    // Body must be empty (no JSON error) — same shape as the not-found path.
    let body_bytes = resp.bytes().await.expect("body bytes");
    assert!(
        body_bytes.is_empty(),
        "wrong-kind cancel must return empty body, got {} bytes",
        body_bytes.len()
    );

    // The bridge MUST NOT remove a PaymentSimulated entry through this path.
    let guard = store.lock().await;
    assert!(
        guard.get(&nonce).is_some(),
        "PaymentSimulated entry must remain after bridge-side cancel attempt"
    );
    drop(guard);

    handle.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn approve_cancel_with_correct_csrf_returns_204() {
    let (handle, store, _dir) = start_test_bridge().await;
    let local = handle.local_addr();
    let (nonce, csrf) = insert_sign_with_passkey(&store).await;

    let csrf_hex = hex::encode(csrf);
    let url = format!("http://{local}/approve/{nonce}/cancel");

    let resp = client()
        .post(&url)
        .header("Host", local.to_string())
        .header("Origin", format!("http://{local}"))
        .header("X-Stellar-Approval-CSRF", csrf_hex)
        .send()
        .await
        .expect("POST /approve/<nonce>/cancel");

    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Entry should be gone from the store.
    let guard = store.lock().await;
    assert!(
        guard.get(&nonce).is_none(),
        "entry must be removed after cancel"
    );

    handle.shutdown().await.expect("shutdown");
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /static/webauthn.js + GET /static/glue.js (vendored assets)
// ─────────────────────────────────────────────────────────────────────────────

/// `/static/webauthn.js` serves the vendored `@simplewebauthn/browser` 13.3.0
/// UMD bundle. Asserts the version-marker comment + the expected byte count.
#[tokio::test]
async fn static_webauthn_js_serves_vendored_bundle() {
    let (handle, _store, _dir) = start_test_bridge().await;
    let local = handle.local_addr();
    let url = format!("http://{local}/static/webauthn.js");

    let resp = client()
        .get(&url)
        .header("Host", local.to_string())
        .send()
        .await
        .expect("GET /static/webauthn.js");

    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.starts_with("application/javascript"),
        "expected application/javascript, got: {ct}"
    );
    // SecurityHeadersLayer must still inject Cache-Control: no-store.
    assert_eq!(
        resp.headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok()),
        Some("no-store"),
        "Cache-Control: no-store must apply to static assets"
    );

    let body_bytes = resp.bytes().await.expect("body");
    assert_eq!(
        body_bytes.len(),
        9_269,
        "vendored bundle byte count must match the audit-recorded value"
    );
    let body = std::str::from_utf8(&body_bytes).expect("utf-8");
    assert!(
        body.contains("[@simplewebauthn/browser@13.3.0]"),
        "bundle must carry the upstream version-marker comment"
    );

    handle.shutdown().await.expect("shutdown");
}

/// `/static/glue.js` serves the wallet-authored DOM/fetch glue. The glue
/// invokes the two `SimpleWebAuthnBrowser.start*` symbols from the bundle
/// and POSTs to the bridge with the CSRF header.
#[tokio::test]
async fn static_glue_js_serves_wallet_glue() {
    let (handle, _store, _dir) = start_test_bridge().await;
    let local = handle.local_addr();
    let url = format!("http://{local}/static/glue.js");

    let resp = client()
        .get(&url)
        .header("Host", local.to_string())
        .send()
        .await
        .expect("GET /static/glue.js");

    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.starts_with("application/javascript"),
        "expected application/javascript, got: {ct}"
    );

    let body = resp.text().await.expect("body");
    assert!(
        body.contains("SimpleWebAuthnBrowser.startRegistration"),
        "glue must invoke SimpleWebAuthnBrowser.startRegistration"
    );
    assert!(
        body.contains("SimpleWebAuthnBrowser.startAuthentication"),
        "glue must invoke SimpleWebAuthnBrowser.startAuthentication"
    );
    assert!(
        body.contains("X-Stellar-Approval-CSRF"),
        "glue must POST with the CSRF header"
    );

    handle.shutdown().await.expect("shutdown");
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /approve/<nonce> — additional error paths
// ─────────────────────────────────────────────────────────────────────────────

/// `GET /approve/<nonce>` on a `PaymentSimulated` entry must return
/// `400 Bad Request` with `approval_kind_mismatch` (the GET path distinguishes
/// wrong-kind from not-found because the caller already knows the nonce).
#[tokio::test]
async fn approve_get_returns_400_for_wrong_kind_entry() {
    let (handle, store, _dir) = start_test_bridge().await;
    let local = handle.local_addr();
    let nonce = insert_payment_simulated(&store).await;

    let url = format!("http://{local}/approve/{nonce}");
    let resp = client()
        .get(&url)
        .header("Host", local.to_string())
        .send()
        .await
        .expect("GET /approve/<payment-simulated-nonce>");

    assert_eq!(resp.status().as_u16(), 400);
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(
        body["error"], "approval_kind_mismatch",
        "GET wrong-kind must return approval_kind_mismatch"
    );

    handle.shutdown().await.expect("shutdown");
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /approve/<nonce>/assertion — additional CSRF + field error paths
// ─────────────────────────────────────────────────────────────────────────────

/// CSRF header that is 64 characters but contains non-hex characters must
/// return 403 csrf_invalid (fails `CsrfToken::from_hex` at the non-hex char
/// check before the constant-time compare).
#[tokio::test]
async fn approve_assertion_post_rejects_csrf_non_hex() {
    let (handle, store, _dir) = start_test_bridge().await;
    let local = handle.local_addr();
    let (nonce, _csrf) = insert_sign_with_passkey(&store).await;

    // 64 chars, but last char is 'z' (non-hex).
    let non_hex_csrf = format!("{}{}", "a".repeat(63), "z");
    assert_eq!(non_hex_csrf.len(), 64);

    let url = format!("http://{local}/approve/{nonce}/assertion");
    let payload = serde_json::json!({
        "id": "AAAA",
        "rawId": "AAAA",
        "type": "public-key",
        "response": {
            "clientDataJSON": "AAAA",
            "authenticatorData": "AAAA",
            "signature": "AAAA"
        }
    });

    let resp = client()
        .post(&url)
        .header("Host", local.to_string())
        .header("Origin", format!("http://{local}"))
        .header("X-Stellar-Approval-CSRF", non_hex_csrf)
        .json(&payload)
        .send()
        .await
        .expect("POST /approve/<nonce>/assertion");

    assert_eq!(resp.status().as_u16(), 403);
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["error"], "csrf_invalid");

    handle.shutdown().await.expect("shutdown");
}

/// Nonce that does not exist returns 400 approval_not_found on the assertion
/// POST path (nonce absence is indistinguishable from expiry at the wire level).
#[tokio::test]
async fn approve_assertion_post_returns_400_for_unknown_nonce() {
    let (handle, _store, _dir) = start_test_bridge().await;
    let local = handle.local_addr();

    let csrf_hex = hex::encode([0x00_u8; 32]);
    let url = format!("http://{local}/approve/no-such-nonce/assertion");
    let payload = serde_json::json!({
        "id": "AAAA",
        "rawId": "AAAA",
        "type": "public-key",
        "response": {
            "clientDataJSON": "AAAA",
            "authenticatorData": "AAAA",
            "signature": "AAAA"
        }
    });

    let resp = client()
        .post(&url)
        .header("Host", local.to_string())
        .header("Origin", format!("http://{local}"))
        .header("X-Stellar-Approval-CSRF", csrf_hex)
        .json(&payload)
        .send()
        .await
        .expect("POST /approve/no-such-nonce/assertion");

    assert_eq!(resp.status().as_u16(), 400);
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["error"], "approval_not_found");

    handle.shutdown().await.expect("shutdown");
}

/// Wrong-kind entry (RegisterPasskey nonce) on POST /approve/<nonce>/assertion
/// collapses to 400 approval_not_found — same code as not-found (error
/// indistinguishability on the POST path, unlike the GET path).
#[tokio::test]
async fn approve_assertion_post_returns_400_for_wrong_kind_register_passkey() {
    let (handle, store, _dir) = start_test_bridge().await;
    let local = handle.local_addr();
    let (nonce, csrf) = insert_register_passkey(&store).await;
    let csrf_hex = hex::encode(csrf);

    let url = format!("http://{local}/approve/{nonce}/assertion");
    let payload = serde_json::json!({
        "id": "AAAA",
        "rawId": "AAAA",
        "type": "public-key",
        "response": {
            "clientDataJSON": "AAAA",
            "authenticatorData": "AAAA",
            "signature": "AAAA"
        }
    });

    let resp = client()
        .post(&url)
        .header("Host", local.to_string())
        .header("Origin", format!("http://{local}"))
        .header("X-Stellar-Approval-CSRF", csrf_hex)
        .json(&payload)
        .send()
        .await
        .expect("POST /approve/<register-passkey-nonce>/assertion");

    assert_eq!(resp.status().as_u16(), 400);
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(
        body["error"], "approval_not_found",
        "POST wrong-kind MUST collapse to approval_not_found (not approval_kind_mismatch)"
    );

    handle.shutdown().await.expect("shutdown");
}

/// Wrong-kind entry (PaymentSimulated nonce) on POST /approve/<nonce>/assertion
/// collapses to 400 approval_not_found (error indistinguishability on POST).
#[tokio::test]
async fn approve_assertion_post_returns_400_for_wrong_kind_payment_simulated() {
    let (handle, store, _dir) = start_test_bridge().await;
    let local = handle.local_addr();
    let nonce = insert_payment_simulated(&store).await;
    // Any valid-hex CSRF — wrong-kind arm fires before CSRF compare.
    let csrf_hex = hex::encode([0x00_u8; 32]);

    let url = format!("http://{local}/approve/{nonce}/assertion");
    let payload = serde_json::json!({
        "id": "AAAA",
        "rawId": "AAAA",
        "type": "public-key",
        "response": {
            "clientDataJSON": "AAAA",
            "authenticatorData": "AAAA",
            "signature": "AAAA"
        }
    });

    let resp = client()
        .post(&url)
        .header("Host", local.to_string())
        .header("Origin", format!("http://{local}"))
        .header("X-Stellar-Approval-CSRF", csrf_hex)
        .json(&payload)
        .send()
        .await
        .expect("POST /approve/<payment-simulated-nonce>/assertion");

    assert_eq!(resp.status().as_u16(), 400);
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["error"], "approval_not_found");

    handle.shutdown().await.expect("shutdown");
}

/// `authenticatorData` field containing invalid base64url returns
/// 400 webauthn_assertion_invalid (CSRF validates first, then decode fails).
#[tokio::test]
async fn approve_assertion_post_rejects_invalid_authenticator_data_b64() {
    let (handle, store, _dir) = start_test_bridge().await;
    let local = handle.local_addr();
    let (nonce, csrf) = insert_sign_with_passkey(&store).await;
    let csrf_hex = hex::encode(csrf);

    let url = format!("http://{local}/approve/{nonce}/assertion");
    let payload = serde_json::json!({
        "id": URL_SAFE_NO_PAD.encode([0x01_u8; 16]),
        "rawId": URL_SAFE_NO_PAD.encode([0x01_u8; 16]),
        "type": "public-key",
        "response": {
            // Valid base64url client data so that field passes.
            "clientDataJSON": URL_SAFE_NO_PAD.encode(b"{}"),
            // "!!" is not valid base64url (contains non-alphabet chars).
            "authenticatorData": "!!INVALID!!",
            "signature": URL_SAFE_NO_PAD.encode(b"sig")
        }
    });

    let resp = client()
        .post(&url)
        .header("Host", local.to_string())
        .header("Origin", format!("http://{local}"))
        .header("X-Stellar-Approval-CSRF", csrf_hex)
        .json(&payload)
        .send()
        .await
        .expect("POST /approve/<nonce>/assertion");

    assert_eq!(resp.status().as_u16(), 400);
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["error"], "webauthn_assertion_invalid");

    handle.shutdown().await.expect("shutdown");
}

/// `clientDataJSON` field containing invalid base64url returns
/// 400 webauthn_assertion_invalid.
#[tokio::test]
async fn approve_assertion_post_rejects_invalid_client_data_json_b64() {
    let (handle, store, _dir) = start_test_bridge().await;
    let local = handle.local_addr();
    let (nonce, csrf) = insert_sign_with_passkey(&store).await;
    let csrf_hex = hex::encode(csrf);

    let url = format!("http://{local}/approve/{nonce}/assertion");
    let payload = serde_json::json!({
        "id": URL_SAFE_NO_PAD.encode([0x01_u8; 16]),
        "rawId": URL_SAFE_NO_PAD.encode([0x01_u8; 16]),
        "type": "public-key",
        "response": {
            // "!!" is not valid base64url.
            "clientDataJSON": "!!INVALID!!",
            "authenticatorData": URL_SAFE_NO_PAD.encode([0u8; 37]),
            "signature": URL_SAFE_NO_PAD.encode(b"sig")
        }
    });

    let resp = client()
        .post(&url)
        .header("Host", local.to_string())
        .header("Origin", format!("http://{local}"))
        .header("X-Stellar-Approval-CSRF", csrf_hex)
        .json(&payload)
        .send()
        .await
        .expect("POST /approve/<nonce>/assertion");

    assert_eq!(resp.status().as_u16(), 400);
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["error"], "webauthn_assertion_invalid");

    handle.shutdown().await.expect("shutdown");
}

/// `signature` field containing invalid base64url returns
/// 400 webauthn_assertion_invalid.
#[tokio::test]
async fn approve_assertion_post_rejects_invalid_signature_b64() {
    let (handle, store, _dir) = start_test_bridge().await;
    let local = handle.local_addr();
    let (nonce, csrf) = insert_sign_with_passkey(&store).await;
    let csrf_hex = hex::encode(csrf);

    let url = format!("http://{local}/approve/{nonce}/assertion");
    let payload = serde_json::json!({
        "id": URL_SAFE_NO_PAD.encode([0x01_u8; 16]),
        "rawId": URL_SAFE_NO_PAD.encode([0x01_u8; 16]),
        "type": "public-key",
        "response": {
            "clientDataJSON": URL_SAFE_NO_PAD.encode(b"{}"),
            "authenticatorData": URL_SAFE_NO_PAD.encode([0u8; 37]),
            // "!!" is not valid base64url.
            "signature": "!!INVALID!!"
        }
    });

    let resp = client()
        .post(&url)
        .header("Host", local.to_string())
        .header("Origin", format!("http://{local}"))
        .header("X-Stellar-Approval-CSRF", csrf_hex)
        .json(&payload)
        .send()
        .await
        .expect("POST /approve/<nonce>/assertion");

    assert_eq!(resp.status().as_u16(), 400);
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["error"], "webauthn_assertion_invalid");

    handle.shutdown().await.expect("shutdown");
}

/// `id` (credential_id) field containing invalid base64url returns
/// 400 webauthn_assertion_invalid.
#[tokio::test]
async fn approve_assertion_post_rejects_invalid_credential_id_b64() {
    let (handle, store, _dir) = start_test_bridge().await;
    let local = handle.local_addr();
    let (nonce, csrf) = insert_sign_with_passkey(&store).await;
    let csrf_hex = hex::encode(csrf);

    let url = format!("http://{local}/approve/{nonce}/assertion");
    let payload = serde_json::json!({
        // "!!" is not valid base64url.
        "id": "!!INVALID!!",
        "rawId": "!!INVALID!!",
        "type": "public-key",
        "response": {
            "clientDataJSON": URL_SAFE_NO_PAD.encode(b"{}"),
            "authenticatorData": URL_SAFE_NO_PAD.encode([0u8; 37]),
            "signature": URL_SAFE_NO_PAD.encode(b"sig")
        }
    });

    let resp = client()
        .post(&url)
        .header("Host", local.to_string())
        .header("Origin", format!("http://{local}"))
        .header("X-Stellar-Approval-CSRF", csrf_hex)
        .json(&payload)
        .send()
        .await
        .expect("POST /approve/<nonce>/assertion");

    assert_eq!(resp.status().as_u16(), 400);
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["error"], "webauthn_assertion_invalid");

    handle.shutdown().await.expect("shutdown");
}

/// Valid base64url-encoded bytes that are not a valid DER ECDSA signature
/// trigger the `normalize_der_to_compact_low_s` failure and return
/// 400 webauthn_assertion_invalid.
#[tokio::test]
async fn approve_assertion_post_rejects_invalid_der_signature() {
    let (handle, store, _dir) = start_test_bridge().await;
    let local = handle.local_addr();
    let (nonce, csrf) = insert_sign_with_passkey(&store).await;
    let csrf_hex = hex::encode(csrf);

    // Produce bytes that decode from base64url successfully but are NOT a
    // valid DER ECDSA-secp256r1 signature (just random bytes).
    let not_der_sig = [0xFFu8; 32];

    let url = format!("http://{local}/approve/{nonce}/assertion");
    let payload = serde_json::json!({
        "id": URL_SAFE_NO_PAD.encode([0x01_u8; 16]),
        "rawId": URL_SAFE_NO_PAD.encode([0x01_u8; 16]),
        "type": "public-key",
        "response": {
            "clientDataJSON": URL_SAFE_NO_PAD.encode(b"{}"),
            "authenticatorData": URL_SAFE_NO_PAD.encode([0u8; 37]),
            "signature": URL_SAFE_NO_PAD.encode(not_der_sig)
        }
    });

    let resp = client()
        .post(&url)
        .header("Host", local.to_string())
        .header("Origin", format!("http://{local}"))
        .header("X-Stellar-Approval-CSRF", csrf_hex)
        .json(&payload)
        .send()
        .await
        .expect("POST /approve/<nonce>/assertion");

    assert_eq!(resp.status().as_u16(), 400);
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["error"], "webauthn_assertion_invalid");

    handle.shutdown().await.expect("shutdown");
}

/// When the assertion's `pre_verify_assertion` fails (valid DER signature but
/// signed for a different auth_digest than the entry's), returns
/// 400 webauthn_assertion_invalid.
///
/// Uses `valid_assertion_fixture` built for a DIFFERENT auth_digest than the
/// `[0xab; 32]` stored by `insert_sign_with_passkey`.
#[tokio::test]
async fn approve_assertion_post_rejects_signature_for_wrong_auth_digest() {
    // Build a fixture for a DIFFERENT digest than what insert_sign_with_passkey stores.
    let wrong_digest = [0xde_u8; 32]; // entry stores [0xab; 32]
    let credential_id = vec![0x01_u8; 16];
    let (pubkey, authenticator_data, client_data_json, signature_der) =
        valid_assertion_fixture(&wrong_digest);

    // Wire the lookup so the credential is "found", but the signature won't verify
    // against [0xab; 32] (the entry's auth_digest).
    let (handle, store, _dir) = start_test_bridge_with_lookup(Arc::new(TestPubkeyLookup::hit(
        credential_id.clone(),
        pubkey,
    )))
    .await;
    let local = handle.local_addr();
    let (nonce, csrf) = insert_sign_with_passkey(&store).await;
    let csrf_hex = hex::encode(csrf);
    let credential_id_b64 = URL_SAFE_NO_PAD.encode(&credential_id);

    let url = format!("http://{local}/approve/{nonce}/assertion");
    let payload = serde_json::json!({
        "id": credential_id_b64,
        "rawId": credential_id_b64,
        "type": "public-key",
        "response": {
            "clientDataJSON": URL_SAFE_NO_PAD.encode(&client_data_json),
            "authenticatorData": URL_SAFE_NO_PAD.encode(&authenticator_data),
            "signature": URL_SAFE_NO_PAD.encode(&signature_der)
        }
    });

    let resp = client()
        .post(&url)
        .header("Host", local.to_string())
        .header("Origin", format!("http://{local}"))
        .header("X-Stellar-Approval-CSRF", csrf_hex)
        .json(&payload)
        .send()
        .await
        .expect("POST /approve/<nonce>/assertion");

    assert_eq!(resp.status().as_u16(), 400);
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["error"], "webauthn_assertion_invalid");

    handle.shutdown().await.expect("shutdown");
}

/// credential_id mismatch: assertion `id` decodes to bytes that differ from
/// the entry's expected `credential_id` → 400 webauthn_assertion_invalid.
///
/// Uses a valid fixture (correct auth_digest, correct pubkey) but presents a
/// DIFFERENT credential_id (`[0x02; 16]` instead of `[0x01; 16]`).
/// `pre_verify_assertion` passes; the post-verify id-mismatch check fires.
#[tokio::test]
async fn approve_assertion_post_rejects_credential_id_mismatch() {
    let auth_digest = [0xab_u8; 32]; // matches insert_sign_with_passkey
    let registered_cred_id = vec![0x01_u8; 16]; // the one in the store entry
    let (pubkey, authenticator_data, client_data_json, signature_der) =
        valid_assertion_fixture(&auth_digest);

    let (handle, store, _dir) = start_test_bridge_with_lookup(Arc::new(TestPubkeyLookup::hit(
        registered_cred_id.clone(),
        pubkey,
    )))
    .await;
    let local = handle.local_addr();
    let (nonce, csrf) = insert_sign_with_passkey(&store).await;
    let csrf_hex = hex::encode(csrf);

    // Present a DIFFERENT credential_id in the payload.
    let wrong_cred_id = vec![0x02_u8; 16];
    let wrong_cred_id_b64 = URL_SAFE_NO_PAD.encode(&wrong_cred_id);

    let url = format!("http://{local}/approve/{nonce}/assertion");
    let payload = serde_json::json!({
        "id": wrong_cred_id_b64,
        "rawId": wrong_cred_id_b64,
        "type": "public-key",
        "response": {
            "clientDataJSON": URL_SAFE_NO_PAD.encode(&client_data_json),
            "authenticatorData": URL_SAFE_NO_PAD.encode(&authenticator_data),
            "signature": URL_SAFE_NO_PAD.encode(&signature_der)
        }
    });

    let resp = client()
        .post(&url)
        .header("Host", local.to_string())
        .header("Origin", format!("http://{local}"))
        .header("X-Stellar-Approval-CSRF", csrf_hex)
        .json(&payload)
        .send()
        .await
        .expect("POST /approve/<nonce>/assertion");

    assert_eq!(resp.status().as_u16(), 400);
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["error"], "webauthn_assertion_invalid");

    handle.shutdown().await.expect("shutdown");
}

/// Valid challenge + rp_id + registered pubkey, but the signed payload is
/// tampered after signing (a signature-counter byte in `authenticator_data` is
/// flipped), so the ECDSA signature no longer verifies. Forces the
/// signature-verification rejection specifically — not a challenge or rp_id
/// mismatch — and returns 400 webauthn_assertion_invalid.
#[tokio::test]
async fn approve_assertion_post_rejects_tampered_signature_with_valid_challenge() {
    let auth_digest = [0xab_u8; 32]; // matches insert_sign_with_passkey
    let credential_id = vec![0x01_u8; 16];
    let (pubkey, mut authenticator_data, client_data_json, signature_der) =
        valid_assertion_fixture(&auth_digest);

    // Flip a signature-counter byte (index 36) — outside the rp_id-hash region
    // (bytes 0..32) and the flags byte (32) — so only the signed payload
    // changes, leaving the rp_id-hash and challenge checks intact.
    authenticator_data[36] ^= 0x01;

    let (handle, store, _dir) = start_test_bridge_with_lookup(Arc::new(TestPubkeyLookup::hit(
        credential_id.clone(),
        pubkey,
    )))
    .await;
    let local = handle.local_addr();
    let (nonce, csrf) = insert_sign_with_passkey(&store).await;
    let csrf_hex = hex::encode(csrf);
    let credential_id_b64 = URL_SAFE_NO_PAD.encode(&credential_id);

    let url = format!("http://{local}/approve/{nonce}/assertion");
    let payload = serde_json::json!({
        "id": credential_id_b64,
        "rawId": credential_id_b64,
        "type": "public-key",
        "response": {
            "clientDataJSON": URL_SAFE_NO_PAD.encode(&client_data_json),
            "authenticatorData": URL_SAFE_NO_PAD.encode(&authenticator_data),
            "signature": URL_SAFE_NO_PAD.encode(&signature_der)
        }
    });

    let resp = client()
        .post(&url)
        .header("Host", local.to_string())
        .header("Origin", format!("http://{local}"))
        .header("X-Stellar-Approval-CSRF", csrf_hex)
        .json(&payload)
        .send()
        .await
        .expect("POST /approve/<nonce>/assertion");

    assert_eq!(resp.status().as_u16(), 400);
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["error"], "webauthn_assertion_invalid");

    handle.shutdown().await.expect("shutdown");
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /approve/<nonce>/cancel — additional error paths
// ─────────────────────────────────────────────────────────────────────────────

/// CSRF header that is syntactically valid hex but wrong value (mismatch)
/// on POST /approve/<nonce>/cancel returns 403 csrf_invalid.
///
/// Distinct from the missing-CSRF test: the header IS present and IS valid hex,
/// but the 32-byte value does not match the stored token.
#[tokio::test]
async fn approve_cancel_rejects_wrong_csrf() {
    let (handle, store, _dir) = start_test_bridge().await;
    let local = handle.local_addr();
    let (nonce, _correct_csrf) = insert_sign_with_passkey(&store).await;

    // All-zeroes CSRF is a valid hex string but will never match the generated token.
    let wrong_csrf_hex = hex::encode([0x00_u8; 32]);
    let url = format!("http://{local}/approve/{nonce}/cancel");

    let resp = client()
        .post(&url)
        .header("Host", local.to_string())
        .header("Origin", format!("http://{local}"))
        .header("X-Stellar-Approval-CSRF", wrong_csrf_hex)
        .send()
        .await
        .expect("POST /approve/<nonce>/cancel");

    assert_eq!(resp.status().as_u16(), 403);
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["error"], "csrf_invalid");

    // The entry must NOT have been removed.
    let guard = store.lock().await;
    assert!(
        guard.get(&nonce).is_some(),
        "wrong-CSRF cancel must not remove the entry"
    );
    drop(guard);

    handle.shutdown().await.expect("shutdown");
}

/// CSRF header that contains non-hex characters on POST /approve/<nonce>/cancel
/// returns 403 csrf_invalid (fails `CsrfToken::from_hex` before compare).
#[tokio::test]
async fn approve_cancel_rejects_non_hex_csrf() {
    let (handle, store, _dir) = start_test_bridge().await;
    let local = handle.local_addr();
    let (nonce, _csrf) = insert_sign_with_passkey(&store).await;

    let non_hex_csrf = format!("{}{}", "a".repeat(63), "z");
    assert_eq!(non_hex_csrf.len(), 64);

    let url = format!("http://{local}/approve/{nonce}/cancel");
    let resp = client()
        .post(&url)
        .header("Host", local.to_string())
        .header("Origin", format!("http://{local}"))
        .header("X-Stellar-Approval-CSRF", non_hex_csrf)
        .send()
        .await
        .expect("POST /approve/<nonce>/cancel");

    assert_eq!(resp.status().as_u16(), 403);
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["error"], "csrf_invalid");

    handle.shutdown().await.expect("shutdown");
}

/// Happy-path cancel of a `RegisterPasskey` entry: correct CSRF → 204 + entry removed.
///
/// The cancel handler accepts both `SignWithPasskey` and `RegisterPasskey` kinds.
/// This test exercises the `RegisterPasskey` arm of the kind-match in the handler.
#[tokio::test]
async fn approve_cancel_with_correct_csrf_removes_register_passkey_entry() {
    let (handle, store, _dir) = start_test_bridge().await;
    let local = handle.local_addr();
    let (nonce, csrf) = insert_register_passkey(&store).await;

    let csrf_hex = hex::encode(csrf);
    let url = format!("http://{local}/approve/{nonce}/cancel");

    let resp = client()
        .post(&url)
        .header("Host", local.to_string())
        .header("Origin", format!("http://{local}"))
        .header("X-Stellar-Approval-CSRF", csrf_hex)
        .send()
        .await
        .expect("POST /approve/<nonce>/cancel");

    assert_eq!(resp.status().as_u16(), 204);
    let body_bytes = resp.bytes().await.expect("body bytes");
    assert!(
        body_bytes.is_empty(),
        "204 cancel must return empty body, got {} bytes",
        body_bytes.len()
    );

    let guard = store.lock().await;
    assert!(
        guard.get(&nonce).is_none(),
        "RegisterPasskey entry must be removed after successful cancel"
    );
    drop(guard);

    handle.shutdown().await.expect("shutdown");
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /register/<nonce>/credential — additional error paths
// ─────────────────────────────────────────────────────────────────────────────

/// CSRF header that is 64 chars but contains a non-hex character on
/// POST /register/<nonce>/credential returns 403 csrf_invalid.
#[tokio::test]
async fn register_post_rejects_csrf_non_hex() {
    let (handle, store, _dir) = start_test_bridge().await;
    let local = handle.local_addr();
    let (nonce, _csrf) = insert_register_passkey(&store).await;

    let non_hex_csrf = format!("{}{}", "a".repeat(63), "z");
    assert_eq!(non_hex_csrf.len(), 64);

    let url = format!("http://{local}/register/{nonce}/credential");
    let payload = serde_json::json!({
        "id": "AAAA",
        "rawId": "AAAA",
        "type": "public-key",
        "response": {
            "clientDataJSON": "AAAA",
            "attestationObject": "AAAA",
            "publicKeySec1B64": "AAAA"
        }
    });

    let resp = client()
        .post(&url)
        .header("Host", local.to_string())
        .header("Origin", format!("http://{local}"))
        .header("X-Stellar-Approval-CSRF", non_hex_csrf)
        .json(&payload)
        .send()
        .await
        .expect("POST /register/<nonce>/credential");

    assert_eq!(resp.status().as_u16(), 403);
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["error"], "csrf_invalid");

    handle.shutdown().await.expect("shutdown");
}

/// Unknown nonce on POST /register/<nonce>/credential returns
/// 400 approval_not_found (nonce absence is indistinguishable from expiry).
#[tokio::test]
async fn register_post_returns_400_for_unknown_nonce() {
    let (handle, _store, _dir) = start_test_bridge().await;
    let local = handle.local_addr();

    let csrf_hex = hex::encode([0x00_u8; 32]);
    let url = format!("http://{local}/register/no-such-nonce/credential");
    let payload = serde_json::json!({
        "id": "AAAA",
        "rawId": "AAAA",
        "type": "public-key",
        "response": {
            "clientDataJSON": "AAAA",
            "attestationObject": "AAAA",
            "publicKeySec1B64": "AAAA"
        }
    });

    let resp = client()
        .post(&url)
        .header("Host", local.to_string())
        .header("Origin", format!("http://{local}"))
        .header("X-Stellar-Approval-CSRF", csrf_hex)
        .json(&payload)
        .send()
        .await
        .expect("POST /register/no-such-nonce/credential");

    assert_eq!(resp.status().as_u16(), 400);
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["error"], "approval_not_found");

    handle.shutdown().await.expect("shutdown");
}

/// `id` field containing invalid base64url on POST /register/<nonce>/credential
/// returns 400 webauthn_registration_invalid.
///
/// Requires valid CSRF so the field-decode path is reached.
#[tokio::test]
async fn register_post_rejects_invalid_credential_id_b64() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    let (handle, store, _dir) = start_test_bridge().await;
    let local = handle.local_addr();
    let (nonce, csrf) = insert_register_passkey(&store).await;
    let csrf_hex = hex::encode(csrf);

    // Build a valid 65-byte pubkey for the publicKeySec1B64 field so only the id decode fails.
    let mut pubkey_sec1 = [0u8; 65];
    pubkey_sec1[0] = 0x04;
    let pubkey_b64 = STANDARD.encode(pubkey_sec1);

    let url = format!("http://{local}/register/{nonce}/credential");
    let payload = serde_json::json!({
        // "!!" is not valid base64url.
        "id": "!!INVALID!!",
        "rawId": "!!INVALID!!",
        "type": "public-key",
        "response": {
            "clientDataJSON": URL_SAFE_NO_PAD.encode(b"{}"),
            "attestationObject": "",
            "publicKeySec1B64": pubkey_b64
        }
    });

    let resp = client()
        .post(&url)
        .header("Host", local.to_string())
        .header("Origin", format!("http://{local}"))
        .header("X-Stellar-Approval-CSRF", csrf_hex)
        .json(&payload)
        .send()
        .await
        .expect("POST /register/<nonce>/credential");

    assert_eq!(resp.status().as_u16(), 400);
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["error"], "webauthn_registration_invalid");

    handle.shutdown().await.expect("shutdown");
}

/// `publicKeySec1B64` field that is not valid standard base64 returns
/// 400 webauthn_registration_invalid.
///
/// The bridge decodes this field with `STANDARD.decode` (not URL_SAFE_NO_PAD).
#[tokio::test]
async fn register_post_rejects_invalid_public_key_b64() {
    let (handle, store, _dir) = start_test_bridge().await;
    let local = handle.local_addr();
    let (nonce, csrf) = insert_register_passkey(&store).await;
    let csrf_hex = hex::encode(csrf);

    let credential_id_b64 = URL_SAFE_NO_PAD.encode([0x42u8; 16]);
    let url = format!("http://{local}/register/{nonce}/credential");
    let payload = serde_json::json!({
        "id": credential_id_b64,
        "rawId": credential_id_b64,
        "type": "public-key",
        "response": {
            "clientDataJSON": URL_SAFE_NO_PAD.encode(b"{}"),
            "attestationObject": "",
            // "!!" is not valid standard base64.
            "publicKeySec1B64": "!!INVALID!!"
        }
    });

    let resp = client()
        .post(&url)
        .header("Host", local.to_string())
        .header("Origin", format!("http://{local}"))
        .header("X-Stellar-Approval-CSRF", csrf_hex)
        .json(&payload)
        .send()
        .await
        .expect("POST /register/<nonce>/credential");

    assert_eq!(resp.status().as_u16(), 400);
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["error"], "webauthn_registration_invalid");

    handle.shutdown().await.expect("shutdown");
}

/// Non-empty `attestationObject` that is not valid base64url returns
/// 400 webauthn_registration_invalid.
///
/// The bridge only decodes `attestationObject` when it is non-empty; an empty
/// string maps to `None` (no error). This test covers the non-empty invalid path.
#[tokio::test]
async fn register_post_rejects_invalid_attestation_object_b64() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    let (handle, store, _dir) = start_test_bridge().await;
    let local = handle.local_addr();
    let (nonce, csrf) = insert_register_passkey(&store).await;
    let csrf_hex = hex::encode(csrf);

    let credential_id_b64 = URL_SAFE_NO_PAD.encode([0x42u8; 16]);
    let mut pubkey_sec1 = [0u8; 65];
    pubkey_sec1[0] = 0x04;
    let pubkey_b64 = STANDARD.encode(pubkey_sec1);

    let url = format!("http://{local}/register/{nonce}/credential");
    let payload = serde_json::json!({
        "id": credential_id_b64,
        "rawId": credential_id_b64,
        "type": "public-key",
        "response": {
            "clientDataJSON": URL_SAFE_NO_PAD.encode(b"{}"),
            // Non-empty but invalid base64url.
            "attestationObject": "!!INVALID!!",
            "publicKeySec1B64": pubkey_b64
        }
    });

    let resp = client()
        .post(&url)
        .header("Host", local.to_string())
        .header("Origin", format!("http://{local}"))
        .header("X-Stellar-Approval-CSRF", csrf_hex)
        .json(&payload)
        .send()
        .await
        .expect("POST /register/<nonce>/credential");

    assert_eq!(resp.status().as_u16(), 400);
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["error"], "webauthn_registration_invalid");

    handle.shutdown().await.expect("shutdown");
}

/// `RegistrationInput::new` validation failure: `public_key_sec1_b64` decodes
/// to bytes that do NOT satisfy the 65-byte / `0x04` prefix constraint.
///
/// Feeds a 16-byte payload (too short); the `RegistrationInput::new` constructor
/// rejects it → 400 webauthn_registration_invalid.
#[tokio::test]
async fn register_post_rejects_pubkey_wrong_length() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    let (handle, store, _dir) = start_test_bridge().await;
    let local = handle.local_addr();
    let (nonce, csrf) = insert_register_passkey(&store).await;
    let csrf_hex = hex::encode(csrf);

    let credential_id_b64 = URL_SAFE_NO_PAD.encode([0x42u8; 16]);
    // A 16-byte blob: valid standard base64 but wrong length (not 65 bytes).
    let short_pubkey_b64 = STANDARD.encode([0x04u8; 16]);

    let url = format!("http://{local}/register/{nonce}/credential");
    let payload = serde_json::json!({
        "id": credential_id_b64,
        "rawId": credential_id_b64,
        "type": "public-key",
        "response": {
            "clientDataJSON": URL_SAFE_NO_PAD.encode(b"{}"),
            "attestationObject": "",
            "publicKeySec1B64": short_pubkey_b64
        }
    });

    let resp = client()
        .post(&url)
        .header("Host", local.to_string())
        .header("Origin", format!("http://{local}"))
        .header("X-Stellar-Approval-CSRF", csrf_hex)
        .json(&payload)
        .send()
        .await
        .expect("POST /register/<nonce>/credential");

    assert_eq!(resp.status().as_u16(), 400);
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["error"], "webauthn_registration_invalid");

    handle.shutdown().await.expect("shutdown");
}

/// `RegistrationInput::new` validation failure: 65-byte key that does NOT have
/// the `0x04` uncompressed-point prefix.
///
/// All bytes are `0x01` (no `0x04` at index 0); the validator rejects this →
/// 400 webauthn_registration_invalid.
#[tokio::test]
async fn register_post_rejects_pubkey_wrong_prefix() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    let (handle, store, _dir) = start_test_bridge().await;
    let local = handle.local_addr();
    let (nonce, csrf) = insert_register_passkey(&store).await;
    let csrf_hex = hex::encode(csrf);

    let credential_id_b64 = URL_SAFE_NO_PAD.encode([0x42u8; 16]);
    // 65 bytes, all `0x01` — wrong prefix (not `0x04`).
    let wrong_prefix_pubkey_b64 = STANDARD.encode([0x01u8; 65]);

    let url = format!("http://{local}/register/{nonce}/credential");
    let payload = serde_json::json!({
        "id": credential_id_b64,
        "rawId": credential_id_b64,
        "type": "public-key",
        "response": {
            "clientDataJSON": URL_SAFE_NO_PAD.encode(b"{}"),
            "attestationObject": "",
            "publicKeySec1B64": wrong_prefix_pubkey_b64
        }
    });

    let resp = client()
        .post(&url)
        .header("Host", local.to_string())
        .header("Origin", format!("http://{local}"))
        .header("X-Stellar-Approval-CSRF", csrf_hex)
        .json(&payload)
        .send()
        .await
        .expect("POST /register/<nonce>/credential");

    assert_eq!(resp.status().as_u16(), 400);
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["error"], "webauthn_registration_invalid");

    handle.shutdown().await.expect("shutdown");
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /register/<nonce> — wrong-kind via PaymentSimulated nonce
// ─────────────────────────────────────────────────────────────────────────────

/// `GET /register/<nonce>` on a `PaymentSimulated` entry (not `RegisterPasskey`)
/// returns 400 + `approval_kind_mismatch`.
///
/// The GET path deliberately distinguishes wrong-kind from not-found because
/// the caller already knows the nonce (it navigated to this URL).
#[tokio::test]
async fn register_get_returns_400_for_payment_simulated_nonce() {
    let (handle, store, _dir) = start_test_bridge().await;
    let local = handle.local_addr();
    let nonce = insert_payment_simulated(&store).await;

    let url = format!("http://{local}/register/{nonce}");
    let resp = client()
        .get(&url)
        .header("Host", local.to_string())
        .send()
        .await
        .expect("GET /register/<payment-simulated-nonce>");

    assert_eq!(resp.status().as_u16(), 400);
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["error"], "approval_kind_mismatch");

    handle.shutdown().await.expect("shutdown");
}

// ─────────────────────────────────────────────────────────────────────────────
// Origin-header enforcement on POST
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn origin_layer_blocks_post_without_origin() {
    let (handle, _store, _dir) = start_test_bridge().await;
    let local = handle.local_addr();
    // POST to any endpoint without an Origin header must be rejected by the
    // origin-allowlist middleware.
    let url = format!("http://{local}/approve/fake-nonce/cancel");

    let resp = client()
        .post(&url)
        .header("Host", local.to_string())
        // No Origin header.
        .send()
        .await
        .expect("POST without Origin");

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["error"], "origin_header_rejected");

    handle.shutdown().await.expect("shutdown");
}
