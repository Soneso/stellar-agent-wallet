//! Router-level HTTP tests for the interactive operator-enrollment server.
//!
//! These drive the assembled `Router` (state + the full middleware stack)
//! via `tower::ServiceExt::oneshot`, exercising the Host/Origin/security
//! header middleware exactly as a real request would.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics acceptable in unit tests"
)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex as StdMutex};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, Request, StatusCode, header};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::json;
use stellar_agent_loopback_http::brand::PageIdentity;
use tempfile::TempDir;
use tokio::sync::oneshot;
use tower::ServiceExt as _;

use stellar_agent_core::approval::operator_credentials::{
    OperatorApprovalCredential, OperatorApprovalCredentialStore,
};

use crate::auth::{AuthState, OpaqueToken, SESSION_IDLE_TIMEOUT, SessionClock, SessionPurpose};

use super::confirmation::StagedEnrollment;
use super::registration::REGISTRATION_CHALLENGE_TTL;
use super::test_support::{RegistrationBuilder, SoftwareRegistrar};
use super::{Ceremony, OperatorEnrollState, build_router, expected_origin};

const HOST: &str = "127.0.0.1:9999";
const ORIGIN: &str = "http://127.0.0.1:9999";
/// The origin the page runs at, which `clientDataJSON` names.
const PAGE_ORIGIN: &str = "http://localhost:9999";

struct Harness {
    router: Router,
    state: Arc<OperatorEnrollState>,
    store_path: std::path::PathBuf,
    bootstrap_hex: String,
    cookie_name: String,
    clock: SessionClock,
    proof: StdMutex<Option<String>>,
    completion_rx: oneshot::Receiver<StagedEnrollment>,
    _dir: TempDir,
}

impl Harness {
    fn with_label_prefill(label_prefill: Option<String>) -> Self {
        let dir = TempDir::new().unwrap();
        let store_path = dir.path().join("default.toml");
        let (tx, rx) = oneshot::channel();
        let bootstrap = OpaqueToken::generate();
        let bootstrap_hex = bootstrap.to_hex();
        let clock = SessionClock::manual();
        let auth = AuthState::with_clock(bootstrap, SessionPurpose::OperatorEnroll, clock.clone());
        let cookie_name = auth.cookie_name().to_owned();
        let local_addr: SocketAddr = HOST.parse().unwrap();
        let state = Arc::new(OperatorEnrollState {
            purpose: super::EnrollmentPurpose::RemoteOperator,
            profile: "default".to_owned(),
            auth: StdMutex::new(auth),
            store: Some(OperatorApprovalCredentialStore::new(store_path.clone())),
            expected_origin: expected_origin(local_addr),
            rp_id: super::REGISTRATION_RP_ID.to_owned(),
            signed: None,
            label_prefill,
            identity: PageIdentity::neutral(),
            ceremony: StdMutex::new(Ceremony {
                challenge: None,
                completion: Some(tx),
            }),
        });
        let router = build_router(Arc::clone(&state), local_addr);
        Self {
            router,
            state,
            store_path,
            bootstrap_hex,
            cookie_name,
            clock,
            proof: StdMutex::new(None),
            completion_rx: rx,
            _dir: dir,
        }
    }

    fn new() -> Self {
        Self::with_label_prefill(None)
    }

    /// Pre-seed the store, bypassing the HTTP layer entirely (as if a prior
    /// enrollment had already used this credential id).
    fn seeded(credential: OperatorApprovalCredential) -> Self {
        let h = Self::new();
        let seed_store = OperatorApprovalCredentialStore::new(h.store_path.clone());
        seed_store.enroll(credential).unwrap();
        h
    }

    async fn get_raw(&self, path: &str, cookie: Option<&str>) -> (StatusCode, String) {
        let (status, _headers, body) = self.get_with_headers(path, cookie).await;
        (status, body)
    }

    async fn get_with_headers(
        &self,
        path: &str,
        cookie: Option<&str>,
    ) -> (StatusCode, HeaderMap, String) {
        let mut builder = Request::builder()
            .method("GET")
            .uri(path)
            .header(header::HOST, HOST);
        if let Some(c) = cookie {
            builder = builder.header(header::COOKIE, format!("{}={c}", self.cookie_name));
        }
        let req = builder.body(Body::empty()).unwrap();
        let resp = self.router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        (status, headers, String::from_utf8(body.to_vec()).unwrap())
    }

    async fn get(&self, path: &str, cookie: &str) -> (StatusCode, String) {
        self.get_raw(path, Some(cookie)).await
    }

    /// POSTs `body` with the session proof the last bootstrap delivered,
    /// when there is one.
    async fn post(
        &self,
        path: &str,
        cookie: Option<&str>,
        csrf: Option<&str>,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let proof = self.proof.lock().unwrap().clone();
        self.post_with_proof(path, cookie, csrf, proof.as_deref(), body)
            .await
    }

    async fn post_with_proof(
        &self,
        path: &str,
        cookie: Option<&str>,
        csrf: Option<&str>,
        proof: Option<&str>,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let (status, _headers, parsed) = self
            .post_with_headers(path, cookie, csrf, proof, body)
            .await;
        (status, parsed)
    }

    async fn post_with_headers(
        &self,
        path: &str,
        cookie: Option<&str>,
        csrf: Option<&str>,
        proof: Option<&str>,
        body: serde_json::Value,
    ) -> (StatusCode, HeaderMap, serde_json::Value) {
        let mut builder = Request::builder()
            .method("POST")
            .uri(path)
            .header(header::HOST, HOST)
            .header(header::ORIGIN, ORIGIN)
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(c) = cookie {
            builder = builder.header(header::COOKIE, format!("{}={c}", self.cookie_name));
        }
        if let Some(c) = csrf {
            builder = builder.header("x-stellar-approval-csrf", c);
        }
        if let Some(p) = proof {
            builder = builder.header("x-session-proof", p);
        }
        let req = builder.body(Body::from(body.to_string())).unwrap();
        let resp = self.router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let parsed: serde_json::Value = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
        };
        (status, headers, parsed)
    }

    /// Exchanges the bootstrap token via `GET /bootstrap/{token}`, keeps the
    /// session proof the bootstrap page carries, and returns the cookie
    /// value.
    async fn bootstrap(&self) -> String {
        let req = Request::builder()
            .method("GET")
            .uri(format!("/bootstrap/{}", self.bootstrap_hex))
            .header(header::HOST, HOST)
            .body(Body::empty())
            .unwrap();
        let resp = self.router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let set_cookie = resp
            .headers()
            .get(header::SET_COOKIE)
            .expect("bootstrap exchange must set a session cookie")
            .to_str()
            .unwrap()
            .to_owned();
        let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let island = extract_island(
            std::str::from_utf8(&bytes).unwrap(),
            "session-bootstrap-data",
        );
        assert_eq!(island["next"], "/enroll");
        assert_eq!(
            island["storageKey"],
            "stellar-agent-operator-enroll-session-proof"
        );
        *self.proof.lock().unwrap() = Some(island["proof"].as_str().unwrap().to_owned());
        extract_cookie_value(&self.cookie_name, &set_cookie)
    }

    /// The session proof the last bootstrap delivered.
    fn proof(&self) -> String {
        self.proof
            .lock()
            .unwrap()
            .clone()
            .expect("bootstrap delivered a proof")
    }

    /// `POST /enroll/challenge` with the session's CSRF value and proof;
    /// returns the challenge it issued.
    async fn challenge(&self, cookie: &str, csrf: &str) -> [u8; 32] {
        let (status, body) = self
            .post("/enroll/challenge", Some(cookie), Some(csrf), json!({}))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["rp_id"], "localhost");
        assert_eq!(body["alg"], -7);
        assert_eq!(body["user_verification"], "required");
        assert_eq!(body["attestation"], "none");
        URL_SAFE_NO_PAD
            .decode(body["challenge"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    }

    /// The registration the completion latch handed over, when one was.
    fn staged(&mut self) -> Option<StagedEnrollment> {
        self.completion_rx.try_recv().ok()
    }

    /// Asserts that no registration was staged and the store is empty.
    fn assert_nothing_staged_or_stored(&mut self) {
        assert!(matches!(
            self.completion_rx.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        let store = OperatorApprovalCredentialStore::new(self.store_path.clone());
        assert!(store.list().unwrap().is_empty());
    }

    /// Establishes a session and returns `(session_cookie, csrf_hex)` read
    /// from the rendered `/enroll` page's data island.
    async fn establish_session(&self) -> (String, String) {
        let cookie = self.bootstrap().await;
        let (status, body) = self.get("/enroll", &cookie).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "GET /enroll after bootstrap: {body}"
        );
        let csrf = extract_csrf(&body);
        (cookie, csrf)
    }
}

fn extract_cookie_value(cookie_name: &str, set_cookie: &str) -> String {
    let prefix = format!("{cookie_name}=");
    let after = set_cookie
        .strip_prefix(&prefix)
        .expect("Set-Cookie must carry the session cookie name");
    after
        .split(';')
        .next()
        .expect("Set-Cookie must carry a value")
        .to_owned()
}

fn extract_island(html: &str, id: &str) -> serde_json::Value {
    let open = format!(r#"<script type="application/json" id="{id}""#);
    let tag = html.find(&open).expect("data island opening tag");
    let start = tag + html[tag..].find('>').expect("data island opening tag end") + 1;
    let rest = &html[start..];
    let end = rest.find("</script>").expect("data island closing tag");
    serde_json::from_str(&rest[..end]).expect("data island must be valid JSON")
}

fn extract_csrf(html: &str) -> String {
    extract_island(html, "enroll-data")["csrfToken"]
        .as_str()
        .expect("csrfToken must be a string")
        .to_owned()
}

fn valid_credential_id_b64(seed: u8) -> String {
    URL_SAFE_NO_PAD.encode([seed; 16])
}

fn valid_pubkey_b64(seed: u8) -> String {
    URL_SAFE_NO_PAD.encode(registrar(seed).public_key_sec1())
}

/// A software authenticator with a real P-256 key and the credential ID
/// `[seed; 16]`.
fn registrar(seed: u8) -> SoftwareRegistrar {
    SoftwareRegistrar::new([seed; 32], vec![seed; 16])
}

/// The page's registration response from `registrar(seed)` over
/// `challenge`.
fn registration(seed: u8, challenge: &[u8; 32]) -> RegistrationBuilder {
    registrar(seed).builder(challenge, PAGE_ORIGIN)
}

/// A verified registration body over `challenge`.
fn valid_body(seed: u8, challenge: &[u8; 32]) -> serde_json::Value {
    registration(seed, challenge).json()
}

/// The credential metadata alone, with a client-chosen counter: the body
/// that carries no ceremony.
fn metadata_only_body(seed: u8) -> serde_json::Value {
    json!({
        "credential_id_b64url": valid_credential_id_b64(seed),
        "public_key_sec1_b64": valid_pubkey_b64(seed),
        "label": "laptop",
        "sign_count": 3,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Bootstrap → session-cookie gate
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn enroll_page_without_session_cookie_is_not_found() {
    let h = Harness::new();
    let (status, _body) = h.get_raw("/enroll", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn bootstrap_wrong_token_is_not_found() {
    let h = Harness::new();
    let req = Request::builder()
        .method("GET")
        .uri(format!("/bootstrap/{}", "f".repeat(64)))
        .header(header::HOST, HOST)
        .body(Body::empty())
        .unwrap();
    let resp = h.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn bootstrap_token_is_single_use() {
    let h = Harness::new();
    let _cookie = h.bootstrap().await;

    // A second exchange of the same token must 404: it was consumed by the
    // first successful exchange.
    let req = Request::builder()
        .method("GET")
        .uri(format!("/bootstrap/{}", h.bootstrap_hex))
        .header(header::HOST, HOST)
        .body(Body::empty())
        .unwrap();
    let resp = h.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn bootstrap_exchange_returns_the_proof_page_and_sets_session_cookie() {
    let h = Harness::new();
    let req = Request::builder()
        .method("GET")
        .uri(format!("/bootstrap/{}", h.bootstrap_hex))
        .header(header::HOST, HOST)
        .body(Body::empty())
        .unwrap();
    let resp = h.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().get(header::LOCATION).is_none());
    let set_cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    assert!(set_cookie.starts_with(&format!("{}=", h.cookie_name)));
    assert!(set_cookie.contains("HttpOnly"));
    assert!(set_cookie.contains("SameSite=Strict"));
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let html = std::str::from_utf8(&bytes).unwrap();
    assert!(html.contains(r#"<script src="/static/session-bootstrap.js"></script>"#));
    let island = extract_island(html, "session-bootstrap-data");
    assert_eq!(island["proof"].as_str().unwrap().len(), 64);
}

#[tokio::test]
async fn enroll_page_reachable_after_bootstrap_and_carries_session_csrf() {
    let h = Harness::new();
    let (cookie, csrf) = h.establish_session().await;
    assert_eq!(csrf.len(), 64);

    let (status, body) = h.get("/enroll", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains(r#""rpId":"localhost""#));
    assert!(body.contains(&csrf));
    assert!(body.contains(r#"id="label-input""#));

    // The session-derived CSRF must actually authorize both POSTs.
    let challenge = h.challenge(&cookie, &csrf).await;
    let (post_status, post_body) = h
        .post(
            "/enroll/credential",
            Some(&cookie),
            Some(&csrf),
            valid_body(1, &challenge),
        )
        .await;
    assert_eq!(post_status, StatusCode::OK, "body: {post_body}");
    assert_eq!(post_body["status"], "awaiting_confirmation");
}

#[tokio::test]
async fn enroll_page_carries_label_prefill_when_configured() {
    let h = Harness::with_label_prefill(Some("laptop".to_owned()));
    let (cookie, _csrf) = h.establish_session().await;
    let (status, body) = h.get("/enroll", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains(r#"value="laptop""#));
}

#[tokio::test]
async fn operator_enroll_js_without_session_cookie_is_not_found() {
    let h = Harness::new();
    let req = Request::builder()
        .method("GET")
        .uri("/static/operator-enroll.js")
        .header(header::HOST, HOST)
        .body(Body::empty())
        .unwrap();
    let resp = h.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn operator_enroll_js_is_served_with_javascript_content_type_after_bootstrap() {
    let h = Harness::new();
    let (cookie, _csrf) = h.establish_session().await;
    let req = Request::builder()
        .method("GET")
        .uri("/static/operator-enroll.js")
        .header(header::HOST, HOST)
        .header(header::COOKIE, format!("{}={cookie}", h.cookie_name))
        .body(Body::empty())
        .unwrap();
    let resp = h.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let content_type = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    assert!(content_type.starts_with("application/javascript"));
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    assert!(
        std::str::from_utf8(&bytes)
            .unwrap()
            .contains("navigator.credentials")
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /enroll/credential — session + CSRF gate
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn post_without_session_cookie_is_not_found() {
    let h = Harness::new();
    let (_cookie, csrf) = h.establish_session().await;
    // Session gate precedes CSRF: no cookie at all must 404, even with a
    // structurally valid CSRF value in hand.
    let (status, _body) = h
        .post(
            "/enroll/credential",
            None,
            Some(&csrf),
            valid_body(1, &[0; 32]),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn post_missing_csrf_is_rejected() {
    let h = Harness::new();
    let (cookie, _csrf) = h.establish_session().await;
    let (status, body) = h
        .post(
            "/enroll/credential",
            Some(&cookie),
            None,
            valid_body(1, &[0; 32]),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "csrf_invalid");
}

#[tokio::test]
async fn post_wrong_csrf_is_rejected() {
    let h = Harness::new();
    let (cookie, _csrf) = h.establish_session().await;
    let (status, body) = h
        .post(
            "/enroll/credential",
            Some(&cookie),
            Some(&"f".repeat(64)),
            valid_body(2, &[0; 32]),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "csrf_invalid");
}

#[tokio::test]
async fn post_credential_id_too_short_is_rejected() {
    let h = Harness::new();
    let (cookie, csrf) = h.establish_session().await;
    let challenge = h.challenge(&cookie, &csrf).await;
    let mut body = valid_body(3, &challenge);
    body["credential_id_b64url"] = json!(URL_SAFE_NO_PAD.encode([0x01u8; 8]));
    let (status, body) = h
        .post("/enroll/credential", Some(&cookie), Some(&csrf), body)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "credential_id_invalid");
}

#[tokio::test]
async fn post_credential_id_too_long_is_rejected() {
    let h = Harness::new();
    let (cookie, csrf) = h.establish_session().await;
    let challenge = h.challenge(&cookie, &csrf).await;
    let mut body = valid_body(4, &challenge);
    body["credential_id_b64url"] = json!(URL_SAFE_NO_PAD.encode([0x01u8; 65]));
    let (status, body) = h
        .post("/enroll/credential", Some(&cookie), Some(&csrf), body)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "credential_id_invalid");
}

#[tokio::test]
async fn post_credential_id_not_base64url_is_rejected() {
    let h = Harness::new();
    let (cookie, csrf) = h.establish_session().await;
    let challenge = h.challenge(&cookie, &csrf).await;
    let mut body = valid_body(5, &challenge);
    body["credential_id_b64url"] = json!("not base64url!!");
    let (status, body) = h
        .post("/enroll/credential", Some(&cookie), Some(&csrf), body)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "credential_id_invalid");
}

#[tokio::test]
async fn post_pubkey_wrong_length_is_rejected() {
    let h = Harness::new();
    let (cookie, csrf) = h.establish_session().await;
    let challenge = h.challenge(&cookie, &csrf).await;
    let mut body = valid_body(6, &challenge);
    body["public_key_sec1_b64"] = json!(URL_SAFE_NO_PAD.encode([0x04u8; 10]));
    let (status, body) = h
        .post("/enroll/credential", Some(&cookie), Some(&csrf), body)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "public_key_invalid");
}

#[tokio::test]
async fn post_pubkey_wrong_prefix_is_rejected() {
    let h = Harness::new();
    let (cookie, csrf) = h.establish_session().await;
    let challenge = h.challenge(&cookie, &csrf).await;
    let mut body = valid_body(7, &challenge);
    let mut bytes = vec![0x02u8; 65];
    bytes[0] = 0x02;
    body["public_key_sec1_b64"] = json!(URL_SAFE_NO_PAD.encode(bytes));
    let (status, body) = h
        .post("/enroll/credential", Some(&cookie), Some(&csrf), body)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "public_key_invalid");
}

#[tokio::test]
async fn post_label_empty_is_rejected() {
    let h = Harness::new();
    let (cookie, csrf) = h.establish_session().await;
    let challenge = h.challenge(&cookie, &csrf).await;
    let mut body = valid_body(8, &challenge);
    body["label"] = json!("   ");
    let (status, body) = h
        .post("/enroll/credential", Some(&cookie), Some(&csrf), body)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "label_invalid");
}

#[tokio::test]
async fn post_label_oversized_is_rejected() {
    let h = Harness::new();
    let (cookie, csrf) = h.establish_session().await;
    let challenge = h.challenge(&cookie, &csrf).await;
    let mut body = valid_body(9, &challenge);
    body["label"] = json!("x".repeat(65));
    let (status, body) = h
        .post("/enroll/credential", Some(&cookie), Some(&csrf), body)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "label_invalid");
}

/// Every C0 control, DEL and every C1 control refuses with `label_invalid`
/// at the start, in the middle and at the end of an otherwise valid label,
/// where trimming would otherwise remove it, and stages nothing. Surrounding
/// spaces still trim: `" laptop "` stages `laptop`.
#[tokio::test]
async fn post_label_with_any_control_at_any_position_is_rejected() {
    let mut h = Harness::new();
    let (cookie, csrf) = h.establish_session().await;
    let challenge = h.challenge(&cookie, &csrf).await;
    let controls = (0x00..=0x1f_u32)
        .chain(std::iter::once(0x7f))
        .chain(0x80..=0x9f)
        .map(|code| char::from_u32(code).unwrap());
    for control in controls {
        assert!(control.is_control(), "{control:?}");
        for label in [
            format!("{control}laptop"),
            format!("lap{control}top"),
            format!("laptop{control}"),
        ] {
            let mut body = valid_body(12, &challenge);
            body["label"] = json!(label);
            let (status, body) = h
                .post("/enroll/credential", Some(&cookie), Some(&csrf), body)
                .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{label:?}");
            assert_eq!(body, json!({"error": "label_invalid"}), "{label:?}");
            h.assert_nothing_staged_or_stored();
        }
    }

    let mut body = valid_body(12, &challenge);
    body["label"] = json!(" laptop ");
    let (status, body) = h
        .post("/enroll/credential", Some(&cookie), Some(&csrf), body)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let staged = h.staged().expect("the spaced label is staged");
    assert_eq!(
        staged.with_deadline(std::time::Instant::now()).label(),
        "laptop"
    );
}

/// A label carrying a control character never reaches the terminal prompt:
/// each hostile label answers `label_invalid` and stages nothing, and the
/// challenge stays usable for a clean label.
#[tokio::test]
async fn post_label_with_control_character_is_rejected() {
    let mut h = Harness::new();
    let (cookie, csrf) = h.establish_session().await;
    let challenge = h.challenge(&cookie, &csrf).await;
    for (name, label) in [
        ("ansi erase", "laptop\u{1b}[2K\u{1b}[1Aphone"),
        ("osc 52 clipboard", "laptop\u{1b}]52;c;Y3VybCBldmls\u{07}"),
        ("carriage return", "laptop\rphone"),
        ("bell", "laptop\u{07}"),
        ("c1 csi", "laptop\u{9b}2K"),
        ("delete", "laptop\u{7f}"),
    ] {
        let mut body = valid_body(11, &challenge);
        body["label"] = json!(label);
        let (status, body) = h
            .post("/enroll/credential", Some(&cookie), Some(&csrf), body)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{name}");
        assert_eq!(body, json!({"error": "label_invalid"}), "{name}");
        h.assert_nothing_staged_or_stored();
    }

    let mut body = valid_body(11, &challenge);
    body["label"] = json!("laptop phone");
    let (status, body) = h
        .post("/enroll/credential", Some(&cookie), Some(&csrf), body)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let staged = h.staged().expect("the clean label is staged");
    assert_eq!(
        staged.with_deadline(std::time::Instant::now()).label(),
        "laptop phone"
    );
}

/// The signature counter comes from the authenticator data only: a body
/// that also names one is refused, and the challenge stays usable.
#[tokio::test]
async fn post_client_supplied_sign_count_is_refused() {
    let mut h = Harness::new();
    let (cookie, csrf) = h.establish_session().await;
    let challenge = h.challenge(&cookie, &csrf).await;
    for sign_count in [json!(3), json!(-1), json!(4_294_967_296_u64)] {
        let mut body = valid_body(10, &challenge);
        body["sign_count"] = sign_count.clone();
        let (status, body) = h
            .post("/enroll/credential", Some(&cookie), Some(&csrf), body)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{sign_count}");
        assert_eq!(
            body,
            json!({"error": "registration_invalid"}),
            "{sign_count}"
        );
    }
    h.assert_nothing_staged_or_stored();
    let (status, body) = h
        .post(
            "/enroll/credential",
            Some(&cookie),
            Some(&csrf),
            valid_body(10, &challenge),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

// ─────────────────────────────────────────────────────────────────────────────
// Server challenge, staged candidate, duplicate id, single-use latch
// ─────────────────────────────────────────────────────────────────────────────

/// With the cookie, the CSRF value and the proof all present, a registration
/// that answers no server-issued challenge is refused as
/// `registration_invalid`: credential metadata alone, a ceremony over a
/// challenge the client chose before any was issued, and one over a
/// client-chosen challenge while the server's is outstanding. Nothing is
/// staged or stored.
#[tokio::test]
async fn registration_requires_server_challenge() {
    let mut h = Harness::new();
    let (cookie, csrf) = h.establish_session().await;
    let client_chosen = [0x5c; 32];

    let (status, body) = h
        .post(
            "/enroll/credential",
            Some(&cookie),
            Some(&csrf),
            metadata_only_body(12),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body, json!({"error": "registration_invalid"}));

    let (status, body) = h
        .post(
            "/enroll/credential",
            Some(&cookie),
            Some(&csrf),
            valid_body(12, &client_chosen),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body, json!({"error": "registration_invalid"}));

    let issued = h.challenge(&cookie, &csrf).await;
    assert_ne!(issued, client_chosen);
    for body in [metadata_only_body(12), valid_body(12, &client_chosen)] {
        let (status, body) = h
            .post("/enroll/credential", Some(&cookie), Some(&csrf), body)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body, json!({"error": "registration_invalid"}));
    }
    h.assert_nothing_staged_or_stored();

    let (status, body) = h
        .post(
            "/enroll/credential",
            Some(&cookie),
            Some(&csrf),
            valid_body(12, &issued),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// A verified registration is staged for the CLI with the page's code and
/// the counter from the authenticator data; the server writes nothing. Only
/// the confirmed candidate persists, exactly as registered.
#[tokio::test]
async fn verified_registration_stages_without_persisting() {
    let mut h = Harness::new();
    let (cookie, csrf) = h.establish_session().await;
    let challenge = h.challenge(&cookie, &csrf).await;
    let response = registration(20, &challenge).sign_count(3);
    let (status, body) = h
        .post(
            "/enroll/credential",
            Some(&cookie),
            Some(&csrf),
            response.json(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body, json!({"status": "awaiting_confirmation"}));

    let store = OperatorApprovalCredentialStore::new(h.store_path.clone());
    assert!(
        store.list().unwrap().is_empty(),
        "the server never persists"
    );
    let staged = h.staged().expect("the verified registration is staged");
    let now = std::time::Instant::now();
    let persisted = staged
        .with_deadline(now + std::time::Duration::from_secs(60))
        .confirm(&response.confirmation_code(), now)
        .unwrap()
        .persist(&store)
        .unwrap();
    let listed = store.list().unwrap();
    assert_eq!(listed, vec![persisted]);
    assert_eq!(listed[0].credential_id_b64url, valid_credential_id_b64(20));
    assert_eq!(listed[0].public_key_sec1_b64, valid_pubkey_b64(20));
    assert_eq!(listed[0].rp_id, "localhost");
    assert_eq!(listed[0].label, "laptop");
    assert_eq!(listed[0].sign_count, Some(3));
}

/// Repeated challenge requests return the outstanding challenge. Past its
/// lifetime on the session clock a registration answers
/// `registration_expired` and the challenge is replaced. Once a registration
/// is accepted, a replay, a second credential, a further challenge request
/// and a concurrent post are all `already_completed`; exactly one candidate
/// is staged and nothing is stored.
#[tokio::test]
async fn registration_challenge_expires_and_is_single_use() {
    let mut h = Harness::new();
    let (cookie, csrf) = h.establish_session().await;
    let first = h.challenge(&cookie, &csrf).await;
    assert_eq!(h.challenge(&cookie, &csrf).await, first, "not replaced");

    h.clock
        .advance(REGISTRATION_CHALLENGE_TTL - std::time::Duration::from_secs(1));
    assert_eq!(
        h.challenge(&cookie, &csrf).await,
        first,
        "still outstanding"
    );
    h.clock.advance(std::time::Duration::from_secs(1));
    let (status, body) = h
        .post(
            "/enroll/credential",
            Some(&cookie),
            Some(&csrf),
            valid_body(30, &first),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body, json!({"error": "registration_expired"}));
    h.assert_nothing_staged_or_stored();

    let second = h.challenge(&cookie, &csrf).await;
    assert_ne!(second, first, "an expired challenge is replaced");
    let (status, body) = h
        .post(
            "/enroll/credential",
            Some(&cookie),
            Some(&csrf),
            valid_body(30, &first),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body, json!({"error": "registration_invalid"}));

    let (accepted, rival) = tokio::join!(
        h.post(
            "/enroll/credential",
            Some(&cookie),
            Some(&csrf),
            valid_body(30, &second),
        ),
        h.post(
            "/enroll/credential",
            Some(&cookie),
            Some(&csrf),
            valid_body(31, &second),
        ),
    );
    let mut statuses = [accepted.0, rival.0];
    statuses.sort();
    assert_eq!(statuses, [StatusCode::OK, StatusCode::CONFLICT]);
    for (status, body) in [accepted, rival] {
        if status == StatusCode::CONFLICT {
            assert_eq!(body, json!({"error": "already_completed"}));
        }
    }

    for body in [valid_body(30, &second), valid_body(32, &second)] {
        let (status, body) = h
            .post("/enroll/credential", Some(&cookie), Some(&csrf), body)
            .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body, json!({"error": "already_completed"}));
    }
    let (status, body) = h
        .post("/enroll/challenge", Some(&cookie), Some(&csrf), json!({}))
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body, json!({"error": "already_completed"}));

    assert!(h.staged().is_some(), "exactly one candidate is staged");
    let store = OperatorApprovalCredentialStore::new(h.store_path.clone());
    assert!(store.list().unwrap().is_empty());
}

/// A verified registration whose ID is already enrolled is refused before
/// staging and consumes neither the challenge nor the latch.
#[tokio::test]
async fn post_duplicate_credential_id_is_refused_without_consuming_the_latch() {
    let mut h = Harness::seeded(OperatorApprovalCredential {
        credential_id_b64url: valid_credential_id_b64(60),
        public_key_sec1_b64: valid_pubkey_b64(60),
        rp_id: "localhost".to_owned(),
        label: "existing".to_owned(),
        registered_at_unix_ms: 1,
        sign_count: None,
        source: stellar_agent_core::approval::OperatorCredentialSource::Enrolled,
    });
    let (cookie, csrf) = h.establish_session().await;
    let challenge = h.challenge(&cookie, &csrf).await;

    let (status, body) = h
        .post(
            "/enroll/credential",
            Some(&cookie),
            Some(&csrf),
            valid_body(60, &challenge),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body, json!({"error": "duplicate_credential_id"}));
    assert!(h.staged().is_none());

    // The latch and the challenge are still available: a distinct
    // credential over the same challenge is staged.
    let (status2, body2) = h
        .post(
            "/enroll/credential",
            Some(&cookie),
            Some(&csrf),
            valid_body(61, &challenge),
        )
        .await;
    assert_eq!(
        status2,
        StatusCode::OK,
        "latch must not be consumed by a duplicate-id failure: {body2}"
    );
    assert!(h.staged().is_some());
    let store = OperatorApprovalCredentialStore::new(h.store_path.clone());
    assert_eq!(store.list().unwrap().len(), 1, "only the seeded credential");
}

#[tokio::test]
async fn second_successful_shape_post_after_completion_is_refused() {
    let mut h = Harness::new();
    let (cookie, csrf) = h.establish_session().await;
    let challenge = h.challenge(&cookie, &csrf).await;

    let (status1, body1) = h
        .post(
            "/enroll/credential",
            Some(&cookie),
            Some(&csrf),
            valid_body(40, &challenge),
        )
        .await;
    assert_eq!(status1, StatusCode::OK, "first registration: {body1}");

    // A second, verified registration for a DIFFERENT credential id must be
    // refused outright: the single-use latch, not the store's duplicate-id
    // check, is what stops it.
    let (status2, body2) = h
        .post(
            "/enroll/credential",
            Some(&cookie),
            Some(&csrf),
            valid_body(41, &challenge),
        )
        .await;
    assert_eq!(status2, StatusCode::CONFLICT);
    assert_eq!(body2["error"], "already_completed");

    let staged = h.staged().expect("the first registration is staged");
    let store = OperatorApprovalCredentialStore::new(h.store_path.clone());
    assert!(store.list().unwrap().is_empty());
    let now = std::time::Instant::now();
    let persisted = staged
        .with_deadline(now + std::time::Duration::from_secs(60))
        .confirm(&registration(40, &challenge).confirmation_code(), now)
        .unwrap()
        .persist(&store)
        .unwrap();
    assert_eq!(persisted.credential_id_b64url, valid_credential_id_b64(40));
    assert_eq!(store.list().unwrap().len(), 1);
}

#[tokio::test]
async fn completion_signal_fires_exactly_once() {
    let mut h = Harness::new();
    let (cookie, csrf) = h.establish_session().await;
    let challenge = h.challenge(&cookie, &csrf).await;
    let (status, _) = h
        .post(
            "/enroll/credential",
            Some(&cookie),
            Some(&csrf),
            valid_body(50, &challenge),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    // Swap the receiver out (rather than moving `h.completion_rx` directly)
    // so `h` stays fully initialised for the `&h` borrows below.
    let rx = std::mem::replace(&mut h.completion_rx, oneshot::channel().1);
    let received = rx.await;
    assert!(received.is_ok(), "completion signal must fire on success");

    // A second verified registration cannot fire it again (the sender was
    // consumed on the first success); confirm it is refused rather than
    // silently accepted.
    let (status2, body2) = h
        .post(
            "/enroll/credential",
            Some(&cookie),
            Some(&csrf),
            valid_body(51, &challenge),
        )
        .await;
    assert_eq!(status2, StatusCode::CONFLICT);
    assert_eq!(body2["error"], "already_completed");
}

/// `POST /enroll/challenge` sits behind the same boundary as the credential
/// POST: no cookie is `404`, a missing or wrong CSRF value is `403`
/// `csrf_invalid`, a missing proof is `403` `session_proof_invalid`, and
/// none of them issues a challenge.
#[tokio::test]
async fn challenge_route_requires_session_csrf_and_proof() {
    let h = Harness::new();
    let (cookie, csrf) = h.establish_session().await;
    let (status, _) = h
        .post("/enroll/challenge", None, Some(&csrf), json!({}))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    for wrong in [None, Some("f".repeat(64))] {
        let (status, body) = h
            .post(
                "/enroll/challenge",
                Some(&cookie),
                wrong.as_deref(),
                json!({}),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, json!({"error": "csrf_invalid"}));
    }
    let (status, body) = h
        .post_with_proof(
            "/enroll/challenge",
            Some(&cookie),
            Some(&csrf),
            None,
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, json!({"error": "session_proof_invalid"}));
    assert!(h.state.ceremony.lock().unwrap().challenge.is_none());
    let issued = h.challenge(&cookie, &csrf).await;
    assert_eq!(
        h.state
            .ceremony
            .lock()
            .unwrap()
            .challenge
            .as_ref()
            .unwrap()
            .bytes(),
        &issued
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Session proof, lifetime and cookie shape
// ─────────────────────────────────────────────────────────────────────────────

/// The session cookie and a valid CSRF value do not authorize an enrollment
/// without the session proof: missing, malformed, wrong, and the session id
/// in its place are all refused with `session_proof_invalid`. Nothing is
/// staged or persisted and the completion signal stays unfired.
#[tokio::test]
async fn cookie_and_csrf_without_proof_cannot_mutate() {
    let mut h = Harness::new();
    let (cookie, csrf) = h.establish_session().await;
    let challenge = h.challenge(&cookie, &csrf).await;
    let wrong = OpaqueToken::generate().to_hex();
    let session_id = h
        .state
        .auth
        .lock()
        .unwrap()
        .session
        .as_ref()
        .unwrap()
        .session_id
        .to_hex();

    for proof in [
        None,
        Some("not-a-proof"),
        Some(wrong.as_str()),
        Some(session_id.as_str()),
    ] {
        let (status, body) = h
            .post_with_proof(
                "/enroll/credential",
                Some(&cookie),
                Some(&csrf),
                proof,
                valid_body(7, &challenge),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{proof:?}");
        assert_eq!(body, json!({"error": "session_proof_invalid"}), "{proof:?}");
    }

    let store = OperatorApprovalCredentialStore::new(h.store_path.clone());
    assert!(store.list().unwrap().is_empty());
    assert!(matches!(
        h.completion_rx.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));

    // The same request with the proof is the operator's: it is staged for
    // the terminal confirmation, and the server still writes nothing.
    let (status, body) = h
        .post_with_proof(
            "/enroll/credential",
            Some(&cookie),
            Some(&csrf),
            Some(&h.proof()),
            valid_body(7, &challenge),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, json!({"status": "awaiting_confirmation"}));
    assert!(store.list().unwrap().is_empty());
    assert!(h.staged().is_some());
}

/// The proof leaves the server once, in the successful bootstrap response:
/// no header or body of the enrollment page, either script, a POST response
/// or a repeated bootstrap carries it.
#[tokio::test]
async fn bootstrap_proof_is_one_shot_and_not_recoverable() {
    fn assert_no_proof_in_headers(headers: &HeaderMap, proof: &str, what: &str) {
        for (name, value) in headers {
            assert!(
                !value.to_str().unwrap_or_default().contains(proof),
                "{what}: header {name}"
            );
        }
    }

    let h = Harness::new();
    let (cookie, csrf) = h.establish_session().await;
    let proof = h.proof();

    for path in [
        "/enroll",
        "/static/operator-enroll.js",
        "/static/session-bootstrap.js",
    ] {
        let (status, headers, body) = h.get_with_headers(path, Some(&cookie)).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert_no_proof_in_headers(&headers, &proof, path);
        assert!(!body.contains(&proof), "{path}");
    }
    let (status, headers, body) = h
        .get_with_headers(&format!("/bootstrap/{}", h.bootstrap_hex), Some(&cookie))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(headers.get(header::SET_COOKIE).is_none());
    assert_no_proof_in_headers(&headers, &proof, "repeated bootstrap");
    assert!(!body.contains(&proof));

    for _ in 0..2 {
        let (status, headers, response) = h
            .post_with_headers(
                "/enroll/challenge",
                Some(&cookie),
                Some(&csrf),
                Some(&proof),
                json!({}),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_no_proof_in_headers(&headers, &proof, "POST /enroll/challenge");
        assert!(!response.to_string().contains(&proof));
    }
    let challenge = h.challenge(&cookie, &csrf).await;
    for body in [
        json!({"credential_id_b64url": "x"}),
        valid_body(9, &[0; 32]),
        valid_body(9, &challenge),
    ] {
        let (_status, headers, response) = h
            .post_with_headers(
                "/enroll/credential",
                Some(&cookie),
                Some(&csrf),
                Some(&proof),
                body,
            )
            .await;
        assert_no_proof_in_headers(&headers, &proof, "POST /enroll/credential");
        assert!(!response.to_string().contains(&proof));
    }
    let (status, headers, response) = h
        .post_with_headers(
            "/enroll/challenge",
            Some(&cookie),
            Some(&csrf),
            Some(&proof),
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "the ceremony completed");
    assert_no_proof_in_headers(&headers, &proof, "POST /enroll/challenge");
    assert!(!response.to_string().contains(&proof));
}

/// The enrollment cookie is bounded and carries its own prefix and a
/// per-listener suffix, so it never collides with the inbox cookie or with
/// another enrollment listener.
#[tokio::test]
async fn bootstrap_sets_max_age_and_distinct_cookie_names() {
    let a = Harness::new();
    let b = Harness::new();
    for h in [&a, &b] {
        let req = Request::builder()
            .method("GET")
            .uri(format!("/bootstrap/{}", h.bootstrap_hex))
            .header(header::HOST, HOST)
            .body(Body::empty())
            .unwrap();
        let resp = h.router.clone().oneshot(req).await.unwrap();
        let set_cookie = resp
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let attributes: Vec<&str> = set_cookie.split(';').map(str::trim).collect();
        assert!(attributes.contains(&"Max-Age=28800"), "{set_cookie}");
        assert!(attributes.contains(&"HttpOnly"), "{set_cookie}");
        assert!(attributes.contains(&"SameSite=Strict"), "{set_cookie}");
        assert!(
            h.cookie_name
                .starts_with("stellar_agent_operator_enroll_session_"),
            "{}",
            h.cookie_name
        );
        assert!(!h.cookie_name.starts_with("stellar_agent_approval_session"));
    }
    assert_ne!(a.cookie_name, b.cookie_name);
}

/// The enrollment session uses the same idle limit: held one tick before it,
/// refused exactly at it on the page and on the POST, and never revived.
#[tokio::test]
async fn idle_expiry_boundary() {
    let h = Harness::new();
    let (cookie, csrf) = h.establish_session().await;
    let tick = std::time::Duration::from_secs(1);

    h.clock.advance(SESSION_IDLE_TIMEOUT - tick);
    let (status, _) = h.get("/enroll", &cookie).await;
    assert_eq!(status, StatusCode::OK);

    h.clock.advance(tick);
    let (status, _) = h.get("/enroll", &cookie).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = h
        .post(
            "/enroll/credential",
            Some(&cookie),
            Some(&csrf),
            valid_body(3, &[0; 32]),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = h
        .post("/enroll/challenge", Some(&cookie), Some(&csrf), json!({}))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let store = OperatorApprovalCredentialStore::new(h.store_path.clone());
    assert!(store.list().unwrap().is_empty());
}

/// A refused enrollment POST does not record activity; an authorized one
/// does.
#[tokio::test]
async fn only_an_authorized_post_records_activity() {
    let h = Harness::new();
    let (cookie, csrf) = h.establish_session().await;
    let tick = std::time::Duration::from_secs(1);

    h.clock.advance(SESSION_IDLE_TIMEOUT - tick);
    let (status, _) = h
        .post_with_proof(
            "/enroll/credential",
            Some(&cookie),
            Some(&csrf),
            None,
            valid_body(4, &[0; 32]),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, body) = h
        .post(
            "/enroll/credential",
            Some(&cookie),
            Some(&csrf),
            registration(4, &[0; 32]).label("").json(),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body, json!({"error": "label_invalid"}));

    h.clock.advance(SESSION_IDLE_TIMEOUT - tick);
    let (status, _) = h.get("/enroll", &cookie).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the authorized POST, though its body was refused, recorded activity"
    );
    h.clock.advance(tick);
    let (status, _) = h.get("/enroll", &cookie).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// Each enrollment request span records the matched route template: neither
/// the bootstrap token nor the session proof reaches the trace. The listener
/// has no nonce-bearing route besides the bootstrap, so a nonce-bearing path
/// that matches no route stands in and records the fixed label.
#[tokio::test(flavor = "current_thread")]
async fn bootstrap_trace_redacts_token() {
    let h = Harness::new();
    let capture = crate::trace_capture::SpanCapture::install();
    let stray_nonce = "c3RyYXktbm9uY2UtdmFsdWU";

    let (cookie, csrf) = h.establish_session().await;
    let proof = h.proof();
    let (status, _) = h
        .get(&format!("/bootstrap/{}", h.bootstrap_hex), &cookie)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = h.get(&format!("/enroll/{stray_nonce}"), &cookie).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let challenge = h.challenge(&cookie, &csrf).await;
    let (status, _) = h
        .post(
            "/enroll/credential",
            Some(&cookie),
            Some(&csrf),
            valid_body(5, &challenge),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let paths = capture.span_paths("operator_enroll_request");
    assert_eq!(
        paths
            .iter()
            .filter(|path| *path == "/bootstrap/{token}")
            .count(),
        2,
        "{:?}",
        capture.lines()
    );
    assert!(
        paths.iter().any(|path| path == "/enroll/credential"),
        "{paths:?}"
    );
    assert!(
        paths.iter().any(|path| path == "/enroll/challenge"),
        "{paths:?}"
    );
    assert!(
        paths
            .iter()
            .any(|path| path == stellar_agent_loopback_http::request_trace::UNMATCHED_ROUTE_LABEL),
        "{paths:?}"
    );
    for line in capture.lines() {
        assert!(!line.contains(&h.bootstrap_hex), "token in trace: {line}");
        assert!(!line.contains(stray_nonce), "nonce in trace: {line}");
        assert!(!line.contains(&proof), "proof in trace: {line}");
    }
}

const SIGNED_ORIGIN: &str = "https://approve.example.invalid:8443";
const SIGNED_RP_ID: &str = "approve.example.invalid";
const MAINNET_PROOF_KEY: &str = "stellar-agent-mainnet-approval-enroll-session-proof";

/// A signed-origin ceremony's router, without the signed Host and Origin
/// layers its listener installs.
fn signed() -> (Router, super::SignedEnrollmentCeremony) {
    super::signed_ceremony(
        SIGNED_ORIGIN,
        SIGNED_RP_ID,
        "main".to_owned(),
        None,
        PageIdentity::neutral(),
        std::time::Duration::from_secs(300),
    )
}

/// One in-process request to `router`.
async fn send(
    router: &Router,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<String>,
) -> (StatusCode, HeaderMap, String) {
    let mut builder = Request::builder().method(method).uri(path);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let req = builder
        .body(body.map_or_else(Body::empty, Body::from))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    (status, headers, String::from_utf8(bytes.to_vec()).unwrap())
}

/// `POST /enroll/code` with `code`.
async fn post_code(router: &Router, code: &str) -> (StatusCode, HeaderMap, String) {
    send(
        router,
        "POST",
        "/enroll/code",
        &[("content-type", "application/json")],
        Some(json!({ "code": code }).to_string()),
    )
    .await
}

/// A different eight-digit code than `code`.
fn other_code(code: &str) -> String {
    let mut digits = code.as_bytes().to_vec();
    digits[0] = if digits[0] == b'0' { b'1' } else { b'0' };
    String::from_utf8(digits).unwrap()
}

/// The signed router selects the page by session: the code form and its
/// pre-auth asset without one, the registration page with one. Only the
/// terminal's code, once, yields the cookie and the proof page; a wrong or
/// replayed code yields neither. The loopback router serves no code asset
/// and no code route.
#[tokio::test]
async fn signed_enrollment_code_form_and_exchange() {
    let (router, ceremony) = signed();
    let code = ceremony.enrollment_code().to_owned();
    assert_eq!(code.len(), 8);

    let (status, headers, form) = send(&router, "GET", "/enroll", &[], None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(form.contains(r#"id="code-input""#), "{form}");
    assert!(form.contains(r#"<script src="/static/operator-enroll-code.js"></script>"#));
    assert!(!form.contains("enroll-data"));
    assert!(!form.contains(&code));
    let csp = headers[header::CONTENT_SECURITY_POLICY]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(csp.contains("form-action 'none'"), "{csp}");

    let (status, _, asset) =
        send(&router, "GET", "/static/operator-enroll-code.js", &[], None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(asset.as_bytes(), super::web::OPERATOR_ENROLL_CODE_JS);
    for path in [
        "/static/operator-enroll.js".to_owned(),
        format!("/bootstrap/{}", "ab".repeat(32)),
        "/static/session-bootstrap.js".to_owned(),
    ] {
        assert_eq!(
            send(&router, "GET", &path, &[], None).await.0,
            StatusCode::NOT_FOUND,
            "{path}"
        );
    }

    let (status, headers, body) = post_code(&router, &other_code(&code)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, r#"{"error":"code_invalid"}"#);
    assert!(headers.get(header::SET_COOKIE).is_none());

    let (status, headers, page) = post_code(&router, &code).await;
    assert_eq!(status, StatusCode::OK, "{page}");
    let cookie = headers[header::SET_COOKIE].to_str().unwrap().to_owned();
    assert!(cookie.ends_with("; Secure"), "{cookie}");
    let island = extract_island(&page, "session-bootstrap-data");
    assert_eq!(island["storageKey"], MAINNET_PROOF_KEY);
    assert_eq!(island["next"], "/enroll");
    let proof = island["proof"].as_str().unwrap().to_owned();
    assert_eq!(proof.len(), 64);
    assert!(!page.contains(&code));

    let (status, headers, body) = post_code(&router, &code).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a spent code never matches again"
    );
    assert!(headers.get(header::SET_COOKIE).is_none());
    assert!(!body.contains(&proof));

    let session_cookie = cookie.split(';').next().unwrap().to_owned();
    let (status, headers, registration) = send(
        &router,
        "GET",
        "/enroll",
        &[("cookie", &session_cookie)],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers[header::CONTENT_SECURITY_POLICY].to_str().unwrap(),
        csp
    );
    assert!(!registration.contains(r#"id="code-input""#));
    assert_eq!(
        extract_island(&registration, "enroll-data")["rpId"],
        SIGNED_RP_ID
    );
    assert!(registration.contains(r#"<script src="/static/operator-enroll.js"></script>"#));
    let (status, _, script) = send(
        &router,
        "GET",
        "/static/operator-enroll.js",
        &[("cookie", &session_cookie)],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(script.as_bytes(), super::web::OPERATOR_ENROLL_JS);

    let loopback = Harness::new();
    let cookie = loopback.bootstrap().await;
    assert_eq!(
        loopback
            .get("/static/operator-enroll-code.js", &cookie)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    let (status, _) = loopback
        .post("/enroll/code", Some(&cookie), None, json!({"code": code}))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// A signed ceremony verifies registrations against the origin and RP of
/// the body it starts from. A foreign `Host` and forwarded headers change
/// neither the challenge RP nor the expected origin: a registration for the
/// signed origin passes, one for the header's origin fails.
#[tokio::test]
async fn signed_registration_origin_uses_body_state() {
    let (router, mut ceremony) = signed();
    let code = ceremony.enrollment_code().to_owned();
    let (_, headers, page) = post_code(&router, &code).await;
    let cookie = headers[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let proof = extract_island(&page, "session-bootstrap-data")["proof"]
        .as_str()
        .unwrap()
        .to_owned();
    let foreign = [
        ("host", "evil.example:9443"),
        ("x-forwarded-host", "evil.example"),
        ("x-forwarded-proto", "http"),
        ("forwarded", "host=evil.example;proto=http"),
    ];
    let mut get_headers = foreign.to_vec();
    get_headers.push(("cookie", &cookie));
    let (_, _, registration) = send(&router, "GET", "/enroll", &get_headers, None).await;
    let csrf = extract_csrf(&registration);
    assert_eq!(
        extract_island(&registration, "enroll-data")["rpId"],
        SIGNED_RP_ID
    );
    let mut post_headers = get_headers.clone();
    post_headers.extend([
        ("origin", "https://evil.example:9443"),
        ("x-stellar-approval-csrf", csrf.as_str()),
        ("x-session-proof", proof.as_str()),
        ("content-type", "application/json"),
    ]);
    let (status, _, options) = send(
        &router,
        "POST",
        "/enroll/challenge",
        &post_headers,
        Some("{}".to_owned()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{options}");
    let options: serde_json::Value = serde_json::from_str(&options).unwrap();
    assert_eq!(options["rp_id"], SIGNED_RP_ID);
    let challenge: [u8; 32] = URL_SAFE_NO_PAD
        .decode(options["challenge"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let registrar = SoftwareRegistrar::new([0x31; 32], vec![0x7c; 16]).with_rp_id(SIGNED_RP_ID);
    for (origin, rp_id) in [
        ("https://evil.example:9443", SIGNED_RP_ID),
        ("https://approve.example.invalid", SIGNED_RP_ID),
        (SIGNED_ORIGIN, "evil.example"),
        (SIGNED_ORIGIN, "localhost"),
    ] {
        let builder = SoftwareRegistrar::new([0x31; 32], vec![0x7c; 16])
            .with_rp_id(rp_id)
            .builder(&challenge, origin);
        let (status, _, body) = send(
            &router,
            "POST",
            "/enroll/credential",
            &post_headers,
            Some(builder.json().to_string()),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{origin} {rp_id}");
        assert_eq!(body, r#"{"error":"registration_invalid"}"#);
    }
    let valid = registrar.builder(&challenge, SIGNED_ORIGIN);
    let (status, _, body) = send(
        &router,
        "POST",
        "/enroll/credential",
        &post_headers,
        Some(valid.json().to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let pending = ceremony
        .await_completion_until(std::time::Instant::now() + std::time::Duration::from_secs(5))
        .await
        .unwrap();
    let confirmed = pending
        .confirm(
            &valid.confirmation_code_for(super::EnrollmentPurpose::MainnetApproval),
            std::time::Instant::now(),
        )
        .unwrap();
    let credential = confirmed.into_mainnet_policy_credential().unwrap();
    assert_eq!(credential.credential_id(), registrar.credential_id());
}

/// The handle of a signed ceremony ends with the typed exhaustion outcome
/// after the sixth attempt and with a timeout when the code expires, both
/// without a staged registration.
#[tokio::test]
async fn signed_enrollment_code_exhaustion_and_expiry_end_the_wait() {
    let (router, mut ceremony) = signed();
    let wrong = other_code(ceremony.enrollment_code());
    for _ in 0..5 {
        assert_eq!(post_code(&router, &wrong).await.0, StatusCode::FORBIDDEN);
    }
    let (status, headers, body) = post_code(&router, ceremony.enrollment_code()).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, r#"{"error":"code_exhausted"}"#);
    assert!(headers.get(header::SET_COOKIE).is_none());
    let ended = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        ceremony
            .await_completion_until(std::time::Instant::now() + std::time::Duration::from_secs(60)),
    )
    .await
    .expect("exhaustion ends the wait");
    assert!(matches!(
        ended,
        Err(super::OperatorEnrollAwaitError::CodeExhausted)
    ));

    let (_router, mut ceremony) = super::signed_ceremony(
        SIGNED_ORIGIN,
        SIGNED_RP_ID,
        "main".to_owned(),
        None,
        PageIdentity::neutral(),
        std::time::Duration::from_millis(200),
    );
    let ended = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        ceremony
            .await_completion_until(std::time::Instant::now() + std::time::Duration::from_secs(60)),
    )
    .await
    .expect("expiry ends the wait without a request");
    assert!(matches!(
        ended,
        Err(super::OperatorEnrollAwaitError::Timeout)
    ));
    assert!(!format!("{ceremony:?}").contains(ceremony.enrollment_code()));
}

/// One raw HTTP/1.1 exchange with a loopback enrollment server: the response
/// head without its `date` and `content-length` lines, then the body.
async fn raw_exchange(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
) -> String {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nhost: localhost:{}\r\nconnection: close\r\n",
        addr.port()
    );
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    let body = if method == "POST" { "{}" } else { "" };
    head.push_str(&format!("content-length: {}\r\n\r\n{body}", body.len()));
    stream.write_all(head.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.unwrap();
    let text = String::from_utf8(raw).unwrap();
    let (response_head, response_body) = text.split_once("\r\n\r\n").unwrap();
    let mut kept: Vec<&str> = response_head
        .split("\r\n")
        .filter(|line| {
            let lower = line.to_ascii_lowercase();
            !lower.starts_with("date:") && !lower.starts_with("content-length:")
        })
        .collect();
    kept[1..].sort_unstable();
    format!("{method} {path}\n{}\n\n{response_body}\n", kept.join("\n"))
}

/// The loopback transcript of one purpose, with the port, the bootstrap
/// token, the cookie, the proof, the CSRF value, the challenge and its
/// remaining time replaced by fixed names.
async fn loopback_transcript(purpose: super::EnrollmentPurpose) -> String {
    let dir = TempDir::new().unwrap();
    let handle = match purpose {
        super::EnrollmentPurpose::RemoteOperator => super::start_operator_enroll_server(
            dir.path().join("default.toml"),
            "default",
            SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0),
            Some("laptop".to_owned()),
            PageIdentity::neutral(),
        )
        .await
        .unwrap(),
        super::EnrollmentPurpose::MainnetApproval => {
            super::start_mainnet_approval_enroll("main".to_owned(), None, PageIdentity::neutral())
                .await
                .unwrap()
        }
    };
    let addr = handle.local_addr();
    let token = handle.bootstrap_token_hex().to_owned();
    let mut transcript = format!("url {}\n", handle.enroll_url());
    let bootstrap = raw_exchange(addr, "GET", &format!("/bootstrap/{token}"), &[]).await;
    let set_cookie = bootstrap
        .lines()
        .find_map(|line| line.strip_prefix("set-cookie: "))
        .unwrap()
        .to_owned();
    let cookie = set_cookie.split(';').next().unwrap().to_owned();
    let proof = extract_island(&bootstrap, "session-bootstrap-data")["proof"]
        .as_str()
        .unwrap()
        .to_owned();
    transcript.push_str(&bootstrap);
    transcript.push_str(&raw_exchange(addr, "GET", &format!("/bootstrap/{token}"), &[]).await);
    let page = raw_exchange(addr, "GET", "/enroll", &[("cookie", &cookie)]).await;
    let csrf = extract_csrf(&page);
    transcript.push_str(&page);
    transcript.push_str(&raw_exchange(addr, "GET", "/enroll", &[]).await);
    for asset in [
        "/static/operator-enroll.js",
        "/static/session-bootstrap.js",
        "/static/operator-enroll-code.js",
    ] {
        transcript.push_str(&raw_exchange(addr, "GET", asset, &[("cookie", &cookie)]).await);
    }
    transcript.push_str(&raw_exchange(addr, "GET", "/static/operator-enroll.js", &[]).await);
    let origin = format!("http://localhost:{}", addr.port());
    let post_headers = [
        ("cookie", cookie.as_str()),
        ("origin", origin.as_str()),
        ("x-stellar-approval-csrf", csrf.as_str()),
        ("x-session-proof", proof.as_str()),
        ("content-type", "application/json"),
    ];
    let challenge = raw_exchange(addr, "POST", "/enroll/challenge", &post_headers).await;
    let challenge_json: serde_json::Value =
        serde_json::from_str(challenge.rsplit("\n\n").next().unwrap().trim()).unwrap();
    let challenge_b64 = challenge_json["challenge"].as_str().unwrap().to_owned();
    let remaining = challenge_json["timeout_ms"].to_string();
    transcript.push_str(&challenge.replace(
        &format!("\"timeout_ms\":{remaining}"),
        "\"timeout_ms\":{remaining}",
    ));
    transcript.push_str(&raw_exchange(addr, "POST", "/enroll/code", &post_headers).await);
    handle.shutdown().await.unwrap();
    let cookie_value = cookie.split_once('=').unwrap().1.to_owned();
    let cookie_name = cookie.split_once('=').unwrap().0.to_owned();
    // Only the random 16-hex-digit suffix of the cookie name varies; the
    // purpose prefix stays in the transcript.
    let (cookie_prefix, cookie_suffix) = cookie_name.split_at(cookie_name.len() - 16);
    assert!(cookie_suffix.bytes().all(|b| b.is_ascii_hexdigit()));
    transcript
        .replace(&token, "{token}")
        .replace(&proof, "{proof}")
        .replace(&cookie_value, "{cookie}")
        .replace(&cookie_name, &format!("{cookie_prefix}{{cookie_suffix}}"))
        .replace(&csrf, "{csrf}")
        .replace(&challenge_b64, "{challenge}")
        .replace(&format!("localhost:{}", addr.port()), "localhost:{port}")
}

/// Both loopback purposes keep their base transcript: URLs, pages, data
/// islands, cookies, assets, challenge options and 404 answers, including
/// 404 for the signed code asset and the code route.
#[tokio::test]
async fn loopback_enrollment_transcript_keeps_base_bytes() {
    use sha2::{Digest as _, Sha256};
    // `whole_name` is the hash the base tree yields with the whole cookie
    // name replaced; it ties this transcript to the base bytes. `expected`
    // keeps the purpose prefix of the cookie name.
    for (purpose, expected, whole_name) in [
        (
            super::EnrollmentPurpose::RemoteOperator,
            "ece062491853771fc8e1b3da36c34d18cd6cabbcff6a83d0a9b3da3d3bf09bab",
            "f6df8795002c881b6ba786017514c45ec3e104b76840820eb5e4529bad2891cc",
        ),
        (
            super::EnrollmentPurpose::MainnetApproval,
            "3c87a65a9eee4608a0206a58c593451e2a967c43b461ace7d47c13fe288ee803",
            "9c69bcc0ac07ba80c6083f4ebe8e8013e1e183485988d54b038a969c72cf7322",
        ),
    ] {
        let transcript = loopback_transcript(purpose).await;
        let prefix = match purpose {
            super::EnrollmentPurpose::RemoteOperator => "stellar_agent_operator_enroll_session_",
            super::EnrollmentPurpose::MainnetApproval => {
                "stellar_agent_mainnet_approval_enroll_session_"
            }
        };
        let whole = transcript.replace(&format!("{prefix}{{cookie_suffix}}"), "{cookie_name}");
        assert_eq!(
            hex::encode(Sha256::digest(whole.as_bytes())),
            whole_name,
            "{purpose:?} transcript against the base value:\n{transcript}"
        );
        assert_eq!(
            hex::encode(Sha256::digest(transcript.as_bytes())),
            expected,
            "{purpose:?} transcript:\n{transcript}"
        );
    }
}
