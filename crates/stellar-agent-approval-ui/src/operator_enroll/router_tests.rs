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

use super::{OperatorEnrollState, build_router};

const HOST: &str = "127.0.0.1:9999";
const ORIGIN: &str = "http://127.0.0.1:9999";

struct Harness {
    router: Router,
    state: Arc<OperatorEnrollState>,
    store_path: std::path::PathBuf,
    bootstrap_hex: String,
    cookie_name: String,
    clock: SessionClock,
    proof: StdMutex<Option<String>>,
    completion_rx: oneshot::Receiver<()>,
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
        let state = Arc::new(OperatorEnrollState {
            profile: "default".to_owned(),
            auth: StdMutex::new(auth),
            store: OperatorApprovalCredentialStore::new(store_path.clone()),
            label_prefill,
            identity: PageIdentity::neutral(),
            completion: StdMutex::new(Some(tx)),
        });
        let local_addr: SocketAddr = HOST.parse().unwrap();
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
    let open = format!(r#"<script type="application/json" id="{id}">"#);
    let start = html.find(&open).expect("data island opening tag") + open.len();
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
    let mut bytes = vec![seed; 65];
    bytes[0] = 0x04;
    URL_SAFE_NO_PAD.encode(bytes)
}

fn valid_body(seed: u8) -> serde_json::Value {
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

    // The session-derived CSRF must actually authorize a POST.
    let (post_status, post_body) = h
        .post(
            "/enroll/credential",
            Some(&cookie),
            Some(&csrf),
            valid_body(1),
        )
        .await;
    assert_eq!(post_status, StatusCode::OK, "body: {post_body}");
    assert_eq!(post_body["status"], "enrolled");
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
        .post("/enroll/credential", None, Some(&csrf), valid_body(1))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn post_missing_csrf_is_rejected() {
    let h = Harness::new();
    let (cookie, _csrf) = h.establish_session().await;
    let (status, body) = h
        .post("/enroll/credential", Some(&cookie), None, valid_body(1))
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
            valid_body(2),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "csrf_invalid");
}

#[tokio::test]
async fn post_credential_id_too_short_is_rejected() {
    let h = Harness::new();
    let (cookie, csrf) = h.establish_session().await;
    let mut body = valid_body(3);
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
    let mut body = valid_body(4);
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
    let mut body = valid_body(5);
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
    let mut body = valid_body(6);
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
    let mut body = valid_body(7);
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
    let mut body = valid_body(8);
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
    let mut body = valid_body(9);
    body["label"] = json!("x".repeat(65));
    let (status, body) = h
        .post("/enroll/credential", Some(&cookie), Some(&csrf), body)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "label_invalid");
}

#[tokio::test]
async fn post_sign_count_out_of_range_is_rejected() {
    let h = Harness::new();
    let (cookie, csrf) = h.establish_session().await;
    let mut body = valid_body(10);
    // u32::MAX + 1 does not fit in the wire type's `u32` field.
    body["sign_count"] = json!(4_294_967_296_u64);
    let (status, _body) = h
        .post("/enroll/credential", Some(&cookie), Some(&csrf), body)
        .await;
    assert!(
        status.is_client_error(),
        "out-of-range sign_count must be rejected, got {status}"
    );
}

#[tokio::test]
async fn post_sign_count_negative_is_rejected() {
    let h = Harness::new();
    let (cookie, csrf) = h.establish_session().await;
    let mut body = valid_body(11);
    body["sign_count"] = json!(-1);
    let (status, _body) = h
        .post("/enroll/credential", Some(&cookie), Some(&csrf), body)
        .await;
    assert!(
        status.is_client_error(),
        "negative sign_count must be rejected, got {status}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Success path, duplicate id, single-use latch
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn post_valid_credential_enrolls_and_persists_sign_count() {
    let h = Harness::new();
    let (cookie, csrf) = h.establish_session().await;
    let (status, body) = h
        .post(
            "/enroll/credential",
            Some(&cookie),
            Some(&csrf),
            valid_body(20),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["status"], "enrolled");

    let store = OperatorApprovalCredentialStore::new(h.store_path.clone());
    let listed = store.list().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].rp_id, "localhost");
    assert_eq!(listed[0].label, "laptop");
    assert_eq!(listed[0].sign_count, Some(3));
}

#[tokio::test]
async fn post_duplicate_credential_id_is_refused_without_consuming_the_latch() {
    let h = Harness::seeded(OperatorApprovalCredential {
        credential_id_b64url: valid_credential_id_b64(60),
        public_key_sec1_b64: valid_pubkey_b64(60),
        rp_id: "localhost".to_owned(),
        label: "existing".to_owned(),
        registered_at_unix_ms: 1,
        sign_count: None,
    });
    let (cookie, csrf) = h.establish_session().await;

    let (status, body) = h
        .post(
            "/enroll/credential",
            Some(&cookie),
            Some(&csrf),
            valid_body(60),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"], "duplicate_credential_id");

    // The latch must still be available: a distinct credential id still
    // succeeds after the duplicate-id failure.
    let (status2, body2) = h
        .post(
            "/enroll/credential",
            Some(&cookie),
            Some(&csrf),
            valid_body(61),
        )
        .await;
    assert_eq!(
        status2,
        StatusCode::OK,
        "latch must not be consumed by a duplicate-id failure: {body2}"
    );
}

#[tokio::test]
async fn second_successful_shape_post_after_completion_is_refused() {
    let h = Harness::new();
    let (cookie, csrf) = h.establish_session().await;

    let (status1, body1) = h
        .post(
            "/enroll/credential",
            Some(&cookie),
            Some(&csrf),
            valid_body(40),
        )
        .await;
    assert_eq!(status1, StatusCode::OK, "first enrollment: {body1}");

    // A second, well-formed POST for a DIFFERENT credential id must be
    // refused outright — the single-use latch, not the store's own
    // duplicate-id check, is what stops it.
    let (status2, body2) = h
        .post(
            "/enroll/credential",
            Some(&cookie),
            Some(&csrf),
            valid_body(41),
        )
        .await;
    assert_eq!(status2, StatusCode::CONFLICT);
    assert_eq!(body2["error"], "already_completed");

    let store = OperatorApprovalCredentialStore::new(h.store_path.clone());
    let listed = store.list().unwrap();
    assert_eq!(
        listed.len(),
        1,
        "the second POST must not have persisted a second credential"
    );
}

#[tokio::test]
async fn completion_signal_fires_exactly_once() {
    let mut h = Harness::new();
    let (cookie, csrf) = h.establish_session().await;
    let (status, _) = h
        .post(
            "/enroll/credential",
            Some(&cookie),
            Some(&csrf),
            valid_body(50),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    // Swap the receiver out (rather than moving `h.completion_rx` directly)
    // so `h` stays fully initialised for the `&h` borrows below.
    let rx = std::mem::replace(&mut h.completion_rx, oneshot::channel().1);
    let received = rx.await;
    assert!(received.is_ok(), "completion signal must fire on success");

    // A second successful-shape POST cannot fire it again (there is nothing
    // left to fire — the sender was consumed on the first success); confirm
    // it is refused rather than silently accepted.
    let (status2, body2) = h
        .post(
            "/enroll/credential",
            Some(&cookie),
            Some(&csrf),
            valid_body(51),
        )
        .await;
    assert_eq!(status2, StatusCode::CONFLICT);
    assert_eq!(body2["error"], "already_completed");
}

// ─────────────────────────────────────────────────────────────────────────────
// Session proof, lifetime and cookie shape
// ─────────────────────────────────────────────────────────────────────────────

/// The session cookie and a valid CSRF value do not authorize an enrollment
/// without the session proof: missing, malformed, wrong, and the session id
/// in its place are all refused with `session_proof_invalid`. Nothing is
/// persisted and the completion signal stays unfired.
#[tokio::test]
async fn cookie_and_csrf_without_proof_cannot_mutate() {
    let mut h = Harness::new();
    let (cookie, csrf) = h.establish_session().await;
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
                valid_body(7),
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

    // The same request with the proof is the operator's and enrolls.
    let (status, body) = h
        .post_with_proof(
            "/enroll/credential",
            Some(&cookie),
            Some(&csrf),
            Some(&h.proof()),
            valid_body(7),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(store.list().unwrap().len(), 1);
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

    for body in [valid_body(9), json!({"credential_id_b64url": "x"})] {
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
            valid_body(3),
        )
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
            valid_body(4),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, body) = h
        .post(
            "/enroll/credential",
            Some(&cookie),
            Some(&csrf),
            json!({
                "credential_id_b64url": valid_credential_id_b64(4),
                "public_key_sec1_b64": valid_pubkey_b64(4),
                "label": "",
                "sign_count": 0,
            }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

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
    let (status, _) = h
        .post(
            "/enroll/credential",
            Some(&cookie),
            Some(&csrf),
            valid_body(5),
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
