//! Router-level HTTP tests for the approval-inbox server.
//!
//! These drive the assembled `Router` via `tower::ServiceExt::oneshot`, so they
//! exercise the full middleware stack (Host / Origin / security headers / body
//! limit) plus the session-cookie and CSRF auth boundary against a real
//! `PendingApprovalStore` and mock keyring.

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
use axum::http::{Request, StatusCode, header};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use keyring_core::Entry as KeyringEntry;
use serial_test::serial;
use tempfile::TempDir;
use tower::ServiceExt as _;

use stellar_agent_core::approval::attestation::{compute_attestation, verify_attestation};
use stellar_agent_core::approval::{
    ApprovalKind, DEFAULT_TTL_MS, PendingApproval, PendingApprovalStore, decode_sha256_hex,
    process_uid_for_attestation,
};
use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_core::profile::schema::KeyringEntryRef;
use stellar_agent_core::timefmt;

use crate::auth::{AuthState, OpaqueToken, compute_csrf};
use crate::decision::DecisionContext;
use crate::{ServeConfig, ServeStartError, ServeState, build_router, start_serve};

const BOUND: &str = "127.0.0.1:8080";
const HOST: &str = "127.0.0.1:8080";
const ORIGIN: &str = "http://127.0.0.1:8080";

struct Harness {
    _dir: TempDir,
    state: ServeState,
    store_path: std::path::PathBuf,
    bootstrap_hex: String,
    raw_key: [u8; 32],
}

impl Harness {
    fn new(tag: &str) -> Self {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let store_path = dir.path().join("default.toml");
        let audit_path = dir.path().join("audit.log");
        let grant_path = dir.path().join("grants.toml");
        let svc = format!("stellar-agent-attestation-ui-router-{tag}");
        let raw_key = [0xABu8; 32];
        KeyringEntry::new(&svc, "default")
            .unwrap()
            .set_password(&URL_SAFE_NO_PAD.encode(raw_key))
            .unwrap();

        let audit_writer = Arc::new(StdMutex::new(
            AuditWriter::open(audit_path, None).expect("audit writer"),
        ));
        let ctx = DecisionContext::new(
            "ui-router-test".to_owned(),
            store_path.clone(),
            KeyringEntryRef::new(svc, "default"),
            audit_writer,
            Some(grant_path),
        );
        let bootstrap = OpaqueToken::generate();
        let bootstrap_hex = bootstrap.to_hex();
        let state = ServeState {
            auth: Arc::new(StdMutex::new(AuthState::new(bootstrap))),
            ctx: Arc::new(ctx),
        };
        Self {
            _dir: dir,
            state,
            store_path,
            bootstrap_hex,
            raw_key,
        }
    }

    fn router(&self) -> Router {
        let bound: SocketAddr = BOUND.parse().unwrap();
        build_router(self.state.clone(), bound)
    }

    fn insert(&self, entry: PendingApproval) -> String {
        let nonce = entry.approval_nonce.clone();
        let mut store = PendingApprovalStore::open(self.store_path.clone()).unwrap();
        store
            .insert(entry, timefmt::now_unix_ms().unwrap())
            .unwrap();
        nonce
    }

    /// Perform the bootstrap exchange and return the session cookie header value.
    async fn bootstrap(&self) -> String {
        let req = Request::builder()
            .uri(format!("/bootstrap/{}", self.bootstrap_hex))
            .header(header::HOST, HOST)
            .body(Body::empty())
            .unwrap();
        let resp = self.router().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER, "bootstrap should 302");
        let set_cookie = resp
            .headers()
            .get(header::SET_COOKIE)
            .expect("bootstrap sets a session cookie")
            .to_str()
            .unwrap();
        // Keep only the `name=value` part for the Cookie header.
        set_cookie.split(';').next().unwrap().trim().to_owned()
    }

    /// The session CSRF value for `nonce` under the live session key.
    fn csrf_for(&self, nonce: &str) -> String {
        let guard = self.state.auth.lock().unwrap();
        let session = guard.session.as_ref().expect("session established");
        compute_csrf(&session.csrf_key, nonce)
    }
}

fn uid() -> String {
    process_uid_for_attestation().expect("uid on test host")
}

fn payment_entry(ttl_ms: u64) -> PendingApproval {
    PendingApproval::new_payment_pending(
        "b64xdr".to_owned(),
        b"fake-xdr",
        "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
        2_500_000,
        "XLM".to_owned(),
        None,
        100,
        1_234_567,
        uid(),
        ttl_ms,
    )
    .unwrap()
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

// ─────────────────────────────────────────────────────────────────────────────
// Bootstrap + session
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
#[serial]
async fn bootstrap_is_single_use() {
    let h = Harness::new("bootstrap-single");
    let cookie = h.bootstrap().await;
    assert!(cookie.starts_with("stellar_agent_approval_session="));

    // Second attempt with the same token must 404.
    let req = Request::builder()
        .uri(format!("/bootstrap/{}", h.bootstrap_hex))
        .header(header::HOST, HOST)
        .body(Body::empty())
        .unwrap();
    let resp = h.router().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // Garbage token also 404.
    let req = Request::builder()
        .uri("/bootstrap/deadbeef")
        .header(header::HOST, HOST)
        .body(Body::empty())
        .unwrap();
    let resp = h.router().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
#[serial]
async fn protected_route_without_cookie_is_404() {
    let h = Harness::new("no-cookie");
    let req = Request::builder()
        .uri("/pending.json")
        .header(header::HOST, HOST)
        .body(Body::empty())
        .unwrap();
    let resp = h.router().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
#[serial]
async fn wrong_host_is_421() {
    let h = Harness::new("wrong-host");
    let req = Request::builder()
        .uri("/inbox")
        .header(header::HOST, "evil.example:8080")
        .body(Body::empty())
        .unwrap();
    let resp = h.router().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::MISDIRECTED_REQUEST);
}

// ─────────────────────────────────────────────────────────────────────────────
// Origin + CSRF on POST
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
#[serial]
async fn post_without_origin_is_403() {
    let h = Harness::new("no-origin");
    let cookie = h.bootstrap().await;
    let nonce = h.insert(payment_entry(DEFAULT_TTL_MS));
    let csrf = h.csrf_for(&nonce);

    let req = Request::builder()
        .method("POST")
        .uri(format!("/approval/{nonce}/approve"))
        .header(header::HOST, HOST)
        .header(header::COOKIE, &cookie)
        .header("x-stellar-approval-csrf", csrf)
        .body(Body::empty())
        .unwrap();
    let resp = h.router().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
#[serial]
async fn post_with_missing_or_wrong_csrf_is_403_and_does_not_mutate() {
    let h = Harness::new("bad-csrf");
    let cookie = h.bootstrap().await;
    let nonce = h.insert(payment_entry(DEFAULT_TTL_MS));

    // Missing CSRF header.
    let req = Request::builder()
        .method("POST")
        .uri(format!("/approval/{nonce}/approve"))
        .header(header::HOST, HOST)
        .header(header::ORIGIN, ORIGIN)
        .header(header::COOKIE, &cookie)
        .body(Body::empty())
        .unwrap();
    let resp = h.router().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Wrong CSRF value.
    let req = Request::builder()
        .method("POST")
        .uri(format!("/approval/{nonce}/reject"))
        .header(header::HOST, HOST)
        .header(header::ORIGIN, ORIGIN)
        .header(header::COOKIE, &cookie)
        .header("x-stellar-approval-csrf", "00".repeat(32))
        .body(Body::empty())
        .unwrap();
    let resp = h.router().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // The entry must be untouched: still pending, not attested, not rejected.
    let store = PendingApprovalStore::open(h.store_path.clone()).unwrap();
    let entry = store.get(&nonce).expect("entry still present");
    assert!(matches!(entry.kind, ApprovalKind::PaymentSimulated { .. }));
    assert!(entry.attestation_blob_b64.is_none());
}

// ─────────────────────────────────────────────────────────────────────────────
// Approve / reject happy paths
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
#[serial]
async fn approve_payment_mints_verifiable_attestation() {
    let h = Harness::new("approve-ok");
    let cookie = h.bootstrap().await;
    let entry = payment_entry(DEFAULT_TTL_MS);
    let process_uid = entry.process_uid.clone();
    let envelope_sha256_hex = match &entry.kind {
        ApprovalKind::PaymentSimulated {
            envelope_sha256_hex,
            ..
        } => envelope_sha256_hex.clone(),
        _ => unreachable!(),
    };
    let nonce = h.insert(entry);
    let csrf = h.csrf_for(&nonce);

    let req = Request::builder()
        .method("POST")
        .uri(format!("/approval/{nonce}/approve"))
        .header(header::HOST, HOST)
        .header(header::ORIGIN, ORIGIN)
        .header(header::COOKIE, &cookie)
        .header("x-stellar-approval-csrf", csrf)
        .body(Body::empty())
        .unwrap();
    let resp = h.router().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["status"], "attested");
    let blob_b64 = json["attestation"].as_str().unwrap();

    let sha = decode_sha256_hex(&envelope_sha256_hex).unwrap();
    let expected = compute_attestation(&h.raw_key, &nonce, &sha, &process_uid);
    let blob: [u8; 32] = URL_SAFE_NO_PAD
        .decode(blob_b64)
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(blob, expected);
    assert!(verify_attestation(
        &h.raw_key,
        &nonce,
        &sha,
        &process_uid,
        &blob
    ));
}

#[tokio::test]
#[serial]
async fn reject_creates_tombstone() {
    let h = Harness::new("reject-ok");
    let cookie = h.bootstrap().await;
    let nonce = h.insert(payment_entry(DEFAULT_TTL_MS));
    let csrf = h.csrf_for(&nonce);

    let req = Request::builder()
        .method("POST")
        .uri(format!("/approval/{nonce}/reject"))
        .header(header::HOST, HOST)
        .header(header::ORIGIN, ORIGIN)
        .header(header::COOKIE, &cookie)
        .header("x-stellar-approval-csrf", csrf)
        .body(Body::empty())
        .unwrap();
    let resp = h.router().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["status"], "rejected");

    let store = PendingApprovalStore::open(h.store_path.clone()).unwrap();
    let entry = store.get(&nonce).expect("tombstone present");
    assert!(matches!(entry.kind, ApprovalKind::Rejected { .. }));
}

#[tokio::test]
#[serial]
async fn second_approve_is_idempotent_already_resolved() {
    let h = Harness::new("reshow");
    let cookie = h.bootstrap().await;
    let nonce = h.insert(payment_entry(DEFAULT_TTL_MS));
    let csrf = h.csrf_for(&nonce);

    let mk = || {
        Request::builder()
            .method("POST")
            .uri(format!("/approval/{nonce}/approve"))
            .header(header::HOST, HOST)
            .header(header::ORIGIN, ORIGIN)
            .header(header::COOKIE, &cookie)
            .header("x-stellar-approval-csrf", &csrf)
            .body(Body::empty())
            .unwrap()
    };

    let first = h.router().oneshot(mk()).await.unwrap();
    let first_json = body_json(first).await;
    let first_blob = first_json["attestation"].as_str().unwrap().to_owned();

    let second = h.router().oneshot(mk()).await.unwrap();
    assert_eq!(second.status(), StatusCode::OK);
    let second_json = body_json(second).await;
    assert_eq!(second_json["status"], "already_resolved");
    assert_eq!(second_json["attestation"], first_blob);
}

#[tokio::test]
#[serial]
async fn approve_expired_entry_reports_expired() {
    let h = Harness::new("expired");
    let cookie = h.bootstrap().await;
    let nonce = h.insert(payment_entry(1));
    let csrf = h.csrf_for(&nonce);
    std::thread::sleep(std::time::Duration::from_millis(5));

    let req = Request::builder()
        .method("POST")
        .uri(format!("/approval/{nonce}/approve"))
        .header(header::HOST, HOST)
        .header(header::ORIGIN, ORIGIN)
        .header(header::COOKIE, &cookie)
        .header("x-stellar-approval-csrf", csrf)
        .body(Body::empty())
        .unwrap();
    let resp = h.router().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["status"], "expired");

    let store = PendingApprovalStore::open(h.store_path.clone()).unwrap();
    assert!(store.get(&nonce).unwrap().attestation_blob_b64.is_none());
}

#[tokio::test]
#[serial]
async fn approve_foreign_process_uid_reports_user_mismatch() {
    let h = Harness::new("approve-mismatch");
    let cookie = h.bootstrap().await;
    let entry = PendingApproval::new_payment_pending(
        "b64xdr".to_owned(),
        b"fake-xdr",
        "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
        2_500_000,
        "XLM".to_owned(),
        None,
        100,
        1_234_567,
        "99999999".to_owned(),
        DEFAULT_TTL_MS,
    )
    .unwrap();
    let nonce = h.insert(entry);
    let csrf = h.csrf_for(&nonce);

    let req = Request::builder()
        .method("POST")
        .uri(format!("/approval/{nonce}/approve"))
        .header(header::HOST, HOST)
        .header(header::ORIGIN, ORIGIN)
        .header(header::COOKIE, &cookie)
        .header("x-stellar-approval-csrf", csrf)
        .body(Body::empty())
        .unwrap();
    let resp = h.router().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["status"], "user_mismatch");
    assert!(json["message"].as_str().unwrap().contains("OS user"));

    let store = PendingApprovalStore::open(h.store_path.clone()).unwrap();
    assert!(store.get(&nonce).unwrap().attestation_blob_b64.is_none());
}

#[tokio::test]
#[serial]
async fn reject_foreign_process_uid_reports_user_mismatch() {
    let h = Harness::new("reject-mismatch");
    let cookie = h.bootstrap().await;
    let entry = PendingApproval::new_payment_pending(
        "b64xdr".to_owned(),
        b"fake-xdr",
        "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
        2_500_000,
        "XLM".to_owned(),
        None,
        100,
        1_234_567,
        "99999999".to_owned(),
        DEFAULT_TTL_MS,
    )
    .unwrap();
    let nonce = h.insert(entry);
    let csrf = h.csrf_for(&nonce);

    let req = Request::builder()
        .method("POST")
        .uri(format!("/approval/{nonce}/reject"))
        .header(header::HOST, HOST)
        .header(header::ORIGIN, ORIGIN)
        .header(header::COOKIE, &cookie)
        .header("x-stellar-approval-csrf", csrf)
        .body(Body::empty())
        .unwrap();
    let resp = h.router().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["status"], "user_mismatch");

    let store = PendingApprovalStore::open(h.store_path.clone()).unwrap();
    let entry = store.get(&nonce).unwrap();
    assert!(
        !matches!(entry.kind, ApprovalKind::Rejected { .. }),
        "a foreign-uid caller must not be able to reject this entry"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// pending.json + detail
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
#[serial]
async fn pending_json_reports_shape() {
    let h = Harness::new("pending-json");
    let cookie = h.bootstrap().await;
    h.insert(payment_entry(DEFAULT_TTL_MS));

    let req = Request::builder()
        .uri("/pending.json")
        .header(header::HOST, HOST)
        .header(header::COOKIE, &cookie)
        .body(Body::empty())
        .unwrap();
    let resp = h.router().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert!(json["pending"].is_array());
    assert_eq!(json["pending"].as_array().unwrap().len(), 1);
    assert_eq!(json["expired_count"], 0);
}

#[tokio::test]
#[serial]
async fn detail_page_renders_for_known_nonce() {
    let h = Harness::new("detail");
    let cookie = h.bootstrap().await;
    let nonce = h.insert(payment_entry(DEFAULT_TTL_MS));

    let req = Request::builder()
        .uri(format!("/approval/{nonce}"))
        .header(header::HOST, HOST)
        .header(header::COOKIE, &cookie)
        .body(Body::empty())
        .unwrap();
    let resp = h.router().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 256 * 1024).await.unwrap();
    let html = std::str::from_utf8(&bytes).unwrap();
    assert!(html.contains("Approval detail"));
    assert!(html.contains(&nonce));
    assert!(html.contains("approval-data"));
}

// ─────────────────────────────────────────────────────────────────────────────
// Busy + body cap
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
#[serial]
async fn approve_when_store_locked_returns_503_busy() {
    let h = Harness::new("busy");
    let cookie = h.bootstrap().await;
    let nonce = h.insert(payment_entry(DEFAULT_TTL_MS));
    let csrf = h.csrf_for(&nonce);

    // Hold the store lock for the whole request so open_with_retry exhausts.
    let _holder = PendingApprovalStore::open(h.store_path.clone()).unwrap();

    let req = Request::builder()
        .method("POST")
        .uri(format!("/approval/{nonce}/approve"))
        .header(header::HOST, HOST)
        .header(header::ORIGIN, ORIGIN)
        .header(header::COOKIE, &cookie)
        .header("x-stellar-approval-csrf", csrf)
        .body(Body::empty())
        .unwrap();
    let resp = h.router().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let json = body_json(resp).await;
    assert_eq!(json["status"], "busy");
    assert_eq!(json["retriable"], true);
}

// ─────────────────────────────────────────────────────────────────────────────
// start_serve bind guards
// ─────────────────────────────────────────────────────────────────────────────

fn config_for(
    bind_addr: SocketAddr,
    store_path: std::path::PathBuf,
    audit: std::path::PathBuf,
) -> ServeConfig {
    let audit_writer = Arc::new(StdMutex::new(AuditWriter::open(audit, None).unwrap()));
    let ctx = DecisionContext::new(
        "ui-bind-test".to_owned(),
        store_path,
        KeyringEntryRef::new("stellar-agent-attestation-ui-bind", "default"),
        audit_writer,
        None,
    );
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel::<usize>();
    ServeConfig::new(bind_addr, ctx, tx, false)
}

#[tokio::test]
async fn start_serve_rejects_non_loopback_bind() {
    let dir = TempDir::new().unwrap();
    let config = config_for(
        "0.0.0.0:0".parse().unwrap(),
        dir.path().join("default.toml"),
        dir.path().join("audit.log"),
    );
    let err = start_serve(config).await.unwrap_err();
    assert!(matches!(err, ServeStartError::NonLoopbackBind { .. }));
}

#[tokio::test]
async fn start_serve_bind_conflict_is_clean_error() {
    let dir = TempDir::new().unwrap();
    // Occupy a loopback port, then ask the server to bind the same one.
    let occupier = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = occupier.local_addr().unwrap().port();
    let config = config_for(
        format!("127.0.0.1:{port}").parse().unwrap(),
        dir.path().join("default.toml"),
        dir.path().join("audit.log"),
    );
    let err = start_serve(config).await.unwrap_err();
    assert!(matches!(err, ServeStartError::Bind { .. }));
}

/// Exercises `start_serve` end-to-end against a real `127.0.0.1:0` bind: the
/// `ServeHandle` accessors, a real TCP connection through `axum::serve` (not
/// the in-process `tower::ServiceExt::oneshot` harness used everywhere else in
/// this file), and a clean `shutdown()` of both the server and watcher tasks.
#[tokio::test]
#[serial]
async fn start_serve_end_to_end_over_real_tcp_bind() {
    stellar_agent_test_support::keyring_mock::install().unwrap();
    let dir = TempDir::new().unwrap();
    let config = config_for(
        "127.0.0.1:0".parse().unwrap(),
        dir.path().join("default.toml"),
        dir.path().join("audit.log"),
    );

    let handle = start_serve(config)
        .await
        .expect("start_serve must succeed on a fresh loopback bind");

    let local = handle.local_addr();
    assert!(local.ip().is_loopback());
    assert_ne!(local.port(), 0, "the OS must assign a concrete port");

    let debug_repr = format!("{handle:?}");
    assert!(debug_repr.contains("ServeHandle"));
    assert!(debug_repr.contains(&local.to_string()));

    let token_hex = handle.bootstrap_token_hex().to_owned();
    assert_eq!(token_hex.len(), 64);
    assert!(token_hex.bytes().all(|b| b.is_ascii_hexdigit()));
    assert_eq!(
        handle.bootstrap_url(),
        format!("http://127.0.0.1:{}/bootstrap/{token_hex}", local.port())
    );

    // A real socket request — exercises `axum::serve` / `TcpListener` inside
    // `start_serve`, not just the router the oneshot harness builds directly.
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let mut stream = tokio::net::TcpStream::connect(local)
        .await
        .expect("connect to the real bound listener");
    let request = format!(
        "GET /bootstrap/{token_hex} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
        local.port()
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write the bootstrap request");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("read the bootstrap response");
    let response_text = String::from_utf8_lossy(&response);
    assert!(
        response_text.starts_with("HTTP/1.1 303"),
        "bootstrap exchange over a real socket must redirect: {response_text}"
    );
    assert!(
        response_text.to_ascii_lowercase().contains("set-cookie"),
        "bootstrap exchange must set the session cookie: {response_text}"
    );

    handle
        .shutdown()
        .await
        .expect("shutdown must join both tasks cleanly");
}

#[tokio::test]
#[serial]
async fn oversized_post_body_is_rejected() {
    let h = Harness::new("body-cap");
    // Host + Origin are valid; the body-limit layer sits before the handler, so
    // no session cookie is needed to observe the 413.
    let big = vec![0u8; crate::BODY_LIMIT_BYTES + 4096];
    let req = Request::builder()
        .method("POST")
        .uri("/approval/AAAAAAAAAAAAAAAAAAAAAA/approve")
        .header(header::HOST, HOST)
        .header(header::ORIGIN, ORIGIN)
        .header(header::CONTENT_LENGTH, big.len().to_string())
        .body(Body::from(big))
        .unwrap();
    let resp = h.router().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /inbox
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
#[serial]
async fn inbox_get_renders_for_authenticated_session() {
    let h = Harness::new("inbox-ok");
    let cookie = h.bootstrap().await;
    h.insert(payment_entry(DEFAULT_TTL_MS));

    let req = Request::builder()
        .uri("/inbox")
        .header(header::HOST, HOST)
        .header(header::COOKIE, &cookie)
        .body(Body::empty())
        .unwrap();
    let resp = h.router().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 256 * 1024).await.unwrap();
    let html = std::str::from_utf8(&bytes).unwrap();
    assert!(html.contains(r#"id="pending-data""#));
    assert!(html.contains("Pending approvals"));
}

#[tokio::test]
#[serial]
async fn inbox_get_without_cookie_is_404() {
    let h = Harness::new("inbox-no-cookie");
    let req = Request::builder()
        .uri("/inbox")
        .header(header::HOST, HOST)
        .body(Body::empty())
        .unwrap();
    let resp = h.router().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// `?include_expired=1` on `/inbox` and `/pending.json` includes an already
/// expired entry that the default (unset) query omits.
#[tokio::test]
#[serial]
async fn include_expired_query_flag_controls_expired_visibility() {
    let h = Harness::new("include-expired");
    let cookie = h.bootstrap().await;
    let nonce = h.insert(payment_entry(1)); // TTL=1ms
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    let default_req = Request::builder()
        .uri("/pending.json")
        .header(header::HOST, HOST)
        .header(header::COOKIE, &cookie)
        .body(Body::empty())
        .unwrap();
    let default_resp = h.router().oneshot(default_req).await.unwrap();
    let default_json = body_json(default_resp).await;
    assert_eq!(default_json["pending"].as_array().unwrap().len(), 0);
    assert_eq!(default_json["expired_count"], 1);

    let included_req = Request::builder()
        .uri("/pending.json?include_expired=1")
        .header(header::HOST, HOST)
        .header(header::COOKIE, &cookie)
        .body(Body::empty())
        .unwrap();
    let included_resp = h.router().oneshot(included_req).await.unwrap();
    let included_json = body_json(included_resp).await;
    assert_eq!(included_json["pending"].as_array().unwrap().len(), 1);
    assert_eq!(
        included_json["pending"][0]["approval_nonce"],
        nonce.as_str()
    );

    // Same flag on the inbox HTML shell.
    let inbox_req = Request::builder()
        .uri("/inbox?include_expired=1")
        .header(header::HOST, HOST)
        .header(header::COOKIE, &cookie)
        .body(Body::empty())
        .unwrap();
    let inbox_resp = h.router().oneshot(inbox_req).await.unwrap();
    let bytes = to_bytes(inbox_resp.into_body(), 256 * 1024).await.unwrap();
    let html = std::str::from_utf8(&bytes).unwrap();
    assert!(html.contains(&nonce));
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /approval/{nonce} — auth, not-found, and reshow
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
#[serial]
async fn detail_page_without_cookie_is_404() {
    let h = Harness::new("detail-no-cookie");
    let nonce = h.insert(payment_entry(DEFAULT_TTL_MS));
    let req = Request::builder()
        .uri(format!("/approval/{nonce}"))
        .header(header::HOST, HOST)
        .body(Body::empty())
        .unwrap();
    let resp = h.router().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// A session exists, but the submitted cookie value does not match it — a
/// forged or stale cookie, distinct from an absent one.
#[tokio::test]
#[serial]
async fn protected_route_with_wrong_cookie_value_is_404() {
    let h = Harness::new("wrong-cookie-value");
    let _cookie = h.bootstrap().await;
    let req = Request::builder()
        .uri("/pending.json")
        .header(header::HOST, HOST)
        .header(
            header::COOKIE,
            format!("stellar_agent_approval_session={}", "0".repeat(64)),
        )
        .body(Body::empty())
        .unwrap();
    let resp = h.router().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
#[serial]
async fn detail_page_unknown_nonce_returns_not_found_page() {
    let h = Harness::new("detail-unknown");
    let cookie = h.bootstrap().await;
    let req = Request::builder()
        .uri("/approval/AAAAAAAAAAAAAAAAAAAAAA")
        .header(header::HOST, HOST)
        .header(header::COOKIE, &cookie)
        .body(Body::empty())
        .unwrap();
    let resp = h.router().oneshot(req).await.unwrap();
    // A clean 200 "not found in queue" page, not a 404 — the caller is
    // already authenticated, so this is a normal UX case, not an
    // auth-boundary rejection.
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 256 * 1024).await.unwrap();
    let html = std::str::from_utf8(&bytes).unwrap();
    assert!(html.contains("Approval not found"));
}

#[tokio::test]
#[serial]
async fn detail_page_reshows_attestation_after_approve() {
    let h = Harness::new("detail-reshow");
    let cookie = h.bootstrap().await;
    let nonce = h.insert(payment_entry(DEFAULT_TTL_MS));
    let csrf = h.csrf_for(&nonce);

    let approve_req = Request::builder()
        .method("POST")
        .uri(format!("/approval/{nonce}/approve"))
        .header(header::HOST, HOST)
        .header(header::ORIGIN, ORIGIN)
        .header(header::COOKIE, &cookie)
        .header("x-stellar-approval-csrf", csrf)
        .body(Body::empty())
        .unwrap();
    let approve_resp = h.router().oneshot(approve_req).await.unwrap();
    let attestation = body_json(approve_resp).await["attestation"]
        .as_str()
        .unwrap()
        .to_owned();

    let detail_req = Request::builder()
        .uri(format!("/approval/{nonce}"))
        .header(header::HOST, HOST)
        .header(header::COOKIE, &cookie)
        .body(Body::empty())
        .unwrap();
    let detail_resp = h.router().oneshot(detail_req).await.unwrap();
    assert_eq!(detail_resp.status(), StatusCode::OK);
    let bytes = to_bytes(detail_resp.into_body(), 256 * 1024).await.unwrap();
    let html = std::str::from_utf8(&bytes).unwrap();
    assert!(html.contains(&attestation));
    assert!(!html.contains(r#"id="approve-btn""#));
}

// ─────────────────────────────────────────────────────────────────────────────
// POST auth boundary (no session cookie at all)
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
#[serial]
async fn post_approve_and_reject_without_cookie_are_404() {
    let h = Harness::new("post-no-cookie");
    let nonce = h.insert(payment_entry(DEFAULT_TTL_MS));

    for action in ["approve", "reject"] {
        let req = Request::builder()
            .method("POST")
            .uri(format!("/approval/{nonce}/{action}"))
            .header(header::HOST, HOST)
            .header(header::ORIGIN, ORIGIN)
            .body(Body::empty())
            .unwrap();
        let resp = h.router().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "{action} without a session cookie must 404, not surface a CSRF error"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /static/app.js
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
#[serial]
async fn static_app_js_requires_session_and_serves_expected_content() {
    let h = Harness::new("app-js");

    let no_cookie_req = Request::builder()
        .uri("/static/app.js")
        .header(header::HOST, HOST)
        .body(Body::empty())
        .unwrap();
    let no_cookie_resp = h.router().oneshot(no_cookie_req).await.unwrap();
    assert_eq!(no_cookie_resp.status(), StatusCode::NOT_FOUND);

    let cookie = h.bootstrap().await;
    let req = Request::builder()
        .uri("/static/app.js")
        .header(header::HOST, HOST)
        .header(header::COOKIE, &cookie)
        .body(Body::empty())
        .unwrap();
    let resp = h.router().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap(),
        "application/javascript; charset=utf-8"
    );
    let bytes = to_bytes(resp.into_body(), 256 * 1024).await.unwrap();
    assert_eq!(bytes.as_ref(), crate::web::APP_JS);
}

// ─────────────────────────────────────────────────────────────────────────────
// GET data endpoints under a locked store
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
#[serial]
async fn get_endpoints_report_busy_or_degrade_when_store_locked() {
    let h = Harness::new("get-busy");
    let cookie = h.bootstrap().await;
    let nonce = h.insert(payment_entry(DEFAULT_TTL_MS));

    let _holder = PendingApprovalStore::open(h.store_path.clone()).unwrap();

    // /pending.json: a data endpoint — busy surfaces as 503.
    let pending_req = Request::builder()
        .uri("/pending.json")
        .header(header::HOST, HOST)
        .header(header::COOKIE, &cookie)
        .body(Body::empty())
        .unwrap();
    let pending_resp = h.router().oneshot(pending_req).await.unwrap();
    assert_eq!(pending_resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body_json(pending_resp).await["error"], "store_busy");

    // /approval/{nonce}: its own store open also surfaces 503 when locked.
    let detail_req = Request::builder()
        .uri(format!("/approval/{nonce}"))
        .header(header::HOST, HOST)
        .header(header::COOKIE, &cookie)
        .body(Body::empty())
        .unwrap();
    let detail_resp = h.router().oneshot(detail_req).await.unwrap();
    assert_eq!(detail_resp.status(), StatusCode::SERVICE_UNAVAILABLE);

    // /inbox: a page, not a data endpoint — it still renders (empty list);
    // the client-side poll of /pending.json recovers once the lock clears.
    let inbox_req = Request::builder()
        .uri("/inbox")
        .header(header::HOST, HOST)
        .header(header::COOKIE, &cookie)
        .body(Body::empty())
        .unwrap();
    let inbox_resp = h.router().oneshot(inbox_req).await.unwrap();
    assert_eq!(inbox_resp.status(), StatusCode::OK);
    let bytes = to_bytes(inbox_resp.into_body(), 256 * 1024).await.unwrap();
    let html = std::str::from_utf8(&bytes).unwrap();
    assert!(html.contains(r#""pending":[]"#));
}

// ─────────────────────────────────────────────────────────────────────────────
// outcome_to_response: kinds outcome_to_response otherwise never reaches
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
#[serial]
async fn approve_toolset_first_invoke_gate_via_router_returns_grant_active() {
    let h = Harness::new("toolset-router");
    let cookie = h.bootstrap().await;
    let entry = PendingApproval::new_toolset_first_invoke_gate_pending(
        "my-toolset".to_owned(),
        "sign-payment".to_owned(),
        "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
        "XLM".to_owned(),
        0,
        1_000_000,
        uid(),
        DEFAULT_TTL_MS,
    )
    .unwrap();
    let nonce = h.insert(entry);
    let csrf = h.csrf_for(&nonce);

    let req = Request::builder()
        .method("POST")
        .uri(format!("/approval/{nonce}/approve"))
        .header(header::HOST, HOST)
        .header(header::ORIGIN, ORIGIN)
        .header(header::COOKIE, &cookie)
        .header("x-stellar-approval-csrf", csrf)
        .body(Body::empty())
        .unwrap();
    let resp = h.router().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["status"], "grant_active");
}

#[tokio::test]
#[serial]
async fn approve_unknown_nonce_via_router_returns_not_found_status() {
    let h = Harness::new("unknown-router");
    let cookie = h.bootstrap().await;
    let nonce = "AAAAAAAAAAAAAAAAAAAAAA".to_owned();
    let csrf = h.csrf_for(&nonce);

    let req = Request::builder()
        .method("POST")
        .uri(format!("/approval/{nonce}/approve"))
        .header(header::HOST, HOST)
        .header(header::ORIGIN, ORIGIN)
        .header(header::COOKIE, &cookie)
        .header("x-stellar-approval-csrf", csrf)
        .body(Body::empty())
        .unwrap();
    let resp = h.router().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["status"], "not_found");
}

#[tokio::test]
#[serial]
async fn approve_sign_with_passkey_via_router_returns_wrong_kind_status() {
    let h = Harness::new("passkey-router");
    let cookie = h.bootstrap().await;
    let entry = PendingApproval::new_passkey_pending(
        [0x01u8; 32],
        vec![0u8; 32],
        "CAAAA...BBBBB".to_owned(),
        vec![0],
        [0x02u8; 32],
        "localhost".to_owned(),
        uid(),
        DEFAULT_TTL_MS,
    )
    .unwrap();
    let nonce = h.insert(entry);
    let csrf = h.csrf_for(&nonce);

    let req = Request::builder()
        .method("POST")
        .uri(format!("/approval/{nonce}/approve"))
        .header(header::HOST, HOST)
        .header(header::ORIGIN, ORIGIN)
        .header(header::COOKIE, &cookie)
        .header("x-stellar-approval-csrf", csrf)
        .body(Body::empty())
        .unwrap();
    let resp = h.router().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["status"], "wrong_kind");
}

/// A missing/unseeded attestation key surfaces `Outcome::Unavailable`
/// (503 `"unavailable"`), never a panic, distinct from `Outcome::Busy`.
#[tokio::test]
#[serial]
async fn approve_with_unseeded_keyring_returns_unavailable_status() {
    stellar_agent_test_support::keyring_mock::install().unwrap();
    let dir = TempDir::new().unwrap();
    let store_path = dir.path().join("default.toml");
    let audit_path = dir.path().join("audit.log");
    let audit_writer = Arc::new(StdMutex::new(
        AuditWriter::open(audit_path, None).expect("audit writer"),
    ));
    // Deliberately never seed a password for this keyring entry.
    let ctx = DecisionContext::new(
        "ui-router-unseeded".to_owned(),
        store_path.clone(),
        KeyringEntryRef::new("stellar-agent-attestation-ui-router-unseeded", "default"),
        audit_writer,
        Some(dir.path().join("grants.toml")),
    );
    let bootstrap = OpaqueToken::generate();
    let bootstrap_hex = bootstrap.to_hex();
    let state = ServeState {
        auth: Arc::new(StdMutex::new(AuthState::new(bootstrap))),
        ctx: Arc::new(ctx),
    };
    let bound: SocketAddr = BOUND.parse().unwrap();
    let router = build_router(state.clone(), bound);

    let bootstrap_req = Request::builder()
        .uri(format!("/bootstrap/{bootstrap_hex}"))
        .header(header::HOST, HOST)
        .body(Body::empty())
        .unwrap();
    let bootstrap_resp = router.clone().oneshot(bootstrap_req).await.unwrap();
    let cookie = bootstrap_resp
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();

    let entry = PendingApproval::new_payment_pending(
        "b64xdr".to_owned(),
        b"fake-xdr",
        "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
        1_000,
        "XLM".to_owned(),
        None,
        100,
        1,
        uid(),
        DEFAULT_TTL_MS,
    )
    .unwrap();
    let nonce = entry.approval_nonce.clone();
    {
        let mut store = PendingApprovalStore::open(store_path).unwrap();
        store
            .insert(entry, timefmt::now_unix_ms().unwrap())
            .unwrap();
    }
    let csrf = {
        let guard = state.auth.lock().unwrap();
        let session = guard.session.as_ref().unwrap();
        compute_csrf(&session.csrf_key, &nonce)
    };

    let approve_req = Request::builder()
        .method("POST")
        .uri(format!("/approval/{nonce}/approve"))
        .header(header::HOST, HOST)
        .header(header::ORIGIN, ORIGIN)
        .header(header::COOKIE, &cookie)
        .header("x-stellar-approval-csrf", csrf)
        .body(Body::empty())
        .unwrap();
    let approve_resp = router.oneshot(approve_req).await.unwrap();
    assert_eq!(approve_resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let json = body_json(approve_resp).await;
    assert_eq!(json["status"], "unavailable");
    assert_eq!(json["retriable"], false);
}

// ─────────────────────────────────────────────────────────────────────────────
// Poisoned auth mutex: production must recover, never propagate the panic
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
#[serial]
async fn protected_route_survives_poisoned_auth_mutex() {
    let h = Harness::new("poisoned-session");
    let cookie = h.bootstrap().await;

    // Poison the mutex on a background thread, mirroring a prior handler
    // panic while holding the lock.
    let auth = Arc::clone(&h.state.auth);
    let _ = std::thread::spawn(move || {
        let _guard = auth.lock().unwrap();
        panic!("intentional poison for coverage of the recovery path");
    })
    .join();
    assert!(h.state.auth.is_poisoned());

    // `require_session` recovers via `poison.into_inner()`: the session data
    // is still intact, so an authenticated request still succeeds.
    let req = Request::builder()
        .uri("/pending.json")
        .header(header::HOST, HOST)
        .header(header::COOKIE, &cookie)
        .body(Body::empty())
        .unwrap();
    let resp = h.router().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
#[serial]
async fn bootstrap_survives_poisoned_auth_mutex() {
    let h = Harness::new("poisoned-bootstrap");

    let auth = Arc::clone(&h.state.auth);
    let _ = std::thread::spawn(move || {
        let _guard = auth.lock().unwrap();
        panic!("intentional poison for coverage of the recovery path");
    })
    .join();
    assert!(h.state.auth.is_poisoned());

    let req = Request::builder()
        .uri(format!("/bootstrap/{}", h.bootstrap_hex))
        .header(header::HOST, HOST)
        .body(Body::empty())
        .unwrap();
    let resp = h.router().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
}

// ─────────────────────────────────────────────────────────────────────────────
// A genuinely corrupt store file (not lock contention) reports "unavailable"
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
#[serial]
async fn get_endpoints_report_unavailable_on_corrupt_store_file() {
    let h = Harness::new("corrupt-store-get");
    let cookie = h.bootstrap().await;
    std::fs::write(&h.store_path, b"this is not valid toml {{{").unwrap();

    let pending_req = Request::builder()
        .uri("/pending.json")
        .header(header::HOST, HOST)
        .header(header::COOKIE, &cookie)
        .body(Body::empty())
        .unwrap();
    let pending_resp = h.router().oneshot(pending_req).await.unwrap();
    assert_eq!(pending_resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body_json(pending_resp).await["error"], "store_unavailable");

    let detail_req = Request::builder()
        .uri("/approval/AAAAAAAAAAAAAAAAAAAAAA")
        .header(header::HOST, HOST)
        .header(header::COOKIE, &cookie)
        .body(Body::empty())
        .unwrap();
    let detail_resp = h.router().oneshot(detail_req).await.unwrap();
    assert_eq!(detail_resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body_json(detail_resp).await["error"], "store_unavailable");
}
