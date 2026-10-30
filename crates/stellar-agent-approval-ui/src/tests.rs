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

const SOURCE_G: &str = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";
const DEST_G: &str = "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL";

// ChangeTrust with transaction source [1; 32] and operation source [2; 32].
const CHANGE_TRUST_ENVELOPE: &str = concat!(
    "AAAAAgAAAAABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQAAAGQAAAAAAAAAAQAAAAAA",
    "AAAAAAAAAQAAAAEAAAAAAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAAAAGAAAAAVVT",
    "REMAAAAABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAR//////////wAAAAAAAAAA",
);

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

use stellar_agent_core::approval::AttestedApprover;
use stellar_agent_core::approval::attestation::{compute_attestation_v4, verify_attestation};
use stellar_agent_core::approval::{
    ApprovalKind, DEFAULT_TTL_MS, PendingApproval, PendingApprovalStore, decode_sha256_hex,
    fixtures, process_uid_for_attestation,
};
use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_core::profile::schema::KeyringEntryRef;
use stellar_agent_core::timefmt;

use crate::auth::{
    AuthState, OpaqueToken, SESSION_ABSOLUTE_TIMEOUT, SESSION_IDLE_TIMEOUT, SessionClock,
    SessionPurpose, compute_csrf,
};
use crate::decision::DecisionContext;
use crate::{PageIdentity, ServeConfig, ServeStartError, ServeState, build_router, start_serve};

const BOUND: &str = "127.0.0.1:8080";
const HOST: &str = "127.0.0.1:8080";
const ORIGIN: &str = "http://127.0.0.1:8080";

pub(crate) struct Harness {
    _dir: TempDir,
    state: ServeState,
    pub(crate) store_path: std::path::PathBuf,
    audit_path: std::path::PathBuf,
    bootstrap_hex: String,
    raw_key: [u8; 32],
    clock: SessionClock,
    proof: StdMutex<Option<String>>,
}

impl Harness {
    pub(crate) fn new(tag: &str) -> Self {
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
            AuditWriter::open(audit_path.clone(), None).expect("audit writer"),
        ));
        let ctx = DecisionContext::new(
            stellar_agent_core::approval::ApprovalContext::from_profile(
                "ui-router-test",
                &stellar_agent_core::profile::schema::Profile::builder_testnet(
                    "svc", "default", "nonce", "default",
                )
                .build(),
            ),
            store_path.clone(),
            KeyringEntryRef::new(svc, "default"),
            stellar_agent_core::profile::owner_key::OwnerKeyContext::for_profile_name("ui-test"),
            audit_writer,
            Some(grant_path),
        );
        let bootstrap = OpaqueToken::generate();
        let bootstrap_hex = bootstrap.to_hex();
        let clock = SessionClock::manual();
        let state = ServeState {
            presence: None,
            auth: Arc::new(StdMutex::new(AuthState::with_clock(
                bootstrap,
                SessionPurpose::Inbox,
                clock.clone(),
            ))),
            ctx: Arc::new(ctx),
            identity: Arc::new(PageIdentity::neutral()),
        };
        Self {
            _dir: dir,
            state,
            store_path,
            audit_path,
            bootstrap_hex,
            raw_key,
            clock,
            proof: StdMutex::new(None),
        }
    }

    pub(crate) fn router(&self) -> Router {
        let bound: SocketAddr = BOUND.parse().unwrap();
        build_router(self.state.clone(), bound)
    }

    pub(crate) fn insert(&self, entry: PendingApproval) -> String {
        let nonce = entry.approval_nonce.clone();
        let mut store = PendingApprovalStore::open(self.store_path.clone()).unwrap();
        store
            .insert(entry, timefmt::now_unix_ms().unwrap())
            .unwrap();
        nonce
    }

    /// Perform the bootstrap exchange and return the session cookie header
    /// value. The session proof the bootstrap page carries is kept for
    /// [`Self::proof`].
    pub(crate) async fn bootstrap(&self) -> String {
        let req = Request::builder()
            .uri(format!("/bootstrap/{}", self.bootstrap_hex))
            .header(header::HOST, HOST)
            .body(Body::empty())
            .unwrap();
        let resp = self.router().oneshot(req).await.unwrap();
        let (cookie, proof) = read_bootstrap_response(resp).await;
        *self.proof.lock().unwrap() = Some(proof);
        cookie
    }

    /// The session proof the last bootstrap exchange delivered.
    pub(crate) fn proof(&self) -> String {
        self.proof
            .lock()
            .unwrap()
            .clone()
            .expect("bootstrap delivered a proof")
    }

    /// The audit log bytes, or `None` while no event was written.
    fn audit_bytes(&self) -> Option<Vec<u8>> {
        std::fs::read(&self.audit_path).ok()
    }

    /// The session CSRF value for `nonce` under the live session key.
    pub(crate) fn csrf_for(&self, nonce: &str) -> String {
        let guard = self.state.auth.lock().unwrap();
        let session = guard.session.as_ref().expect("session established");
        compute_csrf(&session.csrf_key, nonce)
    }
}

/// Reads a successful bootstrap response: `200`, an HTML page, the session
/// cookie, and the proof from the page's data island. Returns the cookie's
/// `name=value` part and the proof.
pub(crate) async fn read_bootstrap_response(resp: axum::response::Response) -> (String, String) {
    assert_eq!(resp.status(), StatusCode::OK, "bootstrap returns its page");
    let set_cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .expect("bootstrap sets a session cookie")
        .to_str()
        .unwrap()
        .to_owned();
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let html = String::from_utf8(bytes.to_vec()).unwrap();
    let island = json_island(&html, "session-bootstrap-data");
    let proof = island["proof"].as_str().unwrap().to_owned();
    assert_eq!(island["next"], "/inbox");
    // Keep only the `name=value` part for the Cookie header.
    let cookie = set_cookie.split(';').next().unwrap().trim().to_owned();
    (cookie, proof)
}

/// Parses the JSON data island with element id `id` out of `html`.
fn json_island(html: &str, id: &str) -> serde_json::Value {
    let open = format!(r#"<script type="application/json" id="{id}">"#);
    let start = html.find(&open).expect("data island present") + open.len();
    let end = start + html[start..].find("</script>").unwrap();
    serde_json::from_str(&html[start..end]).unwrap()
}

fn uid() -> String {
    process_uid_for_attestation().expect("uid on test host")
}

fn payment_entry(ttl_ms: u64) -> PendingApproval {
    fixtures::payment_pending(
        SOURCE_G,
        DEST_G,
        "XLM",
        2_500_000,
        None,
        100,
        1_234_567,
        uid(),
        ttl_ms,
    )
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
    assert!(cookie.starts_with("stellar_agent_approval_session_"));

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
        .header("x-session-proof", h.proof())
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
        .header("x-session-proof", h.proof())
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
    let attested = entry.clone();
    let nonce = h.insert(entry);
    let csrf = h.csrf_for(&nonce);

    let req = Request::builder()
        .method("POST")
        .uri(format!("/approval/{nonce}/approve"))
        .header(header::HOST, HOST)
        .header(header::ORIGIN, ORIGIN)
        .header(header::COOKIE, &cookie)
        .header("x-stellar-approval-csrf", csrf)
        .header("x-session-proof", h.proof())
        .body(Body::empty())
        .unwrap();
    let resp = h.router().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["status"], "attested");
    let blob_b64 = json["attestation"].as_str().unwrap();

    let sha = decode_sha256_hex(&envelope_sha256_hex).unwrap();
    let expected = compute_attestation_v4(
        &h.raw_key,
        &h.state.ctx.context.binding(),
        &nonce,
        &sha,
        &process_uid,
        &attested.attested_lifetime(),
        &AttestedApprover::Local,
    );
    let blob: [u8; 32] = URL_SAFE_NO_PAD
        .decode(blob_b64)
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(blob, expected);
    let store = PendingApprovalStore::open(h.state.ctx.store_path.clone()).unwrap();
    let persisted = store.get(&nonce).unwrap().clone();
    drop(store);
    assert!(persisted.attested_approver == Some(AttestedApprover::Local));
    assert!(verify_attestation(
        &h.raw_key,
        &h.state.ctx.context.binding(),
        &nonce,
        &sha,
        &process_uid,
        &persisted.attestation_scope().unwrap(),
        &blob
    ));
}

#[tokio::test]
#[serial]
async fn serve_trustline_json_returns_attestation() {
    let h = Harness::new("approve-trustline");
    let cookie = h.bootstrap().await;
    let limit = None;
    let entry = PendingApproval::new_trustline_pending(
        CHANGE_TRUST_ENVELOPE.to_owned(),
        CHANGE_TRUST_ENVELOPE.as_bytes(),
        "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
        "USDC".to_owned(),
        "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5".to_owned(),
        limit,
        100,
        42,
        process_uid_for_attestation().unwrap(),
        DEFAULT_TTL_MS,
    )
    .unwrap();
    let process_uid = entry.process_uid.clone();
    let envelope_sha256_hex = match &entry.kind {
        ApprovalKind::TrustlineSimulated {
            envelope_sha256_hex,
            ..
        } => envelope_sha256_hex.clone(),
        _ => unreachable!(),
    };
    let attested = entry.clone();
    let nonce = h.insert(entry);
    let csrf = h.csrf_for(&nonce);

    let req = Request::builder()
        .method("POST")
        .uri(format!("/approval/{nonce}/approve"))
        .header(header::HOST, HOST)
        .header(header::ORIGIN, ORIGIN)
        .header(header::COOKIE, &cookie)
        .header("x-stellar-approval-csrf", csrf)
        .header("x-session-proof", h.proof())
        .body(Body::empty())
        .unwrap();
    let resp = h.router().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["status"], "attested");
    let blob_b64 = json["attestation"].as_str().unwrap();

    let sha = decode_sha256_hex(&envelope_sha256_hex).unwrap();
    let expected = compute_attestation_v4(
        &h.raw_key,
        &h.state.ctx.context.binding(),
        &nonce,
        &sha,
        &process_uid,
        &attested.attested_lifetime(),
        &AttestedApprover::Local,
    );
    let blob: [u8; 32] = URL_SAFE_NO_PAD
        .decode(blob_b64)
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(blob, expected);
    let store = PendingApprovalStore::open(h.state.ctx.store_path.clone()).unwrap();
    let persisted = store.get(&nonce).unwrap().clone();
    drop(store);
    assert!(persisted.attested_approver == Some(AttestedApprover::Local));
    assert!(verify_attestation(
        &h.raw_key,
        &h.state.ctx.context.binding(),
        &nonce,
        &sha,
        &process_uid,
        &persisted.attestation_scope().unwrap(),
        &blob
    ));
    let req = Request::builder()
        .uri("/pending.json")
        .header(header::HOST, HOST)
        .header(header::COOKIE, &cookie)
        .body(Body::empty())
        .unwrap();
    let resp = h.router().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let snapshot = body_json(resp).await;
    assert_eq!(snapshot["pending"][0]["summary"]["kind"], "trustline");
    assert_eq!(snapshot["pending"][0]["attested"], true);
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
        .header("x-session-proof", h.proof())
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
            .header("x-session-proof", h.proof())
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
        .header("x-session-proof", h.proof())
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
    let entry = fixtures::payment_pending(
        SOURCE_G,
        DEST_G,
        "XLM",
        2_500_000,
        None,
        100,
        1_234_567,
        "99999999".to_owned(),
        DEFAULT_TTL_MS,
    );
    let nonce = h.insert(entry);
    let csrf = h.csrf_for(&nonce);

    let req = Request::builder()
        .method("POST")
        .uri(format!("/approval/{nonce}/approve"))
        .header(header::HOST, HOST)
        .header(header::ORIGIN, ORIGIN)
        .header(header::COOKIE, &cookie)
        .header("x-stellar-approval-csrf", csrf)
        .header("x-session-proof", h.proof())
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
    let entry = fixtures::payment_pending(
        SOURCE_G,
        DEST_G,
        "XLM",
        2_500_000,
        None,
        100,
        1_234_567,
        "99999999".to_owned(),
        DEFAULT_TTL_MS,
    );
    let nonce = h.insert(entry);
    let csrf = h.csrf_for(&nonce);

    let req = Request::builder()
        .method("POST")
        .uri(format!("/approval/{nonce}/reject"))
        .header(header::HOST, HOST)
        .header(header::ORIGIN, ORIGIN)
        .header(header::COOKIE, &cookie)
        .header("x-stellar-approval-csrf", csrf)
        .header("x-session-proof", h.proof())
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
        .header("x-session-proof", h.proof())
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
        stellar_agent_core::approval::ApprovalContext::from_profile(
            "ui-bind-test",
            &stellar_agent_core::profile::schema::Profile::builder_testnet(
                "svc", "default", "nonce", "default",
            )
            .build(),
        ),
        store_path,
        KeyringEntryRef::new("stellar-agent-attestation-ui-bind", "default"),
        stellar_agent_core::profile::owner_key::OwnerKeyContext::for_profile_name("ui-test"),
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
        response_text.starts_with("HTTP/1.1 200"),
        "bootstrap exchange over a real socket must return its page: {response_text}"
    );
    let lower = response_text.to_ascii_lowercase();
    assert!(
        lower.contains("set-cookie: stellar_agent_approval_session_")
            && lower.contains("max-age=28800"),
        "bootstrap exchange must set the bounded session cookie: {response_text}"
    );
    assert!(
        response_text.contains(r#"id="session-bootstrap-data""#),
        "bootstrap exchange must deliver the session proof page: {response_text}"
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

/// Both inbox sinks, the `/inbox` data island and the `/pending.json`
/// poll, carry a memo's U+202E only as the visible escape.
#[tokio::test]
#[serial]
async fn inbox_sinks_carry_a_bidi_memo_escaped() {
    let h = Harness::new("inbox-bidi");
    let cookie = h.bootstrap().await;
    // The envelope carries the memo; the stored summary memo, which no
    // surface displays, is absent.
    let envelope = fixtures::payment_envelope(
        SOURCE_G,
        DEST_G,
        "XLM",
        2_500_000,
        Some("memo\u{202e}"),
        100,
        1_234_567,
    );
    h.insert(
        PendingApproval::new_payment_pending(
            envelope.clone(),
            envelope.as_bytes(),
            DEST_G.to_owned(),
            2_500_000,
            "XLM".to_owned(),
            None,
            100,
            1_234_567,
            uid(),
            DEFAULT_TTL_MS,
        )
        .unwrap(),
    );

    let get = |uri: &'static str| {
        Request::builder()
            .uri(uri)
            .header(header::HOST, HOST)
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .unwrap()
    };
    let resp = h.router().oneshot(get("/inbox")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 256 * 1024).await.unwrap();
    let html = std::str::from_utf8(&bytes).unwrap();
    assert!(html.contains(r#""value":"memo\\u{202e}""#), "{html}");
    assert!(!html.contains('\u{202e}'), "{html}");

    let resp = h.router().oneshot(get("/pending.json")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let body = std::str::from_utf8(&bytes).unwrap();
    assert!(!body.contains('\u{202e}'), "{body}");
    let json: serde_json::Value = serde_json::from_str(body).unwrap();
    assert_eq!(
        json["pending"][0]["summary"]["memo"]["value"],
        r"memo\u{202e}"
    );
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
    let cookie = h.bootstrap().await;
    let (name, _) = cookie.split_once('=').unwrap();
    let req = Request::builder()
        .uri("/pending.json")
        .header(header::HOST, HOST)
        .header(header::COOKIE, format!("{name}={}", "0".repeat(64)))
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
        .header("x-session-proof", h.proof())
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
        .header("x-session-proof", h.proof())
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
        .header("x-session-proof", h.proof())
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
        .header("x-session-proof", h.proof())
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
        stellar_agent_core::approval::ApprovalContext::from_profile(
            "ui-router-unseeded",
            &stellar_agent_core::profile::schema::Profile::builder_testnet(
                "svc", "default", "nonce", "default",
            )
            .build(),
        ),
        store_path.clone(),
        KeyringEntryRef::new("stellar-agent-attestation-ui-router-unseeded", "default"),
        stellar_agent_core::profile::owner_key::OwnerKeyContext::for_profile_name("ui-test"),
        audit_writer,
        Some(dir.path().join("grants.toml")),
    );
    let bootstrap = OpaqueToken::generate();
    let bootstrap_hex = bootstrap.to_hex();
    let state = ServeState {
        presence: None,
        auth: Arc::new(StdMutex::new(AuthState::new(
            bootstrap,
            SessionPurpose::Inbox,
        ))),
        ctx: Arc::new(ctx),
        identity: Arc::new(PageIdentity::neutral()),
    };
    let bound: SocketAddr = BOUND.parse().unwrap();
    let router = build_router(state.clone(), bound);

    let bootstrap_req = Request::builder()
        .uri(format!("/bootstrap/{bootstrap_hex}"))
        .header(header::HOST, HOST)
        .body(Body::empty())
        .unwrap();
    let bootstrap_resp = router.clone().oneshot(bootstrap_req).await.unwrap();
    let (cookie, proof) = read_bootstrap_response(bootstrap_resp).await;

    let entry = fixtures::payment_pending(
        SOURCE_G,
        DEST_G,
        "XLM",
        1_000,
        None,
        100,
        1,
        uid(),
        DEFAULT_TTL_MS,
    );
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
        .header("x-session-proof", &proof)
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
    let (cookie, _proof) = read_bootstrap_response(resp).await;
    assert!(cookie.starts_with("stellar_agent_approval_session_"));
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

#[tokio::test]
#[serial]
async fn authenticated_detail_renders_selected_context_and_envelope_source() {
    let mut h = Harness::new("context-source");
    let context = &mut Arc::get_mut(&mut h.state.ctx).unwrap().context;
    context.profile_name = "treasury-route".to_owned();
    context.chain_id = "stellar:mainnet".to_owned();
    context.endpoint_host = "https://route-rpc.example".to_owned();
    context.signer_account = Some("GENROLLED".to_owned());
    // A payment whose operation source ([2; 32]) overrides its transaction
    // source ([1; 32]).
    let envelope = "AAAAAgAAAAABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQAAAGQAAAAAAAAAAQAAAAAAAAAAAAAAAQAAAAEAAAAAAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAAAABAAAAAAMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAAAAAAAAAAAAD0JAAAAAAAAAAAA=";
    let entry = PendingApproval::new_payment_pending(
        envelope.to_owned(),
        envelope.as_bytes(),
        DEST_G.to_owned(),
        1_000_000,
        "XLM".to_owned(),
        None,
        100,
        1,
        uid(),
        DEFAULT_TTL_MS,
    )
    .unwrap();
    let nonce = h.insert(entry);
    let cookie = h.bootstrap().await;
    let response = h
        .router()
        .oneshot(
            Request::builder()
                .uri(format!("/approval/{nonce}"))
                .header(header::HOST, HOST)
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), 256 * 1024).await.unwrap();
    let html = std::str::from_utf8(&bytes).unwrap();
    for value in [
        "treasury-route",
        "stellar:mainnet",
        "https://route-rpc.example",
        "GENROLLED",
        "GABAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEJXA",
    ] {
        assert!(html.contains(value), "missing {value}: {html}");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Session proof, lifetime and cookie shape
// ─────────────────────────────────────────────────────────────────────────────

/// A `POST` to `path` carrying the given cookie, CSRF value and proof headers.
fn mutation(path: &str, cookie: &str, csrf: Option<&str>, proof: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::HOST, HOST)
        .header(header::ORIGIN, ORIGIN)
        .header(header::COOKIE, cookie);
    if let Some(csrf) = csrf {
        builder = builder.header("x-stellar-approval-csrf", csrf);
    }
    if let Some(proof) = proof {
        builder = builder.header("x-session-proof", proof);
    }
    builder.body(Body::empty()).unwrap()
}

/// A cookie-only `GET` of `path`.
fn cookie_get(path: &str, cookie: &str) -> Request<Body> {
    Request::builder()
        .uri(path)
        .header(header::HOST, HOST)
        .header(header::COOKIE, cookie)
        .body(Body::empty())
        .unwrap()
}

async fn body_text(resp: axum::response::Response) -> String {
    let bytes = to_bytes(resp.into_body(), 256 * 1024).await.unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

/// The session cookie and a valid CSRF value do not authorize approve or
/// reject without the session proof: a missing, malformed, or wrong proof is
/// refused with `session_proof_invalid`, and neither the store nor the audit
/// log changes.
#[tokio::test]
#[serial]
async fn cookie_and_csrf_without_proof_cannot_mutate() {
    let h = Harness::new("proof-required");
    let cookie = h.bootstrap().await;
    let nonce = h.insert(payment_entry(DEFAULT_TTL_MS));
    let csrf = h.csrf_for(&nonce);
    let store_before = std::fs::read(&h.store_path).unwrap();
    let audit_before = h.audit_bytes();
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

    for action in ["approve", "reject"] {
        for proof in [
            None,
            Some("not-a-proof"),
            Some(wrong.as_str()),
            Some(session_id.as_str()),
        ] {
            let resp = h
                .router()
                .oneshot(mutation(
                    &format!("/approval/{nonce}/{action}"),
                    &cookie,
                    Some(&csrf),
                    proof,
                ))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{action} {proof:?}");
            assert_eq!(
                body_json(resp).await,
                serde_json::json!({"error": "session_proof_invalid"}),
                "{action} {proof:?}"
            );
        }
    }

    assert_eq!(std::fs::read(&h.store_path).unwrap(), store_before);
    assert_eq!(h.audit_bytes(), audit_before);
    {
        let store = PendingApprovalStore::open(h.store_path.clone()).unwrap();
        let entry = store.get(&nonce).expect("entry still present");
        assert!(matches!(entry.kind, ApprovalKind::PaymentSimulated { .. }));
        assert!(entry.attestation_blob_b64.is_none());
    }

    // The same request with the proof is the operator's and goes through.
    let resp = h
        .router()
        .oneshot(mutation(
            &format!("/approval/{nonce}/approve"),
            &cookie,
            Some(&csrf),
            Some(&h.proof()),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["status"], "attested");
}

/// The proof leaves the server once, in the successful bootstrap response.
/// No cookie-authorized page, script, JSON body, or header carries it, and a
/// repeated bootstrap cannot mint or recover it.
#[tokio::test]
#[serial]
async fn bootstrap_proof_is_one_shot_and_not_recoverable() {
    let h = Harness::new("proof-one-shot");
    let nonce = h.insert(payment_entry(DEFAULT_TTL_MS));
    let cookie = h.bootstrap().await;
    let proof = h.proof();
    assert_eq!(proof.len(), 64);

    let paths = [
        "/inbox".to_owned(),
        "/inbox?include_expired=1".to_owned(),
        "/pending.json".to_owned(),
        format!("/approval/{nonce}"),
        "/approval/AAAAAAAAAAAAAAAAAAAAAA".to_owned(),
        "/static/app.js".to_owned(),
        "/static/app-shared.js".to_owned(),
        "/static/session-bootstrap.js".to_owned(),
    ];
    for path in &paths {
        let resp = h.router().oneshot(cookie_get(path, &cookie)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "{path}");
        for value in resp.headers().values() {
            assert!(
                !value.to_str().unwrap_or_default().contains(&proof),
                "{path} header"
            );
        }
        assert!(!body_text(resp).await.contains(&proof), "{path} body");
    }

    let resp = h
        .router()
        .oneshot(cookie_get(
            &format!("/bootstrap/{}", h.bootstrap_hex),
            &cookie,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert!(resp.headers().get(header::SET_COOKIE).is_none());
    assert!(!body_text(resp).await.contains(&proof));

    // The decision responses do not echo it either.
    let resp = h
        .router()
        .oneshot(mutation(
            &format!("/approval/{nonce}/reject"),
            &cookie,
            Some(&h.csrf_for(&nonce)),
            Some(&proof),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(!body_text(resp).await.contains(&proof));
}

/// The session cookie is bounded and per listener: `Max-Age` of the absolute
/// limit, `HttpOnly`, `SameSite=Strict`, `Path=/`, and a name no other
/// listener shares.
#[tokio::test]
#[serial]
async fn bootstrap_sets_max_age_and_distinct_cookie_names() {
    let a = Harness::new("cookie-a");
    let b = Harness::new("cookie-b");
    let mut names = Vec::new();
    for h in [&a, &b] {
        let req = Request::builder()
            .uri(format!("/bootstrap/{}", h.bootstrap_hex))
            .header(header::HOST, HOST)
            .body(Body::empty())
            .unwrap();
        let resp = h.router().oneshot(req).await.unwrap();
        let set_cookie = resp
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let attributes: Vec<&str> = set_cookie.split(';').map(str::trim).collect();
        assert!(attributes.contains(&"HttpOnly"), "{set_cookie}");
        assert!(attributes.contains(&"SameSite=Strict"), "{set_cookie}");
        assert!(attributes.contains(&"Path=/"), "{set_cookie}");
        assert!(
            attributes
                .contains(&format!("Max-Age={}", SESSION_ABSOLUTE_TIMEOUT.as_secs()).as_str()),
            "{set_cookie}"
        );
        assert_eq!(SESSION_ABSOLUTE_TIMEOUT.as_secs(), 28_800);
        let name = attributes[0].split_once('=').unwrap().0.to_owned();
        assert!(
            name.starts_with("stellar_agent_approval_session_"),
            "{name}"
        );
        assert!(
            name.len() > "stellar_agent_approval_session_".len(),
            "{name}"
        );
        names.push(name);
    }
    assert_ne!(
        names[0], names[1],
        "two listeners must not share a cookie name"
    );

    // The cookie of one listener does not open the other.
    let cookie_a = format!("{}={}", names[0], "0".repeat(64));
    let resp = b
        .router()
        .oneshot(cookie_get("/pending.json", &cookie_a))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// The router holds a session one tick before the idle limit and refuses it
/// exactly at the limit, on every route, for good.
#[tokio::test]
#[serial]
async fn idle_expiry_boundary() {
    let h = Harness::new("idle-boundary");
    let nonce = h.insert(payment_entry(DEFAULT_TTL_MS));
    let cookie = h.bootstrap().await;
    let csrf = h.csrf_for(&nonce);
    let tick = std::time::Duration::from_secs(1);

    h.clock.advance(SESSION_IDLE_TIMEOUT - tick);
    let resp = h
        .router()
        .oneshot(cookie_get("/pending.json", &cookie))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    h.clock.advance(tick);
    let resp = h
        .router()
        .oneshot(cookie_get("/pending.json", &cookie))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let resp = h
        .router()
        .oneshot(mutation(
            &format!("/approval/{nonce}/approve"),
            &cookie,
            Some(&csrf),
            Some(&h.proof()),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert!(h.state.auth.lock().unwrap().session.is_none());
    let store = PendingApprovalStore::open(h.store_path.clone()).unwrap();
    assert!(store.get(&nonce).unwrap().attestation_blob_b64.is_none());
}

/// Background polls, cookie-only page loads, and refused mutations never
/// record activity: the session still expires at the idle limit counted from
/// the bootstrap exchange.
#[tokio::test]
#[serial]
async fn polling_and_cookie_only_requests_do_not_extend_idle() {
    let h = Harness::new("idle-polling");
    let nonce = h.insert(payment_entry(DEFAULT_TTL_MS));
    let cookie = h.bootstrap().await;
    let csrf = h.csrf_for(&nonce);
    let activity_csrf = h.csrf_for(crate::routes::SESSION_ACTIVITY_NONCE);
    let poll = std::time::Duration::from_secs(2);

    let mut elapsed = std::time::Duration::ZERO;
    while elapsed + poll < SESSION_IDLE_TIMEOUT {
        h.clock.advance(poll);
        elapsed += poll;
        let resp = h
            .router()
            .oneshot(cookie_get("/pending.json", &cookie))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "poll at {elapsed:?}");
    }
    for path in ["/inbox".to_owned(), format!("/approval/{nonce}")] {
        let resp = h
            .router()
            .oneshot(cookie_get(&path, &cookie))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "{path}");
    }
    let refused = [
        mutation(
            &format!("/approval/{nonce}/approve"),
            &cookie,
            Some(&csrf),
            None,
        ),
        mutation("/session/activity", &cookie, Some(&activity_csrf), None),
        mutation("/session/activity", &cookie, None, Some(&h.proof())),
        mutation("/session/activity", &cookie, Some(&csrf), Some(&h.proof())),
    ];
    for req in refused {
        let resp = h.router().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    h.clock.advance(SESSION_IDLE_TIMEOUT - elapsed);
    let resp = h
        .router()
        .oneshot(cookie_get("/pending.json", &cookie))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// `POST /session/activity` with the proof and its CSRF value answers `204`
/// and moves the idle deadline; so does an authorized decision.
#[tokio::test]
#[serial]
async fn activity_and_decisions_extend_idle() {
    let h = Harness::new("idle-activity");
    let first = h.insert(payment_entry(DEFAULT_TTL_MS));
    let cookie = h.bootstrap().await;
    let activity_csrf = h.csrf_for(crate::routes::SESSION_ACTIVITY_NONCE);
    let tick = std::time::Duration::from_secs(1);

    h.clock.advance(SESSION_IDLE_TIMEOUT - tick);
    let resp = h
        .router()
        .oneshot(mutation(
            "/session/activity",
            &cookie,
            Some(&activity_csrf),
            Some(&h.proof()),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(body_text(resp).await.is_empty());

    h.clock.advance(SESSION_IDLE_TIMEOUT - tick);
    let resp = h
        .router()
        .oneshot(mutation(
            &format!("/approval/{first}/reject"),
            &cookie,
            Some(&h.csrf_for(&first)),
            Some(&h.proof()),
        ))
        .await
        .unwrap();
    assert_eq!(body_json(resp).await["status"], "rejected");

    h.clock.advance(SESSION_IDLE_TIMEOUT - tick);
    let resp = h
        .router()
        .oneshot(cookie_get("/pending.json", &cookie))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    h.clock.advance(tick);
    let resp = h
        .router()
        .oneshot(cookie_get("/pending.json", &cookie))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// Activity every ten minutes keeps the session only until the absolute
/// limit: one tick before it the session holds, at it the session is gone.
#[tokio::test]
#[serial]
async fn absolute_expiry_boundary() {
    let h = Harness::new("absolute-boundary");
    let cookie = h.bootstrap().await;
    let activity_csrf = h.csrf_for(crate::routes::SESSION_ACTIVITY_NONCE);
    let step = std::time::Duration::from_secs(10 * 60);
    let tick = std::time::Duration::from_secs(1);
    let activity = |h: &Harness| {
        mutation(
            "/session/activity",
            &cookie,
            Some(&activity_csrf),
            Some(&h.proof()),
        )
    };

    let mut elapsed = std::time::Duration::ZERO;
    while elapsed + step < SESSION_ABSOLUTE_TIMEOUT {
        h.clock.advance(step);
        elapsed += step;
        let resp = h.router().oneshot(activity(&h)).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NO_CONTENT,
            "activity at {elapsed:?}"
        );
    }
    h.clock.advance(SESSION_ABSOLUTE_TIMEOUT - elapsed - tick);
    let resp = h.router().oneshot(activity(&h)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    h.clock.advance(tick);
    let resp = h.router().oneshot(activity(&h)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let resp = h
        .router()
        .oneshot(cookie_get("/pending.json", &cookie))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// The bootstrap page's script is reachable before any session exists and
/// serves the fixed bytes.
#[tokio::test]
#[serial]
async fn session_bootstrap_js_is_served_without_a_session() {
    let h = Harness::new("bootstrap-js");
    let req = Request::builder()
        .uri("/static/session-bootstrap.js")
        .header(header::HOST, HOST)
        .body(Body::empty())
        .unwrap();
    let resp = h.router().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/javascript; charset=utf-8"
    );
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    assert_eq!(bytes.as_ref(), crate::web::SESSION_BOOTSTRAP_JS);
}

/// The bootstrap page keeps the listener's CSP and cache posture.
#[tokio::test]
#[serial]
async fn bootstrap_page_keeps_the_security_headers() {
    let h = Harness::new("bootstrap-headers");
    let req = Request::builder()
        .uri(format!("/bootstrap/{}", h.bootstrap_hex))
        .header(header::HOST, HOST)
        .body(Body::empty())
        .unwrap();
    let resp = h.router().oneshot(req).await.unwrap();
    let headers = resp.headers();
    let csp = headers
        .get(header::CONTENT_SECURITY_POLICY)
        .unwrap()
        .to_str()
        .unwrap();
    let script_src: Vec<&str> = csp
        .split(';')
        .map(str::trim)
        .filter(|directive| directive.starts_with("script-src"))
        .collect();
    assert_eq!(script_src, ["script-src 'self'"], "{csp}");
    assert_eq!(headers.get(header::CACHE_CONTROL).unwrap(), "no-store");
    assert_eq!(headers.get(header::REFERRER_POLICY).unwrap(), "no-referrer");
}

/// Each request span records the matched route template: neither the
/// bootstrap token, nor an approval nonce, nor the session proof an
/// authorized mutation carries reaches the trace, and a request that matches
/// no route records the fixed label.
#[tokio::test(flavor = "current_thread")]
#[serial]
async fn bootstrap_trace_redacts_token() {
    let h = Harness::new("bootstrap-trace");
    let nonce = h.insert(payment_entry(DEFAULT_TTL_MS));
    let capture = crate::trace_capture::SpanCapture::install();

    let cookie = h.bootstrap().await;
    let proof = h.proof();
    let replay = Request::builder()
        .uri(format!("/bootstrap/{}", h.bootstrap_hex))
        .header(header::HOST, HOST)
        .body(Body::empty())
        .unwrap();
    let resp = h.router().oneshot(replay).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let resp = h
        .router()
        .oneshot(cookie_get("/pending.json", &cookie))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = h
        .router()
        .oneshot(cookie_get(&format!("/approval/{nonce}"), &cookie))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = h
        .router()
        .oneshot(cookie_get(&format!("/unknown/{nonce}"), &cookie))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let resp = h
        .router()
        .oneshot(mutation(
            "/session/activity",
            &cookie,
            Some(&h.csrf_for(crate::routes::SESSION_ACTIVITY_NONCE)),
            Some(&proof),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    assert_eq!(
        capture.span_paths("approval_inbox_request"),
        [
            "/bootstrap/{token}",
            "/bootstrap/{token}",
            "/pending.json",
            "/approval/{nonce}",
            stellar_agent_loopback_http::request_trace::UNMATCHED_ROUTE_LABEL,
            "/session/activity",
        ],
        "{:?}",
        capture.lines()
    );
    for line in capture.lines() {
        assert!(!line.contains(&h.bootstrap_hex), "token in trace: {line}");
        assert!(!line.contains(&nonce), "nonce in trace: {line}");
        assert!(!line.contains(&proof), "proof in trace: {line}");
    }
}
