//! Counter contention through the routes without a listening socket.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test assertions"
)]

use super::*;
use axum::body::{Body, to_bytes};
use axum::http::Request;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
    mpsc,
};
use stellar_agent_core::approval::{
    ApprovalContext, ListenerIdentity, RemoteApprovalAuthority,
    mainnet_fixtures::{
        MainnetConsentFixture, SIGNED_CERT_SPKI_SHA256, SIGNED_ORIGIN, SIGNED_RP_ID,
    },
    operator_credentials::{OperatorApprovalCredentialStore, test_hooks},
};
use stellar_agent_test_support::webauthn::{
    FLAG_UP, FLAG_UV, authenticator_data, fixture_authenticator,
};
use tower::ServiceExt as _;

fn fixture() -> (MainnetConsentFixture, RemoteServeState) {
    let mut fixture = MainnetConsentFixture::with_profile("counter-login", |profile| {
        profile.remote_approval = Some(
            serde_json::from_value(json!({
                "enabled": true, "bind": "127.0.0.1:8443", "rp_id": SIGNED_RP_ID,
            }))
            .unwrap(),
        );
    });
    fixture.sign_signed_origin_policy(&[&fixture_authenticator()], &SIGNED_CERT_SPKI_SHA256);
    let current = fixture.authority().load_current().unwrap();
    let authority = RemoteApprovalAuthority::for_profile(fixture.name()).unwrap();
    let state = RemoteServeState {
        listener_identity: Some(ListenerIdentity::capture(current.policy()).unwrap()),
        selected_nonce: None,
        rp_id: SIGNED_RP_ID.into(),
        expected_origin: SIGNED_ORIGIN.into(),
        operator_credentials: Arc::new(OperatorApprovalCredentialStore::new(
            authority.credentials_path().to_path_buf(),
        )),
        authority: Arc::new(authority),
        chain: stellar_agent_core::profile::caip2::Caip2::Mainnet,
        ctx: Arc::new(crate::RemoteContext {
            context: ApprovalContext::from_profile(fixture.name(), current.profile()),
            store_path: fixture.store_path(),
            mainnet_authority: Some(fixture.authority()),
            decision: None,
        }),
        login_challenges: Arc::new(Mutex::new(
            crate::challenge_store::LoginChallengeStore::new(),
        )),
        action_challenges: Arc::new(Mutex::new(
            crate::challenge_store::ActionChallengeStore::new(),
        )),
        login_rate_limiter: Arc::new(Mutex::new(crate::rate_limit::TokenBucket::default())),
        session: Arc::new(Mutex::new(None)),
        identity: Arc::new(crate::PageIdentity::neutral()),
    };
    (fixture, state)
}

async fn post(state: &RemoteServeState, path: &str, body: Vec<u8>) -> Response {
    signed_router()
        .with_state(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn assertion(state: &RemoteServeState, count: u32) -> Vec<u8> {
    let response = post(state, "/login/challenge", vec![]).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap();
    let client = serde_json::to_vec(
        &json!({"type":"webauthn.get", "challenge":body["challenge"], "origin":SIGNED_ORIGIN}),
    )
    .unwrap();
    let signed = fixture_authenticator().sign_raw(
        authenticator_data(SIGNED_RP_ID, FLAG_UP | FLAG_UV, count),
        client,
    );
    serde_json::to_vec(&json!({"assertion": {
        "id": B64.encode(signed.credential_id), "response": {
            "authenticator_data": B64.encode(signed.authenticator_data),
            "client_data_json": B64.encode(signed.client_data_json),
            "signature": B64.encode(signed.signature_der),
        }
    }}))
    .unwrap()
}

async fn login(state: &RemoteServeState, count: u32) -> Response {
    post(state, "/login/assertion", assertion(state, count).await).await
}

pub(super) fn counter_bytes(state: &RemoteServeState) -> Vec<u8> {
    std::fs::read(state.operator_credentials.path()).unwrap()
}

pub(super) fn assert_counter(state: &RemoteServeState, count: u32) {
    let text = String::from_utf8(counter_bytes(state)).unwrap();
    assert_eq!(text.matches("sign_count = ").count(), 1);
    assert!(text.contains(&format!("sign_count = {count}\n")), "{text}");
}

pub(super) struct Holder {
    release: Option<mpsc::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
    path: std::path::PathBuf,
}

impl Holder {
    pub(super) fn new(state: &RemoteServeState) -> Self {
        let path = state.operator_credentials.path().to_path_buf();
        let lock_path = path.with_extension("toml.lock");
        let (ready, held) = mpsc::sync_channel(0);
        let (release, wait) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(lock_path)
                .unwrap();
            let _lock = stellar_agent_core::file_lock::HeldFileLock::try_lock(file).unwrap();
            ready.send(()).unwrap();
            let _ = wait.recv();
        });
        held.recv().unwrap();
        Self {
            release: Some(release),
            thread: Some(thread),
            path,
        }
    }

    pub(super) fn release(&mut self) {
        if let Some(signal) = self.release.take() {
            signal.send(()).unwrap();
            self.thread.take().unwrap().join().unwrap();
        }
    }
}

impl Drop for Holder {
    fn drop(&mut self) {
        test_hooks::clear(&self.path);
        self.release();
    }
}

#[tokio::test]
#[serial_test::serial]
async fn signed_login_waits_for_held_lock() {
    let (_fixture, state) = fixture();
    assert_eq!(login(&state, 1).await.status(), StatusCode::OK);
    let mut holder = Holder::new(&state);
    let waiting = Arc::new(tokio::sync::Notify::new());
    let notify = waiting.clone();
    let attempts = AtomicUsize::new(0);
    test_hooks::install(state.operator_credentials.path(), move |point| {
        if point == test_hooks::Point::Busy && attempts.fetch_add(1, Ordering::SeqCst) == 5 {
            notify.notify_one();
        }
    });
    let response = login(&state, 7);
    tokio::pin!(response);
    // The current-thread runtime must keep polling while the blocking pool waits.
    let response = tokio::select! {
        response = &mut response => response,
        () = waiting.notified() => {
            holder.release();
            response.await
        }
    };
    assert_eq!(response.status(), StatusCode::OK);
    assert_counter(&state, 7);
}

#[tokio::test]
#[serial_test::serial]
async fn signed_login_lock_timeout_is_busy_and_retryable() {
    let (_fixture, state) = fixture();
    assert_eq!(login(&state, 1).await.status(), StatusCode::OK);
    let before = counter_bytes(&state);
    let session = state
        .session
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .session_id
        .to_hex();
    let mut holder = Holder::new(&state);
    let body = assertion(&state, 7).await;
    let response = post(&state, "/login/assertion", body.clone()).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(!response.headers().contains_key(header::SET_COOKIE));
    let response: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(response, json!({"error":"store_busy", "retriable":true}));
    assert_eq!(counter_bytes(&state), before);
    assert_eq!(
        state
            .session
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .session_id
            .to_hex(),
        session
    );
    holder.release();
    assert_eq!(
        post(&state, "/login/assertion", body).await.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(counter_bytes(&state), before);
    assert_eq!(login(&state, 7).await.status(), StatusCode::OK);
    assert_counter(&state, 7);
}

#[tokio::test]
#[serial_test::serial]
async fn signed_login_counter_task_failure_is_unavailable() {
    let (_fixture, state) = fixture();
    assert_eq!(login(&state, 1).await.status(), StatusCode::OK);
    let before = counter_bytes(&state);
    let session = state
        .session
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .session_id
        .to_hex();
    let mut holder = Holder::new(&state);
    test_hooks::install(state.operator_credentials.path(), |point| {
        if point == test_hooks::Point::Busy {
            panic!("counter task fails while waiting for the lock");
        }
    });
    let response = login(&state, 7).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(!response.headers().contains_key(header::SET_COOKIE));
    let body: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(
        body,
        json!({"error":"store_unavailable", "retriable":false})
    );
    assert_eq!(counter_bytes(&state), before);
    assert_eq!(
        state
            .session
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .session_id
            .to_hex(),
        session
    );
    test_hooks::clear(state.operator_credentials.path());
    holder.release();
    assert_eq!(login(&state, 7).await.status(), StatusCode::OK);
    assert_counter(&state, 7);
}

#[tokio::test]
#[serial_test::serial]
async fn signed_login_lower_and_equal_counters_are_invalid() {
    let (_fixture, state) = fixture();
    assert_eq!(login(&state, 5).await.status(), StatusCode::OK);
    let before = counter_bytes(&state);
    for count in [3, 5] {
        let body = assertion(&state, count).await;
        for _ in 0..2 {
            let response = post(&state, "/login/assertion", body.clone()).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let body: serde_json::Value =
                serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                    .unwrap();
            assert_eq!(body, json!({"error":"webauthn_assertion_invalid"}));
            assert_eq!(counter_bytes(&state), before);
        }
    }
}
