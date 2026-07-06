//! Interactive WebAuthn operator-enrollment server (loopback, one-shot).
//!
//! `approve operator enroll --interactive` starts this server instead of
//! reading `--credential-id` / `--public-key` / `--rp-id` / `--label`
//! arguments: the operator's authenticator creates the credential in place,
//! and the credential (id, SEC1 public key, best-effort seeded sign count)
//! is persisted server-side into the same
//! [`stellar_agent_core::approval::operator_credentials::OperatorApprovalCredentialStore`]
//! the argument-based mode writes to — never passing through the shell.
//!
//! # rp-id binding is why this server exists
//!
//! WebAuthn binds a credential to its `rp.id` at creation, and a loopback
//! HTTP origin can only claim `"localhost"` as an effective domain (WebAuthn
//! Level 2 §5.1.3). This server therefore always registers against
//! `rp_id: "localhost"` — correct for the SSH-tunnel / loopback approval
//! surfaces, and USELESS for a domain-configured remote listener (which
//! needs the argument-mode import path from its own `/enroll` page instead;
//! see `stellar-agent-approval-remote`'s crate docs).
//!
//! # Enrollment never authorizes anything
//!
//! Enrolling here only writes to the credential store. The profile's
//! `[remote_approval] allowed_credentials` list is the sole, separate,
//! operator-controlled authorization step — this server's success page and
//! the CLI summary both restate that reminder; the ceremony never touches
//! the profile allowlist.
//!
//! # Single-use, single-server-run
//!
//! The server is started fresh for exactly one enrollment ceremony and shut
//! down by the caller once it completes (or the caller's timeout elapses). A
//! 32-byte bootstrap token is minted at start and never embedded in a served
//! page; the operator's browser exchanges it once, at `GET /bootstrap/<hex>`,
//! for an `HttpOnly; SameSite=Strict` session cookie. Every other route
//! requires that cookie — absent, malformed, or mismatched collapses to a
//! bare `404` — so a local process that never opened the bootstrap URL itself
//! cannot scrape a token from a served page and race the operator to
//! `POST /enroll/credential`. `POST /enroll/credential` fires a single-use
//! completion signal (see [`OperatorEnrollHandle::await_completion`]) the
//! first time it persists a credential; see `routes::enroll_credential_post`
//! for how the single-use latch is enforced atomically against concurrent
//! requests.
//!
//! # Defence stack
//!
//! Shares the `stellar-agent-loopback-http` middleware stack with
//! [`crate::start_serve`] and `stellar-agent-webauthn-bridge`: Host-header
//! allowlist, hardened security headers + CSP, Origin-header allowlist on
//! state-changing methods, and a 16 KiB body cap (defence-in-depth alongside
//! axum's own `DefaultBodyLimit`). In front of that stack sits the bootstrap
//! → session-cookie exchange described above, mirroring
//! [`crate::start_serve`]'s auth boundary.
//!
//! # Server-side attestation verification is intentionally omitted
//!
//! See `routes` module docs for the full rationale: enrollment authorizes
//! nothing, so verifying the attestation statement would add a CBOR/COSE
//! parser and a trust-anchor set in exchange for a guarantee this surface
//! has no use for.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use axum::{Router, extract::DefaultBodyLimit};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tower_http::{limit::RequestBodyLimitLayer, trace::TraceLayer};

use stellar_agent_core::approval::operator_credentials::OperatorApprovalCredentialStore;

use crate::auth::{AuthState, OpaqueToken};
use crate::{HostHeaderAllowlistLayer, OriginHeaderAllowlistLayer, SecurityHeadersLayer};

mod error;
mod routes;
mod templates;
mod web;

#[cfg(test)]
mod router_tests;

pub use error::{OperatorEnrollAwaitError, OperatorEnrollShutdownError, OperatorEnrollStartError};

/// Maximum request body size accepted by this server, in bytes (16 KiB) —
/// the same cap the approval-inbox server and the WebAuthn bridge apply.
/// Applied at both `tower_http::limit::RequestBodyLimitLayer` and
/// `axum::extract::DefaultBodyLimit`.
const BODY_LIMIT_BYTES: usize = 16 * 1024;

/// Shutdown deadline for [`OperatorEnrollHandle::shutdown`].
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(5);

/// Shared axum state for the operator-enrollment handlers.
struct OperatorEnrollState {
    /// Wallet profile name, shown on the page for operator orientation only.
    profile: String,
    /// Bootstrap-token / session-cookie auth state. See the module docs'
    /// "Single-use, single-server-run" section for the exchange this guards.
    auth: StdMutex<AuthState>,
    /// The credential store this ceremony persists into.
    store: OperatorApprovalCredentialStore,
    /// Optional label to pre-populate the `/enroll` page's label input with
    /// (from `--label` in interactive mode). `None` leaves the field empty
    /// for the operator to fill in.
    label_prefill: Option<String>,
    /// Single-use completion latch: `Some` until the first successful
    /// enrollment consumes it. Guarded by a `std::sync::Mutex` so the
    /// check-then-persist-then-consume sequence in
    /// `routes::enroll_credential_post` is atomic with respect to
    /// concurrent POSTs — the guard is held only across synchronous work,
    /// never across an `.await` point.
    completion: StdMutex<Option<oneshot::Sender<()>>>,
}

// ─────────────────────────────────────────────────────────────────────────────
// OperatorEnrollHandle
// ─────────────────────────────────────────────────────────────────────────────

/// Handle to a running interactive operator-enrollment server.
///
/// # Drop behaviour
///
/// Dropping the handle without calling [`OperatorEnrollHandle::shutdown`]
/// leaves the server task running. Always call `shutdown` before process
/// exit.
pub struct OperatorEnrollHandle {
    local_addr: SocketAddr,
    bootstrap_token_hex: String,
    /// `Some` until [`Self::await_completion`] is called once; `take`n so a
    /// second call has a clear, typed error rather than reusing an already
    /// resolved future.
    completion_rx: Option<oneshot::Receiver<()>>,
    shutdown_tx: oneshot::Sender<()>,
    join_handle: JoinHandle<()>,
}

impl std::fmt::Debug for OperatorEnrollHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OperatorEnrollHandle")
            .field("local_addr", &self.local_addr)
            .finish_non_exhaustive()
    }
}

impl OperatorEnrollHandle {
    /// The actual bound socket address (the OS-assigned port when `0` was
    /// requested).
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// The one-time bootstrap token, hex-encoded, for assembling the
    /// `http://localhost:<port>/bootstrap/<token>` URL.
    #[must_use]
    pub fn bootstrap_token_hex(&self) -> &str {
        &self.bootstrap_token_hex
    }

    /// The full bootstrap URL the operator opens to establish a session and
    /// reach the `/enroll` page.
    ///
    /// # rp-id binding
    ///
    /// Always uses `localhost:<port>` — NEVER `local_addr`'s bind IP — so the
    /// browser's origin (`http://localhost:<port>`) matches this server's
    /// hard-coded `rp_id: "localhost"` per WebAuthn Level 2 §5.1.2.
    /// `local_addr.ip()` is `127.0.0.1` in the common case, but
    /// `http://127.0.0.1:<port>` and `http://localhost:<port>` are DIFFERENT
    /// origins to the browser even though both resolve to the loopback
    /// interface; opening the bind-IP form here would make the browser's
    /// origin mismatch the credential's `rp.id`, and WebAuthn would refuse the
    /// ceremony with a `SecurityError`. Mirrors the same localhost-not-bind-IP
    /// rewrite `stellar_agent_smart_account::managers::credentials` applies
    /// for the passkey-signing bridge's registration and approval URLs.
    #[must_use]
    pub fn enroll_url(&self) -> String {
        format!(
            "http://localhost:{}/bootstrap/{}",
            self.local_addr.port(),
            self.bootstrap_token_hex
        )
    }

    /// Await the single completion signal, or time out.
    ///
    /// # Errors
    ///
    /// - [`OperatorEnrollAwaitError::AlreadyAwaited`] — this handle's
    ///   completion signal was already awaited (it can only be awaited
    ///   once).
    /// - [`OperatorEnrollAwaitError::Timeout`] — no enrollment completed
    ///   within `timeout`.
    /// - [`OperatorEnrollAwaitError::SenderDropped`] — the server task
    ///   exited without ever completing an enrollment.
    pub async fn await_completion(
        &mut self,
        timeout: Duration,
    ) -> Result<(), OperatorEnrollAwaitError> {
        let Some(rx) = self.completion_rx.take() else {
            return Err(OperatorEnrollAwaitError::AlreadyAwaited);
        };
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_recv_error)) => Err(OperatorEnrollAwaitError::SenderDropped),
            Err(_elapsed) => Err(OperatorEnrollAwaitError::Timeout),
        }
    }

    /// Trigger graceful shutdown and wait for the server task to stop.
    ///
    /// # Errors
    ///
    /// - [`OperatorEnrollShutdownError::Timeout`] — the server task did not
    ///   stop within 5 seconds.
    /// - [`OperatorEnrollShutdownError::JoinFailed`] — the server task
    ///   panicked.
    pub async fn shutdown(self) -> Result<(), OperatorEnrollShutdownError> {
        let _ = self.shutdown_tx.send(());
        match tokio::time::timeout(SHUTDOWN_DEADLINE, self.join_handle).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(join_err)) => Err(OperatorEnrollShutdownError::JoinFailed {
                detail: join_err.to_string(),
            }),
            Err(_elapsed) => Err(OperatorEnrollShutdownError::Timeout),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// start_operator_enroll_server
// ─────────────────────────────────────────────────────────────────────────────

/// Start the interactive operator-enrollment HTTP server.
///
/// Binds `bind_addr` (typically `127.0.0.1:0` for a random loopback port),
/// mints a single-use bootstrap token, builds the axum router with the full
/// middleware stack, and spawns a server task. Returns an
/// [`OperatorEnrollHandle`] giving the actual bound address, the bootstrap
/// URL ([`OperatorEnrollHandle::enroll_url`]), the single-use completion
/// signal, and a graceful-shutdown handle.
///
/// `store_path` is opened lazily by [`OperatorApprovalCredentialStore`] (no
/// filesystem access happens here); `profile` is shown on the page for
/// operator orientation only and has no bearing on the persisted
/// credential, which is always recorded with `rp_id: "localhost"`.
/// `label_prefill` pre-populates the page's label input (from
/// `--label <L>` in interactive mode); the operator can still edit it, and
/// `None` leaves the field empty.
///
/// # Errors
///
/// - [`OperatorEnrollStartError::NonLoopbackBind`] — `bind_addr.ip()` is not
///   a loopback address. Enforced at runtime as a defence-in-depth measure:
///   a credential created against a non-loopback origin could never carry
///   rp-id `"localhost"` anyway, so a non-loopback bind here can only be a
///   misconfiguration.
/// - [`OperatorEnrollStartError::Bind`] — `TcpListener::bind(bind_addr)`
///   failed (OS error, port already in use, etc.).
pub async fn start_operator_enroll_server(
    store_path: PathBuf,
    profile: impl Into<String>,
    bind_addr: SocketAddr,
    label_prefill: Option<String>,
) -> Result<OperatorEnrollHandle, OperatorEnrollStartError> {
    if !bind_addr.ip().is_loopback() {
        return Err(OperatorEnrollStartError::NonLoopbackBind { addr: bind_addr });
    }

    let listener =
        TcpListener::bind(bind_addr)
            .await
            .map_err(|source| OperatorEnrollStartError::Bind {
                kind: source.kind(),
                source,
            })?;
    let local_addr = listener
        .local_addr()
        .map_err(|source| OperatorEnrollStartError::Bind {
            kind: source.kind(),
            source,
        })?;

    let bootstrap = OpaqueToken::generate();
    let bootstrap_token_hex = bootstrap.to_hex();

    let (completion_tx, completion_rx) = oneshot::channel::<()>();
    let state = Arc::new(OperatorEnrollState {
        profile: profile.into(),
        auth: StdMutex::new(AuthState::new(bootstrap)),
        store: OperatorApprovalCredentialStore::new(store_path),
        label_prefill,
        completion: StdMutex::new(Some(completion_tx)),
    });

    let router = build_router(state, local_addr);

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let join_handle = tokio::spawn(async move {
        let serve_result = axum::serve(listener, router.into_make_service())
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await;
        if let Err(err) = serve_result {
            tracing::error!(
                error.message = %err,
                "operator-enroll server task exited with error"
            );
        }
    });

    tracing::info!(local_addr = %local_addr, "operator-enroll server started");

    Ok(OperatorEnrollHandle {
        local_addr,
        bootstrap_token_hex,
        completion_rx: Some(completion_rx),
        shutdown_tx,
        join_handle,
    })
}

/// Build the axum `Router` with state and the full Clone-compatible
/// middleware stack.
///
/// Inbound processing order (the last `.layer()` wraps outermost):
///
/// ```text
/// HostHeaderAllowlistLayer (outermost)
///   → SecurityHeadersLayer
///   → OriginHeaderAllowlistLayer
///   → RequestBodyLimitLayer
///   → DefaultBodyLimit
///   → TraceLayer (innermost)
///   → handler
/// ```
fn build_router(state: Arc<OperatorEnrollState>, local_addr: SocketAddr) -> Router {
    let trace_layer = TraceLayer::new_for_http().make_span_with(
        |request: &axum::http::Request<axum::body::Body>| {
            tracing::info_span!(
                "operator_enroll_request",
                method = %request.method(),
                path = request.uri().path(),
            )
        },
    );

    routes::build_router()
        .with_state(state)
        .layer(trace_layer)
        .layer(DefaultBodyLimit::max(BODY_LIMIT_BYTES))
        .layer(RequestBodyLimitLayer::new(BODY_LIMIT_BYTES))
        .layer(OriginHeaderAllowlistLayer::new(local_addr))
        .layer(SecurityHeadersLayer::new())
        .layer(HostHeaderAllowlistLayer::new(local_addr))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::*;

    fn store_path(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("default.toml")
    }

    #[tokio::test]
    async fn enroll_url_uses_localhost_not_bind_ip_and_carries_the_bootstrap_token() {
        let dir = tempfile::tempdir().unwrap();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let handle = start_operator_enroll_server(store_path(&dir), "default", addr, None)
            .await
            .expect("start should succeed");
        let url = handle.enroll_url();
        assert_eq!(
            url,
            format!(
                "http://localhost:{}/bootstrap/{}",
                handle.local_addr().port(),
                handle.bootstrap_token_hex()
            )
        );
        assert!(!url.contains("127.0.0.1"));
        assert!(url.contains("/bootstrap/"));
        handle.shutdown().await.expect("clean shutdown");
    }

    #[tokio::test]
    async fn start_rejects_non_loopback_v4() {
        let dir = tempfile::tempdir().unwrap();
        let addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let err = start_operator_enroll_server(store_path(&dir), "default", addr, None)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            OperatorEnrollStartError::NonLoopbackBind { .. }
        ));
    }

    #[tokio::test]
    async fn start_rejects_non_loopback_external_ipv4() {
        let dir = tempfile::tempdir().unwrap();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 0);
        let err = start_operator_enroll_server(store_path(&dir), "default", addr, None)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            OperatorEnrollStartError::NonLoopbackBind { .. }
        ));
    }

    #[tokio::test]
    async fn start_binds_loopback_and_returns_local_addr() {
        let dir = tempfile::tempdir().unwrap();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let handle = start_operator_enroll_server(store_path(&dir), "default", addr, None)
            .await
            .expect("start should succeed");
        let local = handle.local_addr();
        assert!(local.ip().is_loopback());
        assert_ne!(local.port(), 0);
        handle.shutdown().await.expect("clean shutdown");
    }

    #[tokio::test]
    async fn ipv6_loopback_is_accepted_if_available() {
        let dir = tempfile::tempdir().unwrap();
        let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0);
        match start_operator_enroll_server(store_path(&dir), "default", addr, None).await {
            Ok(handle) => {
                assert!(handle.local_addr().ip().is_loopback());
                handle.shutdown().await.expect("clean shutdown");
            }
            Err(OperatorEnrollStartError::Bind { .. }) => {
                // IPv6 unavailable on this host — acceptable.
            }
            Err(other) => panic!("unexpected error for IPv6 loopback: {other}"),
        }
    }

    #[tokio::test]
    async fn shutdown_completes_within_5s() {
        let dir = tempfile::tempdir().unwrap();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let handle = start_operator_enroll_server(store_path(&dir), "default", addr, None)
            .await
            .expect("start should succeed");
        handle.shutdown().await.expect("shutdown should succeed");
    }

    #[tokio::test]
    async fn await_completion_times_out_when_nothing_enrolls() {
        let dir = tempfile::tempdir().unwrap();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let mut handle = start_operator_enroll_server(store_path(&dir), "default", addr, None)
            .await
            .expect("start should succeed");
        let err = handle
            .await_completion(Duration::from_millis(50))
            .await
            .unwrap_err();
        assert!(matches!(err, OperatorEnrollAwaitError::Timeout));
        handle.shutdown().await.expect("clean shutdown");
    }

    #[tokio::test]
    async fn await_completion_twice_returns_already_awaited() {
        let dir = tempfile::tempdir().unwrap();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let mut handle = start_operator_enroll_server(store_path(&dir), "default", addr, None)
            .await
            .expect("start should succeed");
        let _ = handle.await_completion(Duration::from_millis(10)).await;
        let err = handle
            .await_completion(Duration::from_millis(10))
            .await
            .unwrap_err();
        assert!(matches!(err, OperatorEnrollAwaitError::AlreadyAwaited));
        handle.shutdown().await.expect("clean shutdown");
    }

    #[tokio::test]
    async fn await_completion_reports_sender_dropped_after_shutdown() {
        let dir = tempfile::tempdir().unwrap();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let handle = start_operator_enroll_server(store_path(&dir), "default", addr, None)
            .await
            .expect("start should succeed");
        // Partial-move the receiver out before consuming the rest of the
        // handle, so it can be awaited after the server task (and the
        // OperatorEnrollState holding the sender) has been dropped.
        let Some(rx) = handle.completion_rx else {
            panic!("completion_rx must be present before first await");
        };
        handle.shutdown_tx.send(()).ok();
        let _ = tokio::time::timeout(SHUTDOWN_DEADLINE, handle.join_handle).await;
        let result = rx.await;
        assert!(result.is_err(), "sender must have dropped without sending");
    }
}
