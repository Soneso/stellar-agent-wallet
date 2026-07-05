//! Localhost approval-inbox web UI for the Stellar agent wallet.
//!
//! This crate implements a loopback HTTP server that gives the operator a
//! browser view of the pending-approval queue that would otherwise be actioned
//! only via `stellar-agent approve --id <nonce>` on a terminal. It renders the
//! wallet-controlled summary for each pending entry and drives the exact same
//! attest / reject spine ([`stellar_agent_core::approval`]) as the CLI, with
//! [`stellar_agent_core::approval::Surface::Serve`].
//!
//! # Security posture
//!
//! - **Loopback-only bind.** The server refuses any non-loopback bind address
//!   ([`ServeStartError::NonLoopbackBind`]); the queue and the approve/reject
//!   actions must never be reachable off-host.
//! - **One-time bootstrap → session cookie.** A 32-byte bootstrap token is
//!   emitted once (`GET /bootstrap/<hex>`); the first successful exchange
//!   consumes it and sets an `HttpOnly; SameSite=Strict` session cookie. Every
//!   other route requires that cookie; absent / malformed / mismatched
//!   collapses to `404` — no route reveals a session concept exists.
//! - **Per-nonce CSRF.** State-changing POSTs carry
//!   `hex(HMAC-SHA256(session_csrf_key, nonce))` in `X-Stellar-Approval-CSRF`,
//!   recomputed and constant-time-compared server-side.
//! - **Layered defence stack.** Host allowlist, security headers + CSP
//!   (`script-src 'self'`), Origin allowlist on state-changing methods, and a
//!   16 KiB body cap — the same `stellar-agent-loopback-http` layers the
//!   WebAuthn bridge applies.
//! - **No resident store.** Every watcher tick and every handler action opens
//!   the store via [`stellar_agent_core::approval::open_with_retry`], performs
//!   one action, and drops it — releasing the advisory file lock — before
//!   returning. Lock contention surfaces as a `503` busy response, never a
//!   panic or a `500`.
//!
//! # Self-custodial invariant
//!
//! The server never touches signing keys or private key material. The
//! attestation HMAC key is read from the platform keyring only inside the
//! decision seam and zeroized after use; keys never pass through the HTTP layer.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use axum::{Router, extract::DefaultBodyLimit};
use tokio::net::TcpListener;
use tokio::sync::{mpsc::UnboundedSender, oneshot};
use tokio::task::JoinHandle;
use tower_http::{limit::RequestBodyLimitLayer, trace::TraceLayer};

pub mod decision;
pub mod error;

mod auth;
mod routes;
mod templates;
mod watcher;
mod web;

#[cfg(test)]
mod tests;

pub use decision::{
    Decision, DecisionContext, Outcome, REJECT_TOMBSTONE_TTL_MS, RequestIdentity, apply_decision,
};
pub use error::{ServeShutdownError, ServeStartError};
pub use stellar_agent_loopback_http::host_header::HostHeaderAllowlistLayer;
pub use stellar_agent_loopback_http::origin_header::OriginHeaderAllowlistLayer;
pub use stellar_agent_loopback_http::security_headers::SecurityHeadersLayer;
// Shared `RuleProposalSimulated` full-definition HTML renderer — reused
// as-is by `stellar-agent-approval-remote` so both approval surfaces render
// the identical markup for the same entry kind.
pub use templates::render_rule_proposal_definition_html;

use auth::{AuthState, OpaqueToken};

/// Maximum request body size accepted by the server, in bytes (16 KiB).
///
/// Approval-action POSTs carry no body; the tight cap is defence-in-depth,
/// applied at both `tower_http::limit::RequestBodyLimitLayer` and
/// `axum::extract::DefaultBodyLimit`.
pub const BODY_LIMIT_BYTES: usize = 16 * 1024;

/// Deadline for [`ServeHandle::shutdown`] to await each spawned task.
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(5);

/// Shared axum state for all handlers.
#[derive(Clone)]
pub(crate) struct ServeState {
    pub(crate) auth: Arc<StdMutex<AuthState>>,
    pub(crate) ctx: Arc<DecisionContext>,
}

/// Configuration for [`start_serve`].
#[non_exhaustive]
pub struct ServeConfig {
    /// Address to bind (must be loopback; use `127.0.0.1:0` for a random port).
    pub bind_addr: SocketAddr,
    /// The decision context (store path, keyring ref, audit writer, profile).
    pub context: DecisionContext,
    /// Channel the watcher sends the new total pending count on when the queue
    /// grows. The CLI reads the paired receiver and prints the notice.
    pub on_pending_count_changed: UnboundedSender<usize>,
    /// Whether to attempt a best-effort OS toast on a count increase.
    pub notify_enabled: bool,
}

impl ServeConfig {
    /// Construct a server configuration.
    #[must_use]
    pub fn new(
        bind_addr: SocketAddr,
        context: DecisionContext,
        on_pending_count_changed: UnboundedSender<usize>,
        notify_enabled: bool,
    ) -> Self {
        Self {
            bind_addr,
            context,
            on_pending_count_changed,
            notify_enabled,
        }
    }
}

/// Handle to a running approval-inbox server.
///
/// # Drop behaviour
///
/// Dropping the handle without calling [`ServeHandle::shutdown`] leaves the
/// server and watcher tasks running. Always call `shutdown` before process
/// exit.
pub struct ServeHandle {
    local_addr: SocketAddr,
    bootstrap_token_hex: String,
    server_shutdown_tx: oneshot::Sender<()>,
    server_join: JoinHandle<()>,
    watcher_shutdown_tx: oneshot::Sender<()>,
    watcher_join: JoinHandle<()>,
}

impl std::fmt::Debug for ServeHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServeHandle")
            .field("local_addr", &self.local_addr)
            .finish_non_exhaustive()
    }
}

impl ServeHandle {
    /// The actual bound socket address (with the OS-assigned port when `0` was
    /// requested).
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// The one-time bootstrap token, hex-encoded, for assembling the
    /// `http://127.0.0.1:<port>/bootstrap/<token>` URL.
    #[must_use]
    pub fn bootstrap_token_hex(&self) -> &str {
        &self.bootstrap_token_hex
    }

    /// The full bootstrap URL the operator opens to establish a session.
    #[must_use]
    pub fn bootstrap_url(&self) -> String {
        format!(
            "http://127.0.0.1:{}/bootstrap/{}",
            self.local_addr.port(),
            self.bootstrap_token_hex
        )
    }

    /// Trigger graceful shutdown of the server and watcher, awaiting both.
    ///
    /// # Errors
    ///
    /// - [`ServeShutdownError::Timeout`] — a task did not stop within the
    ///   deadline.
    /// - [`ServeShutdownError::JoinFailed`] — a task panicked.
    pub async fn shutdown(self) -> Result<(), ServeShutdownError> {
        let _ = self.server_shutdown_tx.send(());
        let _ = self.watcher_shutdown_tx.send(());

        let server = tokio::time::timeout(SHUTDOWN_DEADLINE, self.server_join).await;
        let watcher = tokio::time::timeout(SHUTDOWN_DEADLINE, self.watcher_join).await;

        for outcome in [server, watcher] {
            match outcome {
                Ok(Ok(())) => {}
                Ok(Err(join_err)) => {
                    return Err(ServeShutdownError::JoinFailed {
                        detail: join_err.to_string(),
                    });
                }
                Err(_elapsed) => return Err(ServeShutdownError::Timeout),
            }
        }
        Ok(())
    }
}

/// Start the approval-inbox HTTP server.
///
/// Binds `config.bind_addr` (loopback-only), mints a single-use bootstrap
/// token, builds the router with the full middleware stack, and spawns the
/// server and the pending-approval watcher. Returns a [`ServeHandle`] carrying
/// the bound address, the bootstrap token, and a graceful-shutdown handle.
///
/// # Errors
///
/// - [`ServeStartError::NonLoopbackBind`] — `config.bind_addr` is not loopback.
/// - [`ServeStartError::Bind`] — the TCP listener could not be bound (port in
///   use, permission, etc.).
///
/// # Panics
///
/// Never panics.
pub async fn start_serve(config: ServeConfig) -> Result<ServeHandle, ServeStartError> {
    if !config.bind_addr.ip().is_loopback() {
        return Err(ServeStartError::NonLoopbackBind {
            addr: config.bind_addr,
        });
    }

    let listener = TcpListener::bind(config.bind_addr).await.map_err(|e| {
        let kind = e.kind();
        ServeStartError::Bind { kind, source: e }
    })?;
    let local_addr = listener.local_addr().map_err(|e| {
        let kind = e.kind();
        ServeStartError::Bind { kind, source: e }
    })?;

    let bootstrap_token = OpaqueToken::generate();
    let bootstrap_token_hex = bootstrap_token.to_hex();
    let auth = Arc::new(StdMutex::new(AuthState::new(bootstrap_token)));

    let store_path = config.context.store_path.clone();
    let state = ServeState {
        auth,
        ctx: Arc::new(config.context),
    };

    let router = build_router(state, local_addr);

    let (server_shutdown_tx, server_shutdown_rx) = oneshot::channel::<()>();
    let server_join = tokio::spawn(async move {
        let serve_result = axum::serve(listener, router.into_make_service())
            .with_graceful_shutdown(async move {
                let _ = server_shutdown_rx.await;
            })
            .await;
        if let Err(err) = serve_result {
            tracing::error!(error.message = %err, "approval-inbox server task exited with error");
        }
    });

    let (watcher_shutdown_tx, watcher_shutdown_rx) = oneshot::channel::<()>();
    let watcher_join = watcher::spawn_watcher(
        store_path,
        config.notify_enabled,
        config.on_pending_count_changed,
        watcher_shutdown_rx,
    );

    tracing::info!(local_addr = %local_addr, "approval-inbox server started");

    Ok(ServeHandle {
        local_addr,
        bootstrap_token_hex,
        server_shutdown_tx,
        server_join,
        watcher_shutdown_tx,
        watcher_join,
    })
}

/// Build the axum `Router` with state and the full Clone-compatible middleware
/// stack.
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
fn build_router(state: ServeState, local_addr: SocketAddr) -> Router {
    let trace_layer = TraceLayer::new_for_http().make_span_with(
        |request: &axum::http::Request<axum::body::Body>| {
            tracing::info_span!(
                "approval_inbox_request",
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
