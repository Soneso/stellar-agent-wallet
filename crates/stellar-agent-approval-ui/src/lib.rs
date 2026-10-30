//! Localhost approval-inbox web UI for the Stellar agent wallet.
//!
//! This crate implements a loopback HTTP server that gives the operator a
//! browser view of the pending-approval queue that would otherwise be actioned
//! only via `stellar-agent approve --id <nonce> --profile <name>` on a terminal. It renders the
//! wallet-controlled summary for each pending entry and drives the exact same
//! attest / reject spine ([`stellar_agent_core::approval`]) as the CLI, with
//! [`stellar_agent_core::approval::Surface::Serve`].
//!
//! # Security posture
//!
//! - **Loopback-only bind.** The server refuses any non-loopback bind address
//!   ([`ServeStartError::NonLoopbackBind`]); the queue and the approve/reject
//!   actions must never be reachable off-host.
//! - **One-time bootstrap → session cookie and session proof.** A 32-byte
//!   bootstrap token is emitted once (`GET /bootstrap/<hex>`); the first
//!   successful exchange consumes it, sets an `HttpOnly; SameSite=Strict`
//!   session cookie with a per-listener random name and a `Max-Age` of the
//!   absolute session limit, and returns a page that stores a separate
//!   session proof in the tab's `sessionStorage`. Every other route requires
//!   the cookie; absent / malformed / mismatched / expired collapses to
//!   `404`.
//! - **Cookies are host-scoped, the proof is origin-scoped.** A browser sends
//!   the cookie to every port on `127.0.0.1`, so another local service can
//!   receive it. `sessionStorage` belongs to the full origin, port included,
//!   so that service cannot read the proof, and no cookie-authorized route
//!   returns it. State-changing POSTs require the proof in `X-Session-Proof`;
//!   a stolen cookie can still read what the cookie authorizes until the
//!   session expires.
//! - **Per-nonce CSRF.** State-changing POSTs carry
//!   `hex(HMAC-SHA256(session_csrf_key, nonce))` in `X-Stellar-Approval-CSRF`,
//!   recomputed and constant-time-compared server-side.
//! - **Bounded session.** A session expires after 15 minutes without operator
//!   activity or 8 hours after the bootstrap exchange, and is never revived;
//!   restart the server for a new one. Background polling and cookie-only
//!   requests do not count as activity.
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
pub mod operator_enroll;
pub mod presence;
pub use presence::{MainnetPresenceConfig, MainnetPresenceHandle, start_mainnet_presence};

mod auth;
mod routes;
mod templates;
mod watcher;
mod web;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod trace_capture;

pub use decision::{
    Decision, DecisionContext, Outcome, REJECT_TOMBSTONE_TTL_MS, RequestIdentity, apply_decision,
};
pub use error::{PresenceStartRefusal, ServeShutdownError, ServeStartError};
pub use stellar_agent_loopback_http::brand::PageIdentity;
pub use stellar_agent_loopback_http::host_header::HostHeaderAllowlistLayer;
pub use stellar_agent_loopback_http::origin_header::OriginHeaderAllowlistLayer;
pub use stellar_agent_loopback_http::security_headers::SecurityHeadersLayer;
// Approval rendering reused as-is by `stellar-agent-approval-remote`, so both
// approval surfaces render an entry identically instead of drifting apart as
// two copies. The browser-side half is served by both servers at
// `/static/app-shared.js`; the server-side half renders the decision card.
pub use templates::{
    DETAIL_STYLE, INBOX_STYLE, INCONSISTENT_MESSAGE, INCONSISTENT_NOTICE, SIMULATED_FEE_NOTE,
    approve_button_label, asset_code, escape_value, html_escape, kind_pill, pending_json_value,
    render_context_header_html, render_rule_proposal_definition_html, render_summary_html,
};
pub use web::APP_SHARED_JS;

use auth::{AuthState, OpaqueToken, SessionPurpose};

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
    pub(crate) presence: Option<Arc<presence::PresenceState>>,
    pub(crate) auth: Arc<StdMutex<AuthState>>,
    pub(crate) ctx: Arc<DecisionContext>,
    /// The identity every served page renders, neutral unless the deployment
    /// configured one.
    pub(crate) identity: Arc<PageIdentity>,
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
    /// The identity the served pages announce.
    ///
    /// [`PageIdentity::neutral`] unless [`ServeConfig::with_page_identity`]
    /// supplies one: a deployment that configured nothing serves pages with a
    /// plain title, no name, and no mark.
    pub page_identity: PageIdentity,
}

impl ServeConfig {
    /// Construct a server configuration with the neutral page identity.
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
            page_identity: PageIdentity::neutral(),
        }
    }

    /// Sets the identity the served pages announce.
    #[must_use = "builder setters return the updated configuration by value"]
    pub fn with_page_identity(mut self, page_identity: PageIdentity) -> Self {
        self.page_identity = page_identity;
        self
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
    bootstrap_host: &'static str,
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
            "http://{}:{}/bootstrap/{}",
            self.bootstrap_host,
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
    let auth = Arc::new(StdMutex::new(AuthState::new(
        bootstrap_token,
        SessionPurpose::Inbox,
    )));

    let mainnet =
        config.context.context.chain_id == stellar_agent_core::approval::presence::MAINNET_CHAIN_ID;
    if mainnet {
        let refused = || ServeStartError::Presence(PresenceStartRefusal::PolicyUnavailable);
        config
            .context
            .mainnet_authority
            .as_ref()
            .ok_or_else(refused)?
            .load_current()
            .map_err(|_| refused())?;
    }
    let store_path = config.context.store_path.clone();
    let ctx = Arc::new(config.context);
    let identity = Arc::new(config.page_identity);
    let presence = if mainnet {
        presence::PresenceState::inbox(
            auth.clone(),
            ctx.clone(),
            identity.clone(),
            local_addr.port(),
        )
    } else {
        None
    };
    let state = ServeState {
        auth,
        ctx,
        identity,
        presence,
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
        bootstrap_host: if mainnet { "localhost" } else { "127.0.0.1" },
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
    // The span records the matched route template, never the request path:
    // the bootstrap and approval paths carry a token or a nonce.
    let trace_layer = TraceLayer::new_for_http().make_span_with(
        |request: &axum::http::Request<axum::body::Body>| {
            tracing::info_span!(
                "approval_inbox_request",
                method = %request.method(),
                path = stellar_agent_loopback_http::request_trace::route_label(request),
            )
        },
    );

    let presence = state.presence.clone();
    let mut router = routes::build_router().with_state(state);
    if let Some(presence) = presence {
        router = router.merge(presence::routes(presence));
    }
    router
        .layer(trace_layer)
        .layer(DefaultBodyLimit::max(BODY_LIMIT_BYTES))
        .layer(RequestBodyLimitLayer::new(BODY_LIMIT_BYTES))
        .layer(OriginHeaderAllowlistLayer::new(local_addr))
        .layer(SecurityHeadersLayer::new())
        .layer(HostHeaderAllowlistLayer::new(local_addr))
}
