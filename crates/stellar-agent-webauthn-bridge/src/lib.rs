//! WebAuthn browser-handoff bridge for the Stellar agent wallet.
//!
//! This crate implements the localhost HTTP listener that ferries WebAuthn
//! ceremony bytes from the operator's browser into the wallet-owned approval
//! spine ([`stellar_agent_core::approval::PendingApprovalStore`]).
//!
//! # Architecture
//!
//! The bridge:
//!
//! - Binds exclusively to a loopback address (`127.0.0.1:0` by default; the
//!   OS assigns a random port per session, preventing port-scan guessing).
//! - Enforces a layered defence stack (see below).
//! - Exposes two public entry points: [`start_bridge_register_only`] for
//!   registration-only sessions (no signing-time pubkey lookup wired) and
//!   [`start_bridge_with_pubkey_lookup`] for signing sessions (caller injects
//!   an [`ApprovalPubkeyLookup`] so `/approve/<nonce>/assertion` can resolve
//!   the registered credential pubkey before running `pre_verify_assertion`).
//!   Both return a [`BridgeHandle`] for querying the bound port and
//!   requesting graceful shutdown.
//!
//! # Defence stack
//!
//! Layers 1-3 are the shared `stellar-agent-loopback-http` middleware also
//! applied by `stellar-agent-approval-ui`; the two loopback listeners share
//! one implementation of the Host/Origin/security-header defences. The
//! middleware layers, listed outermost first:
//!
//! 1. **`HostHeaderAllowlistLayer`** — DNS-rebinding defence; rejects any
//!    `Host:` header that is not `127.0.0.1:<port>`, `localhost:<port>`, or
//!    `[::1]:<port>`. Outermost so a rejected Host short-circuits before any
//!    body buffering runs.
//! 2. **`SecurityHeadersLayer`** — injects hardened response headers
//!    (`Cache-Control: no-store`, `X-Content-Type-Options: nosniff`,
//!    `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`,
//!    `Content-Security-Policy`) on every response regardless of status code.
//! 3. **`OriginHeaderAllowlistLayer`** — enforces `Origin:` header on
//!    state-changing methods (POST/PUT/PATCH/DELETE); rejects requests
//!    whose `Origin:` is not `http://127.0.0.1:<port>` or
//!    `http://localhost:<port>`.
//! 4. **`RequestBodyLimitLayer(16 KiB)`** — `tower-http` body cap; defence-in-
//!    depth over axum's `DefaultBodyLimit::max(16 KiB)`. The 16 KiB cap is
//!    tighter than the 64 KiB default; authentic WebAuthn payloads are well
//!    under 4 KiB.
//! 5. **`DefaultBodyLimit::max(16 KiB)`** — axum-level body cap applied via
//!    the router layer (same constant as above).
//! 6. **`TraceLayer`** — path-only structured logging; query strings and body
//!    bytes are never emitted. Innermost wrapper so the recorded span reflects
//!    only the surface area that survives the prior layers' admission
//!    decisions.
//!
//! Global concurrency and request-rate limiting are intentionally not applied.
//! tower's `ConcurrencyLimit` and `RateLimit` produce non-`Clone` services,
//! which cannot be applied at the `Router::layer` level; the only available
//! application point (wrapping `IntoMakeService`) would scope the gate to
//! TCP-connection creation rather than inbound HTTP requests
//! (`MakeService::call(IncomingStream)` runs once per TCP connection, not once
//! per HTTP request — axum 0.8.9 `serve/mod.rs`). For a loopback-bound,
//! single-operator listener the per-request body-size limits plus per-request
//! validation are the operative controls.
//!
//! # Non-goals
//!
//! - This crate does NOT touch signing keys, private key material, or
//!   Soroban auth entries. It is plumbing only and preserves the self-custodial
//!   invariant: keys never pass through the bridge.
//!
//! # Sibling crates
//!
//! - `stellar-agent-core` — provides [`PendingApprovalStore`] and the
//!   `ApprovalKind` enum consumed by the bridge POST handlers.
//! - `stellar-agent-smart-account` — provides the off-chain WebAuthn
//!   verification pipeline consumed after the bridge POST handler delivers
//!   [`stellar_agent_core::approval::AssertionInput`] to the manager.
//! - `stellar-agent-loopback-http` — provides the Host/Origin allowlist and
//!   security-headers middleware re-exported below.
//!
//! # HTTP framework choice
//!
//! axum is used as a thin wrapper over hyper. Migrating to hyper directly would
//! re-implement routing and middleware at meaningful additional cost; actix-web
//! carries a heavier, different middleware model. axum's `Router::layer` model
//! maps cleanly onto the layered defence stack above.

#![forbid(unsafe_code)]

use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use axum::{Router, extract::DefaultBodyLimit};
use stellar_agent_core::approval::store::PendingApprovalStore;
use stellar_agent_smart_account::managers::credentials::CredentialsManager;
use tokio::{net::TcpListener, sync::Mutex, sync::oneshot, task::JoinHandle};
use tower_http::{limit::RequestBodyLimitLayer, trace::TraceLayer};
use tracing::instrument;

pub mod csrf;
pub mod error;
pub(crate) mod templates;
// `wire` carries the @simplewebauthn/browser 13.x JSON shapes. All struct
// fields are credential / signature / attestation material; the module
// deliberately omits `Debug` derives to prevent the tracing layer from
// echoing those bytes. Keep the module crate-private so the no-Debug
// invariant is not re-exported across the crate boundary.
pub(crate) mod wire;

mod handlers;
mod routes;
// `web` holds the vendored `@simplewebauthn/browser` bundle bytes, the
// unminified-source audit companion, and the wallet-authored DOM/fetch glue.
// Crate-private: only `routes` consumes the `include_bytes!` constants for the
// two `/static/*.js` handlers.
pub(crate) mod web;

// Re-export public API surface.
pub use csrf::{CsrfToken, CsrfTokenParseError};
pub use error::{BridgeShutdownError, BridgeStartError};
pub use stellar_agent_loopback_http::host_header::HostHeaderAllowlistLayer;
pub use stellar_agent_loopback_http::origin_header::OriginHeaderAllowlistLayer;
pub use stellar_agent_loopback_http::security_headers::SecurityHeadersLayer;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum request body size accepted by the bridge, in bytes.
///
/// Set to 16 KiB — tighter than the 64 KiB default. Authentic WebAuthn
/// assertion JSON payloads are well under 4 KiB; the additional headroom serves
/// no legitimate request shape.
///
/// Applied at two independent enforcement points:
/// - `tower_http::limit::RequestBodyLimitLayer::new(BRIDGE_BODY_LIMIT_BYTES)`
/// - `axum::extract::DefaultBodyLimit::max(BRIDGE_BODY_LIMIT_BYTES)`
pub const BRIDGE_BODY_LIMIT_BYTES: usize = 16 * 1024;

/// Shutdown deadline for `BridgeHandle::shutdown`.
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(5);

// ─────────────────────────────────────────────────────────────────────────────
// Pubkey lookup
// ─────────────────────────────────────────────────────────────────────────────

/// Opaque error returned by an approval-time passkey public-key lookup.
///
/// The bridge deliberately does not surface backend details to HTTP clients or
/// logs; lookup failure collapses to the same generic assertion-invalid response
/// as malformed WebAuthn bytes.
#[derive(Debug, Clone, Copy)]
pub struct ApprovalPubkeyLookupError;

impl std::fmt::Display for ApprovalPubkeyLookupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("passkey public-key lookup failed")
    }
}

impl std::error::Error for ApprovalPubkeyLookupError {}

/// Resolves the registered SEC1 public key for an approval credential ID.
///
/// Implementations must perform a fresh registry/keyring lookup for each call;
/// the bridge must not cache passkey public keys across approval requests.
pub trait ApprovalPubkeyLookup: Send + Sync + 'static {
    /// Return the 65-byte uncompressed SEC1 P-256 public key for
    /// `credential_id`, or `None` when no matching credential record exists.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalPubkeyLookupError`] when the backing store cannot be
    /// read or the matched credential record carries malformed public-key data.
    fn public_key_sec1_for_credential_id(
        &self,
        credential_id: &[u8],
    ) -> Result<Option<[u8; 65]>, ApprovalPubkeyLookupError>;
}

#[derive(Debug)]
struct MissingApprovalPubkeyLookup;

impl ApprovalPubkeyLookup for MissingApprovalPubkeyLookup {
    fn public_key_sec1_for_credential_id(
        &self,
        _credential_id: &[u8],
    ) -> Result<Option<[u8; 65]>, ApprovalPubkeyLookupError> {
        Ok(None)
    }
}

/// Passkeys-registry backed approval public-key lookup.
///
/// This adapter reads the same per-profile passkeys registry used by
/// [`CredentialsManager`]. It is intended for passkey-signing bridge sessions;
/// registration-only sessions may keep using [`start_bridge_register_only`].
pub struct PasskeysRegistryPubkeyLookup {
    manager: CredentialsManager,
}

impl PasskeysRegistryPubkeyLookup {
    /// Create a lookup adapter for `<passkeys_dir>/<profile_name>.toml`.
    #[must_use]
    pub fn new(
        passkeys_dir: impl Into<PathBuf>,
        profile_name: impl Into<String>,
        rp_id: impl Into<String>,
    ) -> Self {
        Self {
            manager: CredentialsManager::new(passkeys_dir.into(), profile_name, rp_id, None),
        }
    }
}

impl ApprovalPubkeyLookup for PasskeysRegistryPubkeyLookup {
    fn public_key_sec1_for_credential_id(
        &self,
        credential_id: &[u8],
    ) -> Result<Option<[u8; 65]>, ApprovalPubkeyLookupError> {
        self.manager
            .public_key_sec1_for_credential_id(credential_id)
            .map_err(|_| ApprovalPubkeyLookupError)
    }
}

/// Shared axum state for all bridge handlers.
#[derive(Clone)]
pub(crate) struct BridgeState {
    pub(crate) approval_store: Arc<Mutex<PendingApprovalStore>>,
    pub(crate) pubkey_lookup: Arc<dyn ApprovalPubkeyLookup>,
}

// ─────────────────────────────────────────────────────────────────────────────
// BridgeHandle
// ─────────────────────────────────────────────────────────────────────────────

/// Handle to a running bridge HTTP server.
///
/// Returned by [`start_bridge_register_only`] and
/// [`start_bridge_with_pubkey_lookup`].  Provides the actual bound address
/// (useful when the caller requested port `0`) and a graceful-shutdown
/// mechanism.
///
/// # Drop behaviour
///
/// Dropping the `BridgeHandle` without calling [`BridgeHandle::shutdown`]
/// leaves the server task running.  Always call `shutdown` before the process
/// exits to ensure the `tokio::JoinHandle` is resolved.
pub struct BridgeHandle {
    local_addr: SocketAddr,
    shutdown_tx: oneshot::Sender<()>,
    join_handle: JoinHandle<()>,
}

impl std::fmt::Debug for BridgeHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BridgeHandle")
            .field("local_addr", &self.local_addr)
            .finish_non_exhaustive()
    }
}

impl BridgeHandle {
    /// Return the actual bound socket address.
    ///
    /// When `bind_addr` was `127.0.0.1:0`, this returns the OS-assigned port.
    /// Consumers call this to assemble the approval URL emitted to the agent.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Trigger graceful shutdown and wait for the server task to stop.
    ///
    /// Sends a shutdown signal, then waits up to 5 seconds for the server task
    /// to finish.  Returns [`BridgeShutdownError::Timeout`] if the task does
    /// not stop within the deadline, or [`BridgeShutdownError::JoinFailed`] if
    /// the task panicked.
    ///
    /// # Errors
    ///
    /// - [`BridgeShutdownError::Timeout`] — the server task did not stop
    ///   within 5 seconds.
    /// - [`BridgeShutdownError::JoinFailed`] — the server task panicked.
    pub async fn shutdown(self) -> Result<(), BridgeShutdownError> {
        // Signal the server to stop.  If the receiver has already dropped
        // (e.g. the server task exited early), that is not an error.
        let _ = self.shutdown_tx.send(());

        // Wait for the server task to finish, with a timeout.
        match tokio::time::timeout(SHUTDOWN_DEADLINE, self.join_handle).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(join_err)) => Err(BridgeShutdownError::JoinFailed {
                detail: join_err.to_string(),
            }),
            Err(_elapsed) => Err(BridgeShutdownError::Timeout),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// start_bridge
// ─────────────────────────────────────────────────────────────────────────────

/// Start the WebAuthn browser-handoff bridge HTTP server.
///
/// Binds to `bind_addr` (typically `127.0.0.1:0` for a random loopback port),
/// builds the axum router with the full middleware stack, and spawns a
/// server task. IPv6 loopback binds are accepted by the runtime loopback
/// guard; wallet-emitted browser URLs still use `localhost` to preserve
/// WebAuthn RP-ID binding, and the Host-header allowlist also accepts
/// `[::1]:<port>`. Returns a [`BridgeHandle`] giving the actual bound address
/// and a graceful-shutdown handle.
///
/// # State ownership
///
/// `approval_store` is an `Arc<tokio::sync::Mutex<PendingApprovalStore>>` so
/// that the bridge POST handlers can acquire mutable access without blocking
/// the async runtime (blocking I/O inside async tasks would require
/// `spawn_blocking` or an async-aware primitive). The `Mutex` guarantees that
/// at most one handler mutates the store at a time.
///
/// # Errors
///
/// - [`BridgeStartError::NonLoopbackBind`] — `bind_addr.ip()` is not a
///   loopback address.  The bridge enforces loopback-only at runtime as a
///   defence-in-depth measure on top of the loopback-only bind invariant.
/// - [`BridgeStartError::Bind`] — `TcpListener::bind(bind_addr)` failed (OS
///   error, port already in use, etc.).
///
/// # Examples
///
/// ```no_run
/// use std::{net::{IpAddr, Ipv4Addr, SocketAddr}, path::PathBuf, sync::Arc};
/// use tokio::sync::Mutex;
/// use stellar_agent_core::approval::store::PendingApprovalStore;
/// use stellar_agent_webauthn_bridge::start_bridge_register_only;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let store = Arc::new(Mutex::new(PendingApprovalStore::open(
///     PathBuf::from("/tmp/approvals/default.toml"),
/// )?));
/// let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
/// let handle = start_bridge_register_only(store, addr).await?;
/// println!("bridge listening on {}", handle.local_addr());
/// handle.shutdown().await?;
/// # Ok(())
/// # }
/// ```
///
/// # Use-case constraint
///
/// This entry point wires a no-op `MissingApprovalPubkeyLookup` so any
/// signing-flow assertion POST will silently 4xx with
/// `webauthn_assertion_invalid`. **Use
/// this only for registration-only sessions.** Signing sessions MUST go
/// through [`start_bridge_with_pubkey_lookup`] with an injected
/// [`ApprovalPubkeyLookup`] (typically [`PasskeysRegistryPubkeyLookup`]).
/// The function name encodes the constraint to make the misuse hard to reach.
#[instrument(skip(approval_store), fields(bind_addr = %bind_addr))]
pub async fn start_bridge_register_only(
    approval_store: Arc<Mutex<PendingApprovalStore>>,
    bind_addr: SocketAddr,
) -> Result<BridgeHandle, BridgeStartError> {
    start_bridge_with_pubkey_lookup(
        approval_store,
        bind_addr,
        Arc::new(MissingApprovalPubkeyLookup),
    )
    .await
}

/// Start the bridge with an injected passkey public-key lookup.
///
/// Use this entry point for passkey-signing sessions so the
/// `/approve/<nonce>/assertion` handler can resolve the registered credential
/// public key before running `pre_verify_assertion`.
///
/// # Errors
///
/// Returns [`BridgeStartError`] when `bind_addr` is not loopback or the TCP
/// listener cannot be bound.
#[instrument(skip(approval_store, pubkey_lookup), fields(bind_addr = %bind_addr))]
pub async fn start_bridge_with_pubkey_lookup(
    approval_store: Arc<Mutex<PendingApprovalStore>>,
    bind_addr: SocketAddr,
    pubkey_lookup: Arc<dyn ApprovalPubkeyLookup>,
) -> Result<BridgeHandle, BridgeStartError> {
    // Runtime loopback enforcement: reject any non-loopback bind address.
    if !bind_addr.ip().is_loopback() {
        return Err(BridgeStartError::NonLoopbackBind { addr: bind_addr });
    }

    // Bind the TCP listener before spawning the task so bind errors surface
    // immediately to the caller (before any async work).
    let listener = TcpListener::bind(bind_addr)
        .await
        .map_err(|source| BridgeStartError::Bind { source })?;

    let local_addr = listener
        .local_addr()
        .map_err(|source| BridgeStartError::Bind { source })?;

    // Build the router with all Clone-capable middleware layers applied.
    let router = build_router(approval_store, pubkey_lookup, local_addr);

    // Global concurrency / request-rate limiting is intentionally not applied
    // here: tower's `ConcurrencyLimit` / `RateLimit` services are not `Clone`
    // and cannot be applied at `Router::layer`; see the crate-level docs.

    // Oneshot channel: sending () triggers graceful shutdown.
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    // Spawn the server task.
    let join_handle = tokio::spawn(async move {
        let serve_result = axum::serve(listener, router.into_make_service())
            .with_graceful_shutdown(async move {
                // Await the shutdown signal; if the sender drops without
                // sending, treat that as a shutdown request too.
                let _ = shutdown_rx.await;
            })
            .await;

        if let Err(err) = serve_result {
            tracing::error!(
                error.message = %err,
                "bridge server task exited with error"
            );
        }
    });

    tracing::info!(
        local_addr = %local_addr,
        "bridge HTTP server started"
    );

    Ok(BridgeHandle {
        local_addr,
        shutdown_tx,
        join_handle,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Router builder
// ─────────────────────────────────────────────────────────────────────────────

/// Build the axum `Router` with approval-store state and the full Clone-compatible
/// middleware stack.
///
/// # Middleware stack
///
/// `ConcurrencyLimitLayer` / `RateLimitLayer` are intentionally not applied:
/// tower's produced services are not `Clone`, so they cannot be applied at
/// `Router::layer`, and wrapping the `IntoMakeService` would scope the gate to
/// TCP-connection creation instead of inbound HTTP requests.
///
/// Inbound processing order at the router level (the last `.layer()` call
/// wraps outermost):
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
fn build_router(
    approval_store: Arc<Mutex<PendingApprovalStore>>,
    pubkey_lookup: Arc<dyn ApprovalPubkeyLookup>,
    local_addr: SocketAddr,
) -> Router {
    // TraceLayer: path-only logging (never full URI), so query strings and body
    // bytes are never emitted.
    let trace_layer = TraceLayer::new_for_http().make_span_with(
        |request: &axum::http::Request<axum::body::Body>| {
            tracing::info_span!(
                "bridge_request",
                method = %request.method(),
                path = request.uri().path(),
            )
        },
    );

    // HostHeaderAllowlistLayer: DNS-rebinding defence.
    let host_layer = HostHeaderAllowlistLayer::new(local_addr);

    // SecurityHeadersLayer: hardened response headers on every response.
    let security_headers_layer = SecurityHeadersLayer::new();

    // OriginHeaderAllowlistLayer: cross-origin POST hardening.
    let origin_layer = OriginHeaderAllowlistLayer::new(local_addr);

    // axum layer ordering: last `.layer()` call wraps outermost.
    // Inbound order: host → security_headers → origin → body-limits → trace → handler.
    let state = BridgeState {
        approval_store,
        pubkey_lookup,
    };

    routes::build_router()
        .with_state(state)
        .layer(trace_layer)
        .layer(DefaultBodyLimit::max(BRIDGE_BODY_LIMIT_BYTES))
        .layer(RequestBodyLimitLayer::new(BRIDGE_BODY_LIMIT_BYTES))
        .layer(origin_layer)
        .layer(security_headers_layer)
        .layer(host_layer)
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
        reason = "test-only"
    )]
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    // Helper: open a real PendingApprovalStore in a temp dir.
    //
    // Each call creates a fresh temporary directory so tests remain independent.
    // Returns the `Arc<Mutex<PendingApprovalStore>>` together with the `TempDir`
    // hold-handle. The caller binds the `TempDir` into a local so it lives
    // until the test ends — `TempDir::drop` removes the directory; leaking
    // would litter the disk over a long test run.
    fn test_store() -> (Arc<Mutex<PendingApprovalStore>>, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bridge-test.toml");
        let store = PendingApprovalStore::open(path).expect("open approval store");
        (Arc::new(Mutex::new(store)), dir)
    }

    #[tokio::test]
    async fn start_bridge_rejects_non_loopback_v4() {
        let (store, _dir) = test_store();
        let addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let err = start_bridge_register_only(store, addr).await.unwrap_err();
        assert!(
            matches!(err, BridgeStartError::NonLoopbackBind { .. }),
            "expected NonLoopbackBind, got: {err}"
        );
    }

    #[tokio::test]
    async fn start_bridge_rejects_non_loopback_external_ipv4() {
        let (store, _dir) = test_store();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 0);
        let err = start_bridge_register_only(store, addr).await.unwrap_err();
        assert!(
            matches!(err, BridgeStartError::NonLoopbackBind { .. }),
            "expected NonLoopbackBind for 8.8.8.8, got: {err}"
        );
    }

    #[tokio::test]
    async fn start_bridge_binds_loopback_and_returns_local_addr() {
        let (store, _dir) = test_store();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let handle = start_bridge_register_only(store, addr)
            .await
            .expect("start_bridge_register_only should succeed");
        let local = handle.local_addr();
        assert!(
            local.ip().is_loopback(),
            "local_addr should be loopback, got: {local}"
        );
        assert_ne!(local.port(), 0, "OS should have assigned a non-zero port");
        handle.shutdown().await.expect("clean shutdown");
    }

    #[tokio::test]
    async fn healthz_route_responds_200() {
        let (store, _dir) = test_store();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let handle = start_bridge_register_only(store, addr)
            .await
            .expect("start_bridge_register_only should succeed");
        let local = handle.local_addr();

        // Send a real HTTP/1.1 request over loopback TCP.
        let url = format!("http://{local}/healthz");
        let host_header = local.to_string();

        let client = reqwest::Client::builder().build().expect("reqwest client");

        let resp = client
            .get(&url)
            .header("Host", &host_header)
            .send()
            .await
            .expect("GET /healthz");

        assert_eq!(
            resp.status().as_u16(),
            200,
            "GET /healthz should return 200"
        );
        let body: serde_json::Value = resp.json().await.expect("JSON body");
        assert_eq!(
            body,
            serde_json::json!({"status": "ok"}),
            "GET /healthz body should be {{\"status\":\"ok\"}}"
        );

        handle.shutdown().await.expect("clean shutdown");
    }

    #[tokio::test]
    async fn shutdown_completes_within_5s() {
        let (store, _dir) = test_store();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let handle = start_bridge_register_only(store, addr)
            .await
            .expect("start_bridge_register_only should succeed");

        // Immediately shut down; must complete within 5 seconds without error.
        handle.shutdown().await.expect("shutdown should succeed");
    }

    // IPv6 loopback address is_loopback() returns true; verify it is accepted
    // by start_bridge_register_only (the bind itself may fail if IPv6 is unavailable).
    #[tokio::test]
    async fn ipv6_loopback_is_accepted_if_available() {
        let (store, _dir) = test_store();
        let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0);
        match start_bridge_register_only(store, addr).await {
            Ok(handle) => {
                // IPv6 available: verify it is loopback.
                assert!(handle.local_addr().ip().is_loopback());
                handle.shutdown().await.expect("clean shutdown");
            }
            Err(BridgeStartError::Bind { .. }) => {
                // IPv6 unavailable on this host — acceptable.
            }
            Err(other) => {
                panic!("unexpected error for IPv6 loopback: {other}");
            }
        }
    }

    // ─── ApprovalPubkeyLookupError ────────────────────────────────────────────

    /// `ApprovalPubkeyLookupError` implements `Display` with the exact string
    /// "passkey public-key lookup failed". Assert the exact text so that any
    /// accidental change to the user-facing message is caught.
    #[test]
    fn approval_pubkey_lookup_error_display() {
        let err = ApprovalPubkeyLookupError;
        let rendered = err.to_string();
        assert_eq!(
            rendered, "passkey public-key lookup failed",
            "Display text changed; check error-indistinguishability posture"
        );
    }

    /// `ApprovalPubkeyLookupError` implements `std::error::Error`. Confirm the
    /// `source()` is `None` (no cause chain) as the type is a terminal error.
    #[test]
    fn approval_pubkey_lookup_error_is_std_error() {
        let err = ApprovalPubkeyLookupError;
        // Confirm it satisfies the std::error::Error bound.
        let _: &dyn std::error::Error = &err;
        // No source chain — it is a terminal, opaque error.
        assert!(
            std::error::Error::source(&err).is_none(),
            "ApprovalPubkeyLookupError must have no error source"
        );
    }

    // ─── PasskeysRegistryPubkeyLookup ────────────────────────────────────────

    /// `PasskeysRegistryPubkeyLookup` wraps `CredentialsManager`. With an
    /// empty / nonexistent passkeys registry, looking up any credential ID
    /// returns `Ok(None)` — no match, no error.
    #[test]
    fn passkeys_registry_pubkey_lookup_returns_none_for_missing_credential() {
        let dir = tempfile::tempdir().expect("tempdir");
        let passkeys_dir = dir.path().join("passkeys");
        // Do NOT create the directory — CredentialsManager should handle missing
        // directories gracefully and return Ok(None) for unknown credential IDs.
        let lookup = PasskeysRegistryPubkeyLookup::new(&passkeys_dir, "test-profile", "localhost");
        let cred_id = [0xAAu8; 16];
        let result = lookup.public_key_sec1_for_credential_id(&cred_id);
        assert!(
            matches!(result, Ok(None)),
            "empty registry must return Ok(None), got: {result:?}"
        );
    }
}
