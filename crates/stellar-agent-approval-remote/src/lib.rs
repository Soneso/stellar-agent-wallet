//! TLS-protected, passkey-authenticated remote approval HTTP surface.
//!
//! Lets an operator approve or reject pending agent actions from a device
//! other than the wallet host, without SSH access. `approve serve --remote`
//! binds this listener beyond loopback behind TLS, authenticates the
//! operator with a registered passkey, and requires a fresh passkey
//! assertion — computed over a challenge cryptographically bound to the
//! exact pending approval — for every approve/reject action.
//!
//! # What does NOT change
//!
//! Signing keys, the keyring, the attestation key, the audit hash-chain, the
//! two-phase commit, and every existing wire contract are untouched. This
//! crate is additive: a new TLS listener, a new identity path
//! (`ApproverIdentity::PasskeyCredential`, from `stellar-agent-core`), and
//! two opt-in CLI flags gated behind explicit operator consent
//! (`stellar-agent-cli`). The attestation this listener produces is
//! byte-identical to the loopback path's — the distinction between a local
//! and a remote approval lives only in the audit log
//! (`EventKind::ApprovalAttestedRemote` / `ApprovalRejectedRemote`).
//!
//! # Security posture
//!
//! - **TLS is mandatory.** There is no plaintext remote path; `--remote`
//!   without a provisioned or provisionable certificate is a hard start
//!   error (see [`tls`]).
//! - **Two independent authorization layers.** The HTTP layer verifies a
//!   fresh WebAuthn assertion over a challenge bound to the specific pending
//!   entry (see [`challenge_store`], [`verify`]); the core gate
//!   (`ApproverIdentity::is_authorized_for_entry`, `stellar-agent-core`)
//!   independently re-checks allowlist membership and the witness's
//!   entry-binding. Either layer refuses alone even if the other is
//!   mis-wired.
//! - **What-you-see-is-what-you-sign.** The per-action challenge binds
//!   `SHA-256(rand32 || envelope_sha256 || approval_nonce)`, where
//!   `envelope_sha256` is derived from the PARKED pending-approval entry on
//!   the server, never from the request body — an assertion verified for
//!   one entry can never authorize a different entry.
//! - **Enrollment stays loopback-only.** This crate never accepts or
//!   persists a new operator credential over the network. `GET /enroll`
//!   serves a helper page that runs `navigator.credentials.create()`
//!   client-side and displays the resulting credential id and public key —
//!   there is no corresponding write endpoint; the operator copies those
//!   values into `stellar-agent-cli`'s `approve operator enroll`, which
//!   writes the credential store from the local host only. The page must be
//!   served from this listener (rather than run from a local file) because
//!   a WebAuthn credential is bound to its `rp.id` at creation time.

// `deny` (not `forbid`): the test-only `STELLAR_AGENT_HOME` env-var override
// helper in `tls.rs` needs a narrowly-scoped `#[allow(unsafe_code)]` for
// `std::env::set_var` (Rust 2024 marks process-env mutation unsafe). No
// production code path uses `unsafe`.
#![deny(unsafe_code)]

pub mod challenge_store;
pub mod config_validate;
pub mod rate_limit;
pub mod remote_origin;
pub mod session;
pub mod tls;
pub mod verify;
pub mod wire;

mod routes;
mod templates;
mod web;

#[cfg(any(test, feature = "test-helpers"))]
pub mod test_helpers;

pub use config_validate::{RemoteConfigValidationError, validate_remote_config};
pub use tls::{ProvisionedTls, TlsProvisionError, provision_or_load};

use std::net::SocketAddr;
use std::sync::Mutex as StdMutex;
use std::time::Duration;

use axum::Router;
use axum_server::tls_rustls::RustlsConfig;

/// [`axum_server::Handle`] specialised to a plain socket-address listener.
type ServerHandle = axum_server::Handle<SocketAddr>;
use stellar_agent_approval_ui::DecisionContext;
use stellar_agent_core::approval::error::ApprovalError;
use stellar_agent_core::approval::operator_credentials::OperatorApprovalCredentialStore;
use tokio::task::JoinHandle;

use challenge_store::{ActionChallengeStore, LoginChallengeStore};
use rate_limit::TokenBucket;
use session::SessionState;

/// Maximum request body size accepted by the server, in bytes (16 KiB) —
/// matches the loopback approval-inbox server's cap; assertion payloads are
/// well under this.
pub const BODY_LIMIT_BYTES: usize = 16 * 1024;

/// Deadline for [`RemoteServeHandle::shutdown`] to await the server task.
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(5);

/// Configuration for [`start_remote_serve`].
#[non_exhaustive]
pub struct RemoteServeConfig {
    /// Address to bind (validated by [`validate_remote_config`] before this
    /// is constructed in the CLI layer — this type does not re-validate).
    pub bind_addr: SocketAddr,
    /// WebAuthn Relying Party ID — a DNS hostname, never an IP literal.
    pub rp_id: String,
    /// The profile's operator-approval credential allowlist
    /// (`RemoteApprovalConfig::allowed_credentials`).
    pub allowed_credentials: Vec<String>,
    /// The decision context (store path, keyring ref, audit writer, profile)
    /// — reused verbatim from `stellar-agent-approval-ui`, so this crate
    /// never re-implements attestation, grant persistence, or audit
    /// plumbing.
    pub decision_context: DecisionContext,
    /// Path to the profile's operator-approval credential store
    /// (`stellar_agent_core::approval::operator_credentials::default_operator_approval_credentials_path`).
    pub operator_credentials_path: std::path::PathBuf,
    /// Provisioned TLS certificate and key (see [`provision_or_load`]).
    pub tls: ProvisionedTls,
}

impl RemoteServeConfig {
    /// Constructs a `RemoteServeConfig`.
    ///
    /// `#[non_exhaustive]` blocks external struct-literal construction; this
    /// is the canonical entry point for `stellar-agent-cli`.
    #[must_use]
    pub fn new(
        bind_addr: SocketAddr,
        rp_id: impl Into<String>,
        allowed_credentials: Vec<String>,
        decision_context: DecisionContext,
        operator_credentials_path: std::path::PathBuf,
        tls: ProvisionedTls,
    ) -> Self {
        Self {
            bind_addr,
            rp_id: rp_id.into(),
            allowed_credentials,
            decision_context,
            operator_credentials_path,
            tls,
        }
    }
}

/// Shared axum state for all handlers.
#[derive(Clone)]
pub(crate) struct RemoteServeState {
    pub(crate) rp_id: std::sync::Arc<str>,
    /// The exact `https://<rp_id>[:<port>]` origin every WebAuthn
    /// assertion's `clientDataJSON.origin` must match (see
    /// [`remote_origin::expected_https_origin`]). Computed once here at
    /// server-start time, never per-request.
    pub(crate) expected_origin: std::sync::Arc<str>,
    pub(crate) allowed_credentials: std::sync::Arc<Vec<String>>,
    pub(crate) ctx: std::sync::Arc<DecisionContext>,
    pub(crate) operator_credentials: std::sync::Arc<OperatorApprovalCredentialStore>,
    pub(crate) login_challenges: std::sync::Arc<StdMutex<LoginChallengeStore>>,
    pub(crate) action_challenges: std::sync::Arc<StdMutex<ActionChallengeStore>>,
    pub(crate) login_rate_limiter: std::sync::Arc<StdMutex<TokenBucket>>,
    /// Single live session — remote approval is single-operator-sufficient;
    /// a fresh login replaces any prior session.
    pub(crate) session: std::sync::Arc<StdMutex<Option<SessionState>>>,
}

/// Handle to a running remote-approval server.
pub struct RemoteServeHandle {
    local_addr: SocketAddr,
    axum_handle: ServerHandle,
    server_join: JoinHandle<()>,
}

impl std::fmt::Debug for RemoteServeHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteServeHandle")
            .field("local_addr", &self.local_addr)
            .finish_non_exhaustive()
    }
}

impl RemoteServeHandle {
    /// The actual bound socket address.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Triggers graceful shutdown, awaiting the server task.
    ///
    /// # Errors
    ///
    /// Returns an error string if the server task does not stop within the
    /// shutdown deadline or panicked.
    pub async fn shutdown(self) -> Result<(), String> {
        self.axum_handle.graceful_shutdown(Some(SHUTDOWN_DEADLINE));
        tokio::time::timeout(SHUTDOWN_DEADLINE + Duration::from_secs(1), self.server_join)
            .await
            .map_err(|_| {
                "remote-approval server did not stop within the shutdown deadline".to_owned()
            })?
            .map_err(|e| format!("remote-approval server task panicked: {e}"))
    }
}

/// Errors starting the remote-approval server.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RemoteServeStartError {
    /// The TLS certificate/key could not be loaded into a `rustls`
    /// `ServerConfig`.
    #[error("remote-approval TLS config load failed: {detail}")]
    TlsConfigLoad {
        /// Non-secret diagnostic detail.
        detail: String,
    },
    /// The listener could not be bound (port in use, permission, etc.).
    #[error("remote-approval listener bind failed: {kind:?}")]
    Bind {
        /// The I/O error kind.
        kind: std::io::ErrorKind,
    },
}

/// Starts the remote-approval HTTPS server.
///
/// # Errors
///
/// See [`RemoteServeStartError`] variants.
pub async fn start_remote_serve(
    config: RemoteServeConfig,
) -> Result<RemoteServeHandle, RemoteServeStartError> {
    let rustls_config =
        RustlsConfig::from_pem(config.tls.cert_pem.clone(), config.tls.key_pem.clone())
            .await
            .map_err(|e| RemoteServeStartError::TlsConfigLoad {
                detail: e.to_string(),
            })?;

    let operator_credentials =
        OperatorApprovalCredentialStore::new(config.operator_credentials_path);

    // Bind synchronously, before constructing anything origin-dependent: the
    // requested `config.bind_addr` may specify port 0 (OS-assigned ephemeral
    // port), in which case the REAL port is only known once the socket is
    // actually bound. The expected-origin string (used both by the
    // `clientDataJSON.origin` check and the `Origin`-header allowlist layer)
    // MUST use the real bound port — computing it from `config.bind_addr`'s
    // requested port would bake in port `0` and reject every WebAuthn
    // ceremony against an ephemeral-port listener.
    let std_listener = std::net::TcpListener::bind(config.bind_addr)
        .map_err(|e| RemoteServeStartError::Bind { kind: e.kind() })?;
    std_listener
        .set_nonblocking(true)
        .map_err(|e| RemoteServeStartError::Bind { kind: e.kind() })?;
    let local_addr = std_listener
        .local_addr()
        .map_err(|e| RemoteServeStartError::Bind { kind: e.kind() })?;

    let expected_origin: std::sync::Arc<str> =
        remote_origin::expected_https_origin(&config.rp_id, local_addr.port()).into();

    let state = RemoteServeState {
        rp_id: config.rp_id.clone().into(),
        expected_origin,
        allowed_credentials: std::sync::Arc::new(config.allowed_credentials),
        ctx: std::sync::Arc::new(config.decision_context),
        operator_credentials: std::sync::Arc::new(operator_credentials),
        login_challenges: std::sync::Arc::new(StdMutex::new(LoginChallengeStore::new())),
        action_challenges: std::sync::Arc::new(StdMutex::new(ActionChallengeStore::new())),
        login_rate_limiter: std::sync::Arc::new(StdMutex::new(TokenBucket::default())),
        session: std::sync::Arc::new(StdMutex::new(None)),
    };

    let router = build_router(state, &config.rp_id, local_addr.port());

    let axum_handle = ServerHandle::new();
    let server_handle_for_task = axum_handle.clone();
    let server_join = tokio::spawn(async move {
        let result = match axum_server::tls_rustls::from_tcp_rustls(std_listener, rustls_config) {
            Ok(server) => {
                server
                    .handle(server_handle_for_task)
                    .serve(router.into_make_service())
                    .await
            }
            Err(err) => Err(err),
        };
        if let Err(err) = result {
            tracing::error!(error = %err, "remote-approval server task exited with error");
        }
    });

    tracing::info!(local_addr = %local_addr, rp_id = %config.rp_id, "remote-approval server started");

    Ok(RemoteServeHandle {
        local_addr,
        axum_handle,
        server_join,
    })
}

/// Opens the approval store with the standard bounded-retry policy, mapping
/// [`ApprovalError::WriterLocked`] distinctly for the caller.
pub(crate) fn open_store(
    store_path: &std::path::Path,
) -> Result<stellar_agent_core::approval::PendingApprovalStore, ApprovalError> {
    stellar_agent_core::approval::open_with_retry(
        store_path,
        stellar_agent_core::approval::DEFAULT_RETRY_ATTEMPTS,
        stellar_agent_core::approval::DEFAULT_RETRY_BACKOFF,
    )
}

/// Builds the full router, layers included (security headers, origin
/// allowlist, body limits, tracing).
///
/// Visible within the crate (not only this module) so tests can exercise the
/// real, fully-layered response a browser receives — in particular the CSP
/// contract, which only the layer stack applied here enforces.
pub(crate) fn build_router(state: RemoteServeState, rp_id: &str, port: u16) -> Router {
    use axum::extract::DefaultBodyLimit;
    use tower_http::{limit::RequestBodyLimitLayer, trace::TraceLayer};

    let trace_layer = TraceLayer::new_for_http().make_span_with(
        |request: &axum::http::Request<axum::body::Body>| {
            tracing::info_span!(
                "remote_approval_request",
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
        .layer(remote_origin::RemoteOriginAllowlistLayer::new(rp_id, port))
        .layer(stellar_agent_loopback_http::security_headers::SecurityHeadersLayer::new())
}
