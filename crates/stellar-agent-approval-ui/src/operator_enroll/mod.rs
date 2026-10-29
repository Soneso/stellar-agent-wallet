//! Interactive WebAuthn operator-enrollment server (loopback, one-shot).
//!
//! `approve operator enroll --interactive` starts this server instead of
//! reading `--credential-id` / `--public-key` / `--rp-id` / `--label`
//! arguments: the operator's authenticator creates the credential in place,
//! over a challenge this server issues. The server verifies the registration
//! response and stages the credential; it never writes the credential store.
//! The process that started it receives a [`PendingOperatorEnrollment`],
//! asks the operator to type the confirmation code the page shows, and only
//! a matching code yields the [`ConfirmedOperatorEnrollment`] that persists
//! the credential into the same
//! [`stellar_agent_core::approval::operator_credentials::OperatorApprovalCredentialStore`]
//! the argument-based mode writes to.
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
//! `[remote_approval] allowed_credentials` list is the separate,
//! operator-controlled authorization step; this server's page and the CLI
//! summary both restate that reminder; the ceremony never touches the
//! profile allowlist.
//!
//! # The ceremony
//!
//! 1. The operator's browser exchanges the one-time bootstrap token for a
//!    session (see below) and loads `/enroll`.
//! 2. `POST /enroll/challenge` returns the ceremony's single outstanding
//!    registration challenge: a fresh 32-byte value valid for five minutes
//!    on the session clock. A second request while it is outstanding
//!    returns the same challenge; an expired one is replaced.
//! 3. The page registers a credential over that challenge and posts the
//!    response to `POST /enroll/credential`, which verifies it (see
//!    `registration`). A response that fails verification changes nothing.
//!    The first one that passes consumes the challenge and the single-use
//!    completion latch together, and is handed to
//!    [`OperatorEnrollHandle::await_completion`]; every later post is
//!    refused with `already_completed`.
//! 4. The page computes the confirmation code from the credential its own
//!    ceremony created and shows it. The CLI asks for it at the terminal and
//!    persists the credential only when the typed code matches, before the
//!    ceremony deadline.
//!
//! # Single-use, single-server-run
//!
//! The server is started fresh for exactly one enrollment ceremony and shut
//! down by the caller once it completes (or the caller's timeout elapses). A
//! 32-byte bootstrap token is minted at start and never embedded in a served
//! page; the operator's browser exchanges it once, at `GET /bootstrap/<hex>`,
//! for an `HttpOnly; SameSite=Strict` session cookie and a session proof the
//! bootstrap page keeps in the tab's `sessionStorage`. Every other route
//! requires that cookie; an absent, malformed, mismatched, or expired cookie
//! collapses to a bare `404`. The cookie is host-scoped, so a service on
//! another `localhost` port can receive it; the proof is origin-scoped and
//! never served again, and both POST routes refuse a request without it.
//! The session uses the same lifetime limits as the approval inbox (see
//! `crate::auth`); the ceremony timeout of the caller is normally the shorter
//! limit.
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
//! # Mainnet approval credentials
//!
//! [`start_mainnet_approval_enroll`] runs the same ceremony for an approval
//! credential of the owner-signed mainnet policy
//! ([`EnrollmentPurpose::MainnetApproval`]). It has its own session purpose,
//! so its cookie name and proof storage key differ from the operator
//! enrollment's, and its own confirmation-code domain, so a code computed
//! for one purpose never confirms the other. The server renders the purpose
//! into the page, which derives the code domain from it. This mode neither
//! reads nor writes any credential store: the confirmed credential is only
//! exported, through
//! [`ConfirmedOperatorEnrollment::into_mainnet_policy_credential`], for the
//! owner to add to `mainnet.approval_credentials` and sign. Enrollment alone
//! grants no approval authority.
//!
//! # What registration verification claims
//!
//! The page requests the `none` attestation format, so no statement about
//! the authenticator's make or certification is verified, and the response
//! is no standalone proof of key possession. Verification binds the response
//! to this server's challenge, the exact page origin and `localhost`; the
//! session boundary and the terminal code bind it to the operator.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use axum::{Router, extract::DefaultBodyLimit};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tower_http::{limit::RequestBodyLimitLayer, trace::TraceLayer};

use stellar_agent_core::approval::operator_credentials::OperatorApprovalCredentialStore;

use stellar_agent_loopback_http::brand::PageIdentity;

use crate::auth::{AuthState, OpaqueToken, SessionPurpose};
use crate::{HostHeaderAllowlistLayer, OriginHeaderAllowlistLayer, SecurityHeadersLayer};
use confirmation::{MAINNET_APPROVAL_CODE_DOMAIN, OPERATOR_CODE_DOMAIN};

mod confirmation;
mod error;
mod registration;
mod routes;
mod templates;
#[cfg(any(test, feature = "test-helpers"))]
pub mod test_support;
mod web;

#[cfg(test)]
mod router_tests;

pub use confirmation::{
    ConfirmedOperatorEnrollment, OperatorEnrollmentConfirmationError, PendingOperatorEnrollment,
};
pub use error::{OperatorEnrollAwaitError, OperatorEnrollShutdownError, OperatorEnrollStartError};

use confirmation::StagedEnrollment;
use registration::RegistrationChallenge;

/// Maximum request body size accepted by this server, in bytes (16 KiB) —
/// the same cap the approval-inbox server and the WebAuthn bridge apply.
/// Applied at both `tower_http::limit::RequestBodyLimitLayer` and
/// `axum::extract::DefaultBodyLimit`.
const BODY_LIMIT_BYTES: usize = 16 * 1024;

/// Shutdown deadline for [`OperatorEnrollHandle::shutdown`].
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(5);

/// What a ceremony enrolls a credential for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentPurpose {
    /// An operator credential of the remote-approval surface, persisted to
    /// the profile's operator credential store.
    RemoteOperator,
    /// An approval credential of the owner-signed mainnet policy, exported
    /// for the owner and never persisted by the ceremony.
    MainnetApproval,
}

impl EnrollmentPurpose {
    /// The session purpose of a server running this ceremony.
    fn session_purpose(self) -> SessionPurpose {
        match self {
            Self::RemoteOperator => SessionPurpose::OperatorEnroll,
            Self::MainnetApproval => SessionPurpose::MainnetApprovalEnroll,
        }
    }

    /// The value the server renders into the page's `data-purpose`
    /// attribute, from which the page derives its code domain.
    pub(crate) fn page_value(self) -> &'static str {
        match self {
            Self::RemoteOperator => "remote-operator",
            Self::MainnetApproval => "mainnet-approval",
        }
    }

    /// The domain separator of this purpose's confirmation code.
    pub(crate) fn code_domain(self) -> &'static [u8] {
        match self {
            Self::RemoteOperator => OPERATOR_CODE_DOMAIN,
            Self::MainnetApproval => MAINNET_APPROVAL_CODE_DOMAIN,
        }
    }
}

/// Shared axum state for the operator-enrollment handlers.
struct OperatorEnrollState {
    /// What the ceremony enrolls a credential for.
    purpose: EnrollmentPurpose,
    /// Wallet profile name, shown on the page for operator orientation only.
    profile: String,
    /// Bootstrap-token / session-cookie auth state. See the module docs'
    /// "Single-use, single-server-run" section for the exchange this guards.
    auth: StdMutex<AuthState>,
    /// The credential store the confirmed credential will be enrolled into,
    /// for [`EnrollmentPurpose::RemoteOperator`] only. The server only reads
    /// it, to refuse an already-enrolled ID before staging;
    /// [`ConfirmedOperatorEnrollment::persist`] is the only writer.
    store: Option<OperatorApprovalCredentialStore>,
    /// The exact origin the page runs at, `http://localhost:<bound port>`,
    /// which a registration's `clientDataJSON` must name.
    expected_origin: String,
    /// Optional label to pre-populate the `/enroll` page's label input with
    /// (from `--label` in interactive mode). `None` leaves the field empty
    /// for the operator to fill in.
    label_prefill: Option<String>,
    /// The identity the enrollment page renders, neutral unless the
    /// deployment configured one.
    identity: PageIdentity,
    /// The outstanding challenge and the single-use completion latch,
    /// under one `std::sync::Mutex` so issuing, verifying against and
    /// consuming them is atomic with respect to concurrent requests. The
    /// guard is held only across synchronous work, never across an `.await`
    /// point, and never while the `auth` lock is held.
    ceremony: StdMutex<Ceremony>,
}

/// The mutable state of the one ceremony a server runs.
struct Ceremony {
    /// The challenge the page registers over: `None` until the first
    /// `POST /enroll/challenge`, and again once a registration consumed it
    /// or it expired.
    challenge: Option<RegistrationChallenge>,
    /// `Some` until the first verified registration consumes it.
    completion: Option<oneshot::Sender<StagedEnrollment>>,
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
    completion_rx: Option<oneshot::Receiver<StagedEnrollment>>,
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

    /// Await the verified registration the page posts, for at most
    /// `timeout`. The returned [`PendingOperatorEnrollment`] expires at the
    /// end of that window, so the terminal confirmation shares it.
    ///
    /// # Errors
    ///
    /// The errors of [`Self::await_completion_until`].
    pub async fn await_completion(
        &mut self,
        timeout: Duration,
    ) -> Result<PendingOperatorEnrollment, OperatorEnrollAwaitError> {
        self.await_completion_until(Instant::now() + timeout).await
    }

    /// Await the verified registration the page posts, until `deadline`.
    /// The returned [`PendingOperatorEnrollment`] carries `deadline`, after
    /// which its confirmation refuses.
    ///
    /// # Errors
    ///
    /// - [`OperatorEnrollAwaitError::AlreadyAwaited`]: this handle's
    ///   completion signal was already awaited (it can only be awaited
    ///   once).
    /// - [`OperatorEnrollAwaitError::Timeout`]: no registration was
    ///   verified before `deadline`.
    /// - [`OperatorEnrollAwaitError::SenderDropped`]: the server task
    ///   exited without ever verifying a registration.
    pub async fn await_completion_until(
        &mut self,
        deadline: Instant,
    ) -> Result<PendingOperatorEnrollment, OperatorEnrollAwaitError> {
        let Some(rx) = self.completion_rx.take() else {
            return Err(OperatorEnrollAwaitError::AlreadyAwaited);
        };
        match tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), rx).await {
            Ok(Ok(staged)) => Ok(staged.with_deadline(deadline)),
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
/// filesystem access happens here); the server only reads it, to refuse an
/// already-enrolled credential ID before staging. `profile` is shown on the
/// page for operator orientation only and has no bearing on the credential,
/// which is always recorded with `rp_id: "localhost"`.
/// `label_prefill` pre-populates the page's label input (from
/// `--label <L>` in interactive mode); the operator can still edit it, and
/// `None` leaves the field empty. `page_identity` is the identity the page
/// announces; pass [`PageIdentity::neutral`] for a deployment that configured
/// none.
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
    page_identity: PageIdentity,
) -> Result<OperatorEnrollHandle, OperatorEnrollStartError> {
    start(
        EnrollmentPurpose::RemoteOperator,
        Some(OperatorApprovalCredentialStore::new(store_path)),
        profile.into(),
        bind_addr,
        label_prefill,
        page_identity,
    )
    .await
}

/// Start the enrollment server for an approval credential of the
/// owner-signed mainnet policy, bound to `127.0.0.1:0`.
///
/// The ceremony is the one [`start_operator_enroll_server`] runs, under
/// [`EnrollmentPurpose::MainnetApproval`]: its own session purpose and
/// confirmation-code domain, and no credential store. `profile` is shown on
/// the page for orientation only; `label_prefill` and `page_identity` are as
/// there.
///
/// # Errors
///
/// [`OperatorEnrollStartError::Bind`] when the loopback listener cannot be
/// bound.
pub async fn start_mainnet_approval_enroll(
    profile: String,
    label_prefill: Option<String>,
    page_identity: PageIdentity,
) -> Result<OperatorEnrollHandle, OperatorEnrollStartError> {
    start(
        EnrollmentPurpose::MainnetApproval,
        None,
        profile,
        SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0),
        label_prefill,
        page_identity,
    )
    .await
}

/// Binds the listener and spawns the server of one ceremony for `purpose`.
async fn start(
    purpose: EnrollmentPurpose,
    store: Option<OperatorApprovalCredentialStore>,
    profile: String,
    bind_addr: SocketAddr,
    label_prefill: Option<String>,
    page_identity: PageIdentity,
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

    let (completion_tx, completion_rx) = oneshot::channel::<StagedEnrollment>();
    let state = Arc::new(OperatorEnrollState {
        purpose,
        profile,
        auth: StdMutex::new(AuthState::new(bootstrap, purpose.session_purpose())),
        store,
        expected_origin: expected_origin(local_addr),
        label_prefill,
        identity: page_identity,
        ceremony: StdMutex::new(Ceremony {
            challenge: None,
            completion: Some(completion_tx),
        }),
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

/// The origin the enrollment page runs at: always `localhost` with the bound
/// port, the form [`OperatorEnrollHandle::enroll_url`] opens.
fn expected_origin(local_addr: SocketAddr) -> String {
    format!("http://localhost:{}", local_addr.port())
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
    // The span records the matched route template, never the request path:
    // the bootstrap path carries the single-use token.
    let trace_layer = TraceLayer::new_for_http().make_span_with(
        |request: &axum::http::Request<axum::body::Body>| {
            tracing::info_span!(
                "operator_enroll_request",
                method = %request.method(),
                path = stellar_agent_loopback_http::request_trace::route_label(request),
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
        let handle = start_operator_enroll_server(
            store_path(&dir),
            "default",
            addr,
            None,
            PageIdentity::neutral(),
        )
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
        let err = start_operator_enroll_server(
            store_path(&dir),
            "default",
            addr,
            None,
            PageIdentity::neutral(),
        )
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
        let err = start_operator_enroll_server(
            store_path(&dir),
            "default",
            addr,
            None,
            PageIdentity::neutral(),
        )
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
        let handle = start_operator_enroll_server(
            store_path(&dir),
            "default",
            addr,
            None,
            PageIdentity::neutral(),
        )
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
        match start_operator_enroll_server(
            store_path(&dir),
            "default",
            addr,
            None,
            PageIdentity::neutral(),
        )
        .await
        {
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
        let handle = start_operator_enroll_server(
            store_path(&dir),
            "default",
            addr,
            None,
            PageIdentity::neutral(),
        )
        .await
        .expect("start should succeed");
        handle.shutdown().await.expect("shutdown should succeed");
    }

    #[tokio::test]
    async fn await_completion_times_out_when_nothing_enrolls() {
        let dir = tempfile::tempdir().unwrap();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let mut handle = start_operator_enroll_server(
            store_path(&dir),
            "default",
            addr,
            None,
            PageIdentity::neutral(),
        )
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
        let mut handle = start_operator_enroll_server(
            store_path(&dir),
            "default",
            addr,
            None,
            PageIdentity::neutral(),
        )
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
        let handle = start_operator_enroll_server(
            store_path(&dir),
            "default",
            addr,
            None,
            PageIdentity::neutral(),
        )
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
