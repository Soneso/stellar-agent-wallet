//! TLS-protected, passkey-authenticated remote approval HTTP surface.
//!
//! Every approval and rejection requires a fresh assertion bound to the entry.
//! Testnet trusts the live profile allowlist and enrolled operator keys.
//! Mainnet requires an origin and leaf SPKI pin from the verified owner-signed policy.
//! Its login and consent trust policy credentials alone; the store supplies counters.
//! Each verified login or decision checks the counter once under the store lock.
//! Receipt verification and commit do not update counters.
//!
//! Signed-origin startup loads explicit PEM paths and checks the served leaf pin.
//! Host and Origin checks use the signed public authority, independent of backend ports.
//! The secure session cookie and page CSRF header protect consent routes and assets.
//! A policy re-sign requires restart, and running listeners never reload TLS.
//!
//! Persistent serving requires exposure consent at the CLI.
//! One-shot serving prints a secret-free signed link and scopes routes to one entry.
//! Testnet enrollment writes remain local; its remote helper only displays registration data.
//! Signed consent mounts no enrollment helper; [`enroll_listener`] serves signed-origin enrollment.

// `deny` (not `forbid`): the test-only `STELLAR_AGENT_HOME` env-var override
// helper in `tls.rs` needs a narrowly-scoped `#[allow(unsafe_code)]` for
// `std::env::set_var` (Rust 2024 marks process-env mutation unsafe). No
// production code path uses `unsafe`.
#![deny(unsafe_code)]

pub mod challenge_store;
pub mod config_validate;
pub mod enroll_listener;
pub mod rate_limit;
pub mod remote_origin;
pub mod session;
pub mod tls;
pub mod verify;
pub mod wire;

mod routes;
mod templates;
mod web;

// Gated on the feature alone, not `any(test, feature = "test-helpers")`: the
// module needs the optional `p256` dependency, which is gated to the SAME
// feature (`test-helpers = ["dep:p256"]`) — `cfg(test)` alone would compile
// this module (and its `use p256::...` imports) without the dependency
// present, an unresolved-import build failure under any bare `cargo test`/
// `cargo build --tests` invocation that omits `--features test-helpers`. The
// sole internal consumer (`routes.rs`) is already double-gated
// `#[cfg(all(test, feature = "test-helpers"))]`, so no caller depends on this
// module compiling under `cfg(test)` alone.
#[cfg(feature = "test-helpers")]
pub mod test_helpers;

/// Generates an independent P-256 leaf and its SPKI pin for listener clients.
///
/// # Panics
///
/// Panics if certificate generation fails for the supplied DNS host.
#[cfg(feature = "test-helpers")]
#[must_use]
pub fn signed_origin_test_leaf(host: &str) -> test_helpers::PinnedLeaf {
    test_helpers::pinned_leaf(host, &rcgen::PKCS_ECDSA_P256_SHA256)
}

pub use config_validate::{RemoteConfigValidationError, validate_remote_config};
pub use stellar_agent_loopback_http::brand::PageIdentity;
pub use tls::{ProvisionedTls, TlsProvisionError, provision_or_load};

use std::net::SocketAddr;
use std::sync::Mutex as StdMutex;
use std::time::Duration;

use axum::Router;
use axum_server::tls_rustls::RustlsConfig;

/// [`axum_server::Handle`] specialised to a plain socket-address listener.
type ServerHandle = axum_server::Handle<SocketAddr>;
use stellar_agent_approval_ui::DecisionContext;
use stellar_agent_approval_ui::presence::{
    MainnetPresenceConfig, PresenceCompletion, SignedOriginMode, signed_origin_consent,
};
use stellar_agent_core::approval::ListenerIdentity;
use stellar_agent_core::approval::RemoteApprovalAuthority;
use stellar_agent_core::approval::error::ApprovalError;
use stellar_agent_core::approval::operator_credentials::OperatorApprovalCredentialStore;
use stellar_agent_core::profile::caip2::Caip2;
use stellar_agent_core::{ApprovalFailure, WalletError};
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
    /// Where the served profile's current authorization lives: its
    /// `[remote_approval] allowed_credentials` list and its
    /// operator-credential store, both read again at every check.
    pub authority: RemoteApprovalAuthority,
    /// The decision context (store path, keyring ref, audit writer, profile)
    /// — reused verbatim from `stellar-agent-approval-ui`, so this crate
    /// never re-implements attestation, grant persistence, or audit
    /// plumbing.
    pub decision_context: DecisionContext,
    /// Provisioned TLS certificate and key (see [`provision_or_load`]).
    pub tls: ProvisionedTls,
    /// The identity the served pages announce.
    ///
    /// [`PageIdentity::neutral`] unless
    /// [`RemoteServeConfig::with_page_identity`] supplies one: a deployment
    /// that configured nothing serves pages with a plain title, no name, and
    /// no mark.
    pub page_identity: PageIdentity,
    prepared: Option<PreparedStartup>,
    one_shot: Option<MainnetPresenceConfig>,
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
        authority: RemoteApprovalAuthority,
        decision_context: DecisionContext,
        tls: ProvisionedTls,
    ) -> Self {
        Self {
            bind_addr,
            rp_id: rp_id.into(),
            authority,
            decision_context,
            tls,
            page_identity: PageIdentity::neutral(),
            prepared: None,
            one_shot: None,
        }
    }

    /// Loads the profile policy and TLS pair once for startup.
    ///
    /// # Errors
    /// Returns policy, configuration, permission, or pin refusals before binding.
    pub async fn from_profile(
        bind_addr: SocketAddr,
        remote: &stellar_agent_core::profile::schema::RemoteApprovalConfig,
        authority: RemoteApprovalAuthority,
        decision_context: DecisionContext,
    ) -> Result<Self, RemoteServeStartError> {
        let current = decision_context
            .mainnet_authority
            .as_ref()
            .map(stellar_agent_core::approval::MainnetApprovalAuthority::load_current)
            .transpose()?;
        let pin = current
            .as_ref()
            .map(|current| ListenerIdentity::capture(current.policy()))
            .transpose()?
            .map(|identity| identity.cert_spki_sha256());
        let (tls, server) =
            tls::select_tls(&decision_context.context.profile_name, remote, pin.as_ref()).await?;
        let mut config = Self::new(bind_addr, &remote.rp_id, authority, decision_context, tls);
        config.prepared = Some(PreparedStartup { current, server });
        Ok(config)
    }

    /// Sets the identity the served pages announce.
    #[must_use = "builder setters return the updated configuration by value"]
    pub fn with_page_identity(mut self, page_identity: PageIdentity) -> Self {
        self.page_identity = page_identity;
        self
    }

    /// Restricts this listener to one entry and returns presence to its command.
    #[must_use]
    pub fn with_one_shot(mut self, config: MainnetPresenceConfig) -> Self {
        self.one_shot = Some(config);
        self
    }
}

/// Shared axum state for all handlers.
#[derive(Clone)]
pub(crate) struct RemoteServeState {
    pub(crate) listener_identity: Option<ListenerIdentity>,
    pub(crate) selected_nonce: Option<std::sync::Arc<str>>,
    pub(crate) rp_id: std::sync::Arc<str>,
    /// The exact `https://<rp_id>[:<port>]` origin every WebAuthn
    /// assertion's `clientDataJSON.origin` must match (see
    /// [`remote_origin::expected_https_origin`]). Computed once here at
    /// server-start time, never per-request.
    pub(crate) expected_origin: std::sync::Arc<str>,
    /// The served profile's authorization source, read at every check.
    pub(crate) authority: std::sync::Arc<RemoteApprovalAuthority>,
    /// The chain the served profile is on; a profile whose current chain
    /// differs is no authorization.
    pub(crate) chain: Caip2,
    pub(crate) ctx: std::sync::Arc<RemoteContext>,
    pub(crate) operator_credentials: std::sync::Arc<OperatorApprovalCredentialStore>,
    pub(crate) login_challenges: std::sync::Arc<StdMutex<LoginChallengeStore>>,
    pub(crate) action_challenges: std::sync::Arc<StdMutex<ActionChallengeStore>>,
    pub(crate) login_rate_limiter: std::sync::Arc<StdMutex<TokenBucket>>,
    /// Single live session — remote approval is single-operator-sufficient;
    /// a fresh login replaces any prior session.
    pub(crate) session: std::sync::Arc<StdMutex<Option<SessionState>>>,
    /// The identity every served page renders, neutral unless the deployment
    /// configured one.
    pub(crate) identity: std::sync::Arc<PageIdentity>,
}

pub(crate) struct RemoteContext {
    pub(crate) context: stellar_agent_core::approval::ApprovalContext,
    pub(crate) store_path: std::path::PathBuf,
    pub(crate) mainnet_authority: Option<stellar_agent_core::approval::MainnetApprovalAuthority>,
    pub(crate) decision: Option<std::sync::Arc<DecisionContext>>,
}

impl From<DecisionContext> for RemoteContext {
    fn from(context: DecisionContext) -> Self {
        Self {
            context: context.context.clone(),
            store_path: context.store_path.clone(),
            mainnet_authority: context.mainnet_authority.clone(),
            decision: Some(std::sync::Arc::new(context)),
        }
    }
}

struct PreparedStartup {
    current: Option<stellar_agent_core::approval::CurrentMainnetApprovalPolicy>,
    server: RustlsConfig,
}

struct ListenerConfig {
    bind_addr: SocketAddr,
    rp_id: String,
    authority: RemoteApprovalAuthority,
    decision_context: RemoteContext,
    tls: ProvisionedTls,
    prepared: Option<PreparedStartup>,
    page_identity: PageIdentity,
    one_shot: Option<MainnetPresenceConfig>,
}

/// Handle to a running remote-approval server.
pub struct RemoteServeHandle {
    local_addr: SocketAddr,
    axum_handle: ServerHandle,
    server_join: JoinHandle<()>,
    public_origin: String,
    completion: Option<PresenceCompletion>,
    #[cfg(feature = "test-helpers")]
    test_session: std::sync::Arc<StdMutex<Option<SessionState>>>,
}

impl std::fmt::Debug for RemoteServeHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteServeHandle")
            .field("local_addr", &self.local_addr)
            .finish_non_exhaustive()
    }
}

impl RemoteServeHandle {
    /// Exposes session timing and CSRF state to adversarial listener tests.
    #[cfg(feature = "test-helpers")]
    #[must_use]
    pub fn session_for_test(&self) -> std::sync::Arc<StdMutex<Option<SessionState>>> {
        self.test_session.clone()
    }

    /// The public origin of this listener, including the signed canonical port.
    #[must_use]
    pub fn public_origin(&self) -> &str {
        &self.public_origin
    }

    /// Takes the completion channel of a one-shot ceremony once.
    pub fn take_completion(&mut self) -> Option<PresenceCompletion> {
        self.completion.take()
    }

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
    /// A verified-policy or configuration refusal before binding.
    #[error("{0}")]
    Policy(#[from] WalletError),
    /// A TLS file or served-leaf pin refusal before binding.
    #[error("{0}")]
    Tls(#[from] TlsProvisionError),
    /// Mainnet remote consent requires a signed approval origin.
    #[error(
        "Mainnet consent uses the local passkey page; remote approval is unavailable for mainnet."
    )]
    MainnetPresenceUnsupported,
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
    /// The decision context names a chain that is not a Stellar CAIP-2 ID.
    #[error("remote-approval decision context names an unknown chain: {detail}")]
    UnknownChain {
        /// Non-secret diagnostic detail.
        detail: String,
    },
}

impl RemoteServeStartError {
    /// Converts startup errors to their CLI envelope codes.
    #[must_use]
    pub fn into_wallet_error(self) -> WalletError {
        match self {
            Self::Policy(error) => error,
            Self::Tls(error) => error.wallet_error(),
            error => {
                WalletError::Internal(stellar_agent_core::error::InternalError::UnexpectedState {
                    detail: format!("approve.remote_serve_start_failed: {error}"),
                })
            }
        }
    }
}

/// Requires an enabled remote configuration for either signed listener mode.
///
/// # Errors
/// Returns the disabled-remote refusal when the configuration is absent or disabled.
pub(crate) fn enabled_remote_config(
    profile: &stellar_agent_core::profile::schema::Profile,
) -> Result<&stellar_agent_core::profile::schema::RemoteApprovalConfig, WalletError> {
    profile.remote_approval.as_ref().filter(|config| config.enabled).ok_or_else(|| {
        WalletError::Internal(stellar_agent_core::error::InternalError::UnexpectedState {
            detail: "approve.remote_not_configured: profile has no enabled [remote_approval] block; enable it before starting signed-origin consent".to_owned(),
        })
    })
}

/// Starts the remote-approval HTTPS server.
///
/// # Errors
///
/// See [`RemoteServeStartError`] variants.
pub async fn start_remote_serve(
    config: RemoteServeConfig,
) -> Result<RemoteServeHandle, RemoteServeStartError> {
    start_listener(ListenerConfig {
        bind_addr: config.bind_addr,
        rp_id: config.rp_id,
        authority: config.authority,
        decision_context: config.decision_context.into(),
        tls: config.tls,
        prepared: config.prepared,
        page_identity: config.page_identity,
        one_shot: config.one_shot,
    })
    .await
}

/// Starts the signed-origin TLS ceremony for one command without holding its audit writer.
///
/// # Errors
/// Returns policy, disabled-remote, TLS, bind, or presented-entry refusals.
pub async fn start_remote_presence(
    config: MainnetPresenceConfig,
) -> Result<RemoteServeHandle, RemoteServeStartError> {
    let current = config.authority.load_current()?;
    let identity = ListenerIdentity::capture(current.policy())?;
    let remote = enabled_remote_config(current.profile())?;
    let bind_addr = validate_remote_config(&remote.bind, &remote.rp_id).map_err(|error| {
        WalletError::Internal(stellar_agent_core::error::InternalError::UnexpectedState {
            detail: format!("approve.remote_config_invalid: {error}"),
        })
    })?;
    let (tls, server) = tls::select_tls(
        &config.context.profile_name,
        remote,
        Some(&identity.cert_spki_sha256()),
    )
    .await?;
    let context = RemoteContext {
        context: config.context.clone(),
        store_path: config.store_path.clone(),
        mainnet_authority: Some(config.authority.clone()),
        decision: None,
    };
    start_listener(ListenerConfig {
        bind_addr,
        rp_id: remote.rp_id.clone(),
        prepared: Some(PreparedStartup {
            current: Some(current.clone()),
            server,
        }),
        authority: RemoteApprovalAuthority::for_profile(&config.context.profile_name)?,
        decision_context: context,
        tls,
        page_identity: config.page_identity.clone(),
        one_shot: Some(config),
    })
    .await
}

async fn start_listener(
    mut config: ListenerConfig,
) -> Result<RemoteServeHandle, RemoteServeStartError> {
    let mut prepared = config.prepared.take();
    let signed = if config.decision_context.context.chain_id
        == stellar_agent_core::approval::presence::MAINNET_CHAIN_ID
    {
        let Some(authority) = config.decision_context.mainnet_authority.as_ref() else {
            return Err(RemoteServeStartError::MainnetPresenceUnsupported);
        };
        let current = match prepared
            .as_mut()
            .and_then(|prepared| prepared.current.take())
        {
            Some(current) => current,
            None => authority.load_current()?,
        };
        let Some(origin) = current
            .policy()
            .mainnet()
            .and_then(|body| body.approval_origin.clone())
        else {
            return Err(RemoteServeStartError::MainnetPresenceUnsupported);
        };
        let identity = ListenerIdentity::capture(current.policy())?;
        let remote = enabled_remote_config(current.profile())?;
        if config.rp_id != origin.rp_id() || remote.rp_id != origin.rp_id() {
            return Err(WalletError::Approval(ApprovalFailure::OriginProfileMismatch).into());
        }
        if authority.profile_name() != config.decision_context.context.profile_name {
            return Err(WalletError::Approval(ApprovalFailure::PresencePolicyUnavailable).into());
        }
        tls::verify_pin(&config.tls, &identity.cert_spki_sha256())?;
        Some((origin, identity))
    } else {
        None
    };
    if config.one_shot.is_some() && signed.is_none() {
        return Err(RemoteServeStartError::MainnetPresenceUnsupported);
    }
    let rustls_config = match prepared {
        Some(prepared) => prepared.server,
        None if signed.is_some() => tls::server_config(&config.tls).await?,
        None => RustlsConfig::from_pem(config.tls.cert_pem.clone(), config.tls.key_pem.clone())
            .await
            .map_err(|error| RemoteServeStartError::TlsConfigLoad {
                detail: error.to_string(),
            })?,
    };

    let chain: Caip2 = config.decision_context.context.chain_id.parse().map_err(
        |e: stellar_agent_core::profile::caip2::Caip2ParseError| {
            RemoteServeStartError::UnknownChain {
                detail: e.to_string(),
            }
        },
    )?;
    let operator_credentials =
        OperatorApprovalCredentialStore::new(config.authority.credentials_path().to_path_buf());

    // Testnet derives its origin from the actual bound port, including ephemeral ports.
    // Signed listeners retain the public authority from the verified policy.
    let std_listener = std::net::TcpListener::bind(config.bind_addr).map_err(|e| {
        if config.one_shot.is_some() && e.kind() == std::io::ErrorKind::AddrInUse {
            RemoteServeStartError::Policy(WalletError::Approval(ApprovalFailure::ListenerBusy))
        } else {
            RemoteServeStartError::Bind { kind: e.kind() }
        }
    })?;
    std_listener
        .set_nonblocking(true)
        .map_err(|e| RemoteServeStartError::Bind { kind: e.kind() })?;
    let local_addr = std_listener
        .local_addr()
        .map_err(|e| RemoteServeStartError::Bind { kind: e.kind() })?;

    let expected_origin: std::sync::Arc<str> = signed
        .as_ref()
        .map_or_else(
            || remote_origin::expected_https_origin(&config.rp_id, local_addr.port()),
            |(origin, _)| origin.as_str().to_owned(),
        )
        .into();
    let public_origin = expected_origin.to_string();

    let state = RemoteServeState {
        listener_identity: signed.as_ref().map(|(_, identity)| identity.clone()),
        selected_nonce: config
            .one_shot
            .as_ref()
            .map(|one| one.entry.approval_nonce.clone().into()),
        rp_id: config.rp_id.clone().into(),
        expected_origin,
        authority: std::sync::Arc::new(config.authority),
        chain,
        ctx: std::sync::Arc::new(config.decision_context),
        operator_credentials: std::sync::Arc::new(operator_credentials),
        login_challenges: std::sync::Arc::new(StdMutex::new(LoginChallengeStore::new())),
        action_challenges: std::sync::Arc::new(StdMutex::new(ActionChallengeStore::new())),
        login_rate_limiter: std::sync::Arc::new(StdMutex::new(TokenBucket::default())),
        session: std::sync::Arc::new(StdMutex::new(None)),
        identity: std::sync::Arc::new(config.page_identity),
    };

    #[cfg(feature = "test-helpers")]
    let test_session = state.session.clone();
    let (router, completion) = if let Some((origin, identity)) = signed {
        let mode = match config.one_shot {
            Some(one) => SignedOriginMode::OneShot(Box::new(one)),
            None => SignedOriginMode::Inbox {
                context: state
                    .ctx
                    .decision
                    .clone()
                    .ok_or(WalletError::Approval(ApprovalFailure::PresenceUnavailable))?,
                page_identity: (*state.identity).clone(),
            },
        };
        let consent = signed_origin_consent(
            mode,
            identity,
            origin.as_str(),
            std::sync::Arc::new(state.clone()),
        )
        .map_err(|error| {
            RemoteServeStartError::Policy(WalletError::Approval(
                error
                    .presence_failure()
                    .unwrap_or(ApprovalFailure::PresenceUnavailable),
            ))
        })?;
        let (consent, completion) = consent.into_parts();
        (
            layer_router(routes::signed_router().with_state(state).merge(consent))
                .layer(
                    stellar_agent_loopback_http::signed_origin::SignedOriginLayer::new(
                        origin.as_str(),
                    ),
                )
                .layer(
                    stellar_agent_loopback_http::signed_origin::SignedHostLayer::new(
                        origin.as_str(),
                    ),
                )
                .layer(stellar_agent_loopback_http::security_headers::SecurityHeadersLayer::new()),
            completion,
        )
    } else {
        let decision = state
            .ctx
            .decision
            .clone()
            .ok_or(WalletError::Approval(ApprovalFailure::PresenceUnavailable))?;
        (
            build_router(state, decision, &config.rp_id, local_addr.port()),
            None,
        )
    };

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
        #[cfg(feature = "test-helpers")]
        test_session,
        local_addr,
        axum_handle,
        server_join,
        public_origin,
        completion,
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
pub(crate) fn build_router(
    state: RemoteServeState,
    context: std::sync::Arc<DecisionContext>,
    rp_id: &str,
    port: u16,
) -> Router {
    layer_router(routes::build_router(context).with_state(state))
        .layer(remote_origin::RemoteOriginAllowlistLayer::new(rp_id, port))
        .layer(stellar_agent_loopback_http::security_headers::SecurityHeadersLayer::new())
}

fn layer_router(router: Router) -> Router {
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

    router
        .layer(trace_layer)
        .layer(DefaultBodyLimit::max(BODY_LIMIT_BYTES))
        .layer(RequestBodyLimitLayer::new(BODY_LIMIT_BYTES))
}

#[cfg(test)]
mod mainnet_presence_tests {
    #![allow(clippy::unwrap_used, reason = "startup refusal assertions")]
    use super::*;

    #[tokio::test]
    #[serial_test::serial]
    async fn mainnet_remote_refuses_before_bind() {
        let fixture = stellar_agent_core::approval::mainnet_fixtures::MainnetConsentFixture::new(
            "remote-refusal",
        );
        let context = DecisionContext::new(
            stellar_agent_core::approval::ApprovalContext::from_profile(
                fixture.name(),
                fixture.profile(),
            ),
            fixture.store_path(),
            fixture.profile().attestation_key_id.clone(),
            stellar_agent_core::profile::owner_key::OwnerKeyContext::for_profile(
                fixture.name(),
                fixture.profile(),
            ),
            std::sync::Arc::new(StdMutex::new(fixture.audit_writer())),
            None,
        );
        let config = RemoteServeConfig::new(
            "0.0.0.0:0".parse().unwrap(),
            "remote.example",
            RemoteApprovalAuthority::for_profile(fixture.name()).unwrap(),
            context,
            ProvisionedTls {
                cert_pem: vec![],
                key_pem: vec![],
                fingerprint_sha256_hex: String::new(),
            },
        );
        assert!(matches!(
            start_remote_serve(config).await,
            Err(RemoteServeStartError::MainnetPresenceUnsupported)
        ));
    }
}
