//! Local browser consent over single-use, policy-bound WebAuthn challenges.
//!
//! A listener serves one mode: the persistent inbox, whose decision path
//! consumes a verified presence, or the ceremony of one command for one
//! pending entry, whose completion channel carries the verified presence to
//! that command.
//!
//! Pending-store locks cover snapshots and final decisions only. Challenge-table
//! locks cover insertion and removal only. Policy loads follow pending-store
//! acquisition and never hold a window-state lock across a browser wait. The
//! attestation key a page view needs loads while no pending-store lock is
//! held.

use crate::{
    PageIdentity, PresenceStartRefusal, ServeStartError,
    auth::{AuthState, OpaqueToken, SessionPurpose, SessionState, compute_csrf},
    decision::{Decision, DecisionContext, RequestIdentity, apply_decision},
    routes::{SESSION_ACTIVITY_NONCE, authorize_mutation, outcome_to_response, require_session},
    templates::{ConsentPageMode, render_mainnet_consent_page, render_not_found_page},
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::json;
use std::{
    collections::HashMap,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Instant,
};
use stellar_agent_core::{
    ApprovalFailure as Failure, WalletError,
    approval::{
        ApprovalContext, ApprovalKind, ApprovalSummaryView, ApproverIdentity,
        CurrentMainnetApprovalPolicy, DEFAULT_RETRY_ATTEMPTS, DEFAULT_RETRY_BACKOFF,
        MainnetApprovalAuthority, MainnetAssertionWire, PendingApproval, PendingApprovalStore,
        PendingApprovalView, PendingMainnetPresence, VerifiedMainnetPresence,
        issue_mainnet_presence, load_and_validate_entry, mainnet_consent_view_digest,
        mainnet_presence_origin, open_with_retry, process_uid_for_attestation,
        verify_mainnet_presence,
    },
};
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};

/// Trusted inputs for a single mainnet consent page.
pub struct MainnetPresenceConfig {
    /// The pending entry the command presents.
    pub entry: PendingApproval,
    /// Persisted profile and network context.
    pub context: ApprovalContext,
    /// The owner-signed credential authority.
    pub authority: MainnetApprovalAuthority,
    /// The pending store selected by the command.
    pub store_path: PathBuf,
    /// The identity displayed by the page.
    pub page_identity: PageIdentity,
}

type Completion = oneshot::Sender<Result<VerifiedMainnetPresence, WalletError>>;
struct Challenge {
    pending: PendingMainnetPresence,
    view_digest: String,
}

/// The listener a presence state serves, and where a verified presence goes.
enum Mode {
    /// The persistent inbox: a verified assertion goes to the decision path
    /// of this context, which records the consent.
    Inbox(Arc<DecisionContext>),
    /// The ceremony of one command for the entry `nonce`, which lasts until
    /// the entry expires at `expires_at` (unix ms). The first outcome, a
    /// verified presence or a refusal, goes to `completion`.
    OneShot {
        nonce: String,
        expires_at: u64,
        completion: Mutex<Option<Completion>>,
    },
}

impl Mode {
    /// The session purpose whose proof the page's requests carry.
    fn purpose(&self) -> SessionPurpose {
        match self {
            Self::Inbox(_) => SessionPurpose::Inbox,
            Self::OneShot { .. } => SessionPurpose::MainnetPresence,
        }
    }

    /// Whether this listener serves the entry `nonce`: every entry for the
    /// inbox, the one entry of its command for a ceremony.
    fn serves(&self, nonce: &str) -> bool {
        match self {
            Self::Inbox(_) => true,
            Self::OneShot {
                nonce: expected, ..
            } => expected == nonce,
        }
    }

    /// The page the ceremony's bootstrap lands on, or `None` for the inbox,
    /// whose bootstrap route lands on `/inbox`.
    fn destination(&self) -> Option<String> {
        match self {
            Self::Inbox(_) => None,
            Self::OneShot { nonce, .. } => Some(one_shot_destination(nonce)),
        }
    }

    fn page_mode(&self) -> ConsentPageMode {
        match self {
            Self::Inbox(_) => ConsentPageMode::Inbox,
            Self::OneShot { .. } => ConsentPageMode::OneShot,
        }
    }
}

/// The consent page a ceremony's bootstrap lands on: the detail page of its
/// one entry, `/approval/{nonce}`.
pub(crate) fn one_shot_destination(nonce: &str) -> String {
    format!("/approval/{nonce}")
}

pub(crate) struct PresenceState {
    auth: Arc<Mutex<AuthState>>,
    context: ApprovalContext,
    authority: MainnetApprovalAuthority,
    store_path: PathBuf,
    identity: Arc<PageIdentity>,
    origin: String,
    challenges: Mutex<HashMap<(String, String), Challenge>>,
    mode: Mode,
}

impl PresenceState {
    pub(crate) fn inbox(
        auth: Arc<Mutex<AuthState>>,
        ctx: Arc<DecisionContext>,
        identity: Arc<PageIdentity>,
        port: u16,
    ) -> Option<Arc<Self>> {
        Some(Arc::new(Self {
            auth,
            context: ctx.context.clone(),
            authority: ctx.mainnet_authority.clone()?,
            store_path: ctx.store_path.clone(),
            identity,
            origin: mainnet_presence_origin(port),
            challenges: Mutex::new(HashMap::new()),
            mode: Mode::Inbox(ctx),
        }))
    }

    /// Drops every outstanding challenge for the entry `nonce`, in every
    /// session.
    pub(crate) fn discard(&self, nonce: &str) {
        if let Ok(mut challenges) = self.challenges.lock() {
            challenges.retain(|(_, n), _| n != nonce);
        }
    }

    fn snapshot(
        &self,
        nonce: &str,
        advance: bool,
    ) -> Result<(PendingApprovalStore, CurrentMainnetApprovalPolicy), WalletError> {
        if !self.mode.serves(nonce) {
            return Err(failure(Failure::PresenceChanged));
        }
        let store = self.open_store()?;
        let current = if advance {
            self.authority.load_current()?
        } else {
            self.authority.load_current_compare_only()?
        };
        if current
            .policy()
            .mainnet()
            .is_none_or(|body| body.profile != self.context.profile_name)
            || !current.profile().chain_id.is_mainnet()
        {
            return Err(failure(Failure::PresencePolicyUnavailable));
        }
        Ok((store, current))
    }

    fn open_store(&self) -> Result<PendingApprovalStore, WalletError> {
        open_with_retry(
            &self.store_path,
            DEFAULT_RETRY_ATTEMPTS,
            DEFAULT_RETRY_BACKOFF,
        )
        .map_err(|_| failure(Failure::PresenceUnavailable))
    }

    /// The entry `nonce` while it still awaits a decision: unknown, expired,
    /// attested, rejected and spent entries refuse with their entry
    /// failures, which the consent routes answer as the inbox does.
    fn live_entry(
        &self,
        store: &PendingApprovalStore,
        nonce: &str,
    ) -> Result<PendingApproval, WalletError> {
        let uid =
            process_uid_for_attestation().map_err(|_| failure(Failure::PresenceUnavailable))?;
        let entry = load_and_validate_entry(store, nonce, &ApproverIdentity::OsUid(uid), &[])?;
        match entry.kind {
            ApprovalKind::Rejected { .. } => Err(failure(Failure::Rejected {
                detail: "this pending approval was rejected".to_owned(),
            })),
            ApprovalKind::Consumed { .. } => Err(failure(Failure::Consumed {
                detail: "this approval was already spent on a submission".to_owned(),
            })),
            _ => Ok(entry),
        }
    }

    /// The attestation key the reshow of an attested trustline clawback
    /// opt-in verifies its blob with, or `None` for any other entry.
    ///
    /// The entry's kind is read under a short store lock that is released
    /// before the key loads, since a keyring read can wait on an operator
    /// prompt.
    fn reshow_key(
        &self,
        nonce: &str,
    ) -> Result<Option<impl std::ops::Deref<Target = Vec<u8>>>, WalletError> {
        let attested_opt_in = self.open_store()?.get(nonce).is_some_and(|entry| {
            entry.attestation_blob_b64.is_some()
                && matches!(entry.kind, ApprovalKind::TrustlineClawbackOptIn { .. })
        });
        if !attested_opt_in {
            return Ok(None);
        }
        let current = self.authority.load_current_compare_only()?;
        stellar_agent_core::approval::load_attestation_key(
            &current.profile().attestation_key_id,
            &stellar_agent_core::profile::owner_key::OwnerKeyContext::for_profile(
                &self.context.profile_name,
                current.profile(),
            ),
        )
        .map(Some)
    }

    /// The detail page of an entry this listener offers no passkey consent
    /// for: the inbox renders it as its detail route does, with the inbox's
    /// decision buttons; a ceremony renders the same card with no action.
    fn settled_page(
        &self,
        view: &PendingApprovalView,
        session: &SessionState,
        attestation: Option<&str>,
    ) -> Response {
        let csrf = compute_csrf(&session.csrf_key, &view.approval_nonce);
        let html = match self.mode {
            Mode::Inbox(_) => crate::templates::render_detail_page(
                view,
                &self.context,
                &csrf,
                &compute_csrf(&session.csrf_key, SESSION_ACTIVITY_NONCE),
                attestation,
                &self.identity,
            ),
            Mode::OneShot { .. } => crate::templates::render_detail_page_with(
                view,
                &self.context,
                &csrf,
                "",
                attestation,
                &self.identity,
                false,
            ),
        };
        Html(html).into_response()
    }
}

/// A private listener whose completion carries verified presence to its owner.
pub struct MainnetPresenceHandle {
    bootstrap_url: String,
    completion: Option<oneshot::Receiver<Result<VerifiedMainnetPresence, WalletError>>>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    server_task: Option<JoinHandle<Result<(), std::io::Error>>>,
}

impl std::fmt::Debug for MainnetPresenceHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MainnetPresenceHandle")
            .finish_non_exhaustive()
    }
}

impl MainnetPresenceHandle {
    /// The private bootstrap destination, passed only to the private opener.
    #[must_use]
    pub fn bootstrap_url(&self) -> &str {
        &self.bootstrap_url
    }

    /// Waits for a verified assertion until the entry deadline.
    ///
    /// # Errors
    /// Returns the ceremony refusal, expiry, or an unavailable completion.
    pub async fn await_presence(
        &mut self,
        deadline: Instant,
    ) -> Result<VerifiedMainnetPresence, WalletError> {
        let receiver = self
            .completion
            .take()
            .ok_or_else(|| failure(Failure::PresenceConsumed))?;
        tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), receiver)
            .await
            .map_err(|_| failure(Failure::PresenceExpired))?
            .map_err(|_| failure(Failure::PresenceUnavailable))?
    }

    /// Stops the listener and waits for its task within five seconds.
    ///
    /// # Errors
    /// Returns presence unavailable if shutdown fails or exceeds its deadline.
    pub async fn shutdown(&mut self) -> Result<(), WalletError> {
        if let Some(sender) = self.shutdown_tx.take() {
            let _ = sender.send(());
        }
        if let Some(mut task) = self.server_task.take() {
            match tokio::time::timeout(crate::SHUTDOWN_DEADLINE, &mut task).await {
                Ok(Ok(Ok(()))) => {}
                _ => {
                    task.abort();
                    return Err(failure(Failure::PresenceUnavailable));
                }
            }
        }
        Ok(())
    }
}

impl Drop for MainnetPresenceHandle {
    fn drop(&mut self) {
        if let Some(sender) = self.shutdown_tx.take() {
            let _ = sender.send(());
        }
        if let Some(task) = self.server_task.take() {
            task.abort();
        }
    }
}

/// The start refusal of a snapshot or entry check: the policy, store and
/// changed-entry refusals keep their codes, and an entry that is not
/// pending as presented is a changed entry.
fn start_refusal(error: &WalletError) -> ServeStartError {
    let refusal = match error {
        WalletError::Approval(Failure::PresencePolicyUnavailable) => {
            PresenceStartRefusal::PolicyUnavailable
        }
        WalletError::Approval(
            Failure::PresenceChanged
            | Failure::NotFound { .. }
            | Failure::Expired { .. }
            | Failure::AlreadyAttested { .. }
            | Failure::Rejected { .. }
            | Failure::Consumed { .. }
            | Failure::UserMismatch { .. },
        ) => PresenceStartRefusal::Changed,
        _ => PresenceStartRefusal::Unavailable,
    };
    ServeStartError::Presence(refusal)
}

/// Starts a localhost-only presence listener without holding the pending store.
///
/// The stored entry must be the one `config` presents: its consent view
/// digest under the current policy must equal that of `config.entry`.
///
/// # Errors
/// [`ServeStartError::Presence`] with
/// [`PresenceStartRefusal::PolicyUnavailable`] when the current signed
/// policy cannot be verified for the profile,
/// [`PresenceStartRefusal::Changed`] when the stored entry is not the
/// presented one, and [`PresenceStartRefusal::Unavailable`] when the store
/// cannot be read; [`ServeStartError::Bind`] for an unavailable loopback
/// listener.
pub async fn start_mainnet_presence(
    config: MainnetPresenceConfig,
) -> Result<MainnetPresenceHandle, ServeStartError> {
    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(bind_error)?;
    let address = listener.local_addr().map_err(bind_error)?;
    let token = OpaqueToken::generate();
    let bootstrap_url = format!(
        "{}/bootstrap/{}",
        mainnet_presence_origin(address.port()),
        token.to_hex()
    );
    let (sender, completion) = oneshot::channel();
    let state = Arc::new(PresenceState {
        auth: Arc::new(Mutex::new(AuthState::new(
            token,
            SessionPurpose::MainnetPresence,
        ))),
        context: config.context,
        authority: config.authority,
        store_path: config.store_path,
        identity: Arc::new(config.page_identity),
        origin: mainnet_presence_origin(address.port()),
        challenges: Mutex::new(HashMap::new()),
        mode: Mode::OneShot {
            nonce: config.entry.approval_nonce.clone(),
            expires_at: config.entry.expires_at_unix_ms,
            completion: Mutex::new(Some(sender)),
        },
    });
    let (store, current) = state
        .snapshot(&config.entry.approval_nonce, true)
        .map_err(|error| start_refusal(&error))?;
    let entry = state
        .live_entry(&store, &config.entry.approval_nonce)
        .map_err(|error| start_refusal(&error))?;
    let binding = state.context.binding();
    let stored = mainnet_consent_view_digest(&entry, &binding, current.policy())
        .map_err(|error| start_refusal(&error))?;
    let presented = mainnet_consent_view_digest(&config.entry, &binding, current.policy())
        .map_err(|error| start_refusal(&error))?;
    if stored != presented {
        return Err(ServeStartError::Presence(PresenceStartRefusal::Changed));
    }
    drop(store);
    let router = routes(state.clone())
        .route(
            "/bootstrap/{token}",
            get(bootstrap).with_state(state.clone()),
        )
        .route(
            "/approval/{nonce}",
            get(detail_get).with_state(state.clone()),
        )
        .route(
            "/approval/{nonce}/approve",
            post(stale_approve).with_state(state.clone()),
        )
        .route(
            "/static/app-shared.js",
            get(app_shared_script).with_state(state.clone()),
        )
        .route("/static/app.js", get(app_script).with_state(state))
        .route(
            "/static/session-bootstrap.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "application/javascript")],
                    crate::web::SESSION_BOOTSTRAP_JS,
                )
            }),
        );
    let router = layers(router, address);
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await
    });
    Ok(MainnetPresenceHandle {
        bootstrap_url,
        completion: Some(completion),
        shutdown_tx: Some(shutdown_tx),
        server_task: Some(task),
    })
}

fn bind_error(source: std::io::Error) -> ServeStartError {
    ServeStartError::Bind {
        kind: source.kind(),
        source,
    }
}

pub(crate) fn layers(router: Router, address: SocketAddr) -> Router {
    router.layer(tower_http::trace::TraceLayer::new_for_http().make_span_with(|request: &axum::http::Request<axum::body::Body>| {
        tracing::info_span!("mainnet_presence_request", method = %request.method(), path = stellar_agent_loopback_http::request_trace::route_label(request))
    }))
        .layer(axum::extract::DefaultBodyLimit::max(crate::BODY_LIMIT_BYTES))
        .layer(tower_http::limit::RequestBodyLimitLayer::new(crate::BODY_LIMIT_BYTES))
        .layer(crate::OriginHeaderAllowlistLayer::new(address))
        .layer(crate::SecurityHeadersLayer::new())
        .layer(crate::HostHeaderAllowlistLayer::new(address))
}

pub(crate) fn routes(state: Arc<PresenceState>) -> Router {
    Router::new()
        .route("/approval/{nonce}/challenge", post(challenge))
        .route("/approval/{nonce}/assertion", post(assertion))
        .route("/approval/{nonce}/cancel", post(cancel))
        .route("/static/mainnet-presence.js", get(script))
        .with_state(state)
}

fn failure(value: Failure) -> WalletError {
    WalletError::Approval(value)
}
fn now_ms() -> Result<u64, WalletError> {
    stellar_agent_core::timefmt::now_unix_ms().map_err(|_| failure(Failure::PresenceUnavailable))
}

/// The HTTP status of a mainnet presence refusal.
///
/// 403 for a refusal no retry of the same request can overcome, 409 for a
/// challenge or entry that changed or ended, 503 for an authority or store
/// that cannot be read. A failure that is not a presence refusal is a
/// server error.
#[must_use]
pub fn refusal_status(failure: &Failure) -> StatusCode {
    match failure {
        Failure::PresenceRequired
        | Failure::PresenceInvalid
        | Failure::PresenceBrowserRequired
        | Failure::PresenceCanceled
        | Failure::MainnetRemoteUnsupported => StatusCode::FORBIDDEN,
        Failure::PresenceExpired | Failure::PresenceConsumed | Failure::PresenceChanged => {
            StatusCode::CONFLICT
        }
        Failure::PresencePolicyUnavailable | Failure::PresenceUnavailable => {
            StatusCode::SERVICE_UNAVAILABLE
        }
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

/// The HTTP status of the presence refusal whose stable code is `code`, as
/// [`refusal_status`] answers for the failure carrying that code.
#[must_use]
pub fn refusal_status_of_code(code: &str) -> StatusCode {
    crate::decision::presence_refusal_failure(code)
        .map_or(StatusCode::INTERNAL_SERVER_ERROR, |failure| {
            refusal_status(&failure)
        })
}

/// The response to a refused presence request: a presence refusal in its one
/// body shape and status, and an entry outcome as the inbox decision routes
/// answer it.
fn error_response(error: &WalletError) -> Response {
    outcome_to_response(
        crate::decision::presence_refusal(error)
            .unwrap_or_else(|| crate::decision::entry_outcome(error)),
    )
}

async fn bootstrap(State(state): State<Arc<PresenceState>>, Path(token): Path<String>) -> Response {
    let Some(destination) = state.mode.destination() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Ok(mut auth) = state.auth.lock() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let now = auth.now();
    let Some(session) = auth.exchange_bootstrap(&token, now) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let cookie = auth.set_cookie_value(&session);
    drop(auth);
    let html = crate::templates::render_session_bootstrap_destination(
        &session.session_proof.to_hex(),
        state.mode.purpose(),
        &destination,
    );
    ([(header::SET_COOKIE, cookie)], Html(html)).into_response()
}

async fn detail_get(
    State(state): State<Arc<PresenceState>>,
    headers: HeaderMap,
    Path(nonce): Path<String>,
) -> Response {
    match require_session(&state.auth, &headers) {
        Ok(session) => detail(&state, &session, &nonce),
        Err(response) => response,
    }
}

/// `GET /approval/{nonce}` of a mainnet listener.
///
/// A live entry renders the consent page with its view digest. An entry
/// this listener offers no passkey consent for keeps the inbox detail
/// route's outcome: an unknown nonce is the not-found page with 404, and an
/// expired, rejected, spent, inconsistent or recorded entry is its detail
/// card. A recorded consent's attestation is shown only after its receipt
/// verifies against the current signed policy.
pub(crate) fn detail(state: &PresenceState, session: &SessionState, nonce: &str) -> Response {
    match render_detail(state, session, nonce) {
        Ok(response) => response,
        Err(error) => error_response(&error),
    }
}

fn render_detail(
    state: &PresenceState,
    session: &SessionState,
    nonce: &str,
) -> Result<Response, WalletError> {
    if !state.mode.serves(nonce) {
        return Err(failure(Failure::PresenceChanged));
    }
    let key = state.reshow_key(nonce)?;
    let (store, current) = state.snapshot(nonce, false)?;
    let Some(view) = store
        .snapshot(now_ms()?)
        .into_iter()
        .find(|view| view.approval_nonce == nonce)
    else {
        drop(store);
        return Ok((
            StatusCode::NOT_FOUND,
            Html(render_not_found_page(nonce, &state.identity)),
        )
            .into_response());
    };
    if view.attested {
        let key = key.as_ref().map(|key| key.as_slice());
        let blob = match verified_blob(state, &store, &current, nonce, key) {
            Ok(blob) => Some(blob),
            Err(error) if crate::decision::presence_refusal(&error).is_some() => {
                return Err(error);
            }
            Err(_) => None,
        };
        drop(store);
        return Ok(state.settled_page(&view, session, blob.as_deref()));
    }
    if view.expired
        || matches!(
            view.summary,
            ApprovalSummaryView::Rejected { .. }
                | ApprovalSummaryView::Consumed { .. }
                | ApprovalSummaryView::Inconsistent { .. }
        )
    {
        drop(store);
        return Ok(state.settled_page(&view, session, None));
    }
    let consent = state.live_entry(&store, nonce).and_then(|entry| {
        let digest =
            mainnet_consent_view_digest(&entry, &state.context.binding(), current.policy())?;
        Ok((entry, digest))
    });
    drop(store);
    let (entry, digest) = match consent {
        Ok(consent) => consent,
        Err(error) if crate::decision::presence_refusal(&error).is_some() => return Err(error),
        Err(_) => return Ok(state.settled_page(&view, session, None)),
    };
    let data = json!({
        "nonce": nonce,
        "csrf": compute_csrf(&session.csrf_key, nonce),
        "consent_view_digest": hex::encode(digest),
        "storageKey": state.mode.purpose().proof_storage_key(),
        "mode": match state.mode {
            Mode::Inbox(_) => "inbox",
            Mode::OneShot { .. } => "one_shot",
        },
    });
    let intent = match &entry.kind {
        ApprovalKind::X402Payment { intent_digest, .. } => Some(hex::encode(intent_digest)),
        _ => None,
    };
    Ok(Html(render_mainnet_consent_page(
        &view,
        &state.context,
        &data,
        intent.as_deref(),
        state.mode.page_mode(),
        &state.identity,
    ))
    .into_response())
}

/// The stored attestation of `nonce`, after its receipt verifies against
/// the current signed policy. `key` is the attestation key
/// [`PresenceState::reshow_key`] loaded for a trustline clawback opt-in.
fn verified_blob(
    state: &PresenceState,
    store: &PendingApprovalStore,
    current: &CurrentMainnetApprovalPolicy,
    nonce: &str,
    key: Option<&[u8]>,
) -> Result<String, WalletError> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use stellar_agent_core::approval::witness::{
        ApprovalExpectation, ApprovedKind, verify_approval,
    };
    let entry = store
        .get(nonce)
        .ok_or_else(|| failure(Failure::PresenceChanged))?;
    if entry.process_uid
        != process_uid_for_attestation().map_err(|_| failure(Failure::PresenceUnavailable))?
    {
        return Err(failure(Failure::PresenceInvalid));
    }
    let encoded = entry
        .attestation_blob_b64
        .as_ref()
        .ok_or_else(|| failure(Failure::PresenceInvalid))?;
    let blob: [u8; 32] = URL_SAFE_NO_PAD
        .decode(encoded)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| failure(Failure::PresenceInvalid))?;
    let kind = match &entry.kind {
        ApprovalKind::PaymentSimulated { .. } => ApprovedKind::Payment,
        ApprovalKind::ClaimSimulated { .. } => ApprovedKind::Claim,
        ApprovalKind::TrustlineSimulated { .. } => ApprovedKind::Trustline,
        ApprovalKind::X402Payment { .. } => ApprovedKind::X402Payment,
        ApprovalKind::TrustlineClawbackOptIn { code, issuer, .. } => {
            // The entry became an attested opt-in after the key was read:
            // the page is stale.
            let key: &[u8; 32] = key
                .ok_or_else(|| failure(Failure::PresenceChanged))?
                .try_into()
                .map_err(|_| failure(Failure::PresenceInvalid))?;
            if !store.verify_mainnet_trustline_clawback_opt_in(
                key,
                &state.context.binding(),
                code,
                issuer,
                current.policy(),
                now_ms()?,
            )? {
                return Err(failure(Failure::PresenceInvalid));
            }
            return Ok(encoded.clone());
        }
        _ => return Err(failure(Failure::PresenceInvalid)),
    };
    let expected = ApprovalExpectation {
        kind,
        subject: stellar_agent_core::approval::mainnet_consent_subject(
            entry,
            &state.context.binding(),
        )?,
    };
    verify_approval(
        store,
        current.profile(),
        &state.context.profile_name,
        nonce,
        &blob,
        &expected,
        current.policy(),
        now_ms()?,
    )?;
    Ok(encoded.clone())
}

/// The rendered consent digest returned on challenge issue.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PresenceChallengeRequest {
    consent_view_digest: String,
}
/// The bounded raw WebAuthn response and its challenge identifier.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PresenceAssertionRequest {
    request_id: String,
    credential_id_b64url: String,
    authenticator_data_b64url: String,
    client_data_json_b64url: String,
    signature_der_b64url: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PresenceCancelRequest {
    reason: PresenceCancelReason,
}
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum PresenceCancelReason {
    OperatorCancel,
    AuthenticatorCanceled,
    BrowserUnavailable,
}

async fn challenge(
    State(state): State<Arc<PresenceState>>,
    headers: HeaderMap,
    Path(nonce): Path<String>,
    body: Bytes,
) -> Response {
    if let Err(response) = authorize_mutation(&state.auth, &headers, &nonce) {
        return response;
    }
    let result = (|| {
        let session = require_session(&state.auth, &headers)
            .map_err(|_| failure(Failure::PresenceConsumed))?;
        let request: PresenceChallengeRequest =
            serde_json::from_slice(&body).map_err(|_| failure(Failure::PresenceChanged))?;
        let (store, current) = state.snapshot(&nonce, true)?;
        let entry = state.live_entry(&store, &nonce)?;
        let view_digest = hex::encode(mainnet_consent_view_digest(
            &entry,
            &state.context.binding(),
            current.policy(),
        )?);
        if request.consent_view_digest != view_digest {
            return Err(failure(Failure::PresenceChanged));
        }
        let now = now_ms()?;
        let instant = Instant::now();
        let pending = issue_mainnet_presence(
            &entry,
            &state.context.binding(),
            current.policy(),
            &state.origin,
            now,
            instant,
        )?;
        drop(store);
        let options = pending.options();
        let mut challenges = state
            .challenges
            .lock()
            .map_err(|_| failure(Failure::PresenceUnavailable))?;
        challenges.retain(|_, challenge| challenge.pending.is_live(now, instant));
        let key = (session.session_id.to_hex(), nonce);
        if challenges.len() >= 128 && !challenges.contains_key(&key) {
            return Err(failure(Failure::PresenceUnavailable));
        }
        challenges.insert(
            key,
            Challenge {
                pending,
                view_digest,
            },
        );
        Ok(options)
    })();
    match result {
        Ok(options) => Json(options).into_response(),
        Err(error) => error_response(&error),
    }
}

async fn assertion(
    State(state): State<Arc<PresenceState>>,
    headers: HeaderMap,
    Path(nonce): Path<String>,
    body: Bytes,
) -> Response {
    if let Err(response) = authorize_mutation(&state.auth, &headers, &nonce) {
        return response;
    }
    let result = (|| {
        let session = require_session(&state.auth, &headers)
            .map_err(|_| failure(Failure::PresenceConsumed))?;
        let request: PresenceAssertionRequest =
            serde_json::from_slice(&body).map_err(|_| failure(Failure::PresenceInvalid))?;
        let challenge = {
            let mut challenges = state
                .challenges
                .lock()
                .map_err(|_| failure(Failure::PresenceUnavailable))?;
            let key = (session.session_id.to_hex(), nonce.clone());
            let now = now_ms()?;
            let instant = Instant::now();
            challenges.retain(|candidate, challenge| {
                candidate == &key || challenge.pending.is_live(now, instant)
            });
            if challenges
                .get(&key)
                .is_none_or(|challenge| challenge.pending.request_id() != request.request_id)
            {
                return Err(failure(Failure::PresenceConsumed));
            }
            challenges
                .remove(&key)
                .ok_or_else(|| failure(Failure::PresenceConsumed))?
        };
        let assertion = MainnetAssertionWire {
            credential_id_b64url: request.credential_id_b64url,
            authenticator_data_b64url: request.authenticator_data_b64url,
            client_data_json_b64url: request.client_data_json_b64url,
            signature_der_b64url: request.signature_der_b64url,
        }
        .decode()?;
        let presence =
            verify_mainnet_presence(challenge.pending, assertion, now_ms()?, Instant::now())?;
        let (store, current) = state.snapshot(&nonce, false)?;
        let entry = state.live_entry(&store, &nonce)?;
        if hex::encode(mainnet_consent_view_digest(
            &entry,
            &state.context.binding(),
            current.policy(),
        )?) != challenge.view_digest
        {
            return Err(failure(Failure::PresenceChanged));
        }
        drop(store);
        match &state.mode {
            Mode::Inbox(context) => Ok(outcome_to_response(apply_decision(
                context,
                Decision::Approve { nonce },
                RequestIdentity::Mainnet(presence),
            ))),
            Mode::OneShot { completion, .. } => {
                let request_id = presence.request_id().to_owned();
                completion
                    .lock()
                    .map_err(|_| failure(Failure::PresenceUnavailable))?
                    .take()
                    .ok_or_else(|| failure(Failure::PresenceConsumed))?
                    .send(Ok(presence))
                    .map_err(|_| failure(Failure::PresenceUnavailable))?;
                Ok(
                    Json(json!({"status": "presence_verified", "request_id": request_id}))
                        .into_response(),
                )
            }
        }
    })();
    match result {
        Ok(response) => response,
        Err(error) => error_response(&error),
    }
}

/// `POST /approval/{nonce}/cancel`: drops this session's outstanding
/// challenge for the entry.
///
/// A ceremony completes its command with the refusal of the reason, or
/// with an expired presence once the entry's deadline has passed; the inbox
/// leaves the pending entry unchanged. Cancellation is never evidence of
/// presence.
async fn cancel(
    State(state): State<Arc<PresenceState>>,
    headers: HeaderMap,
    Path(nonce): Path<String>,
    body: Bytes,
) -> Response {
    if let Err(response) = authorize_mutation(&state.auth, &headers, &nonce) {
        return response;
    }
    let result = (|| {
        if !state.mode.serves(&nonce) {
            return Err(failure(Failure::PresenceChanged));
        }
        let request: PresenceCancelRequest =
            serde_json::from_slice(&body).map_err(|_| failure(Failure::PresenceInvalid))?;
        let session = require_session(&state.auth, &headers)
            .map_err(|_| failure(Failure::PresenceConsumed))?;
        let now = now_ms()?;
        let challenge_expired = state
            .challenges
            .lock()
            .map_err(|_| failure(Failure::PresenceUnavailable))?
            .remove(&(session.session_id.to_hex(), nonce.clone()))
            .is_some_and(|challenge| !challenge.pending.is_live(now, Instant::now()));
        let (reason, status) = match request.reason {
            PresenceCancelReason::BrowserUnavailable => {
                (Failure::PresenceBrowserRequired, "browser_unavailable")
            }
            PresenceCancelReason::OperatorCancel | PresenceCancelReason::AuthenticatorCanceled => {
                (Failure::PresenceCanceled, "canceled")
            }
        };
        let Mode::OneShot {
            expires_at,
            completion,
            ..
        } = &state.mode
        else {
            return Ok(Json(json!({"status": status})).into_response());
        };
        let expired = challenge_expired || now >= *expires_at;
        if let Some(sender) = completion
            .lock()
            .map_err(|_| failure(Failure::PresenceUnavailable))?
            .take()
        {
            let completed = if expired {
                Failure::PresenceExpired
            } else {
                reason
            };
            let _ = sender.send(Err(failure(completed)));
        }
        if expired {
            return Err(failure(Failure::PresenceExpired));
        }
        Ok(Json(json!({"status": status})).into_response())
    })();
    match result {
        Ok(response) => response,
        Err(error) => error_response(&error),
    }
}

async fn stale_approve(
    State(state): State<Arc<PresenceState>>,
    headers: HeaderMap,
    Path(nonce): Path<String>,
) -> Response {
    if let Err(response) = authorize_mutation(&state.auth, &headers, &nonce) {
        return response;
    }
    error_response(&failure(Failure::PresenceRequired))
}

fn session_script(state: &PresenceState, headers: &HeaderMap, source: &'static [u8]) -> Response {
    if let Err(response) = require_session(&state.auth, headers) {
        return response;
    }
    (
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        source,
    )
        .into_response()
}

async fn script(State(state): State<Arc<PresenceState>>, headers: HeaderMap) -> Response {
    session_script(&state, &headers, include_bytes!("web/mainnet-presence.js"))
}

async fn app_shared_script(
    State(state): State<Arc<PresenceState>>,
    headers: HeaderMap,
) -> Response {
    session_script(&state, &headers, crate::web::APP_SHARED_JS)
}

async fn app_script(State(state): State<Arc<PresenceState>>, headers: HeaderMap) -> Response {
    session_script(&state, &headers, crate::web::APP_JS)
}

#[cfg(any(test, feature = "test-helpers"))]
pub mod test_support;
#[cfg(test)]
mod tests;
