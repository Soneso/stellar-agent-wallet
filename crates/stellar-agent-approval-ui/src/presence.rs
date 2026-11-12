//! Browser consent over single-use, policy-bound WebAuthn challenges.
//!
//! A listener serves one mode: the persistent inbox, whose decision path
//! consumes a verified presence, or the ceremony of one command for one
//! pending entry, whose completion channel carries the verified presence to
//! that command.
//!
//! A listener serves at one site. A loopback listener runs at
//! `http://localhost:<port>` under a policy without an approval origin.
//! Under a policy that names one, every loopback challenge and listener
//! startup refuses with `approval.origin_signed_remote`. A
//! signed-origin listener ([`signed_origin_consent`]) runs at the signed
//! HTTPS origin with the [`ListenerIdentity`] its caller captures.
//! Each challenge loads the current policy and issues under that identity.
//! A policy re-sign after capture refuses with
//! `approval.listener_policy_stale`. Its inbox consent is attributed to the
//! remote surface, and its rejection needs a fresh assertion as a consent
//! does. A [`ConsentSessionGate`] checks the session of each request; the
//! loopback gate is the listener's own session state.
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
        ApprovalContext, ApprovalKind, ApprovalSummaryView, ApproverIdentity, ClassicIntent,
        CurrentMainnetApprovalPolicy, DEFAULT_RETRY_ATTEMPTS, DEFAULT_RETRY_BACKOFF, IntentView,
        ListenerIdentity, MainnetApprovalAuthority, MainnetAssertionWire, PendingApproval,
        PendingApprovalStore, PendingApprovalView, PendingMainnetPresence, PresenceListener,
        VerifiedMainnetPresence, approval_view_digest, issue_mainnet_intent_presence,
        issue_mainnet_presence, load_and_validate_entry, mainnet_consent_view_digest,
        mainnet_intent_consent_view_digest, mainnet_presence_origin, open_with_retry,
        process_uid_for_attestation, verify_mainnet_presence,
    },
};
use stellar_agent_loopback_http::{LoopbackPair, PairBindError, PairServer};
use tokio::sync::oneshot;

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

/// The session check of a consent listener.
///
/// The consent routes call it at their auth boundary, before anything else.
/// A state-changing route calls [`Self::authorize_mutation`] and then reads
/// the session with [`Self::session`]. The detail page and the script read
/// the session only. The loopback listeners implement it over their own
/// session state, whose checks and responses this trait does not change.
pub trait ConsentSessionGate: Send + Sync + 'static {
    /// The session a request carries.
    type Session;

    /// The live session `headers` carry.
    ///
    /// # Errors
    ///
    /// The ready response that refuses a request without a live session.
    #[allow(
        clippy::result_large_err,
        reason = "the Err variant is the ready-to-return axum Response for the auth-boundary rejection"
    )]
    fn session(&self, headers: &HeaderMap) -> Result<Self::Session, Response>;

    /// Authorizes a state-changing request whose CSRF value names
    /// `csrf_nonce`.
    ///
    /// # Errors
    ///
    /// The ready response that refuses the request.
    #[allow(
        clippy::result_large_err,
        reason = "the Err variant is the ready-to-return axum Response for the auth-boundary rejection"
    )]
    fn authorize_mutation(&self, headers: &HeaderMap, csrf_nonce: &str) -> Result<(), Response>;

    /// The key of `session`, which scopes its outstanding challenges.
    fn session_key(&self, session: &Self::Session) -> String;

    /// The CSRF value of `nonce` in `session`, which the page sends back in
    /// `X-Stellar-Approval-CSRF`.
    fn csrf(&self, session: &Self::Session, nonce: &str) -> String;

    /// Checks verified action facts before approval or rejection proceeds.
    ///
    /// # Errors
    /// Returns a refusal when the listener cannot accept the verified assertion.
    fn verified(&self, _presence: &VerifiedMainnetPresence) -> Result<(), WalletError> {
        Ok(())
    }
}

/// The loopback gate: the cookie, CSRF and session proof checks of the
/// listener's own session state.
impl ConsentSessionGate for Mutex<AuthState> {
    type Session = SessionState;

    fn session(&self, headers: &HeaderMap) -> Result<SessionState, Response> {
        require_session(self, headers)
    }

    fn authorize_mutation(&self, headers: &HeaderMap, csrf_nonce: &str) -> Result<(), Response> {
        authorize_mutation(self, headers, csrf_nonce)
    }

    fn session_key(&self, session: &SessionState) -> String {
        session.session_id.to_hex()
    }

    fn csrf(&self, session: &SessionState, nonce: &str) -> String {
        compute_csrf(&session.csrf_key, nonce)
    }
}

/// Where a presence listener serves, which selects how its challenges issue.
enum Site {
    /// `http://localhost:<port>`, under a policy without an approval origin.
    Loopback,
    /// The signed HTTPS origin, under the identity its listener captured.
    Signed(ListenerIdentity),
}

pub(crate) struct PresenceState<G: ConsentSessionGate = Mutex<AuthState>> {
    auth: Arc<G>,
    context: ApprovalContext,
    authority: MainnetApprovalAuthority,
    store_path: PathBuf,
    identity: Arc<PageIdentity>,
    origin: String,
    site: Site,
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
            site: Site::Loopback,
            challenges: Mutex::new(HashMap::new()),
            mode: Mode::Inbox(ctx),
        }))
    }
}

impl<G: ConsentSessionGate> PresenceState<G> {
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
        if matches!(self.site, Site::Loopback)
            && current
                .policy()
                .mainnet()
                .is_some_and(|body| body.approval_origin.is_some())
        {
            return Err(failure(Failure::OriginSignedRemote));
        }
        if advance
            && let Site::Signed(listener) = &self.site
            && (listener.policy_digest() != current.policy().digest()
                || current
                    .policy()
                    .mainnet()
                    .and_then(|body| body.approval_cert_spki_sha256)
                    != Some(listener.cert_spki_sha256()))
        {
            return Err(failure(Failure::ListenerPolicyStale));
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
    /// for. The loopback inbox renders it with the inbox's decision buttons.
    /// A ceremony and a signed-origin listener render the same card without
    /// actions because a signed-origin rejection needs an assertion.
    fn settled_page(
        &self,
        view: &PendingApprovalView,
        session: &G::Session,
        attestation: Option<&str>,
    ) -> Response {
        let csrf = self.auth.csrf(session, &view.approval_nonce);
        let html = match (&self.mode, &self.site) {
            // A mainnet approve takes a passkey consent, which this page does
            // not offer, so it carries no view digest.
            (Mode::Inbox(_), Site::Loopback) => crate::templates::render_detail_page(
                view,
                &self.context,
                &csrf,
                &self.auth.csrf(session, SESSION_ACTIVITY_NONCE),
                attestation,
                None,
                &self.identity,
            ),
            _ => crate::templates::render_detail_page_with(
                view,
                &self.context,
                &csrf,
                "",
                attestation,
                None,
                &self.identity,
                false,
            ),
        };
        Html(html).into_response()
    }
}

/// A private listener whose completion carries verified presence to its owner.
///
/// The listener holds `127.0.0.1` and `[::1]` on one port for as long as the
/// handle lives; shutting it down or dropping it closes both.
///
/// # Drop behaviour
///
/// Dropping the handle without calling [`MainnetPresenceHandle::shutdown`]
/// drops its [`PairServer`], whose drop aborts both listener tasks at once:
/// both addresses stop accepting without waiting for open connections.
/// Call `shutdown` to let open connections finish and to wait for both
/// listeners.
pub struct MainnetPresenceHandle {
    bootstrap_url: String,
    completion: Option<oneshot::Receiver<Result<VerifiedMainnetPresence, WalletError>>>,
    server: Option<PairServer>,
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
        await_completion(receiver, deadline).await
    }

    /// Stops both loopback listeners and waits for them within five seconds.
    ///
    /// # Errors
    /// Returns presence unavailable if shutdown fails or exceeds its deadline;
    /// both listeners are closed either way.
    pub async fn shutdown(&mut self) -> Result<(), WalletError> {
        if let Some(server) = self.server.take() {
            server.shutdown();
            match tokio::time::timeout(crate::SHUTDOWN_DEADLINE, server.join()).await {
                Ok(Ok(())) => {}
                _ => return Err(failure(Failure::PresenceUnavailable)),
            }
        }
        Ok(())
    }
}

/// Waits on a ceremony's completion until `deadline`.
async fn await_completion(
    receiver: oneshot::Receiver<Result<VerifiedMainnetPresence, WalletError>>,
    deadline: Instant,
) -> Result<VerifiedMainnetPresence, WalletError> {
    tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), receiver)
        .await
        .map_err(|_| failure(Failure::PresenceExpired))?
        .map_err(|_| failure(Failure::PresenceUnavailable))?
}

/// The start refusal of a snapshot or entry check: the policy, store,
/// signed-origin and changed-entry refusals keep their codes. An entry
/// that is not pending as presented is a changed entry.
fn start_refusal(error: &WalletError) -> ServeStartError {
    let refusal = match error {
        WalletError::Approval(Failure::PresencePolicyUnavailable) => {
            PresenceStartRefusal::PolicyUnavailable
        }
        WalletError::Approval(Failure::OriginSignedRemote) => {
            PresenceStartRefusal::OriginSignedRemote
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
/// The listener binds `127.0.0.1` and `[::1]` on one OS-assigned port before
/// it creates the bootstrap token, because the page runs at
/// `http://localhost:<port>` and a browser may reach either address. Both
/// serve the same session and close together.
///
/// The stored entry must be the one `config` presents: its consent view
/// digest under the current policy must equal that of `config.entry`.
///
/// # Errors
/// [`ServeStartError::Presence`] with
/// [`PresenceStartRefusal::PolicyUnavailable`] when the current signed
/// policy cannot be verified for the profile.
/// [`PresenceStartRefusal::OriginSignedRemote`] when it names an approval
/// origin. [`PresenceStartRefusal::Changed`] when the stored entry is not the
/// presented one. [`PresenceStartRefusal::Unavailable`] when the store
/// cannot be read. [`ServeStartError::LoopbackPair`] when both loopback
/// addresses cannot be held on one port.
pub async fn start_mainnet_presence(
    config: MainnetPresenceConfig,
) -> Result<MainnetPresenceHandle, ServeStartError> {
    start_mainnet_presence_with(config, || LoopbackPair::bind(0)).await
}

/// [`start_mainnet_presence`] with the loopback pair from `bind_pair`, which
/// runs before anything else, so no token exists unless the pair does.
async fn start_mainnet_presence_with<B, F>(
    config: MainnetPresenceConfig,
    bind_pair: B,
) -> Result<MainnetPresenceHandle, ServeStartError>
where
    B: FnOnce() -> F,
    F: Future<Output = Result<LoopbackPair, PairBindError>>,
{
    let pair = bind_pair().await.map_err(ServeStartError::LoopbackPair)?;
    let address = pair.v4_addr();
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
        site: Site::Loopback,
        challenges: Mutex::new(HashMap::new()),
        mode: Mode::OneShot {
            nonce: config.entry.approval_nonce.clone(),
            expires_at: config.entry.expires_at_unix_ms,
            completion: Mutex::new(Some(sender)),
        },
    });
    check_presented(&state, &config.entry)?;
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
    Ok(MainnetPresenceHandle {
        bootstrap_url,
        completion: Some(completion),
        server: Some(pair.serve(router)),
    })
}

/// Checks at a ceremony's start that the stored entry is `presented`: live,
/// and with the consent view digest of `presented` under the current policy.
fn check_presented<G: ConsentSessionGate>(
    state: &PresenceState<G>,
    presented: &PendingApproval,
) -> Result<(), ServeStartError> {
    let (store, current) = state
        .snapshot(&presented.approval_nonce, true)
        .map_err(|error| start_refusal(&error))?;
    let entry = state
        .live_entry(&store, &presented.approval_nonce)
        .map_err(|error| start_refusal(&error))?;
    let binding = state.context.binding();
    let stored = mainnet_consent_view_digest(&entry, &binding, current.policy())
        .map_err(|error| start_refusal(&error))?;
    let presented = mainnet_consent_view_digest(presented, &binding, current.policy())
        .map_err(|error| start_refusal(&error))?;
    if stored != presented {
        return Err(ServeStartError::Presence(PresenceStartRefusal::Changed));
    }
    drop(store);
    Ok(())
}

/// What a signed-origin consent listener does with a verified assertion.
#[non_exhaustive]
pub enum SignedOriginMode {
    /// The persistent inbox: a verified assertion approves through the
    /// decision path of `context`, attributed to the remote surface, and a
    /// verified assertion posted to the reject route rejects.
    Inbox {
        /// The decision context of the served profile, with its mainnet
        /// authority.
        context: Arc<DecisionContext>,
        /// The identity the pages display.
        page_identity: PageIdentity,
    },
    /// The ceremony of one command for `config.entry`: the first verified
    /// presence or refusal goes to the returned [`PresenceCompletion`].
    OneShot(Box<MainnetPresenceConfig>),
}

/// The consent routes of a signed-origin listener and, for a ceremony, the
/// completion its command awaits.
pub struct SignedOriginConsent {
    router: Router,
    completion: Option<PresenceCompletion>,
}

impl std::fmt::Debug for SignedOriginConsent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedOriginConsent")
            .field("one_shot", &self.completion.is_some())
            .finish_non_exhaustive()
    }
}

impl SignedOriginConsent {
    /// The routes, and the completion of a ceremony; `None` for the inbox.
    pub fn into_parts(self) -> (Router, Option<PresenceCompletion>) {
        (self.router, self.completion)
    }
}

/// Where a signed-origin ceremony's verified presence arrives.
pub struct PresenceCompletion(oneshot::Receiver<Result<VerifiedMainnetPresence, WalletError>>);

impl std::fmt::Debug for PresenceCompletion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PresenceCompletion").finish_non_exhaustive()
    }
}

impl PresenceCompletion {
    /// Waits for a verified assertion until the entry deadline.
    ///
    /// # Errors
    /// Returns the ceremony refusal, expiry, or an unavailable completion.
    pub async fn await_presence(
        self,
        deadline: Instant,
    ) -> Result<VerifiedMainnetPresence, WalletError> {
        await_completion(self.0, deadline).await
    }
}

/// The consent routes at the signed `origin` under `listener`, the identity
/// captured from the policy that signs `origin`. The `gate` checks each request's session.
///
/// The router serves `GET /approval/{nonce}`, the challenge, assertion and
/// cancel actions, and `GET /static/mainnet-presence.js`. The inbox also
/// serves `POST /approval/{nonce}/reject`, which rejects only with a fresh
/// assertion from an approval credential of the current policy. The pages
/// also load `/static/app-shared.js` and `/static/app.js`, which the caller
/// serves. No `Host`, `Origin`, security header or body limit layer is
/// installed: the caller installs the signed-origin layers for `origin`.
///
/// Each challenge loads the current policy and issues under `listener`, so a
/// policy signed again since the capture refuses with
/// `approval.listener_policy_stale` and issues nothing. A ceremony first
/// checks that the stored entry is the one `config` presents.
///
/// # Errors
/// [`ServeStartError::Presence`] with
/// [`PresenceStartRefusal::PolicyUnavailable`] for an inbox context without
/// a mainnet authority. A ceremony also refuses with
/// [`PresenceStartRefusal::PolicyUnavailable`] when the current signed policy
/// cannot be verified for the profile. [`PresenceStartRefusal::Changed`]
/// applies when the stored entry is not the presented one, and
/// [`PresenceStartRefusal::Unavailable`] when the store cannot be read.
pub fn signed_origin_consent<G: ConsentSessionGate>(
    mode: SignedOriginMode,
    listener: ListenerIdentity,
    origin: &str,
    gate: Arc<G>,
) -> Result<SignedOriginConsent, ServeStartError> {
    match mode {
        SignedOriginMode::Inbox {
            context,
            page_identity,
        } => {
            let authority = context
                .mainnet_authority
                .clone()
                .ok_or(ServeStartError::Presence(
                    PresenceStartRefusal::PolicyUnavailable,
                ))?;
            let state = Arc::new(PresenceState {
                auth: gate,
                context: context.context.clone(),
                authority,
                store_path: context.store_path.clone(),
                identity: Arc::new(page_identity),
                origin: origin.to_owned(),
                site: Site::Signed(listener),
                challenges: Mutex::new(HashMap::new()),
                mode: Mode::Inbox(context),
            });
            let router = signed_origin_routes(state.clone())
                .route(
                    "/approval/{nonce}/revoke",
                    post(signed_revoke::<G>).with_state(state.clone()),
                )
                .route(
                    "/approval/{nonce}/reject",
                    post(signed_reject::<G>).with_state(state),
                );
            Ok(SignedOriginConsent {
                router,
                completion: None,
            })
        }
        SignedOriginMode::OneShot(config) => {
            let config = *config;
            let (sender, completion) = oneshot::channel();
            let state = Arc::new(PresenceState {
                auth: gate,
                context: config.context,
                authority: config.authority,
                store_path: config.store_path,
                identity: Arc::new(config.page_identity),
                origin: origin.to_owned(),
                site: Site::Signed(listener),
                challenges: Mutex::new(HashMap::new()),
                mode: Mode::OneShot {
                    nonce: config.entry.approval_nonce.clone(),
                    expires_at: config.entry.expires_at_unix_ms,
                    completion: Mutex::new(Some(sender)),
                },
            });
            check_presented(&state, &config.entry)?;
            Ok(SignedOriginConsent {
                router: signed_origin_routes(state),
                completion: Some(PresenceCompletion(completion)),
            })
        }
    }
}

/// The consent routes and the detail route of a signed-origin listener.
fn signed_origin_routes<G: ConsentSessionGate>(state: Arc<PresenceState<G>>) -> Router {
    routes(state.clone())
        .route(
            "/static/revoke.js",
            get(revoke_script::<G>).with_state(state.clone()),
        )
        .route(
            "/static/revoke.css",
            get(revoke_style::<G>).with_state(state.clone()),
        )
        .route("/approval/{nonce}", get(detail_get::<G>).with_state(state))
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

pub(crate) fn routes<G: ConsentSessionGate>(state: Arc<PresenceState<G>>) -> Router {
    Router::new()
        .route("/approval/{nonce}/challenge", post(challenge::<G>))
        .route("/approval/{nonce}/assertion", post(assertion::<G>))
        .route("/approval/{nonce}/cancel", post(cancel::<G>))
        .route("/static/mainnet-presence.js", get(script::<G>))
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
        | Failure::MainnetRemoteUnsupported
        | Failure::ListenerPolicyStale
        | Failure::OriginSignedRemote => StatusCode::FORBIDDEN,
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

async fn detail_get<G: ConsentSessionGate>(
    State(state): State<Arc<PresenceState<G>>>,
    headers: HeaderMap,
    Path(nonce): Path<String>,
) -> Response {
    match state.auth.session(&headers) {
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
pub(crate) fn detail<G: ConsentSessionGate>(
    state: &PresenceState<G>,
    session: &G::Session,
    nonce: &str,
) -> Response {
    match render_detail(state, session, nonce, None) {
        Ok(response) => response,
        Err(error) => error_response(&error),
    }
}

/// The detail page of `nonce`, showing `intent` in place of the envelope
/// summary when one is given.
///
/// The island carries the consent view digest of the entry with that
/// intent, [`mainnet_intent_consent_view_digest`], so the page stands for
/// the intent it renders and for no other. The inbox and the ceremony of
/// one command pass no intent and render the legacy page.
fn render_detail<G: ConsentSessionGate>(
    state: &PresenceState<G>,
    session: &G::Session,
    nonce: &str,
    intent: Option<&ClassicIntent>,
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
            Html(render_not_found_page(&state.identity)),
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
        let digest = mainnet_intent_consent_view_digest(
            &entry,
            &state.context.binding(),
            current.policy(),
            intent,
        )?;
        Ok((entry, digest))
    });
    drop(store);
    let (entry, digest) = match consent {
        Ok(consent) => consent,
        Err(error) if crate::decision::presence_refusal(&error).is_some() => return Err(error),
        Err(_) => return Ok(state.settled_page(&view, session, None)),
    };
    let mut data = json!({
        "nonce": nonce,
        "csrf": state.auth.csrf(session, nonce),
        "consent_view_digest": hex::encode(digest),
        "storageKey": state.mode.purpose().proof_storage_key(),
        "mode": match state.mode {
            Mode::Inbox(_) => "inbox",
            Mode::OneShot { .. } => "one_shot",
        },
    });
    if matches!(state.site, Site::Signed(_)) {
        // The page then runs an assertion before it posts a rejection.
        data["signed_origin"] = json!(true);
    }
    let x402_intent = match &entry.kind {
        ApprovalKind::X402Payment { intent_digest, .. } => Some(hex::encode(intent_digest)),
        _ => None,
    };
    let intent_view = intent.map(IntentView::new);
    let page = render_mainnet_consent_page(
        &view,
        &state.context,
        &data,
        x402_intent.as_deref(),
        intent_view.as_ref(),
        state.mode.page_mode(),
        &state.identity,
    );
    let page = match &state.mode {
        Mode::Inbox(context) => {
            crate::templates::with_revocation_control(page, context, nonce, &data)
        }
        Mode::OneShot { .. } => page,
    };
    Ok(Html(page).into_response())
}

async fn signed_revoke<G: ConsentSessionGate>(
    State(state): State<Arc<PresenceState<G>>>,
    headers: HeaderMap,
    Path(nonce): Path<String>,
    body: Bytes,
) -> Response {
    signed_action(&state, &headers, nonce, &body, |nonce| Decision::Revoke {
        nonce,
    })
}

/// Applies `decision` for `nonce` after the session, its per-nonce CSRF and
/// a fresh action assertion verify on the signed-origin inbox.
fn signed_action<G: ConsentSessionGate>(
    state: &PresenceState<G>,
    headers: &HeaderMap,
    nonce: String,
    body: &[u8],
    decision: impl FnOnce(String) -> Decision,
) -> Response {
    if let Err(response) = state.auth.authorize_mutation(headers, &nonce) {
        return response;
    }
    let result = (|| {
        let Mode::Inbox(context) = &state.mode else {
            return Err(failure(Failure::PresenceChanged));
        };
        let session = state
            .auth
            .session(headers)
            .map_err(|_| failure(Failure::PresenceConsumed))?;
        let (presence, _) = verified_presence(state, &session, &nonce, body)?;
        state.discard(&nonce);
        Ok(outcome_to_response(apply_decision(
            context,
            decision(nonce),
            RequestIdentity::SignedOrigin(presence),
        )))
    })();
    match result {
        Ok(response) => response,
        Err(error) => error_response(&error),
    }
}

async fn revoke_script<G: ConsentSessionGate>(
    State(state): State<Arc<PresenceState<G>>>,
    headers: HeaderMap,
) -> Response {
    session_script(&state, &headers, crate::web::REVOKE_JS)
}

async fn revoke_style<G: ConsentSessionGate>(
    State(state): State<Arc<PresenceState<G>>>,
    headers: HeaderMap,
) -> Response {
    session_asset(
        &state,
        &headers,
        "text/css; charset=utf-8",
        crate::web::REVOKE_CSS,
    )
}

/// The stored attestation of `nonce`, after its receipt verifies against
/// the current signed policy. `key` is the attestation key
/// [`PresenceState::reshow_key`] loaded for a trustline clawback opt-in.
fn verified_blob<G: ConsentSessionGate>(
    state: &PresenceState<G>,
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

async fn challenge<G: ConsentSessionGate>(
    State(state): State<Arc<PresenceState<G>>>,
    headers: HeaderMap,
    Path(nonce): Path<String>,
    body: Bytes,
) -> Response {
    if let Err(response) = state.auth.authorize_mutation(&headers, &nonce) {
        return response;
    }
    let result = (|| {
        let session = state
            .auth
            .session(&headers)
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
        let pending = match &state.site {
            Site::Loopback => issue_mainnet_presence(
                &entry,
                &state.context.binding(),
                current.policy(),
                &state.origin,
                now,
                instant,
            )?,
            Site::Signed(listener) => {
                let pending = issue_mainnet_intent_presence(
                    &entry,
                    &state.context.binding(),
                    current.policy(),
                    PresenceListener::SignedOrigin(listener),
                    None,
                    now,
                    instant,
                )?;
                // The policy the identity names signs the origin this
                // listener serves; a challenge for any other origin could
                // never verify here.
                if pending.expected_origin() != state.origin {
                    return Err(failure(Failure::ListenerPolicyStale));
                }
                pending
            }
        };
        drop(store);
        let options = pending.options();
        let mut challenges = state
            .challenges
            .lock()
            .map_err(|_| failure(Failure::PresenceUnavailable))?;
        challenges.retain(|_, challenge| challenge.pending.is_live(now, instant));
        let key = (state.auth.session_key(&session), nonce);
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

/// Takes this session's challenge for `nonce` that `body` names and
/// verifies the assertion `body` carries against it, consuming the
/// challenge. Returns the verified presence and the view digest the
/// challenge was issued for.
fn verified_presence<G: ConsentSessionGate>(
    state: &PresenceState<G>,
    session: &G::Session,
    nonce: &str,
    body: &[u8],
) -> Result<(VerifiedMainnetPresence, String), WalletError> {
    let request: PresenceAssertionRequest =
        serde_json::from_slice(body).map_err(|_| failure(Failure::PresenceInvalid))?;
    let challenge = {
        let mut challenges = state
            .challenges
            .lock()
            .map_err(|_| failure(Failure::PresenceUnavailable))?;
        let key = (state.auth.session_key(session), nonce.to_owned());
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
    state.auth.verified(&presence)?;
    Ok((presence, challenge.view_digest))
}

async fn assertion<G: ConsentSessionGate>(
    State(state): State<Arc<PresenceState<G>>>,
    headers: HeaderMap,
    Path(nonce): Path<String>,
    body: Bytes,
) -> Response {
    if let Err(response) = state.auth.authorize_mutation(&headers, &nonce) {
        return response;
    }
    if matches!(state.site, Site::Signed(_)) && !state.mode.serves(&nonce) {
        return error_response(&failure(Failure::PresenceChanged));
    }
    let result = (|| {
        let session = state
            .auth
            .session(&headers)
            .map_err(|_| failure(Failure::PresenceConsumed))?;
        let (presence, view_digest) = verified_presence(&state, &session, &nonce, &body)?;
        let (store, current) = state.snapshot(&nonce, false)?;
        let entry = state.live_entry(&store, &nonce)?;
        if hex::encode(mainnet_consent_view_digest(
            &entry,
            &state.context.binding(),
            current.policy(),
        )?) != view_digest
        {
            return Err(failure(Failure::PresenceChanged));
        }
        drop(store);
        match &state.mode {
            Mode::Inbox(context) => Ok(outcome_to_response(apply_decision(
                context,
                Decision::Approve {
                    nonce,
                    shown_view_digest: Some(approval_view_digest(
                        &entry,
                        &state.context.binding(),
                    )?),
                },
                match state.site {
                    Site::Loopback => RequestIdentity::Mainnet(presence),
                    Site::Signed(_) => RequestIdentity::SignedOrigin(presence),
                },
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
async fn cancel<G: ConsentSessionGate>(
    State(state): State<Arc<PresenceState<G>>>,
    headers: HeaderMap,
    Path(nonce): Path<String>,
    body: Bytes,
) -> Response {
    if let Err(response) = state.auth.authorize_mutation(&headers, &nonce) {
        return response;
    }
    let result = (|| {
        if !state.mode.serves(&nonce) {
            return Err(failure(Failure::PresenceChanged));
        }
        let request: PresenceCancelRequest =
            serde_json::from_slice(&body).map_err(|_| failure(Failure::PresenceInvalid))?;
        let session = state
            .auth
            .session(&headers)
            .map_err(|_| failure(Failure::PresenceConsumed))?;
        let now = now_ms()?;
        let challenge_expired = state
            .challenges
            .lock()
            .map_err(|_| failure(Failure::PresenceUnavailable))?
            .remove(&(state.auth.session_key(&session), nonce.clone()))
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

/// `POST /approval/{nonce}/reject` of a signed-origin inbox.
///
/// A rejection needs this session's challenge and a fresh assertion over it.
/// With both decision locks held, it rechecks the current verified policy,
/// listener identity, admitted credential, challenged entry, and live deadlines.
/// These checks precede the rejection row and tombstone. Each refusal uses
/// the approval path's code and status, and writes neither record.
/// A request without a verified assertion refuses and leaves the entry pending.
/// A verified rejection drops every outstanding challenge for the entry.
async fn signed_reject<G: ConsentSessionGate>(
    State(state): State<Arc<PresenceState<G>>>,
    headers: HeaderMap,
    Path(nonce): Path<String>,
    body: Bytes,
) -> Response {
    signed_action(&state, &headers, nonce, &body, |nonce| Decision::Reject {
        nonce,
    })
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

fn session_script<G: ConsentSessionGate>(
    state: &PresenceState<G>,
    headers: &HeaderMap,
    source: &'static [u8],
) -> Response {
    session_asset(
        state,
        headers,
        "application/javascript; charset=utf-8",
        source,
    )
}

/// Serves `source` with `content_type` to a request that holds a session.
fn session_asset<G: ConsentSessionGate>(
    state: &PresenceState<G>,
    headers: &HeaderMap,
    content_type: &'static str,
    source: &'static [u8],
) -> Response {
    if let Err(response) = state.auth.session(headers) {
        return response;
    }
    ([(header::CONTENT_TYPE, content_type)], source).into_response()
}

async fn script<G: ConsentSessionGate>(
    State(state): State<Arc<PresenceState<G>>>,
    headers: HeaderMap,
) -> Response {
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
