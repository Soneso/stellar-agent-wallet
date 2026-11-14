//! The presence adapter of the CLI mainnet consent paths.
//!
//! [`acquire_mainnet_presence`] obtains the verified WebAuthn presence that a
//! mainnet consent records: a fresh assertion with user presence and user
//! verification from an approval credential in the owner-signed policy,
//! over a challenge the core issues for one pending entry. Bare `approve`
//! and the direct confirmation of a classic mainnet write call it after
//! they release the pending store, then reopen the store, read the current
//! policy again and attest.
//!
//! The local page obtains a signed assertion through WebAuthn user verification.
//! Terminal input and the process identity supply no presence.
//! A signed approval origin selects HTTPS before the local browser check.
//! The command prints a secret-free link to stderr and closes the listener on every completion path.

use std::path::Path;

use stellar_agent_core::approval::{
    ApprovalContext, MainnetApprovalAuthority, PendingApproval, VerifiedMainnetPresence,
};
use stellar_agent_core::error::{ApprovalFailure, WalletError};

/// How the operator receives a mainnet ceremony URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OpenMode {
    Private,
    Operator,
}

impl From<bool> for OpenMode {
    fn from(operator: bool) -> Self {
        if operator {
            Self::Operator
        } else {
            Self::Private
        }
    }
}

impl OpenMode {
    /// Delivers the URL once, retaining a private handoff only in the default mode.
    #[allow(clippy::print_stderr, reason = "CLI operator URL handoff")]
    pub(crate) fn open(
        self,
        url: &str,
        opener: impl FnOnce(&str) -> std::io::Result<()>,
    ) -> std::io::Result<Option<crate::common::private_open::PrivateOpen>> {
        match self {
            Self::Operator => {
                eprintln!("Open this URL in your browser: {url}");
                Ok(None)
            }
            Self::Private => {
                // Binary tests observe an attempted launch before the platform browser runs.
                #[cfg(all(feature = "test-helpers", not(test)))]
                if std::env::var_os(TEST_NO_BROWSER_ENV).is_some() {
                    eprintln!("Browser launch attempted in test mode.");
                    return Err(std::io::Error::other("test browser unavailable"));
                }
                crate::common::private_open::open_private(url, opener).map(Some)
            }
        }
    }
}

/// The verified presence of the operator for `entry`.
///
/// `store_path` is the pending store `entry` lives in, which the caller has
/// released; `authority` names the profile whose current signed policy
/// lists the approval credentials.
///
/// # Errors
///
/// Returns browser-required, canceled, expired, or a sealed-verifier refusal.
pub(crate) async fn acquire_mainnet_presence(
    entry: &PendingApproval,
    context: &ApprovalContext,
    authority: &MainnetApprovalAuthority,
    store_path: &Path,
) -> Result<VerifiedMainnetPresence, WalletError> {
    acquire_mainnet_presence_with_mode(entry, context, authority, store_path, OpenMode::Private)
        .await
}

/// Obtains verified presence with the selected URL delivery mode.
pub(crate) async fn acquire_mainnet_presence_with_mode(
    entry: &PendingApproval,
    context: &ApprovalContext,
    authority: &MainnetApprovalAuthority,
    store_path: &Path,
    mode: OpenMode,
) -> Result<VerifiedMainnetPresence, WalletError> {
    #[cfg(test)]
    if let Some(result) = driver::drive(entry, context, authority) {
        return result;
    }
    let current = authority.load_current()?;
    if current
        .policy()
        .mainnet()
        .is_some_and(|body| body.approval_origin.is_some())
    {
        return acquire_signed_presence(entry, context, authority, store_path, &current).await;
    }
    #[cfg(test)]
    let browser_driver = mode == OpenMode::Private && listener_driver::is_installed();
    #[cfg(not(test))]
    let browser_driver = false;
    if mode == OpenMode::Private && !browser_available() && !browser_driver {
        return Err(WalletError::Approval(
            ApprovalFailure::PresenceBrowserRequired,
        ));
    }
    let config = stellar_agent_approval_ui::MainnetPresenceConfig {
        entry: entry.clone(),
        context: context.clone(),
        authority: authority.clone(),
        store_path: store_path.to_path_buf(),
        page_identity: crate::common::served_pages::page_identity_for(current.profile()),
    };
    let handle = stellar_agent_approval_ui::start_mainnet_presence(config)
        .await
        .map_err(|error| {
            if let Some(pair) = error.loopback_pair() {
                crate::common::log_pair_refusal("mainnet presence", pair);
            }
            WalletError::Approval(
                error
                    .presence_failure()
                    .unwrap_or(ApprovalFailure::PresenceUnavailable),
            )
        })?;
    #[cfg(test)]
    if let Some(flags) = listener_driver::take() {
        return listener_driver::drive(
            handle,
            &entry.approval_nonce,
            flags,
            mode,
            entry.expires_at_unix_ms,
        )
        .await;
    }
    presence_until_done(
        handle,
        mode,
        entry.expires_at_unix_ms,
        crate::common::private_open::browser_opener,
        tokio::signal::ctrl_c(),
    )
    .await
}

async fn acquire_signed_presence(
    entry: &PendingApproval,
    context: &ApprovalContext,
    authority: &MainnetApprovalAuthority,
    store_path: &Path,
    current: &stellar_agent_core::approval::CurrentMainnetApprovalPolicy,
) -> Result<VerifiedMainnetPresence, WalletError> {
    let interrupt = register_interrupt().await;
    let config = stellar_agent_approval_ui::MainnetPresenceConfig {
        entry: entry.clone(),
        context: context.clone(),
        authority: authority.clone(),
        store_path: store_path.to_path_buf(),
        page_identity: crate::common::served_pages::page_identity_for(current.profile()),
    };
    let handle = stellar_agent_approval_remote::start_remote_presence(config)
        .await
        .map_err(|error| error.into_wallet_error())?;
    #[cfg(any(test, feature = "test-helpers"))]
    remote_test_ready(&handle).await;
    signed_presence_until_done(
        handle,
        &entry.approval_nonce,
        entry.expires_at_unix_ms,
        interrupt,
    )
    .await
}

/// Reports the bound test endpoint.
#[cfg(any(test, feature = "test-helpers"))]
#[allow(clippy::print_stderr, reason = "binary test readiness")]
pub(crate) async fn remote_test_ready(handle: &stellar_agent_approval_remote::RemoteServeHandle) {
    #[cfg(test)]
    bound_listener::record(handle.local_addr());
    if std::env::var_os(TEST_REMOTE_READY_ENV).is_none() {
        return;
    }
    eprintln!("Test listener: https://{}/", handle.local_addr());
    // This yield lets the native harness interrupt immediately after readiness.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
}

/// The address the newest remote listener of this test process holds.
#[cfg(test)]
pub(crate) mod bound_listener {
    static ADDRESS: std::sync::Mutex<Option<std::net::SocketAddr>> = std::sync::Mutex::new(None);

    pub(super) fn record(address: std::net::SocketAddr) {
        *ADDRESS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(address);
    }

    /// Takes the recorded address, leaving none.
    pub(crate) fn take() -> Option<std::net::SocketAddr> {
        ADDRESS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }
}

/// Polls the signal future before binding so startup cannot expose an unhandled interrupt.
pub(crate) async fn register_interrupt() -> impl std::future::Future<Output = std::io::Result<()>> {
    use std::future::Future as _;
    let mut signal = Box::pin(tokio::signal::ctrl_c());
    let ready = std::future::poll_fn(|cx| {
        std::task::Poll::Ready(match signal.as_mut().poll(cx) {
            std::task::Poll::Ready(result) => Some(result),
            std::task::Poll::Pending => None,
        })
    })
    .await;
    async move {
        match ready {
            Some(result) => result,
            None => signal.await,
        }
    }
}

/// The token-free page link of `nonce` at the signed `origin`.
pub(crate) fn signed_approval_link(origin: &str, nonce: &str) -> String {
    format!("{origin}/approvals/{nonce}")
}

async fn signed_presence_until_done(
    mut handle: stellar_agent_approval_remote::RemoteServeHandle,
    nonce: &str,
    expires_at: u64,
    interrupt: impl std::future::Future<Output = std::io::Result<()>>,
) -> Result<VerifiedMainnetPresence, WalletError> {
    let result = async {
        let completion = handle
            .take_completion()
            .ok_or(WalletError::Approval(ApprovalFailure::PresenceUnavailable))?;
        #[allow(clippy::print_stderr, reason = "CLI signed-origin approval link")]
        {
            eprintln!(
                "Approve at the signed origin: {}",
                signed_approval_link(handle.public_origin(), nonce)
            );
        }
        let now = stellar_agent_core::timefmt::now_unix_ms().unwrap_or(u64::MAX);
        let deadline = std::time::Instant::now()
            .checked_add(std::time::Duration::from_millis(
                expires_at.saturating_sub(now),
            ))
            .ok_or(WalletError::Approval(ApprovalFailure::PresenceUnavailable))?;
        tokio::select! {
            result = completion.await_presence(deadline) => result,
            _ = interrupt => Err(WalletError::Approval(ApprovalFailure::PresenceCanceled)),
        }
    }
    .await;
    handle
        .shutdown()
        .await
        .map_err(|_| WalletError::Approval(ApprovalFailure::PresenceUnavailable))?;
    result
}

/// The environment variable that, in a build with the `test-helpers`
/// feature, reports the local browser unavailable to every ceremony, so a
/// binary-level test reaches the browser boundary without launching one. The
/// release build never reads it.
#[cfg(feature = "test-helpers")]
pub(crate) const TEST_NO_BROWSER_ENV: &str = "STELLAR_AGENT_TEST_PRESENCE_NO_BROWSER";

/// The variable that makes a `test-helpers` or unit-test build report its bound remote endpoint.
/// The release build never reads it.
#[cfg(any(test, feature = "test-helpers"))]
pub(crate) const TEST_REMOTE_READY_ENV: &str = "STELLAR_AGENT_TEST_REMOTE_READY";

/// Whether a local browser can take the ceremony: a graphical session, and
/// in a `test-helpers` build no `TEST_NO_BROWSER_ENV`.
fn browser_available() -> bool {
    #[cfg(feature = "test-helpers")]
    if std::env::var_os(TEST_NO_BROWSER_ENV).is_some() {
        return false;
    }
    crate::common::display_available()
}

async fn presence_until_done(
    mut handle: stellar_agent_approval_ui::MainnetPresenceHandle,
    mode: OpenMode,
    expires_at: u64,
    opener: impl FnOnce(&str) -> std::io::Result<()>,
    interrupt: impl std::future::Future<Output = std::io::Result<()>>,
) -> Result<VerifiedMainnetPresence, WalletError> {
    let handoff = match mode.open(handle.bootstrap_url(), opener) {
        Ok(handoff) => handoff,
        Err(_) => {
            let _ = handle.shutdown().await;
            return Err(WalletError::Approval(
                ApprovalFailure::PresenceBrowserRequired,
            ));
        }
    };
    let now = stellar_agent_core::timefmt::now_unix_ms().unwrap_or(u64::MAX);
    let deadline = std::time::Instant::now()
        .checked_add(std::time::Duration::from_millis(
            expires_at.saturating_sub(now),
        ))
        .ok_or(WalletError::Approval(ApprovalFailure::PresenceUnavailable))?;
    #[cfg(test)]
    expiry_trace::arm(deadline);
    let result = tokio::select! {
        result = handle.await_presence(deadline) => result,
        _ = interrupt => Err(WalletError::Approval(ApprovalFailure::PresenceCanceled)),
    };
    #[cfg(test)]
    expiry_trace::decide(&result);
    let stopped = handle.shutdown().await;
    let closed = handoff
        .map(crate::common::private_open::PrivateOpen::close)
        .transpose()
        .map_err(|_| WalletError::Approval(ApprovalFailure::PresenceUnavailable));
    stopped?;
    closed?;
    result
}

#[cfg(test)]
mod expiry_trace {
    use super::*;
    use std::cell::Cell;

    thread_local! {
        static ARMED: Cell<Option<std::time::Instant>> = const { Cell::new(None) };
        static DECIDED: Cell<Option<(tokio::time::Instant, &'static str)>> = const { Cell::new(None) };
    }

    pub(super) fn reset() {
        ARMED.set(None);
        DECIDED.set(None);
    }
    pub(super) fn arm(deadline: std::time::Instant) {
        ARMED.set(Some(deadline));
    }
    pub(super) fn armed() -> Option<std::time::Instant> {
        ARMED.get()
    }
    pub(super) fn decide(result: &Result<VerifiedMainnetPresence, WalletError>) {
        DECIDED.set(Some((
            tokio::time::Instant::now(),
            result.as_ref().map_or_else(|e| e.code(), |_| "ok"),
        )));
    }
    pub(super) fn decided() -> Option<(tokio::time::Instant, &'static str)> {
        DECIDED.get()
    }
}

#[cfg(test)]
pub(crate) mod listener_driver {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    thread_local! { static FLAGS: std::cell::Cell<Option<u8>> = const { std::cell::Cell::new(None) }; }
    pub(crate) struct Guard;
    impl Drop for Guard {
        fn drop(&mut self) {
            FLAGS.set(None);
        }
    }
    pub(crate) fn install(flags: u8) -> Guard {
        FLAGS.set(Some(flags));
        Guard
    }
    pub(super) fn is_installed() -> bool {
        FLAGS.get().is_some()
    }
    pub(super) fn take() -> Option<u8> {
        FLAGS.take()
    }
    pub(super) async fn drive(
        mut handle: stellar_agent_approval_ui::MainnetPresenceHandle,
        nonce: &str,
        flags: u8,
        mode: OpenMode,
        expires_at: u64,
    ) -> Result<VerifiedMainnetPresence, WalletError> {
        if mode == OpenMode::Operator {
            let url = handle.bootstrap_url().to_owned();
            let unavailable = || WalletError::Approval(ApprovalFailure::PresenceUnavailable);
            let port = url::Url::parse(&url)
                .map_err(|_| unavailable())?
                .port()
                .ok_or_else(unavailable)?;
            let ceremony = presence_until_done(
                handle,
                mode,
                expires_at,
                |_| Err(std::io::Error::other("operator-open launches no browser")),
                std::future::pending(),
            );
            let browser = submit(&url, nonce, flags);
            let (presence, sent) = tokio::join!(ceremony, browser);
            sent?;
            if std::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port)).is_ok() {
                return Err(unavailable());
            }
            return presence;
        }
        let result = async {
            submit(handle.bootstrap_url(), nonce, flags).await?;
            tokio::time::pause();
            let result = stellar_agent_test_support::timing::drive_call(
                handle
                    .await_presence(std::time::Instant::now() + std::time::Duration::from_secs(1)),
                |_| async {},
            )
            .await;
            tokio::time::resume();
            result
        }
        .await;
        handle.shutdown().await?;
        result
    }
    pub(super) async fn submit(url: &str, nonce: &str, flags: u8) -> Result<(), WalletError> {
        let unavailable = || WalletError::Approval(ApprovalFailure::PresenceUnavailable);
        let client =
            stellar_agent_approval_ui::presence::test_support::PresenceClient::connect(url, nonce)
                .await
                .map_err(|_| unavailable())?;
        let parsed = url::Url::parse(url).map_err(|_| unavailable())?;
        let addr =
            std::net::SocketAddr::from(([127, 0, 0, 1], parsed.port().ok_or_else(unavailable)?));
        let second = stellar_agent_approval_ui::operator_enroll::test_support::request(
            addr,
            "GET",
            parsed.path(),
            &[],
            None,
        )
        .await
        .map_err(|_| unavailable())?;
        if second.status != 404 {
            return Err(unavailable());
        }
        let options = client.challenge().await.map_err(|_| unavailable())?.json();
        let challenge = options["challenge"]
            .as_str()
            .and_then(|value| URL_SAFE_NO_PAD.decode(value).ok())
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(unavailable)?;
        let assertion = stellar_agent_test_support::webauthn::fixture_authenticator().assert(
            challenge,
            &client.origin(),
            "localhost",
            flags,
            1,
        );
        let body = serde_json::json!({"request_id": options["request_id"], "credential_id_b64url": URL_SAFE_NO_PAD.encode(assertion.credential_id),
            "authenticator_data_b64url": URL_SAFE_NO_PAD.encode(assertion.authenticator_data), "client_data_json_b64url": URL_SAFE_NO_PAD.encode(assertion.client_data_json), "signature_der_b64url": URL_SAFE_NO_PAD.encode(assertion.signature_der)});
        let response = client
            .post("assertion", &body)
            .await
            .map_err(|_| unavailable())?;
        if response.status != 200 {
            return Err(refusal_of(&response.json()).unwrap_or_else(unavailable));
        }
        Ok(())
    }

    /// The presence refusal a refused assertion's body names in `error`.
    fn refusal_of(body: &serde_json::Value) -> Option<WalletError> {
        let code = body["error"].as_str()?;
        [
            ApprovalFailure::PresenceRequired,
            ApprovalFailure::PresenceInvalid,
            ApprovalFailure::PresenceChanged,
            ApprovalFailure::PresenceExpired,
            ApprovalFailure::PresenceConsumed,
            ApprovalFailure::PresencePolicyUnavailable,
            ApprovalFailure::PresenceBrowserRequired,
            ApprovalFailure::PresenceUnavailable,
            ApprovalFailure::PresenceCanceled,
        ]
        .into_iter()
        .find(|failure| failure.code() == code)
        .map(WalletError::Approval)
    }
}

/// The browser side of a test ceremony.
///
/// A test installs a [`driver::Driver`] for its thread. The adapter then
/// loads the current signed policy as a challenge issuer does, issues a
/// real challenge for the entry, hands the driver the challenge bytes, the
/// expected origin and the RP ID, and verifies whatever assertion bytes the
/// driver returns with the core verifier. The driver supplies bytes or a
/// refusal, never a verified presence, so every accepted presence passed
/// the production checks.
#[cfg(test)]
pub(crate) mod driver {
    use std::cell::RefCell;
    use std::time::Instant;

    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use stellar_agent_core::approval::{
        ApprovalContext, AssertionInput, MAINNET_APPROVAL_RP_ID, MainnetApprovalAuthority,
        PendingApproval, VerifiedMainnetPresence, issue_mainnet_presence, mainnet_presence_origin,
        verify_mainnet_presence,
    };
    use stellar_agent_core::error::{ApprovalFailure, WalletError};

    /// The listener port of the origin a test ceremony binds.
    pub(crate) const TEST_ORIGIN_PORT: u16 = 4100;

    /// What the browser receives: the challenge to sign, the origin the
    /// page runs at and the RP ID the credential belongs to.
    #[derive(Debug, Clone)]
    pub(crate) struct Ceremony {
        /// The 32 challenge bytes the core issued.
        pub(crate) challenge: [u8; 32],
        /// The expected origin of the assertion.
        pub(crate) origin: String,
        /// The relying-party ID.
        pub(crate) rp_id: &'static str,
        /// The pending entry the challenge is for.
        pub(crate) nonce: String,
    }

    /// The assertion bytes for a ceremony, or the refusal the browser ends
    /// it with.
    pub(crate) type Driver = Box<dyn FnMut(&Ceremony) -> Result<AssertionInput, WalletError>>;

    thread_local! {
        static DRIVER: RefCell<Option<Driver>> = const { RefCell::new(None) };
        static CEREMONIES: RefCell<Vec<Ceremony>> = const { RefCell::new(Vec::new()) };
    }

    /// Removes the driver of this thread when dropped.
    pub(crate) struct DriverGuard(());

    impl Drop for DriverGuard {
        fn drop(&mut self) {
            DRIVER.with(|slot| slot.borrow_mut().take());
            CEREMONIES.with(|seen| seen.borrow_mut().clear());
        }
    }

    /// Runs every ceremony on this thread through `driver` until the guard
    /// drops.
    pub(crate) fn install(driver: Driver) -> DriverGuard {
        DRIVER.with(|slot| *slot.borrow_mut() = Some(driver));
        CEREMONIES.with(|seen| seen.borrow_mut().clear());
        DriverGuard(())
    }

    /// The ceremonies the driver received on this thread, oldest first.
    pub(crate) fn ceremonies() -> Vec<Ceremony> {
        CEREMONIES.with(|seen| seen.borrow().clone())
    }

    /// The ceremony through the installed driver, or `None` without one.
    pub(super) fn drive(
        entry: &PendingApproval,
        context: &ApprovalContext,
        authority: &MainnetApprovalAuthority,
    ) -> Option<Result<VerifiedMainnetPresence, WalletError>> {
        let mut driver = DRIVER.with(|slot| slot.borrow_mut().take())?;
        let result = ceremony(&mut driver, entry, context, authority);
        DRIVER.with(|slot| {
            let mut slot = slot.borrow_mut();
            if slot.is_none() {
                *slot = Some(driver);
            }
        });
        Some(result)
    }

    fn ceremony(
        driver: &mut Driver,
        entry: &PendingApproval,
        context: &ApprovalContext,
        authority: &MainnetApprovalAuthority,
    ) -> Result<VerifiedMainnetPresence, WalletError> {
        let clock = || {
            stellar_agent_core::timefmt::now_unix_ms().map_err(|error| {
                WalletError::Approval(ApprovalFailure::ClockError {
                    detail: error.to_string(),
                })
            })
        };
        let policy = authority.load_current()?.into_policy();
        let origin = mainnet_presence_origin(TEST_ORIGIN_PORT);
        let pending = issue_mainnet_presence(
            entry,
            &context.binding(),
            &policy,
            &origin,
            clock()?,
            Instant::now(),
        )?;
        let challenge: [u8; 32] = URL_SAFE_NO_PAD
            .decode(pending.options().challenge)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(WalletError::Approval(ApprovalFailure::PresenceInvalid))?;
        let ceremony = Ceremony {
            challenge,
            origin,
            rp_id: MAINNET_APPROVAL_RP_ID,
            nonce: entry.approval_nonce.clone(),
        };
        CEREMONIES.with(|seen| seen.borrow_mut().push(ceremony.clone()));
        let assertion = driver(&ceremony)?;
        verify_mainnet_presence(pending, assertion, clock()?, Instant::now())
    }

    /// A driver answering every ceremony with the test-support fixture
    /// credential, user presence and user verification set.
    pub(crate) fn fixture_credential() -> Driver {
        credential(
            stellar_agent_test_support::webauthn::fixture_authenticator(),
            stellar_agent_test_support::webauthn::FLAG_UP
                | stellar_agent_test_support::webauthn::FLAG_UV,
        )
    }

    /// A driver answering every ceremony with an assertion of
    /// `authenticator` carrying `flags`, over the ceremony's challenge,
    /// origin and RP ID.
    pub(crate) fn credential(
        authenticator: stellar_agent_test_support::webauthn::TestAuthenticator,
        flags: u8,
    ) -> Driver {
        Box::new(move |ceremony| {
            let assertion = authenticator.assert(
                ceremony.challenge,
                &ceremony.origin,
                ceremony.rp_id,
                flags,
                1,
            );
            AssertionInput::new(
                assertion.credential_id,
                assertion.authenticator_data,
                assertion.client_data_json,
                assertion.signature_compact,
            )
            .map_err(|_| WalletError::Approval(ApprovalFailure::PresenceInvalid))
        })
    }

    /// `driver` answering over a challenge whose first byte differs from the
    /// issued one.
    pub(crate) fn over_another_challenge(mut driver: Driver) -> Driver {
        Box::new(move |ceremony| {
            let mut other = ceremony.clone();
            other.challenge[0] ^= 1;
            driver(&other)
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test assertions"
    )]

    use serial_test::serial;
    use stellar_agent_core::approval::mainnet_fixtures::MainnetConsentFixture;
    use stellar_agent_test_support::timing::{ClockHold, drive_call};

    use super::*;

    fn context(fixture: &MainnetConsentFixture) -> ApprovalContext {
        ApprovalContext::from_profile(fixture.name(), fixture.profile())
    }

    #[tokio::test]
    #[serial]
    async fn signed_origin_shutdown_completes_before_returning() {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
        use serde_json::{Value, json};
        use stellar_agent_approval_remote::session::{SESSION_COOKIE_NAME, SessionState};
        use stellar_agent_core::approval::{
            PendingApprovalStore,
            mainnet_fixtures::{SIGNED_ORIGIN, SIGNED_RP_ID},
        };
        for action in ["consent", "cancel", "expiry", "interrupt"] {
            let files = tempfile::tempdir().unwrap();
            let leaf = stellar_agent_approval_remote::signed_origin_test_leaf(SIGNED_RP_ID);
            let cert = files.path().join("cert.pem");
            let key = files.path().join("key.pem");
            std::fs::write(&cert, leaf.chain_pem()).unwrap();
            std::fs::write(&key, &leaf.key_pem).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
            let mut fixture = MainnetConsentFixture::with_profile("signed-shutdown", |profile| {
                profile.remote_approval = Some(serde_json::from_value(json!({
                    "enabled":true,"bind":"127.0.0.1:0","rp_id":SIGNED_RP_ID,"cert_path":cert,"key_path":key
                })).unwrap());
            });
            let auth = stellar_agent_test_support::webauthn::fixture_authenticator();
            fixture.sign_signed_origin_policy(&[&auth], &leaf.pin);
            let entry = fixture.payment(60_000);
            PendingApprovalStore::open(fixture.store_path())
                .unwrap()
                .insert(
                    entry.clone(),
                    stellar_agent_core::timefmt::now_unix_ms().unwrap(),
                )
                .unwrap();
            let handle = stellar_agent_approval_remote::start_remote_presence(
                stellar_agent_approval_ui::MainnetPresenceConfig {
                    entry: entry.clone(),
                    context: context(&fixture),
                    authority: fixture.authority(),
                    store_path: fixture.store_path(),
                    page_identity: stellar_agent_approval_ui::PageIdentity::neutral(),
                },
            )
            .await
            .unwrap();
            let address = handle.local_addr();
            let session = SessionState::generate(auth.credential_id_b64url());
            let cookie = format!("{SESSION_COOKIE_NAME}={}", session.session_id.to_hex());
            *handle.session_for_test().lock().unwrap() = Some(session);
            let client = reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .no_proxy()
                .build()
                .unwrap();
            let request = |method: &str, suffix: &str| {
                client
                    .request(
                        method.parse().unwrap(),
                        format!(
                            "https://{address}/approval/{}{suffix}",
                            entry.approval_nonce
                        ),
                    )
                    .header("host", SIGNED_ORIGIN.trim_start_matches("https://"))
                    .header("origin", SIGNED_ORIGIN)
                    .header("cookie", &cookie)
            };
            let drive = async {
                if !matches!(action, "consent" | "cancel") {
                    return;
                }
                let html = request("GET", "")
                    .send()
                    .await
                    .unwrap()
                    .text()
                    .await
                    .unwrap();
                let page: Value = serde_json::from_str(
                    html.split("id=\"presence-data\"")
                        .nth(1)
                        .unwrap()
                        .split_once('>')
                        .unwrap()
                        .1
                        .split("</script>")
                        .next()
                        .unwrap(),
                )
                .unwrap();
                let csrf = page["csrf"].as_str().unwrap();
                if action == "cancel" {
                    assert_eq!(
                        request("POST", "/cancel")
                            .header("x-stellar-approval-csrf", csrf)
                            .json(&json!({"reason":"operator_cancel"}))
                            .send()
                            .await
                            .unwrap()
                            .status(),
                        200
                    );
                    return;
                }
                let options: Value = request("POST", "/challenge")
                    .header("x-stellar-approval-csrf", csrf)
                    .json(&json!({"consent_view_digest":page["consent_view_digest"]}))
                    .send()
                    .await
                    .unwrap()
                    .json()
                    .await
                    .unwrap();
                let assertion = auth.assert(
                    B64.decode(options["challenge"].as_str().unwrap())
                        .unwrap()
                        .try_into()
                        .unwrap(),
                    SIGNED_ORIGIN,
                    SIGNED_RP_ID,
                    5,
                    1,
                );
                let response = request("POST", "/assertion").header("x-stellar-approval-csrf", csrf).json(&json!({
                    "request_id":options["request_id"],"credential_id_b64url":B64.encode(assertion.credential_id),
                    "authenticator_data_b64url":B64.encode(assertion.authenticator_data),"client_data_json_b64url":B64.encode(assertion.client_data_json),
                    "signature_der_b64url":B64.encode(assertion.signature_der)
                })).send().await.unwrap();
                assert_eq!(response.status(), 200);
            };
            let interrupt = async {
                if action == "interrupt" {
                    Ok(())
                } else {
                    std::future::pending().await
                }
            };
            let expires = if action == "expiry" {
                0
            } else {
                entry.expires_at_unix_ms
            };
            let (result, ()) = tokio::join!(
                signed_presence_until_done(handle, &entry.approval_nonce, expires, interrupt),
                drive
            );
            if action == "consent" {
                assert!(result.is_ok());
            } else {
                assert_eq!(
                    result.unwrap_err().code(),
                    if action == "expiry" {
                        "approval.presence_expired"
                    } else {
                        "approval.presence_canceled"
                    }
                );
            }
            std::net::TcpListener::bind(address)
                .expect("shutdown releases the socket before the adapter returns");
        }
    }

    async fn operator_presence(name: &str) {
        use crate::common::render::take_rendered_for_test;
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        use clap::Parser as _;

        struct KeepMock;
        impl Drop for KeepMock {
            fn drop(&mut self) {
                stellar_agent_network::keyring::KEEP_REGISTERED_STORE
                    .store(false, std::sync::atomic::Ordering::SeqCst);
            }
        }
        stellar_agent_network::keyring::KEEP_REGISTERED_STORE
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let _mock = KeepMock;
        let fixture = MainnetConsentFixture::new(name);
        let key = &fixture.profile().audit_log_hash_chain_key_id;
        keyring_core::Entry::new(&key.service, &key.account)
            .unwrap()
            .set_password(&URL_SAFE_NO_PAD.encode([0xAB; 32]))
            .unwrap();
        let entry = fixture.payment(600_000);
        let mut store =
            stellar_agent_core::approval::PendingApprovalStore::open(fixture.store_path()).unwrap();
        store
            .insert(
                entry.clone(),
                stellar_agent_core::timefmt::now_unix_ms().unwrap(),
            )
            .unwrap();
        drop(store);
        let _driver = listener_driver::install(5);
        let cli = crate::Cli::try_parse_from([
            "stellar-agent",
            "approve",
            "--id",
            &entry.approval_nonce,
            "--profile",
            name,
            "--open-by-operator",
        ])
        .unwrap();
        let crate::Commands::Approve(args) = cli.command else {
            panic!("approval command")
        };
        take_rendered_for_test();
        let code = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            crate::commands::approve::dispatch(args),
        )
        .await
        .unwrap();
        let envelopes = take_rendered_for_test();
        assert_eq!(code, 0, "{envelopes:?}");
        assert_eq!(envelopes.len(), 1);
        assert_eq!(envelopes[0]["data"]["approval_nonce"], entry.approval_nonce);
        assert_eq!(envelopes[0]["data"]["presence"]["method"], "webauthn_uv");
        assert_eq!(envelopes[0]["data"]["attested"], true);
        let store =
            stellar_agent_core::approval::PendingApprovalStore::open(fixture.store_path()).unwrap();
        let saved = store.get(&entry.approval_nonce).unwrap();
        assert!(saved.mainnet_presence.is_some());
        assert!(saved.attestation_blob_b64.is_some());
    }

    async fn presence_handle(
        fixture: &MainnetConsentFixture,
        entry: &PendingApproval,
    ) -> stellar_agent_approval_ui::MainnetPresenceHandle {
        let mut store =
            stellar_agent_core::approval::PendingApprovalStore::open(fixture.store_path()).unwrap();
        store
            .insert(
                entry.clone(),
                stellar_agent_core::timefmt::now_unix_ms().unwrap(),
            )
            .unwrap();
        drop(store);
        stellar_agent_approval_ui::start_mainnet_presence(
            stellar_agent_approval_ui::MainnetPresenceConfig {
                entry: entry.clone(),
                context: context(fixture),
                authority: fixture.authority(),
                store_path: fixture.store_path(),
                page_identity: stellar_agent_approval_ui::PageIdentity::neutral(),
            },
        )
        .await
        .unwrap()
    }

    async fn expire_at_armed_deadline(
        ceremony: impl std::future::Future<Output = Result<VerifiedMainnetPresence, WalletError>>,
        expires_at: u64,
    ) -> Result<VerifiedMainnetPresence, WalletError> {
        use std::{future::poll_fn, task::Poll, time::Duration};
        use stellar_agent_core::timefmt::now_unix_ms;
        use stellar_agent_test_support::timing::{let_io_run, wait_until};
        use tokio::time::Instant;

        expiry_trace::reset();
        tokio::time::pause();
        let _clock = ClockHold::new();
        let mut ceremony = std::pin::pin!(ceremony);
        let w0 = now_unix_ms().unwrap();
        let i0 = std::time::Instant::now();
        assert!(
            poll_fn(|cx| Poll::Ready(ceremony.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        let i1 = std::time::Instant::now();
        let w1 = now_unix_ms().unwrap();
        let armed = expiry_trace::armed().expect("the presence deadline is armed");
        assert!(
            armed >= i0 + Duration::from_millis(expires_at - w1) - Duration::from_millis(1),
            "the armed deadline is not shortened"
        );
        assert!(
            armed <= i1 + Duration::from_millis(expires_at - w0) + Duration::from_millis(1),
            "the armed deadline is not extended"
        );
        let before = Instant::from_std(armed) - Duration::from_millis(1);
        tokio::time::advance(before.duration_since(Instant::now())).await;
        let_io_run(Duration::from_millis(20)).await;
        assert!(
            poll_fn(|cx| Poll::Ready(ceremony.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        assert_eq!(
            expiry_trace::decided(),
            None,
            "presence is pending before the armed tick"
        );
        let at = Instant::from_std(armed) + Duration::from_nanos(999_999);
        tokio::time::advance(at.duration_since(Instant::now())).await;
        let polled = poll_fn(|cx| Poll::Ready(ceremony.as_mut().poll(cx))).await;
        wait_until("presence is decided at the armed tick", || {
            expiry_trace::decided().is_some()
        })
        .await;
        assert_eq!(
            expiry_trace::decided(),
            Some((at, "approval.presence_expired"))
        );
        let result = drive_call(
            async {
                match polled {
                    Poll::Ready(result) => result,
                    Poll::Pending => ceremony.await,
                }
            },
            |_| async {},
        )
        .await;
        tokio::time::resume();
        result
    }

    #[tokio::test]
    #[serial]
    async fn approve_open_by_operator_prints_url_once() {
        use crate::common::test_support::{assert_url_output, capture};
        if let Some((stdout, stderr)) = capture("approve_open_by_operator_prints_url_once") {
            assert_url_output(&stdout, &stderr);
            return;
        }
        operator_presence("operator-approve-print").await;
    }

    #[tokio::test]
    #[serial]
    async fn approve_open_by_operator_launches_no_browser() {
        use crate::common::test_support::capture;
        if capture("approve_open_by_operator_launches_no_browser").is_some() {
            return;
        }
        operator_presence("operator-approve-no-browser").await;
    }

    #[tokio::test]
    #[serial]
    async fn open_by_operator_keeps_presence_and_expiry() {
        let ending = async |cancel: bool| {
            let fixture = MainnetConsentFixture::new("main");
            let entry = fixture.payment(600_000);
            let handle = presence_handle(&fixture, &entry).await;
            let url = handle.bootstrap_url().to_owned();
            let addr = url::Url::parse(&url)
                .unwrap()
                .socket_addrs(|| None)
                .unwrap()[0];
            let ceremony = presence_until_done(
                handle,
                OpenMode::Operator,
                entry.expires_at_unix_ms,
                |_| panic!("no browser"),
                async {
                    if cancel {
                        Ok(())
                    } else {
                        std::future::pending().await
                    }
                },
            );
            let result = if cancel {
                drive_call(ceremony, |_| async {}).await
            } else {
                expire_at_armed_deadline(ceremony, entry.expires_at_unix_ms).await
            }
            .unwrap_err();
            assert_eq!(
                result.code(),
                if cancel {
                    "approval.presence_canceled"
                } else {
                    "approval.presence_expired"
                }
            );
            assert!(std::net::TcpStream::connect(addr).is_err());
            let store =
                stellar_agent_core::approval::PendingApprovalStore::open(fixture.store_path())
                    .unwrap();
            assert!(
                store
                    .get(&entry.approval_nonce)
                    .unwrap()
                    .mainnet_presence
                    .is_none()
            );
        };
        ending(true).await;
        let fixture = MainnetConsentFixture::new("main");
        let entry = fixture.payment(60_000);
        let handle = presence_handle(&fixture, &entry).await;
        let url = handle.bootstrap_url().to_owned();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let browser = async {
            let error = listener_driver::submit(&url, &entry.approval_nonce, 1)
                .await
                .unwrap_err();
            assert_eq!(error.code(), "approval.presence_invalid");
            tx.send(()).unwrap();
        };
        let ceremony = presence_until_done(
            handle,
            OpenMode::Operator,
            entry.expires_at_unix_ms,
            |_| Ok(()),
            async {
                rx.await.unwrap();
                Ok(())
            },
        );
        let result = drive_call(ceremony, |_| browser).await;
        assert_eq!(result.unwrap_err().code(), "approval.presence_canceled");
        crate::commands::approve::credential::tests::operator_mismatch_and_cancellation().await;
        // The expiry case runs last: advancing Tokio time leaves its clock
        // ahead of later wall-clock deadlines.
        ending(false).await;
    }

    #[test]
    fn open_by_operator_keeps_stdout_one_envelope() {
        use crate::common::test_support::{assert_url_output, capture};
        for name in [
            "serve_open_by_operator_prints_url_once",
            "credential_open_by_operator_prints_url_once",
            "approve_open_by_operator_prints_url_once",
        ] {
            let (stdout, stderr) = capture(name).unwrap();
            assert_url_output(&stdout, &stderr);
        }
    }

    /// The private opener completes real assertions and refuses failed launches.
    #[tokio::test]
    #[serial]
    async fn mainnet_browser_open_and_no_browser_refusal() {
        if crate::common::test_support::capture(
            "common::mainnet_presence::tests::mainnet_browser_open_and_no_browser_refusal",
        )
        .is_some()
        {
            return;
        }
        let fixture = MainnetConsentFixture::new("main");
        let entry = fixture.payment(600_000);
        let error = acquire_mainnet_presence(
            &entry,
            &context(&fixture),
            &fixture.authority(),
            &fixture.store_path(),
        )
        .await
        .unwrap_err();
        assert_eq!(
            error.code(),
            "approval.presence_browser_required",
            "default mode requires a display"
        );
        let mut store =
            stellar_agent_core::approval::PendingApprovalStore::open(fixture.store_path()).unwrap();
        store
            .insert(
                entry.clone(),
                stellar_agent_core::timefmt::now_unix_ms().unwrap(),
            )
            .unwrap();
        drop(store);
        let config = stellar_agent_approval_ui::MainnetPresenceConfig {
            entry: entry.clone(),
            context: context(&fixture),
            authority: fixture.authority(),
            store_path: fixture.store_path(),
            page_identity: stellar_agent_approval_ui::PageIdentity::neutral(),
        };
        let handle = stellar_agent_approval_ui::start_mainnet_presence(config)
            .await
            .unwrap();
        let error = presence_until_done(
            handle,
            OpenMode::Private,
            entry.expires_at_unix_ms,
            |_| Err(std::io::Error::other("synthetic opener refusal")),
            std::future::pending(),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), "approval.presence_browser_required");
        let store =
            stellar_agent_core::approval::PendingApprovalStore::open(fixture.store_path()).unwrap();
        assert!(
            store
                .get(&entry.approval_nonce)
                .unwrap()
                .attestation_blob_b64
                .is_none()
        );
        assert!(!fixture.audit_path().exists());
        drop(store);
        let handle = stellar_agent_approval_ui::start_mainnet_presence(
            stellar_agent_approval_ui::MainnetPresenceConfig {
                entry: entry.clone(),
                context: context(&fixture),
                authority: fixture.authority(),
                store_path: fixture.store_path(),
                page_identity: stellar_agent_approval_ui::PageIdentity::neutral(),
            },
        )
        .await
        .unwrap();
        let destination = handle.bootstrap_url().to_owned();
        let nonce = entry.approval_nonce.clone();
        let mut launched = None;
        let mut browser = None;
        let presence = presence_until_done(
            handle,
            OpenMode::Private,
            entry.expires_at_unix_ms,
            |file_url| {
                assert!(file_url.starts_with("file://"));
                assert!(!file_url.contains("bootstrap"));
                let path = url::Url::parse(file_url).unwrap().to_file_path().unwrap();
                assert!(
                    std::fs::read_to_string(&path)
                        .unwrap()
                        .contains(&destination)
                );
                launched = Some(path);
                browser = Some(tokio::spawn(async move {
                    listener_driver::submit(&destination, &nonce, 5).await
                }));
                Ok(())
            },
            std::future::pending(),
        )
        .await
        .unwrap();
        browser.unwrap().await.unwrap().unwrap();
        assert_eq!(presence.approval_nonce(), entry.approval_nonce);
        let path = launched.unwrap();
        assert!(!path.exists());
        assert!(!path.parent().unwrap().exists());
    }

    /// A ceremony without an assertion ends with an expired presence when
    /// its entry expires, not later: the wait's deadline is the entry's
    /// expiry.
    #[tokio::test]
    #[serial]
    async fn the_ceremony_ends_at_the_entry_expiry() {
        let fixture = MainnetConsentFixture::new("main");
        let entry = fixture.payment(600_000);
        let mut store =
            stellar_agent_core::approval::PendingApprovalStore::open(fixture.store_path()).unwrap();
        store
            .insert(
                entry.clone(),
                stellar_agent_core::timefmt::now_unix_ms().unwrap(),
            )
            .unwrap();
        drop(store);
        let handle = stellar_agent_approval_ui::start_mainnet_presence(
            stellar_agent_approval_ui::MainnetPresenceConfig {
                entry: entry.clone(),
                context: context(&fixture),
                authority: fixture.authority(),
                store_path: fixture.store_path(),
                page_identity: stellar_agent_approval_ui::PageIdentity::neutral(),
            },
        )
        .await
        .unwrap();
        let ended = expire_at_armed_deadline(
            presence_until_done(
                handle,
                OpenMode::Private,
                entry.expires_at_unix_ms,
                |_| Ok(()),
                std::future::pending(),
            ),
            entry.expires_at_unix_ms,
        )
        .await;
        assert_eq!(ended.unwrap_err().code(), "approval.presence_expired");
    }

    /// The test driver receives the issued challenge and returns bytes only:
    /// a genuine assertion verifies, an assertion over another challenge and
    /// a driver refusal do not.
    #[tokio::test]
    #[serial]
    async fn the_test_driver_cannot_skip_verification() {
        let fixture = MainnetConsentFixture::new("main");
        let entry = fixture.payment(600_000);
        let context = context(&fixture);
        let authority = fixture.authority();
        let store_path = fixture.store_path();
        let acquire = || acquire_mainnet_presence(&entry, &context, &authority, &store_path);

        let guard = driver::install(driver::fixture_credential());
        acquire().await.unwrap();
        let seen = driver::ceremonies();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].nonce, entry.approval_nonce);
        assert_eq!(seen[0].origin, "http://localhost:4100");
        drop(guard);

        let _guard = driver::install(driver::over_another_challenge(driver::fixture_credential()));
        assert_eq!(
            acquire().await.unwrap_err().code(),
            "approval.presence_invalid"
        );

        let _guard = driver::install(Box::new(|_| {
            Err(WalletError::Approval(ApprovalFailure::PresenceCanceled))
        }));
        assert_eq!(
            acquire().await.unwrap_err().code(),
            "approval.presence_canceled"
        );
    }
}
