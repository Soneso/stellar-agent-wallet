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

use std::path::Path;

use stellar_agent_core::approval::{
    ApprovalContext, MainnetApprovalAuthority, PendingApproval, VerifiedMainnetPresence,
};
use stellar_agent_core::error::{ApprovalFailure, WalletError};

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
    #[cfg(test)]
    if let Some(result) = driver::drive(entry, context, authority) {
        return result;
    }
    let current = authority.load_current()?;
    #[cfg(test)]
    let browser_driver = listener_driver::is_installed();
    #[cfg(not(test))]
    let browser_driver = false;
    if !browser_available() && !browser_driver {
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
            WalletError::Approval(
                error
                    .presence_failure()
                    .unwrap_or(ApprovalFailure::PresenceUnavailable),
            )
        })?;
    #[cfg(test)]
    if let Some(flags) = listener_driver::take() {
        return listener_driver::drive(handle, &entry.approval_nonce, flags).await;
    }
    presence_until_done(
        handle,
        entry.expires_at_unix_ms,
        crate::common::private_open::browser_opener,
        tokio::signal::ctrl_c(),
    )
    .await
}

/// The environment variable that, in a build with the `test-helpers`
/// feature, reports the local browser unavailable to every ceremony, so a
/// binary-level test reaches the browser boundary without launching one. The
/// release build never reads it.
#[cfg(feature = "test-helpers")]
pub(crate) const TEST_NO_BROWSER_ENV: &str = "STELLAR_AGENT_TEST_PRESENCE_NO_BROWSER";

/// Whether a local browser can take the ceremony: a graphical session, and
/// in a `test-helpers` build no [`TEST_NO_BROWSER_ENV`].
fn browser_available() -> bool {
    #[cfg(feature = "test-helpers")]
    if std::env::var_os(TEST_NO_BROWSER_ENV).is_some() {
        return false;
    }
    crate::common::display_available()
}

async fn presence_until_done(
    mut handle: stellar_agent_approval_ui::MainnetPresenceHandle,
    expires_at: u64,
    opener: impl FnOnce(&str) -> std::io::Result<()>,
    interrupt: impl std::future::Future<Output = std::io::Result<()>>,
) -> Result<VerifiedMainnetPresence, WalletError> {
    let handoff = match crate::common::private_open::open_private(handle.bootstrap_url(), opener) {
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
    let result = tokio::select! {
        result = handle.await_presence(deadline) => result,
        _ = interrupt => Err(WalletError::Approval(ApprovalFailure::PresenceCanceled)),
    };
    let stopped = handle.shutdown().await;
    let closed = handoff
        .close()
        .map_err(|_| WalletError::Approval(ApprovalFailure::PresenceUnavailable));
    stopped?;
    closed?;
    result
}

#[cfg(test)]
pub(crate) mod listener_driver {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    thread_local! { static FLAGS: std::cell::Cell<Option<u8>> = const { std::cell::Cell::new(None) }; }
    #[cfg(feature = "mainnet-write")]
    pub(crate) struct Guard;
    #[cfg(feature = "mainnet-write")]
    impl Drop for Guard {
        fn drop(&mut self) {
            FLAGS.set(None);
        }
    }
    #[cfg(feature = "mainnet-write")]
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
    ) -> Result<VerifiedMainnetPresence, WalletError> {
        let result = async {
            submit(handle.bootstrap_url(), nonce, flags).await?;
            handle
                .await_presence(std::time::Instant::now() + std::time::Duration::from_secs(1))
                .await
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
    #![allow(clippy::unwrap_used, clippy::expect_used, reason = "test assertions")]

    use serial_test::serial;
    use stellar_agent_core::approval::mainnet_fixtures::MainnetConsentFixture;

    use super::*;

    fn context(fixture: &MainnetConsentFixture) -> ApprovalContext {
        ApprovalContext::from_profile(fixture.name(), fixture.profile())
    }

    /// The private opener completes real assertions and refuses failed launches.
    #[tokio::test]
    #[serial]
    async fn mainnet_browser_open_and_no_browser_refusal() {
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
        let ttl = std::time::Duration::from_millis(1500);
        let entry = fixture.payment(u64::try_from(ttl.as_millis()).unwrap());
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
        let started = std::time::Instant::now();
        let ended = tokio::time::timeout(
            ttl + std::time::Duration::from_secs(3),
            presence_until_done(
                handle,
                entry.expires_at_unix_ms,
                |_| Ok(()),
                std::future::pending(),
            ),
        )
        .await
        .expect("the ceremony ends at the entry's expiry");
        assert_eq!(ended.unwrap_err().code(), "approval.presence_expired");
        let elapsed = started.elapsed();
        assert!(
            elapsed + std::time::Duration::from_millis(250) >= ttl,
            "{elapsed:?}"
        );
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
