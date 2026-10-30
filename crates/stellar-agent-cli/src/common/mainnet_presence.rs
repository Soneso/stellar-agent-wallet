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
//! No browser ceremony is connected to this adapter, so it refuses every
//! mainnet consent with `approval.presence_required` and no approval is
//! recorded. Terminal input, a pseudo-terminal and the process identity
//! supply no presence. Reading, simulation, setup, approval credential
//! enrollment and policy signing are unaffected.

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
/// `approval.presence_required`: no presence ceremony is available, so no
/// mainnet consent can be recorded through this adapter.
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
    let _ = (entry, context, authority, store_path);
    Err(WalletError::Approval(ApprovalFailure::PresenceRequired))
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
    #![allow(clippy::unwrap_used, reason = "test assertions")]

    use serial_test::serial;
    use stellar_agent_core::approval::mainnet_fixtures::MainnetConsentFixture;

    use super::*;

    fn context(fixture: &MainnetConsentFixture) -> ApprovalContext {
        ApprovalContext::from_profile(fixture.name(), fixture.profile())
    }

    /// Without a ceremony the adapter refuses every mainnet consent with
    /// `approval.presence_required`, for an enabled profile whose signed
    /// policy lists a credential.
    #[tokio::test]
    #[serial]
    async fn the_release_adapter_refuses_with_presence_required() {
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
        assert_eq!(error.code(), "approval.presence_required");
        assert_eq!(
            error.to_string(),
            "Mainnet consent requires a verified assertion from an approval credential in the \
             owner-signed policy."
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
