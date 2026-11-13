//! The current owner-signed mainnet approval policy of a named profile.
//!
//! [`MainnetApprovalAuthority`] names a persisted mainnet profile;
//! [`MainnetApprovalAuthority::load_current`] reads that profile's owner key,
//! signed policy, pin and enablement from the wallet's own locations and
//! returns the verified policy whose `mainnet.approval_credentials` decide
//! which assertions are mainnet consent. No HTTP request, overlay, or caller
//! path enters the load, and no constructor accepts a path or a key.
//!
//! # When it is read
//!
//! A consent surface reads the policy before it issues a challenge, again
//! after every browser, keyring, or audit wait and before it persists, and
//! the commit witness reads it once more. Each read compares the sequence,
//! digest, and owner with the policy the challenge bound; any difference
//! requires a fresh consent, even when the same credential appears in both.
//!
//! # Locks
//!
//! A load takes the policy window-state lock shared for the pin comparison,
//! and exclusive only to advance the pin, and releases it before returning.
//! A lock that a writer holds through the final retry refuses the load as
//! `approval.presence_policy_busy`. The signature and body checks may have
//! run, but the pin freshness check has not, so the answer invites a retry.
//!
//! [`MainnetApprovalAuthority::admit`] holds the lock shared across one
//! request, and [`MainnetApprovalAuthority::admit_exclusive`] holds it
//! exclusively for a request that also writes window state. The request
//! takes it while it holds no other lock and before it consumes a challenge,
//! so a busy answer leaves stored state unchanged. The policy-state lock
//! comes before the pending approval store. Every later read of the request
//! goes through [`MainnetApprovalAuthority::load_admitted`], and its write
//! runs under [`PolicyAdmission::exclusive`], so the request takes the lock
//! once.
//!
//! The issuing load advances the pin, so an observed credential removal at a
//! higher signed sequence cannot be rolled back through wallet commands. The
//! witness load compares only.

use crate::error::{ApprovalFailure, WalletError};
use crate::mainnet::verified_policy::VerifiedPolicy;
use crate::policy::PolicyError;
use crate::policy::pin::{self, PinScope, PinState};
use crate::policy::state_lock::{StateLockError, WindowStoreLock, WindowStoreReadLock};
use crate::policy::v1::PolicyStateStore;
use crate::policy::v1::verified::{
    OwnerKeySource, PinMode, PolicyLoad, check_signed_policy, load_verified_policy,
    load_verified_policy_against,
};
use crate::profile::schema::{PolicyEngineKind, Profile};

/// The profile whose owner-signed mainnet policy holds the approval
/// credentials.
///
/// `Debug` shows the profile name only.
#[derive(Clone)]
pub struct MainnetApprovalAuthority {
    profile_name: String,
}

impl std::fmt::Debug for MainnetApprovalAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MainnetApprovalAuthority")
            .field("profile_name", &self.profile_name)
            .finish()
    }
}

/// A verified mainnet policy with the persisted profile it was loaded for.
#[derive(Debug, Clone)]
pub struct CurrentMainnetApprovalPolicy {
    profile: Profile,
    policy: VerifiedPolicy,
}

impl CurrentMainnetApprovalPolicy {
    /// The persisted profile, read without overlays.
    #[must_use]
    pub fn profile(&self) -> &Profile {
        &self.profile
    }

    /// The verified owner-signed policy.
    #[must_use]
    pub fn policy(&self) -> &VerifiedPolicy {
        &self.policy
    }

    /// The policy, consumed.
    #[must_use]
    pub fn into_policy(self) -> VerifiedPolicy {
        self.policy
    }

    /// Whether this policy is `other`: the same sequence, digest, and owner.
    #[must_use]
    pub fn is(&self, other: &VerifiedPolicy) -> bool {
        same_policy(&self.policy, other)
    }
}

/// A guard on the policy-state lock of one profile, from
/// [`MainnetApprovalAuthority::admit`] (shared) or
/// [`MainnetApprovalAuthority::admit_exclusive`]. Dropping it releases the
/// lock. [`MainnetApprovalAuthority::load_admitted`] reads the pin through it.
#[derive(Debug)]
pub struct PolicyAdmission {
    guard: AdmissionGuard,
}

#[derive(Debug)]
enum AdmissionGuard {
    Shared(WindowStoreReadLock),
    Exclusive(WindowStoreLock),
}

impl PolicyAdmission {
    /// The exclusive guard, which a write of the same request runs under.
    /// `None` for a shared admission.
    #[must_use]
    pub fn exclusive(&self) -> Option<&WindowStoreLock> {
        match &self.guard {
            AdmissionGuard::Exclusive(lock) => Some(lock),
            AdmissionGuard::Shared(_) => None,
        }
    }

    /// Reads the pin of `profile` under the held guard. A guard for another
    /// window-state entry refuses with the pin's wrong-guard error.
    fn read_pin(
        &self,
        window_path: &std::path::Path,
        profile: &Profile,
    ) -> Result<PinState, PolicyError> {
        let scope = PinScope::for_profile(window_path, profile);
        match &self.guard {
            AdmissionGuard::Shared(lock) => pin::read_shared(lock, &scope),
            AdmissionGuard::Exclusive(lock) => pin::read(lock, &scope),
        }
        .map_err(PolicyError::from)
    }
}

/// How a load reads the pin: by taking the lock in `PinMode`, or through
/// the guard of an admission the caller holds.
#[derive(Clone, Copy)]
enum PinRead<'a> {
    Mode(PinMode),
    Held(&'a PolicyAdmission),
}

/// Whether two verified policies have the same sequence, digest, and owner.
#[must_use]
pub fn same_policy(a: &VerifiedPolicy, b: &VerifiedPolicy) -> bool {
    a.sequence() == b.sequence() && a.digest() == b.digest() && a.owner() == b.owner()
}

fn unavailable(code: &str) -> WalletError {
    tracing::debug!(code, "mainnet approval policy unavailable");
    WalletError::Approval(ApprovalFailure::PresencePolicyUnavailable)
}

fn busy() -> WalletError {
    tracing::debug!("mainnet approval policy-state lock busy");
    WalletError::Approval(ApprovalFailure::PresencePolicyBusy)
}

/// The refusal of an admission whose lock acquisition failed.
fn lock_refusal(error: StateLockError) -> WalletError {
    match error {
        StateLockError::WriterLocked => busy(),
        StateLockError::Io { .. } => unavailable("policy.state_lock_io"),
    }
}

impl MainnetApprovalAuthority {
    /// The authority of the persisted profile `name`.
    ///
    /// # Errors
    ///
    /// `approval.presence_policy_unavailable` for a name that is not a safe
    /// path component, and for `default`, which never enables mainnet.
    pub fn for_profile(name: &str) -> Result<Self, WalletError> {
        crate::profile::name::validate_path_component_ascii_safe(name)
            .map_err(|_| unavailable("profile.invalid_name"))?;
        if name == "default" {
            return Err(unavailable("profile.default"));
        }
        Ok(Self {
            profile_name: name.to_owned(),
        })
    }

    /// The profile name.
    #[must_use]
    pub fn profile_name(&self) -> &str {
        &self.profile_name
    }

    /// Loads the current policy and advances the pin to it.
    ///
    /// # Errors
    ///
    /// `approval.presence_policy_busy` when the policy-state lock stays held
    /// by a writer through the final retry, and
    /// `approval.presence_policy_unavailable` when any other step the module
    /// documents fails.
    pub fn load_current(&self) -> Result<CurrentMainnetApprovalPolicy, WalletError> {
        self.load(PinRead::Mode(PinMode::Advance))
    }

    /// Loads the current policy and compares it with the pin without writing
    /// the pin or creating a lock file.
    ///
    /// # Errors
    ///
    /// As [`Self::load_current`].
    pub fn load_current_compare_only(&self) -> Result<CurrentMainnetApprovalPolicy, WalletError> {
        self.load(PinRead::Mode(PinMode::CompareOnly))
    }

    /// Takes the policy-state lock of the profile shared and holds it until
    /// the returned admission drops.
    ///
    /// A request takes it before it consumes a challenge or records a
    /// counter, and keeps it until it publishes its result. While it lives,
    /// no writer takes the lock, so every compare-only load under it reads
    /// the same pin. An advancing load under it answers busy. The admission
    /// does not stop an edit of the policy file, which each load verifies.
    ///
    /// # Errors
    ///
    /// The admission runs the checks every load runs before its lock: the
    /// profile, the owner key, and the policy signature and body. Each
    /// refuses as `approval.presence_policy_unavailable`. Then
    /// `approval.presence_policy_busy` when a writer holds the lock through
    /// the final retry. A busy lock wins over a refusal that needs the pin,
    /// such as a rollback. An absent or unreadable lock file is unavailable.
    pub fn admit(&self) -> Result<PolicyAdmission, WalletError> {
        self.admit_with(false)
    }

    /// Takes the policy-state lock of the profile exclusively, for a request
    /// that writes window state under it, and holds it until the returned
    /// admission drops.
    ///
    /// The request reads the policy only through
    /// [`Self::load_admitted`] and writes only under
    /// [`PolicyAdmission::exclusive`], so it never takes the lock twice.
    ///
    /// # Errors
    ///
    /// As [`Self::admit`]; any held guard, shared or exclusive, is busy.
    pub fn admit_exclusive(&self) -> Result<PolicyAdmission, WalletError> {
        self.admit_with(true)
    }

    fn admit_with(&self, exclusive: bool) -> Result<PolicyAdmission, WalletError> {
        let inputs = self.load_inputs()?;
        check_signed_policy(&inputs.policy_load(&self.profile_name))
            .map_err(|error| unavailable(error.wire_code()))?;
        let (window, key) = (
            &inputs.window_path,
            &inputs.profile.policy_window_state_key_id,
        );
        let guard = if exclusive {
            WindowStoreLock::acquire_existing_for_with_retry(window, key)
                .map(|guard| guard.map(AdmissionGuard::Exclusive))
        } else {
            WindowStoreReadLock::acquire_existing_for_with_retry(window, key)
                .map(|guard| guard.map(AdmissionGuard::Shared))
        };
        match guard {
            Ok(Some(guard)) => Ok(PolicyAdmission { guard }),
            Ok(None) => Err(unavailable("policy.pin_absent")),
            Err(error) => Err(lock_refusal(error)),
        }
    }

    /// Loads the current policy and compares it with the pin read through
    /// `admission`, without taking the lock.
    ///
    /// # Errors
    ///
    /// As [`Self::load_current_compare_only`]. An admission for another
    /// window-state entry refuses as `approval.presence_policy_unavailable`.
    pub fn load_admitted(
        &self,
        admission: &PolicyAdmission,
    ) -> Result<CurrentMainnetApprovalPolicy, WalletError> {
        self.load(PinRead::Held(admission))
    }

    /// The persisted profile and its directory, after the profile checks
    /// every load makes before it reads the policy.
    fn persisted_profile(&self) -> Result<(Profile, std::path::PathBuf), WalletError> {
        let name = self.profile_name.as_str();
        let profile_dir = crate::profile::schema::default_profile_dir()
            .map_err(|_| unavailable("profile.state_dir"))?;
        let profile =
            crate::profile::loader::load_from_dir_without_overlays(name, &profile_dir, None)
                .map_err(|_| unavailable("profile.load"))?;
        if crate::profile::name::derive_profile_name_from_owner_key(&profile) != Some(name) {
            return Err(unavailable("profile.owner_namespace"));
        }
        if !profile.chain_id.is_mainnet() {
            return Err(unavailable("profile.chain"));
        }
        if profile.policy.engine != PolicyEngineKind::V1 {
            return Err(unavailable("policy.engine"));
        }
        if !crate::mainnet::enablement::has_enablement_nonce(&profile)
            .map_err(|_| unavailable("mainnet.enablement_unreadable"))?
        {
            return Err(unavailable("mainnet.not_enabled"));
        }
        Ok((profile, profile_dir))
    }

    /// The profile, owner key and paths a load or an admission reads.
    fn load_inputs(&self) -> Result<LoadInputs, WalletError> {
        let name = self.profile_name.as_str();
        let (profile, profile_dir) = self.persisted_profile()?;
        let owner = read_owner_key(&profile)?;
        let policy_path = crate::profile::schema::default_policy_dir()
            .map_err(|_| unavailable("policy.state_dir"))?
            .join(format!("{name}.toml"));
        let window_path = crate::profile::schema::default_policy_window_state_path_for(name);
        Ok(LoadInputs {
            profile,
            profile_dir,
            owner,
            policy_path,
            window_path,
        })
    }

    fn load(&self, pin: PinRead<'_>) -> Result<CurrentMainnetApprovalPolicy, WalletError> {
        let name = self.profile_name.as_str();
        let inputs = self.load_inputs()?;
        let load = inputs.policy_load(name);
        let (profile, window_path) = (&inputs.profile, &inputs.window_path);
        let policy = match pin {
            PinRead::Mode(mode) => load_verified_policy(&load, PolicyStateStore::new(), mode),
            PinRead::Held(admission) => {
                admission.read_pin(window_path, profile).and_then(|state| {
                    load_verified_policy_against(&load, PolicyStateStore::new(), &state)
                })
            }
        }
        .map_err(|error| match error {
            PolicyError::StateLockBusy => busy(),
            error => unavailable(error.wire_code()),
        })?;
        crate::mainnet::enablement::verify_enablement_bindings(
            &policy,
            name,
            profile,
            &inputs.profile_dir,
            &crate::mainnet::enablement::read_enablement_nonce,
        )
        .map_err(|error| unavailable(error.code()))?;
        if policy
            .mainnet()
            .is_none_or(|body| body.approval_credentials.is_empty())
        {
            return Err(unavailable("policy.approval_credentials"));
        }
        Ok(CurrentMainnetApprovalPolicy {
            profile: inputs.profile,
            policy,
        })
    }
}

/// What a load reads besides the policy file and the pin.
struct LoadInputs {
    profile: Profile,
    profile_dir: std::path::PathBuf,
    owner: [u8; 32],
    policy_path: std::path::PathBuf,
    window_path: std::path::PathBuf,
}

impl LoadInputs {
    fn policy_load<'a>(&'a self, name: &'a str) -> PolicyLoad<'a> {
        PolicyLoad {
            path: &self.policy_path,
            profile: &self.profile,
            profile_name: name,
            owner_pubkey: &self.owner,
            owner_source: OwnerKeySource::Keyring,
            window_path: &self.window_path,
        }
    }
}

/// Reads and decodes the owner public key at the profile's owner coordinate,
/// without rewriting it or rendering its bytes.
fn read_owner_key(profile: &Profile) -> Result<[u8; 32], WalletError> {
    let coordinate = &profile.policy_owner_key_id;
    let raw = keyring_core::Entry::new(&coordinate.service, &coordinate.account)
        .and_then(|entry| entry.get_password())
        .map(zeroize::Zeroizing::new)
        .map_err(|_| unavailable("policy.missing_owner_key"))?;
    crate::profile::owner_key::decode_owner_public_key(&raw)
        .map_err(|_| unavailable("policy.owner_key_form"))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use serial_test::serial;
    use stellar_agent_test_support::webauthn::{TestAuthenticator, fixture_authenticator};

    use super::*;
    use crate::approval::mainnet_fixtures::MainnetConsentFixture;

    fn refused(result: Result<CurrentMainnetApprovalPolicy, WalletError>) -> String {
        result.unwrap_err().code().to_owned()
    }

    fn delete(entry: &crate::profile::schema::KeyringEntryRef) {
        keyring_core::Entry::new(&entry.service, &entry.account)
            .unwrap()
            .delete_credential()
            .unwrap();
    }

    /// The authority names a persisted profile by a safe name, never
    /// `default`, and renders nothing but the name.
    #[test]
    fn authority_names_a_safe_non_default_profile() {
        for name in ["default", "../main", "", "a/b"] {
            assert_eq!(
                MainnetApprovalAuthority::for_profile(name)
                    .unwrap_err()
                    .code(),
                "approval.presence_policy_unavailable",
                "{name}"
            );
        }
        let authority = MainnetApprovalAuthority::for_profile("main").unwrap();
        assert_eq!(authority.profile_name(), "main");
        assert_eq!(
            format!("{authority:?}"),
            "MainnetApprovalAuthority { profile_name: \"main\" }"
        );
    }

    /// The load needs the enablement nonce, the owner key and a policy that
    /// verifies under it; each missing piece refuses with one code.
    #[test]
    #[serial]
    fn load_requires_an_enabled_profile_and_a_verified_policy() {
        let fixture = MainnetConsentFixture::new("main");
        let current = fixture.authority().load_current().unwrap();
        assert!(current.is(&fixture.current_policy()));
        assert_eq!(current.profile().chain_id, fixture.profile().chain_id);
        assert_eq!(
            current
                .policy()
                .mainnet()
                .unwrap()
                .approval_credentials
                .len(),
            1
        );
        assert!(
            MainnetApprovalAuthority::for_profile("other")
                .unwrap()
                .load_current()
                .is_err()
        );

        let policy_path = fixture.policy_path();
        let signed = std::fs::read_to_string(&policy_path).unwrap();
        std::fs::write(&policy_path, signed.replace("sequence = 1", "sequence = 2")).unwrap();
        assert_eq!(
            refused(fixture.authority().load_current_compare_only()),
            "approval.presence_policy_unavailable",
            "an unsigned edit"
        );
        std::fs::write(&policy_path, &signed).unwrap();
        assert!(fixture.authority().load_current_compare_only().is_ok());

        delete(&crate::profile::schema::mainnet_enablement_entry_ref(
            &fixture.profile().policy_window_state_key_id,
        ));
        assert_eq!(
            refused(fixture.authority().load_current_compare_only()),
            "approval.presence_policy_unavailable",
            "no enablement"
        );
        drop(fixture);
        let fixture = MainnetConsentFixture::new("main");
        delete(&fixture.profile().policy_owner_key_id);
        assert_eq!(
            refused(fixture.authority().load_current_compare_only()),
            "approval.presence_policy_unavailable",
            "no owner key"
        );
    }

    /// A policy-state writer that holds the lock through the final retry
    /// refuses both loads as busy, never as an unavailable policy, and a
    /// load after its release succeeds. An unsigned edit stays unavailable,
    /// whether or not the writer holds the lock.
    #[test]
    #[serial]
    fn a_held_policy_lock_answers_policy_busy() {
        let fixture = MainnetConsentFixture::new("main");
        let window = crate::profile::schema::default_policy_window_state_path_for("main");
        let key = &fixture.profile().policy_window_state_key_id;
        let writer = crate::policy::state_lock::WindowStoreLock::acquire_for(&window, key).unwrap();
        for load in [
            MainnetApprovalAuthority::load_current_compare_only,
            MainnetApprovalAuthority::load_current,
        ] {
            assert_eq!(
                refused(load(&fixture.authority())),
                "approval.presence_policy_busy"
            );
        }
        let policy_path = fixture.policy_path();
        let signed = std::fs::read_to_string(&policy_path).unwrap();
        std::fs::write(&policy_path, signed.replace("sequence = 1", "sequence = 2")).unwrap();
        assert_eq!(
            refused(fixture.authority().load_current_compare_only()),
            "approval.presence_policy_unavailable",
            "an unsigned edit under a held lock"
        );
        drop(writer);
        assert_eq!(
            refused(fixture.authority().load_current_compare_only()),
            "approval.presence_policy_unavailable",
            "an unsigned edit"
        );
        std::fs::write(&policy_path, &signed).unwrap();
        assert!(fixture.authority().load_current_compare_only().is_ok());
        assert!(fixture.authority().load_current().is_ok());
    }

    /// The issuing load advances the pin, so a credential removal observed
    /// at a higher sequence cannot be rolled back; the compare-only load
    /// never advances it.
    #[test]
    #[serial]
    fn issuing_load_advances_the_pin_and_compare_only_does_not() {
        let mut fixture = MainnetConsentFixture::new("main");
        let first = fixture.policy_body(1, &[&fixture_authenticator()]);
        let other = TestAuthenticator::from_seed([0x33; 32], vec![0x44; 16]);

        fixture.sign_policy(&[&other]);
        assert_eq!(
            fixture
                .authority()
                .load_current_compare_only()
                .unwrap()
                .policy()
                .sequence(),
            2
        );
        fixture.write_signed(&first);
        assert!(
            fixture.authority().load_current_compare_only().is_ok(),
            "the compare-only load left the pin at sequence 1"
        );

        let second = fixture.policy_body(2, &[&other]);
        fixture.write_signed(&second);
        assert_eq!(
            fixture
                .authority()
                .load_current()
                .unwrap()
                .policy()
                .sequence(),
            2
        );
        fixture.write_signed(&first);
        for load in [
            MainnetApprovalAuthority::load_current_compare_only,
            MainnetApprovalAuthority::load_current,
        ] {
            assert_eq!(
                refused(load(&fixture.authority())),
                "approval.presence_policy_unavailable",
                "the removal at sequence 2 is pinned"
            );
        }
    }
}
