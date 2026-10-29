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
//! A load takes the policy window-state lock for the pin comparison and
//! releases it before returning. A caller that also holds the pending
//! approval store takes the store first, then loads; no presence code runs
//! while it holds the window-state lock.
//!
//! The issuing load advances the pin, so an observed credential removal at a
//! higher signed sequence cannot be rolled back through wallet commands. The
//! witness load compares only.

use crate::error::{ApprovalFailure, WalletError};
use crate::mainnet::verified_policy::VerifiedPolicy;
use crate::policy::v1::PolicyStateStore;
use crate::policy::v1::verified::{OwnerKeySource, PinMode, PolicyLoad, load_verified_policy};
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

/// Whether two verified policies have the same sequence, digest, and owner.
#[must_use]
pub fn same_policy(a: &VerifiedPolicy, b: &VerifiedPolicy) -> bool {
    a.sequence() == b.sequence() && a.digest() == b.digest() && a.owner() == b.owner()
}

fn unavailable(code: &str) -> WalletError {
    tracing::debug!(code, "mainnet approval policy unavailable");
    WalletError::Approval(ApprovalFailure::PresencePolicyUnavailable)
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
    /// `approval.presence_policy_unavailable` when any step the module
    /// documents fails.
    pub fn load_current(&self) -> Result<CurrentMainnetApprovalPolicy, WalletError> {
        self.load(PinMode::Advance)
    }

    /// Loads the current policy and compares it with the pin without writing
    /// the pin or creating a lock file.
    ///
    /// # Errors
    ///
    /// As [`Self::load_current`].
    pub fn load_current_compare_only(&self) -> Result<CurrentMainnetApprovalPolicy, WalletError> {
        self.load(PinMode::CompareOnly)
    }

    fn load(&self, mode: PinMode) -> Result<CurrentMainnetApprovalPolicy, WalletError> {
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
        let owner = read_owner_key(&profile)?;
        let policy_path = crate::profile::schema::default_policy_dir()
            .map_err(|_| unavailable("policy.state_dir"))?
            .join(format!("{name}.toml"));
        let window_path = crate::profile::schema::default_policy_window_state_path_for(name);
        let policy = load_verified_policy(
            &PolicyLoad {
                path: &policy_path,
                profile: &profile,
                profile_name: name,
                owner_pubkey: &owner,
                owner_source: OwnerKeySource::Keyring,
                window_path: &window_path,
            },
            PolicyStateStore::new(),
            mode,
        )
        .map_err(|error| unavailable(error.wire_code()))?;
        crate::mainnet::enablement::verify_enablement_bindings(
            &policy,
            name,
            &profile,
            &profile_dir,
            &crate::mainnet::enablement::read_enablement_nonce,
        )
        .map_err(|error| unavailable(error.code()))?;
        if policy
            .mainnet()
            .is_none_or(|body| body.approval_credentials.is_empty())
        {
            return Err(unavailable("policy.approval_credentials"));
        }
        Ok(CurrentMainnetApprovalPolicy { profile, policy })
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
