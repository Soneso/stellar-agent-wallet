//! Consent fixtures opted out of every kind's delivery enforcement.

use stellar_agent_core::approval::witness::ApprovedKind;
use stellar_agent_network::policy_state::approvals::ConsentEvidenceDisableGuard;

/// The four approval kinds, all of which the production capability lists.
/// The listener and `approve --id` tests run each kind's enforced routes,
/// and the activation matrix rows assert that the compiled kind list
/// enforces each, so a kind dropped from that list fails them by name.
pub(crate) fn listed_kinds() -> Vec<ApprovedKind> {
    vec![
        ApprovedKind::Payment,
        ApprovedKind::Claim,
        ApprovedKind::Trustline,
        ApprovedKind::X402Payment,
    ]
}

/// A fixture whose opt-outs keep the legacy approval paths of its profile
/// unenforced for every kind. A test's later enforcement guard overrides
/// them; [`Self::enforce_listed`] restores the compiled kind capabilities.
pub(crate) struct Unenforced<T> {
    inner: T,
    unenforced: Vec<ConsentEvidenceDisableGuard>,
}

impl<T> Unenforced<T> {
    /// Wraps `inner`, opting `profile` out of every kind.
    pub(crate) fn new(inner: T, profile: &str) -> Self {
        Self {
            inner,
            unenforced: ConsentEvidenceDisableGuard::every_kind(profile),
        }
    }

    /// Drops the opt-outs, so the compiled kind capabilities decide.
    pub(crate) fn enforce_listed(&mut self) {
        self.unenforced.clear();
    }
}

impl<T> std::ops::Deref for Unenforced<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.inner
    }
}

impl<T> std::ops::DerefMut for Unenforced<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}
