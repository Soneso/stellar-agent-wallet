//! Policy engine and payment-recovery policy shared by the remote-approval
//! browser acceptance suites.

use stellar_agent_core::policy::v1::{
    AccountIdentityView, AccountReservesView, CheckedSizing, CounterpartyCacheView, OpaqueReason,
    Sep10SessionView, Sep45SessionView, SizingOutcome, ValueClass,
};
use stellar_agent_core::policy::{
    ApprovalRequest, Decision, NoopPolicyEngine, PolicyEngine, PolicyError, ToolDescriptor,
};
use stellar_agent_core::profile::schema::Profile;

/// A signed, verified allow-all policy for `server`'s approval profile.
///
/// A direct `stellar_pay` preparation queues a new payment approval only
/// under a verified policy, which binds the entry for recovery. A synthetic
/// engine set through `set_policy_engine_for_test` carries none, so a suite
/// that queues a direct payment supplies this one through
/// `set_payment_recovery_policy_for_test`.
///
/// # Panics
///
/// Panics if the fixture policy cannot be written or does not verify.
#[allow(
    dead_code,
    clippy::expect_used,
    reason = "shared fixture; a suite without a direct payment approval does not use it"
)]
#[must_use]
pub fn payment_recovery_policy(
    server: &stellar_agent_mcp::server::WalletServer,
) -> stellar_agent_core::mainnet::verified_policy::VerifiedPolicy {
    use stellar_agent_core::policy::v1::{
        PolicyStateStore,
        verified::{OwnerKeySource, PinMode, PolicyLoad, load_verified_policy},
    };
    let dir = tempfile::tempdir().expect("fixture policy directory");
    let path = dir.path().join("policy.toml");
    let name = server.profile_name_for_approval();
    let body = format!(
        "version = 1\nscope = \"profile:{name}\"\n[[rules]]\nmatch = {{ tool = \"*\", chain = \"*\" }}\ncriteria = []\ndecision = \"allow\"\n"
    );
    let profile = Profile::builder_testnet("fixture", "signer", "fixture", "nonce").build();
    let owner = ed25519_dalek::SigningKey::from_bytes(&[61; 32]);
    std::fs::write(
        &path,
        stellar_agent_core::approval::mainnet_fixtures::signed_policy_text(&body, &owner),
    )
    .expect("signed fixture policy");
    load_verified_policy(
        &PolicyLoad {
            path: &path,
            profile: &profile,
            profile_name: &name,
            owner_pubkey: &owner.verifying_key().to_bytes(),
            owner_source: OwnerKeySource::Keyring,
            window_path: &dir.path().join("window"),
        },
        PolicyStateStore::new(),
        PinMode::CompareOnly,
    )
    .expect("fixture signature verifies")
}

/// A policy engine that parks every dispatch as a pending approval.
///
/// Checked sizing delegates to [`NoopPolicyEngine`]: the action is sized as
/// on a profile that holds no window state. The commit path sizes the approved
/// action before it submits, and the operator's decision is what the suites
/// exercise.
pub struct RequireApprovalEngine {
    /// The reason the pending approval carries.
    pub reason: &'static str,
}

impl PolicyEngine for RequireApprovalEngine {
    fn record_confirmed_checked(
        &self,
        tool: &ToolDescriptor,
        profile: &Profile,
        value: &ValueClass,
    ) -> Result<SizingOutcome, PolicyError> {
        NoopPolicyEngine.record_confirmed_checked(tool, profile, value)
    }

    fn size_unvalued_call(
        &self,
        tool: &ToolDescriptor,
        profile: &Profile,
        reason: OpaqueReason,
        now_ms: u64,
    ) -> Result<SizingOutcome, PolicyError> {
        NoopPolicyEngine.size_unvalued_call(tool, profile, reason, now_ms)
    }

    fn size_no_value(
        &self,
        tool: &ToolDescriptor,
        profile: &Profile,
        now_ms: u64,
    ) -> Result<CheckedSizing, PolicyError> {
        NoopPolicyEngine.size_no_value(tool, profile, now_ms)
    }

    fn evaluate(
        &self,
        _tool: &ToolDescriptor,
        _args: &serde_json::Value,
        _profile: &Profile,
        _account_view: Option<&dyn AccountReservesView>,
        _identity_view: Option<&dyn AccountIdentityView>,
        _counterparty_cache: Option<&dyn CounterpartyCacheView>,
        _sep10_sessions: Option<&dyn Sep10SessionView>,
        _sep45_sessions: Option<&dyn Sep45SessionView>,
        _now_ms: u64,
    ) -> Result<Decision, PolicyError> {
        Ok(Decision::RequireApproval(ApprovalRequest::new(
            self.reason.into(),
            600,
        )))
    }
}
