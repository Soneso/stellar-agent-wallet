//! Policy engine shared by the remote-approval browser acceptance suites.

use stellar_agent_core::policy::v1::{
    AccountIdentityView, AccountReservesView, CheckedSizing, CounterpartyCacheView, OpaqueReason,
    Sep10SessionView, Sep45SessionView, SizingOutcome, ValueClass,
};
use stellar_agent_core::policy::{
    ApprovalRequest, Decision, NoopPolicyEngine, PolicyEngine, PolicyError, ToolDescriptor,
};
use stellar_agent_core::profile::schema::Profile;

/// A policy engine that parks every dispatch as a pending approval.
///
/// The commit path sizes the approved action before it submits, so the checked
/// sizing methods delegate to [`NoopPolicyEngine`]: the action is sized as on a
/// profile that holds no window state, and the operator's decision is what the
/// suites exercise.
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
    ) -> Result<Decision, PolicyError> {
        Ok(Decision::RequireApproval(ApprovalRequest::new(
            self.reason.into(),
            600,
        )))
    }
}
