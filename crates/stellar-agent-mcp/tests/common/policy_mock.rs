//! Shared policy-engine mocks for MCP integration tests.

use std::sync::Arc;

use stellar_agent_core::policy::v1::{
    AccountIdentityView, AccountReservesView, CounterpartyCacheView, Sep10SessionView,
    Sep45SessionView,
};
use stellar_agent_core::policy::{
    ApprovalRequest, Decision, DenyReason, PolicyEngine, PolicyError, ToolDescriptor,
};
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_mcp::server::WalletServer;
use stellar_agent_test_support::keyring_mock;

pub struct MockPolicyEngine {
    result: Result<Decision, PolicyError>,
}

#[allow(
    dead_code,
    reason = "shared integration-test helper; each test binary uses a different constructor subset"
)]
impl MockPolicyEngine {
    /// Returns `Decision::Allow`.
    pub fn allow() -> Self {
        Self {
            result: Ok(Decision::Allow),
        }
    }

    /// Returns `Decision::Deny(DenyReason::NoMatchingRule)`.
    pub fn deny_no_matching_rule() -> Self {
        Self {
            result: Ok(Decision::Deny(DenyReason::NoMatchingRule)),
        }
    }

    /// Returns `Decision::Deny(DenyReason::ExplicitRuleDeny)`.
    pub fn deny_explicit_rule() -> Self {
        Self {
            result: Ok(Decision::Deny(DenyReason::ExplicitRuleDeny)),
        }
    }

    /// Returns `Decision::RequireApproval` with a deterministic test nonce.
    pub fn require_approval() -> Self {
        Self {
            result: Ok(Decision::RequireApproval(ApprovalRequest::new(
                "test-require-nonce".into(),
                120,
            ))),
        }
    }
}

impl PolicyEngine for MockPolicyEngine {
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
        self.result.clone()
    }
}

/// Returns a testnet `WalletServer` with the given engine injected AND
/// `rpc_url` set to a caller-supplied endpoint (typically a local wiremock
/// server).
///
/// The commit tools refuse a mainnet profile before their policy gate, so the
/// engine verdicts these tests pin are reached on testnet. Commit-phase policy
/// gates fetch the source `account_view` BEFORE evaluating policy (feeds
/// `minimum_reserve`). A test that reaches the commit gate therefore performs
/// a real RPC round-trip, even when the injected `PolicyEngine` ignores its
/// `account_view` argument entirely (as `MockPolicyEngine` does). Pointing
/// `rpc_url` at a local mock keeps that round-trip fast and deterministic.
#[allow(
    dead_code,
    reason = "shared integration-test helper; most test binaries that include `common` do not call it"
)]
pub fn testnet_server_with_engine_and_rpc(
    engine: impl PolicyEngine + 'static,
    rpc_url: &str,
) -> WalletServer {
    keyring_mock::install().expect("mock keyring install");
    let profile = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
        .rpc_url(rpc_url)
        .with_noop_engine()
        .build();
    let mut server = WalletServer::new(profile).expect("WalletServer::new");
    server.set_policy_engine_for_test(Arc::new(engine));
    server
}
