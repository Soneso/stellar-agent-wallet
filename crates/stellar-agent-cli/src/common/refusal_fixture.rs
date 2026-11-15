//! Branch-specific command refusal fixtures.

#![allow(clippy::unwrap_used, reason = "fixture assertions")]

use super::test_support::EnvGuard;

/// Storage and a local connection counter for command refusal tests.
pub(crate) struct RefusalFixture {
    _home: stellar_agent_test_support::StellarAgentHomeGuard,
    _environment: Vec<EnvGuard>,
    pub(crate) sandbox: stellar_agent_test_support::sandbox::StateSandbox,
    pub(crate) rpc: stellar_agent_test_support::ConnectionCounter,
}

impl RefusalFixture {
    /// Clears wallet overlays and signer inputs under the unnamed serial lock.
    pub(crate) fn new() -> Self {
        let mut environment: Vec<_> = std::env::vars_os()
            .filter_map(|(key, _)| key.into_string().ok())
            .filter(|key| {
                key.trim()
                    .to_ascii_uppercase()
                    .starts_with("STELLAR_AGENT_")
            })
            .map(EnvGuard::cleared)
            .collect();
        for name in [
            "__UNSET_ENROLL_OWNER_KEY_VAR__",
            "__UNSET_ENROLL_SIGNER_VAR__",
            "__UNSET_SIGN_POLICY_VAR__",
            "__STELLAR_AGENT_RULES_ADD_POLICY_DUMMY",
            "__STELLAR_AGENT_RULES_SET_SPENDING_LIMIT_DUMMY",
            "__STELLAR_AGENT_SIGNERS_TEST_DUMMY_VAR",
            "__STELLAR_AGENT_SIGNERS_ED25519_DUMMY",
            "__EXEC_TEST_FEE_PAYER_RUNTIME",
            "__EXEC_TEST_RULE_SIGNER_RUNTIME",
        ] {
            environment.push(EnvGuard::cleared(name.to_owned()));
        }
        let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        assert!(
            sandbox
                .path()
                .join(stellar_agent_test_support::sandbox::MARKER)
                .is_file(),
            "owned wallet root is marked before the home guard"
        );
        let home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
        let rpc = stellar_agent_test_support::ConnectionCounter::start().unwrap();
        super::render::take_rendered_for_test();
        Self {
            _home: home,
            _environment: environment,
            sandbox,
            rpc,
        }
    }

    /// Requires one branch-specific failure envelope and no endpoint contact.
    pub(crate) fn assert_refusal(&self, code: Option<&str>, details: &[&str]) {
        assert_refusal_envelopes(&super::render::take_rendered_for_test(), code, details);
        assert_eq!(
            self.rpc.accepted().unwrap(),
            0,
            "refusal must precede network access"
        );
    }
}

/// Checks the same failure contract for collected and real-stream envelopes.
pub(crate) fn assert_refusal_envelopes(
    envelopes: &[serde_json::Value],
    code: Option<&str>,
    details: &[&str],
) {
    assert_eq!(envelopes.len(), 1, "one refusal envelope: {envelopes:?}");
    let envelope = &envelopes[0];
    assert_eq!(envelope["ok"], false, "{envelope}");
    assert!(
        envelope.get("data").is_none(),
        "no success data: {envelope}"
    );
    if let Some(code) = code {
        assert_eq!(envelope["error"]["code"], code, "refusal code: {envelope}");
    }
    let message = envelope["error"]["message"].as_str().unwrap();
    for detail in details {
        assert!(
            message.contains(detail),
            "refusal detail {detail:?}: {envelope}"
        );
    }
}
