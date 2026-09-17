//! Local startup advisories for a loaded policy's tool coverage.

use stellar_agent_core::policy::TRANSACTION_STATUS_UNMATCHED_ADVISORY_CODE;
use stellar_agent_core::policy::v1::loader::PolicyDocument;

fn omits_transaction_status(document: &PolicyDocument) -> bool {
    !document.rules.iter().any(|rule| {
        matches!(
            rule.r#match.tool.as_str(),
            "*" | "stellar_transaction_status"
        )
    })
}

/// Names a missing reconciliation tool rule without changing policy decisions.
pub(crate) fn warn_if_transaction_status_unmatched(document: &PolicyDocument, profile_name: &str) {
    if omits_transaction_status(document) {
        tracing::warn!(
            code = TRANSACTION_STATUS_UNMATCHED_ADVISORY_CODE,
            tool = "stellar_transaction_status",
            profile = profile_name,
            "v1 policy has no rule for stellar_transaction_status; timed-out submissions cannot be settled through this server"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_agent_core::policy::v1::loader::{PolicyRule, RuleMatch, ScopeId};
    use stellar_agent_core::policy::{Decision, DenyReason};

    fn document(tools: &[&str]) -> PolicyDocument {
        PolicyDocument {
            version: 1,
            scope: ScopeId::AllProfiles,
            rules: tools
                .iter()
                .map(|tool| PolicyRule {
                    r#match: RuleMatch {
                        tool: (*tool).to_owned(),
                        chain: "stellar:testnet".to_owned(),
                    },
                    criteria: Vec::new(),
                    decision: Decision::Deny(DenyReason::ExplicitRuleDeny),
                    allow_opaque_signing: false,
                })
                .collect(),
            signature: None,
        }
    }

    #[test]
    fn wildcard_tool_suppresses_the_missing_tool_advisory() {
        assert!(!omits_transaction_status(&document(&["stellar_pay", "*"])));
    }

    #[test]
    fn explicit_transaction_status_suppresses_the_missing_tool_advisory() {
        assert!(!omits_transaction_status(&document(&[
            "stellar_pay",
            "stellar_transaction_status"
        ])));
    }

    #[test]
    fn omitted_transaction_status_requires_the_advisory() {
        for tools in [
            &[][..],
            &["stellar_pay", "stellar_transaction_status_extra"][..],
        ] {
            assert!(omits_transaction_status(&document(tools)));
        }
    }
}
