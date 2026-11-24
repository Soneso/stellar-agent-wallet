//! Startup advisories for a verified policy's tool coverage.

use super::{TRANSACTION_STATUS_UNMATCHED_ADVISORY_CODE, v1::PolicyEngineV1};

/// Warns when MCP cannot use the policy to reconcile timed-out submissions.
pub fn warn_if_transaction_status_unmatched(engine: &PolicyEngineV1, profile_name: &str) {
    if !engine.has_rule_for_tool("stellar_transaction_status") {
        tracing::warn!(
            code = TRANSACTION_STATUS_UNMATCHED_ADVISORY_CODE,
            tool = "stellar_transaction_status",
            profile = profile_name,
            "v1 policy has no rule for stellar_transaction_status; timed-out submissions cannot \
                be settled through this server"
        );
    }
}
