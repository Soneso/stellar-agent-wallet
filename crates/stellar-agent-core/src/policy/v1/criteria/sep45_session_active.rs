//! SEP-45 session-active policy criterion.
//!
//! [`Sep45SessionActiveCriterion`] verifies that an active SEP-45 session
//! exists for the agent's contract account (as identified by the profile)
//! before allowing a tool call.
//!
//! # TOML shape
//!
//! ```toml
//! { kind = "sep45_session_active" }
//! ```
//!
//! # Logic
//!
//! ```text
//! if ctx.sep45_sessions is None
//!     → Err(CriterionEvaluationFailed)   [fail-closed; view required]
//!
//! let contract_id = ctx.profile.account
//! let now_unix    = system_time_unix_secs()
//!
//! if ctx.sep45_sessions.is_active(contract_id, now_unix)
//!     → Ok(None)                          [pass; active session present]
//!
//! else
//!     → Ok(Some(DenyReason::Sep45SessionMissing { contract_id }))
//! ```
//!
//! # Fail-closed posture
//!
//! When the criterion is configured:
//!
//! - A missing `sep45_sessions` view is an evaluator error — the criterion
//!   cannot determine session state without the view.  The operator configured
//!   this criterion, so the view MUST be wired at the dispatch site.  Absent
//!   view silently passing would bypass the session guard entirely.
//!
//! # Account identity
//!
//! The criterion checks `ctx.profile.account` — the agent's own account
//! strkey (may be a C-strkey for contract accounts in SEP-45 flows).
//! SEP-45 sessions are issued to the requesting contract account by the
//! anchor, so the relevant identity is the agent's profile account, not a
//! counterparty.
//!
//! # Clock source
//!
//! The `now_unix` timestamp is sourced from [`std::time::SystemTime`].  The
//! implementation falls back to `u64::MAX` (always expired) on clock-before-
//! epoch anomalies — a conservative fail-closed choice.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::policy::v1::EvalContext;
use crate::policy::v1::criteria::Criterion;
use crate::policy::{DenyReason, PolicyError};

// ─────────────────────────────────────────────────────────────────────────────
// Sep45SessionActiveCriterion
// ─────────────────────────────────────────────────────────────────────────────

/// Verifies that an active SEP-45 session exists for the agent's profile
/// account before permitting the tool call.
///
/// Configured with `{ kind = "sep45_session_active" }` in the policy TOML.
/// No additional fields.
///
/// # Missing view (fail-closed)
///
/// When `ctx.sep45_sessions` is `None`, the criterion returns
/// [`PolicyError::CriterionEvaluationFailed`] — the operator configured this
/// criterion so the session view MUST be wired at the dispatch site.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::policy::v1::criteria::sep45_session_active::Sep45SessionActiveCriterion;
/// use stellar_agent_core::policy::v1::criteria::Criterion;
///
/// let criterion = Sep45SessionActiveCriterion::new();
/// assert_eq!(criterion.kind(), "sep45_session_active");
/// ```
#[derive(Debug, Clone)]
pub struct Sep45SessionActiveCriterion;

impl Sep45SessionActiveCriterion {
    /// Constructs a new [`Sep45SessionActiveCriterion`].
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::policy::v1::criteria::sep45_session_active::Sep45SessionActiveCriterion;
    /// use stellar_agent_core::policy::v1::criteria::Criterion as _;
    ///
    /// let c = Sep45SessionActiveCriterion::new();
    /// assert_eq!(c.kind(), "sep45_session_active");
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for Sep45SessionActiveCriterion {
    fn default() -> Self {
        Self::new()
    }
}

impl Criterion for Sep45SessionActiveCriterion {
    fn kind(&self) -> &'static str {
        "sep45_session_active"
    }

    /// Evaluates the SEP-45 session-active guard.
    ///
    /// Returns `Ok(None)` when a valid (non-expired) SEP-45 session exists for
    /// the profile account.
    ///
    /// Returns `Ok(Some(DenyReason::Sep45SessionMissing { contract_id }))` when
    /// the session is absent, expired, or otherwise inactive.
    ///
    /// # Errors
    ///
    /// - [`PolicyError::CriterionEvaluationFailed`] when `ctx.sep45_sessions`
    ///   is `None` — the criterion requires a session view.  **Fail-closed**:
    ///   absent view does not silently bypass the session guard.
    fn evaluate(&self, ctx: &EvalContext<'_>) -> Result<Option<DenyReason>, PolicyError> {
        // Fail-closed: sep45_sessions = None means the dispatch site has not
        // injected a session view.  Without it we cannot verify session state.
        // Silently passing would allow bypassing the guard.
        let sessions =
            ctx.sep45_sessions
                .ok_or_else(|| PolicyError::CriterionEvaluationFailed {
                    detail: format!(
                        "sep45_session_active criterion configured for tool '{}' but \
                         sep45_sessions view was not populated by the dispatch site; \
                         EvalContext::with_sep45_sessions() required",
                        ctx.tool.name
                    ),
                })?;

        // The session is checked for the agent's profile account — the entity
        // that authenticates to the anchor via SEP-45.
        let contract_id = &ctx.profile.mcp_signer_default.account;

        // Clock anchor: seconds since UNIX epoch.  Fall back to u64::MAX on
        // anomalous pre-epoch clocks — always-expired is a conservative,
        // fail-closed choice consistent with §2.11 signing-window discipline.
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(u64::MAX);

        if sessions.is_active(contract_id, now_unix) {
            return Ok(None);
        }

        // No active session: deny and surface the contract_id for diagnostics.
        // The dispatch gate redacts sensitive fields before placing this value
        // on the wire.
        Ok(Some(DenyReason::Sep45SessionMissing {
            contract_id: contract_id.clone(),
        }))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only assertions"
    )]

    use super::*;
    use crate::policy::v1::criteria::state_store::PolicyStateStore;
    use crate::policy::v1::{EvalContext, Sep45SessionView};
    use crate::policy::{DenyReason, McpToolRegistration, PolicyError, ToolDescriptor};
    use crate::profile::schema::Profile;

    // ── Test helpers ──────────────────────────────────────────────────────────

    fn make_tool() -> ToolDescriptor {
        ToolDescriptor::from_registration(&McpToolRegistration {
            name: "stellar_pay",
            destructive_hint: true,
            read_only_hint: false,
            chain_id_required: true,
        })
    }

    fn make_profile() -> Profile {
        Profile::builder_testnet(
            "svc",
            "CAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN",
            "n-svc",
            "n-acct",
        )
        .build()
    }

    fn make_state_store() -> PolicyStateStore {
        PolicyStateStore::new()
    }

    // ── Mock Sep45SessionView ─────────────────────────────────────────────────

    struct AlwaysActiveView;

    impl Sep45SessionView for AlwaysActiveView {
        fn is_active(&self, _contract_id: &str, _now_unix: u64) -> bool {
            true
        }
    }

    struct NeverActiveView;

    impl Sep45SessionView for NeverActiveView {
        fn is_active(&self, _contract_id: &str, _now_unix: u64) -> bool {
            false
        }
    }

    struct ContractCheckingView {
        expected_contract: String,
        active: bool,
    }

    impl Sep45SessionView for ContractCheckingView {
        fn is_active(&self, contract_id: &str, _now_unix: u64) -> bool {
            contract_id == self.expected_contract && self.active
        }
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    /// Fail-closed: missing `sep45_sessions` view → `CriterionEvaluationFailed`.
    ///
    /// When the dispatch site has not wired a session view, the criterion MUST
    /// error rather than silently passing.
    #[test]
    fn missing_view_fails_closed() {
        let criterion = Sep45SessionActiveCriterion::new();
        let tool = make_tool();
        let profile = make_profile();
        let args = serde_json::Value::Null;
        let store = make_state_store();

        let ctx = EvalContext {
            tool: &tool,
            args: &args,
            profile_name: "default",
            profile: &profile,
            account_view: None,
            identity_view: None,
            quorum: None,
            counterparty_cache: None,
            sep10_sessions: None,
            sep45_sessions: None, // ← not wired
            state_store: &store,
            bundle: None,
        };

        let result = criterion.evaluate(&ctx);
        assert!(
            matches!(result, Err(PolicyError::CriterionEvaluationFailed { .. })),
            "missing sep45_sessions view must produce CriterionEvaluationFailed; got: {result:?}"
        );
        let Err(PolicyError::CriterionEvaluationFailed { detail }) = result else {
            unreachable!();
        };
        assert!(
            detail.contains("sep45_session_active"),
            "error detail must mention criterion kind: {detail}"
        );
        assert!(
            detail.contains("sep45_sessions"),
            "error detail must mention the missing field: {detail}"
        );
    }

    /// Active session → `Ok(None)` pass.
    #[test]
    fn active_session_passes() {
        let criterion = Sep45SessionActiveCriterion::new();
        let tool = make_tool();
        let profile = make_profile();
        let args = serde_json::Value::Null;
        let store = make_state_store();
        let view = AlwaysActiveView;

        let ctx = EvalContext {
            tool: &tool,
            args: &args,
            profile_name: "default",
            profile: &profile,
            account_view: None,
            identity_view: None,
            quorum: None,
            counterparty_cache: None,
            sep10_sessions: None,
            sep45_sessions: Some(&view),
            state_store: &store,
            bundle: None,
        };

        let result = criterion.evaluate(&ctx);
        assert!(
            matches!(result, Ok(None)),
            "active session must produce Ok(None); got: {result:?}"
        );
    }

    /// No active session → `Ok(Some(DenyReason::Sep45SessionMissing))`.
    #[test]
    fn inactive_session_denies() {
        let criterion = Sep45SessionActiveCriterion::new();
        let tool = make_tool();
        let profile = make_profile();
        let args = serde_json::Value::Null;
        let store = make_state_store();
        let view = NeverActiveView;

        let ctx = EvalContext {
            tool: &tool,
            args: &args,
            profile_name: "default",
            profile: &profile,
            account_view: None,
            identity_view: None,
            quorum: None,
            counterparty_cache: None,
            sep10_sessions: None,
            sep45_sessions: Some(&view),
            state_store: &store,
            bundle: None,
        };

        let result = criterion.evaluate(&ctx);
        assert!(
            matches!(result, Ok(Some(DenyReason::Sep45SessionMissing { .. }))),
            "inactive session must produce Sep45SessionMissing; got: {result:?}"
        );
        if let Ok(Some(DenyReason::Sep45SessionMissing { contract_id })) = result {
            assert_eq!(
                contract_id, profile.mcp_signer_default.account,
                "contract_id in deny reason must match profile account"
            );
        }
    }

    /// The criterion passes the profile account (not a literal or default)
    /// to the session view.  Verified by a `ContractCheckingView` that only
    /// returns `true` for the exact profile account.
    #[test]
    fn passes_profile_account_to_view() {
        let criterion = Sep45SessionActiveCriterion::new();
        let tool = make_tool();
        let profile = make_profile();
        let args = serde_json::Value::Null;
        let store = make_state_store();

        // Active only for the exact profile account.
        let view = ContractCheckingView {
            expected_contract: profile.mcp_signer_default.account.clone(),
            active: true,
        };

        let ctx = EvalContext {
            tool: &tool,
            args: &args,
            profile_name: "default",
            profile: &profile,
            account_view: None,
            identity_view: None,
            quorum: None,
            counterparty_cache: None,
            sep10_sessions: None,
            sep45_sessions: Some(&view),
            state_store: &store,
            bundle: None,
        };

        // Must pass because the view is active for the exact profile account.
        assert!(
            matches!(criterion.evaluate(&ctx), Ok(None)),
            "criterion must pass when view confirms profile account has active session"
        );

        // A different profile account → deny.
        let other_profile = Profile::builder_testnet(
            "svc",
            "CBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            "n-svc",
            "n-acct",
        )
        .build();
        let ctx2 = EvalContext {
            tool: &tool,
            args: &args,
            profile_name: "default",
            profile: &other_profile,
            account_view: None,
            identity_view: None,
            quorum: None,
            counterparty_cache: None,
            sep10_sessions: None,
            sep45_sessions: Some(&view),
            state_store: &store,
            bundle: None,
        };

        assert!(
            matches!(
                criterion.evaluate(&ctx2),
                Ok(Some(DenyReason::Sep45SessionMissing { .. }))
            ),
            "criterion must deny when view returns inactive for a different account"
        );
    }

    /// `kind()` returns the exact TOML kind tag.
    #[test]
    fn kind_tag_is_stable() {
        let criterion = Sep45SessionActiveCriterion::new();
        assert_eq!(criterion.kind(), "sep45_session_active");
    }

    /// `DenyReason::Sep45SessionMissing` wire code matches the plan spec.
    #[test]
    fn deny_reason_wire_code_is_correct() {
        let r = DenyReason::Sep45SessionMissing {
            contract_id: "CABC1".into(),
        };
        assert_eq!(r.code(), "sep45.session_missing");
    }
}
