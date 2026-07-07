//! SEP-10 session-active policy criterion.
//!
//! [`Sep10SessionActiveCriterion`] verifies that an active SEP-10 session
//! exists for the agent's account (as identified by the profile) before
//! allowing a tool call.
//!
//! # TOML shape
//!
//! ```toml
//! { kind = "sep10_session_active" }
//! ```
//!
//! # Logic
//!
//! ```text
//! if ctx.sep10_sessions is None
//!     → Err(CriterionEvaluationFailed)   [fail-closed; view required]
//!
//! let account_id = ctx.profile.account
//! let now_unix   = system_time_unix_secs()
//!
//! if ctx.sep10_sessions.is_active(account_id, now_unix)
//!     → Ok(None)                          [pass; active session present]
//!
//! else
//!     → Ok(Some(DenyReason::Sep10SessionMissing { account_id }))
//! ```
//!
//! # Fail-closed posture
//!
//! When the criterion is configured:
//!
//! - A missing `sep10_sessions` view is an evaluator error — the criterion
//!   cannot determine session state without the view.  The operator configured
//!   this criterion, so the view MUST be wired at the dispatch site.  Absent
//!   view silently passing would bypass the session guard entirely.
//!
//! # Account identity
//!
//! The criterion checks `ctx.profile.account` — the agent's own G-strkey.
//! SEP-10 sessions are issued to the requesting account by the anchor, so the
//! relevant identity is the agent's profile account, not a counterparty.
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
// Sep10SessionActiveCriterion
// ─────────────────────────────────────────────────────────────────────────────

/// Verifies that an active SEP-10 session exists for the agent's profile
/// account before permitting the tool call.
///
/// Configured with `{ kind = "sep10_session_active" }` in the policy TOML.
/// No additional fields.
///
/// # Missing view (fail-closed)
///
/// When `ctx.sep10_sessions` is `None`, the criterion returns
/// [`PolicyError::CriterionEvaluationFailed`] — the operator configured this
/// criterion so the session view MUST be wired at the dispatch site.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::policy::v1::criteria::sep10_session_active::Sep10SessionActiveCriterion;
/// use stellar_agent_core::policy::v1::criteria::Criterion;
///
/// let criterion = Sep10SessionActiveCriterion::new();
/// assert_eq!(criterion.kind(), "sep10_session_active");
/// ```
#[derive(Debug, Clone)]
pub struct Sep10SessionActiveCriterion;

impl Sep10SessionActiveCriterion {
    /// Constructs a new [`Sep10SessionActiveCriterion`].
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::policy::v1::criteria::sep10_session_active::Sep10SessionActiveCriterion;
    /// use stellar_agent_core::policy::v1::criteria::Criterion as _;
    ///
    /// let c = Sep10SessionActiveCriterion::new();
    /// assert_eq!(c.kind(), "sep10_session_active");
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for Sep10SessionActiveCriterion {
    fn default() -> Self {
        Self::new()
    }
}

impl Criterion for Sep10SessionActiveCriterion {
    fn kind(&self) -> &'static str {
        "sep10_session_active"
    }

    /// Evaluates the SEP-10 session-active guard.
    ///
    /// Returns `Ok(None)` when a valid (non-expired) SEP-10 session exists for
    /// the profile account.
    ///
    /// Returns `Ok(Some(DenyReason::Sep10SessionMissing { account_id }))` when
    /// the session is absent, expired, or otherwise inactive.
    ///
    /// # Errors
    ///
    /// - [`PolicyError::CriterionEvaluationFailed`] when `ctx.sep10_sessions`
    ///   is `None` — the criterion requires a session view.  **Fail-closed**:
    ///   absent view does not silently bypass the session guard.
    fn evaluate(&self, ctx: &EvalContext<'_>) -> Result<Option<DenyReason>, PolicyError> {
        // Fail-closed: sep10_sessions = None means the dispatch site has not
        // injected a session view.  Without it we cannot verify session state.
        // Silently passing would allow bypassing the guard.
        let sessions =
            ctx.sep10_sessions
                .ok_or_else(|| PolicyError::CriterionEvaluationFailed {
                    detail: format!(
                        "sep10_session_active criterion configured for tool '{}' but \
                         sep10_sessions view was not populated by the dispatch site; \
                         EvalContext::with_sep10_sessions() required",
                        ctx.tool.name
                    ),
                })?;

        // The session is checked for the agent's profile account — the entity
        // that authenticates to the anchor via SEP-10.
        let account_id = &ctx.profile.mcp_signer_default.account;

        // Clock anchor: seconds since UNIX epoch.  Fall back to u64::MAX on
        // anomalous pre-epoch clocks — always-expired is a conservative,
        // fail-closed choice consistent with §2.11 signing-window discipline.
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(u64::MAX);

        if sessions.is_active(account_id, now_unix) {
            return Ok(None);
        }

        // No active session: deny and surface the account_id for diagnostics.
        // The dispatch gate redacts sensitive fields before placing this value
        // on the wire.
        Ok(Some(DenyReason::Sep10SessionMissing {
            account_id: account_id.clone(),
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
    use crate::policy::v1::{EvalContext, Sep10SessionView};
    use crate::policy::{DenyReason, McpToolRegistration, PolicyError, ToolDescriptor};
    use crate::profile::schema::Profile;

    // ── Test helpers ──────────────────────────────────────────────────────────

    fn make_tool() -> ToolDescriptor {
        ToolDescriptor::from_registration(&McpToolRegistration {
            name: "stellar_pay",
            destructive_hint: true,
            read_only_hint: false,
            chain_id_required: true,
            value_kind: crate::policy::ToolValueKind::ReadOnly,
        })
    }

    fn make_profile() -> Profile {
        Profile::builder_testnet(
            "svc",
            "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN",
            "n-svc",
            "n-acct",
        )
        .build()
    }

    fn make_state_store() -> PolicyStateStore {
        PolicyStateStore::new()
    }

    // ── Mock Sep10SessionView ─────────────────────────────────────────────────

    struct AlwaysActiveView;

    impl Sep10SessionView for AlwaysActiveView {
        fn is_active(&self, _account_id: &str, _now_unix: u64) -> bool {
            true
        }
    }

    struct NeverActiveView;

    impl Sep10SessionView for NeverActiveView {
        fn is_active(&self, _account_id: &str, _now_unix: u64) -> bool {
            false
        }
    }

    struct AccountCheckingView {
        expected_account: String,
        active: bool,
    }

    impl Sep10SessionView for AccountCheckingView {
        fn is_active(&self, account_id: &str, _now_unix: u64) -> bool {
            account_id == self.expected_account && self.active
        }
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    /// Fail-closed: missing `sep10_sessions` view → `CriterionEvaluationFailed`.
    ///
    /// When the dispatch site has not wired a session view, the criterion MUST
    /// error rather than silently passing.
    #[test]
    fn missing_view_fails_closed() {
        let criterion = Sep10SessionActiveCriterion::new();
        let tool = make_tool();
        let profile = make_profile();
        let args = serde_json::Value::Null;
        let store = make_state_store();

        let ctx = EvalContext {
            tool: &tool,
            args: &args,
            profile_name: "default",
            profile: &profile,
            value: crate::policy::v1::value::ValueClass::ReadOnly,
            account_view: None,
            identity_view: None,
            quorum: None,
            counterparty_cache: None,
            sep10_sessions: None, // ← not wired
            sep45_sessions: None,
            state_store: &store,
            bundle: None,
        };

        let result = criterion.evaluate(&ctx);
        assert!(
            matches!(result, Err(PolicyError::CriterionEvaluationFailed { .. })),
            "missing sep10_sessions view must produce CriterionEvaluationFailed; got: {result:?}"
        );
        let Err(PolicyError::CriterionEvaluationFailed { detail }) = result else {
            unreachable!();
        };
        assert!(
            detail.contains("sep10_session_active"),
            "error detail must mention criterion kind: {detail}"
        );
        assert!(
            detail.contains("sep10_sessions"),
            "error detail must mention the missing field: {detail}"
        );
    }

    /// Active session → `Ok(None)` pass.
    #[test]
    fn active_session_passes() {
        let criterion = Sep10SessionActiveCriterion::new();
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
            value: crate::policy::v1::value::ValueClass::ReadOnly,
            account_view: None,
            identity_view: None,
            quorum: None,
            counterparty_cache: None,
            sep10_sessions: Some(&view),
            sep45_sessions: None,
            state_store: &store,
            bundle: None,
        };

        let result = criterion.evaluate(&ctx);
        assert!(
            matches!(result, Ok(None)),
            "active session must produce Ok(None); got: {result:?}"
        );
    }

    /// No active session → `Ok(Some(DenyReason::Sep10SessionMissing))`.
    #[test]
    fn inactive_session_denies() {
        let criterion = Sep10SessionActiveCriterion::new();
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
            value: crate::policy::v1::value::ValueClass::ReadOnly,
            account_view: None,
            identity_view: None,
            quorum: None,
            counterparty_cache: None,
            sep10_sessions: Some(&view),
            sep45_sessions: None,
            state_store: &store,
            bundle: None,
        };

        let result = criterion.evaluate(&ctx);
        assert!(
            matches!(result, Ok(Some(DenyReason::Sep10SessionMissing { .. }))),
            "inactive session must produce Sep10SessionMissing; got: {result:?}"
        );
        if let Ok(Some(DenyReason::Sep10SessionMissing { account_id })) = result {
            assert_eq!(
                account_id, profile.mcp_signer_default.account,
                "account_id in deny reason must match profile account"
            );
        }
    }

    /// The criterion passes the profile account_id (not a literal or default)
    /// to the session view.  Verified by an `AccountCheckingView` that only
    /// returns `true` for the exact profile account.
    #[test]
    fn passes_profile_account_to_view() {
        let criterion = Sep10SessionActiveCriterion::new();
        let tool = make_tool();
        let profile = make_profile();
        let args = serde_json::Value::Null;
        let store = make_state_store();

        // Active only for the exact profile account.
        let view = AccountCheckingView {
            expected_account: profile.mcp_signer_default.account.clone(),
            active: true,
        };

        let ctx = EvalContext {
            tool: &tool,
            args: &args,
            profile_name: "default",
            profile: &profile,
            value: crate::policy::v1::value::ValueClass::ReadOnly,
            account_view: None,
            identity_view: None,
            quorum: None,
            counterparty_cache: None,
            sep10_sessions: Some(&view),
            sep45_sessions: None,
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
            "GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            "n-svc",
            "n-acct",
        )
        .build();
        let ctx2 = EvalContext {
            tool: &tool,
            args: &args,
            profile_name: "default",
            profile: &other_profile,
            value: crate::policy::v1::value::ValueClass::ReadOnly,
            account_view: None,
            identity_view: None,
            quorum: None,
            counterparty_cache: None,
            sep10_sessions: Some(&view),
            sep45_sessions: None,
            state_store: &store,
            bundle: None,
        };

        assert!(
            matches!(
                criterion.evaluate(&ctx2),
                Ok(Some(DenyReason::Sep10SessionMissing { .. }))
            ),
            "criterion must deny when view returns inactive for a different account"
        );
    }

    /// `kind()` returns the exact TOML kind tag.
    #[test]
    fn kind_tag_is_stable() {
        let criterion = Sep10SessionActiveCriterion::new();
        assert_eq!(criterion.kind(), "sep10_session_active");
    }

    /// `DenyReason::Sep10SessionMissing` wire code matches the plan spec.
    #[test]
    fn deny_reason_wire_code_is_correct() {
        let r = DenyReason::Sep10SessionMissing {
            account_id: "GABC1".into(),
        };
        assert_eq!(r.code(), "sep10.session_missing");
    }
}
