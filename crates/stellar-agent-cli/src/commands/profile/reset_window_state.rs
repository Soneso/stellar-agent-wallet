//! `stellar-agent profile reset-window-state <name> --reason <reason>` —
//! re-initialise the persisted policy-window-state store to empty.
//!
//! # Command-group placement
//!
//! Placed under `profile` (not a new top-level `policy` group): every other
//! per-profile keyring/state lifecycle command (`enroll-*`, `rotate-*-key`,
//! `sign-policy`) already lives here, and this command has the identical
//! shape (load profile → keyring/state op → audit row) as the `rotate-*-key`
//! siblings. Introducing a new top-level group for one command would fragment
//! an already-established taxonomy without a second command to justify it.
//!
//! # When to use
//!
//! The window-state store fails closed on an unreadable, tampered
//! (HMAC-mismatched), or unparseable file: `per_period_cap` / `rate_limit` /
//! `bundle_per_period_cap` / `bundle_rate_limit` criteria deny every call with
//! `CriterionEvaluationFailed` until the store is recovered. This command is
//! that recovery path — it discards accumulated history (the operator loses
//! period-cap continuity for the reset profile) rather than attempting
//! partial repair of a file whose integrity cannot be established.
//!
//! # Audit-row ordering
//!
//! The `PolicyWindowStateReset` audit row is emitted BEFORE the store
//! mutation, not after. The row records the OPERATOR'S RESET REQUEST; the
//! store file's post-mutation state is the outcome that request produced,
//! not a precondition for recording that it was made. A crash between the
//! row write and the file mutation leaves a request row with an unmodified
//! store — recoverable simply by re-running the command (the row write is
//! append-only and idempotent to repeat; the store mutation is idempotent
//! too, since reset unconditionally re-initialises rather than requiring a
//! specific starting state). The alternative ordering (mutate first, audit
//! second) would leave a crash between the two with a MUTATED store and NO
//! record of why — the reset that just discarded the operator's accumulated
//! history would be invisible to `audit verify`.
//!
//! # Output (JSON envelope)
//!
//! On success:
//!
//! ```json
//! {
//!   "ok": true,
//!   "data": {
//!     "profile": "default",
//!     "reset": true,
//!     "reason": "corrupt-file recovery"
//!   },
//!   "request_id": "..."
//! }
//! ```
//!
//! # Errors
//!
//! Returns exit code `1` when the profile cannot be loaded or the store
//! reset fails.

use clap::{ArgGroup, Args};
use serde::Serialize;
use stellar_agent_core::audit_log::AuditEntry;
use stellar_agent_core::audit_log::KeyPurpose;
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::{InternalError, WalletError};
use stellar_agent_network::keyring::init_platform_keyring_store;
use stellar_agent_network::policy_state::PersistedWindowStore;
use uuid::Uuid;

use crate::common::profile_access::{
    load_profile_reconciled_by_requested_name, profile_access_envelope,
};
use crate::common::render;

use crate::commands::value_audit::emit_value_audit_row;

use super::audit_emit::emit_keyring_key_written;

/// Arguments for `stellar-agent profile reset-window-state`.
#[derive(Debug, Args)]
#[non_exhaustive]
#[command(group(ArgGroup::new("profile_target").args(["name", "profile"]).required(true)))]
pub(crate) struct ResetWindowStateArgs {
    /// Profile name whose policy-window-state store should be reset, positional
    /// form.
    ///
    /// Exactly one of this positional `NAME` or the `--profile <NAME>` flag is
    /// required; supplying both, or neither, is a usage error.
    #[arg(value_name = "NAME")]
    pub(crate) name: Option<String>,

    /// Profile name whose policy-window-state store should be reset, flag form;
    /// an alternative to the positional `NAME`.
    ///
    /// Exactly one of the positional `NAME` or this `--profile <NAME>` flag is
    /// required; supplying both, or neither, is a usage error.
    #[arg(long, value_name = "NAME")]
    pub(crate) profile: Option<String>,

    /// Operator-supplied reason for the reset, recorded in the audit row
    /// (e.g. `"corrupt-file recovery"`).
    #[arg(long)]
    pub(crate) reason: String,
}

impl ResetWindowStateArgs {
    /// Returns the resolved profile name.
    ///
    /// The clap arg group over the positional `NAME` and `--profile` is
    /// `required` and mutually exclusive, so a parsed invocation sets exactly
    /// one of the two fields; this returns whichever was supplied.
    pub(super) fn profile_name(&self) -> &str {
        self.name
            .as_deref()
            .or(self.profile.as_deref())
            .unwrap_or_default()
    }
}

/// Success payload for the `reset-window-state` envelope.
#[derive(Debug, Serialize)]
struct ResetWindowStateData {
    /// Name of the profile whose window-state store was reset.
    profile: String,
    /// Always `true` on success.
    reset: bool,
    /// The operator-supplied reason, echoed back.
    reason: String,
}

/// Runs `stellar-agent profile reset-window-state <name> --reason <reason>`.
///
/// Returns `0` on success, `1` on error.
///
/// # Errors
///
/// Never returns `Err` — errors are captured into the exit code.
///
/// # Panics
///
/// Never panics.
pub async fn run(args: &ResetWindowStateArgs) -> i32 {
    let profile = match load_profile_reconciled_by_requested_name(args.profile_name(), None) {
        Ok(p) => p,
        Err(e) => {
            tracing::debug!(profile = %args.profile_name(), error = %e, "profile access refused");
            render::render_json(&profile_access_envelope(&e, args.profile_name()));
            return 1;
        }
    };

    if let Err(e) = init_platform_keyring_store() {
        render::render_json(&Envelope::err(&e));
        return 1;
    }

    let store = PersistedWindowStore::for_profile(args.profile_name());
    let request_id = Uuid::new_v4().to_string();

    // Audit row FIRST: records the operator's reset request, independent of
    // whether the store mutation below succeeds. See the module docs'
    // "Audit-row ordering" section.
    let entry = AuditEntry::new_policy_window_state_reset(
        "profile_reset_window_state",
        args.profile_name(),
        &args.reason,
        &request_id,
    );
    emit_value_audit_row(&profile, args.profile_name(), entry);

    let mint_outcome = match store.reset(&profile) {
        Ok(outcome) => outcome,
        Err(e) => {
            let err = WalletError::Internal(InternalError::UnexpectedState {
                detail: format!("policy_window_state.reset_failed: {e}"),
            });
            render::render_json(&Envelope::err(&err));
            return 1;
        }
    };

    // Reset lazily mints the key on first use, exactly as a normal record
    // would — report it the same way the rotate-* commands do. This row
    // stays AFTER the mutation: it reports what `reset` actually did, not
    // the operator's request.
    if mint_outcome.newly_minted {
        emit_keyring_key_written(
            &profile,
            args.profile_name(),
            "profile_reset_window_state",
            KeyPurpose::PolicyWindowStateHmac,
            &profile.policy_window_state_key_id,
            None,
            &request_id,
        );
    }

    render::render_json(&Envelope::ok(ResetWindowStateData {
        profile: args.profile_name().to_owned(),
        reset: true,
        reason: args.reason.clone(),
    }));
    0
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use clap::Parser;
    use clap::error::ErrorKind;
    use serial_test::serial;

    use super::*;

    /// Local flatten wrapper so the `ResetWindowStateArgs` clap contract can be
    /// parsed in isolation from the full command tree. The required `--reason`
    /// is supplied in every case so the only variable under test is the
    /// profile-target group.
    #[derive(Debug, Parser)]
    struct Wrap {
        #[command(flatten)]
        args: ResetWindowStateArgs,
    }

    #[test]
    fn positional_name_is_accepted() {
        let w = Wrap::try_parse_from(["prog", "acme", "--reason", "recovery"])
            .expect("positional parses");
        assert_eq!(w.args.profile_name(), "acme");
    }

    #[test]
    fn profile_flag_is_accepted() {
        let w = Wrap::try_parse_from(["prog", "--profile", "acme", "--reason", "recovery"])
            .expect("flag parses");
        assert_eq!(w.args.profile_name(), "acme");
    }

    #[test]
    fn both_positional_and_flag_is_a_conflict() {
        let err =
            Wrap::try_parse_from(["prog", "acme", "--profile", "other", "--reason", "recovery"])
                .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn neither_positional_nor_flag_is_missing_required() {
        let err = Wrap::try_parse_from(["prog", "--reason", "recovery"]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
    }

    #[tokio::test]
    #[serial]
    async fn reset_window_state_nonexistent_profile_returns_exit_1() {
        let args = ResetWindowStateArgs {
            name: Some("__nonexistent_reset_window_state__".to_owned()),
            profile: None,
            reason: "test".to_owned(),
        };
        let code = run(&args).await;
        assert_eq!(code, 1);
    }
}
