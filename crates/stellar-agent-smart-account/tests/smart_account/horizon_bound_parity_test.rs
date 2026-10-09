//! Parity tests for the cross-crate mirror of `UPPER_BOUND_HORIZON_LEDGERS`
//! and consistency of `DEFAULT_SESSION_RULE_HORIZON_LEDGERS`.
//!
//! The canonical constant `UPPER_BOUND_HORIZON_LEDGERS` lives in
//! `stellar_agent_smart_account::managers::rules` (this crate). It is
//! mirrored in `stellar_agent_core::profile::loader` as
//! `MIRRORED_UPPER_BOUND_HORIZON_LEDGERS` to avoid a crate dependency cycle
//! (`stellar-agent-smart-account` already depends on `stellar-agent-core`).
//!
//! `DEFAULT_SESSION_RULE_HORIZON_LEDGERS` must remain strictly less than
//! `UPPER_BOUND_HORIZON_LEDGERS` to ensure the default is always within the
//! safety cap range.

use stellar_agent_core::profile::loader::MIRRORED_UPPER_BOUND_HORIZON_LEDGERS;
use stellar_agent_smart_account::managers::rules::{
    DEFAULT_SESSION_RULE_HORIZON_LEDGERS, UPPER_BOUND_HORIZON_LEDGERS,
};

/// Asserts the canonical and mirrored `UPPER_BOUND_HORIZON_LEDGERS` constants
/// are identical.
///
/// If they drift, the profile loader would reject profile values the manager
/// would accept (or vice versa), creating a session-horizon enforcement gap.
/// Update both sites in lockstep.
#[test]
fn upper_bound_horizon_parity_across_crates() {
    assert_eq!(
        MIRRORED_UPPER_BOUND_HORIZON_LEDGERS, UPPER_BOUND_HORIZON_LEDGERS,
        "UPPER_BOUND_HORIZON_LEDGERS parity violation: \
         stellar_agent_core::profile::loader::MIRRORED_UPPER_BOUND_HORIZON_LEDGERS = \
         {MIRRORED_UPPER_BOUND_HORIZON_LEDGERS} but \
         stellar_agent_smart_account::managers::rules::UPPER_BOUND_HORIZON_LEDGERS = \
         {UPPER_BOUND_HORIZON_LEDGERS}. \
         Update both sites in lockstep."
    );
}

/// Asserts `DEFAULT_SESSION_RULE_HORIZON_LEDGERS` is strictly less than
/// `UPPER_BOUND_HORIZON_LEDGERS` so a default-configured wallet always
/// passes the profile-load cap check.
///
/// The comparison uses a compile-time `const` assertion so that a future
/// constant-value drift is caught at build time, not at test runtime.
#[test]
fn default_session_rule_horizon_within_upper_bound() {
    const { assert!(DEFAULT_SESSION_RULE_HORIZON_LEDGERS < UPPER_BOUND_HORIZON_LEDGERS) }
}
