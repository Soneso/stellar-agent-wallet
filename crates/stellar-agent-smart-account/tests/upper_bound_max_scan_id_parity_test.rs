//! Parity test for the cross-crate mirror of `UPPER_BOUND_MAX_SCAN_ID`.
//!
//! The canonical constant `UPPER_BOUND_MAX_SCAN_ID` lives in
//! `stellar_agent_smart_account::managers::rules` (this crate). It is
//! mirrored in `stellar_agent_core::profile::loader` to avoid a crate
//! dependency cycle (`stellar-agent-smart-account` already depends on
//! `stellar-agent-core`).
//!
//! This test asserts that the two values stay in sync. If they drift, the
//! migration-planner / `smart-account list-rules` would silently reject values
//! the manager would accept (or vice versa), creating a max-scan-id
//! enforcement gap.

use stellar_agent_core::profile::loader::MIRRORED_UPPER_BOUND_MAX_SCAN_ID;
use stellar_agent_smart_account::managers::rules::UPPER_BOUND_MAX_SCAN_ID;

#[test]
fn upper_bound_max_scan_id_parity_across_crates() {
    assert_eq!(
        MIRRORED_UPPER_BOUND_MAX_SCAN_ID, UPPER_BOUND_MAX_SCAN_ID,
        "UPPER_BOUND_MAX_SCAN_ID parity violation: \
         stellar_agent_core::profile::loader::MIRRORED_UPPER_BOUND_MAX_SCAN_ID = {MIRRORED_UPPER_BOUND_MAX_SCAN_ID} \
         but stellar_agent_smart_account::managers::rules::UPPER_BOUND_MAX_SCAN_ID = {UPPER_BOUND_MAX_SCAN_ID}. \
         Update both sites in lockstep."
    );
}
