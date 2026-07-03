//! Adversarial fixture: `multicall_upper_bound_assertion`.
//!
//! The amplification-defence trust-anchor is enforced by a const-context
//! assertion in `multicall.rs`:
//! `const _: () = assert!(MULTICALL_BUNDLE_CAP <= UPPER_BOUND_MULTICALL_BUNDLE_CAP);`.
//! This is a compile-time invariant — a refactor raising
//! `MULTICALL_BUNDLE_CAP` above `UPPER_BOUND_MULTICALL_BUNDLE_CAP` fails
//! at build time, never reaching runtime.
//!
//! This fixture documents the runtime-witnessable consequences of that
//! invariant (a runtime assertion is redundant with the const-context one
//! but improves discoverability for security review):
//!
//! 1. `MULTICALL_BUNDLE_CAP <= UPPER_BOUND_MULTICALL_BUNDLE_CAP` holds.
//! 2. The current values are `MULTICALL_BUNDLE_CAP = 50`,
//!    `UPPER_BOUND_MULTICALL_BUNDLE_CAP = 75`.
//!
//! # Why compile-time enforcement was chosen
//!
//! A compile-time `const _: () = assert!(...)` is preferred because:
//! - **Build-time enforcement.** A refactor violating the invariant fails
//!   the build step; a violating production binary cannot be produced.
//! - **Zero runtime cost.** No CPU cycles spent on the assertion at every
//!   invocation.
//! - **Discoverability at the constants' definition site.** Lives
//!   alongside `MULTICALL_BUNDLE_CAP` + `UPPER_BOUND_MULTICALL_BUNDLE_CAP`
//!   in `multicall.rs`, immediately next to what it guards.
//!
//! This fixture's runtime assertion is retained for discoverability under
//! `tests/smart-account-fixtures/adversarial/`.
//!
//! # Defence scope
//!
//! Amplification-defence ceiling: `MULTICALL_BUNDLE_CAP` must never
//! exceed `UPPER_BOUND_MULTICALL_BUNDLE_CAP`.

use stellar_agent_smart_account::multicall::{
    MULTICALL_BUNDLE_CAP, UPPER_BOUND_MULTICALL_BUNDLE_CAP,
};

/// `MULTICALL_BUNDLE_CAP <= UPPER_BOUND_MULTICALL_BUNDLE_CAP` invariant
/// witnessed via `const { assert!(...) }` block; the assertion is
/// evaluated at compile time (zero runtime cost) and a failure shifts
/// the violation to build-time, identical in semantics to the
/// const-context assertion in `multicall.rs`.
#[test]
fn multicall_bundle_cap_does_not_exceed_upper_bound_ceiling() {
    const {
        assert!(
            MULTICALL_BUNDLE_CAP <= UPPER_BOUND_MULTICALL_BUNDLE_CAP,
            "MULTICALL_BUNDLE_CAP must not exceed UPPER_BOUND_MULTICALL_BUNDLE_CAP \
             (amplification-defence ceiling violated)",
        );
    }
}

/// Baseline values: `MULTICALL_BUNDLE_CAP = 50`,
/// `UPPER_BOUND_MULTICALL_BUNDLE_CAP = 75`. A future intentional change to
/// either value must update this test and the rustdoc in `multicall.rs`.
#[test]
fn multicall_bundle_cap_matches_plans_33_baseline() {
    assert_eq!(MULTICALL_BUNDLE_CAP, 50, "MULTICALL_BUNDLE_CAP must be 50",);
    assert_eq!(
        UPPER_BOUND_MULTICALL_BUNDLE_CAP, 75,
        "UPPER_BOUND_MULTICALL_BUNDLE_CAP must be 75 \
         (OZ MAX_SIGNERS × MAX_POLICIES storage-entry upper bound)",
    );
}
