//! Recursive `ClaimPredicate` evaluation against a Unix timestamp.
//!
//! [`evaluate`] decides whether a [`stellar_xdr::ClaimPredicate`] is
//! satisfied at a given point in time. [`derive_window`] extracts the
//! claimability time window `[valid_from, valid_until]` that is exactly
//! representable from the predicate's boolean structure, when one exists.
//!
//! # Fail-closed forms
//!
//! [`evaluate`] and [`derive_window`] both refuse (`evaluate` returns
//! [`ClaimError::PredicateUnsupported`]; `derive_window` returns `None` for
//! the affected bound) rather than guess at the following forms:
//!
//! - `BeforeRelativeTime`: stellar-core normalizes a relative predicate to an
//!   absolute one at `ClaimableBalanceEntry` creation time (CAP-23); a
//!   *stored* entry carrying `BeforeRelativeTime` is out of protocol
//!   contract and is refused rather than evaluated against an assumed
//!   reference point.
//! - `Not(None)`: the XDR schema allows a `Not` predicate with no inner
//!   predicate; this has no defined truth value.
//! - `And` / `Or` with fewer than 2 sub-predicates: the XDR schema allows
//!   `VecM<ClaimPredicate, 2>` of length 0 or 1, which stellar-core never
//!   produces; treated as malformed input.
//! - Nesting beyond [`MAX_PREDICATE_DEPTH`]: defense in depth. XDR decode
//!   already bounds recursion via
//!   `stellar_agent_xdr_limits::XDR_DECODE_MAX_DEPTH`; this explicit bound
//!   protects the evaluator independently of that decode-time limit.

use serde::{Deserialize, Serialize};
use stellar_xdr::ClaimPredicate;

use crate::error::ClaimError;

/// Maximum recursion depth the evaluator descends before refusing with
/// [`ClaimError::PredicateUnsupported`].
///
/// Defense in depth alongside `stellar_agent_xdr_limits::XDR_DECODE_MAX_DEPTH`
/// (500), which already bounds recursion at XDR-decode time.
pub const MAX_PREDICATE_DEPTH: u32 = 64;

/// The verdict of evaluating a [`ClaimPredicate`] against a point in time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PredicateVerdict {
    /// The predicate is satisfied at the evaluated time.
    Satisfied,
    /// The predicate is not satisfied at the evaluated time.
    NotSatisfied,
}

impl PredicateVerdict {
    /// Returns `true` when the verdict is [`PredicateVerdict::Satisfied`].
    #[must_use]
    pub fn is_satisfied(self) -> bool {
        matches!(self, Self::Satisfied)
    }
}

/// The claimability time window derivable from a predicate's boolean
/// structure.
///
/// Each bound is `None` when it is not exactly derivable through the
/// predicate's structure — callers must not treat `None` as "unbounded" for
/// display purposes without noting the derivation was inexact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ClaimabilityWindow {
    /// The earliest Unix time at which the predicate becomes satisfied, when
    /// exactly derivable (from a `Not(BeforeAbsoluteTime(t))` lower bound).
    pub valid_from: Option<u64>,
    /// The Unix time at which the predicate stops being satisfied, when
    /// exactly derivable (from a `BeforeAbsoluteTime(t)` upper bound).
    pub valid_until: Option<u64>,
}

/// Evaluates `predicate` against `now` (a Unix timestamp).
///
/// # Errors
///
/// Returns [`ClaimError::PredicateUnsupported`] for the fail-closed forms
/// documented at the module level.
pub fn evaluate(predicate: &ClaimPredicate, now: u64) -> Result<PredicateVerdict, ClaimError> {
    let satisfied = evaluate_depth(predicate, now, 0)?;
    Ok(if satisfied {
        PredicateVerdict::Satisfied
    } else {
        PredicateVerdict::NotSatisfied
    })
}

fn evaluate_depth(predicate: &ClaimPredicate, now: u64, depth: u32) -> Result<bool, ClaimError> {
    if depth > MAX_PREDICATE_DEPTH {
        return Err(ClaimError::PredicateUnsupported {
            detail: format!(
                "predicate nesting exceeds the evaluator's {MAX_PREDICATE_DEPTH}-level bound"
            ),
        });
    }

    match predicate {
        ClaimPredicate::Unconditional => Ok(true),

        ClaimPredicate::And(preds) => {
            if preds.len() < 2 {
                return Err(ClaimError::PredicateUnsupported {
                    detail: format!(
                        "And predicate carries {} sub-predicates; at least 2 are required",
                        preds.len()
                    ),
                });
            }
            for p in preds.iter() {
                if !evaluate_depth(p, now, depth + 1)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }

        ClaimPredicate::Or(preds) => {
            if preds.len() < 2 {
                return Err(ClaimError::PredicateUnsupported {
                    detail: format!(
                        "Or predicate carries {} sub-predicates; at least 2 are required",
                        preds.len()
                    ),
                });
            }
            for p in preds.iter() {
                if evaluate_depth(p, now, depth + 1)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }

        ClaimPredicate::Not(inner) => match inner {
            None => Err(ClaimError::PredicateUnsupported {
                detail: "Not predicate carries no inner predicate".to_owned(),
            }),
            Some(p) => Ok(!evaluate_depth(p, now, depth + 1)?),
        },

        ClaimPredicate::BeforeAbsoluteTime(t) => {
            // Compare in i128 so the u64 `now` and i64 `t` (which may be
            // negative or exceed i64::MAX when reinterpreted, though the
            // protocol never produces a negative absBefore in practice) never
            // require a lossy cast in either direction.
            Ok(i128::from(now) < i128::from(*t))
        }

        ClaimPredicate::BeforeRelativeTime(_) => Err(ClaimError::PredicateUnsupported {
            detail: "BeforeRelativeTime predicates are normalized to BeforeAbsoluteTime by \
                      stellar-core at entry-creation time (CAP-23); a stored relative \
                      predicate is out of protocol contract"
                .to_owned(),
        }),
    }
}

/// Extracts the claimability window `[valid_from, valid_until]` exactly
/// derivable from `predicate`'s boolean structure.
///
/// Returns [`ClaimabilityWindow::default`] (both bounds `None`) for any
/// structure not covered below — most notably `Or`, whose union of windows
/// is generally not itself a single interval.
///
/// Derivable forms:
/// - `BeforeAbsoluteTime(t)` with `t > 0` → `valid_until = Some(t)`.
/// - `Not(Some(BeforeAbsoluteTime(t)))` with `t > 0` → `valid_from = Some(t)`
///   (since `Not(now < t)` is `now >= t`).
/// - `And(preds)` → the intersection of each sub-predicate's derivable
///   window: `valid_from` is the maximum of the sub-windows' `valid_from`
///   values present, `valid_until` is the minimum of the sub-windows'
///   `valid_until` values present.
#[must_use]
pub fn derive_window(predicate: &ClaimPredicate) -> ClaimabilityWindow {
    derive_window_depth(predicate, 0)
}

fn derive_window_depth(predicate: &ClaimPredicate, depth: u32) -> ClaimabilityWindow {
    if depth > MAX_PREDICATE_DEPTH {
        return ClaimabilityWindow::default();
    }

    match predicate {
        ClaimPredicate::BeforeAbsoluteTime(t) => match u64::try_from(*t) {
            Ok(v) if v > 0 => ClaimabilityWindow {
                valid_until: Some(v),
                valid_from: None,
            },
            _ => ClaimabilityWindow::default(),
        },

        ClaimPredicate::Not(Some(inner)) => {
            if let ClaimPredicate::BeforeAbsoluteTime(t) = inner.as_ref()
                && let Ok(v) = u64::try_from(*t)
                && v > 0
            {
                return ClaimabilityWindow {
                    valid_from: Some(v),
                    valid_until: None,
                };
            }
            ClaimabilityWindow::default()
        }

        ClaimPredicate::And(preds) => {
            let mut valid_from: Option<u64> = None;
            let mut valid_until: Option<u64> = None;
            for p in preds.iter() {
                let w = derive_window_depth(p, depth + 1);
                if let Some(f) = w.valid_from {
                    valid_from = Some(valid_from.map_or(f, |cur| cur.max(f)));
                }
                if let Some(u) = w.valid_until {
                    valid_until = Some(valid_until.map_or(u, |cur| cur.min(u)));
                }
            }
            ClaimabilityWindow {
                valid_from,
                valid_until,
            }
        }

        _ => ClaimabilityWindow::default(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only"
    )]

    use stellar_xdr::VecM;

    use super::*;

    fn before(t: i64) -> ClaimPredicate {
        ClaimPredicate::BeforeAbsoluteTime(t)
    }

    fn not(p: ClaimPredicate) -> ClaimPredicate {
        ClaimPredicate::Not(Some(Box::new(p)))
    }

    fn and2(a: ClaimPredicate, b: ClaimPredicate) -> ClaimPredicate {
        ClaimPredicate::And(VecM::try_from(vec![a, b]).expect("2 fits VecM<_,2>"))
    }

    fn or2(a: ClaimPredicate, b: ClaimPredicate) -> ClaimPredicate {
        ClaimPredicate::Or(VecM::try_from(vec![a, b]).expect("2 fits VecM<_,2>"))
    }

    // ─── Unconditional ─────────────────────────────────────────────────────

    #[test]
    fn unconditional_is_always_satisfied() {
        assert_eq!(
            evaluate(&ClaimPredicate::Unconditional, 0).unwrap(),
            PredicateVerdict::Satisfied
        );
        assert_eq!(
            evaluate(&ClaimPredicate::Unconditional, u64::MAX).unwrap(),
            PredicateVerdict::Satisfied
        );
    }

    // ─── BeforeAbsoluteTime ────────────────────────────────────────────────

    #[test]
    fn before_absolute_time_satisfied_strictly_before() {
        assert_eq!(
            evaluate(&before(1000), 999).unwrap(),
            PredicateVerdict::Satisfied
        );
    }

    #[test]
    fn before_absolute_time_not_satisfied_at_boundary() {
        // "closeTime < absBefore" — equal is NOT satisfied.
        assert_eq!(
            evaluate(&before(1000), 1000).unwrap(),
            PredicateVerdict::NotSatisfied
        );
    }

    #[test]
    fn before_absolute_time_not_satisfied_after() {
        assert_eq!(
            evaluate(&before(1000), 1001).unwrap(),
            PredicateVerdict::NotSatisfied
        );
    }

    #[test]
    fn before_absolute_time_negative_bound_never_satisfied() {
        assert_eq!(
            evaluate(&before(-1), 0).unwrap(),
            PredicateVerdict::NotSatisfied
        );
    }

    // ─── Not ───────────────────────────────────────────────────────────────

    #[test]
    fn not_negates_inner_verdict() {
        // Not(BeforeAbsoluteTime(1000)) satisfied iff now >= 1000.
        let p = not(before(1000));
        assert_eq!(evaluate(&p, 999).unwrap(), PredicateVerdict::NotSatisfied);
        assert_eq!(evaluate(&p, 1000).unwrap(), PredicateVerdict::Satisfied);
        assert_eq!(evaluate(&p, 1001).unwrap(), PredicateVerdict::Satisfied);
    }

    #[test]
    fn not_none_fails_closed() {
        let p = ClaimPredicate::Not(None);
        let err = evaluate(&p, 0).expect_err("Not(None) must be refused");
        assert_eq!(err.code(), "claim.predicate_unsupported");
    }

    // ─── And ───────────────────────────────────────────────────────────────

    #[test]
    fn and_requires_all_satisfied() {
        let p = and2(before(2000), not(before(1000)));
        assert_eq!(
            evaluate(&p, 1500).unwrap(),
            PredicateVerdict::Satisfied,
            "1000 <= 1500 < 2000"
        );
        assert_eq!(evaluate(&p, 500).unwrap(), PredicateVerdict::NotSatisfied);
        assert_eq!(evaluate(&p, 2500).unwrap(), PredicateVerdict::NotSatisfied);
    }

    #[test]
    fn and_short_circuits_on_first_false() {
        // Second branch would be PredicateUnsupported (BeforeRelativeTime);
        // it must never be reached because the first branch is false.
        let p = and2(before(0), ClaimPredicate::BeforeRelativeTime(1));
        assert_eq!(evaluate(&p, 100).unwrap(), PredicateVerdict::NotSatisfied);
    }

    #[test]
    fn and_empty_fails_closed() {
        let p = ClaimPredicate::And(VecM::default());
        let err = evaluate(&p, 0).expect_err("empty And must be refused");
        assert_eq!(err.code(), "claim.predicate_unsupported");
    }

    #[test]
    fn and_single_element_fails_closed() {
        let p = ClaimPredicate::And(VecM::try_from(vec![before(1000)]).unwrap());
        let err = evaluate(&p, 0).expect_err("single-element And must be refused");
        assert_eq!(err.code(), "claim.predicate_unsupported");
    }

    // ─── Or ────────────────────────────────────────────────────────────────

    #[test]
    fn or_satisfied_if_any_branch_satisfied() {
        let p = or2(before(0), before(2000));
        assert_eq!(evaluate(&p, 100).unwrap(), PredicateVerdict::Satisfied);
    }

    #[test]
    fn or_not_satisfied_if_no_branch_satisfied() {
        let p = or2(before(0), before(0));
        assert_eq!(evaluate(&p, 100).unwrap(), PredicateVerdict::NotSatisfied);
    }

    #[test]
    fn or_short_circuits_on_first_true() {
        let p = or2(before(2000), ClaimPredicate::BeforeRelativeTime(1));
        assert_eq!(evaluate(&p, 100).unwrap(), PredicateVerdict::Satisfied);
    }

    #[test]
    fn or_empty_fails_closed() {
        let p = ClaimPredicate::Or(VecM::default());
        let err = evaluate(&p, 0).expect_err("empty Or must be refused");
        assert_eq!(err.code(), "claim.predicate_unsupported");
    }

    // ─── BeforeRelativeTime ────────────────────────────────────────────────

    #[test]
    fn before_relative_time_fails_closed() {
        let p = ClaimPredicate::BeforeRelativeTime(3600);
        let err = evaluate(&p, 0).expect_err("BeforeRelativeTime must be refused");
        assert_eq!(err.code(), "claim.predicate_unsupported");
    }

    // ─── Depth bound ───────────────────────────────────────────────────────

    #[test]
    fn deep_not_chain_fails_closed_beyond_bound() {
        let mut p = ClaimPredicate::Unconditional;
        for _ in 0..(MAX_PREDICATE_DEPTH + 10) {
            p = not(p);
        }
        let err = evaluate(&p, 0).expect_err("excessive nesting must be refused");
        assert_eq!(err.code(), "claim.predicate_unsupported");
    }

    #[test]
    fn not_chain_within_bound_evaluates_normally() {
        let mut p = ClaimPredicate::Unconditional;
        // Wrap in an even number of Not so parity round-trips to Satisfied.
        for _ in 0..10 {
            p = not(p);
        }
        assert_eq!(evaluate(&p, 0).unwrap(), PredicateVerdict::Satisfied);
    }

    // ─── Window derivation ─────────────────────────────────────────────────

    #[test]
    fn window_unconditional_has_no_bounds() {
        let w = derive_window(&ClaimPredicate::Unconditional);
        assert_eq!(w, ClaimabilityWindow::default());
    }

    #[test]
    fn window_before_absolute_time_derives_valid_until() {
        let w = derive_window(&before(5000));
        assert_eq!(w.valid_until, Some(5000));
        assert_eq!(w.valid_from, None);
    }

    #[test]
    fn window_before_absolute_time_non_positive_bound_is_not_derived() {
        let w = derive_window(&before(0));
        assert_eq!(w, ClaimabilityWindow::default());
        let w = derive_window(&before(-100));
        assert_eq!(w, ClaimabilityWindow::default());
    }

    #[test]
    fn window_not_before_absolute_time_derives_valid_from() {
        let w = derive_window(&not(before(3000)));
        assert_eq!(w.valid_from, Some(3000));
        assert_eq!(w.valid_until, None);
    }

    #[test]
    fn window_and_combines_from_and_until() {
        let p = and2(before(2000), not(before(1000)));
        let w = derive_window(&p);
        assert_eq!(w.valid_from, Some(1000));
        assert_eq!(w.valid_until, Some(2000));
    }

    #[test]
    fn window_and_takes_tightest_bounds_across_more_than_two_derivable_children() {
        // valid_from candidates {1000, 1500} -> max = 1500.
        // valid_until candidates {5000, 4000} -> min = 4000.
        let inner_and = and2(not(before(1000)), before(5000));
        let p = and2(inner_and, and2(not(before(1500)), before(4000)));
        let w = derive_window(&p);
        assert_eq!(w.valid_from, Some(1500));
        assert_eq!(w.valid_until, Some(4000));
    }

    #[test]
    fn window_or_is_not_derivable() {
        let p = or2(before(1000), before(5000));
        let w = derive_window(&p);
        assert_eq!(w, ClaimabilityWindow::default());
    }

    #[test]
    fn window_not_of_non_before_absolute_time_is_not_derivable() {
        let p = not(ClaimPredicate::Unconditional);
        let w = derive_window(&p);
        assert_eq!(w, ClaimabilityWindow::default());
    }

    #[test]
    fn window_not_none_is_not_derivable() {
        let p = ClaimPredicate::Not(None);
        let w = derive_window(&p);
        assert_eq!(w, ClaimabilityWindow::default());
    }

    #[test]
    fn window_before_relative_time_is_not_derivable() {
        let w = derive_window(&ClaimPredicate::BeforeRelativeTime(60));
        assert_eq!(w, ClaimabilityWindow::default());
    }

    #[test]
    fn window_deep_nesting_beyond_bound_is_not_derivable() {
        let mut p = before(1000);
        for _ in 0..(MAX_PREDICATE_DEPTH + 10) {
            p = and2(p, ClaimPredicate::Unconditional);
        }
        let w = derive_window(&p);
        assert_eq!(w, ClaimabilityWindow::default());
    }
}
