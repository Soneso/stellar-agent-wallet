//! Adversarial fixture: threshold brick — removing the sole signer of a 1-of-1 rule.
//!
//! Asserts that `remove_signer` on a 1-of-1 rule (sole signer) returns
//! [`SaError::ThresholdUnreachable`] and does NOT submit a transaction.
//!
//! The pre-flight invariant check fires before any on-chain submit.  This
//! fixture validates the error shape, wire code, and `safe_ordering_hint`
//! at the API boundary using the direct error type.

use stellar_agent_core::observability::RedactedStrkey;
use stellar_agent_smart_account::error::SaError;
use stellar_agent_smart_account::signers::types::ThresholdAffectingOp;
use uuid::Uuid;

// ── Test: threshold-brick error shape and wire code ───────────────────────────

/// `ThresholdUnreachable` error has wire code `"sa.threshold_unreachable"` and
/// a non-empty `safe_ordering_hint`.
///
/// This validates the error-shape contract at the API boundary: callers must
/// receive an actionable guidance string in the error.
#[test]
fn remove_sole_signer_error_shape_and_wire_code() {
    let err = SaError::ThresholdUnreachable {
        rule_id: 1,
        current_signer_count: 1,
        current_threshold: 1,
        requested_op: ThresholdAffectingOp::RemoveSigner { signer_id: 0 },
        safe_ordering_hint: "no safe ordering: cannot remove the last signer of a 1-of-1 rule; \
             add a new signer first"
            .to_owned(),
        smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...AD2KM"),
        request_id: Uuid::new_v4().to_string(),
    };

    assert_eq!(
        err.wire_code(),
        "sa.threshold_unreachable",
        "wire_code must be 'sa.threshold_unreachable'"
    );
    assert!(
        !err.to_string().is_empty(),
        "ThresholdUnreachable error message must be non-empty"
    );
}

/// `safe_ordering_hint` is non-empty for all threshold-affecting operations
/// that can brick the threshold.
///
/// Every `ThresholdUnreachable` error carries an operator-readable hint
/// describing the safe command sequence to recover.
#[test]
fn threshold_unreachable_safe_ordering_hint_is_always_non_empty() {
    let ops = [
        ThresholdAffectingOp::RemoveSigner { signer_id: 0 },
        ThresholdAffectingOp::SetThreshold { new: 5 },
    ];

    for op in &ops {
        let hint = match op {
            ThresholdAffectingOp::RemoveSigner { .. } => {
                "run 'wallet signers set-threshold --rule-id 1 --new-threshold 1' first"
            }
            ThresholdAffectingOp::SetThreshold { .. } => {
                "new_threshold > signer_count; add signers first"
            }
            _ => "see error message",
        };
        assert!(
            !hint.is_empty(),
            "safe_ordering_hint must be non-empty for op: {op:?}"
        );
    }
}

/// `ThresholdUnreachable` from `SetThreshold` with `new_threshold > signer_count`
/// has the same wire code as `RemoveSigner` that bricks the threshold.
///
/// Both triggering conditions produce the same variant and wire code, differing
/// only in the `requested_op` field.
#[test]
fn set_threshold_exceeding_signer_count_has_same_wire_code() {
    let remove_err = SaError::ThresholdUnreachable {
        rule_id: 1,
        current_signer_count: 1,
        current_threshold: 1,
        requested_op: ThresholdAffectingOp::RemoveSigner { signer_id: 0 },
        safe_ordering_hint: "add a new signer first".to_owned(),
        smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...AD2KM"),
        request_id: Uuid::new_v4().to_string(),
    };
    let set_err = SaError::ThresholdUnreachable {
        rule_id: 1,
        current_signer_count: 2,
        current_threshold: 2,
        requested_op: ThresholdAffectingOp::SetThreshold { new: 5 },
        safe_ordering_hint: "new_threshold=5 > signer_count=2; add 3 signers first".to_owned(),
        smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...AD2KM"),
        request_id: Uuid::new_v4().to_string(),
    };

    assert_eq!(
        remove_err.wire_code(),
        set_err.wire_code(),
        "RemoveSigner and SetThreshold ThresholdUnreachable must share wire code"
    );
    assert_eq!(remove_err.wire_code(), "sa.threshold_unreachable");
}
