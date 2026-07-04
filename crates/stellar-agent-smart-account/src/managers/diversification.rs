//! Verifier diversification enforce-default trigger helper.
//!
//! Implements the `check_diversification_required` gate that runs inside
//! `sign_with_passkey_rule_inner` before signer-set divergence and wasm-hash
//! drift checks, so the cheapest local refusal fires first.
//!
//! # Trigger logic
//!
//! A rule fires the diversification gate when **all** of the following hold:
//!
//! 1. The rule has exactly **one** distinct pinned verifier wasm hash (read from
//!    the audit-log-derived `PinnedHashesRecord`).
//! 2. The rule's policy criteria evaluates to **either** `Stroops(n)` where
//!    `n > HIGH_VALUE_THRESHOLD_STROOPS`, **or** `Undetermined`.
//!
//! Condition 2 is fail-CLOSED: `Undetermined` is treated as "above threshold".
//! Operators with unknown criteria shapes must use `--accept-single-verifier`
//! to opt out.
//!
//! # Implementation notes
//!
//! Criteria fetch passes `ScVal::Void` for all rules because OZ
//! `stellar-contracts` v0.7.2 (SHA `a9c4216`) carries no `PerTxCapCriterion`
//! type. `ScVal::Void` maps to `Required` through `Undetermined` (fail-CLOSED).
//! `observed_value_threshold_stroops =
//! DiversificationCheck::SENTINEL_OBSERVED_VALUE_THRESHOLD_STROOPS` is the
//! forensic sentinel for `Undetermined`.
//!
//! Not yet supported: schema-anticipation for canonical OZ PerTxCap encoding.

use stellar_agent_core::HIGH_VALUE_THRESHOLD_STROOPS;
use stellar_xdr::ScVal;

use crate::managers::policies::{ValueThresholdResult, extract_value_threshold};
use stellar_agent_core::audit_log::reader::PinnedHashesRecord;

// ── Public(crate) types ──────────────────────────────────────────────────────

/// Result of [`check_diversification_required`].
///
/// Two-value closed set: the trigger either fires or does not. When it fires,
/// the caller must either refuse signing (returning
/// `CredentialsError::DiversificationRequired`) or emit a
/// `SaVerifierDiversificationOverride` audit row and proceed
/// (when `accept_single_verifier = true`).
#[derive(Clone, Debug, PartialEq, Eq)]
// Keep the enum forward-compatible before any future visibility promotion; it
// is currently `pub(crate)`, so this is intentionally a no-op outside the crate.
#[non_exhaustive]
pub(crate) enum DiversificationCheck {
    /// Rule has ≥2 distinct pinned verifier wasm hashes, OR the value threshold
    /// is at or below `HIGH_VALUE_THRESHOLD_STROOPS`. Signing proceeds normally.
    NotRequired,
    /// Single-verifier on a high-value or undetermined-value rule. Signing
    /// refuses unless the operator passes `--accept-single-verifier`.
    ///
    /// # Forensic fields
    ///
    /// All fields are pre-computed for the `SaError::VerifierDiversificationRequired`
    /// and `SaVerifierDiversificationOverride` audit entries emitted at the
    /// call site.
    Required {
        /// Context-rule identifier the trigger fired on.
        rule_id: u32,
        /// Redacted smart-account C-strkey (first-5-last-5).
        ///
        /// Pre-redacted at the call site via `redact_first5_last5`.
        smart_account_redacted: String,
        /// First-8-hex of the sole pinned verifier wasm hash for this rule.
        verifier_hash_first8: String,
        /// Observed per-tx value threshold extracted from policy criteria.
        ///
        /// [`DiversificationCheck::SENTINEL_OBSERVED_VALUE_THRESHOLD_STROOPS`]
        /// when `extract_value_threshold` returned `Undetermined` (the
        /// sentinel value chosen so the forensic field is non-zero and
        /// operators can distinguish "extractor fired but returned sentinel" from
        /// "extracted Stroops(0)", while staying within `i64` range). Callers
        /// Callers MUST treat the sentinel as "above threshold" (fail-CLOSED).
        observed_value_threshold_stroops: i64,
    },
}

impl DiversificationCheck {
    /// Forensic sentinel emitted when the rule value threshold cannot be extracted.
    pub(crate) const SENTINEL_OBSERVED_VALUE_THRESHOLD_STROOPS: i64 = -1;
}

// ── Core check ───────────────────────────────────────────────────────────────

/// Checks whether the diversification enforce-default trigger fires for the
/// given rule.
///
/// # Arguments
///
/// - `rule_id` — context rule identifier.
/// - `smart_account_redacted` — pre-redacted (first-5-last-5) C-strkey of the
///   smart-account contract. The caller applies redaction before this function
///   to avoid logging the full contract address.
/// - `pinned_hashes` — audit-log-derived pinned hash record for the rule.
///   An absent record (no `SaContextRuleCreated` row found) carries
///   `pinned_verifier_first8 = []`, which is treated as single-verifier
///   (fail-CLOSED: a missing baseline means we cannot confirm diversity).
/// - `criteria` — the rule's policy criteria `ScVal`. Pass `ScVal::Void` when
///   the criteria cannot be fetched (maps to `Undetermined` → fail-CLOSED).
///
/// # Trigger conditions
///
/// - If `pinned_verifier_first8.len() >= 2`: `NotRequired` (≥2 hashes implies
///   diversity, regardless of value threshold).
/// - If `extract_value_threshold(criteria)` returns `Stroops(n)` where
///   `n <= HIGH_VALUE_THRESHOLD_STROOPS`: `NotRequired` (low-value rule).
/// - Otherwise (single verifier AND high-value or `Undetermined`): `Required`.
///   Includes:
///   - `Stroops(n)` with `n > HIGH_VALUE_THRESHOLD_STROOPS` AND single verifier.
///   - `Undetermined` (fail-CLOSED: unknown criteria treated as high-value).
///   - Empty `pinned_verifier_first8` (no baseline → treated as single-verifier).
pub(crate) fn check_diversification_required(
    rule_id: u32,
    smart_account_redacted: &str,
    pinned_hashes: &PinnedHashesRecord,
    criteria: &ScVal,
) -> DiversificationCheck {
    // The gate runs before signer-set divergence and wasm-hash drift checks so
    // the cheapest local refusal fires first. If gate ordering ever becomes
    // load-bearing for forensic-row sequence, enforce it via a dedicated gate.
    let verifier_count = pinned_hashes.pinned_verifier_first8.len();

    // Condition 1: ≥2 distinct pinned verifier hashes → diversity satisfied.
    if verifier_count >= 2 {
        return DiversificationCheck::NotRequired;
    }

    // Condition 2: evaluate value threshold (fail-CLOSED on Undetermined).
    let threshold_result = extract_value_threshold(criteria);
    match threshold_result {
        ValueThresholdResult::Stroops(n) if n <= HIGH_VALUE_THRESHOLD_STROOPS => {
            // Low-value rule — diversification not required regardless of
            // verifier count.
            return DiversificationCheck::NotRequired;
        }
        ValueThresholdResult::Stroops(_) | ValueThresholdResult::Undetermined => {
            // High-value or Undetermined → diversification required.
        }
    }

    // Build forensic fields for the Required variant.
    let verifier_hash_first8 = pinned_hashes
        .pinned_verifier_first8
        .first()
        .cloned()
        .unwrap_or_default();

    // Sentinel when Undetermined (cannot fit a real stroop value in the field;
    // operators read it as "criteria not extractable").
    let observed_value_threshold_stroops = match threshold_result {
        ValueThresholdResult::Stroops(n) => n,
        ValueThresholdResult::Undetermined => {
            DiversificationCheck::SENTINEL_OBSERVED_VALUE_THRESHOLD_STROOPS
        }
    };

    DiversificationCheck::Required {
        rule_id,
        smart_account_redacted: smart_account_redacted.to_owned(),
        verifier_hash_first8,
        observed_value_threshold_stroops,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only: infallible constructors for fixture ScVal and PinnedHashesRecord values"
    )]

    use stellar_xdr::VecM;
    use stellar_xdr::{Int128Parts, ScMap, ScMapEntry, ScSymbol, ScVal};

    use super::*;
    use stellar_agent_core::audit_log::reader::PinnedHashesRecord;

    // ── Fixture helpers ───────────────────────────────────────────────────────

    fn pinned_one(hash_first8: &str) -> PinnedHashesRecord {
        PinnedHashesRecord {
            pinned_verifier_first8: vec![hash_first8.to_owned()],
            ..Default::default()
        }
    }

    fn pinned_two(h1: &str, h2: &str) -> PinnedHashesRecord {
        PinnedHashesRecord {
            pinned_verifier_first8: vec![h1.to_owned(), h2.to_owned()],
            ..Default::default()
        }
    }

    fn pinned_none() -> PinnedHashesRecord {
        PinnedHashesRecord::default()
    }

    /// Build a `ScVal::Map` with a single schema-anticipation key `value_threshold`
    /// and a valid `ScVal::I128` value (hi=0, lo=n as u64).
    ///
    /// Both schema-anticipation keys are recognised by `extract_value_threshold`;
    /// `value_threshold` is used here per `managers/policies.rs`.
    fn criteria_with_value_threshold(stroops: i64) -> ScVal {
        assert!(stroops >= 0, "fixture requires non-negative stroop amount");
        let sym = ScSymbol(b"value_threshold".as_ref().try_into().unwrap());
        let val = ScVal::I128(Int128Parts {
            hi: 0,
            lo: stroops as u64,
        });
        let entries: VecM<ScMapEntry> = vec![ScMapEntry {
            key: ScVal::Symbol(sym),
            val,
        }]
        .try_into()
        .unwrap();
        ScVal::Map(Some(ScMap(entries)))
    }

    // ── Test 1: ≥2 distinct verifier hashes → NotRequired ────────────────────

    /// A rule with 2 distinct pinned verifier hashes is not required to
    /// diversify, regardless of the value threshold.
    #[test]
    fn diversification_not_required_when_rule_has_two_verifiers() {
        let pinned = pinned_two("aabbccdd", "11223344");
        // High-value criteria to confirm it is overridden by 2-hash condition.
        let criteria =
            criteria_with_value_threshold(HIGH_VALUE_THRESHOLD_STROOPS.saturating_add(1));
        let result = check_diversification_required(1, "CAAAA...AAAAA", &pinned, &criteria);
        assert_eq!(
            result,
            DiversificationCheck::NotRequired,
            "two distinct verifier hashes must return NotRequired"
        );
    }

    // ── Test 2: single verifier, value_threshold ≤ high-value → NotRequired ───

    /// A rule with a single verifier is not required to diversify when the
    /// criteria `value_threshold` is at or below `HIGH_VALUE_THRESHOLD_STROOPS`.
    #[test]
    fn diversification_not_required_when_value_threshold_below_high_value() {
        let pinned = pinned_one("aabbccdd");
        let criteria = criteria_with_value_threshold(HIGH_VALUE_THRESHOLD_STROOPS);
        let result = check_diversification_required(2, "CAAAA...AAAAA", &pinned, &criteria);
        assert_eq!(
            result,
            DiversificationCheck::NotRequired,
            "value_threshold == HIGH_VALUE_THRESHOLD_STROOPS must return NotRequired \
             (threshold is not exclusive — equal means low-value)"
        );
    }

    // ── Test 3: single verifier, high-value criteria → Required ──────────────

    /// A rule with a single verifier whose criteria `value_threshold` exceeds
    /// `HIGH_VALUE_THRESHOLD_STROOPS` must return `Required`.
    #[test]
    fn diversification_required_when_single_verifier_high_value() {
        let pinned = pinned_one("aabbccdd");
        let high_value = HIGH_VALUE_THRESHOLD_STROOPS.saturating_add(1);
        let criteria = criteria_with_value_threshold(high_value);
        let result = check_diversification_required(3, "CAAAA...AAAAA", &pinned, &criteria);
        assert!(
            matches!(
                &result,
                DiversificationCheck::Required { rule_id: 3, observed_value_threshold_stroops, .. }
                    if *observed_value_threshold_stroops == high_value
            ),
            "single verifier + high-value criteria must return Required with correct \
             observed_value_threshold_stroops; got: {result:?}"
        );
    }

    // ── Test 4: Undetermined criteria → Required (fail-CLOSED) ───────────────

    /// Verifies fail-CLOSED `Undetermined` posture.
    ///
    /// An `Undetermined` criteria result (malformed, absent, or unrecognised
    /// criteria ScVal) is treated as above-threshold. The trigger fires on all
    /// single-verifier rules with unrecognised criteria shapes, including every
    /// real OZ v0.7.2 policy contract (which carries no `PerTxCapCriterion`).
    #[test]
    fn diversification_required_when_undetermined_threshold_fail_closed() {
        let pinned = pinned_one("aabbccdd");
        // ScVal::Void → Undetermined (maps to the fail-CLOSED path).
        let criteria = ScVal::Void;
        let result = check_diversification_required(4, "CAAAA...AAAAA", &pinned, &criteria);
        assert!(
            matches!(
                &result,
                DiversificationCheck::Required {
                    rule_id: 4,
                    observed_value_threshold_stroops:
                        DiversificationCheck::SENTINEL_OBSERVED_VALUE_THRESHOLD_STROOPS,
                    ..
                }
            ),
            "Undetermined criteria must return Required with \
             observed_value_threshold_stroops = sentinel (fail-CLOSED); got: {result:?}"
        );
    }

    // ── Test 5: no pinned hashes → Required (fail-CLOSED, no baseline) ────────

    /// Verifies fail-CLOSED when no audit-log baseline exists for the rule.
    ///
    /// An absent `PinnedHashesRecord` (empty `pinned_verifier_first8`) is
    /// treated as single-verifier. Combined with Undetermined criteria (OZ
    /// v0.7.2 default) this triggers the Required variant with an empty
    /// `verifier_hash_first8` field.
    #[test]
    fn diversification_required_when_no_pinned_hashes_fail_closed() {
        let pinned = pinned_none();
        let criteria = ScVal::Void;
        let result = check_diversification_required(5, "CAAAA...AAAAA", &pinned, &criteria);
        assert!(
            matches!(
                &result,
                DiversificationCheck::Required {
                    rule_id: 5,
                    verifier_hash_first8,
                    ..
                } if verifier_hash_first8.is_empty()
            ),
            "no pinned hashes must return Required with empty verifier_hash_first8; \
             got: {result:?}"
        );
    }

    // ── Test 6: verifier_hash_first8 field is populated correctly ─────────────

    /// Verifies that the `Required` variant carries the first pinned verifier
    /// hash's first-8 hex chars.
    ///
    /// When the trigger fires, the forensic `verifier_hash_first8` field in the
    /// `Required` variant MUST equal `pinned_verifier_first8[0]` so that the
    /// `SaError::VerifierDiversificationRequired` and
    /// `SaVerifierDiversificationOverride` audit entries carry the correct hash.
    #[test]
    fn diversification_required_carries_correct_verifier_hash_first8() {
        let pinned = pinned_one("deadbeef");
        let criteria = ScVal::Void; // Undetermined → above threshold
        let result = check_diversification_required(6, "CAAAA...AAAAA", &pinned, &criteria);
        assert!(
            matches!(
                &result,
                DiversificationCheck::Required { verifier_hash_first8, .. }
                    if verifier_hash_first8 == "deadbeef"
            ),
            "Required.verifier_hash_first8 must equal pinned_verifier_first8[0]; \
             got: {result:?}"
        );
    }
}
