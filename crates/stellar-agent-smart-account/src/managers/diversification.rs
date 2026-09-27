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
//! 1. The rule's pinned verifiers (read from the audit-log-derived
//!    `PinnedHashesRecord`) belong to at most **one** party: a Wasm pin is one
//!    party per distinct first-8, and the external-reference pins that share an
//!    `owner_redacted` are one party together.
//! 2. The rule's policy criteria evaluates to **either** `Stroops(n)` where
//!    `n > HIGH_VALUE_THRESHOLD_STROOPS`, **or** `Undetermined`.
//!
//! Condition 2 is fail-CLOSED: `Undetermined` is treated as "above threshold".
//! Callers with unknown criteria shapes opt out through the
//! `accept_single_verifier` argument of
//! [`crate::managers::credentials::CredentialsManager::sign_with_passkey_rule`].
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
    /// Rule's pinned verifiers belong to at least two parties, OR the value
    /// threshold is at or below `HIGH_VALUE_THRESHOLD_STROOPS`. Signing
    /// proceeds normally.
    NotRequired,
    /// Single-party verifiers on a high-value or undetermined-value rule.
    /// Signing refuses unless the caller sets the `accept_single_verifier`
    /// opt-in of `sign_with_passkey_rule`.
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
        /// First-8-hex of the first pinned verifier of this rule. When several
        /// pins collapse to one party (external references under one owner),
        /// this is the first pin's first-8; empty when no pin is recorded.
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
/// - If the pinned verifiers belong to at least two parties: `NotRequired`
///   (diversity satisfied, regardless of value threshold).
/// - If `extract_value_threshold(criteria)` returns `Stroops(n)` where
///   `n <= HIGH_VALUE_THRESHOLD_STROOPS`: `NotRequired` (low-value rule).
/// - Otherwise (one party AND high-value or `Undetermined`): `Required`.
///   Includes:
///   - `Stroops(n)` with `n > HIGH_VALUE_THRESHOLD_STROOPS` AND one party.
///   - `Undetermined` (fail-CLOSED: unknown criteria treated as high-value).
///   - Empty `pinned_verifier_first8` (no baseline, zero parties).
///
/// # Parties
///
/// A party is whoever decides which verifier code runs. A Wasm pin counts
/// once per distinct first-8. External-reference pins count once per
/// `owner_redacted` of their [`ExecutableRefPin`], because one owner manages
/// every tag it holds: two references whose tags one owner manages are one
/// party. The redacted form can collide for two distinct owners, which only
/// counts fewer parties and makes the gate stricter. A pin whose
/// `owner_redacted` is the unsupported-address placeholder groups with every
/// other such pin into one party, the same stricter direction.
///
/// # Observable effect
///
/// `verify_pinned_verifier_against_chain` refuses every rule with more than
/// one pinned verifier (`MultiplePinnedHashesUnsupported`) after this gate
/// runs in `sign_with_passkey_rule`. For a two-pin rule the party count
/// therefore decides which refusal fires first, and whether a
/// `SaVerifierDiversificationOverride` row is written under the
/// `accept_single_verifier` opt-in; it promises no signing outcome.
///
/// [`ExecutableRefPin`]: stellar_agent_core::audit_log::schema::ExecutableRefPin
pub(crate) fn check_diversification_required(
    rule_id: u32,
    smart_account_redacted: &str,
    pinned_hashes: &PinnedHashesRecord,
    criteria: &ScVal,
) -> DiversificationCheck {
    // The gate runs before signer-set divergence and wasm-hash drift checks so
    // the cheapest local refusal fires first. If gate ordering ever becomes
    // load-bearing for forensic-row sequence, enforce it via a dedicated gate.
    let parties = verifier_party_count(pinned_hashes);

    // Condition 1: pins from at least two parties → diversity satisfied.
    if parties >= 2 {
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

/// One party that decides which pinned verifier code runs.
#[derive(PartialEq, Eq, Hash)]
enum VerifierParty<'a> {
    /// A Wasm pin, identified by its first-8.
    Wasm(&'a str),
    /// The owner of one or more external-reference pins, by its redacted form.
    ReferenceOwner(&'a str),
}

/// Counts the distinct parties behind the pinned verifiers of `pinned_hashes`.
fn verifier_party_count(pinned_hashes: &PinnedHashesRecord) -> usize {
    pinned_hashes
        .pinned_verifier_first8
        .iter()
        .enumerate()
        .map(
            |(position, first8)| match pinned_hashes.verifier_executable_ref(position) {
                Some(pin) => VerifierParty::ReferenceOwner(pin.owner_redacted.as_str()),
                None => VerifierParty::Wasm(first8.as_str()),
            },
        )
        .collect::<std::collections::HashSet<_>>()
        .len()
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
    use stellar_agent_core::audit_log::schema::ExecutableRefPin;
    use stellar_agent_core::observability::RedactedStrkey;

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

    /// An external-reference pin under `owner_redacted` with `tag`.
    fn reference_pin(owner_redacted: &str, tag: &str, first8: &str) -> ExecutableRefPin {
        ExecutableRefPin {
            owner_redacted: RedactedStrkey::from_already_redacted(owner_redacted),
            tag: tag.to_owned(),
            ref_key_hex: format!("{tag:0>64}"),
            resolved_hash_first8: first8.to_owned(),
        }
    }

    /// Verifier pins at the given first-8 values, each with its optional
    /// external-reference pin at the same position.
    fn pinned_with_refs(pins: Vec<(&str, Option<ExecutableRefPin>)>) -> PinnedHashesRecord {
        let (first8, refs): (Vec<String>, Vec<Option<ExecutableRefPin>>) = pins
            .into_iter()
            .map(|(first8, pin)| (first8.to_owned(), pin))
            .unzip();
        PinnedHashesRecord {
            pinned_verifier_first8: first8,
            pinned_verifier_executable_refs: refs,
            ..Default::default()
        }
    }

    fn high_value_criteria() -> ScVal {
        criteria_with_value_threshold(HIGH_VALUE_THRESHOLD_STROOPS.saturating_add(1))
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

    // ── Parties: external references group by owner ───────────────────────────

    /// Two external-reference verifiers whose tags one owner manages are one
    /// party, so a high-value rule requires diversification, carrying the
    /// first pin's first-8.
    #[test]
    fn two_references_under_one_owner_are_one_party() {
        let pinned = pinned_with_refs(vec![
            (
                "aaaaaaaaaaaaaaaa",
                Some(reference_pin("GAAAA...AAWHF", "v1", "aaaaaaaaaaaaaaaa")),
            ),
            (
                "bbbbbbbbbbbbbbbb",
                Some(reference_pin("GAAAA...AAWHF", "v2", "bbbbbbbbbbbbbbbb")),
            ),
        ]);
        let result =
            check_diversification_required(7, "CAAAA...AAAAA", &pinned, &high_value_criteria());
        assert!(
            matches!(
                &result,
                DiversificationCheck::Required { rule_id: 7, verifier_hash_first8, .. }
                    if verifier_hash_first8 == "aaaaaaaaaaaaaaaa"
            ),
            "two references under one owner must return Required; got: {result:?}"
        );
    }

    /// One external-reference pin and one Wasm pin are two parties.
    #[test]
    fn one_reference_and_one_wasm_pin_are_two_parties() {
        let pinned = pinned_with_refs(vec![
            (
                "aaaaaaaaaaaaaaaa",
                Some(reference_pin("GAAAA...AAWHF", "v1", "aaaaaaaaaaaaaaaa")),
            ),
            ("cccccccccccccccc", None),
        ]);
        let result =
            check_diversification_required(8, "CAAAA...AAAAA", &pinned, &high_value_criteria());
        assert_eq!(result, DiversificationCheck::NotRequired);
    }

    /// Two external references under different owners are two parties.
    #[test]
    fn two_references_under_different_owners_are_two_parties() {
        let pinned = pinned_with_refs(vec![
            (
                "aaaaaaaaaaaaaaaa",
                Some(reference_pin("GAAAA...AAWHF", "v1", "aaaaaaaaaaaaaaaa")),
            ),
            (
                "aaaaaaaaaaaaaaaa",
                Some(reference_pin("GBBBB...BBBBB", "v1", "aaaaaaaaaaaaaaaa")),
            ),
        ]);
        let result =
            check_diversification_required(9, "CAAAA...AAAAA", &pinned, &high_value_criteria());
        assert_eq!(result, DiversificationCheck::NotRequired);
    }

    /// Two Wasm pins with the same first-8 are one party.
    #[test]
    fn two_wasm_pins_with_one_first8_are_one_party() {
        let pinned = pinned_two("aabbccdd", "aabbccdd");
        let result =
            check_diversification_required(10, "CAAAA...AAAAA", &pinned, &high_value_criteria());
        assert!(
            matches!(result, DiversificationCheck::Required { rule_id: 10, .. }),
            "two pins of one Wasm hash must return Required; got: {result:?}"
        );
    }
}
