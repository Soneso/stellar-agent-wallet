//! Policy criteria deserialization for the verifier diversification enforce-default gate
//! and future per-policy consumer surfaces.
//!
//! # OZ Criteria Encoding Research Finding
//!
//! OZ stellar-contracts v0.7.1 at SHA `3f81125bed3114cc93f5fca6d13240082050269a`
//! does NOT ship a `PerTxCapCriterion` type or any per-transaction value-cap
//! criterion in any policy contract.
//!
//! The nearest on-chain value-capping primitive is `SpendingLimitData`
//! (`packages/accounts/src/policies/spending_limit.rs:97-108`, SHA `3f81125`),
//! which implements a **rolling-window cumulative spending limit** — NOT a
//! per-transaction cap. Its `spending_limit: i128` field represents the maximum
//! cumulative spend over a `period_ledgers`-wide rolling window, not the maximum
//! value of a single transaction. Treating it as a per-transaction value threshold
//! would make the diversification trigger over-eager: a rule with `spending_limit =
//! 100_000 stroops / 30 days` would be misread as "every transaction is a
//! 100_000-stroop transaction", firing the gate on 1-stroop transfers and
//! producing forensically misleading `observed_value_threshold_stroops` in audit
//! rows. The `SpendingLimitData.spending_limit` key is therefore intentionally
//! NOT recognised by this extractor.
//!
//! The `ContextRule` struct (`packages/accounts/src/smart_account/storage.rs:155-174`,
//! SHA `3f81125`) carries no `criteria` field; policy parameters are stored in the
//! policy contract's own persistent ledger entries, not in the rule struct itself.
//!
//! # Schema-anticipation Pattern
//!
//! Since OZ v0.7.1 does not ship a per-transaction value-cap criterion, this
//! extractor adopts a **schema-anticipation** pattern. It recognises two
//! forward-compat key byte-patterns (`b"value_threshold"` and `b"max_stroops"`)
//! that a future OZ `PerTxCapCriterion`-equivalent might use.
//!
//! Because neither key exists in any OZ v0.7.1 contract, the extractor currently
//! returns `Undetermined` for all real on-chain policy storage, which correctly
//! triggers the fail-CLOSED enforce-default path: operators with unknown policy
//! shapes use `--accept-single-verifier` to opt out.
//!
//! A follow-up tracks updating the extractor once OZ ships a canonical per-transaction
//! value-cap policy type.
//!
//! # Fail-CLOSED discipline
//!
//! `Undetermined` is treated AS IF above the high-value threshold. Unknown criteria
//! shape conservatively enforces diversification. Operators must explicitly opt out
//! via `--accept-single-verifier`.

use stellar_xdr::{Int128Parts, ScMap, ScSymbol, ScVal};

// ── Recognised field keys ────────────────────────────────────────────────────

/// Schema-anticipation forward-compat key for a hypothetical OZ
/// `PerTxCapCriterion`-style value-threshold field.
///
/// Not present in any OZ v0.7.1 contract (SHA `3f81125`).
/// Not yet supported: schema-anticipation for canonical OZ PerTxCap encoding.
const KEY_VALUE_THRESHOLD: &[u8] = b"value_threshold";

/// Schema-anticipation forward-compat key for a hypothetical OZ
/// `PerTxCapCriterion`-style max-stroops field.
///
/// Not present in any OZ v0.7.1 contract (SHA `3f81125`).
/// Not yet supported: schema-anticipation for canonical OZ PerTxCap encoding.
const KEY_MAX_STROOPS: &[u8] = b"max_stroops";

// ── Public(crate) types ──────────────────────────────────────────────────────

// Design rationale for the two variant choices:
//
// 1. `Stroops(i64)` over `Stroops(u64)`:
//    The `SaError::VerifierDiversificationRequired.observed_value_threshold_stroops`
//    field is typed `i64`. Matching that type avoids a cast at the
//    error-construction site. All in-practice per-transaction spending caps fit
//    comfortably in i64 (i64::MAX ≈ 9.2 × 10^18 stroops).
//    Values exceeding i64::MAX return `Undetermined` (overflow → fail-CLOSED).
//
// 2. Bare `Undetermined` (no reason field):
//    The enforce-default trigger needs only a boolean above-threshold answer;
//    a `reason` field has no consumer. `#[non_exhaustive]` allows adding fields
//    or variants in a future update without an SDK bump.

/// Result of [`extract_value_threshold`] for a policy criteria `ScVal`.
///
/// Closed two-value set: a known per-transaction stroop cap, or
/// [`Undetermined`] (fail-CLOSED sentinel for unknown / malformed / absent
/// per-transaction cap criteria).
///
/// # Fail-CLOSED discipline
///
/// The diversification enforce-default trigger treats `Undetermined` AS IF
/// above the high-value threshold — the operator must explicitly opt out via
/// `--accept-single-verifier` to proceed. This is the safe-by-default posture:
/// unknown criteria shape is conservatively assumed to be high-value.
///
/// # Note on `i64` vs `i128`
///
/// Forward-compat OZ per-tx-cap criterion values would likely be `i128`
/// on-chain (consistent with OZ `SpendingLimitData.spending_limit: i128` at
/// `packages/accounts/src/policies/spending_limit.rs:91`, SHA `3f81125`).
/// Values that exceed [`i64::MAX`] (≈ 9.2 × 10¹⁸ stroops — far above any
/// meaningful per-transaction cap) cannot fit in the `Stroops` variant and
/// are classified as `Undetermined` (overflow → fail-CLOSED). The `i64` type
/// is chosen to match the
/// `SaError::VerifierDiversificationRequired.observed_value_threshold_stroops: i64`
/// forensic-field type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
#[allow(
    dead_code,
    reason = "consumed by the diversification enforce-default trigger in credentials.rs"
)]
pub(crate) enum ValueThresholdResult {
    /// Recognised per-transaction stroop cap from a known criteria shape.
    Stroops(i64),
    /// Criteria shape not recognised, absent, or malformed; fail-CLOSED sentinel.
    ///
    /// The diversification enforce-default trigger MUST treat this variant as
    /// "above threshold" — unknown criteria shape is conservatively high-value.
    Undetermined,
}

// ── Core extractor ───────────────────────────────────────────────────────────

/// Extracts the per-transaction value threshold (in stroops) from a policy
/// rule's criteria `ScVal` payload.
///
/// # Canonical criteria encoding
///
/// OZ stellar-contracts v0.7.1 (SHA `3f81125`) does not ship a per-transaction
/// value-cap criterion type. The extractor uses a schema-anticipation pattern
/// and recognises two forward-compat keys (`b"value_threshold"`,
/// `b"max_stroops"`) that a future OZ per-tx-cap policy might emit.
/// Not yet supported: schema-anticipation for canonical OZ PerTxCap encoding.
///
/// The OZ `SpendingLimitData.spending_limit` key
/// (`packages/accounts/src/policies/spending_limit.rs:101`, SHA `3f81125`) is
/// intentionally NOT recognised: that field is a rolling-window cumulative cap,
/// not a per-transaction limit. Using it as a per-tx proxy would fire the
/// diversification gate on low-value transactions and produce misleading
/// `observed_value_threshold_stroops` in audit rows.
///
/// Because no OZ v0.7.1 contract emits the recognised keys, this extractor
/// returns `Undetermined` for all real on-chain policy storage in v0.7.1.
/// That correctly routes operators to the `--accept-single-verifier` opt-out.
///
/// # Fail-CLOSED contract
///
/// Returns [`ValueThresholdResult::Undetermined`] for any of:
///
/// - Non-`Map` `ScVal` discriminant (e.g. `ScVal::U32`, `ScVal::Void`,
///   `ScVal::Bytes`, `ScVal::Vec`).
/// - `ScVal::Map(None)` — null map sentinel.
/// - Empty map or map with no entry matching a recognised key.
/// - Recognised key but associated value is not `ScVal::I128(...)`.
/// - `ScVal::I128` value whose mathematical value overflows `i64` (hi part
///   non-zero or `lo` exceeds `i64::MAX as u64`).
///
/// The caller MUST treat `Undetermined` as triggering the enforce-default
/// diversification gate — unknown criteria shape is conservatively treated as
/// high-value.
#[allow(
    dead_code,
    reason = "consumed by the diversification enforce-default trigger in credentials.rs"
)]
pub(crate) fn extract_value_threshold(criteria: &ScVal) -> ValueThresholdResult {
    let ScVal::Map(Some(map)) = criteria else {
        return ValueThresholdResult::Undetermined;
    };

    extract_from_scmap(map)
}

// ── Internal helpers ─────────────────────────────────────────────────────────

/// Walk a decoded `ScMap` looking for a recognised per-tx-cap key and return
/// its `i64`-range stroop value, or `Undetermined` on any failure.
///
/// Encoding per `soroban-sdk-macros` `derive_type_struct`: sorts named fields
/// by identifier and emits each field as
/// `ScMapEntry { key: ScVal::Symbol(field_name), val: <field IntoVal> }`.
/// The iteration order does not affect correctness here — only presence and
/// value type matter.
#[allow(
    dead_code,
    reason = "consumed transitively via extract_value_threshold by the diversification enforce-default trigger"
)]
fn extract_from_scmap(map: &ScMap) -> ValueThresholdResult {
    for entry in map.0.iter() {
        if let ScVal::Symbol(ref sym) = entry.key
            && is_recognised_key(sym)
        {
            return decode_i128_value(&entry.val);
        }
    }

    // No recognised per-tx-cap key found in the map.
    ValueThresholdResult::Undetermined
}

/// Returns `true` for any `ScSymbol` whose UTF-8 byte content matches one of
/// the recognised per-transaction value-cap field names.
///
/// Recognised names (schema-anticipation forward-compat; not present in any
/// OZ v0.7.1 contract at SHA `3f81125`):
/// - `b"value_threshold"` — anticipated per-tx-cap field name.
/// - `b"max_stroops"` — anticipated per-tx-cap field name.
///
/// Intentionally NOT recognised:
/// - `b"spending_limit"` — OZ `SpendingLimitData` rolling-window cumulative
///   limit (`spending_limit.rs:101`, SHA `3f81125`); semantically distinct
///   from a per-transaction cap; see module-level rustdoc.
#[allow(
    dead_code,
    reason = "consumed transitively via extract_from_scmap by the diversification enforce-default trigger"
)]
fn is_recognised_key(sym: &ScSymbol) -> bool {
    let bytes = sym.0.as_slice();
    bytes == KEY_VALUE_THRESHOLD || bytes == KEY_MAX_STROOPS
}

/// Decode an `ScVal::I128(Int128Parts { hi, lo })` into an `i64`-ranged stroop
/// amount.
///
/// Fail-CLOSED conditions (all return `Undetermined`):
/// - `val` is not `ScVal::I128`.
/// - `hi` is nonzero (value is either negative or exceeds 2^63-1).
/// - `lo` exceeds `i64::MAX as u64` (would overflow `i64::try_from`).
#[allow(
    dead_code,
    reason = "consumed transitively via extract_from_scmap by the diversification enforce-default trigger"
)]
fn decode_i128_value(val: &ScVal) -> ValueThresholdResult {
    let ScVal::I128(Int128Parts { hi, lo }) = val else {
        return ValueThresholdResult::Undetermined;
    };

    // Fail-CLOSED on negative or oversized values: any hi != 0 means either
    // the value is negative (hi < 0) or exceeds 2^63-1 (hi > 0), both of
    // which cannot fit in i64.  An in-practice per-transaction value cap always
    // fits in i64 (i64::MAX ≈ 9.2 × 10^18 stroops = 9.2 × 10^11 XLM).
    if *hi != 0 {
        return ValueThresholdResult::Undetermined;
    }

    // lo is u64; safe to cast to i64 only if it does not exceed i64::MAX.
    i64::try_from(*lo)
        .map(ValueThresholdResult::Stroops)
        .unwrap_or(ValueThresholdResult::Undetermined)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only: infallible constructors for fixture ScVal values"
    )]

    use stellar_xdr::{Int128Parts, ScMap, ScMapEntry, ScString, ScSymbol, ScVal, ScVec};
    use stellar_xdr::{ScBytes, VecM};

    use super::*;

    // ── Helper constructors ──────────────────────────────────────────────────

    /// Build an `ScVal::Map` with a single entry of the given symbol key and value.
    fn single_entry_map(key_bytes: &[u8], val: ScVal) -> ScVal {
        let sym = ScSymbol(key_bytes.try_into().expect("key fits ScSymbol"));
        let entries: VecM<ScMapEntry> = vec![ScMapEntry {
            key: ScVal::Symbol(sym),
            val,
        }]
        .try_into()
        .expect("single entry fits VecM");
        ScVal::Map(Some(ScMap(entries)))
    }

    /// Build an `ScVal::I128` from a non-negative `i64` value (hi = 0, lo = n as u64).
    ///
    /// Precondition: `n >= 0`. The `debug_assert` catches misuse in tests.
    fn i128_from_nonneg_i64(n: i64) -> ScVal {
        debug_assert!(
            n >= 0,
            "i128_from_nonneg_i64: n must be non-negative, got {n}"
        );
        ScVal::I128(Int128Parts {
            hi: 0,
            lo: n as u64,
        })
    }

    // ── Test 1: spending_limit key returns Undetermined (not a per-tx cap) ───

    /// Verifies that the OZ `SpendingLimitData` `spending_limit` key is NOT
    /// recognised by the extractor.
    ///
    /// `spending_limit` is a rolling-window cumulative limit, not a
    /// per-transaction cap (OZ `packages/accounts/src/policies/spending_limit.rs:101`,
    /// SHA `3f81125`). Recognising it would make the trigger over-eager and
    /// produce misleading audit rows. It belongs to the fail-CLOSED
    /// unrecognised-key set.
    #[test]
    fn extract_value_threshold_returns_undetermined_for_spending_limit_key() {
        let criteria = single_entry_map(b"spending_limit", i128_from_nonneg_i64(1_000_000));
        assert_eq!(
            extract_value_threshold(&criteria),
            ValueThresholdResult::Undetermined,
            "spending_limit key (rolling-window cumulative, not per-tx) must return Undetermined"
        );
    }

    // ── Test 2: non-Map ScVal discriminants all return Undetermined ───────────

    /// Verifies fail-CLOSED on non-Map `ScVal` discriminants.
    ///
    /// Criteria that is not a `ScVal::Map(Some(...))` must return `Undetermined`.
    #[test]
    fn extract_value_threshold_returns_undetermined_for_non_map_scval() {
        let non_map_variants: &[ScVal] = &[
            ScVal::Bytes(ScBytes(b"deadbeef".as_ref().try_into().unwrap())),
            ScVal::U32(42),
            ScVal::Void,
            ScVal::Vec(Some(ScVec(
                vec![ScVal::U32(1)].try_into().expect("single elem fits"),
            ))),
            ScVal::I32(0),
            ScVal::U64(100),
            ScVal::Map(None),
        ];

        for variant in non_map_variants {
            assert_eq!(
                extract_value_threshold(variant),
                ValueThresholdResult::Undetermined,
                "non-Map ScVal {variant:?} must return Undetermined"
            );
        }
    }

    // ── Test 3: unrecognised key returns Undetermined ─────────────────────────

    /// Verifies fail-CLOSED on a map with an unrecognised key name.
    ///
    /// A map with key `b"frobnicate"` carries no recognised per-tx-cap
    /// field; the extractor must return `Undetermined`.
    #[test]
    fn extract_value_threshold_returns_undetermined_for_unrecognized_key() {
        let criteria = single_entry_map(b"frobnicate", i128_from_nonneg_i64(9_999_999));
        assert_eq!(
            extract_value_threshold(&criteria),
            ValueThresholdResult::Undetermined,
            "map with unrecognised key 'frobnicate' must return Undetermined"
        );
    }

    // ── Test 4: recognised key but non-integer value returns Undetermined ─────

    /// Verifies fail-CLOSED on a map where a recognised schema-anticipation key
    /// maps to a non-integer value (e.g. `ScVal::Bytes` or `ScVal::String`).
    ///
    /// A recognised key paired with a non-`ScVal::I128` value must return
    /// `Undetermined`.
    #[test]
    fn extract_value_threshold_returns_undetermined_for_non_integer_value() {
        let byte_val = ScVal::Bytes(ScBytes(b"not_an_int".as_ref().try_into().unwrap()));
        let string_val = ScVal::String(ScString(
            "1000000".try_into().expect("string fits ScString"),
        ));

        for (label, val) in [("Bytes", byte_val), ("String", string_val)] {
            // Use a recognised schema-anticipation key to verify value-type rejection.
            let criteria = single_entry_map(b"value_threshold", val);
            assert_eq!(
                extract_value_threshold(&criteria),
                ValueThresholdResult::Undetermined,
                "recognised key with non-integer value ({label}) must return Undetermined"
            );
        }
    }

    // ── Test 5: I128 value that overflows i64::MAX returns Undetermined ───────

    /// Verifies fail-CLOSED on an `ScVal::I128` whose mathematical value
    /// exceeds `i64::MAX`, using all schema-anticipation keys.
    ///
    /// Three overflow cases per key:
    /// - `hi != 0` (value is either negative or > 2^63-1).
    /// - `hi == 0, lo > i64::MAX as u64` (lo alone overflows `i64`).
    /// - `hi < 0` (negative value).
    #[test]
    fn extract_value_threshold_returns_undetermined_for_overflow() {
        // hi = 1 means value ≥ 2^64, far above i64::MAX.
        let hi_nonzero = ScVal::I128(Int128Parts { hi: 1, lo: 0 });
        // hi = 0, lo = u64::MAX = 18446744073709551615 > i64::MAX.
        let lo_overflow = ScVal::I128(Int128Parts {
            hi: 0,
            lo: u64::MAX,
        });
        // hi = -1 (signed) means the value is negative.
        let hi_negative = ScVal::I128(Int128Parts { hi: -1, lo: 0 });

        let overflow_cases = [
            ("hi_nonzero", hi_nonzero),
            ("lo_overflow", lo_overflow),
            ("hi_negative", hi_negative),
        ];

        // Verify all overflow cases against all recognised schema-anticipation keys.
        for key in [b"value_threshold".as_ref(), b"max_stroops".as_ref()] {
            for (label, val) in &overflow_cases {
                let criteria = single_entry_map(key, val.clone());
                assert_eq!(
                    extract_value_threshold(&criteria),
                    ValueThresholdResult::Undetermined,
                    "I128 overflow case '{label}' on key {key:?} must return Undetermined"
                );
            }
        }
    }

    // ── Test 6: empty ScMap returns Undetermined ──────────────────────────────

    /// Verifies fail-CLOSED on an empty `ScMap`.
    ///
    /// An empty map cannot contain any recognised value-threshold key and must
    /// return `Undetermined`.
    #[test]
    fn extract_value_threshold_returns_undetermined_for_empty_map() {
        let empty_entries: VecM<ScMapEntry> = VecM::default();
        let criteria = ScVal::Map(Some(ScMap(empty_entries)));
        assert_eq!(
            extract_value_threshold(&criteria),
            ValueThresholdResult::Undetermined,
            "empty ScMap must return Undetermined"
        );
    }

    // ── Test 7: schema-anticipation forward-compat keys return Stroops ────────

    /// Verifies that the two schema-anticipation forward-compat keys
    /// `b"value_threshold"` and `b"max_stroops"` are recognised when paired
    /// with a valid `ScVal::I128` value.
    ///
    /// Neither key exists in any OZ v0.7.1 contract (SHA `3f81125`).
    /// Not yet supported: schema-anticipation for canonical OZ PerTxCap encoding.
    #[test]
    fn extract_value_threshold_recognises_schema_anticipation_keys() {
        for key in [b"value_threshold".as_ref(), b"max_stroops".as_ref()] {
            let criteria = single_entry_map(key, i128_from_nonneg_i64(500_000_000));
            assert_eq!(
                extract_value_threshold(&criteria),
                ValueThresholdResult::Stroops(500_000_000),
                "schema-anticipation key {key:?} with valid I128 must return Stroops"
            );
        }
    }

    // ── Test 8: i64::MAX boundary ─────────────────────────────────────────────

    /// Verifies the i64::MAX boundary: hi=0, lo=i64::MAX as u64 returns Stroops.
    /// Uses a schema-anticipation key (`value_threshold`).
    #[test]
    fn extract_value_threshold_accepts_i64_max_via_schema_anticipation_key() {
        let val = ScVal::I128(Int128Parts {
            hi: 0,
            lo: i64::MAX as u64,
        });
        let criteria = single_entry_map(b"value_threshold", val);
        assert_eq!(
            extract_value_threshold(&criteria),
            ValueThresholdResult::Stroops(i64::MAX),
            "i64::MAX value on value_threshold key must return Stroops(i64::MAX)"
        );
    }

    #[test]
    fn extract_value_threshold_uses_first_recognised_key_when_multiple_keys_exist() {
        let entries: VecM<ScMapEntry> = vec![
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol(
                    b"value_threshold".as_ref().try_into().expect("symbol fits"),
                )),
                val: i128_from_nonneg_i64(111),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol(
                    b"max_stroops".as_ref().try_into().expect("symbol fits"),
                )),
                val: i128_from_nonneg_i64(222),
            },
        ]
        .try_into()
        .expect("two entries fit VecM");
        let criteria = ScVal::Map(Some(ScMap(entries)));

        assert_eq!(
            extract_value_threshold(&criteria),
            ValueThresholdResult::Stroops(111),
            "extractor must use the first recognised key in ScMap iteration order"
        );
    }
}
