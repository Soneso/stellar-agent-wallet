//! Decoded on-chain `SpendingLimitData` and rolling-window budget math.
//!
//! Off-chain mirror of the OZ `stellar-accounts` v0.7.2 spending-limit-policy
//! storage struct (`packages/accounts/src/policies/spending_limit.rs:99-118`,
//! SHA `a9c42169000638da937577f592ebf61a7a3c94ca`), plus the pure budget
//! computation `SignersManager::get_spending_limit_data` callers use to derive
//! an as-of-ledger spend snapshot.
//!
//! # Byte layout
//!
//! `SpendingLimitData` and `SpendingEntry` are soroban-sdk `#[contracttype]`
//! structs. Each encodes to `ScVal::Map` with one entry per field, keyed by
//! `ScVal::Symbol(field_name)`, in ascending byte-lexicographic key order (the
//! soroban host's ScMap validity rule — the same convention documented in
//! `crate::spending_limit_policy::build_spending_limit_install_param`):
//!
//! - `SpendingLimitData`: `cached_total_spent`, `period_ledgers`,
//!   `spending_history`, `spending_limit` (alphabetical: `c` < `p` <
//!   `spending_h` < `spending_l`).
//! - `SpendingEntry`: `amount`, `ledger_sequence`.
//!
//! [`decode_spending_limit_data`] scans map entries by key regardless of
//! position, so it does not depend on this ordering for correctness — the
//! ordering is documented here only because it is what a hand-built test
//! fixture or a `stellar-xdr` CLI dump will show.
//!
//! # Point-in-time caveat
//!
//! [`compute_spending_window`] produces a snapshot that is exact only as of
//! the ledger it is given. See [`SpendingWindow`] for the full caveat.

use stellar_xdr::{Int128Parts, ScVal};

use crate::SaError;

/// The soroban-rpc entrypoint name, used consistently in decode error messages.
const ENTRYPOINT: &str = "get_spending_limit_data";

// ── Decoded types ─────────────────────────────────────────────────────────────

/// Off-chain mirror of the OZ `SpendingLimitData` `#[contracttype]` struct.
///
/// Produced by [`decode_spending_limit_data`] from a `get_spending_limit_data`
/// simulation return value.
///
/// # Byte layout
///
/// `packages/accounts/src/policies/spending_limit.rs:99-108`, SHA `a9c4216`:
///
/// ```text
/// pub struct SpendingLimitData {
///     pub spending_limit: i128,
///     pub period_ledgers: u32,
///     pub spending_history: Vec<SpendingEntry>,
///     pub cached_total_spent: i128,
/// }
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendingLimitData {
    /// The spending limit for the period, in stroops.
    pub spending_limit: i128,
    /// The period in ledgers over which the spending limit applies.
    pub period_ledgers: u32,
    /// History of spending transactions with their ledger sequences.
    ///
    /// `get_spending_limit_data` performs no eviction on read
    /// (`spending_limit.rs:175-192`, SHA `a9c4216`) — eviction runs lazily
    /// inside `enforce` (`spending_limit.rs:250`), so this history may
    /// contain entries already outside the rolling window. Use
    /// [`compute_spending_window`] to derive the in-window subset.
    pub spending_history: Vec<SpendingEntry>,
    /// Cached total of all amounts in `spending_history`, as last updated by
    /// `enforce`.
    ///
    /// May be stale relative to the current ledger: it reflects the total at
    /// the last write, before any entries that have since aged out of the
    /// rolling window were evicted. Do not use this field as the in-window
    /// spent total; use [`SpendingWindow::in_window_spent`] instead.
    pub cached_total_spent: i128,
}

/// Off-chain mirror of the OZ `SpendingEntry` `#[contracttype]` struct.
///
/// `packages/accounts/src/policies/spending_limit.rs:110-118`, SHA `a9c4216`:
///
/// ```text
/// pub struct SpendingEntry {
///     pub amount: i128,
///     pub ledger_sequence: u32,
/// }
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpendingEntry {
    /// The amount spent in this transaction, in stroops.
    pub amount: i128,
    /// The ledger sequence when this transaction occurred.
    pub ledger_sequence: u32,
}

// ── Decoder ───────────────────────────────────────────────────────────────────

/// Decodes a `get_spending_limit_data` simulation return value into
/// [`SpendingLimitData`].
///
/// Scans the `ScVal::Map` entries by key (order-independent) and requires all
/// four fields to be present with the expected `ScVal` discriminant.
///
/// # Errors
///
/// Returns [`SaError::DeploymentFailed`] (phase `"simulate"`) when:
///
/// - `val` is not `ScVal::Map(Some(_))`.
/// - Any of the four required fields (`spending_limit`, `period_ledgers`,
///   `spending_history`, `cached_total_spent`) is absent.
/// - A present field has an unexpected `ScVal` discriminant.
/// - Any `spending_history` entry is not a well-formed `SpendingEntry` map
///   (missing `amount` / `ledger_sequence`, wrong type, or non-`Map` shape).
pub fn decode_spending_limit_data(val: &ScVal) -> Result<SpendingLimitData, SaError> {
    let ScVal::Map(Some(map)) = val else {
        return Err(shape_err(&format!("expected ScVal::Map, got {val:?}")));
    };

    let mut spending_limit: Option<i128> = None;
    let mut period_ledgers: Option<u32> = None;
    let mut spending_history: Option<Vec<SpendingEntry>> = None;
    let mut cached_total_spent: Option<i128> = None;

    for entry in map.iter() {
        let ScVal::Symbol(key_sym) = &entry.key else {
            continue;
        };
        match key_sym.as_slice() {
            b"spending_limit" => {
                spending_limit = Some(decode_i128_field(&entry.val, "spending_limit")?);
            }
            b"period_ledgers" => {
                period_ledgers = Some(decode_u32_field(&entry.val, "period_ledgers")?);
            }
            b"spending_history" => {
                let ScVal::Vec(Some(entries)) = &entry.val else {
                    return Err(shape_err(&format!(
                        "spending_history field is not ScVal::Vec, got {:?}",
                        entry.val
                    )));
                };
                let mut history = Vec::with_capacity(entries.len());
                for item in entries.iter() {
                    history.push(decode_spending_entry(item)?);
                }
                spending_history = Some(history);
            }
            b"cached_total_spent" => {
                cached_total_spent = Some(decode_i128_field(&entry.val, "cached_total_spent")?);
            }
            _ => {}
        }
    }

    let spending_limit = spending_limit.ok_or_else(|| missing_field_err("spending_limit"))?;
    let period_ledgers = period_ledgers.ok_or_else(|| missing_field_err("period_ledgers"))?;
    let spending_history = spending_history.ok_or_else(|| missing_field_err("spending_history"))?;
    let cached_total_spent =
        cached_total_spent.ok_or_else(|| missing_field_err("cached_total_spent"))?;

    Ok(SpendingLimitData {
        spending_limit,
        period_ledgers,
        spending_history,
        cached_total_spent,
    })
}

/// Decodes a single `SpendingEntry` map from a `spending_history` vector item.
fn decode_spending_entry(val: &ScVal) -> Result<SpendingEntry, SaError> {
    let ScVal::Map(Some(map)) = val else {
        return Err(shape_err(&format!(
            "spending_history entry is not ScVal::Map, got {val:?}"
        )));
    };

    let mut amount: Option<i128> = None;
    let mut ledger_sequence: Option<u32> = None;

    for entry in map.iter() {
        let ScVal::Symbol(key_sym) = &entry.key else {
            continue;
        };
        match key_sym.as_slice() {
            b"amount" => {
                amount = Some(decode_i128_field(&entry.val, "spending_history[].amount")?);
            }
            b"ledger_sequence" => {
                ledger_sequence = Some(decode_u32_field(
                    &entry.val,
                    "spending_history[].ledger_sequence",
                )?);
            }
            _ => {}
        }
    }

    let amount = amount.ok_or_else(|| missing_field_err("spending_history[].amount"))?;
    let ledger_sequence =
        ledger_sequence.ok_or_else(|| missing_field_err("spending_history[].ledger_sequence"))?;

    Ok(SpendingEntry {
        amount,
        ledger_sequence,
    })
}

/// Decodes an `ScVal::I128` field, returning a typed shape error on mismatch.
fn decode_i128_field(val: &ScVal, field_name: &'static str) -> Result<i128, SaError> {
    let ScVal::I128(parts) = val else {
        return Err(shape_err(&format!(
            "{field_name} field is not ScVal::I128, got {val:?}"
        )));
    };
    Ok(i128_from_parts(parts))
}

/// Decodes an `ScVal::U32` field, returning a typed shape error on mismatch.
fn decode_u32_field(val: &ScVal, field_name: &'static str) -> Result<u32, SaError> {
    let ScVal::U32(n) = val else {
        return Err(shape_err(&format!(
            "{field_name} field is not ScVal::U32, got {val:?}"
        )));
    };
    Ok(*n)
}

/// Reconstructs an `i128` from its `Int128Parts { hi, lo }` split.
///
/// `value == ((hi as i128) << 64) | (lo as i128)` — the same reconstruction
/// [`crate::spending_limit_policy::build_spending_limit_install_param`]'s
/// tests already round-trip in the opposite (encode) direction.
fn i128_from_parts(parts: &Int128Parts) -> i128 {
    (i128::from(parts.hi) << 64) | i128::from(parts.lo)
}

/// Builds a [`SaError::DeploymentFailed`] shape-refusal error.
fn shape_err(detail: &str) -> SaError {
    SaError::DeploymentFailed {
        phase: "simulate",
        redacted_reason: format!("{ENTRYPOINT}: {detail}"),
    }
}

/// Builds a [`SaError::DeploymentFailed`] missing-field error.
fn missing_field_err(field_name: &'static str) -> SaError {
    shape_err(&format!("missing '{field_name}' field"))
}

// ── Budget math ───────────────────────────────────────────────────────────────

/// The as-of-ledger rolling-window budget snapshot for a spending-limit
/// policy.
///
/// # Point-in-time caveat
///
/// Values are exact only as of the ledger supplied to
/// [`compute_spending_window`]. Forward ledger movement past that point only
/// grows headroom (older entries fall out of the window through eviction);
/// an intervening spend, however, shrinks it. `remaining` is therefore an
/// estimate, not a guarantee — a transfer sized against a stale snapshot can
/// still fail on-chain with `SpendingLimitError::SpendingLimitExceeded`
/// (code 3221).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpendingWindow {
    /// Ledger sequence at and before which history entries are excluded from
    /// `in_window_spent` (`current_ledger.saturating_sub(period_ledgers)`).
    pub window_cutoff_ledger: u32,
    /// Sum of `spending_history` entry amounts whose `ledger_sequence` is
    /// strictly greater than `window_cutoff_ledger`.
    pub in_window_spent: i128,
    /// `max(0, spending_limit - in_window_spent)`.
    pub remaining: i128,
}

/// Computes the rolling-window budget snapshot for `data` as of
/// `current_ledger`.
///
/// Replicates the OZ `cleanup_old_entries` eviction predicate exactly
/// (`packages/accounts/src/policies/spending_limit.rs:460-481`, SHA
/// `a9c4216`): the contract evicts an entry when
/// `entry.ledger_sequence <= current_ledger.saturating_sub(period_ledgers)`,
/// so an entry counts toward `in_window_spent` iff
/// `entry.ledger_sequence > current_ledger.saturating_sub(period_ledgers)`
/// — the strict-greater-than complement of the eviction condition.
///
/// Deliberately ignores `data.cached_total_spent`: `get_spending_limit_data`
/// performs no eviction on read (`spending_limit.rs:175-192`, SHA `a9c4216`
/// — eviction runs lazily inside `enforce`, `spending_limit.rs:250`), so
/// `cached_total_spent` can include entries that have already fallen outside
/// the rolling window. Summing the in-window entries directly avoids
/// surfacing that stale total.
///
/// `remaining` clamps to zero: a history that is already over-limit (possible
/// when the limit was retuned downward after spends were recorded) never
/// reports a negative budget.
#[must_use]
pub fn compute_spending_window(data: &SpendingLimitData, current_ledger: u32) -> SpendingWindow {
    let window_cutoff_ledger = current_ledger.saturating_sub(data.period_ledgers);

    let in_window_spent: i128 = data
        .spending_history
        .iter()
        .filter(|entry| entry.ledger_sequence > window_cutoff_ledger)
        .fold(0i128, |acc, entry| acc.saturating_add(entry.amount));

    let remaining = data.spending_limit.saturating_sub(in_window_spent).max(0);

    SpendingWindow {
        window_cutoff_ledger,
        in_window_spent,
        remaining,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test-only")]
    #![allow(
        clippy::panic,
        reason = "test-only: panics are the correct failure mode"
    )]

    use stellar_xdr::{ScMap, ScMapEntry, ScSymbol, ScVec, VecM};

    use super::*;

    // ── Fixture builders ──────────────────────────────────────────────────────

    fn sym(name: &str) -> ScVal {
        ScVal::Symbol(ScSymbol::try_from(name).unwrap())
    }

    fn i128_val(v: i128) -> ScVal {
        #[allow(
            clippy::cast_possible_truncation,
            reason = "canonical i128 -> Int128Parts split: hi = high 64 bits, lo = low 64 bits"
        )]
        let parts = Int128Parts {
            hi: (v >> 64) as i64,
            lo: v as u64,
        };
        ScVal::I128(parts)
    }

    fn spending_entry_val(amount: i128, ledger_sequence: u32) -> ScVal {
        let entries: VecM<ScMapEntry> = vec![
            ScMapEntry {
                key: sym("amount"),
                val: i128_val(amount),
            },
            ScMapEntry {
                key: sym("ledger_sequence"),
                val: ScVal::U32(ledger_sequence),
            },
        ]
        .try_into()
        .unwrap();
        ScVal::Map(Some(ScMap(entries)))
    }

    /// Builds a well-formed `SpendingLimitData` `ScVal::Map` in the canonical
    /// alphabetical key order (`cached_total_spent`, `period_ledgers`,
    /// `spending_history`, `spending_limit`).
    fn spending_limit_data_val(
        spending_limit: i128,
        period_ledgers: u32,
        history: &[(i128, u32)],
        cached_total_spent: i128,
    ) -> ScVal {
        let history_entries: VecM<ScVal> = history
            .iter()
            .map(|&(amount, seq)| spending_entry_val(amount, seq))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let entries: VecM<ScMapEntry> = vec![
            ScMapEntry {
                key: sym("cached_total_spent"),
                val: i128_val(cached_total_spent),
            },
            ScMapEntry {
                key: sym("period_ledgers"),
                val: ScVal::U32(period_ledgers),
            },
            ScMapEntry {
                key: sym("spending_history"),
                val: ScVal::Vec(Some(ScVec(history_entries))),
            },
            ScMapEntry {
                key: sym("spending_limit"),
                val: i128_val(spending_limit),
            },
        ]
        .try_into()
        .unwrap();
        ScVal::Map(Some(ScMap(entries)))
    }

    // ── Decoder: round-trip ────────────────────────────────────────────────────

    #[test]
    fn decode_spending_limit_data_round_trips_four_fields() {
        let val = spending_limit_data_val(10_000_000, 17_280, &[(1_000, 100), (2_000, 200)], 3_000);
        let data = decode_spending_limit_data(&val).unwrap();
        assert_eq!(data.spending_limit, 10_000_000);
        assert_eq!(data.period_ledgers, 17_280);
        assert_eq!(
            data.spending_history,
            vec![
                SpendingEntry {
                    amount: 1_000,
                    ledger_sequence: 100
                },
                SpendingEntry {
                    amount: 2_000,
                    ledger_sequence: 200
                },
            ]
        );
        assert_eq!(data.cached_total_spent, 3_000);
    }

    #[test]
    fn decode_spending_limit_data_round_trips_empty_history() {
        let val = spending_limit_data_val(500, 100, &[], 0);
        let data = decode_spending_limit_data(&val).unwrap();
        assert_eq!(data.spending_limit, 500);
        assert_eq!(data.period_ledgers, 100);
        assert!(data.spending_history.is_empty());
        assert_eq!(data.cached_total_spent, 0);
    }

    #[test]
    fn decode_spending_limit_data_round_trips_negative_and_large_i128() {
        let val = spending_limit_data_val(i128::MAX, u32::MAX, &[(i128::MAX, 1)], i128::MAX);
        let data = decode_spending_limit_data(&val).unwrap();
        assert_eq!(data.spending_limit, i128::MAX);
        assert_eq!(data.period_ledgers, u32::MAX);
        assert_eq!(data.spending_history[0].amount, i128::MAX);
        assert_eq!(data.cached_total_spent, i128::MAX);

        // Negative extremes: the on-chain domain is positive (install and
        // set_spending_limit both refuse non-positive limits), but the
        // decoder is a generic Int128Parts reconstruction and must be sign
        // correct for any value it is handed.
        let val = spending_limit_data_val(i128::MIN, 1, &[(-1, 7), (i128::MIN, 8)], -42);
        let data = decode_spending_limit_data(&val).unwrap();
        assert_eq!(data.spending_limit, i128::MIN);
        assert_eq!(data.spending_history[0].amount, -1);
        assert_eq!(data.spending_history[1].amount, i128::MIN);
        assert_eq!(data.cached_total_spent, -42);
    }

    // ── Decoder: malformed-shape refusals ──────────────────────────────────────

    #[test]
    fn decode_spending_limit_data_refuses_non_map_scval() {
        let result = decode_spending_limit_data(&ScVal::Void);
        match result {
            Err(SaError::DeploymentFailed { phase, .. }) => assert_eq!(phase, "simulate"),
            other => panic!("expected DeploymentFailed, got {other:?}"),
        }
    }

    #[test]
    fn decode_spending_limit_data_refuses_missing_field() {
        // Build a map missing 'cached_total_spent'.
        let entries: VecM<ScMapEntry> = vec![
            ScMapEntry {
                key: sym("period_ledgers"),
                val: ScVal::U32(100),
            },
            ScMapEntry {
                key: sym("spending_history"),
                val: ScVal::Vec(Some(ScVec(VecM::default()))),
            },
            ScMapEntry {
                key: sym("spending_limit"),
                val: i128_val(500),
            },
        ]
        .try_into()
        .unwrap();
        let val = ScVal::Map(Some(ScMap(entries)));

        let result = decode_spending_limit_data(&val);
        match result {
            Err(SaError::DeploymentFailed {
                phase,
                redacted_reason,
            }) => {
                assert_eq!(phase, "simulate");
                assert!(redacted_reason.contains("cached_total_spent"));
            }
            other => panic!("expected DeploymentFailed, got {other:?}"),
        }
    }

    #[test]
    fn decode_spending_limit_data_refuses_wrong_type_for_period_ledgers() {
        // `period_ledgers` given as ScVal::I128 instead of ScVal::U32.
        let entries: VecM<ScMapEntry> = vec![
            ScMapEntry {
                key: sym("cached_total_spent"),
                val: i128_val(0),
            },
            ScMapEntry {
                key: sym("period_ledgers"),
                val: i128_val(100),
            },
            ScMapEntry {
                key: sym("spending_history"),
                val: ScVal::Vec(Some(ScVec(VecM::default()))),
            },
            ScMapEntry {
                key: sym("spending_limit"),
                val: i128_val(500),
            },
        ]
        .try_into()
        .unwrap();
        let val = ScVal::Map(Some(ScMap(entries)));

        let result = decode_spending_limit_data(&val);
        match result {
            Err(SaError::DeploymentFailed {
                phase,
                redacted_reason,
            }) => {
                assert_eq!(phase, "simulate");
                assert!(redacted_reason.contains("period_ledgers"));
            }
            other => panic!("expected DeploymentFailed, got {other:?}"),
        }
    }

    #[test]
    fn decode_spending_limit_data_refuses_truncated_history_entry() {
        // A spending_history entry map missing 'ledger_sequence'.
        let truncated_entry: VecM<ScMapEntry> = vec![ScMapEntry {
            key: sym("amount"),
            val: i128_val(1_000),
        }]
        .try_into()
        .unwrap();
        let history: VecM<ScVal> = vec![ScVal::Map(Some(ScMap(truncated_entry)))]
            .try_into()
            .unwrap();

        let val = spending_limit_data_val(500, 100, &[], 0);
        // Splice in the truncated history vec by rebuilding the outer map.
        let ScVal::Map(Some(ScMap(mut outer_entries))) = val else {
            panic!("fixture must be Map")
        };
        for entry in outer_entries.iter_mut() {
            if entry.key == sym("spending_history") {
                entry.val = ScVal::Vec(Some(ScVec(history.clone())));
            }
        }
        let spliced = ScVal::Map(Some(ScMap(outer_entries)));

        let result = decode_spending_limit_data(&spliced);
        match result {
            Err(SaError::DeploymentFailed {
                phase,
                redacted_reason,
            }) => {
                assert_eq!(phase, "simulate");
                assert!(redacted_reason.contains("ledger_sequence"));
            }
            other => panic!("expected DeploymentFailed, got {other:?}"),
        }
    }

    #[test]
    fn decode_spending_limit_data_refuses_non_map_history_entry() {
        let val = spending_limit_data_val(500, 100, &[], 0);
        let ScVal::Map(Some(ScMap(mut outer_entries))) = val else {
            panic!("fixture must be Map")
        };
        for entry in outer_entries.iter_mut() {
            if entry.key == sym("spending_history") {
                let bad_history: VecM<ScVal> = vec![ScVal::U32(7)].try_into().unwrap();
                entry.val = ScVal::Vec(Some(ScVec(bad_history)));
            }
        }
        let spliced = ScVal::Map(Some(ScMap(outer_entries)));

        let result = decode_spending_limit_data(&spliced);
        match result {
            Err(SaError::DeploymentFailed { phase, .. }) => assert_eq!(phase, "simulate"),
            other => panic!("expected DeploymentFailed, got {other:?}"),
        }
    }

    // ── Budget math ─────────────────────────────────────────────────────────────

    fn data_with_history(
        spending_limit: i128,
        period_ledgers: u32,
        history: Vec<SpendingEntry>,
    ) -> SpendingLimitData {
        SpendingLimitData {
            spending_limit,
            period_ledgers,
            spending_history: history,
            cached_total_spent: 0,
        }
    }

    #[test]
    fn compute_spending_window_boundary_entry_exactly_at_cutoff_is_excluded() {
        // current_ledger = 100, period_ledgers = 20 => cutoff = 80.
        // An entry at ledger_sequence == 80 must be EXCLUDED (OZ evicts <= cutoff).
        let data = data_with_history(
            1_000,
            20,
            vec![SpendingEntry {
                amount: 500,
                ledger_sequence: 80,
            }],
        );
        let window = compute_spending_window(&data, 100);
        assert_eq!(window.window_cutoff_ledger, 80);
        assert_eq!(
            window.in_window_spent, 0,
            "entry at exactly the cutoff must be excluded"
        );
        assert_eq!(window.remaining, 1_000);
    }

    #[test]
    fn compute_spending_window_entry_one_past_cutoff_is_included() {
        let data = data_with_history(
            1_000,
            20,
            vec![SpendingEntry {
                amount: 500,
                ledger_sequence: 81,
            }],
        );
        let window = compute_spending_window(&data, 100);
        assert_eq!(window.window_cutoff_ledger, 80);
        assert_eq!(window.in_window_spent, 500);
        assert_eq!(window.remaining, 500);
    }

    #[test]
    fn compute_spending_window_saturates_cutoff_near_genesis() {
        // current_ledger < period_ledgers => cutoff saturates to 0, nothing is evicted.
        let data = data_with_history(
            1_000,
            500,
            vec![SpendingEntry {
                amount: 200,
                ledger_sequence: 1,
            }],
        );
        let window = compute_spending_window(&data, 10);
        assert_eq!(window.window_cutoff_ledger, 0);
        assert_eq!(window.in_window_spent, 200);
        assert_eq!(window.remaining, 800);
    }

    #[test]
    fn compute_spending_window_empty_history_yields_full_remaining_budget() {
        let data = data_with_history(1_000, 100, vec![]);
        let window = compute_spending_window(&data, 500);
        assert_eq!(window.in_window_spent, 0);
        assert_eq!(window.remaining, 1_000);
    }

    #[test]
    fn compute_spending_window_ignores_stale_cached_total_spent() {
        // cached_total_spent reflects a total that no longer matches the
        // in-window entries (all history has aged out); in_window_spent must
        // be computed from spending_history, not cached_total_spent.
        let mut data = data_with_history(
            1_000,
            10,
            vec![SpendingEntry {
                amount: 900,
                ledger_sequence: 5,
            }],
        );
        data.cached_total_spent = 900; // stale: entry is now outside the window.
        let window = compute_spending_window(&data, 100); // cutoff = 90; entry at 5 is evicted.
        assert_eq!(
            window.in_window_spent, 0,
            "stale cached_total_spent must not leak into in_window_spent"
        );
        assert_eq!(window.remaining, 1_000);
    }

    #[test]
    fn compute_spending_window_over_spent_history_clamps_remaining_to_zero() {
        // Limit retuned down below the in-window total: remaining must clamp to 0,
        // never go negative.
        let data = data_with_history(
            100,
            1_000,
            vec![
                SpendingEntry {
                    amount: 60,
                    ledger_sequence: 50,
                },
                SpendingEntry {
                    amount: 60,
                    ledger_sequence: 60,
                },
            ],
        );
        let window = compute_spending_window(&data, 100);
        assert_eq!(window.in_window_spent, 120);
        assert_eq!(
            window.remaining, 0,
            "remaining must clamp to 0, not go negative"
        );
    }

    #[test]
    fn compute_spending_window_sums_multiple_in_window_entries() {
        let data = data_with_history(
            1_000,
            50,
            vec![
                SpendingEntry {
                    amount: 100,
                    ledger_sequence: 60,
                },
                SpendingEntry {
                    amount: 200,
                    ledger_sequence: 70,
                },
                SpendingEntry {
                    amount: 50,
                    ledger_sequence: 10, // outside window: cutoff = 100-50=50, 10 <= 50 evicted
                },
            ],
        );
        let window = compute_spending_window(&data, 100);
        assert_eq!(window.window_cutoff_ledger, 50);
        assert_eq!(window.in_window_spent, 300);
        assert_eq!(window.remaining, 700);
    }
}
