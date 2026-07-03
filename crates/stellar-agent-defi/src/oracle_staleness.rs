//! Protocol-agnostic oracle-staleness substrate.
//!
//! # What this module does
//!
//! Provides the shared oracle-staleness types, evaluation function, and
//! override mechanism used by multiple DeFi adapter crates (Blend, DeFindex,
//! etc.) without requiring a cross-adapter dependency.
//!
//! ## Protocol-agnostic contract
//!
//! None of these types mention Blend in their signatures.  The
//! Blend-specific pieces (Reflector allowlist, `read_pool_oracle_address`,
//! `query_oracle_lastprice_timestamps`) remain in `stellar-agent-blend`.
//!
//! # Ordered trust invariant
//!
//! The dispatch site enforces via `?`-early-return that the
//! [`OracleStalenessSnapshot`] is constructed ONLY after pin-verify passes.
//! A `None` view in [`OracleStalenessEvalExt::evaluate`] is treated as a
//! REFUSE (fail-closed-on-absent): a missing view means the ordered gate did
//! not complete, so proceeding would silently bypass the gate.
//!
//! # Override semantics
//!
//! The staleness override is off by default.  When used,
//! [`proceed_with_staleness_override`] emits an `oracle.staleness_overridden`
//! audit event **unconditionally** before returning a [`StalenessOverrideToken`]
//! (EMIT-THEN-RETURN mechanism: the only way to obtain the token is through
//! this call, so a future edit cannot add a proceed path that forgets the
//! audit event). This mirrors the [`crate::dispatch::SubmitWitness`] pattern.

use std::time::{SystemTime, UNIX_EPOCH};

use stellar_agent_core::observability::redact_strkey_first5_last5;

/// The default oracle staleness threshold in seconds (600s = 10 minutes).
///
/// Tighter than most protocol on-chain thresholds.  Used as the default
/// for both Blend and DeFindex.
pub const DEFAULT_MAX_STALENESS_SECS: u64 = 600;

// ─────────────────────────────────────────────────────────────────────────────
// OracleStalenessView
// ─────────────────────────────────────────────────────────────────────────────

/// View trait injected as `Option<&dyn OracleStalenessView>` into
/// `EvalContext` when the oracle-staleness criterion is active.
///
/// Follows the `#[non_exhaustive]` + circular-dep-break pattern used by
/// `stellar-agent-core`'s policy engine for injected views.
///
/// The concrete implementation is [`OracleStalenessSnapshot`].
///
/// Constructed ONLY after the ordered gate passes (pin-verify → allowlist),
/// so a `None` view unambiguously means "gate did not run" → REFUSE.
pub trait OracleStalenessView: Send + Sync {
    /// Returns the maximum staleness threshold in seconds.
    fn max_staleness_secs(&self) -> u64;

    /// Returns the worst-case staleness for all oracle price entries
    /// associated with the DeFi operation — i.e. the maximum
    /// `now - timestamp` across all assets touched.
    ///
    /// Returns `None` if no price data is available (treat as stale/refuse).
    fn worst_case_age_secs(&self) -> Option<u64>;
}

// ─────────────────────────────────────────────────────────────────────────────
// OracleStalenessSnapshot
// ─────────────────────────────────────────────────────────────────────────────

/// Concrete [`OracleStalenessView`] produced after the ordered gate passes.
///
/// Holds the oracle address (redacted), the max staleness threshold, and
/// the worst-case price age for the touched assets.
///
/// # Display
///
/// `Display` emits `oracle=<first-5-last-5> age=<N>s threshold=<N>s`.
/// The full oracle address is NEVER included; only the first-5-last-5 redacted
/// form is emitted per the strkey redaction rules.
#[derive(Debug)]
pub struct OracleStalenessSnapshot {
    /// First-5-last-5 redacted oracle address (for Display and Debug).
    oracle_redacted: String,
    /// Maximum staleness threshold in seconds.
    max_staleness_secs: u64,
    /// Worst-case price age in seconds across all touched assets.
    ///
    /// `None` if no price data was available.
    worst_case_age_secs: Option<u64>,
}

impl std::fmt::Display for OracleStalenessSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The full oracle address is NEVER emitted; the first-5-last-5 redacted
        // form is safe for logs per the strkey redaction rules.
        let age = self
            .worst_case_age_secs
            .map_or_else(|| "unavailable".to_owned(), |a| format!("{a}s"));
        write!(
            f,
            "oracle={} age={} threshold={}s",
            self.oracle_redacted, age, self.max_staleness_secs
        )
    }
}

impl OracleStalenessSnapshot {
    /// Constructs a snapshot from raw price timestamps.
    ///
    /// `price_timestamps` is a slice of UNIX timestamps from `PriceData.timestamp`
    /// as returned by the oracle's `lastprice` function, one per touched asset.
    /// The worst-case age is `now - min(timestamps)`.
    ///
    /// # Returns
    ///
    /// Returns `None` when `price_timestamps` is empty or when `now` cannot
    /// be determined (system clock failure).
    #[must_use]
    pub fn new(
        oracle_address: &str,
        price_timestamps: &[u64],
        max_staleness_secs: u64,
    ) -> Option<Self> {
        if price_timestamps.is_empty() {
            return None;
        }
        let now_secs = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
        // Safety: we checked is_empty() above, so min() returns Some.
        let oldest_timestamp = price_timestamps.iter().copied().min()?;
        let age = now_secs.saturating_sub(oldest_timestamp);
        Some(Self {
            oracle_redacted: redact_strkey_first5_last5(oracle_address),
            max_staleness_secs,
            worst_case_age_secs: Some(age),
        })
    }

    /// Constructs a snapshot representing "no price data available".
    ///
    /// The criterion will refuse on this snapshot regardless of threshold.
    #[must_use]
    pub fn unavailable(oracle_address: &str, max_staleness_secs: u64) -> Self {
        Self {
            oracle_redacted: redact_strkey_first5_last5(oracle_address),
            max_staleness_secs,
            worst_case_age_secs: None,
        }
    }
}

impl OracleStalenessView for OracleStalenessSnapshot {
    fn max_staleness_secs(&self) -> u64 {
        self.max_staleness_secs
    }

    fn worst_case_age_secs(&self) -> Option<u64> {
        self.worst_case_age_secs
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StalenessCheckResult
// ─────────────────────────────────────────────────────────────────────────────

/// The result of evaluating oracle staleness.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StalenessCheckResult {
    /// The price is fresh (within the threshold).
    Fresh {
        /// How old the oldest price is, in seconds.
        timestamp_delta_secs: u64,
    },
    /// The price is stale (exceeds the threshold).
    Stale {
        /// How old the oldest price is, in seconds.
        timestamp_delta_secs: u64,
    },
    /// No price data was available.
    Unavailable,
}

/// Evaluates oracle staleness from a [`OracleStalenessView`].
///
/// Returns [`StalenessCheckResult::Fresh`] if within threshold,
/// [`StalenessCheckResult::Stale`] if over threshold,
/// or [`StalenessCheckResult::Unavailable`] if no data.
#[must_use]
pub fn evaluate_staleness(view: &dyn OracleStalenessView) -> StalenessCheckResult {
    match view.worst_case_age_secs() {
        None => StalenessCheckResult::Unavailable,
        Some(age) => {
            if age <= view.max_staleness_secs() {
                StalenessCheckResult::Fresh {
                    timestamp_delta_secs: age,
                }
            } else {
                StalenessCheckResult::Stale {
                    timestamp_delta_secs: age,
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// proceed_with_staleness_override — EMIT-THEN-RETURN mechanism
// ─────────────────────────────────────────────────────────────────────────────

/// Emits the `oracle.staleness_overridden` audit event and returns an
/// override token.
///
/// The proceed path on staleness override is reachable ONLY through this
/// function — it ALWAYS emits the audit event before returning.  A future
/// edit cannot add a proceed branch that forgets the event, because the
/// only way to get the [`StalenessOverrideToken`] is through this call.
/// This is the EMIT-THEN-RETURN mechanism (see [`crate::dispatch::SubmitWitness`]
/// for the same pattern applied to the dispatch gate).
///
/// # Note on `timestamp_delta_secs`
///
/// The override audit event carries ONLY the timestamp delta and threshold —
/// NOT the oracle address or full hash per the redaction rules.
pub fn proceed_with_staleness_override(
    timestamp_delta_secs: u64,
    max_staleness_secs: u64,
) -> StalenessOverrideToken {
    // EMIT-THEN-RETURN: the audit event MUST be emitted before the token is
    // produced.  The token proves this function was called.
    tracing::warn!(
        event = "oracle.staleness_overridden",
        timestamp_delta_secs = timestamp_delta_secs,
        max_staleness_secs = max_staleness_secs,
        "oracle staleness override: proceeding with stale price data (operator override)"
    );
    StalenessOverrideToken { _private: () }
}

/// Token proving that [`proceed_with_staleness_override`] was called and the
/// audit event was emitted.
///
/// Constructing this type without calling `proceed_with_staleness_override`
/// is impossible outside this module (the `_private` field is not `pub`).
#[derive(Debug)]
pub struct StalenessOverrideToken {
    _private: (),
}

// ─────────────────────────────────────────────────────────────────────────────
// OracleStalenessEvalExt — evaluation extension
// ─────────────────────────────────────────────────────────────────────────────

/// Extension for evaluating oracle staleness in the dispatch flow.
///
/// `evaluate` returns `Ok(())` when the oracle is fresh enough (or override
/// is granted), and `Err(reason)` otherwise.
///
/// The dispatch site calls this AFTER the ordered gate (pin-verify + allowlist)
/// and INDEPENDENTLY of simulate.
///
/// # Fail-closed-on-absent
///
/// When `view` is `None`, the evaluation REFUSES with
/// [`OracleStalenessDenialReason::ViewAbsent`].  A `None` view means the
/// ordered gate did not complete — this should never be reachable in correct
/// code, but the type model enforces fail-closed.
pub struct OracleStalenessEvalExt;

impl OracleStalenessEvalExt {
    /// Evaluates oracle staleness.
    ///
    /// - `view`: the injected staleness view, or `None` (→ REFUSE).
    /// - `override_staleness`: user opt-in; only overrides `Stale`, never
    ///   `Unavailable` or `ViewAbsent`.
    ///
    /// # Errors
    ///
    /// Returns [`OracleStalenessDenialReason`] when refused.
    pub fn evaluate(
        view: Option<&dyn OracleStalenessView>,
        override_staleness: bool,
    ) -> Result<(), OracleStalenessDenialReason> {
        let Some(view) = view else {
            // Fail-closed-on-absent: no view = gate did not run = refuse.
            return Err(OracleStalenessDenialReason::ViewAbsent);
        };

        match evaluate_staleness(view) {
            StalenessCheckResult::Fresh { .. } => Ok(()),

            StalenessCheckResult::Stale {
                timestamp_delta_secs,
            } => {
                if override_staleness {
                    // EMIT-THEN-RETURN: unconditionally emit before proceeding.
                    let _token = proceed_with_staleness_override(
                        timestamp_delta_secs,
                        view.max_staleness_secs(),
                    );
                    Ok(())
                } else {
                    Err(OracleStalenessDenialReason::StalenessExceeded {
                        timestamp_delta_secs,
                        max_staleness_secs: view.max_staleness_secs(),
                    })
                }
            }

            StalenessCheckResult::Unavailable => {
                // Unavailable is never overridable — no data → always refuse.
                Err(OracleStalenessDenialReason::PriceUnavailable)
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OracleStalenessDenialReason
// ─────────────────────────────────────────────────────────────────────────────

/// The reason string returned when the oracle staleness criterion refuses.
///
/// `Display` carries only the timestamp-delta and threshold — NOT the oracle
/// address or full hash per the redaction rules.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum OracleStalenessDenialReason {
    /// Oracle price data is stale beyond the threshold.
    StalenessExceeded {
        /// How old the price is in seconds.
        timestamp_delta_secs: u64,
        /// The configured threshold.
        max_staleness_secs: u64,
    },
    /// No oracle staleness view was injected (gate did not run or was bypassed).
    ViewAbsent,
    /// Oracle price data is unavailable (no price returned by oracle).
    PriceUnavailable,
}

impl std::fmt::Display for OracleStalenessDenialReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OracleStalenessDenialReason::StalenessExceeded {
                timestamp_delta_secs,
                max_staleness_secs,
            } => write!(
                f,
                "oracle.staleness_exceeded: price is {timestamp_delta_secs}s old (max {max_staleness_secs}s)"
            ),
            OracleStalenessDenialReason::ViewAbsent => {
                write!(
                    f,
                    "oracle.view_absent: no OracleStalenessView injected (fail-closed)"
                )
            }
            OracleStalenessDenialReason::PriceUnavailable => {
                write!(f, "oracle.price_unavailable: oracle price data unavailable")
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only fixture construction"
    )]

    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    const TEST_ORACLE: &str = "CAZOKR2Y5E2OSWSIBRVZMJ47RUTQPIGVWSAQ2UISGAVC46XKPGDG5PKI";

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    // ── Fail-closed-on-absent ────────────────────────────────────────────────

    #[test]
    fn absent_view_refuses_with_view_absent() {
        let result = OracleStalenessEvalExt::evaluate(None, false);
        assert!(
            matches!(result, Err(OracleStalenessDenialReason::ViewAbsent)),
            "absent view must refuse; got {result:?}"
        );
    }

    #[test]
    fn absent_view_refuses_even_with_override_enabled() {
        let result = OracleStalenessEvalExt::evaluate(None, true);
        assert!(
            matches!(result, Err(OracleStalenessDenialReason::ViewAbsent)),
            "absent view must refuse even with override; got {result:?}"
        );
    }

    // ── Fresh price passes ───────────────────────────────────────────────────

    #[test]
    fn fresh_price_passes() {
        let now = now_secs();
        let snapshot =
            OracleStalenessSnapshot::new(TEST_ORACLE, &[now - 100], DEFAULT_MAX_STALENESS_SECS)
                .unwrap();
        let result = OracleStalenessEvalExt::evaluate(Some(&snapshot), false);
        assert!(result.is_ok(), "100s-old price must pass: {result:?}");
    }

    // ── Stale price refuses without override ─────────────────────────────────

    #[test]
    fn stale_700s_refuses_without_override() {
        let now = now_secs();
        let snapshot =
            OracleStalenessSnapshot::new(TEST_ORACLE, &[now - 700], DEFAULT_MAX_STALENESS_SECS)
                .unwrap();
        let result = OracleStalenessEvalExt::evaluate(Some(&snapshot), false);
        assert!(
            matches!(
                result,
                Err(OracleStalenessDenialReason::StalenessExceeded {
                    timestamp_delta_secs: 700,
                    max_staleness_secs: 600
                })
            ),
            "700s-stale price must refuse: {result:?}"
        );
    }

    // ── Stale price with override emits audit and proceeds ───────────────────

    #[test]
    fn stale_700s_with_override_proceeds() {
        let now = now_secs();
        let snapshot =
            OracleStalenessSnapshot::new(TEST_ORACLE, &[now - 700], DEFAULT_MAX_STALENESS_SECS)
                .unwrap();
        let result = OracleStalenessEvalExt::evaluate(Some(&snapshot), true);
        assert!(
            result.is_ok(),
            "override must allow stale price: {result:?}"
        );
    }

    // ── Unavailable price refuses even with override ─────────────────────────

    #[test]
    fn unavailable_price_refuses_even_with_override() {
        let snapshot =
            OracleStalenessSnapshot::unavailable(TEST_ORACLE, DEFAULT_MAX_STALENESS_SECS);
        let result = OracleStalenessEvalExt::evaluate(Some(&snapshot), true);
        assert!(
            matches!(result, Err(OracleStalenessDenialReason::PriceUnavailable)),
            "unavailable price must refuse even with override: {result:?}"
        );
    }

    // ── Display carries only delta/threshold, not oracle address ─────────────

    #[test]
    fn staleness_exceeded_display_has_no_oracle_address() {
        let reason = OracleStalenessDenialReason::StalenessExceeded {
            timestamp_delta_secs: 700,
            max_staleness_secs: 600,
        };
        let display = reason.to_string();
        assert!(
            display.contains("oracle.staleness_exceeded"),
            "must contain error code"
        );
        assert!(display.contains("700"), "must contain delta");
        assert!(display.contains("600"), "must contain threshold");
        // Must not contain any oracle address
        assert!(
            !display.contains("CAZOKR"),
            "must not contain oracle address prefix in error Display"
        );
    }

    #[test]
    fn view_absent_display_uses_distinct_code() {
        let reason = OracleStalenessDenialReason::ViewAbsent;
        let display = reason.to_string();
        assert_eq!(
            display, "oracle.view_absent: no OracleStalenessView injected (fail-closed)",
            "ViewAbsent must use oracle.view_absent: code, not oracle.staleness_exceeded:"
        );
        // Must NOT use the staleness_exceeded machine code (different condition).
        assert!(
            !display.contains("oracle.staleness_exceeded"),
            "ViewAbsent must not emit oracle.staleness_exceeded: code; got: {display}"
        );
    }

    #[test]
    fn price_unavailable_display_uses_distinct_code() {
        let reason = OracleStalenessDenialReason::PriceUnavailable;
        let display = reason.to_string();
        assert_eq!(
            display, "oracle.price_unavailable: oracle price data unavailable",
            "PriceUnavailable must use oracle.price_unavailable: code, not oracle.staleness_exceeded:"
        );
        // Must NOT use the staleness_exceeded machine code (different condition).
        assert!(
            !display.contains("oracle.staleness_exceeded"),
            "PriceUnavailable must not emit oracle.staleness_exceeded: code; got: {display}"
        );
    }

    // ── evaluate_staleness function ──────────────────────────────────────────

    #[test]
    fn evaluate_staleness_fresh() {
        let now = now_secs();
        let snapshot =
            OracleStalenessSnapshot::new(TEST_ORACLE, &[now - 100], DEFAULT_MAX_STALENESS_SECS)
                .unwrap();
        let result = evaluate_staleness(&snapshot);
        assert!(
            matches!(result, StalenessCheckResult::Fresh { .. }),
            "100s-old price must be Fresh; got {result:?}"
        );
    }

    #[test]
    fn evaluate_staleness_stale() {
        let now = now_secs();
        let snapshot =
            OracleStalenessSnapshot::new(TEST_ORACLE, &[now - 700], DEFAULT_MAX_STALENESS_SECS)
                .unwrap();
        let result = evaluate_staleness(&snapshot);
        assert!(
            matches!(result, StalenessCheckResult::Stale { .. }),
            "700s-old price must be Stale; got {result:?}"
        );
    }

    #[test]
    fn empty_timestamps_returns_none() {
        let snapshot = OracleStalenessSnapshot::new(TEST_ORACLE, &[], DEFAULT_MAX_STALENESS_SECS);
        assert!(snapshot.is_none(), "empty timestamps must return None");
    }
}
