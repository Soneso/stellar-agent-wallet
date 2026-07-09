//! Total wall-clock budget for a SEQUENCE of RPC round-trips.
//!
//! A single RPC call against the workspace's Soroban-RPC transport
//! (`jsonrpsee`, via `StellarRpcClient`) is already bounded at 60 seconds by
//! the transport itself — a bare `.await` on one call needs no additional
//! wrapping. The defect this module addresses is a SEQUENCE of round-trips
//! (a loop, a poll, or a multi-stage flow) with no bound on the TOTAL wall
//! time: N sequential calls cost up to N x 60s, unbounded in N when the
//! iteration count is a loop bound, a poll condition, or a caller-supplied
//! list rather than a small fixed constant.
//!
//! [`SequentialRpcBudget`] computes ONE deadline once, at the top of the
//! flow; [`bound_stage`] wraps each stage/iteration against that SAME
//! deadline, so time already spent in an earlier stage shrinks the budget
//! left for a later one, rather than each stage re-arming a fresh timeout.
//! This mirrors `stellar-agent-smart-account`'s `PreSubmitBudget` /
//! `bound_pre_submit_stage` (introduced for `submit_signed_invoke`'s
//! fetch/simulate/re-fetch/re-simulate sequence), generalised here so crates
//! that do not depend on `stellar-agent-smart-account` can share ONE
//! implementation instead of each re-deriving the pattern. The
//! smart-account crate's own machinery is left in place (not migrated to
//! this module in this change) — a mechanical, low-value migration risking
//! its already-tested behavior; new call sites across the workspace use
//! this module directly.

use std::time::Duration;

use tokio::time::Instant;

/// A wall-clock budget shared across every stage or iteration of one
/// multi-RPC-call flow.
///
/// `Copy`, so it threads through call sites (including recursive helpers)
/// as a plain argument.
#[derive(Debug, Clone, Copy)]
pub struct SequentialRpcBudget {
    /// Absolute instant past which a stage is refused.
    pub deadline: Instant,
    /// The total duration `deadline` was derived from — carried only for the
    /// budget figure in [`SequentialRpcBudgetElapsed`]'s message.
    pub total: Duration,
}

impl SequentialRpcBudget {
    /// Computes a budget of `total` starting now.
    #[must_use]
    pub fn new(total: Duration) -> Self {
        Self {
            deadline: Instant::now() + total,
            total,
        }
    }
}

/// The shared [`SequentialRpcBudget`] elapsed before a stage completed.
#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("collective RPC-sequence budget of {total_secs}s elapsed during stage \"{stage}\"")]
pub struct SequentialRpcBudgetElapsed {
    /// The stage tag passed to [`bound_stage`] at the call site that timed out.
    pub stage: &'static str,
    /// The [`SequentialRpcBudget::total`] the deadline was derived from.
    pub total_secs: u64,
}

/// Bounds one stage of a multi-RPC sequence against the shared `budget`.
///
/// Every stage of a flow shares ONE `budget.deadline` rather than each
/// re-arming a fresh per-call timeout, so time spent in an earlier stage
/// (including any non-RPC work between stages) shrinks the budget left for
/// a later one. Map [`SequentialRpcBudgetElapsed`] to the flow's own typed
/// timeout/deadline error at the call site — this module mints no error
/// taxonomy of its own beyond the elapsed marker.
///
/// # Errors
///
/// Returns [`SequentialRpcBudgetElapsed`] when `budget.deadline` elapses
/// before `fut` resolves. Never returns an error for any other reason — a
/// `fut` that itself fails still resolves to `Ok(fut_output)` here (the
/// failure lives inside `T`); only a budget timeout produces `Err`.
pub async fn bound_stage<T>(
    budget: SequentialRpcBudget,
    stage: &'static str,
    fut: impl std::future::Future<Output = T>,
) -> Result<T, SequentialRpcBudgetElapsed> {
    tokio::time::timeout_at(budget.deadline, fut)
        .await
        .map_err(|_elapsed| SequentialRpcBudgetElapsed {
            stage,
            total_secs: budget.total.as_secs(),
        })
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;

    /// A stage that completes before the deadline passes through `Ok`.
    #[tokio::test(start_paused = true)]
    async fn bound_stage_passes_through_ok_before_deadline() {
        let budget = SequentialRpcBudget::new(Duration::from_secs(10));
        let result = bound_stage(budget, "test_stage", async { 42_u32 }).await;
        assert_eq!(result.unwrap(), 42);
    }

    /// A stage whose inner future never resolves times out at the shared
    /// deadline, not before and not after.
    #[tokio::test(start_paused = true)]
    async fn bound_stage_times_out_at_shared_deadline() {
        let budget = SequentialRpcBudget::new(Duration::from_secs(5));
        let result = bound_stage(budget, "hangs_forever", std::future::pending::<()>()).await;
        let err = result.expect_err("a never-resolving future must time out");
        assert_eq!(err.stage, "hangs_forever");
        assert_eq!(err.total_secs, 5);
    }

    /// Two stages sharing ONE budget: the first consumes most of the budget,
    /// leaving too little for the second to complete — proving the deadline
    /// is collective, not re-armed per stage.
    #[tokio::test(start_paused = true)]
    async fn bound_stage_budget_is_collective_across_stages() {
        let budget = SequentialRpcBudget::new(Duration::from_secs(10));

        // First stage: sleeps 8s, well inside the 10s budget.
        let first = bound_stage(budget, "first", tokio::time::sleep(Duration::from_secs(8))).await;
        assert!(first.is_ok(), "first stage must complete within budget");

        // Second stage: only 2s of budget remains (10s total - 8s consumed).
        // A fresh per-call timeout would allow this to run for a full new
        // window; the shared deadline must instead refuse it after ~2s.
        let second =
            bound_stage(budget, "second", tokio::time::sleep(Duration::from_secs(5))).await;
        let err = second.expect_err("second stage must exceed the remaining collective budget");
        assert_eq!(err.stage, "second");
        assert_eq!(err.total_secs, 10);
    }

    /// A budget whose deadline has already elapsed times out immediately on
    /// the very next stage, rather than allowing one more full window.
    ///
    /// The inner future sleeps (yields at least once) rather than resolving
    /// synchronously on the first poll — an immediately-`Ready` future can
    /// complete even past an elapsed deadline (`timeout_at` only checks the
    /// deadline when the inner future returns `Pending`), so a
    /// same-poll fast path would mask the timeout this test pins.
    #[tokio::test(start_paused = true)]
    async fn bound_stage_times_out_when_deadline_already_elapsed() {
        let budget = SequentialRpcBudget::new(Duration::from_secs(1));
        tokio::time::advance(Duration::from_secs(2)).await;

        let result = bound_stage(budget, "late_stage", async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            1_u32
        })
        .await;
        let err = result.expect_err("a stage starting after the deadline must time out");
        assert_eq!(err.stage, "late_stage");
    }
}
