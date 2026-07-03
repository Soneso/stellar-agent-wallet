//! Shared audit-writer health handle for session-level degradation signalling.
//!
//! Provides [`AuditWriterHealth`] (the owner) and [`AuditWriterHealthHandle`]
//! (a cheap-clone read/write view) so that free-standing helpers that do not
//! hold a [`crate::audit_log::writer::AuditWriter`] reference can still set
//! the session-level degraded latch when a mutex-poison event drops an audit
//! row.
//!
//! # Design
//!
//! `AuditWriterHealth` owns the `Arc<AtomicBool>` for the degraded flag.
//! `AuditWriterHealthHandle` is a newtype `(Arc<AuditWriterHealth>)` that
//! provides the public read/write API; callers hold handles, not direct
//! references to the owner.  The newtype wrapper gives explicit `clone()`
//! semantics (cost visible at call sites) and keeps the write path
//! (`mark_degraded`) pub(crate)-scoped from the owner module so external crates
//! cannot set the flag directly.
//!
//! # Ordering rationale
//!
//! `Ordering::Relaxed` is correct for both the `swap` in `mark_degraded` and
//! the `load` in `is_degraded` because:
//!
//! 1. The underlying `Mutex::lock()` result that precedes every call to
//!    `mark_degraded` already carries its own happens-before ordering.
//! 2. The flag is a **write-once monotone latch** — no other shared state is
//!    published through it; it is a pure observability signal.
//! 3. The `swap`-and-warn idiom in `mark_degraded` uses the prior-value return
//!    of `swap` to make the warning one-shot independent of memory ordering.
//!
//! # No on-chain analogue
//!
//! `AuditWriterHealth` is a wallet-side observability primitive.  On-chain
//! smart-account contracts and companion SDKs have no audit-log or degradation
//! concept.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use tracing::warn;

// ── AuditWriterHealth ─────────────────────────────────────────────────────────

/// Owner of the session-level audit-writer degradation flag.
///
/// Holds the shared `Arc<AtomicBool>` and exposes cheap-clone handles via
/// [`AuditWriterHealth::handle`].  The owner is typically created once per
/// session and stored as a field; handles are distributed to free-standing
/// helpers that lack access to the full manager.
pub struct AuditWriterHealth {
    degraded: Arc<AtomicBool>,
}

impl AuditWriterHealth {
    /// Creates a new `AuditWriterHealth` in the non-degraded state.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use stellar_agent_core::audit_log::health::AuditWriterHealth;
    ///
    /// let health = AuditWriterHealth::new();
    /// assert!(!health.is_degraded());
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            degraded: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Returns a cheap-clone handle to this health instance.
    ///
    /// The handle shares the same `Arc<AtomicBool>` as the owner; any call to
    /// [`AuditWriterHealthHandle::mark_degraded`] through the handle is
    /// immediately visible through [`AuditWriterHealth::is_degraded`] on the
    /// owner (and vice versa).
    ///
    /// Handles are cheap to clone: only an `Arc` reference count is incremented.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use stellar_agent_core::audit_log::health::AuditWriterHealth;
    ///
    /// let health = AuditWriterHealth::new();
    /// let handle = health.handle();
    /// handle.mark_degraded();
    /// assert!(health.is_degraded());
    /// ```
    #[must_use]
    pub fn handle(&self) -> AuditWriterHealthHandle {
        AuditWriterHealthHandle(Arc::new(AuditWriterHealth {
            degraded: Arc::clone(&self.degraded),
        }))
    }

    /// Returns `true` if the audit writer was marked degraded during this session.
    ///
    /// The flag is a write-once monotone latch: it transitions from `false` to
    /// `true` on the first poison-detection event and never resets.
    /// `Ordering::Relaxed` is appropriate — see module-level rustdoc for the
    /// ordering rationale.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use stellar_agent_core::audit_log::health::AuditWriterHealth;
    ///
    /// let health = AuditWriterHealth::new();
    /// assert!(!health.is_degraded());
    /// ```
    #[must_use]
    pub fn is_degraded(&self) -> bool {
        self.degraded.load(Ordering::Relaxed)
    }

    /// Marks the audit writer as structurally degraded for the current session.
    ///
    /// Write-once monotone latch: subsequent calls are no-ops (the swap prior
    /// value is `true`, so the warning is emitted only once).
    ///
    /// External callers may also use [`AuditWriterHealthHandle::mark_degraded`]
    /// which delegates here through the shared `Arc`.
    ///
    /// # Panics
    ///
    /// Does not panic.
    pub fn mark_degraded(&self) {
        if !self.degraded.swap(true, Ordering::Relaxed) {
            warn!(
                target: "stellar_agent::audit",
                "audit-log structurally degraded during this session (one or more audit rows \
                 were dropped due to writer poison). See `wallet audit-log verify` for forensic \
                 integrity check."
            );
        }
    }
}

impl Default for AuditWriterHealth {
    fn default() -> Self {
        Self::new()
    }
}

// ── AuditWriterHealthHandle ───────────────────────────────────────────────────

/// Cheap-clone handle to a shared [`AuditWriterHealth`] instance.
///
/// Callers that need to mark the audit writer degraded but do not hold the full
/// manager accept `Option<&AuditWriterHealthHandle>` and call
/// `handle.mark_degraded()` on the poison path.
///
/// Cloning a handle is `O(1)` — only the `Arc` reference count is incremented.
#[derive(Clone)]
pub struct AuditWriterHealthHandle(Arc<AuditWriterHealth>);

impl AuditWriterHealthHandle {
    /// Returns `true` if the audit writer was marked degraded during this session.
    ///
    /// Delegates to [`AuditWriterHealth::is_degraded`]; see that method's
    /// rustdoc for the ordering rationale.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use stellar_agent_core::audit_log::health::AuditWriterHealth;
    ///
    /// let health = AuditWriterHealth::new();
    /// let handle = health.handle();
    /// assert!(!handle.is_degraded());
    /// ```
    #[must_use]
    pub fn is_degraded(&self) -> bool {
        self.0.is_degraded()
    }

    /// Marks the audit writer as structurally degraded for the current session.
    ///
    /// Write-once monotone latch: subsequent calls are no-ops.  The structured
    /// warning is emitted at most once per session via the `stellar_agent::audit`
    /// tracing target.
    ///
    /// # Panics
    ///
    /// Does not panic.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use stellar_agent_core::audit_log::health::AuditWriterHealth;
    ///
    /// let health = AuditWriterHealth::new();
    /// let handle = health.handle();
    /// handle.mark_degraded();
    /// handle.mark_degraded(); // second call is a no-op (no duplicate warning)
    /// assert!(health.is_degraded());
    /// ```
    pub fn mark_degraded(&self) {
        self.0.mark_degraded();
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test-only")]

    use super::*;

    #[test]
    fn new_health_starts_non_degraded() {
        let health = AuditWriterHealth::new();
        assert!(!health.is_degraded());
    }

    #[test]
    fn mark_degraded_transitions_flag_to_true() {
        let health = AuditWriterHealth::new();
        health.mark_degraded();
        assert!(health.is_degraded());
    }

    #[test]
    fn handle_shares_flag_with_owner() {
        let health = AuditWriterHealth::new();
        let handle = health.handle();
        assert!(!handle.is_degraded());
        handle.mark_degraded();
        assert!(health.is_degraded());
        assert!(handle.is_degraded());
    }

    #[test]
    fn multiple_handles_share_same_flag() {
        let health = AuditWriterHealth::new();
        let h1 = health.handle();
        let h2 = health.handle();
        let h3 = h1.clone();

        assert!(!h1.is_degraded());
        assert!(!h2.is_degraded());
        assert!(!h3.is_degraded());

        h1.mark_degraded();

        assert!(health.is_degraded());
        assert!(h2.is_degraded());
        assert!(h3.is_degraded());
    }

    #[test]
    fn mark_degraded_is_idempotent() {
        let health = AuditWriterHealth::new();
        let handle = health.handle();
        handle.mark_degraded();
        handle.mark_degraded();
        handle.mark_degraded();
        assert!(health.is_degraded());
    }

    #[test]
    fn default_is_non_degraded() {
        let health = AuditWriterHealth::default();
        assert!(!health.is_degraded());
    }
}
