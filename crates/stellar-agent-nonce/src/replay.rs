//! In-memory replay-window for single-use nonce enforcement.
//!
//! The [`ReplayWindow`] tracks 48-byte nonces (salt + HMAC tag) that have been
//! consumed, with TTL-based eviction.  It is in-memory only — a process restart
//! wipes it, which is the fail-closed-on-restart property (combined with
//! the `boot_nonce` HMAC input in [`crate::NonceMint`]).
//!
//! # Thread safety
//!
//! `ReplayWindow` is `Send + Sync` (no internal mutability), but its mutating
//! methods take `&mut self`.  Concurrent access from multiple async tasks
//! requires wrapping in `tokio::sync::Mutex<ReplayWindow>` or
//! `parking_lot::Mutex<ReplayWindow>`.
//!
//! # Memory bound
//!
//! Each entry is `48 (full nonce) + 8 (expiry u64) = 56 bytes` plus `HashMap`
//! overhead (~72 bytes per entry on a 64-bit host).  At a burst rate of
//! 1 000 nonces/second with a 5-minute TTL the window holds at most 300 000
//! entries (~38 MiB).  Operators sustaining higher rates should call
//! [`evict_expired`][ReplayWindow::evict_expired] more frequently.
//!
//! ## Defence-in-depth: full 48-byte key
//!
//! The HashMap key is the full 48-byte nonce (16-byte salt + 32-byte HMAC tag)
//! rather than the salt alone.  Keying on the salt alone would suffice for
//! replay prevention (salts are unique with overwhelming probability), but the
//! full-nonce key provides defence-in-depth: an attacker who manages to predict
//! or collide a salt must also forge the HMAC tag to construct a key that
//! matches an existing window entry.

use std::collections::HashMap;

use crate::error::NonceError;

// ─────────────────────────────────────────────────────────────────────────────
// ReplayWindow
// ─────────────────────────────────────────────────────────────────────────────

/// In-memory single-use nonce tracker with TTL eviction.
///
/// Each consumed nonce's full 48-byte value (salt + HMAC tag) is stored with
/// its expiry timestamp.  The internal record path rejects a nonce that already
/// exists (replay detected). [`evict_expired`] removes entries whose expiry is
/// in the past.
///
/// # Fail-closed on process restart
///
/// The HashMap is in-memory only.  After a process restart the window is empty,
/// but pre-restart nonces fail HMAC verification because the `boot_nonce` in
/// [`crate::NonceMint`] changes.  This is the fail-closed-on-restart property.
///
/// [`evict_expired`]: ReplayWindow::evict_expired
pub struct ReplayWindow {
    /// Map from full 48-byte nonce (salt || tag) to expiry unix-milliseconds.
    inner: HashMap<[u8; 48], u64>,
}

impl ReplayWindow {
    /// Creates a new, empty replay window.
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_nonce::ReplayWindow;
    ///
    /// let w = ReplayWindow::new();
    /// assert_eq!(w.len(), 0);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }

    /// Returns the number of entries currently in the window.
    ///
    /// # Panics
    ///
    /// Never panics.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns `true` if the window contains no entries.
    ///
    /// # Panics
    ///
    /// Never panics.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Checks that `nonce` is not already in the replay window.
    ///
    /// Does NOT insert the nonce.  Used by [`crate::NonceMint::verify`] to
    /// separate the check (before HMAC) from the record (after HMAC).
    ///
    /// # Errors
    ///
    /// Returns [`NonceError::Replayed`] if `nonce` is already present.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub(crate) fn check_not_replayed(&self, nonce: &[u8; 48]) -> Result<(), NonceError> {
        if self.inner.contains_key(nonce) {
            return Err(NonceError::Replayed);
        }
        Ok(())
    }

    /// Records a consumed nonce in the replay window.
    ///
    /// If `nonce` is already present, returns [`NonceError::Replayed`].
    /// Otherwise, inserts `nonce → expiry_unix_ms`.
    ///
    /// In the production path this is called only by [`crate::NonceMint::verify`]
    /// after successful HMAC verification.  It is also accessible to integration
    /// tests that need to pre-populate the window must use the test-helper
    /// wrapper.
    ///
    /// # Errors
    ///
    /// Returns [`NonceError::Replayed`] if `nonce` is already present.
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    pub(crate) fn record(
        &mut self,
        nonce: [u8; 48],
        expiry_unix_ms: u64,
    ) -> Result<(), NonceError> {
        use std::collections::hash_map::Entry;
        match self.inner.entry(nonce) {
            Entry::Vacant(e) => {
                e.insert(expiry_unix_ms);
                Ok(())
            }
            Entry::Occupied(_) => Err(NonceError::Replayed),
        }
    }

    /// Test-only wrapper for pre-populating the replay window.
    ///
    /// This method is available only for unit tests and the `test-helpers`
    /// feature. Production callers must exercise the replay window through
    /// [`crate::NonceMint::verify`], which records only after HMAC verification.
    ///
    /// # Errors
    ///
    /// Returns [`NonceError::Replayed`] if `nonce` is already present.
    #[cfg(any(test, feature = "test-helpers"))]
    #[doc(hidden)]
    pub fn record_for_test(
        &mut self,
        nonce: [u8; 48],
        expiry_unix_ms: u64,
    ) -> Result<(), NonceError> {
        self.record(nonce, expiry_unix_ms)
    }

    /// Removes all entries whose expiry is ≤ `now_unix_ms`.
    ///
    /// Call this periodically (e.g. before or after each verify) to bound
    /// memory usage.  It is safe to skip eviction if nonce throughput is low.
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_nonce::ReplayWindow;
    ///
    /// let mut w = ReplayWindow::new();
    /// # #[cfg(feature = "test-helpers")]
    /// # {
    /// w.record_for_test([1u8; 48], 1000).expect("insert");
    /// w.record_for_test([2u8; 48], 5000).expect("insert");
    /// w.evict_expired(2000);
    /// assert_eq!(w.len(), 1);  // nonce [1u8;48] expired at 1000, now = 2000
    /// # }
    /// ```
    pub fn evict_expired(&mut self, now_unix_ms: u64) {
        self.inner.retain(|_, expiry| *expiry > now_unix_ms);
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
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
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;

    #[test]
    fn new_is_empty() {
        let w = ReplayWindow::new();
        assert!(w.is_empty());
        assert_eq!(w.len(), 0);
    }

    #[test]
    fn default_is_empty() {
        let w = ReplayWindow::default();
        assert!(w.is_empty());
    }

    #[test]
    fn record_first_use_ok() {
        let mut w = ReplayWindow::new();
        w.record([0u8; 48], 9_999_000).unwrap();
        assert_eq!(w.len(), 1);
    }

    #[test]
    fn record_replay_rejected() {
        let mut w = ReplayWindow::new();
        w.record([7u8; 48], 9_999_000).unwrap();
        let err = w.record([7u8; 48], 9_999_000).unwrap_err();
        assert!(matches!(err, NonceError::Replayed));
    }

    #[test]
    fn check_not_replayed_before_record() {
        let mut w = ReplayWindow::new();
        // Not yet recorded — should pass.
        w.check_not_replayed(&[3u8; 48]).unwrap();
        // Record it.
        w.record([3u8; 48], 9_999_000).unwrap();
        // Now check should fail.
        let err = w.check_not_replayed(&[3u8; 48]).unwrap_err();
        assert!(matches!(err, NonceError::Replayed));
    }

    #[test]
    fn evict_expired_removes_old_entries() {
        let mut w = ReplayWindow::new();
        w.record([1u8; 48], 1000).unwrap();
        let mut n2 = [2u8; 48];
        n2[0] = 0xAA;
        w.record(n2, 2000).unwrap();
        let mut n3 = [3u8; 48];
        n3[0] = 0xBB;
        w.record(n3, 5000).unwrap();

        w.evict_expired(2000);
        // expiry 1000 <= 2000 → evicted; expiry 2000 <= 2000 → evicted; expiry 5000 > 2000 → kept.
        assert_eq!(w.len(), 1);
    }

    #[test]
    fn evict_expired_keeps_future_entries() {
        let mut w = ReplayWindow::new();
        w.record([9u8; 48], 9_999_999).unwrap();
        w.evict_expired(0);
        assert_eq!(w.len(), 1);
    }

    #[test]
    fn distinct_nonces_are_independent() {
        let mut w = ReplayWindow::new();
        let mut n1 = [0u8; 48];
        let mut n2 = [0u8; 48];
        n1[0] = 1;
        n2[0] = 2;
        w.record(n1, 9_999_000).unwrap();
        w.record(n2, 9_999_000).unwrap();
        assert_eq!(w.len(), 2);
    }

    /// Same salt but different tags must be tracked independently (48-byte key).
    #[test]
    fn same_salt_different_tag_tracked_independently() {
        let mut w = ReplayWindow::new();
        let mut n1 = [0u8; 48];
        let mut n2 = [0u8; 48];
        // Same salt (bytes 0..16), different tag (bytes 16..48).
        n1[16] = 0xAA;
        n2[16] = 0xBB;
        w.record(n1, 9_999_000).unwrap();
        w.record(n2, 9_999_000).unwrap();
        assert_eq!(w.len(), 2);
    }
}
