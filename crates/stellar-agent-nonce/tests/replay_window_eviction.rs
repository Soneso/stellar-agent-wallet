//! Verify that ReplayWindow::evict_expired correctly shrinks the window.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use stellar_agent_nonce::ReplayWindow;

fn make_nonce(tag: u8) -> [u8; 48] {
    let mut n = [0u8; 48];
    n[0] = tag;
    n[16] = tag; // vary tag portion too
    n
}

#[test]
fn replay_window_eviction_removes_expired_entries() {
    let mut w = ReplayWindow::new();

    // Insert entries with various expiry times.
    w.record_for_test(make_nonce(1), 1_000).unwrap();
    w.record_for_test(make_nonce(2), 2_000).unwrap();
    w.record_for_test(make_nonce(3), 3_000).unwrap();
    w.record_for_test(make_nonce(4), 10_000).unwrap();
    w.record_for_test(make_nonce(5), 20_000).unwrap();

    assert_eq!(w.len(), 5);

    // Evict entries with expiry ≤ 3_000.
    w.evict_expired(3_000);

    // Entries 1, 2, 3 (expiry ≤ 3000) are gone; 4 and 5 remain.
    assert_eq!(
        w.len(),
        2,
        "expected 2 entries after eviction, got {}",
        w.len()
    );
}

#[test]
fn replay_window_eviction_of_all_entries() {
    let mut w = ReplayWindow::new();
    w.record_for_test(make_nonce(10), 100).unwrap();
    w.record_for_test(make_nonce(11), 200).unwrap();
    w.evict_expired(999_999);
    assert!(w.is_empty());
}

#[test]
fn replay_window_eviction_keeps_future_entries() {
    let mut w = ReplayWindow::new();
    w.record_for_test(make_nonce(20), 9_999_999_999_000)
        .unwrap();
    w.evict_expired(0);
    assert_eq!(w.len(), 1);
}

#[test]
fn evicted_nonce_can_be_reused() {
    // After eviction, the same nonce can be recorded again (for a new interaction).
    let mut w = ReplayWindow::new();
    let n = make_nonce(42);
    w.record_for_test(n, 100).unwrap();
    w.evict_expired(200); // evict it
    assert!(w.is_empty());
    // Re-recording should succeed (not Replayed).
    w.record_for_test(n, 9_999_000).unwrap();
    assert_eq!(w.len(), 1);
}
