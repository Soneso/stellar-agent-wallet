//! Fixtures for confirmation polls under a paused Tokio clock.

#![allow(clippy::unwrap_used, reason = "test-only fixtures")]

use crate::TransactionRecord;
use std::time::Duration;

pub(crate) fn answer(status: &str) -> TransactionRecord {
    TransactionRecord::from_raw(
        serde_json::from_value(serde_json::json!({ "status": status, "ledger": 7 })).unwrap(),
    )
}

/// Asserts that an answer ready at its deadline reaches the post-await guard.
pub(crate) async fn assert_answer_wins_at_deadline() {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    let result = tokio::time::timeout_at(deadline, async move {
        tokio::time::sleep_until(deadline).await;
    })
    .await;
    assert!(
        result.is_ok(),
        "a request ready on the deadline tick completes through timeout_at"
    );
}
