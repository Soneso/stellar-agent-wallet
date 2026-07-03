//! Pool allocator — credit-as-capability channel acquisition and release.
//!
//! The allocator exposes the `acquire` / `release` semantics for the
//! channel-account pool.  It is a thin coordination layer over the
//! [`ChannelPool`] that adds:
//!
//! - **Immediate exhaustion**: `acquire` returns [`PoolError::PoolExhausted`]
//!   IMMEDIATELY when no free channel is available — it NEVER queues.
//! - **Sequence re-fetch on `tx_bad_seq`**: when `release` is called with
//!   [`TerminalOutcome::TxBadSeq`] and no `fresh_sequence`, the allocator
//!   schedules an on-demand re-fetch via [`stellar_agent_network::fetch_account`].
//! - **Audit emission**: `acquire` emits `ChannelAcquired` and `release` emits
//!   `ChannelReleased` into the caller-supplied optional audit writer.
//!
//! # Credit-as-capability accounting
//!
//! The allocator enforces local credit-as-capability accounting: a "credit"
//! is a free channel slot.  Acquiring a channel consumes one credit; releasing
//! it replenishes one credit.  No centralised credit ledger is used — the
//! accounting is purely in-memory.
//!
//! # Audit writer threading
//!
//! Both `acquire` and `release` accept an optional `Arc<Mutex<AuditWriter>>`
//! by reference.  When `None` the emit is skipped silently.  The writer is
//! locked for the minimal duration of constructing and appending the entry;
//! no lock is held across any `.await` boundary.  This follows the same
//! optional-writer threading pattern used in `stellar-agent-smart-account`.

use std::sync::{Arc, Mutex};

use stellar_agent_core::audit_log::entry::AuditEntry;
use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_core::observability::redact_strkey_first5_last5;
use stellar_agent_network::{StellarRpcClient, fetch_account};

use crate::error::PoolError;
use crate::pool::{ChannelLease, ChannelPool, TerminalOutcome};

/// Acquires a free channel from the pool, optionally emitting a `ChannelAcquired`
/// audit event.
///
/// This is a thin wrapper around [`ChannelPool::acquire`] that returns
/// [`PoolError::PoolExhausted`] IMMEDIATELY when no free channel is available.
///
/// `audit_writer`: when `Some`, a `ChannelAcquired` entry is appended to the
/// writer after the channel is marked `InFlight`.  A write error is logged at
/// `warn` level and does NOT abort the acquire — the pool allocation is already
/// committed and rolling back is not possible.
///
/// `request_id`: opaque caller-supplied idempotency key written into the audit
/// entry.  Pass the enclosing submission's request ID for correlation.
///
/// # Errors
///
/// Returns [`PoolError::PoolExhausted`] if all channels are in-flight.
/// Returns [`PoolError::NotInitialised`] if the pool has no channels.
///
/// # Examples
///
/// ```no_run
/// # use stellar_agent_pool::{ChannelPool, allocator};
/// # use stellar_agent_pool::ChannelRecord;
/// # let channels = vec![ChannelRecord::new(1, "GABC...XYZ")];
/// # let pool = ChannelPool::from_records(channels, vec![100]).unwrap();
/// let lease = allocator::acquire(&pool, None, "req-001").unwrap();
/// ```
pub fn acquire(
    pool: &ChannelPool,
    audit_writer: Option<&Arc<Mutex<AuditWriter>>>,
    request_id: &str,
) -> Result<ChannelLease, PoolError> {
    let lease = pool.acquire()?;

    // Emit ChannelAcquired after the channel is marked InFlight.
    // Write errors are non-fatal: the allocation is already committed.
    if let Some(writer) = audit_writer {
        let entry = AuditEntry::new_channel_acquired(
            redact_strkey_first5_last5(lease.public_key()),
            lease.index(),
            request_id,
        );
        emit_audit(writer, entry);
    }

    Ok(lease)
}

/// Releases a channel lease back to the pool, optionally emitting a
/// `ChannelReleased` audit event.
///
/// On [`TerminalOutcome::TxBadSeq`] without a `fresh_sequence`, this function
/// asynchronously re-fetches the channel's sequence from the network and
/// updates the pool.  The channel is marked `Free` before the re-fetch so
/// that other callers can acquire it immediately (even with a potentially
/// stale sequence — the next submission will either succeed or trigger another
/// re-fetch).
///
/// `audit_writer`: when `Some`, a `ChannelReleased` entry is appended after the
/// channel transitions back to `Free`.  Write errors are logged at `warn` and
/// do NOT abort the release.
///
/// # Errors
///
/// Returns [`PoolError::SequenceFetchFailed`] if the re-fetch fails (only when
/// `outcome == TxBadSeq && fresh_sequence.is_none()`).
///
/// # Panics
///
/// Never panics.
pub async fn release(
    pool: &ChannelPool,
    client: &StellarRpcClient,
    lease: ChannelLease,
    outcome: TerminalOutcome,
    fresh_sequence: Option<i64>,
    audit_writer: Option<&Arc<Mutex<AuditWriter>>>,
    request_id: &str,
) -> Result<(), PoolError> {
    let index = lease.index();
    let public_key = lease.public_key().to_owned();

    // Release into the pool immediately (mark Free, update seq per outcome).
    pool.release(lease, outcome, fresh_sequence);

    // Emit ChannelReleased after the channel transitions back to Free.
    if let Some(writer) = audit_writer {
        let outcome_str = terminal_outcome_str(outcome);
        let entry = AuditEntry::new_channel_released(
            redact_strkey_first5_last5(&public_key),
            index,
            outcome_str,
            request_id,
        );
        emit_audit(writer, entry);
    }

    // On tx_bad_seq without a caller-supplied fresh sequence, re-fetch.
    if outcome == TerminalOutcome::TxBadSeq && fresh_sequence.is_none() {
        let view = fetch_account(client, &public_key, &[]).await.map_err(|e| {
            PoolError::SequenceFetchFailed {
                channel_index: index,
                channel_redacted: redact_strkey_first5_last5(&public_key),
                reason: format!("{e}"),
            }
        })?;
        pool.update_sequence(index, view.sequence_number);
    }

    Ok(())
}

/// Appends `entry` to `writer`, logging at `warn` level on failure.
///
/// Write failures are non-fatal: a failed audit write must not abort a pool
/// operation whose pool state transition has already committed.
fn emit_audit(writer: &Arc<Mutex<AuditWriter>>, entry: AuditEntry) {
    match writer.lock() {
        Ok(mut w) => {
            if let Err(e) = w.write_entry(entry) {
                tracing::warn!(
                    error = %e,
                    "allocator: failed to write audit entry (non-fatal)"
                );
            }
        }
        Err(_) => {
            tracing::warn!("allocator: audit writer mutex poisoned (non-fatal)");
        }
    }
}

/// Maps a [`TerminalOutcome`] to the stable string used in `ChannelReleased.outcome`.
///
/// Matches the string values documented in the schema rustdoc for
/// `EventKind::ChannelReleased` (`stellar-agent-core/src/audit_log/schema.rs`).
fn terminal_outcome_str(outcome: TerminalOutcome) -> &'static str {
    match outcome {
        TerminalOutcome::Success => "success",
        TerminalOutcome::TxBadSeq => "tx_bad_seq",
        TerminalOutcome::Failed => "failed",
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "unit tests"
    )]

    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    use stellar_agent_core::audit_log::schema::EventKind;
    use stellar_agent_core::audit_log::writer::AuditWriter;

    use super::*;
    use crate::ChannelRecord;
    use crate::pool::{ChannelPool, TerminalOutcome};

    fn open_writer() -> (tempfile::TempDir, Arc<Mutex<AuditWriter>>) {
        let dir = tempfile::tempdir().unwrap();
        let path: PathBuf = dir.path().join("audit.jsonl");
        let writer = AuditWriter::open(path, None).unwrap();
        (dir, Arc::new(Mutex::new(writer)))
    }

    fn make_pool() -> ChannelPool {
        let ch = ChannelRecord::new(
            1,
            "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY",
        );
        ChannelPool::from_records(vec![ch], vec![100]).unwrap()
    }

    /// `acquire` emits exactly one `ChannelAcquired` row with a redacted channel.
    #[test]
    fn acquire_emits_channel_acquired() {
        let pool = make_pool();
        let (_dir, writer) = open_writer();

        let lease = acquire(&pool, Some(&writer), "req-test-acq").unwrap();
        assert_eq!(lease.index(), 1);

        // Verify the audit entry was written.
        let w = writer.lock().unwrap();
        let path = w.path().to_path_buf();
        drop(w);

        let content = std::fs::read_to_string(&path).unwrap();
        let entry: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
        // AuditEntry.event_kind uses #[serde(flatten)] and EventKind uses
        // #[serde(tag = "kind", rename_all = "snake_case")], so the discriminant
        // and variant fields appear at the top level of the JSON object.
        assert_eq!(entry["kind"], "channel_acquired");
        assert_eq!(entry["index"], 1);
        // channel_redacted must be first-5-last-5 (not full strkey)
        let ch_red = entry["channel_redacted"].as_str().unwrap();
        assert!(
            ch_red.len() < 56,
            "channel_redacted should be shorter than full strkey"
        );
        assert!(ch_red.contains("..."), "channel_redacted must be redacted");
    }

    /// `release` emits exactly one `ChannelReleased` row with the correct outcome.
    #[tokio::test]
    async fn release_emits_channel_released_with_outcome() {
        use stellar_agent_network::StellarRpcClient;

        let pool = make_pool();
        let (_dir, writer) = open_writer();

        // Acquire first (no writer for acquire in this test).
        let lease = pool.acquire().unwrap();
        let client = StellarRpcClient::new("https://soroban-testnet.stellar.org").unwrap();

        // Release with Success outcome, with audit writer.
        release(
            &pool,
            &client,
            lease,
            TerminalOutcome::Success,
            None,
            Some(&writer),
            "req-test-rel",
        )
        .await
        .unwrap();

        let w = writer.lock().unwrap();
        let path = w.path().to_path_buf();
        drop(w);

        let content = std::fs::read_to_string(&path).unwrap();
        let entry: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
        // AuditEntry.event_kind uses #[serde(flatten)] and EventKind uses
        // #[serde(tag = "kind", rename_all = "snake_case")], so the discriminant
        // and variant fields appear at the top level of the JSON object.
        assert_eq!(entry["kind"], "channel_released");
        assert_eq!(entry["outcome"], "success");
        assert_eq!(entry["index"], 1);
        let ch_red = entry["channel_redacted"].as_str().unwrap();
        assert!(
            ch_red.len() < 56,
            "channel_redacted should be shorter than full strkey"
        );
    }

    /// `acquire` without a writer does not panic or write anything.
    #[test]
    fn acquire_without_writer_is_noop() {
        let pool = make_pool();
        let lease = acquire(&pool, None, "req-no-writer").unwrap();
        assert_eq!(lease.index(), 1);
    }

    /// `terminal_outcome_str` maps all variants to the documented strings.
    #[test]
    fn terminal_outcome_str_values() {
        assert_eq!(terminal_outcome_str(TerminalOutcome::Success), "success");
        assert_eq!(
            terminal_outcome_str(TerminalOutcome::TxBadSeq),
            "tx_bad_seq"
        );
        assert_eq!(terminal_outcome_str(TerminalOutcome::Failed), "failed");
    }

    /// Verify `EventKind::ChannelAcquired` and `ChannelReleased` are constructed
    /// by the entry constructors (schema round-trip).
    #[test]
    fn entry_constructors_schema_round_trip() {
        let acq = AuditEntry::new_channel_acquired("GAAAA...BBBBB", 3, "req-rt");
        assert!(
            matches!(acq.event_kind, EventKind::ChannelAcquired { index: 3, .. }),
            "unexpected event_kind"
        );

        let rel = AuditEntry::new_channel_released("GAAAA...BBBBB", 3, "success", "req-rt");
        assert!(
            matches!(rel.event_kind, EventKind::ChannelReleased { index: 3, .. }),
            "unexpected event_kind"
        );
    }
}
