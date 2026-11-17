//! The audit outbox: operator rows queued beside the log while a draining
//! writer in another process holds the log's sidecar lock.
//!
//! The rows queued here are the consent rows of `stellar-agent approve` and
//! the halt and resume rows of `stellar-agent profile halt` and
//! `stellar-agent profile resume`, each queued while a running MCP server or
//! `approve serve` inbox holds the log.
//!
//! # Files
//!
//! Three files sit beside `<audit_log_path>`:
//!
//! - `<audit_log_path>.outbox`: JSON lines, mode `0600` on Unix. A line holds
//!   a serialized [`AuditEntry`] or a tagged row. Each entry keeps its timestamp.
//! - `<audit_log_path>.outbox.lock`: the lock every append and every drain
//!   holds while it touches the outbox.
//! - `<audit_log_path>.drain.lock`: held for its whole life by every writer
//!   with an anchor store, recovery writers included, so another process can
//!   tell a draining writer from one that does not drain.
//!
//! # Locks
//!
//! Normal operator-row appends acquire the approval-store lock before the
//! outbox lock. Recovery holds all three audit carriers and uses nonblocking
//! acquisition of the permission stores. The outbox lock waits for up to
//! [`OUTBOX_LOCK_WAIT`] in 20 ms steps and then refuses with
//! [`WriterError::OutboxBusy`], whose detail is `audit.outbox_busy`. Every
//! writer open takes the writer's sidecar lock with one `try_lock`; only
//! `stellar-agent approve --id` retries it, within the approval store's retry
//! bound. A draining writer then takes the drain lock with a short bounded
//! retry. Neither lock is waited on indefinitely, so no cycle of waiters can
//! form.
//!
//! # Carriers and generations
//!
//! The writer sidecar, the drain lock and the outbox lock are the carriers of
//! the log. For a keyed log the protected audit state records the identity of
//! each, and every acquisition here locks the file at the path and then
//! compares the identity of the locked handle with that record, refusing a
//! replaced file with `audit.carrier_replaced`. The record also names the
//! outbox generation: each generation's commitment is a separate keyring
//! entry, and a holder reads and writes only the commitment of the generation
//! its lock was taken under. `audit bind-carriers` starts a new generation and
//! watches the commitment of the one it retires, so a holder of the retired
//! generation cannot change the new queue without the change refusing the
//! next outbox acquisition with `audit.outbox_rows_missing`.
//!
//! # Append
//!
//! An ordinary keyed append writes `{"k":"row","g":G,"s":S,"r":0,"body":B,"tag":"T"}`.
//! Queued consent uses `r=1` and returns an [`OutboxRowRef`] after durability succeeds.
//! The owner drain retains delivery evidence for reserved consent rows.
//! The body is the entry's canonical JSON. The tag is lowercase hex HMAC-SHA256
//! over `stellar-agent-outbox-row:v2`, big-endian u64 generation and sequence,
//! one evidence byte, and the exact body bytes, without separators or newline.
//! Without a generation line, G is zero and S is the one-based line number,
//! untagged lines included. With one, G is its generation and S is the row's
//! position after it. Both are assigned under the outbox lock.
//!
//! An unreserved keyed append neither reads nor writes a keyring commitment or owner
//! state. Under the outbox lock it reads an existing file, checks the carrier
//! generation, authenticates a first generation line and checks the quota.
//! It then measures and encodes its row. A generation line that does not
//! verify under the held key triggers one reload of the audit key; the
//! reloaded key then also tags this row. It writes and syncs its row, syncs
//! the directory, and checks the carrier generation again. The directory
//! sync makes the file's name durable before the row is acknowledged, also
//! after a publication whose own directory sync failed.
//! A reservation-bearing append commits its exact Queued reference before
//! the first queue write. A failed write retains that slot for retry.
//! Appenders cannot mark evidence Delivered.
//!
//! An unkeyed append writes the serialized entry. The v1 commitment covers every
//! line's bytes in file order, and its stored representation stays v1.
//! Under the outbox lock it first checks the keyring commitment against the
//! complete lines as read. A committed line that lost its newline or its tail
//! therefore refuses the append with the file unchanged. After its row is
//! written and synced, it stores the new count and chain head.
//!
//! Admission, row measurement, and encoding precede every write.
//! Reserved appends then commit Queued evidence under the same carrier.
//! The first queue write creates a missing file or drops a torn tail, a final segment
//! with no terminating newline. Such a segment is an append that never
//! returned `Ok`, so the file is truncated back to just after the last
//! newline and synced. A failure after a write truncates the file back to its
//! length before the row. A failed truncation is logged as such; a complete
//! line can then remain, and it is never reported queued. Truncation is
//! always in place: the writer refuses to open beside a `*.tmp` file in the
//! audit directory.
//!
//! # Bounds
//!
//! An append admits at most [`MAX_OUTBOX_ROWS`] queued rows and refuses the
//! next with [`WriterError::OutboxFull`]; it never evicts a queued row. It
//! measures the row as a keyed writer appends it, entry tag included, and
//! refuses a row over [`MAX_ROW_BYTES`](super::writer::MAX_ROW_BYTES) with
//! [`WriterError::OutboxRowTooLarge`]. Neither refusal appends the candidate
//! row or stores its consent, and every admitted row fits the writer's byte
//! cap. Both refuse before the first write, so the outbox stays as it was.
//!
//! # Drain
//!
//! The legacy state holds no owner state. Its queue is the v1-committed
//! prefix, tagged or untagged, followed by tagged rows of generation zero at
//! their physical line numbers. Tagged rows require exact layout,
//! authentication, canonical body bytes, matching position, and an operator
//! kind, in that order. A queue with only untagged lines drains as described
//! below; recognition under a zero commitment decodes those lines before the
//! commitment check to identify a delivered batch.
//!
//! The first drain that finds a tagged line cuts over. It validates the
//! committed prefix and every row, appends every row to the log, and
//! requires the tip anchor to cover them. It then stores owner state of
//! queue generation one, whose closed batch commits those rows. Last, it
//! stores the zero commitment and publishes generation line one. Once owner
//! state exists, a drain of live generation G validates the generation line
//! and every row of G, appends them, and requires the anchor. It then stores
//! owner state G+1 closing G and publishes generation line G+1. An empty
//! live queue commits nothing. A drain that
//! finds owner state G+1 beside queue generation G skips the rows the closed
//! batch commits, delivers any later rows of G, and publishes G+1. Different
//! content at the closed coordinates refuses with `audit.outbox_rows_missing`.
//! A nonzero commitment other than the one the owner state recorded at
//! cutover refuses with `audit.outbox_unusable` before any row is decoded.
//!
//! [`check_outbox_commitment`] applies the same owner rules under the stored
//! key.
//! It reads that key once when the store supports key reads.
//! Without a stored key, it checks layout, canonical bodies, coordinates,
//! and kind.
//! Without owner state, a queue that starts with a generation line refuses,
//! since a cutover stores owner state before it publishes.
//! Recoverable publication passes with a warning, leaving every file and
//! item unchanged. Binding selects fully validated bytes, including the
//! header and delivered closed prefix.
//! It copies every owner field into the successor carrier generation.
//! Stages must equal those selected bytes exactly.
//! The retired watch hashes the raw owner value and retains the selected
//! row count.
//!
//! Owner loss acknowledgement validates before permission revocation and
//! records the loss first. It appends the authenticated prefix, requires the
//! anchor, resets nonzero v1 state, and stores the owner item.
//! It then publishes the generation line and resets a changed retired watch
//! last.
//! A watch-only loss leaves the active queue and its items unchanged.
//! A failed closed prefix preserves its stored commitment and selects nothing.
//! An unidentified header selects nothing and advances the owner generation.
//! A crash before the owner item is stored repeats the acknowledgement and
//! selected rows with the same request IDs. The log exposes those duplicates.
//!
//! # Key change
//!
//! `profile rotate-audit-key` fences the drained queue before it persists the
//! new key. The fence is a generation line whose tag is all zeros, which no
//! key verifies. A queue without owner state first gets owner state of
//! generation one, whose closed batch is the empty batch of generation zero.
//! While the fence stands, every keyed append refuses under any key it holds
//! or reloads. The rotation then publishes the line under the new key, and an
//! appender holding the old key reloads the new one. A drain after a crash in
//! between re-signs the lone fence line under its own key. Every keyed writer
//! open first compares its key with the stored key under its carriers. A key
//! that differs refuses with `audit.key_replaced` before any write. A writer
//! opened with a key that a rotation replaced therefore signs no queue line.
//! A row is acknowledged only when it verifies under the key of the next
//! drain.
//!
//! # Publication
//!
//! Under the outbox lock a drain removes a leftover `<log>.outbox.next`,
//! writes the new generation line to it, and syncs it. It then checks the
//! carrier generation, renames it over `<log>.outbox`, and syncs the
//! directory. A
//! leftover replacement never counts as queued rows and never blocks a writer
//! open. The directory sync after replacement makes the rename durable on
//! Unix. Other platforms provide atomic replacement without this
//! directory-durability guarantee.
//!
//! The legacy drain of untagged lines:
//!
//! [`AuditWriter::drain_outbox`](super::writer::AuditWriter::drain_outbox)
//! takes the outbox lock, reads the file, discards a torn final segment,
//! checks that the complete lines are exactly the committed prefix, parses
//! every complete line strictly, appends each entry to the log, stores the
//! zero state, and truncates the outbox to zero. A complete line that does
//! not parse, or that holds a row other than an operator row
//! (`approval_attested`, `approval_attested_remote`, `profile_halted`,
//! `profile_resumed`), refuses the drain with `audit.outbox_unusable` and
//! leaves the file unchanged. A refused append also leaves the file
//! unchanged, and the entries appended before it are appended again by the
//! next drain.
//!
//! # Delivery and its limits
//!
//! Only committed operator rows and authenticated tagged rows at their
//! positions drain. In a queue without owner state, any other complete line
//! past the committed prefix refuses every drain and every unkeyed append
//! with `audit.outbox_rows_missing` until `audit acknowledge-outbox-loss`
//! discards it. An actor with the audit
//! MAC key is inside the trust boundary. Without it, forgery, reordering and
//! replay fail authentication, position or closed-batch checks. Loss of an
//! unreferenced tail row is not detected before delivery.
//!
//! A file writer can also restore a generation line signed under a replaced
//! key. A keyed append reloads the key only when the line fails to verify. An
//! appender that still holds the replaced key therefore queues its row behind
//! the restored line and is told so. `audit verify --profile` authenticates
//! the queue under the stored key and refuses the restored line.
//! A drain that uses the stored key also refuses the
//! queue at line 1 with `tagged record whose tag does not verify`. It leaves
//! the queue unchanged. Every writer open drains first, so a value-moving verb
//! reports `audit.chain_key_unavailable` with the `audit.outbox_unusable`
//! detail. `profile rotate-audit-key` reports `internal.unexpected_state`
//! with the same detail. A writer open that holds the replaced key refuses
//! with `audit.key_replaced` before it drains, so no drain delivers the row
//! under that key. The loss acknowledgement records the refusal and discards
//! every row behind that header. Discarded rows receive no recent evidence.
//!
//! An interrupted append can leave an uncommitted operator row. Approval
//! consent and resuming a halted profile require the row to commit first, so
//! such a row records an approval or a resume that never took effect. A halt
//! marker takes effect before its audit row is queued, so an uncommitted
//! `profile_halted` row can record a halt that is in effect.
//!
//! Delivery is at least once, for the legacy drain and the owner drain alike.
//! A retried row repeats with the same `request_id` and, for a tagged row,
//! the same queue coordinates. In an owner drain, a crash after the appends
//! and before the owner state is stored repeats those rows on the next drain.
//! In the legacy drain, a crash between the appends and the reset of the
//! commitment repeats them. A crash between that reset and the truncation
//! leaves a zero commitment and complete lines. Their canonical bodies equal,
//! in order, those of the active file's last entries. The next drain
//! recognizes that batch as delivered and truncates the outbox without
//! appending. The keyring commitment detects missing, changed, reordered, or
//! added queued rows before parsing or appending any of them. An absent
//! commitment reads as zero. Raw deletion or restore of keyring entries
//! outside the wallet rests on the platform keyring.
//!
//! The stored value is `{"v":1,"pending":N,"head":"sha256:<64 hex>"}`.
//! The initial head is zero; each next head hashes `stellar-agent-outbox:v1`,
//! the prior head, and the line bytes without the newline, in that order.

//! # Owner and generation codecs
//!
//! Version 1 records a queue generation, a closed batch, a legacy-state
//! digest, and at most 15 requested row digests, oldest first.
//! These recent digests migrate to pins when evidence initializes.
//! Version 2 commits the complete lifetime evidence image through its head.
//! Only anchored delivery creates Delivered records in that image.
//! Unreserved compatibility rows consume no evidence slot.
//! Reservations and unresolved pins count toward the 4,096-slot admission cap.
//! Explicit lifecycle notifications and the persistent floor govern reclamation.
//! Every admitted approval retains evidence throughout its permitted uses.
//! The legacy digest hashes the exact v1 commitment value at cutover.
//! Batch commitments hash ordered binary row digests. A row digest hashes the
//! row's bytes without its tag and newline. An untagged row of a cutover
//! prefix hashes as a row of generation zero at its line with evidence zero.
//! Owner accounts follow carrier generations, independently of the queue
//! generation inside the value. Writers hold both writer and outbox carriers
//! for delivery. Appenders hold the outbox carrier for reservation, Queued
//! binding, and authenticated lifecycle changes. Locked verification reads owner state
//! without the writer sidecar and writes nothing.
//!
//! A generation header is `{"k":"gen","g":G,"tag":"T"}` followed by a newline.
//! No header means queue generation zero.
//! Its HMAC-SHA256 tag binds `stellar-agent-outbox-gen:v2` and the big-endian u64 generation.
//! A correctly laid-out first header contributes no pending row or sequence position.
//! Inspection checks layout without a key and keeps physical warning line numbers.

use super::tip_anchor::{TipAnchorStore, TipAnchorStoreError};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

use super::consent_evidence::{
    self, EvidenceImage, EvidenceRecord, EvidenceReservation, MAX_EVIDENCE_ENTRIES, OutboxEvidence,
    RecordState, Selected,
};
use super::entry::AuditEntry;
use super::lock::{AuditWriterLock, BoundCarrierLock, Carrier};
use super::schema::EventKind;
use super::writer::{WriterError, basename_lossy_path as basename, sidecar_path};
use crate::error::{ApprovalFailure, WalletError};

/// Commitment to the complete lines queued in one outbox.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OutboxState {
    /// Number of committed complete lines.
    pub pending: u64,
    /// SHA-256 chain head over the committed lines, without newlines.
    pub head: [u8; 32],
}

impl OutboxState {
    /// Encodes the versioned keyring value.
    #[must_use]
    pub fn to_keyring_value(&self) -> String {
        format!(
            r#"{{"v":1,"pending":{},"head":"sha256:{}"}}"#,
            self.pending,
            crate::hex::encode(&self.head)
        )
    }

    /// Parses a keyring value, refusing malformed or unsupported states.
    ///
    /// # Errors
    /// Returns a store error when the value is unusable.
    pub fn parse(raw: &str) -> Result<Self, TipAnchorStoreError> {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Stored {
            v: u8,
            pending: u64,
            head: String,
        }
        let invalid = || TipAnchorStoreError::new("outbox state is unusable");
        let stored: Stored = serde_json::from_str(raw).map_err(|_| invalid())?;
        if stored.v != 1 {
            return Err(invalid());
        }
        let head = super::chain::decode_hash(&stored.head).map_err(|_| invalid())?;
        if stored.pending == 0 && head != [0; 32] {
            return Err(invalid());
        }
        Ok(Self {
            pending: stored.pending,
            head,
        })
    }

    fn push(&mut self, line: &[u8]) {
        let mut hash = Sha256::new();
        hash.update(b"stellar-agent-outbox:v1");
        hash.update(self.head);
        hash.update(line);
        self.head = hash.finalize().into();
        self.pending += 1;
    }

    pub(crate) fn over(lines: &[&[u8]]) -> Self {
        let mut state = Self::default();
        for line in lines {
            state.push(line);
        }
        state
    }
}

/// Owner evidence for one queue generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxOwnerState {
    g: u64,
    closed: Option<ClosedBatch>,
    legacy: Option<[u8; 32]>,
    recent: Vec<[u8; 32]>,
    e: Option<EvidenceCommitment>,
}

/// The evidence generation and head a v2 owner value commits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EvidenceCommitment {
    g: u64,
    head: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ClosedBatch {
    g: u64,
    n: u64,
    batch: [u8; 32],
}

impl OutboxOwnerState {
    /// Parses the owner value with bounded evidence and required fields.
    ///
    /// Version 1 carries at most 15 recent digests. Version 2 carries the
    /// evidence commitment `e` instead. Both admit only their canonical bytes.
    ///
    /// # Errors
    /// Returns a store error when the owner value is unusable.
    pub fn parse(raw: &str) -> Result<Self, TipAnchorStoreError> {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct StoredClosed {
            g: u64,
            n: u64,
            batch: String,
        }
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct StoredEvidence {
            g: u64,
            head: String,
        }
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Stored {
            v: u64,
            g: u64,
            #[serde(deserialize_with = "serde::Deserialize::deserialize")]
            closed: Option<StoredClosed>,
            #[serde(deserialize_with = "serde::Deserialize::deserialize")]
            legacy: Option<String>,
            #[serde(default)]
            recent: Option<Vec<String>>,
            #[serde(default)]
            e: Option<StoredEvidence>,
        }
        let invalid = || TipAnchorStoreError::new("outbox owner state is unusable");
        let hash = |text: &str| bare_hash(text.as_bytes()).ok_or_else(invalid);
        let stored: Stored = serde_json::from_str(raw).map_err(|_| invalid())?;
        let recent = match (stored.v, stored.recent, &stored.e) {
            (1, Some(recent), None) if recent.len() <= 15 => recent,
            (2, None, Some(_)) => Vec::new(),
            _ => return Err(invalid()),
        };
        let owner = Self {
            g: stored.g,
            closed: stored
                .closed
                .map(|closed| {
                    Ok::<_, TipAnchorStoreError>(ClosedBatch {
                        g: closed.g,
                        n: closed.n,
                        batch: hash(&closed.batch)?,
                    })
                })
                .transpose()?,
            legacy: stored.legacy.as_deref().map(hash).transpose()?,
            recent: recent
                .iter()
                .map(|text| hash(text))
                .collect::<Result<_, _>>()?,
            e: stored
                .e
                .map(|e| {
                    Ok::<_, TipAnchorStoreError>(EvidenceCommitment {
                        g: e.g,
                        head: hash(&e.head)?,
                    })
                })
                .transpose()?,
        };
        if owner.to_keyring_value() != raw {
            return Err(invalid());
        }
        Ok(owner)
    }

    /// Encodes the owner fields in their persistence order.
    #[must_use]
    pub fn to_keyring_value(&self) -> String {
        let closed = self.closed.as_ref().map_or_else(
            || "null".to_owned(),
            |closed| {
                format!(
                    r#"{{"g":{},"n":{},"batch":"{}"}}"#,
                    closed.g,
                    closed.n,
                    crate::hex::encode(&closed.batch)
                )
            },
        );
        let legacy = self.legacy.as_ref().map_or_else(
            || "null".to_owned(),
            |hash| format!(r#""{}""#, crate::hex::encode(hash)),
        );
        if let Some(e) = &self.e {
            return format!(
                r#"{{"v":2,"g":{},"closed":{closed},"legacy":{legacy},"e":{{"g":{},"head":"{}"}}}}"#,
                self.g,
                e.g,
                crate::hex::encode(&e.head)
            );
        }
        let recent = self
            .recent
            .iter()
            .map(|hash| format!(r#""{}""#, crate::hex::encode(hash)))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            r#"{{"v":1,"g":{},"closed":{closed},"legacy":{legacy},"recent":[{recent}]}}"#,
            self.g
        )
    }

    fn new(g: u64, legacy: Option<&OutboxState>) -> Self {
        Self {
            g,
            closed: None,
            legacy: legacy.map(|state| Sha256::digest(state.to_keyring_value()).into()),
            recent: Vec::new(),
            e: None,
        }
    }

    /// One migration pin for each recent digest of a v1 owner.
    fn migration_pins(&self) -> Vec<EvidenceRecord> {
        self.recent
            .iter()
            .map(|digest| EvidenceRecord::legacy_pin(*digest))
            .collect()
    }

    /// The v2 owner that commits evidence generation `g` and `head`, keeping
    /// the queue generation, the closed batch, and the legacy digest.
    fn with_evidence(&self, g: u64, head: [u8; 32]) -> Self {
        Self {
            g: self.g,
            closed: self.closed.clone(),
            legacy: self.legacy,
            recent: Vec::new(),
            e: Some(EvidenceCommitment { g, head }),
        }
    }

    fn record_delivery(&mut self, g: u64, rows: &[(u8, [u8; 32])]) {
        self.close(g, rows, 0);
    }

    /// Closes generation `g` over `rows`, of which the first `delivered`
    /// already count in the recent evidence. A v2 owner keeps its evidence
    /// commitment unchanged and records no recent digest.
    fn close(&mut self, g: u64, rows: &[(u8, [u8; 32])], delivered: usize) {
        for (r, digest) in rows.get(delivered..).unwrap_or_default() {
            if *r == 1 && self.e.is_none() {
                self.recent.push(*digest);
            }
        }
        self.recent.drain(..self.recent.len().saturating_sub(15));
        self.closed = Some(ClosedBatch {
            g,
            n: rows.len() as u64,
            batch: batch_digest(rows),
        });
    }
}

/// The batch commitment: SHA-256 over the ordered binary row digests.
fn batch_digest(rows: &[(u8, [u8; 32])]) -> [u8; 32] {
    let mut batch = Sha256::new();
    for (_, digest) in rows {
        batch.update(digest);
    }
    batch.finalize().into()
}

/// Counts describing a missing or changed committed prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutboxLoss {
    /// Legacy committed rows, or complete owner rows after the header.
    pub expected_rows: u64,
    /// Complete legacy lines, or delivered and selected owner rows.
    pub found_rows: u64,
}

/// The loss, when `lines` are not exactly the committed prefix: the first
/// `state.pending` of them do not exist or do not chain to `state.head`, or
/// there are more complete lines than `state.pending`.
fn committed_prefix_loss(lines: &[&[u8]], state: &OutboxState) -> Option<OutboxLoss> {
    if committed_prefix(lines, state).is_some() && lines.len() as u64 == state.pending {
        return None;
    }
    Some(OutboxLoss {
        expected_rows: state.pending,
        found_rows: lines.len() as u64,
    })
}

/// The first `state.pending` of `lines`, when they exist and chain to
/// `state.head`.
fn committed_prefix<'l, 'b>(lines: &'l [&'b [u8]], state: &OutboxState) -> Option<&'l [&'b [u8]]> {
    usize::try_from(state.pending)
        .ok()
        .and_then(|pending| lines.get(..pending))
        .filter(|prefix| OutboxState::over(prefix).head == state.head)
}

/// How the tagged rows past a legacy commitment are checked.
#[derive(Debug, Clone, Copy)]
pub(crate) enum SuffixCheck<'k> {
    /// Authenticate every tagged row under the key; without one, a tagged row
    /// refuses.
    Keyed(Option<&'k [u8; 32]>),
    /// Check layout, canonical body, position and kind without a key.
    Keyless,
}

/// Validates a legacy queue: the v1 chain over the first `state.pending`
/// lines first, then every following complete line as a tagged row of
/// generation zero at its physical line number.
///
/// The prefix lines are not decoded here.
///
/// # Errors
///
/// - [`WriterError::OutboxRowsMissing`] with the committed and found counts
///   when the prefix is missing or changed. It carries the expected position
///   and zero for an untagged line past the prefix. It carries the expected
///   and found positions for a tagged row out of place.
/// - [`WriterError::OutboxUnusable`] and [`WriterError::OutboxRowKindRefused`]
///   for a tagged row past the prefix that fails layout, authentication,
///   canonical form or kind.
fn validate_legacy_queue(
    lines: &[&[u8]],
    state: &OutboxState,
    check: SuffixCheck<'_>,
) -> Result<Vec<AuditEntry>, WriterError> {
    let prefix = committed_prefix(lines, state).ok_or(WriterError::OutboxRowsMissing {
        recorded: state.pending,
        found: lines.len() as u64,
    })?;
    lines
        .iter()
        .enumerate()
        .skip(prefix.len())
        .map(|(index, line)| {
            let number = index + 1;
            if !is_tagged(line) {
                return Err(WriterError::OutboxRowsMissing {
                    recorded: number as u64,
                    found: 0,
                });
            }
            decode_tagged(line, number, check, 0, number as u64).map(|row| row.entry)
        })
        .collect()
}

/// Validates a queue that no owner state holds.
///
/// Only a cutover publishes a generation line, and it stores the owner state
/// first. A generation line without owner state therefore belongs to no
/// queue of this log, and refuses.
///
/// # Errors
///
/// - [`WriterError::OutboxRowsMissing`] for a queue that starts with a
///   generation line, counting the rows after it as found.
/// - [`WriterError::OutboxUnusable`] for a first line that is an unusable
///   generation line.
/// - The errors of [`validate_legacy_queue`] for any other queue.
fn validate_unowned_queue(
    lines: &[&[u8]],
    state: &OutboxState,
    check: SuffixCheck<'_>,
) -> Result<(), WriterError> {
    match first_generation(lines)? {
        Some(_) => Err(WriterError::OutboxRowsMissing {
            recorded: 0,
            found: lines.len() as u64 - 1,
        }),
        None => validate_legacy_queue(lines, state, check).map(drop),
    }
}

/// One decoded tagged row with its evidence flag and digest.
struct DecodedRow {
    r: u8,
    digest: [u8; 32],
    entry: AuditEntry,
}

/// Decodes the tagged row at physical line `number`, expected at queue
/// generation `g` and position `s`.
///
/// The checks run in this order: exact layout, authentication, canonical
/// body, position, operator kind.
fn decode_tagged(
    line: &[u8],
    number: usize,
    check: SuffixCheck<'_>,
    g: u64,
    s: u64,
) -> Result<DecodedRow, WriterError> {
    if generation_at(line, number)?.is_some() {
        return Err(tagged_refusal(number, "tagged record that does not parse"));
    }
    let row = tagged_layout(line)
        .ok_or_else(|| tagged_refusal(number, "tagged record that does not parse"))?;
    match check {
        SuffixCheck::Keyed(Some(key)) => row_mac(key, row.g, row.s, row.r, row.body)
            .verify_slice(&row.tag)
            .map_err(|_| tagged_refusal(number, "tagged record whose tag does not verify"))?,
        SuffixCheck::Keyed(None) => {
            return Err(tagged_refusal(number, "tagged record without an audit key"));
        }
        SuffixCheck::Keyless => {}
    }
    let entry = canonical_entry(row.body, number)?;
    if row.g != g || row.s != s {
        return Err(WriterError::OutboxRowsMissing {
            recorded: s,
            found: row.s,
        });
    }
    if !is_operator_row(&entry) {
        return Err(WriterError::OutboxRowKindRefused { line: number });
    }
    Ok(DecodedRow {
        r: row.r,
        digest: layout_digest(row.g, row.s, row.r, row.body),
        entry,
    })
}

/// Decodes an untagged line at physical line `number` as an operator row.
fn decode_raw(line: &[u8], number: usize) -> Result<AuditEntry, WriterError> {
    let entry = serde_json::from_slice::<AuditEntry>(line).map_err(|error| {
        WriterError::OutboxUnusable {
            line: number,
            column: error.column(),
            reason: parse_failure_class(&error),
        }
    })?;
    if !is_operator_row(&entry) {
        return Err(WriterError::OutboxRowKindRefused { line: number });
    }
    Ok(entry)
}

/// Whether `entry` is an operator row, the only kinds the outbox carries.
///
/// The CLI queues exactly these when a draining writer in another process
/// holds the log: the attested approval, local or remote, and the halt and
/// resume rows of `profile halt` and `profile resume`.
fn is_operator_row(entry: &AuditEntry) -> bool {
    matches!(
        entry.event_kind,
        EventKind::ApprovalAttested { .. }
            | EventKind::ApprovalAttestedRemote { .. }
            | EventKind::ProfileHalted { .. }
            | EventKind::ProfileResumed { .. }
    )
}

/// Parses `lines`, numbered from one, as operator rows.
///
/// # Errors
///
/// [`WriterError::OutboxUnusable`] for a line that does not parse as an
/// [`AuditEntry`], and [`WriterError::OutboxRowKindRefused`] for one that
/// holds another kind of row.
fn parse_operator_rows(
    lines: &[&[u8]],
    key: Option<&[u8; 32]>,
) -> Result<Vec<AuditEntry>, WriterError> {
    lines
        .iter()
        .enumerate()
        .map(|(index, line)| decode_line(line, index + 1, key))
        .collect()
}

fn row_prefix(g: u64, s: u64, r: u8) -> Vec<u8> {
    format!(r#"{{"k":"row","g":{g},"s":{s},"r":{r},"body":"#).into_bytes()
}

/// The tag binds the exact coordinates, evidence flag, and body bytes.
#[allow(
    clippy::expect_used,
    reason = "HMAC-SHA256 accepts a key of any length"
)]
fn row_mac(key: &[u8; 32], g: u64, s: u64, r: u8, body: &[u8]) -> Hmac<Sha256> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).expect("HMAC-SHA256 accepts a key of any length");
    mac.update(b"stellar-agent-outbox-row:v2");
    mac.update(&g.to_be_bytes());
    mac.update(&s.to_be_bytes());
    mac.update(&[r]);
    mac.update(body);
    mac
}

fn encode_tagged_row(
    key: &[u8; 32],
    g: u64,
    s: u64,
    r: u8,
    entry: &AuditEntry,
) -> Result<Vec<u8>, serde_json::Error> {
    let body = entry.canonical_json_body()?;
    let tag = row_mac(key, g, s, r, &body).finalize().into_bytes();
    let mut line = row_prefix(g, s, r);
    line.extend_from_slice(&body);
    line.extend_from_slice(b",\"tag\":\"");
    line.extend_from_slice(crate::hex::encode(&tag).as_bytes());
    line.extend_from_slice(b"\"}");
    Ok(line)
}

/// The digest of the row `entry` at `(g, s)` with evidence flag `r`: SHA-256
/// over the row's bytes without its tag and newline.
fn row_digest(g: u64, s: u64, r: u8, entry: &AuditEntry) -> Result<[u8; 32], serde_json::Error> {
    Ok(layout_digest(g, s, r, &entry.canonical_json_body()?))
}

/// The coordinates and digest of a durably queued consent row.
///
/// A reference identifies the row; delivery requires separate owner evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutboxRowRef {
    generation: u64,
    sequence: u64,
    digest: [u8; 32],
}

impl OutboxRowRef {
    /// The queue generation that contains the row.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// The row's one-based position within its generation.
    #[must_use]
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// The SHA-256 digest of the row without its tag or newline.
    #[must_use]
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

impl serde::Serialize for OutboxRowRef {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct as _;
        let mut wire = serializer.serialize_struct("OutboxRowRef", 3)?;
        wire.serialize_field("g", &self.generation)?;
        wire.serialize_field("s", &self.sequence)?;
        wire.serialize_field(
            "digest",
            &format!("sha256:{}", crate::hex::encode(&self.digest)),
        )?;
        wire.end()
    }
}

impl<'de> serde::Deserialize<'de> for OutboxRowRef {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            g: u64,
            s: u64,
            digest: String,
        }
        struct Object;
        impl<'de> serde::de::Visitor<'de> for Object {
            type Value = Wire;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an outbox row reference object")
            }

            fn visit_map<M: serde::de::MapAccess<'de>>(self, map: M) -> Result<Wire, M::Error> {
                serde::Deserialize::deserialize(serde::de::value::MapAccessDeserializer::new(map))
            }
        }
        let wire = deserializer.deserialize_map(Object)?;
        let invalid =
            || serde::de::Error::custom("outbox row digest is not sha256:<64 lowercase hex>");
        let hex = wire.digest.strip_prefix("sha256:").ok_or_else(invalid)?;
        if hex.len() != 64 || !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(invalid());
        }
        Ok(Self {
            generation: wire.g,
            sequence: wire.s,
            digest: crate::hex::decode_hex32(hex).map_err(|_| invalid())?,
        })
    }
}

fn layout_digest(g: u64, s: u64, r: u8, body: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(row_prefix(g, s, r));
    digest.update(body);
    digest.update(b"}");
    digest.finalize().into()
}

fn is_tagged(line: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(line)
        .ok()
        .is_some_and(|value| {
            value
                .as_object()
                .is_some_and(|object| object.contains_key("k"))
        })
}

struct TaggedRow<'a> {
    g: u64,
    s: u64,
    r: u8,
    body: &'a [u8],
    tag: [u8; 32],
}

fn take_decimal(input: &mut &[u8]) -> Option<u64> {
    let end = input.iter().position(|byte| *byte == b',')?;
    let (digits, rest) = input.split_at(end);
    if digits.is_empty()
        || (digits.len() > 1 && digits[0] == b'0')
        || !digits.iter().all(u8::is_ascii_digit)
    {
        return None;
    }
    let value = std::str::from_utf8(digits).ok()?.parse().ok()?;
    *input = rest;
    Some(value)
}

fn bare_hash(bytes: &[u8]) -> Option<[u8; 32]> {
    if bytes.len() != 64
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return None;
    }
    crate::hex::decode_hex32(std::str::from_utf8(bytes).ok()?).ok()
}

fn generation_layout(line: &[u8]) -> Option<(u64, [u8; 32])> {
    let mut rest = line.strip_prefix(b"{\"k\":\"gen\",\"g\":")?;
    let g = take_decimal(&mut rest)?;
    let tag = rest.strip_prefix(b",\"tag\":\"")?.strip_suffix(b"\"}")?;
    Some((g, bare_hash(tag)?))
}

fn generation_at(line: &[u8], number: usize) -> Result<Option<(u64, [u8; 32])>, WriterError> {
    let is_generation = line.starts_with(b"{\"k\":\"gen\"")
        || serde_json::from_slice::<serde_json::Value>(line)
            .ok()
            .is_some_and(|value| value.get("k").and_then(|k| k.as_str()) == Some("gen"));
    if !is_generation {
        return Ok(None);
    }
    if number != 1 {
        return Err(tagged_refusal(number, "generation line out of place"));
    }
    generation_layout(line)
        .map(Some)
        .ok_or_else(|| tagged_refusal(number, "tagged record that does not parse"))
}

#[allow(
    clippy::expect_used,
    reason = "HMAC-SHA256 accepts a key of any length"
)]
fn generation_mac(key: &[u8; 32], g: u64) -> Hmac<Sha256> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).expect("HMAC-SHA256 accepts a key of any length");
    mac.update(b"stellar-agent-outbox-gen:v2");
    mac.update(&g.to_be_bytes());
    mac
}

fn generation_verifies(key: &[u8; 32], g: u64, tag: &[u8; 32]) -> bool {
    generation_mac(key, g).verify_slice(tag).is_ok()
}

/// Reads the audit key the store holds now.
fn reload_stored_key(
    store: &dyn TipAnchorStore,
) -> Result<Option<Zeroizing<[u8; 32]>>, WriterError> {
    store.reload_audit_key().map_err(|_| {
        WriterError::TipAnchorStore(TipAnchorStoreError::new("audit key reload failed"))
    })
}

/// Whether `held` is the audit key the store holds now, compared in
/// constant time. An absent stored key matches no held key.
pub(super) fn is_stored_key(
    store: &dyn TipAnchorStore,
    held: &[u8; 32],
) -> Result<bool, WriterError> {
    use subtle::ConstantTimeEq as _;
    Ok(reload_stored_key(store)?
        .is_some_and(|stored| bool::from(stored.as_slice().ct_eq(held.as_slice()))))
}

/// The generation header of the first complete line, its layout checked.
fn first_generation(lines: &[&[u8]]) -> Result<Option<(u64, [u8; 32])>, WriterError> {
    lines
        .first()
        .map_or(Ok(None), |line| generation_at(line, 1))
}

fn encode_generation_line(key: &[u8; 32], g: u64) -> Vec<u8> {
    generation_line_with_tag(g, &generation_mac(key, g).finalize().into_bytes())
}

/// The fence line of generation `g`: a generation line whose tag is all
/// zeros, which no key verifies.
///
/// An appender then refuses under any key it holds or reloads. A drain
/// re-signs a lone fence line of the owned generation under its own key.
fn encode_fence_line(g: u64) -> Vec<u8> {
    generation_line_with_tag(g, &[0; 32])
}

fn generation_line_with_tag(g: u64, tag: &[u8]) -> Vec<u8> {
    format!(
        "{{\"k\":\"gen\",\"g\":{g},\"tag\":\"{}\"}}\n",
        crate::hex::encode(tag)
    )
    .into_bytes()
}

#[cfg(any(test, feature = "test-helpers"))]
fn authenticated_generation(lines: &[&[u8]], key: Option<&[u8; 32]>) -> Result<u64, WriterError> {
    let mut generation = 0;
    for (index, line) in lines.iter().enumerate() {
        if let Some((g, tag)) = generation_at(line, index + 1)? {
            let key = key.ok_or_else(|| tagged_refusal(1, "tagged record without an audit key"))?;
            generation_mac(key, g)
                .verify_slice(&tag)
                .map_err(|_| tagged_refusal(1, "tagged record whose tag does not verify"))?;
            generation = g;
        }
    }
    Ok(generation)
}

fn advance_generation(g: u64) -> Result<u64, WriterError> {
    g.checked_add(1)
        .ok_or_else(|| tagged_refusal(1, "queue generation overflows"))
}

fn tagged_layout(line: &[u8]) -> Option<TaggedRow<'_>> {
    let mut rest = line.strip_prefix(b"{\"k\":\"row\",\"g\":")?;
    let g = take_decimal(&mut rest)?;
    rest = rest.strip_prefix(b",\"s\":")?;
    let s = take_decimal(&mut rest)?;
    rest = rest.strip_prefix(b",\"r\":")?;
    let r = match rest.first()? {
        b'0' => 0,
        b'1' => 1,
        _ => return None,
    };
    rest = rest.get(1..)?.strip_prefix(b",\"body\":")?;
    rest = rest.strip_suffix(b"\"}")?;
    let (body, tag) = rest.split_at(rest.len().checked_sub(64)?);
    if !tag
        .iter()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return None;
    }
    let body = body.strip_suffix(b",\"tag\":\"")?;
    serde_json::from_slice::<serde::de::IgnoredAny>(body).ok()?;
    Some(TaggedRow {
        g,
        s,
        r,
        body,
        tag: crate::hex::decode_hex32(std::str::from_utf8(tag).ok()?).ok()?,
    })
}

fn tagged_refusal(number: usize, reason: &'static str) -> WriterError {
    WriterError::OutboxUnusable {
        line: number,
        column: 1,
        reason,
    }
}

fn canonical_entry(body: &[u8], number: usize) -> Result<AuditEntry, WriterError> {
    let refused = || tagged_refusal(number, "tagged record that is not canonical");
    let entry = serde_json::from_slice::<AuditEntry>(body).map_err(|_| refused())?;
    if entry.canonical_json_body().map_err(|_| refused())? != body {
        return Err(refused());
    }
    Ok(entry)
}

/// Decodes a line of the legacy state: an untagged entry, or a tagged row of
/// generation zero at its physical line number.
fn decode_line(
    line: &[u8],
    number: usize,
    key: Option<&[u8; 32]>,
) -> Result<AuditEntry, WriterError> {
    if is_tagged(line) {
        decode_tagged(line, number, SuffixCheck::Keyed(key), 0, number as u64).map(|row| row.entry)
    } else {
        decode_raw(line, number)
    }
}

fn check_committed_prefix(lines: &[&[u8]], state: &OutboxState) -> Result<(), WriterError> {
    match committed_prefix_loss(lines, state) {
        None => Ok(()),
        Some(loss) => Err(WriterError::OutboxRowsMissing {
            recorded: loss.expected_rows,
            found: loss.found_rows,
        }),
    }
}

fn load_state(store: &dyn TipAnchorStore, generation: u64) -> Result<OutboxState, WriterError> {
    store
        .load_outbox_state(generation)
        .map(Option::unwrap_or_default)
        .map_err(WriterError::TipAnchorStore)
}

/// Checks the outbox's committed prefix and the evidence image its owner
/// commits, under the outbox lock taken through the carrier record.
/// Evidence selection authenticates both slots with the one stored key this
/// check reads.
/// Generation lines and rows authenticate under the stored key when the store
/// reads one. Without that key, verification checks layout, canonical bodies,
/// coordinates, and kind. A recoverable publication passes with a warning and
/// leaves every file and item unchanged.
///
/// # Errors
///
/// - [`WriterError::OutboxBusy`] when the outbox lock stays held.
/// - The carrier refusals of the acquisition: [`WriterError::CarrierReplaced`],
///   [`WriterError::CarrierGenerationChanged`], [`WriterError::CarriersUnbound`],
///   [`WriterError::CarrierIdentityUnavailable`], and
///   [`WriterError::RetiredOutboxChanged`] for a changed retired commitment.
/// - [`WriterError::TipAnchorStore`] when the commitment or the record cannot
///   be read.
/// - [`WriterError::Io`] when the outbox cannot be read.
/// - [`WriterError::OutboxRowsMissing`] for a missing or changed committed
///   prefix, an untagged line past it, or a tagged row past it out of place.
/// - [`WriterError::OutboxUnusable`] and [`WriterError::OutboxRowKindRefused`]
///   for a tagged row past the prefix that fails layout, canonical form or
///   kind, including authentication when a stored key exists.
/// - Under owner state, every refusal of the owner drain:
///   a changed commitment, and a queue generation or row
///   position the owner state does not hold. Rows at the closed coordinates
///   must reproduce the closed batch.
/// - Without owner state, [`WriterError::OutboxRowsMissing`] for a queue
///   that starts with a generation line.
/// - The refusals of an evidence read: evidence files beside a missing owner
///   or an owner that commits none,
///   [`WriterError::KeyedLogNeedsKey`] for committed evidence without the
///   stored key, [`WriterError::CarrierRecoveryRequired`] while a binding is
///   incomplete, and [`WriterError::OutboxEvidenceUnusable`] with its
///   selection reason, or `owner recommit required` for a newer image the
///   owner does not commit yet. Verification never repairs the owner.
pub fn check_outbox_commitment(
    log_path: &Path,
    store: &dyn TipAnchorStore,
) -> Result<(), WriterError> {
    let batch = OutboxBatch::read_locked(log_path, store)?;
    let key = if store.reads_audit_key() {
        reload_stored_key(store)?
    } else {
        None
    };
    let check = key
        .as_deref()
        .map_or(SuffixCheck::Keyless, |key| SuffixCheck::Keyed(Some(key)));
    let lines = parse_lines(&batch.bytes).lines;
    let owner = batch.owner(store)?;
    if owner.as_ref().is_some_and(|owner| owner.e.is_some()) {
        check_no_incomplete_binding(log_path, store, batch.generation)?;
    }
    if select_owner_evidence(log_path, store, owner.clone(), key.as_deref(), false)?
        .is_some_and(|loaded| loaded.recommit)
    {
        return Err(evidence_unusable("owner recommit required"));
    }
    match owner {
        Some(owner) => {
            let selection = batch.select_owner(&lines, owner, check, false)?;
            let pending = selection.publication_pending;
            selection.accepted()?;
            if pending {
                tracing::warn!("audit outbox publication pending; the next drain completes it");
            }
            Ok(())
        }
        None => validate_unowned_queue(&lines, &batch.state, check),
    }
}

/// How long an append or a drain waits for the outbox lock before refusing
/// with [`WriterError::OutboxBusy`].
pub const OUTBOX_LOCK_WAIT: Duration = Duration::from_secs(2);

/// Environment variable that replaces [`OUTBOX_LOCK_WAIT`] with its value in
/// milliseconds.
///
/// Compiled only with the `test-helpers` feature, so a release binary always
/// waits [`OUTBOX_LOCK_WAIT`]. A subprocess test sets it to keep an append
/// waiting long enough to observe the process during the wait.
#[cfg(any(test, feature = "test-helpers"))]
pub const OUTBOX_LOCK_WAIT_ENV: &str = "STELLAR_AGENT_TEST_OUTBOX_LOCK_WAIT_MS";

/// The wait [`lock_outbox`] applies: [`OUTBOX_LOCK_WAIT`], or with the
/// `test-helpers` feature the value of `STELLAR_AGENT_TEST_OUTBOX_LOCK_WAIT_MS`
/// when it parses as a whole number of milliseconds.
#[must_use]
pub(crate) fn outbox_lock_wait() -> Duration {
    #[cfg(any(test, feature = "test-helpers"))]
    if let Some(millis) = std::env::var(OUTBOX_LOCK_WAIT_ENV)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
    {
        return Duration::from_millis(millis);
    }
    OUTBOX_LOCK_WAIT
}

/// Delay between two attempts on the outbox lock.
pub(crate) const OUTBOX_LOCK_STEP: Duration = Duration::from_millis(20);

/// Number of `try_lock` attempts a draining writer's open makes on the drain
/// lock before it refuses.
///
/// Every writer that holds the drain lock, a recovery writer included, takes
/// it while it holds the sidecar lock, so a writer's open finds it held only
/// by a one-shot probe, which releases it at once. A short bound suffices.
pub(crate) const DRAIN_LOCK_ATTEMPTS: u32 = 5;

/// Delay between two attempts on the drain lock.
pub(crate) const DRAIN_LOCK_BACKOFF: Duration = Duration::from_millis(20);

/// Returns `<log_path>.outbox`.
#[must_use]
pub fn outbox_path(log_path: &Path) -> PathBuf {
    sidecar_path(log_path, ".outbox")
}

/// Returns `<log_path>.outbox.lock`.
#[must_use]
pub(crate) fn outbox_lock_path(log_path: &Path) -> PathBuf {
    sidecar_path(log_path, ".outbox.lock")
}

/// Returns `<log_path>.drain.lock`.
#[must_use]
pub(crate) fn drain_lock_path(log_path: &Path) -> PathBuf {
    sidecar_path(log_path, ".drain.lock")
}

/// Returns `true` when a draining writer holds the drain lock of the log at
/// `log_path`.
///
/// One `try_lock` through the carrier record, released before this function
/// returns. A lock that could be taken is not held by any draining writer. A
/// free lock file that is not the recorded one fails the probe closed with
/// [`WriterError::CarrierReplaced`] instead of reading as free.
///
/// # Errors
///
/// - [`WriterError::CarrierReplaced`], [`WriterError::CarriersUnbound`] and
///   [`WriterError::CarrierIdentityUnavailable`] when a free lock file does
///   not match the record.
/// - [`WriterError::TipAnchorStore`] when the record cannot be read.
/// - [`WriterError::Io`] when the lock file cannot be opened or locked for a
///   reason other than contention.
pub fn drain_lock_is_held(
    log_path: &Path,
    store: &dyn TipAnchorStore,
) -> Result<bool, WriterError> {
    match AuditWriterLock::acquire_bound(&drain_lock_path(log_path), Carrier::Drain, store) {
        Ok(lock) => {
            drop(lock);
            Ok(false)
        }
        Err(WriterError::FileLocked) => Ok(true),
        Err(e) => Err(e),
    }
}

/// Takes the drain lock of the log at `log_path` for a draining writer,
/// checked against the carrier record.
///
/// Bounded: [`DRAIN_LOCK_ATTEMPTS`] attempts, [`DRAIN_LOCK_BACKOFF`] apart.
///
/// # Errors
///
/// - [`WriterError::FileLocked`] when every attempt finds the lock held.
/// - The refusals of
///   [`AuditWriterLock::acquire_bound`](super::lock::AuditWriterLock::acquire_bound)
///   when the locked file does not match the record.
/// - [`WriterError::Io`] for any other failure.
pub(crate) fn acquire_drain_lock(
    log_path: &Path,
    store: &dyn TipAnchorStore,
) -> Result<AuditWriterLock, WriterError> {
    let path = drain_lock_path(log_path);
    let mut attempt = 0_u32;
    loop {
        attempt += 1;
        match AuditWriterLock::acquire_bound(&path, Carrier::Drain, store) {
            Err(WriterError::FileLocked) if attempt < DRAIN_LOCK_ATTEMPTS => {
                std::thread::sleep(DRAIN_LOCK_BACKOFF);
            }
            other => return other.map(BoundCarrierLock::into_lock),
        }
    }
}

/// Takes the outbox lock at `lock_path`, checked against the carrier record,
/// waiting up to [`outbox_lock_wait`].
///
/// The first attempt that finds the lock held emits one debug event, so an
/// operator can tell a command that waits on another appender from one that
/// stalls elsewhere. Only contention is retried; a refusal of the record
/// returns at once.
///
/// # Errors
///
/// - [`WriterError::OutboxBusy`] when the lock stays held for the whole wait.
/// - The refusals of
///   [`AuditWriterLock::acquire_bound`](super::lock::AuditWriterLock::acquire_bound)
///   for an outbox acquisition, the retired watch included.
/// - [`WriterError::Io`] for any other failure.
pub(crate) fn lock_outbox(
    lock_path: &Path,
    store: &dyn TipAnchorStore,
) -> Result<BoundCarrierLock, WriterError> {
    wait_for_outbox(lock_path, || {
        AuditWriterLock::acquire_bound(lock_path, Carrier::Outbox, store)
    })
}

/// [`lock_outbox`] for a keyed queue append: the same wait and identity
/// check, without the retired watch, which the drain runs.
///
/// # Errors
///
/// The errors of [`lock_outbox`] except [`WriterError::RetiredOutboxChanged`].
fn lock_queue(
    lock_path: &Path,
    store: &dyn TipAnchorStore,
) -> Result<BoundCarrierLock, WriterError> {
    wait_for_outbox(lock_path, || {
        AuditWriterLock::acquire_queue_bound(lock_path, store)
    })
}

fn wait_for_outbox(
    lock_path: &Path,
    acquire: impl Fn() -> Result<BoundCarrierLock, WriterError>,
) -> Result<BoundCarrierLock, WriterError> {
    let wait = outbox_lock_wait();
    let deadline = Instant::now() + wait;
    let mut waiting = false;
    loop {
        match acquire() {
            Err(WriterError::FileLocked) => {
                if Instant::now() >= deadline {
                    return Err(WriterError::OutboxBusy);
                }
                if !waiting {
                    waiting = true;
                    #[cfg(test)]
                    test_seam::run_contended(lock_path);
                    tracing::debug!(
                        lock = %basename(lock_path),
                        wait_ms = wait.as_millis(),
                        "audit outbox: the outbox lock is held; waiting for it"
                    );
                }
                std::thread::sleep(OUTBOX_LOCK_STEP);
            }
            other => return other,
        }
    }
}

/// The outbox of one audit log, to which an operator row is appended while a
/// draining writer in another process holds the log.
///
/// Every append takes the outbox lock for its own duration.
#[derive(Clone)]
pub struct AuditOutbox {
    log_path: PathBuf,
    path: PathBuf,
    lock_path: PathBuf,
    state: Arc<dyn TipAnchorStore>,
    key: Option<Zeroizing<[u8; 32]>>,
    reservation: Option<EvidenceReservation>,
}

impl std::fmt::Debug for AuditOutbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditOutbox")
            .field("path", &self.path)
            .field("lock_path", &self.lock_path)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl AuditOutbox {
    /// The outbox of the audit log at `log_path`, committed in `state`.
    ///
    /// `state` must be the log's own commitment store: the tip-anchor store
    /// the log's draining writers hold, at the same keyring coordinate. An
    /// append commits to `state` and a drain checks the store of the writer
    /// that drains, so an append committed to any other store reads as a
    /// loss at the next drain.
    #[must_use]
    pub fn for_log(log_path: &Path, state: Arc<dyn TipAnchorStore>) -> Self {
        Self {
            log_path: log_path.to_path_buf(),
            path: outbox_path(log_path),
            lock_path: outbox_lock_path(log_path),
            state,
            key: None,
            reservation: None,
        }
    }

    /// The outbox of `log_path`, with rows authenticated under the audit MAC key.
    ///
    /// `state` is the log's own commitment store, as required by [`Self::for_log`].
    /// The key stays in zeroizing storage and clones with the outbox.
    #[must_use]
    pub fn for_log_keyed(
        log_path: &Path,
        state: Arc<dyn TipAnchorStore>,
        key: Zeroizing<[u8; 32]>,
    ) -> Self {
        Self {
            key: Some(key),
            ..Self::for_log(log_path, state)
        }
    }

    /// Path of the outbox file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether this outbox holds an audit key for authenticated rows.
    #[must_use]
    pub fn is_keyed(&self) -> bool {
        self.key.is_some()
    }

    /// Reserves capacity before ceremony, including consent with a direct sink.
    /// Supply authenticated approval identity, immutable expiry, and verified time.
    /// Use [`EvidenceReservation::deadline`] for the conservative retention deadline.
    /// Finish the policy-window transaction before calling this method.
    ///
    /// # Errors
    /// Refuses unkeyed, uninitialized, expired, conflicting, or unusable evidence.
    /// Full capacity returns `approval.evidence_capacity`; storage errors retain their codes.
    pub fn reserve_evidence(
        &self,
        identity: [u8; 32],
        expires_at_ms: u64,
        now_ms: u64,
    ) -> Result<EvidenceReservation, WalletError> {
        let mut capacity = false;
        let result = (|| {
            let (batch, key) = self.evidence_batch()?;
            batch.commit_evidence_change(
                &self.log_path,
                self.state.as_ref(),
                &key,
                false,
                |image, _| {
                    if expires_at_ms <= image.floor_ms.max(now_ms) {
                        return Err(evidence_unusable("expired reservation"));
                    }
                    image.advance_floor(now_ms);
                    if let Some(record) = image
                        .records
                        .iter()
                        .find(|record| record.identity == identity)
                    {
                        if record.expires_at_ms != expires_at_ms
                            || record.state == RecordState::LegacyPin
                        {
                            return Err(evidence_unusable("conflicting reservation"));
                        }
                    } else if image.records.len() >= MAX_EVIDENCE_ENTRIES {
                        capacity = true;
                    } else {
                        image.records.push(EvidenceRecord {
                            identity,
                            expires_at_ms,
                            digest: [0; 32],
                            generation: 0,
                            sequence: 0,
                            state: RecordState::Reserved,
                        });
                        image.records.sort_by_key(|record| record.identity);
                    }
                    Ok(())
                },
            )
        })();
        let loaded = result.map_err(|error| self.refusal(&error))?;
        if capacity {
            return Err(WalletError::Approval(ApprovalFailure::EvidenceCapacity));
        }
        Ok(EvidenceReservation::new(
            loaded.image.scope,
            identity,
            expires_at_ms,
        ))
    }

    /// Adopts one migration pin as Delivered evidence of `identity`.
    ///
    /// The caller authenticates the identity, the full reference, the scope
    /// association, and the conservative deadline before calling. The pin
    /// whose digest equals the reference's full digest becomes a Delivered
    /// record of the reference's coordinates and `expires_at_ms`, so
    /// occupancy stays the same. An exact retry returns the same reservation.
    /// Adoption reads no approval storage, samples no clock, drains nothing,
    /// and removes no expired record.
    ///
    /// # Errors
    /// Refuses unkeyed, uninitialized, fenced, or unusable evidence, an expiry
    /// at or below the floor, and an identity that holds other facts. Without
    /// a pin of the digest it refuses with `missing migration pin`. At the
    /// last evidence generation an exact retry refuses with
    /// `evidence-generation overflow`. Storage errors retain their codes.
    pub fn adopt_evidence_pin(
        &self,
        identity: [u8; 32],
        reference: &OutboxRowRef,
        expires_at_ms: u64,
    ) -> Result<EvidenceReservation, WalletError> {
        let adopted = EvidenceRecord {
            identity,
            digest: reference.digest,
            expires_at_ms,
            generation: reference.generation,
            sequence: reference.sequence,
            state: RecordState::Delivered,
        };
        let result = (|| {
            let (batch, key) = self.evidence_batch()?;
            batch.commit_evidence_change(
                &self.log_path,
                self.state.as_ref(),
                &key,
                false,
                |image, _| {
                    if expires_at_ms <= image.floor_ms {
                        return Err(evidence_unusable("expired reservation"));
                    }
                    let pin = image.records.iter().position(|record| {
                        record.state == RecordState::LegacyPin && record.digest == reference.digest
                    });
                    // The replaced pin's derived identity may equal `identity`.
                    if let Some(existing) =
                        image.records.iter().enumerate().find(|(index, record)| {
                            record.identity == identity && Some(*index) != pin
                        })
                    {
                        return if *existing.1 == adopted {
                            Ok(())
                        } else {
                            Err(evidence_unusable("conflicting reservation"))
                        };
                    }
                    let pin = pin.ok_or_else(|| evidence_unusable("missing migration pin"))?;
                    image.records[pin] = adopted.clone();
                    image.records.sort_by_key(|record| record.identity);
                    Ok(())
                },
            )
        })();
        let loaded = result.map_err(|error| self.refusal(&error))?;
        Ok(EvidenceReservation::new(
            loaded.image.scope,
            identity,
            expires_at_ms,
        ))
    }

    /// Maps an evidence refusal with the log's file name as its profile field.
    fn refusal(&self, error: &WriterError) -> WalletError {
        super::writer::audit_writer_refusal(&basename(&self.log_path), error)
    }

    /// Carries this reservation into a reference-returning queued append.
    #[must_use]
    pub fn with_evidence_reservation(mut self, reservation: EvidenceReservation) -> Self {
        self.reservation = Some(reservation);
        self
    }

    /// Releases evidence after authenticated revocation or final operation termination.
    /// First consumption and a missing approval record do not authorize release.
    /// Call outside the policy-window lock; retry an interrupted release safely.
    ///
    /// # Errors
    /// Returns carrier, evidence, key, and storage refusals. Migration pins cannot be released.
    pub fn release_evidence(&self, identity: [u8; 32]) -> Result<(), WriterError> {
        let (batch, key) = self.evidence_batch()?;
        batch.commit_evidence_change(
            &self.log_path,
            self.state.as_ref(),
            &key,
            false,
            |image, _| {
                if image.records.iter().any(|record| {
                    record.identity == identity && record.state == RecordState::LegacyPin
                }) {
                    return Err(evidence_unusable("unresolved pin"));
                }
                image.records.retain(|record| record.identity != identity);
                Ok(())
            },
        )?;
        Ok(())
    }

    /// Advances the persistent floor and removes expired records, retaining migration pins.
    /// Authorization uses and mints refresh `max(wall_clock, evidence_floor)`.
    ///
    /// # Errors
    /// Returns carrier, evidence, key, and storage refusals.
    pub fn advance_evidence_floor(&self, now_ms: u64) -> Result<u64, WriterError> {
        let (batch, key) = self.evidence_batch()?;
        let loaded = batch.commit_evidence_change(
            &self.log_path,
            self.state.as_ref(),
            &key,
            false,
            |image, _| {
                image.advance_floor(now_ms);
                Ok(())
            },
        )?;
        Ok(loaded.image.floor_ms)
    }

    /// Reads the authenticated floor, recommitting a newer image before returning it.
    /// Missing or version 1 ownership returns zero only when neither slot exists.
    ///
    /// # Errors
    /// Returns carrier, evidence, key, and storage refusals, including a rotation fence.
    pub fn evidence_time_floor(&self) -> Result<u64, WriterError> {
        Ok(self
            .evidence()?
            .map_or(0, |evidence| evidence.time_floor_ms()))
    }

    /// Reads authenticated evidence through the keyed carrier, recovering a
    /// newer committed image. Absence never initializes an owner.
    ///
    /// # Errors
    /// Returns carrier, evidence, key, and storage refusals.
    pub fn evidence(&self) -> Result<Option<super::OutboxEvidence>, WriterError> {
        let (batch, key) = self.evidence_batch()?;
        read_owner_evidence(&self.log_path, self.state.as_ref(), &batch, Some(&key))
    }

    fn evidence_batch(&self) -> Result<(OutboxBatch, Zeroizing<[u8; 32]>), WriterError> {
        let held = self.key.as_ref().ok_or_else(queued_key_required)?;
        let batch = OutboxBatch::read_locked(&self.log_path, self.state.as_ref())?;
        let key = match first_generation(&parse_lines(&batch.bytes).lines)? {
            Some((g, tag)) => self.generation_key(held, g, &tag)?,
            None => held.clone(),
        };
        Ok((batch, key))
    }

    /// Appends `entry` as one line and syncs it, under the outbox lock.
    ///
    /// `Ok` means the line is durable, and for an unkeyed outbox committed.
    /// For a keyed outbox the file's name is durable too. A refusal before the
    /// first write leaves the outbox unchanged. A later error truncates it back
    /// to its length before the row, unless that truncation fails as well. See
    /// the module documentation.
    ///
    /// # Errors
    ///
    /// - [`WriterError::OutboxBusy`] when the outbox lock stays held.
    /// - [`WriterError::CarrierReplaced`], [`WriterError::CarriersUnbound`] or
    ///   [`WriterError::CarrierIdentityUnavailable`] when the outbox lock file
    ///   is not the recorded one.
    /// - [`WriterError::CarrierGenerationChanged`] when a binding started a
    ///   new generation while the append waited or before its row was synced.
    ///   The row is then not queued.
    /// - [`WriterError::RetiredOutboxChanged`], for an unkeyed outbox, when the
    ///   retired generation's commitment changed after the binding.
    /// - [`WriterError::OutboxRowsMissing`], for an unkeyed outbox, when
    ///   committed rows are lost or changed, a missing file included, or when
    ///   a complete line follows them. The file is neither created nor changed.
    /// - [`WriterError::OutboxUnusable`], for a keyed outbox, when the first
    ///   generation line does not parse, has no reloadable key, or does not
    ///   verify under the held or the reloaded key.
    /// - [`WriterError::OutboxFull`] when the outbox holds [`MAX_OUTBOX_ROWS`]
    ///   rows, and [`WriterError::OutboxRowTooLarge`] when the row exceeds the
    ///   writer's row cap. Neither appends the candidate row.
    /// - [`WriterError::TipAnchorStore`] when the commitment cannot be read or
    ///   stored, or the audit key cannot be reloaded.
    /// - [`WriterError::Serialise`] when the entry cannot be serialized.
    /// - [`WriterError::Io`] on any read, write, flush, or sync failure.
    pub fn append(&self, entry: &AuditEntry) -> Result<(), WriterError> {
        self.prepare_append()?.append(entry)
    }

    /// Queues an evidence-bearing consent row and returns its durable reference.
    ///
    /// After a failed rollback the caller gets the refusal while the row stays
    /// and is delivered later, so a consumer keys on the reference.
    ///
    /// # Errors
    /// Returns [`WriterError::KeyedLogNeedsKey`] before locking an unkeyed outbox.
    /// Other refusals follow [`Self::append`], and return no reference.
    pub fn append_queued(&self, entry: &AuditEntry) -> Result<OutboxRowRef, WriterError> {
        if !self.is_keyed() {
            return Err(queued_key_required());
        }
        self.prepare_append()?.append_queued(entry)
    }

    /// Acquires the outbox lock and loads the state needed for one append.
    pub(crate) fn prepare_append(&self) -> Result<PreparedOutboxAppend<'_>, WriterError> {
        if let Some(parent) = self.path.parent() {
            create_private_dir(parent)?;
        }
        let lock = if self.key.is_some() {
            lock_queue(&self.lock_path, self.state.as_ref())?
        } else {
            lock_outbox(&self.lock_path, self.state.as_ref())?
        };
        self.prepare_append_locked(lock)
    }

    /// Loads the state of one append under an outbox lock already held.
    ///
    /// An unkeyed append uses the commitment of the generation `lock` was
    /// taken under. A keyed append reads no commitment.
    pub(crate) fn prepare_append_locked(
        &self,
        lock: BoundCarrierLock,
    ) -> Result<PreparedOutboxAppend<'_>, WriterError> {
        if let Some(key) = &self.key {
            return self.prepare_keyed(lock, key);
        }
        let state = load_state(self.state.as_ref(), lock.generation())?;
        let (file, bytes) = open_existing_outbox(&self.path)?;
        if file.is_none() && state.pending > 0 {
            return Err(WriterError::OutboxRowsMissing {
                recorded: state.pending,
                found: 0,
            });
        }
        // Recovery can replace a renamed carrier before this data handle opens.
        // Once the handle is open, a matching generation fixes which file it holds.
        lock.check_generation(self.state.as_ref())?;
        // The check reads the bytes as they are: the torn-tail repair would
        // cut a committed line that lost its newline, turning a restorable
        // file into a loss. A complete line past the commitment refuses too,
        // so the commitment below covers exactly the committed lines and this
        // append's own.
        let lines = parse_lines(&bytes).lines;
        check_committed_prefix(&lines, &state)?;
        // Admission counts every queued row, delivered or not, and never
        // evicts one: a full outbox refuses before the approval storage.
        if lines.len() >= MAX_OUTBOX_ROWS {
            return Err(WriterError::OutboxFull {
                queued: lines.len() as u64,
                cap: MAX_OUTBOX_ROWS as u64,
            });
        }
        #[cfg(test)]
        test_seam::run_admitted(&self.path);

        Ok(PreparedOutboxAppend {
            outbox: self,
            file,
            extent: Extent::of(&bytes),
            coordinates: Coordinates::Committed(OutboxState::over(&lines)),
            lock: Arc::new(lock),
        })
    }

    /// Prepares a keyed append under `lock`: reads an existing file, checks
    /// the carrier generation, authenticates a first generation line, and
    /// checks the quota. It writes nothing and reads no commitment or owner
    /// state.
    fn prepare_keyed(
        &self,
        lock: BoundCarrierLock,
        key: &Zeroizing<[u8; 32]>,
    ) -> Result<PreparedOutboxAppend<'_>, WriterError> {
        let (file, bytes) = open_existing_outbox(&self.path)?;
        lock.check_generation(self.state.as_ref())?;
        let lines = parse_lines(&bytes).lines;
        let header = first_generation(&lines)?;
        let (g, key) = match header {
            Some((g, tag)) => (g, self.generation_key(key, g, &tag)?),
            None => (0, key.clone()),
        };
        // The generation line takes neither a quota slot nor a position.
        let rows = lines.len() - usize::from(header.is_some());
        if rows >= MAX_OUTBOX_ROWS {
            return Err(WriterError::OutboxFull {
                queued: rows as u64,
                cap: MAX_OUTBOX_ROWS as u64,
            });
        }
        #[cfg(test)]
        test_seam::run_admitted(&self.path);

        Ok(PreparedOutboxAppend {
            outbox: self,
            file,
            extent: Extent::of(&bytes),
            coordinates: Coordinates::Keyed {
                key,
                g,
                s: rows as u64 + 1,
            },
            lock: Arc::new(lock),
        })
    }

    /// The key that verifies the generation line of queue generation `g`:
    /// the held key, or else the key one reload returns.
    fn generation_key(
        &self,
        held: &Zeroizing<[u8; 32]>,
        g: u64,
        tag: &[u8; 32],
    ) -> Result<Zeroizing<[u8; 32]>, WriterError> {
        if generation_verifies(held, g, tag) {
            return Ok(held.clone());
        }
        let reloaded = reload_stored_key(self.state.as_ref())?
            .ok_or_else(|| tagged_refusal(1, "tagged record without an audit key"))?;
        if !generation_verifies(&reloaded, g, tag) {
            return Err(tagged_refusal(1, "tagged record whose tag does not verify"));
        }
        Ok(reloaded)
    }
}

/// What one prepared append writes and commits.
enum Coordinates {
    /// An unkeyed append: the commitment over the lines already queued, to
    /// which the append adds its line.
    Committed(OutboxState),
    /// A keyed append: the key that tags the row and the row's coordinates.
    Keyed {
        key: Zeroizing<[u8; 32]>,
        g: u64,
        s: u64,
    },
}

/// One append with the outbox lock and its state already acquired.
pub(crate) struct PreparedOutboxAppend<'a> {
    outbox: &'a AuditOutbox,
    /// The open outbox, or `None` when no file exists yet.
    file: Option<File>,
    extent: Extent,
    coordinates: Coordinates,
    /// The outbox lock, held until the append returns; its generation selects
    /// the commitment an unkeyed append stores and is checked again after a
    /// keyed append's sync.
    lock: Arc<BoundCarrierLock>,
}

/// The length of the outbox as preparation read it, and the length up to
/// and including its last newline.
#[derive(Clone, Copy)]
struct Extent {
    len: u64,
    complete: u64,
}

impl Extent {
    fn of(bytes: &[u8]) -> Self {
        let complete = bytes
            .iter()
            .rposition(|&b| b == b'\n')
            .map_or(0, |index| index + 1);
        Self {
            len: bytes.len() as u64,
            complete: complete as u64,
        }
    }
}

impl PreparedOutboxAppend<'_> {
    /// Writes one row while retaining the acquired lock, and commits it for
    /// an unkeyed outbox.
    ///
    /// The row's measure and encoding run before the first write, so their
    /// refusals leave the outbox as preparation found it. The first write
    /// creates a missing file or drops a torn tail.
    pub(crate) fn append(self, entry: &AuditEntry) -> Result<(), WriterError> {
        self.append_row(entry, 0).map(|_| ())
    }

    /// Writes an evidence-bearing row under the acquired lock.
    pub(crate) fn append_queued(self, entry: &AuditEntry) -> Result<OutboxRowRef, WriterError> {
        if !matches!(self.coordinates, Coordinates::Keyed { .. }) {
            return Err(queued_key_required());
        }
        self.append_row(entry, 1)?.ok_or_else(queued_key_required)
    }

    fn append_row(
        mut self,
        entry: &AuditEntry,
        r: u8,
    ) -> Result<Option<OutboxRowRef>, WriterError> {
        #[cfg(test)]
        if test_seam::take_oversized(&self.outbox.path) {
            use super::writer::MAX_ROW_BYTES;
            return Err(WriterError::OutboxRowTooLarge {
                bytes: MAX_ROW_BYTES + 1,
                cap: MAX_ROW_BYTES,
            });
        }
        refuse_undeliverable_row(entry)?;
        let reference = match &self.coordinates {
            Coordinates::Keyed { g, s, .. } if r == 1 => Some(OutboxRowRef {
                generation: *g,
                sequence: *s,
                digest: row_digest(*g, *s, r, entry).map_err(WriterError::Serialise)?,
            }),
            _ => None,
        };
        let mut line = match &self.coordinates {
            Coordinates::Keyed { key, g, s } => encode_tagged_row(key, *g, *s, r, entry),
            Coordinates::Committed(_) => serde_json::to_vec(entry),
        }
        .map_err(WriterError::Serialise)?;
        line.push(b'\n');
        let outbox = self.outbox;
        if let (Some(reservation), Some(reference), Coordinates::Keyed { key, .. }) =
            (&outbox.reservation, &reference, &self.coordinates)
        {
            let (scope, identity, expires_at_ms) = reservation.facts();
            let batch =
                OutboxBatch::read_retained(&outbox.log_path, outbox.state.as_ref(), &self.lock)?;
            batch.commit_evidence_change(
                &outbox.log_path,
                outbox.state.as_ref(),
                key,
                false,
                |image, _| {
                    // A caller can hold a reservation past the expiry GC that
                    // removed its record; the floor names that cause first.
                    if scope != image.scope || expires_at_ms <= image.floor_ms {
                        return Err(evidence_unusable("reservation scope or expiry"));
                    }
                    let record = image
                        .records
                        .iter_mut()
                        .find(|record| record.identity == identity)
                        .ok_or_else(|| evidence_unusable("missing reservation"))?;
                    if record.expires_at_ms != expires_at_ms {
                        return Err(evidence_unusable("conflicting reservation"));
                    }
                    if record.state == RecordState::Delivered && record.digest == reference.digest {
                        return Ok(());
                    }
                    if record.state == RecordState::Queued
                        && record.digest != reference.digest
                        && parse_lines(&batch.bytes)
                            .lines
                            .iter()
                            .filter_map(|line| tagged_layout(line))
                            .any(|row| {
                                layout_digest(row.g, row.s, row.r, row.body) == record.digest
                            })
                    {
                        return Err(evidence_unusable("queued row still present"));
                    }
                    if !matches!(record.state, RecordState::Reserved | RecordState::Queued) {
                        return Err(evidence_unusable("conflicting reservation"));
                    }
                    record.state = RecordState::Queued;
                    record.digest = reference.digest;
                    record.generation = reference.generation;
                    record.sequence = reference.sequence;
                    Ok(())
                },
            )?;
        }
        let (mut file, created) = match self.file.take() {
            Some(file) => (file, false),
            None => {
                let file = open_outbox_0600(&outbox.path)?;
                // A handle opened here is checked as preparation checks its own.
                self.lock.check_generation(outbox.state.as_ref())?;
                (file, true)
            }
        };
        repair_torn_tail(&file, &outbox.path, self.extent)?;
        #[cfg(test)]
        test_seam::run_append_step(&outbox.path, test_seam::AppendStep::Repaired);
        let keyed = matches!(self.coordinates, Coordinates::Keyed { .. });
        let appended = write_line(&mut file, &outbox.path, &line).and_then(|()| {
            #[cfg(test)]
            test_seam::run_append_step(&outbox.path, test_seam::AppendStep::FileSynced);
            // The directory sync makes the file's name durable before the
            // row is acknowledged. An append that created the file needs it,
            // and so does a keyed append after a publication whose own
            // directory sync failed.
            if created || keyed {
                sync_parent_dir(&outbox.path)?;
            }
            #[cfg(test)]
            test_seam::run_append_step(&outbox.path, test_seam::AppendStep::DirectorySynced);
            match &mut self.coordinates {
                Coordinates::Committed(committed) => {
                    committed.push(&line[..line.len() - 1]);
                    outbox
                        .state
                        .store_outbox_state(self.lock.generation(), committed)
                        .map_err(WriterError::TipAnchorStore)
                }
                // A binding that started a new generation after the first
                // check moved this file aside: the row is not in the queue.
                Coordinates::Keyed { .. } => self.lock.check_generation(outbox.state.as_ref()),
            }
        });
        if let Err(error) = appended {
            if let Err(rollback) = roll_back(&file, &outbox.path, self.extent.complete) {
                tracing::error!(
                    outbox = %basename(&outbox.path),
                    error = %rollback,
                    "audit outbox: a refused append could not be truncated back; a line \
                     from the refused operator-row append may remain"
                );
            }
            return Err(error);
        }
        Ok(reference)
    }
}

fn queued_key_required() -> WriterError {
    WriterError::KeyedLogNeedsKey {
        evidence: "a consent row that carries delivery evidence needs the audit key",
    }
}

/// Truncates a refused append's file back to `len`.
fn roll_back(file: &File, path: &Path, len: u64) -> io::Result<()> {
    #[cfg(any(test, feature = "test-helpers"))]
    test_seam::check_sync(path, test_seam::SyncStep::Rollback)?;
    #[cfg(not(any(test, feature = "test-helpers")))]
    let _ = path;
    truncate_in_place(file, len)
}

/// The most rows one outbox holds.
///
/// A queued row counts until a drain clears it. An append to a full outbox
/// refuses with [`WriterError::OutboxFull`] and never evicts a queued row.
pub const MAX_OUTBOX_ROWS: usize = 64;

/// Refuses `entry` with [`WriterError::OutboxRowTooLarge`] when the row a
/// draining writer appends for it would be longer than
/// [`super::writer::MAX_ROW_BYTES`].
///
/// The measure is the writer's own, with an entry tag counted, so every
/// admitted row fits the byte cap of whichever draining writer delivers it.
fn refuse_undeliverable_row(entry: &AuditEntry) -> Result<(), WriterError> {
    let mut measured = entry.clone();
    match super::writer::refuse_oversized_row(&mut measured, true) {
        Err(WriterError::RowTooLarge { bytes, cap }) => {
            Err(WriterError::OutboxRowTooLarge { bytes, cap })
        }
        other => other,
    }
}

/// Opens the outbox for reading and writing, creating it with mode `0600` on
/// Unix. Never `O_APPEND`: an append seeks to the end itself, under the lock.
fn open_outbox_0600(path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(path)
    }
    #[cfg(not(unix))]
    {
        OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)
    }
}

fn create_private_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(dir)
    }
}

/// Syncs the directory holding `path`, so the creation of `path` is durable.
pub(super) fn sync_parent_dir(path: &Path) -> io::Result<()> {
    #[cfg(any(test, feature = "test-helpers"))]
    test_seam::check_sync(path, test_seam::SyncStep::Directory)?;
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        sync_directory(&File::open(parent)?, path)?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Syncs `dir`, the open directory that holds `path`.
///
/// The body is the system call and its test record, so a record of the
/// step is also a record of the call.
#[cfg(unix)]
fn sync_directory(dir: &File, path: &Path) -> io::Result<()> {
    dir.sync_all()?;
    #[cfg(any(test, feature = "test-helpers"))]
    test_seam::record_sync(path, test_seam::SyncStep::Directory);
    #[cfg(not(any(test, feature = "test-helpers")))]
    let _ = path;
    Ok(())
}

/// Truncates `file`, read as `extent`, back to just after its last newline
/// when its final segment has none, and syncs it.
///
/// Such a segment is an append that never returned `Ok`, so nothing relied on
/// it; it is dropped with a `warn`.
fn repair_torn_tail(file: &File, path: &Path, extent: Extent) -> Result<(), WriterError> {
    if extent.len == extent.complete {
        return Ok(());
    }
    tracing::warn!(
        outbox = %basename(path),
        torn_bytes = extent.len - extent.complete,
        "audit outbox: dropping a torn final segment left by an append that never completed"
    );
    truncate_in_place(file, extent.complete)?;
    Ok(())
}

/// Opens an existing outbox for reading and writing and reads it.
///
/// A missing file reads as no bytes and stays missing.
fn open_existing_outbox(path: &Path) -> Result<(Option<File>, Vec<u8>), WriterError> {
    match OpenOptions::new().read(true).write(true).open(path) {
        Ok(mut file) => {
            let bytes = read_all(&mut file)?;
            Ok((Some(file), bytes))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok((None, Vec::new())),
        Err(e) => Err(WriterError::Io(e)),
    }
}

/// Writes `line` at the end of the file, flushes, and syncs it.
fn write_line(file: &mut File, path: &Path, line: &[u8]) -> Result<(), WriterError> {
    file.seek(SeekFrom::End(0))?;
    #[cfg(any(test, feature = "test-helpers"))]
    if let Some(written) = test_seam::take_partial_write(path) {
        let cut = written.min(line.len());
        file.write_all(&line[..cut])?;
        file.flush()?;
        return Err(WriterError::Io(io::Error::other(
            "test fault: partial outbox write",
        )));
    }
    file.write_all(line)?;
    file.flush()?;
    sync_outbox_file(file, path)?;
    Ok(())
}

/// Syncs the data of `file`, the outbox or its replacement at `path`.
///
/// After the fault seam, the body is the system call and its test record,
/// so a record of the step is also a record of the call.
fn sync_outbox_file(file: &File, path: &Path) -> io::Result<()> {
    #[cfg(any(test, feature = "test-helpers"))]
    test_seam::check_sync(path, test_seam::SyncStep::File)?;
    file.sync_data()?;
    #[cfg(any(test, feature = "test-helpers"))]
    test_seam::record_sync(path, test_seam::SyncStep::File);
    #[cfg(not(any(test, feature = "test-helpers")))]
    let _ = path;
    Ok(())
}

/// Renames the replacement at `replacement` over the outbox at `outbox`.
///
/// After the fault seam, the body is the rename and its test record, so a
/// test reads the order of the file sync, the rename and the directory sync.
fn rename_replacement(replacement: &Path, outbox: &Path) -> io::Result<()> {
    #[cfg(any(test, feature = "test-helpers"))]
    test_seam::check_sync(replacement, test_seam::SyncStep::Rename)?;
    fs::rename(replacement, outbox)?;
    #[cfg(any(test, feature = "test-helpers"))]
    test_seam::record_sync(replacement, test_seam::SyncStep::Rename);
    Ok(())
}

/// Truncates `file` to `len` in place and syncs it.
pub(crate) fn truncate_in_place(file: &File, len: u64) -> io::Result<()> {
    file.set_len(len)?;
    file.sync_all()
}

fn read_all(file: &mut File) -> io::Result<Vec<u8>> {
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// The outbox lock an [`OutboxBatch`] holds for its whole life.
enum BatchGuard {
    /// The lock the batch took itself, checked against the carrier record.
    Bound(BoundCarrierLock),
    /// The bound lock a key-rotation writer retains for its whole life. The
    /// batch shares it and checks its generation like a bound lock.
    Retained(Arc<BoundCarrierLock>),
    /// The outbox carrier a recovery writer took at its path. The batch shares
    /// ownership of it, so the carrier stays locked while the batch lives even
    /// when the writer that took it drops first.
    Recovery {
        /// Held only to keep the carrier locked; never read.
        _held: Arc<AuditWriterLock>,
    },
}

/// The raw bytes of an outbox and its commitment, read together under the
/// outbox lock and held under it until the drain either clears the file or
/// drops it unchanged.
pub(crate) struct OutboxBatch {
    /// The outbox lock, held for the batch's whole life.
    _guard: BatchGuard,
    /// The generation whose commitment the batch read.
    generation: u64,
    path: PathBuf,
    file: Option<File>,
    bytes: Vec<u8>,
    state: OutboxState,
    /// The commitment as the store held it, in its keyring form, or the empty
    /// string for an absent entry.
    stored_state: String,
}

impl OutboxBatch {
    /// Takes the outbox lock of the log at `log_path` through the carrier
    /// record, then reads the commitment of the lock's generation from
    /// `store` and the outbox file as it is.
    ///
    /// A missing file reads as no bytes. Nothing is checked or parsed.
    ///
    /// # Errors
    ///
    /// - [`WriterError::OutboxBusy`] when the outbox lock stays held.
    /// - The carrier refusals of [`lock_outbox`], and
    ///   [`WriterError::CarrierGenerationChanged`] when a binding started a
    ///   new generation before the file opened.
    /// - [`WriterError::TipAnchorStore`] when the commitment cannot be read.
    /// - [`WriterError::Io`] when the file cannot be opened or read for a
    ///   reason other than its absence.
    pub(crate) fn read_locked(
        log_path: &Path,
        store: &dyn TipAnchorStore,
    ) -> Result<Self, WriterError> {
        let lock = lock_outbox(&outbox_lock_path(log_path), store)?;
        let generation = lock.generation();
        Self::read_generation(
            outbox_path(log_path),
            store,
            generation,
            BatchGuard::Bound(lock),
        )
    }

    /// Reads the commitment and the outbox file under the bound outbox lock
    /// `held` that a key-rotation writer retains, without acquiring it again.
    ///
    /// # Errors
    ///
    /// [`WriterError::CarrierGenerationChanged`] and
    /// [`WriterError::CarriersUnbound`] when the record does not name the
    /// lock's generation, and the store and I/O errors of
    /// [`Self::read_locked`].
    pub(crate) fn read_retained(
        log_path: &Path,
        store: &dyn TipAnchorStore,
        held: &Arc<BoundCarrierLock>,
    ) -> Result<Self, WriterError> {
        Self::read_generation(
            outbox_path(log_path),
            store,
            held.generation(),
            BatchGuard::Retained(Arc::clone(held)),
        )
    }

    /// Reads the commitment of `generation` and the outbox file under the
    /// outbox carrier a recovery writer holds at its path.
    ///
    /// A recovery writer took the carrier without the record, so the caller
    /// names the generation. The batch keeps `held` locked for its whole life.
    ///
    /// # Errors
    ///
    /// - [`WriterError::TipAnchorStore`] when the commitment cannot be read.
    /// - [`WriterError::Io`] when the file cannot be opened or read for a
    ///   reason other than its absence.
    pub(crate) fn read_for_recovery(
        log_path: &Path,
        store: &dyn TipAnchorStore,
        generation: u64,
        held: &Arc<AuditWriterLock>,
    ) -> Result<Self, WriterError> {
        Self::read_file_for_recovery(&outbox_path(log_path), store, generation, held)
    }

    /// Reads the commitment of `generation` and the queue file at `file`
    /// under the outbox carrier a recovery writer holds at its path.
    ///
    /// A carrier binding reads the rows of the generation it retires from the
    /// retired file once the outbox has been renamed to it, and from the
    /// outbox before that. The batch keeps `held` locked for its whole life.
    ///
    /// # Errors
    ///
    /// - [`WriterError::TipAnchorStore`] when the commitment cannot be read.
    /// - [`WriterError::Io`] when the file cannot be opened or read for a
    ///   reason other than its absence.
    pub(crate) fn read_file_for_recovery(
        file: &Path,
        store: &dyn TipAnchorStore,
        generation: u64,
        held: &Arc<AuditWriterLock>,
    ) -> Result<Self, WriterError> {
        Self::read_generation(
            file.to_path_buf(),
            store,
            generation,
            BatchGuard::Recovery {
                _held: Arc::clone(held),
            },
        )
    }

    fn read_generation(
        path: PathBuf,
        store: &dyn TipAnchorStore,
        generation: u64,
        guard: BatchGuard,
    ) -> Result<Self, WriterError> {
        let stored = store.load_outbox_state(generation)?;
        let stored_state = stored
            .as_ref()
            .map(OutboxState::to_keyring_value)
            .unwrap_or_default();
        let state = stored.unwrap_or_default();
        let mut file = match OpenOptions::new().read(true).write(true).open(&path) {
            Ok(file) => Some(file),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(WriterError::Io(e)),
        };
        // A binding can retire the generation between the lock and the open;
        // a matching generation after the open fixes which file the handle
        // holds.
        match &guard {
            BatchGuard::Bound(lock) => lock.check_generation(store)?,
            BatchGuard::Retained(lock) => lock.check_generation(store)?,
            BatchGuard::Recovery { .. } => {}
        }
        let bytes = file.as_mut().map(read_all).transpose()?.unwrap_or_default();
        Ok(Self {
            _guard: guard,
            generation,
            path,
            file,
            bytes,
            state,
            stored_state,
        })
    }

    /// The generation whose commitment the batch read.
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    /// The selected lines of a valid legacy queue, each verbatim with its
    /// newline, and their number.
    ///
    /// The lines are the committed prefix and the tagged rows after it, each
    /// row authenticated under `key`.
    ///
    /// # Errors
    ///
    /// The errors of the legacy-queue validation: for example
    /// [`WriterError::OutboxRowsMissing`] when the prefix is missing or an
    /// untagged line follows it.
    pub(crate) fn committed_bytes(
        &self,
        key: Option<&[u8; 32]>,
    ) -> Result<(Vec<u8>, u64), WriterError> {
        let lines = parse_lines(&self.bytes).lines;
        validate_legacy_queue(&lines, &self.state, SuffixCheck::Keyed(key))?;
        let mut bytes = Vec::new();
        for line in &lines {
            bytes.extend_from_slice(line);
            bytes.push(b'\n');
        }
        Ok((bytes, lines.len() as u64))
    }

    /// Selects complete source bytes after validating their protected state.
    pub(crate) fn binding_selection(
        &self,
        store: &dyn TipAnchorStore,
        key: Option<&[u8; 32]>,
    ) -> Result<BindingSelection, WriterError> {
        if let Some(owner) = self.owner(store)? {
            let lines = parse_lines(&self.bytes).lines;
            self.select_owner(&lines, owner.clone(), SuffixCheck::Keyed(key), false)?
                .accepted()?;
            let rows = lines.len() as u64 - u64::from(first_generation(&lines)?.is_some());
            let complete = lines.iter().map(|line| line.len() + 1).sum::<usize>();
            return Ok(BindingSelection {
                bytes: self.bytes[..complete].to_vec(),
                rows,
                watch: super::lock::owner_watch(&owner.to_keyring_value(), rows),
                state: StageState::Owner(owner),
            });
        }
        let (bytes, rows) = self.committed_bytes(key)?;
        Ok(BindingSelection {
            bytes,
            rows,
            state: StageState::V1(self.state.clone()),
            watch: self.stored_state.clone(),
        })
    }

    /// Authenticates the evidence image of a binding's source generation, the
    /// generation this batch read, and returns whether it recommitted one.
    ///
    /// A binding holds all three carriers, so the successor state it stages
    /// does not refuse this read. Selection is the ordinary newest-image
    /// selection under the stored key. With `recommit`, a newer image is
    /// committed to the source owner while the record names the source, or
    /// names a staged successor that retires it. Records, floor, and slots
    /// stay unchanged.
    ///
    /// # Errors
    ///
    /// The refusals of an evidence read, and
    /// [`WriterError::CarrierGenerationChanged`] outside those phases.
    pub(crate) fn binding_evidence(
        &self,
        log_path: &Path,
        store: &dyn TipAnchorStore,
        key: Option<&[u8; 32]>,
        recommit: bool,
    ) -> Result<bool, WriterError> {
        let Some(mut loaded) =
            select_owner_evidence(log_path, store, self.owner(store)?, key, false)?
        else {
            return Ok(false);
        };
        if !(recommit && loaded.recommit) {
            return Ok(false);
        }
        commit_owner_evidence(&mut loaded, log_path, store, self.generation, || {
            check_binding_phase(log_path, store, self.generation)
        })?;
        Ok(true)
    }

    /// The path of the file the batch read.
    #[cfg(any(test, feature = "test-helpers"))]
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Reads the outbox under its lock and checks that its complete lines are
    /// exactly the committed prefix.
    ///
    /// `Ok(None)` means there is no outbox file and nothing is committed, so
    /// there is nothing to drain. A torn final segment is left for
    /// [`Self::parse_entries`] to report and [`Self::clear`] to remove.
    ///
    /// # Errors
    ///
    /// - Every error of [`Self::read_locked`].
    /// - Every error of [`Self::checked`].
    #[cfg(test)]
    pub(crate) fn take(
        log_path: &Path,
        store: &dyn TipAnchorStore,
    ) -> Result<Option<Self>, WriterError> {
        Self::read_locked(log_path, store)?.checked()
    }

    /// Checks that the complete lines are exactly the committed prefix, and
    /// returns the batch unless there is no outbox file.
    ///
    /// # Errors
    ///
    /// [`WriterError::OutboxRowsMissing`] when the committed prefix is
    /// missing, changed, or reordered, a missing file under a nonzero
    /// commitment included, or when complete lines follow it. The file is
    /// left unchanged.
    pub(crate) fn checked(self) -> Result<Option<Self>, WriterError> {
        let lines = parse_lines(&self.bytes).lines;
        check_committed_prefix(&lines, &self.state)?;
        if self.file.is_none() {
            return Ok(None);
        }
        Ok(Some(self))
    }

    /// The entries of a batch a drain may already have delivered: under a
    /// zero commitment, every complete line, when there is at least one and
    /// each parses as an [`AuditEntry`].
    ///
    /// A drain resets the commitment after its appends and truncates the
    /// outbox after that, so a crash between the two leaves exactly this
    /// shape. The caller decides whether the entries are the log's last rows.
    pub(crate) fn uncommitted_entries(&self, key: Option<&[u8; 32]>) -> Option<Vec<AuditEntry>> {
        if self.state.pending != 0 {
            return None;
        }
        let lines = parse_lines(&self.bytes).lines;
        if lines.is_empty() {
            return None;
        }
        parse_operator_rows(&lines, key).ok()
    }

    /// The committed prefix as operator rows, when it is intact, or `None`
    /// when committed lines are missing, changed, or reordered.
    ///
    /// # Errors
    ///
    /// Every error of the operator-row parse, for a line of the intact prefix.
    pub(crate) fn committed_entries(
        &self,
        key: Option<&[u8; 32]>,
    ) -> Result<Option<Vec<AuditEntry>>, WriterError> {
        let lines = parse_lines(&self.bytes).lines;
        committed_prefix(&lines, &self.state)
            .map(|prefix| parse_operator_rows(prefix, key))
            .transpose()
    }

    /// The number of complete lines.
    pub(crate) fn complete_lines(&self) -> usize {
        parse_lines(&self.bytes).lines.len()
    }

    /// Whether the checked file has neither complete lines nor a torn tail.
    pub(crate) fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// The loss of committed rows this batch shows, without changing either
    /// the commitment or the file. The caller has checked that no owner
    /// state holds the batch.
    ///
    /// A valid legacy queue shows no loss: its committed prefix followed by
    /// tagged rows authenticated under `key` at their lines. Any other queue
    /// shows the committed count against the complete lines found.
    pub(crate) fn loss(&self, key: Option<&[u8; 32]>) -> Option<OutboxLoss> {
        let lines = parse_lines(&self.bytes).lines;
        validate_unowned_queue(&lines, &self.state, SuffixCheck::Keyed(key))
            .err()
            .map(|_| OutboxLoss {
                expected_rows: self.state.pending,
                found_rows: lines.len() as u64,
            })
    }

    /// Parses every complete line, in queue order, as an operator row before the
    /// caller appends any of them. A torn final segment is discarded with a
    /// `warn`.
    ///
    /// # Errors
    ///
    /// [`WriterError::OutboxUnusable`] when a complete line does not parse as
    /// an [`AuditEntry`], and [`WriterError::OutboxRowKindRefused`] when it
    /// holds a row other than an operator row. The file is left unchanged.
    pub(crate) fn parse_entries(
        &self,
        key: Option<&[u8; 32]>,
    ) -> Result<Vec<AuditEntry>, WriterError> {
        let parsed = parse_lines(&self.bytes);
        if parsed.torn_bytes > 0 {
            tracing::warn!(
                outbox = %basename(&self.path),
                torn_bytes = parsed.torn_bytes,
                "audit outbox: discarding a torn final segment left by an append that never \
                 completed"
            );
        }
        parse_operator_rows(&parsed.lines, key)
    }

    /// Truncates the outbox to zero and syncs it, then releases the lock.
    ///
    /// # Errors
    ///
    /// [`WriterError::Io`] when the truncation or the sync fails.
    pub(crate) fn clear(self) -> Result<(), WriterError> {
        if let Some(file) = self.file {
            truncate_in_place(&file, 0)?;
        }
        Ok(())
    }

    /// Decides the owner delivery of this batch, or `None` for a legacy
    /// queue of untagged lines only, which drains through
    /// [`Self::checked`].
    ///
    /// Without owner state, a queue with any tagged line cuts over. With
    /// owner state, the stored commitment must be absent, zero, or the one
    /// the owner state recorded at cutover, before any row is decoded. Then
    /// the queue generation selects a live drain or the recovery of the
    /// closed generation. Every row to deliver is validated before the
    /// caller appends any.
    ///
    /// # Errors
    ///
    /// - [`WriterError::TipAnchorStore`] when the owner state cannot be read
    ///   or is unusable.
    /// - [`WriterError::OutboxUnusable`] for a changed commitment, an unusable
    ///   generation line or row, and generation overflow.
    /// - [`WriterError::OutboxRowsMissing`] for a changed committed prefix,
    ///   an untagged row where only tagged rows are valid, or a row out of
    ///   place. It also refuses a generation line naming another generation,
    ///   and content at the closed coordinates that the closed batch does
    ///   not commit.
    /// - [`WriterError::OutboxRowKindRefused`] for a row of another kind.
    pub(crate) fn owner_plan(
        &self,
        store: &dyn TipAnchorStore,
        key: Option<&[u8; 32]>,
    ) -> Result<Option<OwnerDelivery>, WriterError> {
        self.owner_plan_loaded(self.owner(store)?, key)
    }

    /// Plans under the carrier using the owner returned by fence recovery.
    pub(crate) fn owner_plan_loaded(
        &self,
        owner: Option<OutboxOwnerState>,
        key: Option<&[u8; 32]>,
    ) -> Result<Option<OwnerDelivery>, WriterError> {
        let lines = parse_lines(&self.bytes).lines;
        match owner {
            None if lines.iter().any(|line| is_tagged(line)) => self.cutover(&lines, key).map(Some),
            None => Ok(None),
            Some(owner) => self
                .select_owner(&lines, owner, SuffixCheck::Keyed(key), false)?
                .accepted()
                .map(Some),
        }
    }

    /// The owner state of this batch's generation, if any.
    fn owner(&self, store: &dyn TipAnchorStore) -> Result<Option<OutboxOwnerState>, WriterError> {
        Ok(store
            .load_outbox_owner_state(self.generation)?
            .map(|raw| OutboxOwnerState::parse(&raw))
            .transpose()?)
    }

    /// The cutover of a legacy queue that holds a tagged line.
    fn cutover(
        &self,
        lines: &[&[u8]],
        key: Option<&[u8; 32]>,
    ) -> Result<OwnerDelivery, WriterError> {
        let prefix =
            committed_prefix(lines, &self.state).ok_or(WriterError::OutboxRowsMissing {
                recorded: self.state.pending,
                found: lines.len() as u64,
            })?;
        let mut rows = Vec::with_capacity(lines.len());
        let mut entries = Vec::with_capacity(lines.len());
        for (index, line) in lines.iter().enumerate() {
            let number = index + 1;
            let decoded = if is_tagged(line) {
                decode_tagged(line, number, SuffixCheck::Keyed(key), 0, number as u64)?
            } else if index < prefix.len() {
                let entry = decode_raw(line, number)?;
                DecodedRow {
                    r: 0,
                    digest: row_digest(0, number as u64, 0, &entry)
                        .map_err(WriterError::Serialise)?,
                    entry,
                }
            } else {
                return Err(WriterError::OutboxRowsMissing {
                    recorded: number as u64,
                    found: 0,
                });
            };
            rows.push((decoded.r, decoded.digest));
            entries.push(decoded.entry);
        }
        let mut owner = OutboxOwnerState::new(
            advance_generation(0)?,
            (!self.stored_state.is_empty()).then_some(&self.state),
        );
        owner.record_delivery(0, &rows);
        Ok(OwnerDelivery {
            publish: Some(owner.g),
            entries,
            owner: Some(owner),
            zero_legacy: true,
            selected: rows,
        })
    }

    /// Selects the authenticated prefix and the first refusal under owner
    /// state.
    /// Recovery counts its closed prefix as delivered and retains its evidence.
    fn select_owner(
        &self,
        lines: &[&[u8]],
        mut owner: OutboxOwnerState,
        check: SuffixCheck<'_>,
        select_loss: bool,
    ) -> Result<OwnerSelection, WriterError> {
        if matches!(check, SuffixCheck::Keyed(None)) {
            return Err(tagged_refusal(1, "tagged record without an audit key"));
        }
        let clean = self.stored_state.is_empty() || self.state == OutboxState::default();
        let zero_legacy =
            !clean && owner.legacy == Some(Sha256::digest(self.stored_state.as_bytes()).into());
        let rewrite = !clean && !zero_legacy;
        if rewrite && !select_loss {
            return Err(tagged_refusal(
                1,
                "legacy outbox state changed in the owner state",
            ));
        }
        let header = match first_generation(lines) {
            Ok(header) => header,
            Err(error) => {
                owner.g = advance_generation(owner.g)?;
                return OwnerSelection::refused(
                    owner,
                    lines.len().saturating_sub(1),
                    !clean,
                    rewrite,
                    error,
                );
            }
        };
        let offset = usize::from(header.is_some());
        let rows = &lines[offset..];
        if let (Some((g, tag)), SuffixCheck::Keyed(Some(key))) = (header, check)
            && !generation_verifies(key, g, &tag)
        {
            // A stopped rotation leaves a lone fence for the next drain.
            if g == owner.g && self.bytes == encode_fence_line(owner.g) && clean {
                return Ok(OwnerSelection {
                    plan: OwnerDelivery::publish_only(owner.g),
                    loss: None,
                    refusal: None,
                    publication_pending: true,
                    rewrite: false,
                });
            }
            owner.g = advance_generation(owner.g)?;
            return OwnerSelection::refused(
                owner,
                rows.len(),
                !clean,
                rewrite,
                tagged_refusal(1, "tagged record whose tag does not verify"),
            );
        }
        let queue = header.map_or(0, |(g, _)| g);
        let closed = owner
            .closed
            .clone()
            .filter(|closed| closed.g == queue && closed.g.checked_add(1) == Some(owner.g));
        let recovery = closed.is_some();
        if !recovery && queue != owner.g {
            owner.g = advance_generation(owner.g)?;
            return OwnerSelection::refused(
                owner,
                rows.len(),
                !clean,
                rewrite,
                WriterError::OutboxRowsMissing {
                    recorded: 0,
                    found: rows.len() as u64,
                },
            );
        }
        let mut digests = Vec::with_capacity(rows.len());
        let delivered = if let Some(closed) = closed {
            let prefix = Self::closed_prefix(rows, offset, check, &closed);
            match prefix {
                Ok(prefix) => {
                    digests = prefix;
                    digests.len()
                }
                Err(error) => {
                    return OwnerSelection::refused(owner, rows.len(), !clean, rewrite, error);
                }
            }
        } else {
            0
        };
        let mut entries = Vec::with_capacity(rows.len() - delivered);
        let mut refusal = None;
        for (index, line) in rows.iter().enumerate().skip(delivered) {
            match owned_row(line, offset + index + 1, check, queue, index + 1) {
                Ok(row) => {
                    digests.push((row.r, row.digest));
                    entries.push(row.entry);
                }
                Err(error @ WriterError::OutboxRowKindRefused { .. }) => return Err(error),
                Err(error) => {
                    refusal = Some(error);
                    break;
                }
            }
        }
        let loss = (rewrite || refusal.is_some()).then_some(OutboxLoss {
            expected_rows: rows.len() as u64,
            found_rows: digests.len() as u64,
        });
        let changes = !entries.is_empty() || loss.is_some();
        let selected = digests.get(delivered..).unwrap_or_default().to_vec();
        if changes {
            if !recovery {
                owner.g = advance_generation(owner.g)?;
            }
            owner.close(queue, &digests, delivered);
        }
        Ok(OwnerSelection {
            plan: OwnerDelivery {
                entries,
                publish: (changes || recovery).then_some(owner.g),
                owner: changes.then_some(owner),
                zero_legacy: !clean,
                selected,
            },
            loss,
            refusal,
            publication_pending: recovery,
            rewrite,
        })
    }

    /// Validates the closed commitment before selecting any later row.
    fn closed_prefix(
        rows: &[&[u8]],
        offset: usize,
        check: SuffixCheck<'_>,
        closed: &ClosedBatch,
    ) -> Result<Vec<(u8, [u8; 32])>, WriterError> {
        let changed = || WriterError::OutboxRowsMissing {
            recorded: closed.n,
            found: rows.len() as u64,
        };
        let delivered = usize::try_from(closed.n)
            .ok()
            .filter(|n| *n <= rows.len())
            .ok_or_else(changed)?;
        let mut digests = Vec::with_capacity(rows.len());
        for (index, line) in rows[..delivered].iter().enumerate() {
            let (number, s) = (offset + index + 1, index as u64 + 1);
            if is_tagged(line) {
                let row = decode_tagged(line, number, check, closed.g, s)?;
                digests.push((row.r, row.digest));
            } else if closed.g == 0 {
                // The closed generation-zero commitment admits raw rows.
                let entry = decode_raw(line, number)?;
                digests.push((
                    0,
                    row_digest(0, s, 0, &entry).map_err(WriterError::Serialise)?,
                ));
            } else {
                return Err(WriterError::OutboxRowsMissing {
                    recorded: s,
                    found: 0,
                });
            }
        }
        if batch_digest(&digests) != closed.batch {
            return Err(changed());
        }
        Ok(digests)
    }

    /// Classifies the owner queue under the caller's held key or keyless check.
    pub(crate) fn owner_selection(
        &self,
        store: &dyn TipAnchorStore,
        check: SuffixCheck<'_>,
    ) -> Result<Option<OwnerSelection>, WriterError> {
        self.owner(store)?
            .map(|owner| self.select_owner(&parse_lines(&self.bytes).lines, owner, check, true))
            .transpose()
    }

    /// Validates evidence before loss classification permits caller revocation.
    pub(crate) fn prepare_delivery_evidence(
        &self,
        log_path: &Path,
        store: &dyn TipAnchorStore,
        key: Option<&[u8; 32]>,
    ) -> Result<bool, WriterError> {
        match key {
            Some(key) => Ok(self
                .evidence_for_change(log_path, store, key, false, true)?
                .is_some()),
            None => Ok(read_owner_evidence(log_path, store, self, key)?.is_some()),
        }
    }

    /// Authenticates a loss plan before revocation or acknowledgement writes.
    pub(crate) fn evidence_owner_selection(
        &self,
        log_path: &Path,
        store: &dyn TipAnchorStore,
        key: Option<&[u8; 32]>,
    ) -> Result<Option<OwnerSelection>, WriterError> {
        let selection = self.owner_selection(store, SuffixCheck::Keyed(key))?;
        if selection.as_ref().is_some_and(|selection| {
            selection.plan.has_consent()
                || (selection.loss.is_some()
                    && selection
                        .plan
                        .owner
                        .as_ref()
                        .is_some_and(|owner| owner.e.is_some()))
        }) {
            self.prepare_delivery_evidence(log_path, store, key)?;
            return self.owner_selection(store, SuffixCheck::Keyed(key));
        }
        Ok(selection)
    }

    /// Commits matching queued records and the closed batch after anchoring.
    pub(crate) fn commit_delivery(
        &self,
        log_path: &Path,
        store: &dyn TipAnchorStore,
        key: Option<&[u8; 32]>,
        plan: &OwnerDelivery,
    ) -> Result<(), WriterError> {
        let Some(owner) = &plan.owner else {
            return Ok(());
        };
        if plan.has_consent()
            && owner.e.is_some()
            && self.owner(store)?.is_some_and(|owner| owner.e.is_some())
        {
            let key = key.ok_or_else(queued_key_required)?;
            self.commit_evidence_change(log_path, store, key, false, |image, current| {
                for record in &mut image.records {
                    if record.state == RecordState::Queued
                        && plan
                            .selected
                            .iter()
                            .any(|(r, digest)| *r == 1 && *digest == record.digest)
                    {
                        record.state = RecordState::Delivered;
                    }
                }
                let evidence = current.e;
                *current = owner.clone();
                current.e = evidence;
                Ok(())
            })?;
        } else {
            store.store_outbox_owner_state(self.generation, &owner.to_keyring_value())?;
        }
        Ok(())
    }

    /// The generation line a key change publishes in place of a queue that
    /// holds no row.
    ///
    /// An owned queue qualifies when it holds only the generation line of
    /// the owned generation. A queue without owner state qualifies when it
    /// holds no line under an absent or zero commitment. The target then
    /// carries new owner state of generation one, which the caller stores
    /// before it publishes. Its closed batch is the empty batch of generation
    /// zero, so a drain delivers a row queued before the line is published.
    /// Any other queue has no target.
    ///
    /// # Errors
    ///
    /// [`WriterError::TipAnchorStore`] when the owner state cannot be read or
    /// is unusable, and [`WriterError::OutboxUnusable`] for a first line
    /// that is an unusable generation line.
    pub(crate) fn key_change_target(
        &self,
        store: &dyn TipAnchorStore,
    ) -> Result<Option<KeyChangeTarget>, WriterError> {
        let lines = parse_lines(&self.bytes).lines;
        match self.owner(store)? {
            Some(owner) => Ok(match first_generation(&lines)? {
                Some((g, _)) if g == owner.g && lines.len() == 1 => Some(KeyChangeTarget {
                    owner: None,
                    generation: g,
                }),
                _ => None,
            }),
            None if lines.is_empty() && self.state == OutboxState::default() => {
                let mut owner = OutboxOwnerState::new(
                    advance_generation(0)?,
                    (!self.stored_state.is_empty()).then_some(&self.state),
                );
                owner.record_delivery(0, &[]);
                Ok(Some(KeyChangeTarget {
                    generation: owner.g,
                    owner: Some(owner),
                }))
            }
            None => Ok(None),
        }
    }

    /// Publishes the fence line of generation `g` in place of the queue, as
    /// [`Self::publish`] publishes a generation line.
    ///
    /// # Errors
    ///
    /// The errors of [`Self::publish`].
    pub(crate) fn publish_fence(
        self,
        g: u64,
        store: &dyn TipAnchorStore,
    ) -> Result<(), WriterError> {
        self.publish_line(&encode_fence_line(g), store)
    }

    /// Publishes generation line `g` under `key` in place of the queue.
    ///
    /// Removes a leftover replacement, then writes and syncs a new one in the
    /// audit directory. Checks that the carrier record still names the
    /// batch's generation, renames the replacement over the outbox, and syncs
    /// the directory. The rename never runs through a stale generation.
    ///
    /// # Errors
    ///
    /// - [`WriterError::CarriersUnbound`] when the record is gone, and
    ///   [`WriterError::CarrierGenerationChanged`] when it names another
    ///   generation. The queue is unchanged.
    /// - [`WriterError::TipAnchorStore`] when the record cannot be read.
    /// - [`WriterError::Io`] when a file operation or sync fails.
    pub(crate) fn publish(
        self,
        key: &[u8; 32],
        g: u64,
        store: &dyn TipAnchorStore,
    ) -> Result<(), WriterError> {
        self.publish_line(&encode_generation_line(key, g), store)
    }

    fn publish_line(mut self, line: &[u8], store: &dyn TipAnchorStore) -> Result<(), WriterError> {
        let replacement = replacement_path(&self.path);
        #[cfg(any(test, feature = "test-helpers"))]
        test_seam::check_sync(&replacement, test_seam::SyncStep::Remove)?;
        match fs::remove_file(&replacement) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(WriterError::Io(e)),
        }
        #[cfg(any(test, feature = "test-helpers"))]
        test_seam::check_sync(&replacement, test_seam::SyncStep::Create)?;
        let mut file = create_replacement_0600(&replacement)?;
        write_line(&mut file, &replacement, line)?;
        drop(file);
        #[cfg(any(test, feature = "test-helpers"))]
        test_seam::check_stop(&self.path, test_seam::Stop::ReplacementSynced)?;
        #[cfg(test)]
        test_seam::run_replacement_synced(&self.path);
        self.check_generation(store)?;
        drop(self.file.take());
        rename_replacement(&replacement, &self.path)?;
        #[cfg(any(test, feature = "test-helpers"))]
        test_seam::check_stop(&self.path, test_seam::Stop::Renamed)?;
        sync_parent_dir(&replacement)?;
        #[cfg(any(test, feature = "test-helpers"))]
        test_seam::check_stop(&self.path, test_seam::Stop::DirectorySynced)?;
        Ok(())
    }
}

/// Decodes a row of owned queue generation `g` at position `s`, physical
/// line `number`: only a tagged row is valid there.
fn owned_row(
    line: &[u8],
    number: usize,
    check: SuffixCheck<'_>,
    g: u64,
    s: usize,
) -> Result<DecodedRow, WriterError> {
    if !is_tagged(line) {
        return Err(WriterError::OutboxRowsMissing {
            recorded: s as u64,
            found: 0,
        });
    }
    decode_tagged(line, number, check, g, s as u64)
}

/// The shared owner verdict and its acknowledgement plan.
pub(crate) struct OwnerSelection {
    pub(crate) plan: OwnerDelivery,
    pub(crate) loss: Option<OutboxLoss>,
    refusal: Option<WriterError>,
    publication_pending: bool,
    rewrite: bool,
}

impl OwnerSelection {
    fn refused(
        owner: OutboxOwnerState,
        expected: usize,
        legacy_present: bool,
        rewrite: bool,
        error: WriterError,
    ) -> Result<Self, WriterError> {
        if !matches!(
            error,
            WriterError::OutboxUnusable { .. } | WriterError::OutboxRowsMissing { .. }
        ) {
            return Err(error);
        }
        Ok(Self {
            plan: OwnerDelivery {
                entries: Vec::new(),
                publish: Some(owner.g),
                owner: Some(owner),
                zero_legacy: legacy_present,
                selected: Vec::new(),
            },
            loss: Some(OutboxLoss {
                expected_rows: expected as u64,
                found_rows: 0,
            }),
            refusal: Some(error),
            publication_pending: false,
            rewrite,
        })
    }

    fn accepted(self) -> Result<OwnerDelivery, WriterError> {
        if self.rewrite {
            return Err(tagged_refusal(
                1,
                "legacy outbox state changed in the owner state",
            ));
        }
        match self.refusal {
            Some(error) => Err(error),
            None => Ok(self.plan),
        }
    }
}

/// The protected state copied with a binding's selected bytes.
pub(crate) enum StageState {
    V1(OutboxState),
    Owner(OutboxOwnerState),
}

/// Fully validated source bytes and the state that interprets them.
pub(crate) struct BindingSelection {
    pub(crate) bytes: Vec<u8>,
    pub(crate) rows: u64,
    state: StageState,
    pub(crate) watch: String,
}

impl BindingSelection {
    /// The empty selection after a legacy batch's delivery is recognized.
    pub(crate) fn empty_legacy() -> Self {
        let state = OutboxState::default();
        Self {
            bytes: Vec::new(),
            rows: 0,
            watch: state.to_keyring_value(),
            state: StageState::V1(state),
        }
    }

    /// Checks that the successor stores the selected descriptor.
    ///
    /// # Errors
    ///
    /// Returns a store error when the successor state cannot be read.
    pub(crate) fn matches_stored(
        &self,
        store: &dyn TipAnchorStore,
        generation: u64,
    ) -> Result<bool, WriterError> {
        Ok(match &self.state {
            StageState::V1(state) => {
                store.load_outbox_state(generation)?.unwrap_or_default() == *state
            }
            StageState::Owner(owner) => {
                store.load_outbox_owner_state(generation)? == Some(owner.to_keyring_value())
            }
        })
    }

    /// Stores the selected state without converting its representation.
    pub(crate) fn store(
        &self,
        store: &dyn TipAnchorStore,
        generation: u64,
    ) -> Result<(), WriterError> {
        match &self.state {
            StageState::V1(state) => store.store_outbox_state(generation, state)?,
            StageState::Owner(owner) => {
                store.store_outbox_owner_state(generation, &owner.to_keyring_value())?
            }
        }
        Ok(())
    }
}

/// What one owner drain delivers and commits.
///
/// In order: the entries appended to the log, the owner state stored after
/// the anchor covers them, the zero commitment, and the published
/// generation line.
pub(crate) struct OwnerDelivery {
    /// The rows to append, in queue order.
    pub(crate) entries: Vec<AuditEntry>,
    /// The owner state to store, or `None` when it stays unchanged.
    owner: Option<OutboxOwnerState>,
    /// Whether the commitment the owner state recorded at cutover is zeroed.
    pub(crate) zero_legacy: bool,
    /// The generation line to publish, or `None` when the queue stays.
    pub(crate) publish: Option<u64>,
    /// Newly selected flags and full digests, excluding the closed prefix.
    selected: Vec<(u8, [u8; 32])>,
}

impl OwnerDelivery {
    fn publish_only(g: u64) -> Self {
        Self {
            entries: Vec::new(),
            owner: None,
            zero_legacy: false,
            publish: Some(g),
            selected: Vec::new(),
        }
    }

    /// Whether newly selected rows require authenticated evidence selection.
    pub(crate) fn has_consent(&self) -> bool {
        self.selected.iter().any(|(r, _)| *r == 1)
    }

    /// The owner value to store, in its keyring form.
    pub(crate) fn owner_value(&self) -> Option<String> {
        self.owner.as_ref().map(OutboxOwnerState::to_keyring_value)
    }
}

/// What a key change publishes: the generation of its line, and the owner
/// state to store first when the queue has none.
pub(crate) struct KeyChangeTarget {
    owner: Option<OutboxOwnerState>,
    /// The generation of the line to publish.
    pub(crate) generation: u64,
}

impl KeyChangeTarget {
    /// The owner state to store before the publication, in its keyring form.
    pub(crate) fn owner_value(&self) -> Option<String> {
        self.owner.as_ref().map(OutboxOwnerState::to_keyring_value)
    }
}

/// What an evidence initialization of one batch did.
pub(crate) enum EvidenceInit {
    /// The owner commits evidence.
    Done,
    /// A v1 owner was migrated; its queue still drains.
    Migrated,
    /// The queue holds rows and has no owner state; a drain runs first.
    NeedsDrain,
    /// Both slots hold the initial image; the caller delivers the rows of
    /// this batch, and the delivery stores the evidence owner.
    Deliver(Box<(OutboxBatch, OwnerDelivery)>),
}

impl OutboxBatch {
    /// Initializes consent evidence under this batch's carrier.
    ///
    /// A v2 owner runs the authenticated read. A v1 owner migrates its recent
    /// digests into pins. An empty queue without owner state gets the owner
    /// of generation one and its published generation line. Both slots hold
    /// the initial image, written and synced, before the owner is stored.
    ///
    /// `retry` marks the attempt after a preliminary drain: a queue without
    /// owner state then takes the validated cutover instead of another drain.
    pub(crate) fn initialize_evidence(
        self,
        log_path: &Path,
        store: &dyn TipAnchorStore,
        key: &[u8; 32],
        retry: bool,
    ) -> Result<EvidenceInit, WriterError> {
        check_no_incomplete_binding(log_path, store, self.generation)?;
        let (owner, publish) = match self.owner(store)? {
            Some(owner) if owner.e.is_some() => {
                read_owner_evidence(log_path, store, &self, Some(key))?;
                return Ok(EvidenceInit::Done);
            }
            Some(owner) => (owner, None),
            None => {
                // Slots beside no owner are either the initial image an
                // interrupted initialization left, or a refusal before any
                // drain can write.
                let initial = EvidenceImage::initial(store.outbox_evidence_scope()?, Vec::new());
                let slot = initial.seal(key);
                let interrupted = consent_evidence::any_slot_exists(log_path)?;
                if interrupted {
                    initial_slots_pending(log_path, &slot)?;
                }
                match self.key_change_target(store)? {
                    Some(KeyChangeTarget {
                        owner: Some(owner),
                        generation,
                    }) => (owner, Some(generation)),
                    // Rows queued after an interrupted initialization, or
                    // after the preliminary drain of a retry, take the
                    // cutover: it validates the committed legacy prefix and
                    // every tagged row, and the delivery appends them in
                    // file order before it stores the evidence owner.
                    _ if interrupted || retry => {
                        let mut plan = self
                            .cutover(&parse_lines(&self.bytes).lines, Some(key))
                            .map_err(|error| match error {
                                WriterError::OutboxRowsMissing { .. }
                                | WriterError::OutboxUnusable { .. }
                                | WriterError::OutboxRowKindRefused { .. } => {
                                    evidence_unusable("queue not drained")
                                }
                                other => other,
                            })?;
                        write_initial_slots(log_path, &slot)?;
                        let head = consent_evidence::head(&slot);
                        plan.owner = plan
                            .owner
                            .map(|owner| owner.with_evidence(initial.generation, head));
                        return Ok(EvidenceInit::Deliver(Box::new((self, plan))));
                    }
                    _ => return Ok(EvidenceInit::NeedsDrain),
                }
            }
        };
        let image = EvidenceImage::initial(store.outbox_evidence_scope()?, owner.migration_pins());
        let slot = image.seal(key);
        write_initial_slots(log_path, &slot)?;
        let next = owner.with_evidence(image.generation, consent_evidence::head(&slot));
        store_owner_confirmed(store, self.generation, &next.to_keyring_value())?;
        #[cfg(any(test, feature = "test-helpers"))]
        test_seam::check_stop(&self.path, test_seam::Stop::OwnerStored)?;
        match publish {
            Some(generation) => {
                self.publish(key, generation, store)?;
                Ok(EvidenceInit::Done)
            }
            None => Ok(EvidenceInit::Migrated),
        }
    }

    /// Checks that the carrier record still names this batch's generation.
    pub(crate) fn check_generation(&self, store: &dyn TipAnchorStore) -> Result<(), WriterError> {
        match &self._guard {
            BatchGuard::Bound(lock) => lock.check_generation(store),
            BatchGuard::Retained(lock) => lock.check_generation(store),
            BatchGuard::Recovery { .. } => {
                let current = store
                    .load_carrier_record()?
                    .ok_or(WriterError::CarriersUnbound)?
                    .generation;
                if current != self.generation {
                    return Err(WriterError::CarrierGenerationChanged {
                        held: self.generation,
                        current,
                    });
                }
                Ok(())
            }
        }
    }
}

fn evidence_unusable(reason: &'static str) -> WriterError {
    WriterError::OutboxEvidenceUnusable { reason }
}

/// Refuses while a binding is incomplete: a staged generation exists beside
/// the log, or owner state waits at the next carrier generation.
fn check_no_incomplete_binding(
    log_path: &Path,
    store: &dyn TipAnchorStore,
    carrier_generation: u64,
) -> Result<(), WriterError> {
    let staged = !super::carriers::staged_files(log_path)?.is_empty();
    let successor = match carrier_generation.checked_add(1) {
        Some(next) => store.load_outbox_owner_state(next)?.is_some(),
        None => false,
    };
    if staged || successor {
        return Err(WriterError::CarrierRecoveryRequired {
            detail: WriterError::CarrierBindingIncomplete.to_string(),
        });
    }
    Ok(())
}

/// Checks that `source` is still a binding's source: the record names it, or
/// names a staged successor whose retired entry is `source`.
fn check_binding_phase(
    log_path: &Path,
    store: &dyn TipAnchorStore,
    source: u64,
) -> Result<(), WriterError> {
    let record = store.load_carrier_record()?;
    let current = record.as_ref().map_or(0, |record| record.generation);
    if current == source {
        return Ok(());
    }
    if let Some(record) = &record
        && record
            .retired
            .as_ref()
            .is_some_and(|retired| retired.generation == source)
        && super::carriers::generation_path(log_path, current).try_exists()?
    {
        return Ok(());
    }
    Err(WriterError::CarrierGenerationChanged {
        held: source,
        current,
    })
}

/// Stores `value` as the owner state of `carrier_generation`. A failed store
/// is resolved by a reread: the value read back decides the outcome.
fn store_owner_confirmed(
    store: &dyn TipAnchorStore,
    carrier_generation: u64,
    value: &str,
) -> Result<(), WriterError> {
    match store.store_outbox_owner_state(carrier_generation, value) {
        Ok(()) => Ok(()),
        Err(error) => match store.load_outbox_owner_state(carrier_generation)? {
            Some(actual) if actual == value => Ok(()),
            _ => Err(error.into()),
        },
    }
}

/// Writes the initial image into each slot that lacks it.
///
/// Every slot is checked before any write. A missing slot is created new, and
/// a prefix of the image, left by an interrupted write, is completed. Each is
/// written in full, synced, and its directory synced. Any other content
/// refuses with nothing written.
fn write_initial_slots(log_path: &Path, slot: &[u8]) -> Result<(), WriterError> {
    for (path, create) in initial_slots_pending(log_path, slot)? {
        let mut options = OpenOptions::new();
        options.write(true);
        if create {
            options.create_new(true);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options.open(&path)?;
        file.write_all(slot)?;
        sync_outbox_file(&file, &path)?;
        sync_parent_dir(&path)?;
    }
    Ok(())
}

/// Classifies both slots against the initial image without writing: each
/// missing slot, with `true`, and each prefix of the image, with `false`.
///
/// # Errors
///
/// [`WriterError::OutboxEvidenceUnusable`] with `evidence image without
/// owner` for any other content.
fn initial_slots_pending(
    log_path: &Path,
    slot: &[u8],
) -> Result<Vec<(PathBuf, bool)>, WriterError> {
    let mut pending = Vec::with_capacity(2);
    for path in consent_evidence::slot_paths(log_path) {
        match consent_evidence::read_slot(&path)? {
            None => pending.push((path, true)),
            Some(existing) if slot.starts_with(&existing) => pending.push((path, false)),
            Some(_) => return Err(evidence_unusable("evidence image without owner")),
        }
    }
    Ok(pending)
}

/// One selected image and its owner, loaded under the carrier.
pub(super) struct LoadedEvidence {
    owner: OutboxOwnerState,
    image: EvidenceImage,
    bytes: Vec<u8>,
    index: usize,
    recommit: bool,
}

/// Loads the owner of `carrier_generation` and both slots, and selects,
/// outside any binding.
fn load_owner_evidence(
    log_path: &Path,
    store: &dyn TipAnchorStore,
    carrier_generation: u64,
    key: Option<&[u8; 32]>,
    fenced: bool,
) -> Result<Option<LoadedEvidence>, WriterError> {
    check_no_incomplete_binding(log_path, store, carrier_generation)?;
    let owner = store
        .load_outbox_owner_state(carrier_generation)?
        .map(|raw| OutboxOwnerState::parse(&raw))
        .transpose()?;
    select_owner_evidence(log_path, store, owner, key, fenced)
}

/// Reads both slots and selects the evidence `owner` commits.
fn select_owner_evidence(
    log_path: &Path,
    store: &dyn TipAnchorStore,
    owner: Option<OutboxOwnerState>,
    key: Option<&[u8; 32]>,
    fenced: bool,
) -> Result<Option<LoadedEvidence>, WriterError> {
    let Some((owner, committed)) = owner.and_then(|owner| owner.e.map(|e| (owner, e))) else {
        if consent_evidence::any_slot_exists(log_path)? {
            return Err(evidence_unusable("evidence image without owner"));
        }
        return Ok(None);
    };
    let key = key.ok_or(WriterError::KeyedLogNeedsKey {
        evidence: "the owner state commits consent evidence",
    })?;
    let scope = store.outbox_evidence_scope()?;
    let paths = consent_evidence::slot_paths(log_path);
    let slots = [
        consent_evidence::read_slot(&paths[0])?,
        consent_evidence::read_slot(&paths[1])?,
    ];
    #[cfg(test)]
    test_seam::run_evidence_loaded(log_path);
    let (image, head, recommit) =
        match consent_evidence::select(&slots, committed.g, &committed.head, &scope, key) {
            Ok(Selected::Current(image)) => (image, committed.head, false),
            Ok(Selected::Newer { image, head }) => {
                if fenced
                    && (image.predecessor != committed.head
                        || committed.g.checked_add(1) != Some(image.generation))
                {
                    return Err(evidence_unusable("head"));
                }
                (image, head, true)
            }
            Err(reason) if fenced => {
                let image = slots.iter().flatten().find_map(|bytes| {
                    if consent_evidence::head(bytes) != committed.head {
                        return None;
                    }
                    consent_evidence::decode_layout(bytes)
                        .ok()
                        .filter(|image| image.generation == committed.g && image.scope == scope)
                });
                (
                    image.ok_or_else(|| evidence_unusable(reason))?,
                    committed.head,
                    false,
                )
            }
            Err(reason) => return Err(evidence_unusable(reason)),
        };
    let index = slots
        .iter()
        .position(|slot| {
            slot.as_ref()
                .is_some_and(|bytes| consent_evidence::head(bytes) == head)
        })
        .ok_or_else(|| evidence_unusable("head"))?;
    let bytes = slots
        .into_iter()
        .nth(index)
        .flatten()
        .ok_or_else(|| evidence_unusable("missing image"))?;
    Ok(Some(LoadedEvidence {
        owner,
        image,
        bytes,
        index,
        recommit,
    }))
}

/// Syncs a complete candidate before its owner store.
fn sync_evidence_slot(path: &Path) -> Result<(), WriterError> {
    let file = OpenOptions::new().read(true).write(true).open(path)?;
    sync_outbox_file(&file, path)?;
    sync_parent_dir(path)?;
    Ok(())
}

/// Writes only the inactive slot, including its file and directory syncs.
fn write_evidence_slot(path: &Path, bytes: &[u8]) -> Result<(), WriterError> {
    #[cfg(any(test, feature = "test-helpers"))]
    test_seam::check_sync(path, test_seam::SyncStep::Create)?;
    let mut file = create_replacement_0600(path)?;
    #[cfg(any(test, feature = "test-helpers"))]
    if let Some(count) = test_seam::take_partial_write(path) {
        file.write_all(&bytes[..count.min(bytes.len())])?;
        return Err(io::Error::other("test fault: partial evidence write").into());
    }
    file.write_all(bytes)?;
    sync_outbox_file(&file, path)?;
    sync_parent_dir(path)?;
    #[cfg(test)]
    test_seam::run_replacement_synced(path);
    Ok(())
}

/// Checked before a successor write and before a mutation's recommit.
fn next_evidence_generation(image: &EvidenceImage) -> Result<u64, WriterError> {
    image
        .generation
        .checked_add(1)
        .ok_or_else(|| evidence_unusable("evidence-generation overflow"))
}

/// Recommits a synced image before returning facts or transforming records.
fn commit_owner_evidence(
    loaded: &mut LoadedEvidence,
    log_path: &Path,
    store: &dyn TipAnchorStore,
    carrier_generation: u64,
    check: impl Fn() -> Result<(), WriterError>,
) -> Result<(), WriterError> {
    if loaded.recommit {
        sync_evidence_slot(&consent_evidence::slot_paths(log_path)[loaded.index])?;
        let next = loaded.owner.clone().with_evidence(
            loaded.image.generation,
            consent_evidence::head(&loaded.bytes),
        );
        check()?;
        store_owner_confirmed(store, carrier_generation, &next.to_keyring_value())?;
        loaded.owner = next;
        loaded.recommit = false;
        #[cfg(any(test, feature = "test-helpers"))]
        test_seam::check_stop(&outbox_path(log_path), test_seam::Stop::EvidenceRecommitted)?;
    }
    check()
}

impl OutboxBatch {
    /// Loads and commits the selected image before a mutation.
    fn evidence_for_change(
        &self,
        log_path: &Path,
        store: &dyn TipAnchorStore,
        key: &[u8; 32],
        fenced: bool,
        advance: bool,
    ) -> Result<Option<LoadedEvidence>, WriterError> {
        let Some(mut loaded) =
            load_owner_evidence(log_path, store, self.generation, Some(key), fenced)?
        else {
            return Ok(None);
        };
        if advance {
            next_evidence_generation(&loaded.image)?;
        }
        commit_owner_evidence(&mut loaded, log_path, store, self.generation, || {
            self.check_generation(store)
        })?;
        Ok(Some(loaded))
    }

    /// The shared successor transaction for records, floor, and owner fields.
    pub(super) fn commit_evidence_change(
        &self,
        log_path: &Path,
        store: &dyn TipAnchorStore,
        key: &[u8; 32],
        fenced: bool,
        transform: impl FnOnce(&mut EvidenceImage, &mut OutboxOwnerState) -> Result<(), WriterError>,
    ) -> Result<LoadedEvidence, WriterError> {
        let mut loaded = self
            .evidence_for_change(log_path, store, key, fenced, !fenced)?
            .ok_or_else(|| evidence_unusable("evidence not initialized"))?;
        if fenced && consent_evidence::tag_verifies(&loaded.bytes, key) {
            return Ok(loaded);
        }
        let generation = next_evidence_generation(&loaded.image)?;
        let predecessor = consent_evidence::head(&loaded.bytes);
        let original = (loaded.image.clone(), loaded.owner.clone());
        transform(&mut loaded.image, &mut loaded.owner)?;
        if !fenced && original.0 == loaded.image {
            if original.1 != loaded.owner {
                self.check_generation(store)?;
                store_owner_confirmed(store, self.generation, &loaded.owner.to_keyring_value())?;
            }
            return Ok(loaded);
        }
        loaded.image.generation = generation;
        loaded.image.predecessor = predecessor;
        loaded.bytes = loaded.image.seal(key);
        consent_evidence::decode(&loaded.bytes, key).map_err(evidence_unusable)?;
        loaded.index = 1 - loaded.index;
        write_evidence_slot(
            &consent_evidence::slot_paths(log_path)[loaded.index],
            &loaded.bytes,
        )?;
        #[cfg(any(test, feature = "test-helpers"))]
        test_seam::check_stop(&self.path, test_seam::Stop::EvidenceCandidateSynced)?;
        loaded.owner = loaded
            .owner
            .with_evidence(generation, consent_evidence::head(&loaded.bytes));
        self.check_generation(store)?;
        store_owner_confirmed(store, self.generation, &loaded.owner.to_keyring_value())?;
        #[cfg(any(test, feature = "test-helpers"))]
        test_seam::check_stop(&self.path, test_seam::Stop::EvidenceOwnerStored)?;
        self.check_generation(store)?;
        Ok(loaded)
    }

    /// Publishes the fence, then preserves the selected image in both slots.
    pub(crate) fn fence_key_change(
        self,
        log_path: &Path,
        store: &dyn TipAnchorStore,
        key: &[u8; 32],
    ) -> Result<(), WriterError> {
        let selected = self.evidence_for_change(log_path, store, key, false, true)?;
        let target = self
            .key_change_target(store)?
            .ok_or_else(|| tagged_refusal(1, "queue not drained before a key change"))?;
        if let Some(ref loaded) = selected
            && self.bytes != encode_generation_line(key, loaded.owner.g)
        {
            return Err(tagged_refusal(1, "queue not drained before a key change"));
        }
        if let Some(owner) = target.owner_value() {
            self.check_generation(store)?;
            store_owner_confirmed(store, self.generation, &owner)?;
            #[cfg(any(test, feature = "test-helpers"))]
            test_seam::check_stop(&self.path, test_seam::Stop::OwnerStored)?;
        }
        self.publish_fence(target.generation, store)?;
        if let Some(loaded) = selected {
            write_evidence_slot(
                &consent_evidence::slot_paths(log_path)[1 - loaded.index],
                &loaded.bytes,
            )?;
        }
        Ok(())
    }

    /// Repairs evidence only while the exact owned fence protects the queue.
    pub(crate) fn recover_evidence_fence(
        &self,
        log_path: &Path,
        store: &dyn TipAnchorStore,
        key: Option<&[u8; 32]>,
        required: bool,
    ) -> Result<Option<OutboxOwnerState>, WriterError> {
        let current = self.owner(store)?;
        let owner = match current {
            Some(owner) if owner.e.is_some() => owner,
            _ => {
                if required && consent_evidence::any_slot_exists(log_path)? {
                    return Err(evidence_unusable("evidence image without owner"));
                }
                return Ok(current);
            }
        };
        if self.bytes != encode_fence_line(owner.g) || self.state != OutboxState::default() {
            return if required {
                Err(evidence_unusable("queue not drained"))
            } else {
                Ok(Some(owner))
            };
        }
        let key = key.ok_or(WriterError::KeyedLogNeedsKey {
            evidence: "the owner state commits consent evidence",
        })?;
        let loaded = self.commit_evidence_change(log_path, store, key, true, |_, _| Ok(()))?;
        let paths = consent_evidence::slot_paths(log_path);
        let other = 1 - loaded.index;
        if consent_evidence::read_slot(&paths[other])?.as_deref() != Some(loaded.bytes.as_slice()) {
            write_evidence_slot(&paths[other], &loaded.bytes)?;
        } else {
            // Equal bytes can follow an interrupted sync, so both files sync.
            sync_evidence_slot(&paths[other])?;
        }
        sync_evidence_slot(&paths[loaded.index])?;
        for path in paths {
            let bytes = consent_evidence::read_slot(&path)?
                .ok_or_else(|| evidence_unusable("missing image"))?;
            consent_evidence::decode(&bytes, key).map_err(evidence_unusable)?;
            if bytes != loaded.bytes {
                return Err(evidence_unusable("head"));
            }
        }
        #[cfg(any(test, feature = "test-helpers"))]
        test_seam::check_stop(&self.path, test_seam::Stop::EvidenceCopiesSynced)?;
        self.check_generation(store)?;
        Ok(Some(loaded.owner))
    }
}

/// The consent evidence the owner of `carrier_generation` commits, read
/// under the active outbox carrier the caller holds.
///
/// `Ok(None)` means no owner commits evidence and neither slot exists. A
/// newer authenticated image is recommitted before it is returned.
///
/// # Errors
///
/// - [`WriterError::CarrierRecoveryRequired`] while a binding is incomplete.
/// - [`WriterError::OutboxEvidenceUnusable`] with its static reason.
/// - [`WriterError::KeyedLogNeedsKey`] for a v2 owner without the key.
/// - [`WriterError::TipAnchorStore`] and [`WriterError::Io`] for the store
///   and the files.
pub(crate) fn read_owner_evidence(
    log_path: &Path,
    store: &dyn TipAnchorStore,
    batch: &OutboxBatch,
    key: Option<&[u8; 32]>,
) -> Result<Option<OutboxEvidence>, WriterError> {
    let Some(mut loaded) = load_owner_evidence(log_path, store, batch.generation, key, false)?
    else {
        return Ok(None);
    };
    commit_owner_evidence(&mut loaded, log_path, store, batch.generation, || {
        batch.check_generation(store)
    })?;
    Ok(Some(loaded.image.into()))
}

/// [`read_owner_evidence`] under the outbox carrier this call acquires.
/// Every load follows the acquisition.
///
/// # Errors
///
/// The errors of [`lock_outbox`] and [`read_owner_evidence`].
pub(crate) fn locked_owner_evidence(
    log_path: &Path,
    store: &dyn TipAnchorStore,
    key: Option<&[u8; 32]>,
) -> Result<Option<OutboxEvidence>, WriterError> {
    let lock = lock_outbox(&outbox_lock_path(log_path), store)?;
    let generation = lock.generation();
    let Some(mut loaded) = load_owner_evidence(log_path, store, generation, key, false)? else {
        return Ok(None);
    };
    commit_owner_evidence(&mut loaded, log_path, store, generation, || {
        lock.check_generation(store)
    })?;
    lock.check_generation(store)?;
    Ok(Some(loaded.image.into()))
}

/// Drains consent rows, then requires exact Delivered membership in the committed image.
/// Callers hold their writer mutex across this call. A missing reference requires
/// authenticated direct or ended provenance and still requires an evidence owner.
///
/// # Errors
/// Returns the drain or evidence refusal unchanged through `audit_writer_refusal`.
/// A membership miss returns `approval.consent_undelivered` with the supplied coordinates.
pub fn require_consent_delivered(
    writer: &mut super::AuditWriter,
    identity: &[u8; 32],
    reference: Option<&OutboxRowRef>,
    profile: &str,
) -> Result<u64, WalletError> {
    let refusal = |error| super::writer::audit_writer_refusal(profile, &error);
    writer.drain_outbox().map_err(refusal)?;
    #[cfg(any(test, feature = "test-helpers"))]
    test_seam::before_delivery_query(writer.path());
    let evidence = writer
        .outbox_evidence()
        .map_err(refusal)?
        .ok_or_else(|| refusal(evidence_unusable("evidence owner is absent")))?;
    if let Some(reference) = reference
        && !evidence.contains_delivered(identity, reference)
    {
        return Err(WalletError::Approval(ApprovalFailure::ConsentUndelivered {
            generation: reference.generation(),
            sequence: reference.sequence(),
        }));
    }
    Ok(evidence.time_floor_ms())
}

/// Returns `<outbox>.next`, the replacement a publication writes.
fn replacement_path(outbox: &Path) -> PathBuf {
    let mut name = outbox.as_os_str().to_os_string();
    name.push(".next");
    PathBuf::from(name)
}

/// Creates the replacement at `path`, truncated, with mode `0600` on Unix.
fn create_replacement_0600(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path)
}

/// The class of a parse failure, from a closed set that carries none of the
/// parsed input.
///
/// The parser's own message can quote the line, for example an unknown
/// variant's name or a whole string placed in a typed field.
fn parse_failure_class(e: &serde_json::Error) -> &'static str {
    match e.classify() {
        serde_json::error::Category::Data => "JSON that is not an audit entry",
        serde_json::error::Category::Eof => "truncated JSON",
        serde_json::error::Category::Syntax | serde_json::error::Category::Io => "invalid JSON",
    }
}

/// Complete lines and the size of the torn final segment of an outbox.
struct ParsedLines<'a> {
    lines: Vec<&'a [u8]>,
    torn_bytes: usize,
}

fn parse_lines(bytes: &[u8]) -> ParsedLines<'_> {
    let complete_end = bytes
        .iter()
        .rposition(|&b| b == b'\n')
        .map_or(0, |idx| idx + 1);
    let (complete, torn) = bytes.split_at(complete_end);
    let lines = complete
        .split_inclusive(|&b| b == b'\n')
        .map(|line| line.strip_suffix(b"\n").unwrap_or(line))
        .collect();
    ParsedLines {
        lines,
        torn_bytes: torn.len(),
    }
}

/// Informational outbox counts and parse warnings, read separately from the
/// locked commitment check.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct OutboxInspection {
    /// Number of complete lines excluding a correctly laid-out first generation header.
    pub pending: usize,
    /// Size of a final segment with no terminating newline, or zero.
    pub torn_bytes: usize,
    /// One-based numbers of complete lines that fail entry deserialization
    /// or tagged layout and canonical-body checks.
    pub unparseable_lines: Vec<usize>,
}

/// Inspects the outbox of the log at `log_path` without taking its lock.
///
/// Tagged rows receive layout and canonical-body checks only. Inspection never
/// authenticates tags or checks coordinates, row kinds, or the commitment.
/// Untagged rows receive only the entry deserialization check.
/// A valid first generation header is excluded from pending rows without authentication.
///
/// A missing outbox reports nothing pending. The result describes the file
/// as read and may already be stale when it returns: a drain or an append in
/// another process can run concurrently.
///
/// # Errors
///
/// [`io::Error`] when the outbox exists and cannot be read.
pub fn inspect_outbox(log_path: &Path) -> io::Result<OutboxInspection> {
    let bytes = match fs::read(outbox_path(log_path)) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(OutboxInspection::default()),
        Err(e) => return Err(e),
    };
    let parsed = parse_lines(&bytes);
    let unparseable_lines = parsed
        .lines
        .iter()
        .enumerate()
        .filter(|(index, line)| {
            match generation_at(line, index + 1) {
                Ok(Some(_)) => return false,
                Err(_) => return true,
                Ok(None) => {}
            }
            if is_tagged(line) {
                tagged_layout(line)
                    .and_then(|row| canonical_entry(row.body, index + 1).ok())
                    .is_none()
            } else {
                serde_json::from_slice::<AuditEntry>(line).is_err()
            }
        })
        .map(|(index, _)| index + 1)
        .collect();
    Ok(OutboxInspection {
        pending: parsed.lines.len()
            - usize::from(
                parsed
                    .lines
                    .first()
                    .is_some_and(|line| generation_layout(line).is_some()),
            ),
        torn_bytes: parsed.torn_bytes,
        unparseable_lines,
    })
}

/// Test-only codec adapters and append fault injection.
///
/// Append faults are keyed by the outbox path so parallel tests stay isolated.
#[cfg(any(test, feature = "test-helpers"))]
pub mod test_seam {
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    /// Creates owner evidence for a cutover state.
    pub fn owner_value(g: u64, legacy: Option<&super::OutboxState>) -> String {
        super::OutboxOwnerState::new(g, legacy).to_keyring_value()
    }

    /// Records a delivered batch in an owner value.
    ///
    /// # Errors
    /// Returns an error for an unusable owner value.
    pub fn owner_after_delivery(
        raw: &str,
        g: u64,
        rows: &[(u8, [u8; 32])],
    ) -> Result<String, super::TipAnchorStoreError> {
        let mut owner = super::OutboxOwnerState::parse(raw)?;
        owner.record_delivery(g, rows);
        Ok(owner.to_keyring_value())
    }

    /// Reads the evidence flag and digest of a canonically encoded row.
    ///
    /// # Errors
    /// Returns an error for invalid layout or body bytes.
    pub fn delivered_row_digest(line: &[u8]) -> Result<(u8, [u8; 32]), super::WriterError> {
        let row = super::tagged_layout(line)
            .ok_or_else(|| super::tagged_refusal(1, "tagged record that does not parse"))?;
        let entry = super::canonical_entry(row.body, 1)?;
        Ok((row.r, super::row_digest(row.g, row.s, row.r, &entry)?))
    }

    /// Encodes a generation header, including its newline.
    pub fn generation_line(key: &[u8; 32], g: u64) -> Vec<u8> {
        super::encode_generation_line(key, g)
    }

    /// Encodes the key-change fence line of generation `g`, including its
    /// newline.
    pub fn fence_line(g: u64) -> Vec<u8> {
        super::encode_fence_line(g)
    }

    /// Encodes `entry` as a tagged row at queue coordinates `(g, s)` with
    /// evidence flag `r`, tagged under `key`, without its newline.
    ///
    /// # Errors
    /// Returns an error when the entry cannot be serialized.
    pub fn tagged_row(
        key: &[u8; 32],
        g: u64,
        s: u64,
        r: u8,
        entry: &crate::audit_log::AuditEntry,
    ) -> Result<Vec<u8>, serde_json::Error> {
        super::encode_tagged_row(key, g, s, r, entry)
    }

    /// Authenticates generation headers in complete lines without newlines.
    ///
    /// # Errors
    /// Returns an error for invalid layout, placement, or authentication.
    pub fn queue_generation(
        lines: &[&[u8]],
        key: Option<&[u8; 32]>,
    ) -> Result<u64, super::WriterError> {
        super::authenticated_generation(lines, key)
    }

    /// Checks the next queue generation before mutation.
    ///
    /// # Errors
    /// Returns an error when the generation overflows.
    pub fn next_generation(g: u64) -> Result<u64, super::WriterError> {
        super::advance_generation(g)
    }

    static PARTIAL_WRITES: Mutex<Vec<(PathBuf, usize)>> = Mutex::new(Vec::new());

    type DeliveryHook = Box<dyn FnOnce() + Send>;
    static DELIVERY_QUERY: Mutex<Vec<(PathBuf, DeliveryHook)>> = Mutex::new(Vec::new());

    /// Removes an unused path-scoped query hook on drop.
    #[derive(Debug)]
    pub struct DeliveryQueryGuard(PathBuf);

    impl Drop for DeliveryQueryGuard {
        fn drop(&mut self) {
            DELIVERY_QUERY
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .retain(|(path, _)| path != &self.0);
        }
    }

    /// Writes two distinct authenticated candidates at the same newer generation.
    ///
    /// # Errors
    /// Returns slot I/O, decoding or generation overflow failures.
    pub fn conflicting_evidence(log_path: &Path, key: &[u8; 32]) -> Result<(), super::WriterError> {
        let paths = super::consent_evidence::slot_paths(log_path);
        let bytes = std::fs::read(&paths[0])?;
        let mut image =
            super::consent_evidence::decode(&bytes, key).map_err(super::evidence_unusable)?;
        image.generation = image
            .generation
            .checked_add(10)
            .ok_or_else(|| super::evidence_unusable("evidence-generation overflow"))?;
        std::fs::write(&paths[0], image.seal(key))?;
        image.floor_ms = image.floor_ms.saturating_add(1);
        std::fs::write(&paths[1], image.seal(key))?;
        Ok(())
    }

    /// Runs once between a successful consumer drain and its evidence query.
    #[must_use]
    pub fn on_delivery_query(
        path: &Path,
        hook: impl FnOnce() + Send + 'static,
    ) -> DeliveryQueryGuard {
        DELIVERY_QUERY
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push((path.to_owned(), Box::new(hook)));
        DeliveryQueryGuard(path.to_owned())
    }

    pub(super) fn before_delivery_query(path: &Path) {
        let hook = {
            let mut hooks = DELIVERY_QUERY
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            hooks
                .iter()
                .position(|(p, _)| p == path)
                .map(|index| hooks.remove(index).1)
        };
        if let Some(hook) = hook {
            hook();
        }
    }

    /// The file operation whose next call refuses.
    ///
    /// Append faults are keyed by the outbox path, and the faults of a
    /// publication by its replacement path, `<log>.outbox.next`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum SyncStep {
        /// The written file's data sync.
        File,
        /// The parent directory sync after a creation or a rename.
        Directory,
        /// The truncation that rolls a refused append back.
        Rollback,
        /// The removal of a leftover replacement.
        Remove,
        /// The creation of the replacement.
        Create,
        /// The rename of the replacement over the outbox.
        Rename,
    }

    /// A point of the drain protocol at which a drain stops with an error,
    /// as a crash there would.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Stop {
        /// After the loss acknowledgement row is appended.
        Acknowledged,
        /// Before the first append of a delivery.
        BeforeAppends,
        /// After the given number of appends, counted from one.
        AfterAppend(usize),
        /// After the anchor check that follows the appends.
        AnchorChecked,
        /// After the owner state is stored.
        OwnerStored,
        /// After the zero commitment is stored.
        LegacyZeroed,
        /// After the replacement is written and synced.
        ReplacementSynced,
        /// After the replacement is renamed over the outbox.
        Renamed,
        /// After the directory sync that ends a publication.
        DirectorySynced,
        /// After an evidence read stores the owner of a newer image.
        EvidenceRecommitted,
        /// After a successor slot and its directory sync.
        EvidenceCandidateSynced,
        /// After the successor owner is confirmed, before its second copy.
        EvidenceOwnerStored,
        /// After both evidence copies sync, before the queue reopens.
        EvidenceCopiesSynced,
    }

    static STOPS: Mutex<Vec<(PathBuf, Stop)>> = Mutex::new(Vec::new());

    /// Stops the next drain of the outbox at `outbox_path` at `stop`,
    /// consuming this arm.
    pub fn arm_stop(outbox_path: &Path, stop: Stop) {
        if let Ok(mut armed) = STOPS.lock() {
            armed.retain(|(path, _)| path != outbox_path);
            armed.push((outbox_path.to_path_buf(), stop));
        }
    }

    pub(crate) fn check_stop(outbox_path: &Path, stop: Stop) -> std::io::Result<()> {
        let hit = STOPS.lock().is_ok_and(|mut armed| {
            armed
                .iter()
                .position(|(p, s)| p == outbox_path && *s == stop)
                .map(|index| armed.swap_remove(index))
                .is_some()
        });
        if hit {
            return Err(std::io::Error::other("test stop: outbox drain protocol"));
        }
        Ok(())
    }

    static SYNC_FAILURES: Mutex<Vec<(PathBuf, SyncStep)>> = Mutex::new(Vec::new());

    /// Fails the next matching sync for `outbox_path`, consuming this arm.
    /// Arms for other steps of the same path stay.
    pub fn arm_sync_failure(outbox_path: &Path, step: SyncStep) {
        if let Ok(mut armed) = SYNC_FAILURES.lock() {
            armed.retain(|(path, armed_step)| path != outbox_path || *armed_step != step);
            armed.push((outbox_path.to_path_buf(), step));
        }
    }

    pub(super) fn check_sync(path: &Path, step: SyncStep) -> std::io::Result<()> {
        let fail = SYNC_FAILURES.lock().is_ok_and(|mut armed| {
            armed
                .iter()
                .position(|(p, s)| p == path && *s == step)
                .map(|index| armed.swap_remove(index))
                .is_some()
        });
        if fail {
            return Err(std::io::Error::other("test fault: outbox sync"));
        }
        Ok(())
    }

    static RECORDED_SYNCS: Mutex<Vec<(PathBuf, Vec<SyncStep>)>> = Mutex::new(Vec::new());

    /// Starts recording the file syncs, renames and directory syncs that
    /// complete for `path`, discarding an earlier recording for it.
    pub fn record_syncs(path: &Path) {
        if let Ok(mut recorded) = RECORDED_SYNCS.lock() {
            recorded.retain(|(recorded_path, _)| recorded_path != path);
            recorded.push((path.to_path_buf(), Vec::new()));
        }
    }

    /// Stops recording for `path` and returns its completed syncs in order.
    pub fn take_syncs(path: &Path) -> Vec<SyncStep> {
        RECORDED_SYNCS.lock().map_or_else(
            |_| Vec::new(),
            |mut recorded| {
                recorded
                    .iter()
                    .position(|(recorded_path, _)| recorded_path == path)
                    .map(|index| recorded.swap_remove(index).1)
                    .unwrap_or_default()
            },
        )
    }

    /// Notes a step of `path` that returned `Ok`. Only the helper that makes
    /// the step's system call calls this, after that call, so a removed call
    /// site leaves no record.
    pub(super) fn record_sync(path: &Path, step: SyncStep) {
        if let Ok(mut recorded) = RECORDED_SYNCS.lock()
            && let Some((_, steps)) = recorded
                .iter_mut()
                .find(|(recorded_path, _)| recorded_path == path)
        {
            steps.push(step);
        }
    }

    /// Arms the seam for `outbox_path`: the next append to that outbox writes
    /// `bytes` bytes of its line and returns an I/O error. The arm is consumed
    /// by that append.
    pub fn arm_partial_write(outbox_path: &Path, bytes: usize) {
        if let Ok(mut armed) = PARTIAL_WRITES.lock() {
            armed.retain(|(path, _)| path != outbox_path);
            armed.push((outbox_path.to_path_buf(), bytes));
        }
    }

    /// Disarms the seam for `outbox_path`. Arms on other outboxes stay.
    pub fn disarm(outbox_path: &Path) {
        if let Ok(mut armed) = PARTIAL_WRITES.lock() {
            armed.retain(|(path, _)| path != outbox_path);
        }
    }

    pub(super) fn take_partial_write(path: &Path) -> Option<usize> {
        let mut armed = PARTIAL_WRITES.lock().ok()?;
        let index = armed
            .iter()
            .position(|(armed_path, _)| armed_path == path)?;
        Some(armed.swap_remove(index).1)
    }

    /// Outboxes whose next append refuses its row as oversized.
    #[cfg(test)]
    static OVERSIZED: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

    /// Arms the seam for `outbox_path`: its next append refuses with
    /// [`super::WriterError::OutboxRowTooLarge`] before writing, as a row over
    /// the byte cap does. The arm is consumed by that append.
    #[cfg(test)]
    pub(crate) fn arm_oversized(outbox_path: &Path) {
        if let Ok(mut armed) = OVERSIZED.lock() {
            armed.push(outbox_path.to_path_buf());
        }
    }

    #[cfg(test)]
    pub(super) fn take_oversized(path: &Path) -> bool {
        OVERSIZED.lock().is_ok_and(|mut armed| {
            armed
                .iter()
                .position(|armed_path| armed_path == path)
                .map(|index| armed.swap_remove(index))
                .is_some()
        })
    }

    /// A hook one append runs once, keyed by a path.
    #[cfg(test)]
    type Hook = Box<dyn FnOnce() + Send>;

    #[cfg(test)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum AppendStep {
        Repaired,
        FileSynced,
        DirectorySynced,
    }

    #[cfg(test)]
    static APPEND_STEPS: Mutex<Vec<(PathBuf, AppendStep, Hook)>> = Mutex::new(Vec::new());

    #[cfg(test)]
    pub(crate) fn on_append_step(
        path: &Path,
        step: AppendStep,
        hook: impl FnOnce() + Send + 'static,
    ) {
        if let Ok(mut hooks) = APPEND_STEPS.lock() {
            hooks.push((path.to_path_buf(), step, Box::new(hook)));
        }
    }

    #[cfg(test)]
    pub(super) fn run_append_step(path: &Path, step: AppendStep) {
        let hook = APPEND_STEPS.lock().ok().and_then(|mut hooks| {
            let index = hooks.iter().position(|(p, s, _)| p == path && *s == step)?;
            Some(hooks.swap_remove(index).2)
        });
        if let Some(hook) = hook {
            hook();
        }
    }

    /// Hooks run by the next admission of an append to an outbox.
    #[cfg(test)]
    static ADMITTED: Mutex<Vec<(PathBuf, Hook)>> = Mutex::new(Vec::new());

    #[cfg(test)]
    static REPLACEMENT_SYNCED: Mutex<Vec<(PathBuf, Hook)>> = Mutex::new(Vec::new());

    /// Runs a callback after the replacement sync and before the generation
    /// check.
    #[cfg(test)]
    pub(crate) fn on_replacement_synced(outbox_path: &Path, hook: impl FnOnce() + Send + 'static) {
        if let Ok(mut armed) = REPLACEMENT_SYNCED.lock() {
            armed.push((outbox_path.to_path_buf(), Box::new(hook)));
        }
    }

    #[cfg(test)]
    pub(super) fn run_replacement_synced(outbox_path: &Path) {
        run(&REPLACEMENT_SYNCED, outbox_path);
    }

    /// Hooks run by the first contended attempt on an outbox lock.
    #[cfg(test)]
    static CONTENDED: Mutex<Vec<(PathBuf, Hook)>> = Mutex::new(Vec::new());

    /// Runs `hook` once, under the outbox lock, after the next append to
    /// `outbox_path` passes its admission checks.
    #[cfg(test)]
    pub(crate) fn on_admitted(outbox_path: &Path, hook: impl FnOnce() + Send + 'static) {
        if let Ok(mut armed) = ADMITTED.lock() {
            armed.push((outbox_path.to_path_buf(), Box::new(hook)));
        }
    }

    /// Runs `hook` once when an acquisition of the lock at `lock_path` first
    /// finds it held.
    #[cfg(test)]
    pub(crate) fn on_contended(lock_path: &Path, hook: impl FnOnce() + Send + 'static) {
        if let Ok(mut armed) = CONTENDED.lock() {
            armed.push((lock_path.to_path_buf(), Box::new(hook)));
        }
    }

    #[cfg(test)]
    fn run(hooks: &Mutex<Vec<(PathBuf, Hook)>>, path: &Path) {
        let hook = hooks.lock().ok().and_then(|mut armed| {
            let index = armed
                .iter()
                .position(|(armed_path, _)| armed_path == path)?;
            Some(armed.swap_remove(index).1)
        });
        if let Some(hook) = hook {
            hook();
        }
    }

    #[cfg(test)]
    pub(super) fn run_admitted(outbox_path: &Path) {
        run(&ADMITTED, outbox_path);
    }

    #[cfg(test)]
    pub(super) fn run_contended(lock_path: &Path) {
        run(&CONTENDED, lock_path);
    }

    /// Hooks run by the next evidence read of a log after its loads.
    #[cfg(test)]
    static EVIDENCE_LOADED: Mutex<Vec<(PathBuf, Hook)>> = Mutex::new(Vec::new());

    /// Runs `hook` once, under the outbox carrier, after the next evidence
    /// read of the log at `log_path` loads the owner and both slots.
    #[cfg(test)]
    pub(crate) fn on_evidence_loaded(log_path: &Path, hook: impl FnOnce() + Send + 'static) {
        if let Ok(mut armed) = EVIDENCE_LOADED.lock() {
            armed.push((log_path.to_path_buf(), Box::new(hook)));
        }
    }

    #[cfg(test)]
    pub(super) fn run_evidence_loaded(log_path: &Path) {
        run(&EVIDENCE_LOADED, log_path);
    }

    /// Hooks run between the preliminary drain of an evidence initialization
    /// and its retry, with no carrier held.
    #[cfg(test)]
    static INITIALIZATION_RETRY: Mutex<Vec<(PathBuf, Hook)>> = Mutex::new(Vec::new());

    /// Runs `hook` once before the next initialization retry of the log at
    /// `log_path`.
    #[cfg(test)]
    pub(crate) fn on_initialization_retry(log_path: &Path, hook: impl FnOnce() + Send + 'static) {
        if let Ok(mut armed) = INITIALIZATION_RETRY.lock() {
            armed.push((log_path.to_path_buf(), Box::new(hook)));
        }
    }

    #[cfg(test)]
    pub(crate) fn run_initialization_retry(log_path: &Path) {
        run(&INITIALIZATION_RETRY, log_path);
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only"
    )]

    use std::sync::Arc;

    use tempfile::TempDir;
    use zeroize::Zeroizing;

    use super::*;
    use crate::audit_log::entry::NewToolInvocation;
    use crate::audit_log::schema::PolicyDecision;
    use crate::audit_log::tip_anchor::{InMemoryTipAnchorStore, KeyedAuditAccess, TipAnchorStore};
    use crate::audit_log::writer::{AuditWriter, AuditWriterRegistry};

    fn bound_store(path: &Path) -> Arc<InMemoryTipAnchorStore> {
        let store = Arc::new(InMemoryTipAnchorStore::new());
        drop(open_draining(path, &store));
        store
    }

    const ROW_KEY: [u8; 32] = [0x42; 32];
    const VECTOR_BODY: &str = r#"{"ts":"2026-01-01T00:00:00.000Z","tool":"approval.attested","arg_keys":[],"policy_decision":"allow","request_id":"vector","kind":"approval_attested","approval_kind":"PaymentSimulated","gated_tool":"stellar_pay_commit","nonce_prefix":"ABCDEFGH","origin":"cli","previous_entry_hash":""}"#;

    fn fixed_row() -> AuditEntry {
        let mut entry = row("vector");
        entry.ts = "2026-01-01T00:00:00.000Z".to_owned();
        entry
    }

    fn keyed_fixture() -> (TempDir, PathBuf, Arc<InMemoryTipAnchorStore>, AuditWriter) {
        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);
        let store = Arc::new(InMemoryTipAnchorStore::new());
        let writer = AuditWriter::open(
            path.clone(),
            Some(KeyedAuditAccess::new(
                Zeroizing::new(ROW_KEY),
                store.clone(),
            )),
        )
        .unwrap();
        (dir, path, store, writer)
    }

    fn keyed_outbox(path: &Path, store: &Arc<InMemoryTipAnchorStore>) -> AuditOutbox {
        AuditOutbox::for_log_keyed(path, store.clone(), Zeroizing::new(ROW_KEY))
    }

    #[test]
    fn queued_append_recovers_each_durable_boundary() {
        use test_seam::AppendStep;
        for step in [
            AppendStep::Repaired,
            AppendStep::FileSynced,
            AppendStep::DirectorySynced,
        ] {
            let (_dir, path, store, writer) = keyed_fixture();
            let outbox = keyed_outbox(&path, &store);
            fs::write(outbox.path(), b"{\"torn\"").unwrap();
            test_seam::on_append_step(outbox.path(), step, || panic!("test crash: queued append"));
            let stopped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                outbox.append_queued(&row("crash"))
            }));
            assert!(
                stopped.is_err(),
                "the append stops before returning a reference: {step:?}"
            );
            let expected = usize::from(step != AppendStep::Repaired);
            assert_eq!(parse_lines(&outbox_bytes(&path)).lines.len(), expected);
            drop(writer);
            let mut restarted = reopen(&path, &store);
            assert_eq!(delivered(&path, "crash"), expected);
            assert_eq!(restarted.drain_outbox().unwrap(), 0);
            outbox.append_queued(&row("retry")).unwrap();
            assert_eq!(restarted.drain_outbox().unwrap(), 1);
            assert_eq!(delivered(&path, "retry"), 1);
        }
    }

    #[cfg(unix)]
    #[test]
    fn queued_append_process() {
        use std::io::{BufRead as _, BufReader, Read as _, Write as _};
        use std::os::unix::net::UnixStream;
        let Ok(log) = std::env::var("QUEUED_TEST_LOG") else {
            return;
        };
        let path = PathBuf::from(log);
        let state = Arc::new(InMemoryTipAnchorStore::new());
        let record = crate::audit_log::tip_anchor::CarrierRecord::parse(
            &std::env::var("QUEUED_TEST_RECORD").unwrap(),
        )
        .unwrap();
        state.store_carrier_record(&record).unwrap();
        let mut stream = UnixStream::connect(std::env::var("QUEUED_TEST_SOCKET").unwrap()).unwrap();
        let mut waiting = stream.try_clone().unwrap();
        test_seam::on_contended(&outbox_lock_path(&path), move || {
            waiting.write_all(b"waiting\n").unwrap();
            let mut release = [0];
            waiting.read_exact(&mut release).unwrap();
        });
        let reference = keyed_outbox(&path, &state)
            .append_queued(&row(&std::env::var("QUEUED_TEST_ID").unwrap()))
            .unwrap();
        writeln!(stream, "{}", serde_json::to_string(&reference).unwrap()).unwrap();
        let mut acknowledgement = String::new();
        BufReader::new(stream)
            .read_line(&mut acknowledgement)
            .unwrap();
        assert_eq!(acknowledgement, "received\n");
    }

    #[cfg(unix)]
    #[test]
    fn two_processes_queue_distinct_references() {
        use std::io::{BufRead as _, BufReader, Write as _};
        use std::os::unix::net::UnixListener;
        let (dir, path, store, mut writer) = keyed_fixture();
        let socket = dir.path().join("queue.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let record = store
            .load_carrier_record()
            .unwrap()
            .unwrap()
            .to_keyring_value()
            .unwrap();
        let outbox = keyed_outbox(&path, &store);
        let held = outbox.prepare_append().unwrap();
        let mut children = Vec::new();
        for id in ["first", "second"] {
            children.push(
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "audit_log::outbox::tests::queued_append_process",
                        "--nocapture",
                    ])
                    .env("QUEUED_TEST_LOG", &path)
                    .env("QUEUED_TEST_RECORD", &record)
                    .env("QUEUED_TEST_SOCKET", &socket)
                    .env("QUEUED_TEST_ID", id)
                    .env(OUTBOX_LOCK_WAIT_ENV, "30000")
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                    .unwrap(),
            );
        }
        let mut streams = Vec::new();
        for _ in 0..2 {
            let mut stream = BufReader::new(listener.accept().unwrap().0);
            let mut state = String::new();
            stream.read_line(&mut state).unwrap();
            assert_eq!(state, "waiting\n");
            streams.push(stream);
        }
        drop(held);
        for stream in &mut streams {
            stream.get_mut().write_all(&[1]).unwrap();
        }
        let mut references = Vec::new();
        for mut stream in streams {
            let mut wire = String::new();
            stream.read_line(&mut wire).unwrap();
            references.push(serde_json::from_str::<OutboxRowRef>(&wire).unwrap());
            stream.get_mut().write_all(b"received\n").unwrap();
        }
        for child in children {
            let output = child.wait_with_output().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        references.sort_by_key(OutboxRowRef::sequence);
        assert_eq!(
            references
                .iter()
                .map(OutboxRowRef::sequence)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(writer.drain_outbox().unwrap(), 2);
        assert_eq!(delivered(&path, "first"), 1);
        assert_eq!(delivered(&path, "second"), 1);
        assert_eq!(
            owner_state(&store).unwrap().recent,
            references.iter().map(|r| *r.digest()).collect::<Vec<_>>()
        );
    }

    fn reference_wire(g: u64, s: u64) -> String {
        format!(
            r#"{{"g":{g},"s":{s},"digest":"sha256:{}"}}"#,
            "ab".repeat(32)
        )
    }

    #[test]
    fn outbox_row_reference_keeps_its_wire_bytes() {
        for (g, s) in [(0, 0), (3, 7), (u64::MAX, u64::MAX)] {
            let wire = reference_wire(g, s);
            let reference: OutboxRowRef = serde_json::from_str(&wire).unwrap();
            assert_eq!(reference.generation(), g);
            assert_eq!(reference.sequence(), s);
            assert_eq!(reference.digest(), &[0xab; 32]);
            assert_eq!(serde_json::to_string(&reference).unwrap(), wire);
            let reordered = format!(
                " {{ \"digest\": \"sha256:{}\", \"s\":{s}, \"g\":{g} }} ",
                "ab".repeat(32),
            );
            assert_eq!(
                serde_json::from_str::<OutboxRowRef>(&reordered).unwrap(),
                reference
            );
        }
    }

    #[test]
    fn outbox_row_reference_refuses_every_other_form() {
        let wire = reference_wire(3, 7);
        for bad in [
            "ab".repeat(32),
            format!("SHA256:{}", "ab".repeat(32)),
            format!("sha256:{}", "AB".repeat(32)),
            format!("sha256:{}", "a".repeat(63)),
            format!("sha256:{}", "a".repeat(65)),
            format!("sha256:{}g", "a".repeat(63)),
        ] {
            let bad_wire = wire.replace(&format!("sha256:{}", "ab".repeat(32)), &bad);
            let error = serde_json::from_str::<OutboxRowRef>(&bad_wire).unwrap_err();
            assert!(
                error
                    .to_string()
                    .starts_with("outbox row digest is not sha256:<64 lowercase hex>")
            );
        }
        for (field, value) in [("g", "3"), ("s", "7")] {
            for bad in ["-1", "3.5", "\"3\"", "18446744073709551616", "null", "true"] {
                let bad_wire = wire.replace(
                    &format!("\"{field}\":{value}"),
                    &format!("\"{field}\":{bad}"),
                );
                assert!(
                    serde_json::from_str::<OutboxRowRef>(&bad_wire).is_err(),
                    "{field}: {bad}"
                );
            }
        }
        for field in ["g", "s", "digest"] {
            let mut value: serde_json::Value = serde_json::from_str(&wire).unwrap();
            let member = value[field].clone();
            value.as_object_mut().unwrap().remove(field);
            assert!(
                serde_json::from_value::<OutboxRowRef>(value).is_err(),
                "missing {field}"
            );
            let duplicate = wire.replacen('{', &format!("{{\"{field}\":{member},"), 1);
            assert!(
                serde_json::from_str::<OutboxRowRef>(&duplicate).is_err(),
                "duplicate {field}"
            );
        }
        let array = format!(r#"[3,7,"sha256:{}"]"#, "ab".repeat(32));
        assert!(
            serde_json::from_str::<OutboxRowRef>(&array).is_err(),
            "object schema"
        );
        let unknown = wire.replacen('{', "{\"extra\":0,", 1);
        assert!(
            serde_json::from_str::<OutboxRowRef>(&unknown).is_err(),
            "unknown field"
        );
    }

    #[test]
    fn a_queued_row_returns_the_digest_of_its_line() {
        let (_dir, path, store, _writer) = cut_over_fixture();
        store.forbid_outbox_items(true);
        let accesses = store.outbox_item_accesses();
        let reference = keyed_outbox(&path, &store)
            .append_queued(&row("queued"))
            .unwrap();
        assert_eq!(store.outbox_item_accesses(), accesses);
        let bytes = outbox_bytes(&path);
        let lines = parse_lines(&bytes).lines;
        let (flag, digest) = test_seam::delivered_row_digest(lines[1]).unwrap();
        assert_eq!(reference.generation(), 1);
        assert_eq!(reference.sequence(), 1);
        assert_eq!(flag, 1);
        assert_eq!(reference.digest(), &digest);
    }

    #[test]
    fn consent_rows_carry_evidence_and_halt_rows_do_not() {
        let (_dir, path, store, _writer) = keyed_fixture();
        let outbox = keyed_outbox(&path, &store);
        outbox.append_queued(&row("consent")).unwrap();
        outbox.append(&row("ordinary")).unwrap();
        let bytes = outbox_bytes(&path);
        let lines = parse_lines(&bytes).lines;
        assert_eq!(test_seam::delivered_row_digest(lines[0]).unwrap().0, 1);
        assert_eq!(test_seam::delivered_row_digest(lines[1]).unwrap().0, 0);
    }

    #[test]
    fn an_unkeyed_outbox_refuses_a_queued_append() {
        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);
        let store = Arc::new(InMemoryTipAnchorStore::new());
        let outbox = AuditOutbox::for_log(&path, store.clone());
        assert!(!outbox.is_keyed());
        let keyed = keyed_outbox(&path, &store);
        assert!(keyed.is_keyed());
        let debug = format!("{keyed:?}");
        assert!(!debug.contains(&crate::hex::encode(&ROW_KEY)));
        assert!(!debug.contains("key:"));
        let error = outbox.append_queued(&row("refused")).unwrap_err();
        assert!(matches!(
            error,
            WriterError::KeyedLogNeedsKey {
                evidence: "a consent row that carries delivery evidence needs the audit key"
            }
        ));
        assert!(!outbox.path().exists(), "no queue is created");
        assert!(!outbox_lock_path(&path).exists(), "no lock is created");
        crate::audit_log::test_helpers::enroll_carriers(&path, store.as_ref()).unwrap();
        let prepared = outbox.prepare_append().unwrap();
        let error = prepared.append_queued(&row("prepared")).unwrap_err();
        assert!(matches!(
            error,
            WriterError::KeyedLogNeedsKey {
                evidence: "a consent row that carries delivery evidence needs the audit key"
            }
        ));
        assert!(!outbox.path().exists());
        drop(outbox.prepare_append().unwrap());
    }

    #[test]
    fn a_refused_queued_append_returns_no_reference() {
        use test_seam::SyncStep;
        for existing in [false, true] {
            for fault in [SyncStep::File, SyncStep::Directory] {
                let (_dir, path, store, mut writer) = keyed_fixture();
                let outbox = keyed_outbox(&path, &store);
                if existing {
                    outbox.append(&row("kept")).unwrap();
                    writer.drain_outbox().unwrap();
                }
                let before = outbox_bytes(&path);
                test_seam::arm_sync_failure(outbox.path(), fault);
                let result = outbox.append_queued(&row("refused"));
                assert!(
                    matches!(result, Err(WriterError::Io(_))),
                    "{existing} {fault:?}: {result:?}"
                );
                assert_eq!(outbox_bytes(&path), before);
                test_seam::record_syncs(outbox.path());
                let reference = outbox.append_queued(&row("retry")).unwrap();
                assert_eq!(reference.sequence(), 1);
                #[cfg(unix)]
                assert_eq!(
                    test_seam::take_syncs(outbox.path()),
                    vec![SyncStep::File, SyncStep::Directory]
                );
            }
        }
    }

    #[test]
    fn a_queued_append_refuses_a_changed_carrier_generation() {
        let (_dir, path, store, _writer) = cut_over_fixture();
        let before = outbox_bytes(&path);
        let callback_store = store.clone();
        test_seam::on_admitted(&outbox_path(&path), move || {
            let mut record = callback_store.load_carrier_record().unwrap().unwrap();
            record.generation += 1;
            callback_store.store_carrier_record(&record).unwrap();
        });
        let result = keyed_outbox(&path, &store).append_queued(&row("retired"));
        assert!(
            matches!(result, Err(WriterError::CarrierGenerationChanged { .. })),
            "{result:?}"
        );
        assert_eq!(outbox_bytes(&path), before);
    }

    #[test]
    fn an_orphan_queued_row_drains_without_an_approval() {
        let (_dir, path, store, writer) = keyed_fixture();
        let reference = keyed_outbox(&path, &store)
            .append_queued(&row("orphan"))
            .unwrap();
        drop(writer);
        let mut restarted = reopen(&path, &store);
        assert_eq!(delivered(&path, "orphan"), 1);
        assert_eq!(
            owner_state(&store).unwrap().recent,
            vec![*reference.digest()]
        );
        assert_eq!(restarted.drain_outbox().unwrap(), 0);
        assert_eq!(delivered(&path, "orphan"), 1);
    }

    #[test]
    fn a_failed_rollback_returns_no_reference_and_the_row_drains() {
        let (_dir, path, store, writer) = keyed_fixture();
        let outbox = keyed_outbox(&path, &store);
        test_seam::arm_sync_failure(outbox.path(), test_seam::SyncStep::File);
        test_seam::arm_sync_failure(outbox.path(), test_seam::SyncStep::Rollback);
        let result = outbox.append_queued(&row("orphan"));
        assert!(matches!(result, Err(WriterError::Io(_))), "{result:?}");
        let bytes = outbox_bytes(&path);
        let lines = parse_lines(&bytes).lines;
        assert_eq!(lines.len(), 1);
        let digest = test_seam::delivered_row_digest(lines[0]).unwrap().1;
        drop(writer);
        let mut restarted = reopen(&path, &store);
        assert_eq!(delivered(&path, "orphan"), 1);
        assert_eq!(owner_state(&store).unwrap().recent, vec![digest]);
        assert_eq!(restarted.drain_outbox().unwrap(), 0);
    }

    #[test]
    fn a_queued_reference_waits_for_owner_commit() {
        let (_dir, path, store, mut writer) = keyed_fixture();
        let reference = keyed_outbox(&path, &store)
            .append_queued(&row("anchored"))
            .unwrap();
        let before = outbox_bytes(&path);
        store.fail_next_writes(3);
        let result = writer.drain_outbox();
        assert!(
            matches!(result, Err(WriterError::TipAnchorStore(_))),
            "{result:?}"
        );
        assert!(store.outbox_item_writes().is_empty());
        assert_eq!(store.load_outbox_owner_state(1).unwrap(), None);
        assert_eq!(outbox_bytes(&path), before);
        assert_eq!(writer.drain_outbox().unwrap(), 1);
        assert_eq!(
            owner_state(&store).unwrap().recent,
            vec![*reference.digest()]
        );
        assert_eq!(delivered(&path, "anchored"), 2);
        assert_eq!(writer.drain_outbox().unwrap(), 0);
    }

    #[test]
    #[serial_test::serial]
    fn a_queued_reference_survives_completed_key_rotation() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        for enforced in [false, true] {
            let (_dir, path, store, writer) = if enforced {
                initialized()
            } else {
                cut_over_fixture()
            };
            let outbox = keyed_outbox(&path, &store);
            let outbox = if enforced {
                let reservation = outbox.reserve_evidence([1; 32], 9_000, 0).unwrap();
                outbox.with_evidence_reservation(reservation)
            } else {
                outbox
            };
            drop(writer);
            let mut rotation = AuditWriter::open_for_key_rotation(
                path.clone(),
                Some(Zeroizing::new(ROW_KEY)),
                store.clone(),
                crate::audit_log::BindingHistory::NotRecorded,
            )
            .unwrap();
            let (waiting, ready) = std::sync::mpsc::channel();
            test_seam::on_contended(&outbox_lock_path(&path), move || waiting.send(()).unwrap());
            let reference = std::thread::scope(|scope| {
                let append = scope.spawn(|| outbox.append_queued(&row("rotated")));
                ready.recv().unwrap();
                store.set_reload(Ok(Some(ROW_KEY)));
                rotation.fence_outbox_for_key_change().unwrap();
                store.set_reload(Ok(Some(NEXT_KEY)));
                rotation
                    .switch_entry_tag_key(Zeroizing::new(NEXT_KEY), "rotation")
                    .unwrap();
                crate::audit_log::resign_chain_root_sidecars(&path, &NEXT_KEY).unwrap();
                drop(rotation);
                append.join().unwrap().unwrap()
            });
            let bytes = outbox_bytes(&path);
            let lines = parse_lines(&bytes).lines;
            let decoded = decode_tagged(lines[1], 2, SuffixCheck::Keyed(Some(&NEXT_KEY)), 1, 1);
            assert!(
                decoded.is_ok(),
                "the queued row authenticates under the reloaded key"
            );
            let entry = decoded.unwrap().entry;
            assert_eq!(entry.request_id, "rotated");
            assert_eq!(
                test_seam::delivered_row_digest(lines[1]).unwrap().1,
                *reference.digest()
            );
            assert!(matches!(
                AuditWriter::open(
                    path.clone(),
                    Some(KeyedAuditAccess::new(
                        Zeroizing::new(ROW_KEY),
                        store.clone(),
                    ))
                ),
                Err(WriterError::AuditKeyReplaced)
            ));
            let mut writer = AuditWriter::open(
                path.clone(),
                Some(KeyedAuditAccess::new(
                    Zeroizing::new(NEXT_KEY),
                    store.clone(),
                )),
            )
            .unwrap();
            assert_eq!(delivered(&path, "rotated"), 1);
            if enforced {
                assert!(evidence_snapshot(&writer).contains_delivered(&[1; 32], &reference));
            } else {
                assert_eq!(
                    owner_state(&store).unwrap().recent,
                    vec![*reference.digest()]
                );
            }
            assert_eq!(writer.drain_outbox().unwrap(), 0);
        }
    }

    fn replace_tagged_line(path: &Path, store: &Arc<InMemoryTipAnchorStore>, line: &[u8]) {
        let mut bytes = line.to_vec();
        bytes.push(b'\n');
        fs::write(outbox_path(path), bytes).unwrap();
        commit_every_line(path, store);
    }

    fn assert_tagged_refusal(line: &[u8], expected: &WriterError) {
        let (_dir, path, store, mut writer) = keyed_fixture();
        keyed_outbox(&path, &store).append(&fixed_row()).unwrap();
        replace_tagged_line(&path, &store, line);
        let before = fs::read(&path).unwrap();
        let queued = outbox_bytes(&path);
        let committed = store.load_outbox_state(1).unwrap();
        let error = writer.drain_outbox().unwrap_err();
        assert_eq!(format!("{error:?}"), format!("{expected:?}"));
        assert_eq!(fs::read(&path).unwrap(), before, "nothing is appended");
        assert_eq!(outbox_bytes(&path), queued);
        assert_eq!(store.load_outbox_state(1).unwrap(), committed);
    }

    fn unusable(reason: &'static str) -> WriterError {
        WriterError::OutboxUnusable {
            line: 1,
            column: 1,
            reason,
        }
    }

    /// Signs exact test body bytes independently of the row encoder.
    fn signed_body(body: &[u8], label: &[u8]) -> Vec<u8> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&ROW_KEY).unwrap();
        mac.update(label);
        mac.update(&0_u64.to_be_bytes());
        mac.update(&1_u64.to_be_bytes());
        mac.update(&[0]);
        mac.update(body);
        format!(
            "{{\"k\":\"row\",\"g\":0,\"s\":1,\"r\":0,\"body\":{},\"tag\":\"{}\"}}",
            std::str::from_utf8(body).unwrap(),
            crate::hex::encode(&mac.finalize().into_bytes())
        )
        .into_bytes()
    }

    #[test]
    fn owner_item_vector_and_limits() {
        use test_seam::owner_value;
        let empty = r#"{"v":1,"g":0,"closed":null,"legacy":null,"recent":[]}"#;
        assert_eq!(owner_value(0, None), empty);
        assert_eq!(
            OutboxOwnerState::parse(empty).unwrap().to_keyring_value(),
            empty
        );
        assert_eq!(
            owner_value(7, Some(&OutboxState::default())),
            r#"{"v":1,"g":7,"closed":null,"legacy":"387c35402193ea541c6ff3160f4562acb59217234b135901f5944ffa9a6822a3","recent":[]}"#
        );
        let maximum = |count| {
            format!(
                r#"{{"v":1,"g":{0},"closed":{{"g":{0},"n":{0},"batch":"{1}"}},"legacy":"{2}","recent":[{3}]}}"#,
                u64::MAX,
                "ab".repeat(32),
                "cd".repeat(32),
                vec![format!(r#""{}""#, "ef".repeat(32)); count].join(",")
            )
        };
        let full = maximum(15);
        assert_eq!(full.len(), 1260);
        assert_eq!(
            OutboxOwnerState::parse(&full).unwrap().to_keyring_value(),
            full
        );
        assert_eq!(maximum(16).len(), 1327);
        assert!(full.encode_utf16().count() * 2 <= 2560);
        assert!(maximum(16).encode_utf16().count() * 2 > 2560);
        let refuse = |raw: &str| {
            assert_eq!(
                OutboxOwnerState::parse(raw).unwrap_err().detail,
                "outbox owner state is unusable",
                "{raw}"
            );
        };
        refuse(&maximum(16));
        refuse(&full.replacen("\"v\":1", "\"v\":1,\"v\":1", 1));
        refuse(&full.replacen("\"v\":1", "\"v\":1,\"delivered\":0", 1));
        refuse(&full.replacen("\"n\":", "\"extra\":0,\"n\":", 1));
        refuse(&full.replacen("\"batch\":", "\"n\":0,\"batch\":", 1));
        let malformed = [
            format!(" {full}"),
            format!("{full}\n"),
            full.replace(',', ", "),
            empty.replace("\"v\":1,\"g\":0", "\"g\":0,\"v\":1"),
            full.replace(
                &format!("\"g\":{0},\"n\":{0}", u64::MAX),
                &format!("\"n\":{0},\"g\":{0}", u64::MAX),
            ),
            full.replacen("ab", r"\u0061b", 1),
            format!("{full}x"),
            empty.replace("\"closed\":null", "\"closed\":0"),
            empty.replace("\"legacy\":null", "\"legacy\":1"),
            empty.replace("\"recent\":[]", "\"recent\":null"),
            empty.replace("\"recent\":[]", "\"recent\":[1]"),
        ];
        for raw in malformed {
            refuse(&raw);
        }
        for raw in ["", "null", "[]", "{}", "private-marker"] {
            refuse(raw);
        }
        let value: serde_json::Value = serde_json::from_str(&full).unwrap();
        for field in ["v", "g", "closed", "legacy", "recent"] {
            let mut missing = value.clone();
            missing.as_object_mut().unwrap().remove(field);
            refuse(&missing.to_string());
        }
        for field in ["g", "n", "batch"] {
            let mut missing = value.clone();
            missing["closed"].as_object_mut().unwrap().remove(field);
            refuse(&missing.to_string());
        }
        for version in ["0", "2", "256", "-1", "1.0", "\"1\""] {
            refuse(&full.replacen("\"v\":1", &format!("\"v\":{version}"), 1));
        }
        for number in ["-1", "1.0", "18446744073709551616", "\"1\"", "null"] {
            for prefix in ["\"g\":", "\"n\":"] {
                refuse(&full.replace(
                    &format!("{prefix}{}", u64::MAX),
                    &format!("{prefix}{number}"),
                ));
            }
        }
        for hash in [
            "AB".repeat(32),
            "a".repeat(63),
            "a".repeat(65),
            "gg".repeat(32),
            format!("sha256:{}", "ab".repeat(32)),
        ] {
            for original in ["ab".repeat(32), "cd".repeat(32), "ef".repeat(32)] {
                refuse(&full.replace(&original, &hash));
            }
        }
    }

    #[test]
    fn recent_keeps_only_fifteen_requested_digests() {
        let rows: Vec<_> = (1..=40)
            .map(|s| {
                let line = encode_tagged_row(&ROW_KEY, 7, s, (s % 2) as u8, &fixed_row()).unwrap();
                test_seam::delivered_row_digest(&line).unwrap()
            })
            .collect();
        let first =
            test_seam::owner_after_delivery(&test_seam::owner_value(8, None), 7, &rows[..20])
                .unwrap();
        let final_value = test_seam::owner_after_delivery(&first, 7, &rows[20..]).unwrap();
        let owner = OutboxOwnerState::parse(&final_value).unwrap();
        let expected: Vec<_> = (11..=39)
            .step_by(2)
            .map(|s| row_digest(7, s, 1, &fixed_row()).unwrap())
            .collect();
        assert_eq!(owner.recent, expected);
        assert_eq!(owner.recent.len(), 15);
        assert_eq!(owner.g, 8);
        assert_eq!(owner.closed.as_ref().unwrap().g, 7);
        assert_eq!(owner.closed.as_ref().unwrap().n, 20);
        let unchanged = test_seam::owner_after_delivery(&final_value, 8, &[(0, [0; 32])]).unwrap();
        assert_eq!(
            OutboxOwnerState::parse(&unchanged).unwrap().recent,
            expected
        );
    }

    #[test]
    fn owner_batch_hashes_ordered_binary_row_digests() {
        let rows: Vec<_> = [0, 1]
            .into_iter()
            .map(|r| {
                test_seam::delivered_row_digest(
                    &encode_tagged_row(&ROW_KEY, 0, 1, r, &fixed_row()).unwrap(),
                )
                .unwrap()
            })
            .collect();
        let value =
            test_seam::owner_after_delivery(&test_seam::owner_value(1, None), 0, &rows).unwrap();
        let owner = OutboxOwnerState::parse(&value).unwrap();
        let closed = owner.closed.unwrap();
        assert_eq!(closed.g, 0);
        assert_eq!(closed.n, 2);
        assert_eq!(
            crate::hex::encode(&closed.batch),
            "b92d22c240f13e919f04f18c992a10a5f3b4cb8885105ee1525219fd0dfc2a43"
        );
        assert_eq!(owner.recent, vec![rows[1].1]);
    }

    #[test]
    fn generation_line_vector_binds_generation_and_domain() {
        for (g, tag) in [
            (
                0,
                "a9100ad8986f84004dba3a37d49d22b163821c500dfc106b869098b40dbbd759",
            ),
            (
                7,
                "bf5a617010a112b0460fa0fe499d38dcbc7070f56cd9cfbb66b63c5544692684",
            ),
            (
                u64::MAX,
                "8f1e49dbfd8f9785c28955595e0fb413a5e0d4e76e9cf4845b65199e15bbd3ba",
            ),
        ] {
            let line = test_seam::generation_line(&ROW_KEY, g);
            assert_eq!(
                line,
                format!("{{\"k\":\"gen\",\"g\":{g},\"tag\":\"{tag}\"}}\n").as_bytes()
            );
            let line = line.strip_suffix(b"\n").unwrap();
            assert_eq!(
                test_seam::queue_generation(&[line], Some(&ROW_KEY)).unwrap(),
                g
            );
            let upper = std::str::from_utf8(line)
                .unwrap()
                .replace(tag, &tag.to_uppercase());
            assert!(matches!(
                test_seam::queue_generation(&[upper.as_bytes()], Some(&ROW_KEY)),
                Err(WriterError::OutboxUnusable {
                    reason: "tagged record that does not parse",
                    ..
                })
            ));
            let changed = std::str::from_utf8(line)
                .unwrap()
                .replace(&format!("\"g\":{g}"), "\"g\":9");
            assert!(matches!(
                test_seam::queue_generation(&[changed.as_bytes()], Some(&ROW_KEY)),
                Err(WriterError::OutboxUnusable {
                    reason: "tagged record whose tag does not verify",
                    ..
                })
            ));
        }
    }

    #[test]
    fn generation_codec_refusals_are_exact() {
        let header = test_seam::generation_line(&ROW_KEY, 7);
        let line = header.strip_suffix(b"\n").unwrap();
        let check = |lines: &[&[u8]], key, number, reason| {
            let error = test_seam::queue_generation(lines, key).unwrap_err();
            assert_eq!(
                format!("{error:?}"),
                format!("{:?}", tagged_refusal(number, reason))
            );
        };
        assert_eq!(test_seam::queue_generation(&[], None).unwrap(), 0);
        assert_eq!(
            test_seam::queue_generation(&[VECTOR_BODY.as_bytes()], None).unwrap(),
            0
        );
        check(&[line], None, 1, "tagged record without an audit key");
        check(
            &[line],
            Some(&[0; 32]),
            1,
            "tagged record whose tag does not verify",
        );
        check(
            &[line, line],
            Some(&ROW_KEY),
            2,
            "generation line out of place",
        );
        check(
            &[b"{}", b"{}", line],
            Some(&ROW_KEY),
            3,
            "generation line out of place",
        );
        let raw = std::str::from_utf8(line).unwrap();
        for malformed in [
            raw.replace("\"g\":7", "\"g\":07"),
            raw.replace("\"g\":7", "\"g\":-1"),
            raw.replace("\"g\":7", "\"g\":7.0"),
            raw.replace("\"g\":7", "\"g\":18446744073709551616"),
            raw.replace("\"g\":7", "\"g\":\"7\""),
            raw.replace("\"g\":7", "\"g\":7,\"extra\":0"),
            raw.replace("\"k\":\"gen\",\"g\":7", "\"g\":7,\"k\":\"gen\""),
            raw.replace(',', ", "),
            raw.replace("\"tag\":", "\"missing\":"),
            raw.replace("bf5a", "zzz"),
            format!("{raw}\n"),
            "{\"k\":\"gen\"".to_owned(),
        ] {
            check(
                &[malformed.as_bytes()],
                None,
                1,
                "tagged record that does not parse",
            );
        }
        assert_eq!(test_seam::next_generation(0).unwrap(), 1);
        assert_eq!(test_seam::next_generation(u64::MAX - 1).unwrap(), u64::MAX);
        assert_eq!(
            format!("{:?}", test_seam::next_generation(u64::MAX).unwrap_err()),
            format!("{:?}", unusable("queue generation overflows"))
        );
    }

    #[test]
    fn generation_inspection_counts_rows_and_file_lines() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("generation.jsonl");
        let header = format!(
            "{{\"k\":\"gen\",\"g\":7,\"tag\":\"{}\"}}\n",
            "00".repeat(32)
        );
        let mut bytes = header.as_bytes().to_vec();
        for s in 0..64 {
            bytes.extend(encode_tagged_row(&ROW_KEY, 99, s, 0, &fixed_row()).unwrap());
            bytes.push(b'\n');
        }
        bytes.extend_from_slice(b"bad\n");
        bytes.extend_from_slice(header.as_bytes());
        bytes.extend_from_slice(b"torn");
        fs::write(outbox_path(&path), &bytes).unwrap();
        assert_eq!(
            inspect_outbox(&path).unwrap(),
            OutboxInspection {
                pending: 66,
                torn_bytes: 4,
                unparseable_lines: vec![66, 67],
            }
        );
        fs::write(outbox_path(&path), header.replace("\"g\":7", "\"g\":07")).unwrap();
        assert_eq!(
            inspect_outbox(&path).unwrap(),
            OutboxInspection {
                pending: 1,
                torn_bytes: 0,
                unparseable_lines: vec![1],
            }
        );
        fs::write(outbox_path(&path), format!("{VECTOR_BODY}\n{header}")).unwrap();
        assert_eq!(
            inspect_outbox(&path).unwrap(),
            OutboxInspection {
                pending: 2,
                torn_bytes: 0,
                unparseable_lines: vec![2],
            }
        );
        fs::write(outbox_path(&path), &header).unwrap();
        assert_eq!(inspect_outbox(&path).unwrap(), OutboxInspection::default());
    }

    #[test]
    fn a_generation_header_alone_is_clean_to_inspect_but_refuses_the_drain() {
        let (_dir, path, store, mut writer) = keyed_fixture();
        let header = test_seam::generation_line(&ROW_KEY, 7);
        fs::write(outbox_path(&path), &header).unwrap();
        commit_every_line(&path, &store);
        assert_eq!(
            inspect_outbox(&path).unwrap(),
            OutboxInspection {
                pending: 0,
                torn_bytes: 0,
                unparseable_lines: vec![],
            }
        );
        assert_eq!(
            writer.drain_outbox().unwrap_err().to_string(),
            "audit.outbox_unusable: line 1 of the audit outbox is unusable \
             (tagged record that does not parse at column 1); the outbox is left unchanged"
        );
        assert_eq!(outbox_bytes(&path), header);
    }

    #[test]
    fn tagged_row_vector_keeps_its_bytes() {
        for (r, tag, digest) in [
            (
                0,
                "4755e2961e64664d1128941005b83a280081bc92046d8ec4678db3e6e6b9aaa0",
                "3962b94979c479ada6680fb1ba13e8ef106378b0dc32f7c3e5cfd53c3320b846",
            ),
            (
                1,
                "a3216b84e5b09e4ea4c63f9d21a934eb688865967c63621e52ff2c08cfc8276b",
                "237b3f7c4f7e8e4003d6e59375649405bc21810fb12dedd4973d309887412435",
            ),
        ] {
            let (_dir, path, store, mut writer) = keyed_fixture();
            let outbox = keyed_outbox(&path, &store);
            outbox.clone().append(&fixed_row()).unwrap();
            assert_eq!(
                format!("{outbox:?}"),
                format!(
                    "AuditOutbox {{ path: {:?}, lock_path: {:?}, state: {store:?}, .. }}",
                    outbox_path(&path),
                    outbox_lock_path(&path)
                )
            );
            if r == 1 {
                let line = encode_tagged_row(&ROW_KEY, 0, 1, r, &fixed_row()).unwrap();
                replace_tagged_line(&path, &store, &line);
            }
            let expected = format!(
                "{{\"k\":\"row\",\"g\":0,\"s\":1,\"r\":{r},\"body\":{VECTOR_BODY},\"tag\":\"{tag}\"}}\n"
            );
            assert_eq!(outbox_bytes(&path), expected.as_bytes(), "wire vector");
            assert_eq!(
                crate::hex::encode(&row_digest(0, 1, r, &fixed_row()).unwrap()),
                digest
            );
            assert_eq!(writer.drain_outbox().unwrap(), 1);
            let entry: AuditEntry = serde_json::from_value(log_rows(&path).pop().unwrap()).unwrap();
            assert_eq!(entry.canonical_json_body().unwrap(), VECTOR_BODY.as_bytes());
        }
    }

    #[test]
    fn tagged_rows_bind_body_sequence_generation_evidence_and_domain() {
        let (_dir, path, store, mut writer) = keyed_fixture();
        keyed_outbox(&path, &store).append(&fixed_row()).unwrap();
        let line = String::from_utf8(outbox_bytes(&path)).unwrap();
        assert_eq!(
            line.trim_end().as_bytes(),
            signed_body(VECTOR_BODY.as_bytes(), b"stellar-agent-outbox-row:v2"),
            "the row binds every component under its domain"
        );
        assert_eq!(
            writer.drain_outbox().unwrap(),
            1,
            "the untouched row drains"
        );
        for (from, to) in [
            ("vector", "sector"),
            ("\"g\":0", "\"g\":1"),
            ("\"s\":1", "\"s\":2"),
            ("\"r\":0", "\"r\":1"),
            ("\"tag\":\"4", "\"tag\":\"5"),
        ] {
            assert!(line.contains(from));
            assert_tagged_refusal(
                line.trim_end().replace(from, to).as_bytes(),
                &unusable("tagged record whose tag does not verify"),
            );
        }
        assert_tagged_refusal(
            &signed_body(VECTOR_BODY.as_bytes(), b"another-row-domain"),
            &unusable("tagged record whose tag does not verify"),
        );
    }

    #[test]
    fn classification_and_refusal_precedence_are_pinned() {
        let line =
            String::from_utf8(encode_tagged_row(&ROW_KEY, 0, 1, 0, &fixed_row()).unwrap()).unwrap();
        assert_tagged_refusal(
            line.replace("\"g\":0", "\"g\":00").as_bytes(),
            &WriterError::OutboxUnusable {
                line: 1,
                column: 17,
                reason: "invalid JSON",
            },
        );
        let body = VECTOR_BODY.replacen("{", "{ ", 1);
        let valid = signed_body(body.as_bytes(), b"stellar-agent-outbox-row:v2");
        assert_tagged_refusal(&valid, &unusable("tagged record that is not canonical"));
        let invalid = signed_body(body.as_bytes(), b"another-row-domain");
        assert_tagged_refusal(
            &invalid,
            &unusable("tagged record whose tag does not verify"),
        );
        let raw = format!("{},\"k\":\"row\"}}", &VECTOR_BODY[..VECTOR_BODY.len() - 1]);
        assert_tagged_refusal(
            raw.as_bytes(),
            &unusable("tagged record that does not parse"),
        );
        let prefixed_raw = format!("{{\"k\":\"row\",{}", &VECTOR_BODY[1..]);
        assert_tagged_refusal(
            prefixed_raw.as_bytes(),
            &unusable("tagged record that does not parse"),
        );
        assert_tagged_refusal(
            line.replacen("\"k\"", "\"\\u006b\"", 1).as_bytes(),
            &unusable("tagged record that does not parse"),
        );
    }

    #[test]
    fn noncanonical_tagged_records_refuse_after_authentication() {
        let line =
            String::from_utf8(encode_tagged_row(&ROW_KEY, 0, 1, 0, &fixed_row()).unwrap()).unwrap();
        for changed in [
            line.replacen("{", "{ ", 1),
            line.replace("\"g\":0,\"s\":1", "\"s\":1,\"g\":0"),
            line.replace("4755e", "4755E"),
            line.replace("\"g\":0", "\"g\":-0"),
            line.replace("\"s\":1", "\"s\":1.0"),
            line.replace("\"r\":0", "\"r\":2"),
            line.replace("\"r\":0", "\"r\":false"),
            line.replace("\"s\":1", "\"s\":18446744073709551616"),
            line.replace("\"k\":\"row\"", "\"k\":\"gen\""),
        ] {
            assert_tagged_refusal(
                changed.as_bytes(),
                &unusable("tagged record that does not parse"),
            );
        }
        assert_tagged_refusal(
            line.replace("\"s\":1", "\"s\":01").as_bytes(),
            &WriterError::OutboxUnusable {
                line: 1,
                column: 23,
                reason: "invalid JSON",
            },
        );
        let reordered =
            serde_json::to_vec(&serde_json::from_str::<serde_json::Value>(VECTOR_BODY).unwrap())
                .unwrap();
        for body in [
            VECTOR_BODY.replacen("{", "{ ", 1).into_bytes(),
            reordered,
            b"{}".to_vec(),
        ] {
            assert_tagged_refusal(
                &signed_body(&body, b"stellar-agent-outbox-row:v2"),
                &unusable("tagged record that is not canonical"),
            );
        }
    }

    #[test]
    fn a_tagged_row_out_of_position_refuses_rows_missing() {
        for (g, s) in [(0, 2), (1, 1), (u64::MAX, u64::MAX)] {
            assert_tagged_refusal(
                &encode_tagged_row(&ROW_KEY, g, s, 0, &fixed_row()).unwrap(),
                &WriterError::OutboxRowsMissing {
                    recorded: 1,
                    found: s,
                },
            );
        }
    }

    #[test]
    fn tagged_rows_of_every_operator_kind_drain() {
        let (_dir, path, store, mut writer) = keyed_fixture();
        let outbox = keyed_outbox(&path, &store);
        let entries = [
            row("local"),
            AuditEntry::new_approval_attested_remote(
                "PaymentSimulated",
                "stellar_pay_commit",
                None,
                "ABCDEFGHIJKLMNOPQRSTUV",
                "credential",
                "remote",
            ),
            AuditEntry::new_profile_halted(
                "fixture",
                "2026-01-01T00:00:00Z",
                Some("incident"),
                "halt",
            ),
            AuditEntry::new_profile_resumed("fixture", true, "resume"),
        ];
        for entry in &entries {
            outbox.append(entry).unwrap();
        }
        assert_eq!(writer.drain_outbox().unwrap(), entries.len());
        let ids = request_ids(&path);
        assert_eq!(&ids[ids.len() - 4..], ["local", "remote", "halt", "resume"]);
        outbox.append(&own_row("refused")).unwrap();
        let before = fs::read(&path).unwrap();
        // The refused row is physical line 2, after the generation line.
        assert!(matches!(
            writer.drain_outbox(),
            Err(WriterError::OutboxRowKindRefused { line: 2 })
        ));
        assert_eq!(fs::read(&path).unwrap(), before);
    }

    #[test]
    fn a_tagged_line_without_a_key_refuses_and_inspects() {
        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);
        let store = bound_store(&path);
        let mut writer = open_draining(&path, &store);
        keyed_outbox(&path, &store).append(&fixed_row()).unwrap();
        assert!(matches!(
            writer.drain_outbox(),
            Err(WriterError::OutboxUnusable {
                line: 1,
                column: 1,
                reason: "tagged record without an audit key"
            })
        ));
        assert!(log_rows(&path).is_empty());
        assert_eq!(
            inspect_outbox(&path).unwrap(),
            OutboxInspection {
                pending: 1,
                torn_bytes: 0,
                unparseable_lines: vec![],
            }
        );
    }

    #[test]
    fn keyed_appends_take_the_line_number_under_the_lock() {
        use std::sync::Barrier;
        let (_dir, path, store, mut writer) = keyed_fixture();
        let admitted = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let waiting = Arc::new(Barrier::new(3));
        let (a, r) = (admitted.clone(), release.clone());
        test_seam::on_admitted(&outbox_path(&path), move || {
            a.wait();
            r.wait();
        });
        std::thread::scope(|scope| {
            let raw =
                scope.spawn(|| AuditOutbox::for_log(&path, store.clone()).append(&row("raw")));
            admitted.wait();
            for _ in 0..2 {
                let waiting = waiting.clone();
                test_seam::on_contended(&outbox_lock_path(&path), move || {
                    waiting.wait();
                });
            }
            let first = scope.spawn(|| keyed_outbox(&path, &store).append(&row("first")));
            let second = scope.spawn(|| keyed_outbox(&path, &store).append(&row("second")));
            waiting.wait();
            release.wait();
            raw.join().unwrap().unwrap();
            first.join().unwrap().unwrap();
            second.join().unwrap().unwrap();
        });
        let bytes = outbox_bytes(&path);
        let lines = parse_lines(&bytes).lines;
        assert_eq!(lines.len(), 3);
        for (index, line) in lines.iter().enumerate().skip(1) {
            let record: serde_json::Value = serde_json::from_slice(line).unwrap();
            assert_eq!(record["g"], 0);
            assert_eq!(record["r"], 0);
            assert_eq!(record["s"], index + 1);
        }
        assert_eq!(writer.drain_outbox().unwrap(), 3);
        keyed_outbox(&path, &store).append(&row("reset")).unwrap();
        let bytes = outbox_bytes(&path);
        let lines = parse_lines(&bytes).lines;
        assert_eq!(lines.len(), 2);
        assert_eq!(
            test_seam::queue_generation(&lines[..1], Some(&ROW_KEY)).unwrap(),
            1
        );
        let record: serde_json::Value = serde_json::from_slice(lines[1]).unwrap();
        assert_eq!(
            (record["g"].as_u64(), record["s"].as_u64()),
            (Some(1), Some(1))
        );
        assert_eq!(writer.drain_outbox().unwrap(), 1);
    }

    #[test]
    fn a_refused_keyed_append_leaves_the_outbox_byte_identical() {
        for fault in 0..4 {
            let (_dir, path, store, _writer) = keyed_fixture();
            let outbox = keyed_outbox(&path, &store);
            if fault != 2 {
                outbox.append(&row("kept")).unwrap();
            }
            let before = outbox_bytes(&path);
            let state = store.load_outbox_state(1).unwrap();
            if fault == 3 {
                // A keyed append touches neither the commitment nor the owner
                // state, so forbidding both item APIs leaves it admitted.
                store.forbid_outbox_items(true);
                outbox.append(&row("accepted")).unwrap();
                store.forbid_outbox_items(false);
                let bytes = outbox_bytes(&path);
                assert_eq!(&bytes[..before.len()], before.as_slice());
                assert_eq!(parse_lines(&bytes).lines.len(), 2);
                assert_eq!(store.load_outbox_state(1).unwrap(), state);
                continue;
            }
            match fault {
                0 => test_seam::arm_partial_write(outbox.path(), 17),
                1 => test_seam::arm_sync_failure(outbox.path(), test_seam::SyncStep::File),
                _ => test_seam::arm_sync_failure(outbox.path(), test_seam::SyncStep::Directory),
            }
            let error = outbox.append(&row("refused")).unwrap_err();
            assert!(matches!(error, WriterError::Io(_)), "{error:?}");
            assert_eq!(outbox_bytes(&path), before, "fault {fault} preserves bytes");
            assert_eq!(
                store.load_outbox_state(1).unwrap(),
                state,
                "fault {fault} preserves commitment"
            );
            store.set_outbox_failing(false, false);
            outbox.append(&row("accepted")).unwrap();
        }
    }

    /// An oversized row refuses before the first write: a torn tail stays,
    /// and a missing outbox stays missing, keyed and unkeyed.
    #[test]
    fn an_oversized_append_refuses_before_any_write() {
        let over = consent_row_of_len("large", super::super::writer::MAX_ROW_BYTES + 1);
        for keyed in [false, true] {
            let dir = TempDir::new().unwrap();
            let path = log_path(&dir);
            let store = bound_store(&path);
            let outbox = if keyed {
                keyed_outbox(&path, &store)
            } else {
                AuditOutbox::for_log(&path, store.clone())
            };
            let refuses = |outbox: &AuditOutbox| {
                assert!(
                    matches!(
                        outbox.append(&over),
                        Err(WriterError::OutboxRowTooLarge { .. })
                    ),
                    "keyed {keyed}"
                );
            };
            refuses(&outbox);
            assert!(
                !outbox_path(&path).exists(),
                "keyed {keyed}: nothing created"
            );
            outbox.append(&row("kept")).unwrap();
            let mut torn = outbox_bytes(&path);
            torn.extend_from_slice(b"{\"ts\":\"2026-");
            fs::write(outbox_path(&path), &torn).unwrap();
            let state = store.load_outbox_state(1).unwrap();
            refuses(&outbox);
            assert_eq!(outbox_bytes(&path), torn, "keyed {keyed}: torn tail kept");
            assert_eq!(store.load_outbox_state(1).unwrap(), state, "keyed {keyed}");
        }
    }

    /// A keyed append syncs the directory before it acknowledges the row,
    /// also when the file exists. After a publication whose directory sync
    /// failed, the outbox's name may not be durable yet.
    #[test]
    fn a_keyed_append_after_an_unsynced_publication_syncs_the_directory() {
        let (_dir, path, store, mut writer) = keyed_fixture();
        enqueue(&path, &store, &["delivered"]);
        test_seam::arm_sync_failure(
            &replacement_path(&outbox_path(&path)),
            test_seam::SyncStep::Directory,
        );
        assert!(matches!(writer.drain_outbox(), Err(WriterError::Io(_))));
        assert_eq!(outbox_bytes(&path), header(1));
        let outbox = keyed_outbox(&path, &store);
        test_seam::arm_sync_failure(outbox.path(), test_seam::SyncStep::Directory);
        let refused = outbox.append(&row("refused-until-synced"));
        assert!(matches!(refused, Err(WriterError::Io(_))), "{refused:?}");
        assert_eq!(outbox_bytes(&path), header(1));
        test_seam::record_syncs(outbox.path());
        outbox.append(&row("accepted")).unwrap();
        let expected: &[test_seam::SyncStep] = if cfg!(unix) {
            &[test_seam::SyncStep::File, test_seam::SyncStep::Directory]
        } else {
            &[test_seam::SyncStep::File]
        };
        assert_eq!(test_seam::take_syncs(outbox.path()), expected);
        drop(writer);
        let _writer = reopen(&path, &store);
        assert_eq!(delivered(&path, "accepted"), 1);
        assert_eq!(delivered(&path, "refused-until-synced"), 0);
    }

    #[test]
    fn tagged_and_untagged_rows_deliver_identical_log_rows() {
        let mut logs = Vec::new();
        for keyed in [false, true] {
            let dir = TempDir::new().unwrap();
            let path = log_path(&dir);
            let store = bound_store(&path);
            let outbox = if keyed {
                keyed_outbox(&path, &store)
            } else {
                AuditOutbox::for_log(&path, store.clone())
            };
            outbox.append(&fixed_row()).unwrap();
            let mut writer =
                AuditWriter::open_for_reanchor(path.clone(), Some(Zeroizing::new(ROW_KEY)), store)
                    .unwrap();
            assert_eq!(writer.drain_outbox().unwrap(), 1);
            logs.push(fs::read(&path).unwrap());
        }
        assert!(!logs[0].is_empty());
        assert_eq!(
            logs[0], logs[1],
            "delivery bytes match under one key and timestamp"
        );
    }

    #[test]
    fn mixed_lines_drain_in_file_order() {
        let (_dir, path, store, mut writer) = keyed_fixture();
        let raw = AuditOutbox::for_log(&path, store.clone());
        let keyed = keyed_outbox(&path, &store);
        let mut expected = Vec::new();
        let entries: Vec<_> = (0..3)
            .map(|index| {
                let mut entry = fixed_row();
                entry.request_id = format!("queued-{index}");
                entry.ts = format!("2026-01-01T00:00:0{index}.000Z");
                expected.push(entry.canonical_json_body().unwrap());
                entry
            })
            .collect();
        raw.append(&entries[0]).unwrap();
        keyed.append(&entries[1]).unwrap();
        // The keyed row is past the commitment, so the unkeyed exact check
        // refuses the next raw append and leaves the bytes.
        let uncommitted = outbox_bytes(&path);
        assert!(matches!(
            raw.append(&entries[2]),
            Err(WriterError::OutboxRowsMissing {
                recorded: 1,
                found: 2
            })
        ));
        assert_eq!(outbox_bytes(&path), uncommitted);
        commit_every_line(&path, &store);
        raw.append(&entries[2]).unwrap();
        assert_eq!(writer.drain_outbox().unwrap(), 3);
        let rows = log_rows(&path);
        let actual: Vec<_> = rows[rows.len() - 3..]
            .iter()
            .map(|value| {
                serde_json::from_value::<AuditEntry>(value.clone())
                    .unwrap()
                    .canonical_json_body()
                    .unwrap()
            })
            .collect();
        assert_eq!(actual, expected);
    }

    #[test]
    fn recognition_after_reset_covers_tagged_batches() {
        let (_dir, path, store, mut writer) = keyed_fixture();
        let outbox = keyed_outbox(&path, &store);
        outbox.append(&row("one")).unwrap();
        outbox.append(&row("two")).unwrap();
        test_seam::arm_stop(&outbox_path(&path), test_seam::Stop::LegacyZeroed);
        assert!(matches!(writer.drain_outbox(), Err(WriterError::Io(_))));
        assert_eq!(
            store.load_outbox_state(1).unwrap(),
            Some(OutboxState::default())
        );
        let owner =
            OutboxOwnerState::parse(&store.load_outbox_owner_state(1).unwrap().unwrap()).unwrap();
        assert_eq!(owner.g, 1);
        assert_eq!(
            owner.closed.map(|closed| (closed.g, closed.n)),
            Some((0, 2))
        );
        let queued = outbox_bytes(&path);
        assert_eq!(parse_lines(&queued).lines.len(), 2);
        let before = fs::read(&path).unwrap();
        drop(writer);
        let mut writer = AuditWriter::open(
            path.clone(),
            Some(KeyedAuditAccess::new(Zeroizing::new(ROW_KEY), store)),
        )
        .unwrap();
        assert_eq!(writer.drain_outbox().unwrap(), 0);
        assert_eq!(
            fs::read(&path).unwrap(),
            before,
            "no row is delivered twice"
        );
        assert_eq!(outbox_bytes(&path), test_seam::generation_line(&ROW_KEY, 1));
    }

    #[test]
    fn inspection_counts_tagged_rows_without_the_key() {
        let (_dir, path, store, _writer) = keyed_fixture();
        let raw = AuditOutbox::for_log(&path, store.clone());
        raw.append(&row("raw")).unwrap();
        keyed_outbox(&path, &store).append(&row("tagged")).unwrap();
        let mut bytes = outbox_bytes(&path);
        let mut forged = encode_tagged_row(&ROW_KEY, 9, 17, 1, &own_row("forged")).unwrap();
        let end = forged.len();
        forged[end - 3] = if forged[end - 3] == b'0' { b'1' } else { b'0' };
        bytes.extend_from_slice(&forged);
        bytes.extend_from_slice(b"\nnot JSON\n{\"k\":\"row\"}\n");
        bytes.extend_from_slice(&signed_body(b"{}", b"stellar-agent-outbox-row:v2"));
        bytes.extend_from_slice(b"\ntorn");
        fs::write(outbox_path(&path), bytes).unwrap();
        assert_eq!(
            inspect_outbox(&path).unwrap(),
            OutboxInspection {
                pending: 6,
                torn_bytes: 4,
                unparseable_lines: vec![4, 5, 6],
            }
        );
    }

    /// A consent-shaped row with a fixed request id.
    fn row(request_id: &str) -> AuditEntry {
        AuditEntry::new_approval_attested(
            "PaymentSimulated",
            "stellar_pay_commit",
            None,
            "ABCDEFGHIJKLMNOPQRSTUV",
            "cli",
            request_id,
        )
    }

    fn own_row(request_id: &str) -> AuditEntry {
        AuditEntry::new_tool_invocation(NewToolInvocation::new(
            "stellar_pay_commit",
            "stellar:testnet",
            vec![],
            PolicyDecision::Allow,
            request_id.to_owned(),
        ))
    }

    fn log_path(dir: &TempDir) -> PathBuf {
        dir.path().join("audit").join("audit.jsonl")
    }

    /// A draining writer: opened with a tip-anchor store in `Check` mode.
    fn open_draining(path: &Path, store: &Arc<InMemoryTipAnchorStore>) -> AuditWriter {
        AuditWriter::open_with_tip_anchor(
            path.to_path_buf(),
            None,
            Arc::clone(store) as Arc<dyn TipAnchorStore>,
            crate::audit_log::BindingHistory::NotRecorded,
        )
        .unwrap()
    }

    /// Every row in the log, as JSON.
    fn log_rows(path: &Path) -> Vec<serde_json::Value> {
        fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn request_ids(path: &Path) -> Vec<String> {
        log_rows(path)
            .iter()
            .map(|row| row["request_id"].as_str().unwrap().to_owned())
            .collect()
    }

    fn outbox_bytes(path: &Path) -> Vec<u8> {
        fs::read(outbox_path(path)).unwrap_or_default()
    }

    /// Commits every complete line of the outbox as it stands, as a
    /// commitment over those exact bytes would.
    fn commit_every_line(path: &Path, store: &InMemoryTipAnchorStore) {
        let bytes = outbox_bytes(path);
        let lines = parse_lines(&bytes).lines;
        store
            .store_outbox_state(1, &OutboxState::over(&lines))
            .unwrap();
    }

    /// Appends `line` and its newline to the outbox and syncs it without
    /// touching the commitment, as an append that stopped before its state
    /// write leaves it.
    fn plant_uncommitted(path: &Path, line: &[u8]) {
        let outbox = outbox_path(path);
        let mut bytes = line.to_vec();
        bytes.push(b'\n');
        write_line(&mut open_outbox_0600(&outbox).unwrap(), &outbox, &bytes).unwrap();
    }

    #[test]
    fn append_and_drain_round_trip() {
        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);
        let store = bound_store(&path);
        let outbox = AuditOutbox::for_log(&path, store.clone());
        outbox.append(&row("queued-1")).unwrap();
        outbox.append(&row("queued-2")).unwrap();
        assert_eq!(inspect_outbox(&path).unwrap().pending, 2);

        let mut writer = AuditWriter::open_for_reanchor(path.clone(), None, store.clone()).unwrap();
        assert!(!writer.drains_outbox(), "an unkeyed writer does not drain");
        assert_eq!(writer.drain_outbox().unwrap(), 2);
        assert_eq!(request_ids(&path), vec!["queued-1", "queued-2"]);
        assert!(
            outbox_bytes(&path).is_empty(),
            "the drain empties the outbox"
        );
        assert_eq!(writer.drain_outbox().unwrap(), 0);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = fs::metadata(outbox_path(&path))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn a_failing_append_leaves_the_outbox_byte_identical() {
        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);
        let store = bound_store(&path);
        let outbox = AuditOutbox::for_log(&path, store.clone());
        outbox.append(&row("kept")).unwrap();
        let before = outbox_bytes(&path);

        test_seam::arm_partial_write(outbox.path(), 17);
        let err = outbox.append(&row("refused")).unwrap_err();
        test_seam::disarm(outbox.path());
        assert!(matches!(err, WriterError::Io(_)), "{err:?}");
        assert_eq!(
            outbox_bytes(&path),
            before,
            "a refused append truncates back to where it started"
        );
    }

    /// A partial-write fault belongs to one outbox: consuming or disarming
    /// the fault of one outbox leaves another outbox's fault armed.
    #[test]
    fn a_partial_write_fault_is_kept_per_outbox() {
        let dir = TempDir::new().unwrap();
        let consumed = AuditOutbox::for_log(
            &dir.path().join("consumed").join("audit.jsonl"),
            bound_store(&dir.path().join("consumed").join("audit.jsonl")),
        );
        let kept = AuditOutbox::for_log(
            &dir.path().join("kept").join("audit.jsonl"),
            bound_store(&dir.path().join("kept").join("audit.jsonl")),
        );
        let disarmed = AuditOutbox::for_log(
            &dir.path().join("disarmed").join("audit.jsonl"),
            bound_store(&dir.path().join("disarmed").join("audit.jsonl")),
        );
        test_seam::arm_partial_write(consumed.path(), 3);
        test_seam::arm_partial_write(kept.path(), 3);
        test_seam::arm_partial_write(disarmed.path(), 3);

        let first = consumed.append(&row("refused"));
        assert!(
            matches!(first, Err(WriterError::Io(_))),
            "the fault armed for this outbox fires: {first:?}"
        );
        consumed
            .append(&row("accepted"))
            .expect("the fault is consumed by the append it fired on");
        test_seam::disarm(disarmed.path());
        disarmed
            .append(&row("accepted"))
            .expect("a disarmed fault does not fire");

        let other = kept.append(&row("refused"));
        test_seam::disarm(kept.path());
        assert!(
            matches!(other, Err(WriterError::Io(_))),
            "the other outbox's fault stays armed: {other:?}"
        );
    }

    #[test]
    fn a_torn_tail_is_dropped_by_the_next_append_and_only_that_append_drains() {
        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);
        let store = bound_store(&path);
        let outbox = AuditOutbox::for_log(&path, store.clone());
        // An append that never returned: a partial line, no newline.
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(outbox_path(&path), b"{\"ts\":\"2026-").unwrap();

        outbox.append(&row("after-the-tear")).unwrap();
        let mut writer = AuditWriter::open_for_reanchor(path.clone(), None, store.clone()).unwrap();
        assert_eq!(writer.drain_outbox().unwrap(), 1);
        assert_eq!(request_ids(&path), vec!["after-the-tear"]);
    }

    #[test]
    fn a_torn_final_line_at_drain_is_discarded_and_the_complete_lines_drain() {
        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);
        let store = bound_store(&path);
        let outbox = AuditOutbox::for_log(&path, store.clone());
        outbox.append(&row("complete-1")).unwrap();
        outbox.append(&row("complete-2")).unwrap();
        let mut file = OpenOptions::new()
            .append(true)
            .open(outbox_path(&path))
            .unwrap();
        file.write_all(b"{\"ts\":\"torn").unwrap();
        drop(file);
        assert_eq!(inspect_outbox(&path).unwrap().torn_bytes, 11);

        let mut writer = AuditWriter::open_for_reanchor(path.clone(), None, store.clone()).unwrap();
        assert_eq!(writer.drain_outbox().unwrap(), 2);
        assert_eq!(request_ids(&path), vec!["complete-1", "complete-2"]);
        assert!(
            outbox_bytes(&path).is_empty(),
            "the tail goes with the drain"
        );
    }

    #[test]
    fn a_complete_unparseable_line_fails_the_drain_and_leaves_the_outbox_untouched() {
        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);
        let store = bound_store(&path);
        let outbox = AuditOutbox::for_log(&path, store.clone());
        outbox.append(&row("good")).unwrap();
        let mut file = OpenOptions::new()
            .append(true)
            .open(outbox_path(&path))
            .unwrap();
        file.write_all(b"not an audit entry\n").unwrap();
        drop(file);
        // A committed line that does not parse: only a committed line reaches
        // the parse, since a line past the commitment refuses before it.
        commit_every_line(&path, &store);
        let before = outbox_bytes(&path);

        let mut writer = AuditWriter::open_for_reanchor(path.clone(), None, store.clone()).unwrap();
        let err = writer.drain_outbox().unwrap_err();
        assert!(
            matches!(err, WriterError::OutboxUnusable { line: 2, .. }),
            "{err:?}"
        );
        assert!(
            err.to_string().starts_with("audit.outbox_unusable"),
            "{err}"
        );
        assert_eq!(outbox_bytes(&path), before, "the outbox is left as it was");
        assert!(log_rows(&path).is_empty(), "nothing is appended");
        assert_eq!(inspect_outbox(&path).unwrap().unparseable_lines, vec![2]);
    }

    /// The refusal names the line, the column, and the class of the failure,
    /// and none of the line's content: the parser's own message would quote
    /// a planted value back into agent and CLI envelopes.
    #[test]
    fn an_unusable_outbox_line_is_reported_without_its_content() {
        const MARKER: &str = "planted-outbox-marker";
        let entry = serde_json::to_value(row("planted")).unwrap();
        let mut unknown_kind = entry.clone();
        unknown_kind["kind"] = serde_json::json!(MARKER);
        let mut string_in_a_typed_field = entry;
        string_in_a_typed_field["truncated"] = serde_json::json!(MARKER);
        for planted in [unknown_kind, string_in_a_typed_field] {
            let line = format!("{planted}\n");
            assert!(
                serde_json::from_str::<AuditEntry>(&line)
                    .unwrap_err()
                    .to_string()
                    .contains(MARKER),
                "the parser's own message quotes this line: {line}"
            );
            let dir = TempDir::new().unwrap();
            let path = log_path(&dir);
            let store = bound_store(&path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(outbox_path(&path), line.as_bytes()).unwrap();
            commit_every_line(&path, &store);

            let mut writer =
                AuditWriter::open_for_reanchor(path.clone(), None, store.clone()).unwrap();
            let err = writer.drain_outbox().unwrap_err();
            assert!(
                matches!(err, WriterError::OutboxUnusable { line: 1, .. }),
                "{line}: {err:?}"
            );
            let detail = crate::audit_log::writer::audit_log_unusable_detail(&err).unwrap();
            assert!(detail.starts_with("audit.outbox_unusable"), "{detail}");
            for rendered in [err.to_string(), format!("{err:?}"), detail] {
                assert!(!rendered.contains(MARKER), "{line}: {rendered}");
            }
        }
    }

    /// An outbox whose existence cannot be determined refuses the drain with
    /// an I/O error: it is never read as an absent, empty outbox.
    // Unix only: Windows reports a path below a regular file as not found.
    #[cfg(unix)]
    #[test]
    fn an_outbox_whose_existence_cannot_be_read_refuses_the_drain() {
        let dir = TempDir::new().unwrap();
        // A regular file where the audit directory belongs: every path below
        // it fails to stat with "not a directory".
        fs::write(dir.path().join("audit"), b"not a directory").unwrap();
        let path = log_path(&dir);
        let store = Arc::new(InMemoryTipAnchorStore::new());
        match OutboxBatch::take(&path, store.as_ref()) {
            Err(WriterError::Io(_)) => {}
            Err(other) => panic!("expected an I/O error, got {other:?}"),
            Ok(batch) => panic!(
                "an unreadable outbox read as {}",
                if batch.is_some() { "a batch" } else { "absent" }
            ),
        }
    }

    #[test]
    fn a_refusal_on_the_second_of_three_appends_leaves_the_outbox_byte_identical() {
        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);
        let store = bound_store(&path);
        let outbox = AuditOutbox::for_log(&path, store.clone());
        for id in ["one", "two", "three"] {
            outbox.append(&row(id)).unwrap();
        }
        let before = outbox_bytes(&path);

        let mut writer = AuditWriter::open_for_reanchor(path.clone(), None, store.clone()).unwrap();
        writer.set_appends_before_fault(Some(1));
        writer.drain_outbox().unwrap_err();
        assert_eq!(
            outbox_bytes(&path),
            before,
            "a partial drain leaves every queued row in place"
        );
        assert_eq!(request_ids(&path), vec!["one"]);

        // The next drain appends all three again: delivery is at least once.
        writer.set_appends_before_fault(None);
        assert_eq!(writer.drain_outbox().unwrap(), 3);
        assert_eq!(request_ids(&path), vec!["one", "one", "two", "three"]);
    }

    #[test]
    fn concurrent_appends_from_two_threads_both_drain() {
        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);
        let store = bound_store(&path);
        // The outbox lock is not fair, and unbounded contention can outlast
        // `OUTBOX_LOCK_WAIT`. Each round lets a worker wait for at most one append
        // of the other.
        let barrier = std::sync::Barrier::new(2);
        let joined: Vec<_> = std::thread::scope(|scope| {
            let workers: Vec<_> = (0..2)
                .map(|t| {
                    let path = &path;
                    let store = &store;
                    let barrier = &barrier;
                    scope.spawn(move || {
                        let outbox = AuditOutbox::for_log(path, store.clone());
                        let mut rounds = Vec::with_capacity(10);
                        for i in 0..10 {
                            barrier.wait();
                            let result =
                                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                    outbox
                                        .append(&row(&format!("thread-{t}-{i}")))
                                        .map_err(|error| format!("{error:?}"))
                                }))
                                .unwrap_or_else(|_| Err("panicked".to_owned()));
                            rounds.push(result);
                        }
                        rounds
                    })
                })
                .collect();
            workers.into_iter().map(|worker| worker.join()).collect()
        });
        for (t, worker) in joined.into_iter().enumerate() {
            let rounds = worker.unwrap_or_else(|_| panic!("worker {t} panicked"));
            for (i, result) in rounds.into_iter().enumerate() {
                assert!(result.is_ok(), "worker {t}, round {i}: {result:?}");
            }
        }
        let mut writer = AuditWriter::open_for_reanchor(path.clone(), None, store.clone()).unwrap();
        assert_eq!(writer.drain_outbox().unwrap(), 20);
        let mut ids = request_ids(&path);
        ids.sort();
        let mut expected: Vec<String> = (0..2)
            .flat_map(|t| (0..10).map(move |i| format!("thread-{t}-{i}")))
            .collect();
        expected.sort();
        assert_eq!(ids, expected);
    }

    #[test]
    fn a_draining_writer_drains_at_open_before_any_append() {
        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);
        let store = bound_store(&path);
        AuditOutbox::for_log(&path, store.clone())
            .append(&row("queued-while-closed"))
            .unwrap();
        let writer = open_draining(&path, &store);
        assert!(writer.drains_outbox());
        assert_eq!(
            request_ids(&path),
            vec!["queued-while-closed"],
            "the open drained the row before anything was appended"
        );
        assert!(outbox_bytes(&path).is_empty());
        assert!(
            drain_lock_is_held(&path, store.as_ref()).unwrap(),
            "the writer holds the drain lock"
        );
        drop(writer);
        assert!(
            !drain_lock_is_held(&path, store.as_ref()).unwrap(),
            "released with the writer"
        );
    }

    #[test]
    fn a_writer_without_an_anchor_store_neither_drains_nor_holds_the_drain_lock() {
        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);
        let store = bound_store(&path);
        AuditOutbox::for_log(&path, store.clone())
            .append(&row("queued"))
            .unwrap();
        let mut writer = AuditWriter::open(path.clone(), None).unwrap();
        assert!(!drain_lock_is_held(&path, store.as_ref()).unwrap());
        writer.write_entry(own_row("own")).unwrap();
        assert_eq!(request_ids(&path), vec!["own"], "write_entry did not drain");
        assert_eq!(inspect_outbox(&path).unwrap().pending, 1);
    }

    #[test]
    fn an_opener_that_loses_the_sidecar_never_touches_the_drain_lock() {
        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);
        let _holder = AuditWriter::open(path.clone(), None).unwrap();
        let store = Arc::new(InMemoryTipAnchorStore::new());
        let err = AuditWriter::open_with_tip_anchor(
            path.clone(),
            None,
            Arc::clone(&store) as Arc<dyn TipAnchorStore>,
            crate::audit_log::BindingHistory::NotRecorded,
        )
        .unwrap_err();
        assert!(matches!(err, WriterError::FileLocked), "{err:?}");
        assert!(
            !drain_lock_path(&path).exists(),
            "the drain lock is taken only after the sidecar lock"
        );
    }

    #[test]
    fn a_registry_cache_hit_drains_with_no_append_of_its_own() {
        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);
        let store = bound_store(&path);
        let key = || Zeroizing::new([0x42_u8; 32]);
        let access = || KeyedAuditAccess::new(key(), store.clone() as Arc<dyn TipAnchorStore>);
        let profile = "outbox-cache-hit";
        let _first = AuditWriterRegistry::get_or_open_keyed(profile, &path, access()).unwrap();
        let rows_at_open = log_rows(&path);
        assert_eq!(rows_at_open.len(), 1);
        assert_eq!(rows_at_open[0]["kind"], "audit_entry_tags_started");
        let mut expected = request_ids(&path);
        AuditOutbox::for_log(&path, store.clone())
            .append(&row("queued-after-open"))
            .unwrap();
        let _second = AuditWriterRegistry::get_or_open_keyed(profile, &path, access()).unwrap();
        expected.push("queued-after-open".to_owned());
        assert_eq!(request_ids(&path), expected);
        assert!(outbox_bytes(&path).is_empty());
    }

    /// Sixty-four queued rows fit. Row 65 refuses with `audit.outbox_full`,
    /// leaves the outbox and its commitment byte for byte, and evicts nothing.
    /// After a drain the next row queues again.
    #[test]
    fn sixty_four_rows_fit_and_the_next_refuses_without_eviction() {
        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);
        let store = bound_store(&path);
        let outbox = AuditOutbox::for_log(&path, store.clone());
        for index in 1..=MAX_OUTBOX_ROWS {
            outbox
                .append(&row(&format!("row-{index}")))
                .unwrap_or_else(|e| panic!("row {index} fits: {e:?}"));
        }
        assert_eq!(MAX_OUTBOX_ROWS, 64);
        let before = outbox_bytes(&path);
        let committed = store.load_outbox_state(1).unwrap();

        let refused = outbox.append(&row("row-65")).unwrap_err();
        assert!(
            matches!(
                refused,
                WriterError::OutboxFull {
                    queued: 64,
                    cap: 64
                }
            ),
            "{refused:?}"
        );
        assert!(refused.to_string().starts_with("audit.outbox_full: "));
        let refusal = crate::audit_log::audit_writer_refusal("fixture", &refused);
        assert_eq!(refusal.code(), "audit.outbox_full");
        assert_eq!(outbox_bytes(&path), before, "nothing is queued or evicted");
        assert_eq!(store.load_outbox_state(1).unwrap(), committed);

        let mut writer = AuditWriter::open_for_reanchor(path.clone(), None, store.clone()).unwrap();
        assert_eq!(writer.drain_outbox().unwrap(), 64);
        let expected: Vec<String> = (1..=64).map(|index| format!("row-{index}")).collect();
        assert_eq!(request_ids(&path), expected, "row 1 is delivered first");
        drop(writer);
        outbox.append(&row("row-65")).unwrap();
    }

    /// With 63 rows queued, two appends race for the last slot. The first
    /// pauses after its admission, under the outbox lock, until the second
    /// is observed waiting on that lock. Exactly one row is admitted, the
    /// other append refuses with `audit.outbox_full`, and the outbox holds
    /// 64 rows.
    #[test]
    fn the_last_slot_goes_to_exactly_one_of_two_racing_appends() {
        use std::sync::mpsc::channel;
        use std::time::Duration;

        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);
        let store = bound_store(&path);
        let outbox = AuditOutbox::for_log(&path, store.clone());
        for index in 1..MAX_OUTBOX_ROWS {
            outbox.append(&row(&format!("row-{index}"))).unwrap();
        }

        let (admitted, first_admitted) = channel();
        let (contended, second_waits) = channel();
        test_seam::on_admitted(outbox.path(), move || {
            admitted.send(()).unwrap();
            second_waits
                .recv_timeout(Duration::from_secs(30))
                .expect("the second append waits on the outbox lock");
        });
        test_seam::on_contended(&outbox_lock_path(&path), move || {
            contended.send(()).unwrap();
        });

        let (first, second) = std::thread::scope(|scope| {
            let first = scope.spawn(|| outbox.append(&row("first")));
            first_admitted
                .recv_timeout(Duration::from_secs(30))
                .expect("the first append passes admission");
            let second = scope.spawn(|| outbox.append(&row("second")));
            (first.join().unwrap(), second.join().unwrap())
        });

        assert!(first.is_ok(), "the first append takes the slot: {first:?}");
        let refused = second.unwrap_err();
        assert!(
            matches!(
                refused,
                WriterError::OutboxFull {
                    queued: 64,
                    cap: 64
                }
            ),
            "{refused:?}"
        );
        assert_eq!(
            crate::audit_log::audit_writer_refusal("fixture", &refused).code(),
            "audit.outbox_full"
        );
        assert_eq!(inspect_outbox(&path).unwrap().pending, 64);
    }

    /// A consent row whose line, measured as a keyed writer appends it, is
    /// exactly `len` bytes with its newline.
    fn consent_row_of_len(request_id: &str, len: u64) -> AuditEntry {
        let mut entry = row(request_id);
        entry.arg_keys.clear();
        entry.truncated = true;
        entry.chain_id = Some(String::new());
        let measured = |entry: &AuditEntry| {
            let mut probe = entry.clone();
            probe.previous_entry_hash = crate::audit_log::chain::ZERO_BLOCK_HASH.to_owned();
            probe.entry_tag = Some(crate::audit_log::chain::ZERO_BLOCK_HASH.to_owned());
            serde_json::to_vec(&probe).unwrap().len() as u64 + 1
        };
        let pad = usize::try_from(len - measured(&entry)).unwrap();
        entry.chain_id = Some("x".repeat(pad));
        assert_eq!(measured(&entry), len);
        entry
    }

    /// The outbox measures a row as the keyed writer appends it. A row at
    /// the one-MiB cap queues and drains through a keyed writer. A row one
    /// byte over refuses with `audit.outbox_row_too_large`, although its own
    /// outbox line is shorter than the cap, and queues nothing.
    #[test]
    fn one_mib_writer_row_boundary_refuses_before_approval_storage() {
        use super::super::writer::MAX_ROW_BYTES;
        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);
        let store = bound_store(&path);
        let outbox = AuditOutbox::for_log(&path, store.clone());

        let over = consent_row_of_len("over", MAX_ROW_BYTES + 1);
        let over_line = serde_json::to_vec(&over).unwrap().len() as u64 + 1;
        assert!(
            over_line <= MAX_ROW_BYTES,
            "the outbox line alone fits the cap: {over_line}"
        );
        let refused = outbox.append(&over).unwrap_err();
        assert!(
            matches!(
                refused,
                WriterError::OutboxRowTooLarge { bytes, cap: MAX_ROW_BYTES }
                    if bytes == MAX_ROW_BYTES + 1
            ),
            "{refused:?}"
        );
        let refusal = crate::audit_log::audit_writer_refusal("fixture", &refused);
        assert_eq!(refusal.code(), "audit.outbox_row_too_large");
        assert!(outbox_bytes(&path).is_empty(), "nothing is queued");

        // An admitted row at the cap drains through a keyed writer, an
        // unkeyed writer, and a keyed writer that rotates before every row.
        // The keyed line is exactly the cap; the unkeyed line omits the tag.
        for (state, keyed, rotating) in [
            ("keyed", true, false),
            ("unkeyed", false, false),
            ("keyed across rotation", true, true),
        ] {
            let dir = TempDir::new().unwrap();
            let path = log_path(&dir);
            let store = bound_store(&path);
            let outbox = AuditOutbox::for_log(&path, store.clone());
            outbox
                .append(&consent_row_of_len("at-cap", MAX_ROW_BYTES))
                .unwrap();
            outbox.append(&row("after")).unwrap();
            let _threshold = rotating
                .then(|| super::super::rotation::test_seam::set_rotation_threshold(&path, 1));
            let writer = if keyed {
                let access = KeyedAuditAccess::new(Zeroizing::new([0x42; 32]), store.clone());
                AuditWriter::open(path.clone(), Some(access)).unwrap()
            } else {
                open_draining(&path, &store)
            };
            drop(writer);
            let lines = every_log_line(&path);
            let delivered_ids: Vec<String> = lines
                .iter()
                .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
                .filter_map(|row| row["request_id"].as_str().map(str::to_owned))
                .filter(|id| ["at-cap", "after"].contains(&id.as_str()))
                .collect();
            assert_eq!(delivered_ids, ["at-cap", "after"], "{state}: both drain");
            let at_cap = lines
                .iter()
                .find(|line| line.contains(r#""request_id":"at-cap""#))
                .unwrap();
            let length = at_cap.len() as u64 + 1;
            if keyed {
                assert_eq!(length, MAX_ROW_BYTES, "{state}");
            } else {
                assert!(length < MAX_ROW_BYTES, "{state}: {length}");
            }
            if rotating {
                assert!(
                    !fs::read_to_string(&path)
                        .unwrap()
                        .contains(r#""request_id":"at-cap""#),
                    "{state}: a rotation follows the row"
                );
            }
            assert!(outbox_bytes(&path).is_empty(), "{state}");
        }
    }

    /// Every line of the active file and of its numbered archives, archives
    /// first in name order.
    fn every_log_line(path: &Path) -> Vec<String> {
        let name = path.file_name().unwrap().to_str().unwrap().to_owned();
        let mut archives: Vec<PathBuf> = fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|candidate| {
                let file = candidate.file_name().unwrap().to_str().unwrap();
                file.strip_prefix(&format!("{name}."))
                    .is_some_and(|suffix| suffix.starts_with(|c: char| c.is_ascii_digit()))
                    && !file.ends_with(".root_hmac")
            })
            .collect();
        archives.sort();
        archives.push(path.to_path_buf());
        archives
            .iter()
            .flat_map(|file| {
                fs::read_to_string(file)
                    .unwrap_or_default()
                    .lines()
                    .filter(|line| !line.trim().is_empty())
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    #[test]
    fn drained_rows_precede_the_writers_own_row_and_keep_their_consent_timestamps() {
        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);
        let store = bound_store(&path);
        let mut writer = open_draining(&path, &store);
        let mut queued = row("consent");
        queued.ts = "2026-01-02T03:04:05.000Z".to_owned();
        AuditOutbox::for_log(&path, store.clone())
            .append(&queued)
            .unwrap();

        writer.write_entry(own_row("own")).unwrap();
        let rows = log_rows(&path);
        assert_eq!(
            rows.iter()
                .map(|row| row["request_id"].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec!["consent", "own"]
        );
        assert_eq!(rows[0]["ts"], "2026-01-02T03:04:05.000Z");
    }

    /// A drain whose commitment reset fails has appended its rows and still
    /// holds a committed outbox, so the next drain appends them once more:
    /// delivery is at least once.
    #[test]
    fn a_drain_whose_commitment_reset_fails_repeats_its_rows_once() {
        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);
        let store = bound_store(&path);
        {
            let mut writer = open_draining(&path, &store);
            AuditOutbox::for_log(&path, store.clone())
                .append(&row("repeated"))
                .unwrap();
            store.set_outbox_failing(false, true);
            assert!(matches!(
                writer.drain_outbox(),
                Err(WriterError::TipAnchorStore(_))
            ));
            store.set_outbox_failing(false, false);
        }
        let _reopened = open_draining(&path, &store);
        assert_eq!(request_ids(&path), vec!["repeated", "repeated"]);
        assert!(outbox_bytes(&path).is_empty());
    }

    /// A crash between a drain's commitment reset and its truncation leaves a
    /// zero commitment and lines that are the log's last rows: the next drain
    /// truncates them without appending them again.
    #[test]
    fn a_crash_between_the_reset_and_the_truncate_appends_the_rows_once() {
        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);
        let store = bound_store(&path);
        {
            let mut writer = open_draining(&path, &store);
            AuditOutbox::for_log(&path, store.clone())
                .append(&row("delivered"))
                .unwrap();
            writer.set_skip_outbox_truncate(true);
            assert_eq!(writer.drain_outbox().unwrap(), 1);
        }
        assert!(!outbox_bytes(&path).is_empty(), "the crash kept the outbox");
        let _reopened = open_draining(&path, &store);
        assert_eq!(request_ids(&path), vec!["delivered"]);
        assert!(outbox_bytes(&path).is_empty());
    }

    /// A signer-set baseline whose `prev_chain_tip_hash` is the writer's tip
    /// at the moment it is built.
    fn baseline_built_from(writer: &AuditWriter) -> AuditEntry {
        use crate::audit_log::signer_set::{
            BaselineReason, SignerEntryV2, SignerIdentityV2, SignerSetSnapshotV2,
        };

        let snapshot = SignerSetSnapshotV2 {
            signers: vec![SignerEntryV2 {
                id: 0,
                identity: SignerIdentityV2::Ed25519 { pubkey: [0x22; 32] },
            }],
            threshold: None,
        };
        AuditEntry::new_sa_signer_set_baselined_v2(
            1,
            &snapshot,
            1000,
            1_700_000_000_000,
            BaselineReason::first_observation(),
            writer.current_chain_tip(),
            [0x33; 32],
            crate::observability::RedactedStrkey::from_already_redacted("CAAAA...AAAAA"),
            "stellar:testnet",
            "baseline",
        )
    }

    /// Asserts that a baseline row's two predecessor fields name one entry.
    fn assert_predecessors_agree(baseline: &serde_json::Value) {
        assert_eq!(
            baseline["prev_chain_tip_hash"].as_str().unwrap(),
            baseline["previous_entry_hash"]
                .as_str()
                .unwrap()
                .strip_prefix("sha256:")
                .unwrap(),
            "prev_chain_tip_hash names the row this one directly follows: {baseline}"
        );
    }

    /// The rows of the newest rotated archive of the log at `path`.
    fn archive_rows(path: &Path) -> Vec<serde_json::Value> {
        let name = path.file_name().unwrap().to_str().unwrap().to_owned();
        let mut archives: Vec<PathBuf> = fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|candidate| {
                let file = candidate.file_name().unwrap().to_str().unwrap();
                file.strip_prefix(&format!("{name}."))
                    .is_some_and(|suffix| suffix.starts_with(|c: char| c.is_ascii_digit()))
                    && !file.ends_with(".root_hmac")
            })
            .collect();
        archives.sort();
        archives
            .last()
            .map(|archive| log_rows(archive))
            .unwrap_or_default()
    }

    #[test]
    fn write_built_names_the_drained_row_as_its_predecessor() {
        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);
        let store = bound_store(&path);
        let mut writer = open_draining(&path, &store);
        writer.write_entry(own_row("first")).unwrap();
        AuditOutbox::for_log(&path, store.clone())
            .append(&row("queued"))
            .unwrap();

        writer.write_built(baseline_built_from).unwrap();
        let rows = log_rows(&path);
        assert_eq!(
            rows.iter()
                .map(|row| row["request_id"].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec!["first", "queued", "baseline"],
            "the drain runs before the build"
        );
        assert_predecessors_agree(&rows[2]);
    }

    /// At the rotation boundary: the drained row fills the active file, so the
    /// append rotates. The rotation completes before `build` reads the tip, so
    /// both predecessor fields of the baseline name the rotation's handoff.
    #[test]
    fn write_built_names_its_predecessor_across_a_rotation() {
        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);
        let store = bound_store(&path);
        let mut writer = open_draining(&path, &store);
        writer.write_entry(own_row("first")).unwrap();
        AuditOutbox::for_log(&path, store.clone())
            .append(&row("queued"))
            .unwrap();
        // The active file reaches the threshold once the queued row lands.
        let threshold = fs::metadata(&path).unwrap().len() + 1;
        let threshold_guard =
            crate::audit_log::rotation::test_seam::set_rotation_threshold(&path, threshold);
        writer.write_built(baseline_built_from).unwrap();
        drop(threshold_guard);

        let archived = archive_rows(&path);
        assert_eq!(
            archived
                .iter()
                .map(|row| row["kind"].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec![
                "tool_invocation",
                "approval_attested",
                "audit_rotation_handoff"
            ],
            "the drained row precedes the rotation"
        );
        let rows = log_rows(&path);
        assert_eq!(
            request_ids(&path),
            vec!["baseline"],
            "the baseline opens the new file"
        );
        assert_predecessors_agree(&rows[0]);
    }

    #[test]
    fn an_outbox_lock_held_past_the_wait_is_outbox_busy() {
        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);
        let store = bound_store(&path);
        let outbox = AuditOutbox::for_log(&path, store.clone());
        let mut writer = open_draining(&path, &store);
        outbox.append(&row("queued")).unwrap();
        let held = AuditWriterLock::acquire(&outbox_lock_path(&path)).unwrap();

        let started = Instant::now();
        let err = outbox.append(&row("refused")).unwrap_err();
        assert!(matches!(err, WriterError::OutboxBusy), "{err:?}");
        assert!(started.elapsed() >= OUTBOX_LOCK_WAIT);
        assert!(err.to_string().starts_with("audit.outbox_busy"), "{err}");

        let err = writer.drain_outbox().unwrap_err();
        assert!(matches!(err, WriterError::OutboxBusy), "{err:?}");
        drop(held);
        assert_eq!(writer.drain_outbox().unwrap(), 1);
    }

    fn committed_pair() -> (TempDir, PathBuf, Arc<InMemoryTipAnchorStore>, AuditWriter) {
        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);
        let store = bound_store(&path);
        let writer = open_draining(&path, &store);
        let outbox = AuditOutbox::for_log(&path, store.clone());
        outbox.append(&row("one")).unwrap();
        outbox.append(&row("two")).unwrap();
        (dir, path, store, writer)
    }

    #[test]
    fn append_commits_the_count_and_the_head() {
        let (_dir, path, store, _writer) = committed_pair();
        let state = store.load_outbox_state(1).unwrap().unwrap();
        assert_eq!(state.pending, 2);
        let mut head = [0; 32];
        for line in outbox_bytes(&path).split_inclusive(|b| *b == b'\n') {
            let mut hash = Sha256::new();
            hash.update(b"stellar-agent-outbox:v1");
            hash.update(head);
            hash.update(&line[..line.len() - 1]);
            head = hash.finalize().into();
        }
        assert_eq!(state.head, head);
    }

    fn assert_changed_queue_refuses(change: impl FnOnce(&Path), found: u64) {
        let (_dir, path, store, mut writer) = committed_pair();
        change(&outbox_path(&path));
        let bytes = fs::read(outbox_path(&path)).ok();
        let log = fs::read(&path).unwrap();
        let state = store.load_outbox_state(1).unwrap();
        assert!(matches!(writer.drain_outbox(),
            Err(WriterError::OutboxRowsMissing { recorded: 2, found: n }) if n == found));
        assert_eq!(fs::read(outbox_path(&path)).ok(), bytes);
        assert_eq!(fs::read(&path).unwrap(), log);
        assert_eq!(store.load_outbox_state(1).unwrap(), state);
    }

    fn remove_first_line(path: &Path) {
        let bytes = fs::read(path).unwrap();
        let end = bytes.iter().position(|b| *b == b'\n').unwrap() + 1;
        fs::write(path, &bytes[end..]).unwrap();
    }

    #[test]
    fn a_drain_after_a_deleted_line_refuses() {
        assert_changed_queue_refuses(remove_first_line, 1);
    }

    #[test]
    fn a_drain_after_a_truncated_outbox_refuses() {
        assert_changed_queue_refuses(|path| fs::write(path, []).unwrap(), 0);
    }

    #[test]
    fn a_drain_after_a_deleted_outbox_refuses() {
        assert_changed_queue_refuses(|path| fs::remove_file(path).unwrap(), 0);
    }

    #[test]
    fn a_drain_after_a_changed_line_refuses() {
        assert_changed_queue_refuses(
            |path| {
                let bytes = fs::read_to_string(path).unwrap().replace("two", "six");
                fs::write(path, bytes).unwrap();
            },
            2,
        );
    }

    #[test]
    fn a_drain_after_reordered_lines_refuses() {
        assert_changed_queue_refuses(
            |path| {
                let bytes = fs::read_to_string(path).unwrap();
                let mut lines: Vec<_> = bytes.split_inclusive('\n').collect();
                lines.reverse();
                fs::write(path, lines.concat()).unwrap();
            },
            2,
        );
    }

    #[test]
    fn an_append_after_a_deletion_refuses() {
        let (_dir, path, store, _writer) = committed_pair();
        remove_first_line(&outbox_path(&path));
        let bytes = outbox_bytes(&path);
        let state = store.load_outbox_state(1).unwrap();
        assert!(matches!(
            AuditOutbox::for_log(&path, store.clone()).append(&row("three")),
            Err(WriterError::OutboxRowsMissing {
                recorded: 2,
                found: 1
            })
        ));
        assert_eq!(outbox_bytes(&path), bytes);
        assert_eq!(store.load_outbox_state(1).unwrap(), state);
    }

    #[test]
    fn a_state_store_failure_truncates_the_line_back() {
        let (_dir, path, store, _writer) = committed_pair();
        let bytes = outbox_bytes(&path);
        let state = store.load_outbox_state(1).unwrap();
        store.set_outbox_failing(false, true);
        assert!(matches!(
            AuditOutbox::for_log(&path, store.clone()).append(&row("three")),
            Err(WriterError::TipAnchorStore(_))
        ));
        assert_eq!(outbox_bytes(&path), bytes);
        assert_eq!(store.load_outbox_state(1).unwrap(), state);
    }

    /// A complete line past the committed prefix, synced without a
    /// commitment, refuses the drain with everything left as it was.
    #[test]
    fn a_planted_line_past_the_commitment_is_not_drained() {
        let (_dir, path, store, mut writer) = committed_pair();
        plant_uncommitted(&path, &serde_json::to_vec(&row("uncommitted")).unwrap());
        let outbox = outbox_bytes(&path);
        let log = fs::read(&path).unwrap();
        let state = store.load_outbox_state(1).unwrap();
        assert!(matches!(
            writer.drain_outbox(),
            Err(WriterError::OutboxRowsMissing {
                recorded: 2,
                found: 3
            })
        ));
        assert_eq!(fs::read(&path).unwrap(), log, "nothing is appended");
        assert_eq!(outbox_bytes(&path), outbox, "the outbox is unchanged");
        assert_eq!(store.load_outbox_state(1).unwrap(), state);
    }

    #[test]
    fn revocation_row_refuses_operator_outbox() {
        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);
        let store = bound_store(&path);
        let mut writer = open_draining(&path, &store);
        let entry = AuditEntry::new_approval_revoked(
            "PaymentSimulated",
            "abcdefgh-secret",
            crate::approval::Surface::Cli,
            None,
            "revoke",
        );
        AuditOutbox::for_log(&path, store.clone())
            .append(&entry)
            .unwrap();
        let outbox = outbox_bytes(&path);
        let log = fs::read(&path).unwrap();
        let state = store.load_outbox_state(1).unwrap();
        assert!(matches!(
            writer.drain_outbox(),
            Err(WriterError::OutboxRowKindRefused { line: 1 })
        ));
        assert_eq!(outbox_bytes(&path), outbox);
        assert_eq!(fs::read(&path).unwrap(), log);
        assert_eq!(store.load_outbox_state(1).unwrap(), state);
    }

    /// A committed line of a kind other than an operator row refuses the drain
    /// at its line; a remote consent row drains.
    #[test]
    fn a_queued_value_row_is_refused() {
        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);
        let store = bound_store(&path);
        let mut writer = open_draining(&path, &store);
        let failed = AuditEntry::new_value_action_failed(
            "stellar_pay",
            Some("stellar:testnet".to_owned()),
            vec![],
            "6ba7aaac...69060003",
            "submission.failed",
            PolicyDecision::Allow,
            Some("sha256:abcdef01".to_owned()),
            None,
            None,
            "planted-failed",
        );
        AuditOutbox::for_log(&path, store.clone())
            .append(&failed)
            .unwrap();
        let outbox = outbox_bytes(&path);
        let log = fs::read(&path).unwrap();
        let err = writer.drain_outbox().unwrap_err();
        assert!(
            matches!(err, WriterError::OutboxRowKindRefused { line: 1 }),
            "{err:?}"
        );
        assert!(
            err.to_string().starts_with("audit.outbox_unusable"),
            "{err}"
        );
        assert_eq!(
            crate::audit_log::writer::audit_log_unusable_detail(&err),
            Some(err.to_string())
        );
        assert_eq!(fs::read(&path).unwrap(), log);
        assert_eq!(outbox_bytes(&path), outbox);

        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);
        let store = bound_store(&path);
        let mut writer = open_draining(&path, &store);
        AuditOutbox::for_log(&path, store.clone())
            .append(&AuditEntry::new_approval_attested_remote(
                "PaymentSimulated",
                "stellar_pay_commit",
                None,
                "ABCDEFGHIJKLMNOPQRSTUV",
                "credential",
                "remote-consent",
            ))
            .unwrap();
        assert_eq!(writer.drain_outbox().unwrap(), 1);
        assert_eq!(request_ids(&path), ["remote-consent"]);
    }

    /// The halt and resume rows `profile halt` and `profile resume` queue
    /// beside a draining writer drain in queue order, after a consent row.
    #[test]
    fn queued_halt_and_resume_rows_drain() {
        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);
        let store = bound_store(&path);
        let mut writer = open_draining(&path, &store);
        let outbox = AuditOutbox::for_log(&path, store.clone());
        outbox.append(&row("consent")).unwrap();
        outbox
            .append(&AuditEntry::new_profile_halted(
                "default",
                "2026-10-31T12:00:00Z",
                Some("incident"),
                "queued-halt",
            ))
            .unwrap();
        outbox
            .append(&AuditEntry::new_profile_resumed(
                "default",
                true,
                "queued-resume",
            ))
            .unwrap();
        assert_eq!(writer.drain_outbox().unwrap(), 3);
        assert_eq!(
            request_ids(&path),
            ["consent", "queued-halt", "queued-resume"]
        );
        assert!(
            outbox_bytes(&path).is_empty(),
            "the drain truncates the outbox"
        );
    }

    #[test]
    fn a_drain_interrupted_before_its_truncation_is_not_redelivered() {
        let (_dir, path, store, mut writer) = committed_pair();
        writer.set_skip_outbox_truncate(true);
        assert_eq!(writer.drain_outbox().unwrap(), 2);
        assert_eq!(
            store.load_outbox_state(1).unwrap(),
            Some(OutboxState::default())
        );
        drop(writer);
        let _writer = open_draining(&path, &store);
        assert_eq!(request_ids(&path), ["one", "two"]);
        assert!(outbox_bytes(&path).is_empty());
    }

    /// Lines under a zero commitment that are not the log's last rows are
    /// past the commitment: the drain refuses with nothing changed.
    #[test]
    fn an_outbox_line_without_a_state_refuses_the_drain() {
        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);
        let store = bound_store(&path);
        let mut writer = open_draining(&path, &store);
        let mut line = serde_json::to_vec(&row("upgrade")).unwrap();
        line.push(b'\n');
        fs::write(outbox_path(&path), &line).unwrap();
        assert_eq!(store.load_outbox_state(1).unwrap(), None);
        assert!(matches!(
            writer.drain_outbox(),
            Err(WriterError::OutboxRowsMissing {
                recorded: 0,
                found: 1
            })
        ));
        assert!(log_rows(&path).is_empty());
        assert_eq!(outbox_bytes(&path), line);
        assert_eq!(store.load_outbox_state(1).unwrap(), None);
    }

    #[test]
    fn a_keyed_open_after_a_loss_refuses() {
        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);
        let store = bound_store(&path);
        let access = || KeyedAuditAccess::new(Zeroizing::new([0x42; 32]), store.clone());
        let writer = AuditWriter::open(path.clone(), Some(access())).unwrap();
        AuditOutbox::for_log(&path, store.clone())
            .append(&row("lost"))
            .unwrap();
        fs::remove_file(outbox_path(&path)).unwrap();
        drop(writer);
        let err = AuditWriter::open(path, Some(access())).unwrap_err();
        assert!(matches!(
            err,
            WriterError::OutboxRowsMissing {
                recorded: 1,
                found: 0
            }
        ));
        let refusal = crate::audit_log::audit_writer_refusal("fixture", &err);
        assert!(matches!(refusal, crate::error::WalletError::Validation(
            crate::error::ValidationError::AuditLogUnusable { ref detail, .. }
        ) if detail.starts_with("audit.outbox_rows_missing")));
    }

    fn open_acknowledging(path: &Path, store: &Arc<InMemoryTipAnchorStore>) -> AuditWriter {
        AuditWriter::open_for_outbox_acknowledgement(
            path.to_path_buf(),
            None,
            Arc::clone(store) as Arc<dyn TipAnchorStore>,
            crate::audit_log::BindingHistory::NotRecorded,
        )
        .unwrap()
    }

    #[test]
    fn acknowledging_without_a_loss_writes_nothing() {
        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);
        let store = bound_store(&path);
        open_draining(&path, &store)
            .write_entry(own_row("kept"))
            .unwrap();
        let mut writer = open_acknowledging(&path, &store);
        let before = fs::read(&path).unwrap();
        assert!(matches!(
            writer.acknowledge_outbox_loss("inspection", Default::default()),
            Err(WriterError::OutboxLossNotFound)
        ));
        assert_eq!(fs::read(&path).unwrap(), before);
    }

    #[test]
    fn acknowledging_a_lost_prefix_records_it_and_discards_the_rest() {
        let (_dir, path, store, writer) = committed_pair();
        remove_first_line(&outbox_path(&path));
        drop(writer);
        let mut writer = open_acknowledging(&path, &store);
        assert!(drain_lock_is_held(&path, store.as_ref()).unwrap());
        let report = writer
            .acknowledge_outbox_loss(
                "queue inspection",
                crate::audit_log::RevokedCounts {
                    approvals: 3,
                    grants: 4,
                },
            )
            .unwrap();
        assert_eq!(
            (
                report.expected_rows,
                report.found_rows,
                report.drained,
                report.discarded
            ),
            (2, 1, 0, 1)
        );
        let rows = log_rows(&path);
        assert_eq!(rows.len(), 1, "a broken prefix appends nothing");
        assert_eq!(rows[0]["kind"], "audit_outbox_loss_acknowledged");
        assert_eq!(rows[0]["expected_rows"], 2);
        assert_eq!(rows[0]["found_rows"], 1);
        assert_eq!(rows[0]["revoked_approvals"], 3);
        assert_eq!(rows[0]["revoked_grants"], 4);
        assert_eq!(
            store.load_outbox_state(1).unwrap(),
            Some(OutboxState::default())
        );
        assert!(outbox_bytes(&path).is_empty());
        drop(writer);
        let _writer = open_draining(&path, &store);
    }

    /// A committed last line that lost its newline is not a torn tail to
    /// repair: the append refuses on the commitment and leaves the file
    /// byte-identical, so restoring the newline restores the queue.
    #[test]
    fn an_append_over_a_committed_line_without_its_newline_refuses_unchanged() {
        let (_dir, path, store, mut writer) = committed_pair();
        let outbox = AuditOutbox::for_log(&path, store.clone());
        let intact = outbox_bytes(&path);
        let cut = &intact[..intact.len() - 1];
        fs::write(outbox_path(&path), cut).unwrap();
        let state = store.load_outbox_state(1).unwrap();

        assert!(matches!(
            outbox.append(&row("three")),
            Err(WriterError::OutboxRowsMissing {
                recorded: 2,
                found: 1
            })
        ));
        assert_eq!(outbox_bytes(&path), cut, "the outbox is byte-identical");
        assert_eq!(store.load_outbox_state(1).unwrap(), state);

        fs::write(outbox_path(&path), &intact).unwrap();
        outbox.append(&row("three")).unwrap();
        assert_eq!(writer.drain_outbox().unwrap(), 3);
        assert_eq!(request_ids(&path), ["one", "two", "three"]);
    }

    /// A deleted outbox under a nonzero commitment refuses the append, which
    /// does not create a new file either.
    #[test]
    fn an_append_after_a_deleted_outbox_refuses_without_creating_it() {
        let (_dir, path, store, _writer) = committed_pair();
        fs::remove_file(outbox_path(&path)).unwrap();
        let state = store.load_outbox_state(1).unwrap();
        assert!(matches!(
            AuditOutbox::for_log(&path, store.clone()).append(&row("three")),
            Err(WriterError::OutboxRowsMissing {
                recorded: 2,
                found: 0
            })
        ));
        assert!(!outbox_path(&path).exists(), "no outbox is created");
        assert_eq!(store.load_outbox_state(1).unwrap(), state);
    }

    /// An append over a line synced past the commitment refuses: the
    /// commitment covers committed lines only, and the file and the
    /// commitment stay as they were.
    #[test]
    fn an_append_refuses_an_uncommitted_line() {
        let (_dir, path, store, _writer) = committed_pair();
        plant_uncommitted(&path, &serde_json::to_vec(&row("uncommitted")).unwrap());
        let bytes = outbox_bytes(&path);
        let state = store.load_outbox_state(1).unwrap();
        assert!(matches!(
            AuditOutbox::for_log(&path, store.clone()).append(&row("four")),
            Err(WriterError::OutboxRowsMissing {
                recorded: 2,
                found: 3
            })
        ));
        assert_eq!(outbox_bytes(&path), bytes, "the outbox is unchanged");
        assert_eq!(store.load_outbox_state(1).unwrap(), state);
    }

    /// The state parser accepts exactly the value the store writes: a zero
    /// count carries the zero head, and no field beyond the three it defines.
    #[test]
    fn the_state_parser_refuses_values_it_does_not_define() {
        let zero = format!("sha256:{}", "00".repeat(32));
        let nonzero = format!("sha256:{}", "11".repeat(32));
        let mut state = OutboxState::default();
        state.push(b"line");
        assert_eq!(
            OutboxState::parse(&state.to_keyring_value()).unwrap(),
            state
        );
        assert_eq!(
            OutboxState::parse(&OutboxState::default().to_keyring_value()).unwrap(),
            OutboxState::default()
        );
        for refused in [
            format!(r#"{{"v":1,"pending":0,"head":"{nonzero}"}}"#),
            format!(r#"{{"v":1,"pending":0,"head":"{zero}","extra":0}}"#),
            format!(r#"{{"v":1,"pending":1,"head":"{nonzero}","extra":0}}"#),
            format!(r#"{{"v":2,"pending":1,"head":"{nonzero}"}}"#),
            format!(r#"{{"v":1,"pending":1,"head":"{}"}}"#, "11".repeat(32)),
        ] {
            assert!(OutboxState::parse(&refused).is_err(), "{refused}");
        }
    }

    /// The intact committed prefix is parsed before the acknowledgement row:
    /// an unusable committed line refuses the loss report and the
    /// acknowledgement with the log, the outbox, and the commitment unchanged.
    #[test]
    fn an_unusable_committed_line_refuses_the_acknowledgement_with_nothing_written() {
        let (_dir, path, store, writer) = committed_pair();
        let mut file = OpenOptions::new()
            .append(true)
            .open(outbox_path(&path))
            .unwrap();
        file.write_all(b"not an audit entry\n").unwrap();
        drop(file);
        commit_every_line(&path, &store);
        plant_uncommitted(&path, &serde_json::to_vec(&row("past")).unwrap());
        drop(writer);
        let outbox = outbox_bytes(&path);
        let log = fs::read(&path).unwrap();
        let state = store.load_outbox_state(1).unwrap();

        let mut writer = open_acknowledging(&path, &store);
        assert!(matches!(
            writer.outbox_loss(),
            Err(WriterError::OutboxUnusable { line: 3, .. })
        ));
        assert!(matches!(
            writer.acknowledge_outbox_loss("inspection", Default::default()),
            Err(WriterError::OutboxUnusable { line: 3, .. })
        ));
        assert_eq!(fs::read(&path).unwrap(), log, "no acknowledgement row");
        assert_eq!(outbox_bytes(&path), outbox);
        assert_eq!(store.load_outbox_state(1).unwrap(), state);
    }

    /// Only the acknowledgement writer acknowledges: a repair writer, which
    /// skips the tip-anchor check, and a checked writer refuse before reading
    /// the outbox.
    #[test]
    fn only_an_acknowledgement_writer_acknowledges_a_loss() {
        let (_dir, path, store, writer) = committed_pair();
        remove_first_line(&outbox_path(&path));
        let outbox = outbox_bytes(&path);
        let state = store.load_outbox_state(1).unwrap();
        let refuses = |writer: &mut AuditWriter| {
            let log = fs::read(&path).unwrap();
            let err = writer
                .acknowledge_outbox_loss("inspection", Default::default())
                .unwrap_err();
            assert!(
                matches!(&err, WriterError::Io(e) if e.kind() == io::ErrorKind::InvalidInput),
                "{err:?}"
            );
            assert_eq!(fs::read(&path).unwrap(), log, "no acknowledgement row");
            assert_eq!(outbox_bytes(&path), outbox);
            assert_eq!(store.load_outbox_state(1).unwrap(), state);
        };
        let mut checked = writer;
        refuses(&mut checked);
        drop(checked);
        let mut repair = AuditWriter::open_for_reanchor(path.clone(), None, store.clone()).unwrap();
        refuses(&mut repair);
    }

    /// A recoverable owner queue reports no loss and refuses acknowledgement
    /// before any write.
    /// Its next drain delivers each row once.
    #[test]
    fn a_loss_acknowledgement_finds_no_loss_in_a_recoverable_owner_queue() {
        let (_dir, path, store, mut writer) = keyed_fixture();
        AuditOutbox::for_log(&path, store.clone())
            .append(&row("raw"))
            .unwrap();
        enqueue(&path, &store, &["cutover-tagged"]);
        test_seam::arm_sync_failure(
            &replacement_path(&outbox_path(&path)),
            test_seam::SyncStep::Rename,
        );
        assert!(matches!(writer.drain_outbox(), Err(WriterError::Io(_))));
        assert_eq!(owner_summary(&store), (1, Some((0, 2))));
        enqueue(&path, &store, &["accepted-in-window"]);
        assert_eq!(writer.outbox_loss().unwrap(), None);
        drop(writer);
        let outbox = outbox_bytes(&path);
        let log = fs::read(&path).unwrap();
        let state = store.load_outbox_state(1).unwrap();
        let owner = store.load_outbox_owner_state(1).unwrap();
        let refused = AuditWriter::open_for_outbox_acknowledgement(
            path.clone(),
            Some(Zeroizing::new(ROW_KEY)),
            store.clone(),
            crate::audit_log::BindingHistory::NotRecorded,
        )
        .map(drop)
        .unwrap_err();
        assert!(matches!(refused, WriterError::OutboxLossNotFound));
        assert_eq!(fs::read(&path).unwrap(), log, "no acknowledgement row");
        assert_eq!(outbox_bytes(&path), outbox);
        assert_eq!(store.load_outbox_state(1).unwrap(), state);
        assert_eq!(store.load_outbox_owner_state(1).unwrap(), owner);
        let _writer = reopen(&path, &store);
        for id in ["raw", "cutover-tagged", "accepted-in-window"] {
            assert_eq!(delivered(&path, id), 1, "{id} delivered once");
        }
        assert_eq!(outbox_bytes(&path), header(1));
    }

    // Owner delivery, publication and the keyed queue path.

    fn header(g: u64) -> Vec<u8> {
        test_seam::generation_line(&ROW_KEY, g)
    }

    fn owner_state(store: &InMemoryTipAnchorStore) -> Option<OutboxOwnerState> {
        store
            .load_outbox_owner_state(1)
            .unwrap()
            .map(|raw| OutboxOwnerState::parse(&raw).unwrap())
    }

    /// The owner's generation and its closed batch's generation and count.
    fn owner_summary(store: &InMemoryTipAnchorStore) -> (u64, Option<(u64, u64)>) {
        let owner = owner_state(store).unwrap();
        (owner.g, owner.closed.map(|closed| (closed.g, closed.n)))
    }

    fn enqueue(path: &Path, store: &Arc<InMemoryTipAnchorStore>, ids: &[&str]) {
        let outbox = keyed_outbox(path, store);
        for id in ids {
            outbox.append(&row(id)).unwrap();
        }
    }

    /// Opens a fresh draining keyed writer, which drains at open.
    fn reopen(path: &Path, store: &Arc<InMemoryTipAnchorStore>) -> AuditWriter {
        AuditWriter::open(
            path.to_path_buf(),
            Some(KeyedAuditAccess::new(
                Zeroizing::new(ROW_KEY),
                store.clone(),
            )),
        )
        .unwrap()
    }

    fn delivered(path: &Path, id: &str) -> usize {
        request_ids(path).iter().filter(|seen| *seen == id).count()
    }

    /// Signs a tagged row over exact body bytes at `(g, s)` with flag `r`.
    fn sign_row(g: u64, s: u64, r: u8, body: &[u8]) -> Vec<u8> {
        let tag = row_mac(&ROW_KEY, g, s, r, body).finalize().into_bytes();
        let mut line = row_prefix(g, s, r);
        line.extend_from_slice(body);
        line.extend_from_slice(b",\"tag\":\"");
        line.extend_from_slice(crate::hex::encode(&tag).as_bytes());
        line.extend_from_slice(b"\"}");
        line
    }

    /// A keyed fixture whose queue was cut over: generation line 1 alone.
    fn cut_over_fixture() -> (TempDir, PathBuf, Arc<InMemoryTipAnchorStore>, AuditWriter) {
        let (dir, path, store, mut writer) = keyed_fixture();
        enqueue(&path, &store, &["cutover"]);
        assert_eq!(writer.drain_outbox().unwrap(), 1);
        assert_eq!(outbox_bytes(&path), header(1));
        (dir, path, store, writer)
    }

    #[test]
    fn replacement_faults_preserve_recoverable_state() {
        use test_seam::SyncStep;
        #[derive(Debug, Clone, Copy)]
        enum Fault {
            Step(SyncStep),
            Partial,
            Carrier,
        }
        for fault in [
            Fault::Step(SyncStep::Remove),
            Fault::Step(SyncStep::Create),
            Fault::Partial,
            Fault::Step(SyncStep::File),
            Fault::Carrier,
            Fault::Step(SyncStep::Rename),
            Fault::Step(SyncStep::Directory),
        ] {
            let (_dir, path, store, mut writer) = keyed_fixture();
            enqueue(&path, &store, &["one", "two"]);
            let queued = outbox_bytes(&path);
            let next = replacement_path(&outbox_path(&path));
            let leftover = b"{\"k\":\"gen\",\"g\":7,\"tag\":\"00\"}\ntorn".to_vec();
            fs::write(&next, &leftover).unwrap();
            match fault {
                Fault::Step(step) => test_seam::arm_sync_failure(&next, step),
                Fault::Partial => test_seam::arm_partial_write(&next, 5),
                Fault::Carrier => {
                    let store = store.clone();
                    writer.set_drain_after_snapshot(move || {
                        let mut record = store.load_carrier_record().unwrap().unwrap();
                        record.generation += 1;
                        store.store_carrier_record(&record).unwrap();
                    });
                }
            }
            let error = writer.drain_outbox().unwrap_err();
            match fault {
                Fault::Carrier => assert!(
                    matches!(
                        error,
                        WriterError::CarrierGenerationChanged {
                            held: 1,
                            current: 2
                        }
                    ),
                    "{error:?}"
                ),
                _ => assert!(matches!(error, WriterError::Io(_)), "{fault:?}: {error:?}"),
            }
            assert_eq!(owner_summary(&store), (1, Some((0, 2))), "{fault:?}");
            let renamed = matches!(fault, Fault::Step(SyncStep::Directory));
            assert_eq!(
                outbox_bytes(&path),
                if renamed { header(1) } else { queued.clone() },
                "{fault:?}"
            );
            match fault {
                Fault::Step(SyncStep::Remove) => assert_eq!(fs::read(&next).unwrap(), leftover),
                Fault::Step(SyncStep::Create | SyncStep::Directory) => {
                    assert!(!next.exists(), "{fault:?}");
                }
                _ => assert!(next.exists(), "{fault:?}"),
            }
            if let Fault::Carrier = fault {
                let mut record = store.load_carrier_record().unwrap().unwrap();
                record.generation = 1;
                store.store_carrier_record(&record).unwrap();
            }
            drop(writer);
            let mut writer = reopen(&path, &store);
            assert_eq!(writer.drain_outbox().unwrap(), 0);
            for id in ["one", "two"] {
                assert_eq!(delivered(&path, id), 1, "{fault:?} delivers {id} once");
            }
            assert_eq!(outbox_bytes(&path), header(1), "{fault:?}");
            assert!(!next.exists(), "{fault:?}");
            assert_eq!(owner_summary(&store), (1, Some((0, 2))), "{fault:?}");
        }
    }

    /// A publication completes the replacement's data sync before the rename
    /// and the directory sync after it.
    #[test]
    fn a_publication_syncs_the_replacement_and_its_directory() {
        use test_seam::SyncStep;
        let (_dir, path, store, mut writer) = keyed_fixture();
        enqueue(&path, &store, &["one"]);
        let next = replacement_path(&outbox_path(&path));
        test_seam::record_syncs(&next);
        assert_eq!(writer.drain_outbox().unwrap(), 1);
        let expected: &[SyncStep] = if cfg!(unix) {
            &[SyncStep::File, SyncStep::Rename, SyncStep::Directory]
        } else {
            &[SyncStep::File, SyncStep::Rename]
        };
        assert_eq!(test_seam::take_syncs(&next), expected);
        assert_eq!(outbox_bytes(&path), header(1));
    }

    /// The sync helpers return what the system call returns. A pipe accepts
    /// no sync, so each helper refuses it and records nothing.
    #[cfg(unix)]
    #[test]
    fn the_sync_helpers_report_the_system_call() {
        use std::os::fd::OwnedFd;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("outbox");
        test_seam::record_syncs(&path);
        let (reader, _writer) = io::pipe().unwrap();
        let pipe = File::from(OwnedFd::from(reader));
        assert!(sync_outbox_file(&pipe, &path).is_err());
        assert!(sync_directory(&pipe, &path).is_err());
        assert!(test_seam::take_syncs(&path).is_empty());
    }

    /// A directory sync opens the directory itself, so a removed directory
    /// refuses the sync.
    #[cfg(unix)]
    #[test]
    fn a_directory_sync_of_a_removed_directory_refuses() {
        let dir = TempDir::new().unwrap();
        let gone = dir.path().join("gone");
        fs::create_dir(&gone).unwrap();
        let path = gone.join("outbox");
        test_seam::record_syncs(&path);
        sync_parent_dir(&path).unwrap();
        assert_eq!(
            test_seam::take_syncs(&path),
            [test_seam::SyncStep::Directory]
        );
        fs::remove_dir(&gone).unwrap();
        test_seam::record_syncs(&path);
        assert_eq!(
            sync_parent_dir(&path).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert!(test_seam::take_syncs(&path).is_empty());
    }

    /// A leftover replacement that is a symbolic link is removed, so the
    /// publication writes a new file and never writes through the link.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_leftover_replacement_is_removed_not_followed() {
        let (dir, path, store, mut writer) = keyed_fixture();
        enqueue(&path, &store, &["one"]);
        let decoy = dir.path().join("decoy");
        fs::write(&decoy, b"decoy").unwrap();
        let next = replacement_path(&outbox_path(&path));
        std::os::unix::fs::symlink(&decoy, &next).unwrap();
        assert_eq!(writer.drain_outbox().unwrap(), 1);
        assert_eq!(fs::read(&decoy).unwrap(), b"decoy");
        let outbox = outbox_path(&path);
        assert!(fs::symlink_metadata(&outbox).unwrap().file_type().is_file());
        assert_eq!(outbox_bytes(&path), header(1));
        assert!(!next.exists());
    }

    /// The key a key-change test persists in place of [`ROW_KEY`].
    const NEXT_KEY: [u8; 32] = [0x35; 32];

    /// Where a key rotation stops, in the order of its writes.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum KeyChange {
        /// The open drained; nothing of the key change is written.
        BeforeFence,
        /// New owner state is stored and the fence line is not published.
        OwnerStored,
        /// The fence line is published and the new key is not persisted.
        Fenced,
        /// The new key is persisted and the queue's line is still the fence.
        KeyPersisted,
        /// The rotation switched the writer and published its line.
        Done,
    }

    /// Stops a rotation at `stop`, then runs an append under the old key,
    /// one under the new key, and a drain under the key the keyring holds.
    ///
    /// Asserts which appends are acknowledged, that the drain delivers each
    /// acknowledged row once, and that it refuses none. The new key exists
    /// only once persisted. Before that, a queue without a generation line
    /// has nothing that could refuse a key, so no new-key append runs there.
    fn stop_key_change(owned: bool, stop: KeyChange) {
        let (_dir, path, store, writer) = if owned {
            cut_over_fixture()
        } else {
            keyed_fixture()
        };
        assert_eq!(owner_state(&store).is_some(), owned);
        let old = keyed_outbox(&path, &store);
        let new = AuditOutbox::for_log_keyed(&path, store.clone(), Zeroizing::new(NEXT_KEY));
        drop(writer);
        store.set_reload(Ok(Some(ROW_KEY)));
        let mut rotation = AuditWriter::open_for_key_rotation(
            path.clone(),
            Some(Zeroizing::new(ROW_KEY)),
            store.clone(),
            crate::audit_log::BindingHistory::NotRecorded,
        )
        .unwrap();
        match stop {
            KeyChange::BeforeFence => {}
            KeyChange::OwnerStored => {
                test_seam::arm_stop(&outbox_path(&path), test_seam::Stop::OwnerStored);
                assert!(matches!(
                    rotation.fence_outbox_for_key_change(),
                    Err(WriterError::Io(_))
                ));
            }
            KeyChange::Fenced | KeyChange::KeyPersisted | KeyChange::Done => {
                rotation.fence_outbox_for_key_change().unwrap();
            }
        }
        let persisted = matches!(stop, KeyChange::KeyPersisted | KeyChange::Done);
        if persisted {
            store.set_reload(Ok(Some(NEXT_KEY)));
        }
        if stop == KeyChange::Done {
            rotation
                .switch_entry_tag_key(Zeroizing::new(NEXT_KEY), "rotation")
                .unwrap();
        }
        drop(rotation);
        let fenced = matches!(stop, KeyChange::Fenced | KeyChange::KeyPersisted);
        let old_acked = old.append(&row("old-key")).is_ok();
        assert_eq!(old_acked, !fenced, "{stop:?} owned {owned}: old-key append");
        let new_runs = owned || !matches!(stop, KeyChange::BeforeFence | KeyChange::OwnerStored);
        let new_acked = new_runs && new.append(&row("new-key")).is_ok();
        assert_eq!(
            new_acked,
            new_runs && !fenced,
            "{stop:?} owned {owned}: new-key append"
        );
        let current = if persisted { NEXT_KEY } else { ROW_KEY };
        let drain = AuditWriter::open_for_key_rotation(
            path.clone(),
            Some(Zeroizing::new(current)),
            store.clone(),
            crate::audit_log::BindingHistory::NotRecorded,
        );
        assert!(drain.is_ok(), "{stop:?} owned {owned}: {:?}", drain.err());
        assert_eq!(
            delivered(&path, "old-key"),
            usize::from(old_acked),
            "{stop:?} owned {owned}"
        );
        assert_eq!(
            delivered(&path, "new-key"),
            usize::from(new_acked),
            "{stop:?} owned {owned}"
        );
        let bytes = outbox_bytes(&path);
        let lines = parse_lines(&bytes).lines;
        assert_eq!(
            lines.len(),
            1,
            "{stop:?} owned {owned}: the drain leaves a lone line"
        );
        assert!(
            test_seam::queue_generation(&lines, Some(&current)).is_ok(),
            "{stop:?} owned {owned}: the line verifies under the keyring's key"
        );
    }

    #[test]
    fn a_key_change_stopped_before_the_fence_delivers_every_acknowledged_row() {
        stop_key_change(true, KeyChange::BeforeFence);
        stop_key_change(false, KeyChange::BeforeFence);
    }

    #[test]
    fn a_key_change_stopped_after_the_owner_state_delivers_every_acknowledged_row() {
        stop_key_change(false, KeyChange::OwnerStored);
    }

    #[test]
    fn a_key_change_stopped_at_the_fence_acknowledges_no_row() {
        stop_key_change(true, KeyChange::Fenced);
        stop_key_change(false, KeyChange::Fenced);
    }

    #[test]
    fn a_key_change_stopped_after_the_key_write_acknowledges_no_row() {
        stop_key_change(true, KeyChange::KeyPersisted);
        stop_key_change(false, KeyChange::KeyPersisted);
    }

    #[test]
    fn a_completed_key_change_delivers_both_appends_under_the_new_key() {
        stop_key_change(true, KeyChange::Done);
        stop_key_change(false, KeyChange::Done);
    }

    /// Without owner state, a rotation that only switches the key still
    /// publishes a line under the new key. An appender that cached the old
    /// key reloads it and queues a row the new key's drain delivers.
    #[test]
    fn a_stale_appender_after_a_rotation_without_owner_state_queues_under_the_new_key() {
        let (_dir, path, store, writer) = keyed_fixture();
        let stale = keyed_outbox(&path, &store);
        assert!(owner_state(&store).is_none());
        drop(writer);
        let mut rotation = AuditWriter::open_for_key_rotation(
            path.clone(),
            Some(Zeroizing::new(ROW_KEY)),
            store.clone(),
            crate::audit_log::BindingHistory::NotRecorded,
        )
        .unwrap();
        store.set_reload(Ok(Some(NEXT_KEY)));
        rotation
            .switch_entry_tag_key(Zeroizing::new(NEXT_KEY), "rotation")
            .unwrap();
        crate::audit_log::resign_chain_root_sidecars(&path, &NEXT_KEY).unwrap();
        drop(rotation);
        assert_eq!(owner_summary(&store), (1, Some((0, 0))));
        assert_eq!(
            outbox_bytes(&path),
            test_seam::generation_line(&NEXT_KEY, 1)
        );
        stale.append(&row("stale-after-rotation")).unwrap();
        assert_eq!(store.reload_count(), 1);
        drop(
            AuditWriter::open(
                path.clone(),
                Some(KeyedAuditAccess::new(
                    Zeroizing::new(NEXT_KEY),
                    store.clone(),
                )),
            )
            .unwrap(),
        );
        assert_eq!(delivered(&path, "stale-after-rotation"), 1);
    }

    /// Completes a rotation of the cut-over fixture from `ROW_KEY` to
    /// `NEXT_KEY` and returns the queue as the rotation left it.
    fn rotate_cut_over(path: &Path, store: &Arc<InMemoryTipAnchorStore>) -> Vec<u8> {
        let mut rotation = AuditWriter::open_for_key_rotation(
            path.to_path_buf(),
            Some(Zeroizing::new(ROW_KEY)),
            store.clone(),
            crate::audit_log::BindingHistory::NotRecorded,
        )
        .unwrap();
        store.set_reload(Ok(Some(ROW_KEY)));
        rotation.fence_outbox_for_key_change().unwrap();
        store.set_reload(Ok(Some(NEXT_KEY)));
        rotation
            .switch_entry_tag_key(Zeroizing::new(NEXT_KEY), "rotation")
            .unwrap();
        drop(rotation);
        let queue = outbox_bytes(path);
        assert_eq!(queue, test_seam::generation_line(&NEXT_KEY, 1));
        queue
    }

    /// A writer opened with a key that a completed rotation replaced signs
    /// no queue line. Its open compares its key with the stored key and
    /// refuses with `audit.key_replaced` before any write. An appender that
    /// cached the replaced key then reloads the stored key, and the stored
    /// key's drain delivers its row.
    #[test]
    fn a_writer_opened_with_a_replaced_key_signs_no_queue_line() {
        let (_dir, path, store, writer) = cut_over_fixture();
        let stale = keyed_outbox(&path, &store);
        drop(writer);
        let queue = rotate_cut_over(&path, &store);
        let log = fs::read(&path).unwrap();
        let replaced = AuditWriter::open_for_key_rotation(
            path.clone(),
            Some(Zeroizing::new(ROW_KEY)),
            store.clone(),
            crate::audit_log::BindingHistory::NotRecorded,
        );
        assert!(
            matches!(replaced, Err(WriterError::AuditKeyReplaced)),
            "a rotation opener with the replaced key: {:?}",
            replaced.err()
        );
        assert_eq!(outbox_bytes(&path), queue);
        let ordinary = AuditWriter::open(
            path.clone(),
            Some(KeyedAuditAccess::new(
                Zeroizing::new(ROW_KEY),
                store.clone(),
            )),
        );
        assert!(
            matches!(ordinary, Err(WriterError::AuditKeyReplaced)),
            "an ordinary opener with the replaced key: {:?}",
            ordinary.err()
        );
        assert_eq!(outbox_bytes(&path), queue);
        assert_eq!(fs::read(&path).unwrap(), log);
        stale.append(&row("after-stale-open")).unwrap();
        drop(
            AuditWriter::open_for_key_rotation(
                path.clone(),
                Some(Zeroizing::new(NEXT_KEY)),
                store.clone(),
                crate::audit_log::BindingHistory::NotRecorded,
            )
            .unwrap(),
        );
        assert_eq!(delivered(&path, "after-stale-open"), 1);
        assert_eq!(
            outbox_bytes(&path),
            test_seam::generation_line(&NEXT_KEY, 2)
        );
    }

    /// A file writer that restores a generation line signed under a replaced
    /// key lets an appender holding that key queue a row. A writer open with
    /// the replaced key refuses with `audit.key_replaced` before any write.
    /// The stored key's drain refuses the queue and leaves it unchanged on
    /// every attempt. The acknowledgement records the loss and discards
    /// the row.
    #[test]
    fn a_restored_header_under_a_replaced_key_refuses_the_drain_and_acknowledges_the_loss() {
        let (_dir, path, store, writer) = cut_over_fixture();
        let old_header = outbox_bytes(&path);
        let stale = keyed_outbox(&path, &store);
        drop(writer);
        rotate_cut_over(&path, &store);
        fs::write(outbox_path(&path), &old_header).unwrap();
        stale.append(&row("behind-a-restored-header")).unwrap();
        let queue = outbox_bytes(&path);
        assert_eq!(parse_lines(&queue).lines.len(), 2);
        let log = fs::read(&path).unwrap();
        let owner = store.load_outbox_owner_state(1).unwrap();
        let state = store.load_outbox_state(1).unwrap();
        let stale_open = AuditWriter::open(
            path.clone(),
            Some(KeyedAuditAccess::new(
                Zeroizing::new(ROW_KEY),
                store.clone(),
            )),
        );
        assert!(
            matches!(stale_open, Err(WriterError::AuditKeyReplaced)),
            "a stale process's next open: {:?}",
            stale_open.err()
        );
        assert_eq!(outbox_bytes(&path), queue);
        assert_eq!(fs::read(&path).unwrap(), log);
        assert_eq!(store.load_outbox_owner_state(1).unwrap(), owner);
        assert_eq!(store.load_outbox_state(1).unwrap(), state);
        for attempt in 0..2 {
            let drain = AuditWriter::open_for_key_rotation(
                path.clone(),
                Some(Zeroizing::new(NEXT_KEY)),
                store.clone(),
                crate::audit_log::BindingHistory::NotRecorded,
            );
            assert!(
                matches!(
                    drain,
                    Err(WriterError::OutboxUnusable {
                        line: 1,
                        reason: "tagged record whose tag does not verify",
                        ..
                    })
                ),
                "attempt {attempt}: {:?}",
                drain.err()
            );
            assert_eq!(outbox_bytes(&path), queue, "attempt {attempt}");
        }
        let mut acknowledgement = AuditWriter::open_for_outbox_acknowledgement(
            path.clone(),
            Some(Zeroizing::new(NEXT_KEY)),
            store.clone(),
            crate::audit_log::BindingHistory::NotRecorded,
        )
        .unwrap();
        let report = acknowledgement
            .acknowledge_outbox_loss("inspection", Default::default())
            .unwrap();
        assert_eq!(
            (
                report.expected_rows,
                report.found_rows,
                report.drained,
                report.discarded
            ),
            (1, 0, 0, 1)
        );
        assert_eq!(owner_summary(&store).0, 2);
        assert_eq!(
            outbox_bytes(&path),
            test_seam::generation_line(&NEXT_KEY, 2)
        );
        assert_eq!(delivered(&path, "behind-a-restored-header"), 0);
    }

    /// What a refused open must leave as it found it: the log, the queue,
    /// the owner state and the commitment of the active generation, and the
    /// carrier record.
    #[derive(Debug, PartialEq, Eq)]
    struct OpenEvidence {
        log: Vec<u8>,
        queue: Vec<u8>,
        owner: Option<String>,
        state: Option<OutboxState>,
        record: Option<crate::audit_log::tip_anchor::CarrierRecord>,
    }

    impl OpenEvidence {
        fn read(path: &Path, store: &InMemoryTipAnchorStore) -> Self {
            let record = store.load_carrier_record().unwrap();
            let generation = record.as_ref().map_or(0, |record| record.generation);
            Self {
                log: fs::read(path).unwrap(),
                queue: outbox_bytes(path),
                owner: store.load_outbox_owner_state(generation).unwrap(),
                state: store.load_outbox_state(generation).unwrap(),
                record,
            }
        }
    }

    /// Asserts that `open`, which holds the key a completed rotation
    /// replaced, refuses with `audit.key_replaced` and changes no evidence.
    fn assert_stale_open_refuses<T>(
        path: &Path,
        store: &InMemoryTipAnchorStore,
        opener: &str,
        open: impl FnOnce() -> Result<T, WriterError>,
    ) {
        let before = OpenEvidence::read(path, store);
        let refused = open();
        assert!(
            matches!(refused, Err(WriterError::AuditKeyReplaced)),
            "{opener}: {:?}",
            refused.err()
        );
        assert_eq!(OpenEvidence::read(path, store), before, "{opener}");
    }

    /// The cut-over fixture after a completed rotation from `ROW_KEY` to
    /// `NEXT_KEY`, with the keyring holding `NEXT_KEY`.
    fn rotated_fixture() -> (TempDir, PathBuf, Arc<InMemoryTipAnchorStore>) {
        let (dir, path, store, writer) = cut_over_fixture();
        drop(writer);
        rotate_cut_over(&path, &store);
        crate::audit_log::resign_chain_root_sidecars(&path, &NEXT_KEY).unwrap();
        (dir, path, store)
    }

    #[test]
    fn a_tip_anchor_open_with_a_replaced_key_refuses_before_any_write() {
        let (_dir, path, store) = rotated_fixture();
        let open = |key| {
            AuditWriter::open_with_tip_anchor(
                path.clone(),
                Some(Zeroizing::new(key)),
                store.clone(),
                crate::audit_log::BindingHistory::NotRecorded,
            )
        };
        assert_stale_open_refuses(&path, &store, "tip-anchor open", || open(ROW_KEY));
        drop(open(NEXT_KEY).unwrap());
    }

    #[test]
    fn a_reanchor_open_with_a_replaced_key_refuses_before_any_write() {
        let (_dir, path, store) = rotated_fixture();
        let open = |key| {
            AuditWriter::open_for_reanchor(path.clone(), Some(Zeroizing::new(key)), store.clone())
        };
        assert_stale_open_refuses(&path, &store, "reanchor open", || open(ROW_KEY));
        drop(open(NEXT_KEY).unwrap());
    }

    /// A binding that holds the replaced key refuses at the key comparison.
    /// A binding that holds the stored key passes it and binds.
    #[test]
    fn a_carrier_binding_with_a_replaced_key_refuses_before_any_write() {
        let (_dir, path, store) = rotated_fixture();
        assert_stale_open_refuses(&path, &store, "binding open", || {
            AuditWriter::open_for_carrier_binding(
                path.clone(),
                KeyedAuditAccess::new(Zeroizing::new(ROW_KEY), store.clone()),
            )
        });

        let (_dir, path, store, writer) = keyed_fixture();
        drop(writer);
        store.set_reload(Ok(Some(ROW_KEY)));
        let mut binding = AuditWriter::open_for_carrier_binding(
            path.clone(),
            KeyedAuditAccess::new(Zeroizing::new(ROW_KEY), store.clone()),
        )
        .unwrap();
        binding.bind_carriers().unwrap();
    }

    /// The registry acquisition the MCP server and keyed CLI verbs use opens
    /// through [`AuditWriter::open`], so a replaced key refuses there too.
    #[test]
    fn a_registry_acquisition_with_a_replaced_key_refuses_before_any_write() {
        let (_dir, path, store) = rotated_fixture();
        let profile = "outbox-replaced-key-acquisition";
        let access = |key| {
            KeyedAuditAccess::new(
                Zeroizing::new(key),
                store.clone() as Arc<dyn TipAnchorStore>,
            )
        };
        assert_stale_open_refuses(&path, &store, "registry acquisition", || {
            AuditWriterRegistry::get_or_open_keyed(profile, &path, access(ROW_KEY))
        });
        drop(AuditWriterRegistry::get_or_open_keyed(profile, &path, access(NEXT_KEY)).unwrap());
        AuditWriterRegistry::remove_for_test(profile);
    }

    /// The acknowledgement open with the replaced key refuses at the key
    /// comparison. The stored key meets a no-loss refusal with unchanged
    /// evidence.
    #[test]
    fn a_loss_acknowledgement_with_a_replaced_key_refuses_before_any_write() {
        let (_dir, path, store) = rotated_fixture();
        let open = |key| {
            AuditWriter::open_for_outbox_acknowledgement(
                path.clone(),
                Some(Zeroizing::new(key)),
                store.clone(),
                crate::audit_log::BindingHistory::NotRecorded,
            )
        };
        assert_stale_open_refuses(&path, &store, "acknowledgement open", || open(ROW_KEY));
        let before = OpenEvidence::read(&path, &store);
        let stored = open(NEXT_KEY).map(drop).unwrap_err();
        assert!(matches!(stored, WriterError::OutboxLossNotFound));
        assert_eq!(OpenEvidence::read(&path, &store), before);
    }

    /// A changed retired commitment lets the acknowledgement open past the
    /// open-time owner classification. An acknowledgement that loaded its key
    /// before a completed rotation then refuses at the key comparison, before
    /// its drain or its row. The stored key's acknowledgement records the
    /// retired loss only, and the active queue and its owner state stay.
    #[cfg(unix)]
    #[test]
    fn a_stale_acknowledgement_of_a_retired_change_refuses_before_any_write() {
        let (_dir, path, store, writer) = keyed_fixture();
        store.set_reload(Ok(Some(ROW_KEY)));
        drop(writer);
        AuditOutbox::for_log(&path, store.clone())
            .append(&row("retired"))
            .unwrap();
        let retired_batch = OutboxBatch::read_locked(&path, store.as_ref()).unwrap();
        let carrier = outbox_lock_path(&path);
        fs::rename(&carrier, carrier.with_extension("replaced")).unwrap();
        File::create(&carrier).unwrap();
        let mut binding = AuditWriter::open_for_carrier_binding(
            path.clone(),
            KeyedAuditAccess::new(Zeroizing::new(ROW_KEY), store.clone()),
        )
        .unwrap();
        assert_eq!(binding.bind_carriers().unwrap().generation, 2);
        drop(binding);
        keyed_outbox(&path, &store)
            .append(&row("cut-over"))
            .unwrap();
        drop(
            AuditWriter::open(
                path.clone(),
                Some(KeyedAuditAccess::new(
                    Zeroizing::new(ROW_KEY),
                    store.clone(),
                )),
            )
            .unwrap(),
        );
        assert!(store.load_outbox_owner_state(2).unwrap().is_some());
        rotate_cut_over(&path, &store);
        crate::audit_log::resign_chain_root_sidecars(&path, &NEXT_KEY).unwrap();
        // The retired generation's drain commits after the binding and the
        // rotation, so the retired watch sees a changed commitment.
        store
            .store_outbox_state(1, &OutboxState::default())
            .unwrap();
        retired_batch.clear().unwrap();
        let open = |key| {
            AuditWriter::open_for_outbox_acknowledgement(
                path.clone(),
                Some(Zeroizing::new(key)),
                store.clone(),
                crate::audit_log::BindingHistory::NotRecorded,
            )
        };
        assert_stale_open_refuses(&path, &store, "retired acknowledgement", || open(ROW_KEY));
        let queue = outbox_bytes(&path);
        let owner = store.load_outbox_owner_state(2).unwrap();
        let mut stored = open(NEXT_KEY).unwrap();
        stored
            .acknowledge_outbox_loss("retired loss", Default::default())
            .unwrap();
        drop(stored);
        assert_eq!(outbox_bytes(&path), queue, "the active queue stays");
        assert_eq!(store.load_outbox_owner_state(2).unwrap(), owner);
    }

    /// A lone fence has no loss, so acknowledgement refuses before every write.
    /// The log, queue, owner item, commitment, and carrier record stay
    /// identical.
    #[test]
    fn a_loss_acknowledgement_after_a_stopped_key_change_finds_no_loss_before_any_write() {
        let (_dir, path, store, writer) = cut_over_fixture();
        drop(writer);
        let mut rotation = AuditWriter::open_for_key_rotation(
            path.clone(),
            Some(Zeroizing::new(ROW_KEY)),
            store.clone(),
            crate::audit_log::BindingHistory::NotRecorded,
        )
        .unwrap();
        rotation.fence_outbox_for_key_change().unwrap();
        store.set_reload(Ok(Some(NEXT_KEY)));
        drop(rotation);
        let log = fs::read(&path).unwrap();
        let queue = outbox_bytes(&path);
        let owner = store.load_outbox_owner_state(1).unwrap();
        let state = store.load_outbox_state(1).unwrap();
        let record = store.load_carrier_record().unwrap();
        let refused = AuditWriter::open_for_outbox_acknowledgement(
            path.clone(),
            Some(Zeroizing::new(NEXT_KEY)),
            store.clone(),
            crate::audit_log::BindingHistory::NotRecorded,
        )
        .map(drop)
        .unwrap_err();
        assert!(matches!(refused, WriterError::OutboxLossNotFound));
        assert_eq!(fs::read(&path).unwrap(), log, "the log is unchanged");
        assert_eq!(outbox_bytes(&path), queue, "the queue is unchanged");
        assert_eq!(store.load_outbox_owner_state(1).unwrap(), owner);
        assert_eq!(store.load_outbox_state(1).unwrap(), state);
        assert_eq!(store.load_carrier_record().unwrap(), record);
    }

    /// A first key replaces none, so no appender holds an older key. The
    /// fence and the switch leave a queue without owner state as it is, and
    /// an unkeyed append still queues.
    #[test]
    fn a_first_key_leaves_a_queue_without_owner_state_as_it_is() {
        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);
        let store = bound_store(&path);
        let mut rotation = AuditWriter::open_for_key_rotation(
            path.clone(),
            None,
            store.clone(),
            crate::audit_log::BindingHistory::NotRecorded,
        )
        .unwrap();
        rotation.fence_outbox_for_key_change().unwrap();
        rotation
            .switch_entry_tag_key(Zeroizing::new(NEXT_KEY), "first-key")
            .unwrap();
        drop(rotation);
        assert!(owner_state(&store).is_none());
        assert!(!outbox_path(&path).exists());
        AuditOutbox::for_log(&path, store.clone())
            .append(&row("unkeyed"))
            .unwrap();
        assert_eq!(parse_lines(&outbox_bytes(&path)).lines.len(), 1);
    }

    /// Only a key-rotation writer fences, and a fence refuses a queue that
    /// holds a row, with nothing written.
    #[test]
    fn a_fence_needs_a_rotation_writer_and_a_drained_queue() {
        let (_dir, path, store, mut writer) = keyed_fixture();
        let error = writer.fence_outbox_for_key_change().unwrap_err();
        assert!(
            matches!(&error, WriterError::Io(e) if e.kind() == io::ErrorKind::InvalidInput),
            "{error:?}"
        );
        drop(writer);
        let mut rotation = AuditWriter::open_for_key_rotation(
            path.clone(),
            Some(Zeroizing::new(ROW_KEY)),
            store.clone(),
            crate::audit_log::BindingHistory::NotRecorded,
        )
        .unwrap();
        let queued = encode_tagged_row(&ROW_KEY, 0, 1, 0, &row("planted")).unwrap();
        let mut bytes = queued;
        bytes.push(b'\n');
        fs::write(outbox_path(&path), &bytes).unwrap();
        assert_eq!(
            format!("{:?}", rotation.fence_outbox_for_key_change()),
            format!(
                "Err({:?})",
                tagged_refusal(1, "queue not drained before a key change")
            )
        );
        assert_eq!(outbox_bytes(&path), bytes);
        assert!(owner_state(&store).is_none());
    }

    /// The commitment check compares a published queue with the owner state:
    /// a restored older generation, a stale lone generation line, and a
    /// generation line without owner state all refuse.
    #[test]
    fn verification_refuses_a_queue_the_owner_state_does_not_hold() {
        let (_dir, path, store, mut writer) = cut_over_fixture();
        enqueue(&path, &store, &["old"]);
        let old_queue = outbox_bytes(&path);
        assert_eq!(writer.drain_outbox().unwrap(), 1);
        enqueue(&path, &store, &["current"]);
        assert_eq!(writer.drain_outbox().unwrap(), 1);
        assert_eq!(owner_summary(&store), (3, Some((2, 1))));
        check_outbox_commitment(&path, store.as_ref()).unwrap();
        let refusal = |path: &Path, store: &InMemoryTipAnchorStore| {
            format!("{:?}", check_outbox_commitment(path, store))
        };
        // Generation 2 is the closed one: its line alone lacks the closed row.
        for (queue, recorded, found) in [(old_queue, 0, 1), (header(1), 0, 0), (header(2), 1, 0)] {
            fs::write(outbox_path(&path), &queue).unwrap();
            assert_eq!(
                refusal(&path, &store),
                format!("Err(OutboxRowsMissing {{ recorded: {recorded}, found: {found} }})")
            );
            assert!(writer.drain_outbox().is_err());
            assert_eq!(outbox_bytes(&path), queue);
        }
        fs::write(outbox_path(&path), header(3)).unwrap();
        check_outbox_commitment(&path, store.as_ref()).unwrap();
        // Without owner state, a generation line belongs to no queue.
        let (_dir, path, store, _writer) = keyed_fixture();
        for found in [0, 1] {
            let mut queue = header(1);
            if found == 1 {
                queue.extend_from_slice(
                    &encode_tagged_row(&ROW_KEY, 1, 1, 0, &row("foreign")).unwrap(),
                );
                queue.push(b'\n');
            }
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(outbox_path(&path), &queue).unwrap();
            assert!(owner_state(&store).is_none());
            assert_eq!(
                refusal(&path, &store),
                format!("Err(OutboxRowsMissing {{ recorded: 0, found: {found} }})")
            );
        }
    }

    /// Verification and inspection preserve files, items, and carrier records.
    #[test]
    fn owner_verify_and_inspection_are_write_free() {
        let (_dir, path, store, writer) = cut_over_fixture();
        enqueue(&path, &store, &["one", "two"]);
        drop(writer);
        store.set_reload(Ok(Some(ROW_KEY)));
        let replacement = replacement_path(&outbox_path(&path));
        fs::write(&replacement, b"preserved replacement").unwrap();
        let before = OpenEvidence::read(&path, &store);
        let writes = store.outbox_item_writes();
        let carriers = store.carrier_record_writes();
        let reads = store.reload_count();
        let accesses = store.outbox_item_accesses();
        check_outbox_commitment(&path, store.as_ref()).unwrap();
        assert_eq!(inspect_outbox(&path).unwrap().pending, 2);
        assert_eq!(
            store.outbox_item_accesses(),
            accesses + 2,
            "verification reads v1 and owner once"
        );
        assert_eq!(OpenEvidence::read(&path, &store), before);
        assert_eq!(
            store.outbox_item_writes(),
            writes,
            "verification writes no owner item"
        );
        assert_eq!(
            store.carrier_record_writes(),
            carriers,
            "verification writes no carrier record"
        );
        assert_eq!(store.reload_count(), reads + 1, "inspection reads no key");
        assert_eq!(
            fs::read(replacement).unwrap(),
            b"preserved replacement",
            "verification leaves the replacement unchanged"
        );
    }

    /// The last generation permits empty queues and interrupted recovery.
    #[test]
    fn owner_selection_at_the_last_generation_only_checks_actual_advances() {
        for recovery in [false, true] {
            let (_dir, path, store, mut writer) = keyed_fixture();
            let g = if recovery { u64::MAX - 1 } else { u64::MAX };
            store
                .store_outbox_owner_state(1, &OutboxOwnerState::new(g, None).to_keyring_value())
                .unwrap();
            fs::write(outbox_path(&path), header(g)).unwrap();
            if recovery {
                enqueue(&path, &store, &["delivered"]);
                test_seam::arm_stop(&outbox_path(&path), test_seam::Stop::OwnerStored);
                assert!(matches!(writer.drain_outbox(), Err(WriterError::Io(_))));
                enqueue(&path, &store, &["late"]);
            }
            drop(writer);
            store.set_reload(Ok(Some(ROW_KEY)));
            let before = OpenEvidence::read(&path, &store);
            let writes = store.outbox_item_writes();
            assert!(
                check_outbox_commitment(&path, store.as_ref()).is_ok(),
                "verification needs no successor generation"
            );
            assert_eq!(OpenEvidence::read(&path, &store), before);
            assert_eq!(store.outbox_item_writes(), writes);
            let mut writer = reopen(&path, &store);
            assert_eq!(writer.drain_outbox().unwrap(), 0);
            assert_eq!(outbox_bytes(&path), header(u64::MAX));
            if recovery {
                assert_eq!(delivered(&path, "delivered"), 1);
                assert_eq!(delivered(&path, "late"), 1);
            }
        }
    }

    /// The verifier and next drain refuse a restored header under the
    /// replaced key.
    #[test]
    fn owner_verify_refuses_a_restored_header_under_a_replaced_key() {
        let (_dir, path, store) = rotated_fixture();
        fs::write(outbox_path(&path), header(1)).unwrap();
        keyed_outbox(&path, &store)
            .append(&row("restored"))
            .unwrap();
        let before = OpenEvidence::read(&path, &store);
        let verify = check_outbox_commitment(&path, store.as_ref()).unwrap_err();
        assert!(matches!(
            verify,
            WriterError::OutboxUnusable {
                line: 1,
                column: 1,
                reason: "tagged record whose tag does not verify"
            }
        ));
        let drain = AuditWriter::open(
            path.clone(),
            Some(KeyedAuditAccess::new(
                Zeroizing::new(NEXT_KEY),
                store.clone(),
            )),
        )
        .err()
        .unwrap();
        assert_eq!(format!("{verify:?}"), format!("{drain:?}"));
        assert_eq!(OpenEvidence::read(&path, &store), before);
    }

    /// Legacy verification authenticates the tagged suffix under the stored
    /// key.
    #[test]
    fn legacy_verify_authenticates_the_tagged_suffix() {
        let (_dir, path, store, writer) = keyed_fixture();
        AuditOutbox::for_log(&path, store.clone())
            .append(&row("raw"))
            .unwrap();
        AuditOutbox::for_log_keyed(&path, store.clone(), Zeroizing::new(NEXT_KEY))
            .append(&row("foreign-key"))
            .unwrap();
        drop(writer);
        store.set_reload(Ok(Some(ROW_KEY)));
        let before = OpenEvidence::read(&path, &store);
        assert!(matches!(
            check_outbox_commitment(&path, store.as_ref()),
            Err(WriterError::OutboxUnusable {
                line: 2,
                column: 1,
                reason: "tagged record whose tag does not verify"
            })
        ));
        assert_eq!(OpenEvidence::read(&path, &store), before);
    }

    /// Each verification reads the stored key once, only when the store
    /// reads keys.
    #[test]
    #[serial_test::serial]
    fn owner_verify_reads_the_stored_key_once() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());

        // Version 2 evidence authenticates under the same single key read,
        // and a store without that key refuses it.
        let (_dir, path, store, writer) = initialized();
        drop(writer);
        store.set_reload(Ok(Some(ROW_KEY)));
        let before = store.reload_count();
        check_outbox_commitment(&path, store.as_ref()).unwrap();
        assert_eq!(
            store.reload_count() - before,
            1,
            "v2 evidence uses the one key read"
        );
        store.set_reload(Ok(None));
        assert!(matches!(
            check_outbox_commitment(&path, store.as_ref()),
            Err(WriterError::KeyedLogNeedsKey { .. })
        ));
        for scripted in [false, true] {
            let (_dir, path, store, writer) = cut_over_fixture();
            enqueue(&path, &store, &["one", "two"]);
            drop(writer);
            if scripted {
                store.set_reload(Ok(Some(ROW_KEY)));
            }
            let before = store.reload_count();
            check_outbox_commitment(&path, store.as_ref()).unwrap();
            assert_eq!(
                store.reload_count() - before,
                usize::from(scripted),
                "one key read per check"
            );
        }
    }

    /// Keyless stores check layout and coordinates, including an absent
    /// stored key.
    #[test]
    fn owner_verify_on_a_keyless_store_checks_layout_and_coordinates() {
        for absent in [false, true] {
            let (_dir, path, store, writer) = cut_over_fixture();
            enqueue(&path, &store, &["one"]);
            drop(writer);
            if absent {
                store.set_reload(Ok(None));
            }
            check_outbox_commitment(&path, store.as_ref()).unwrap();
            let mut bytes = header(1);
            bytes.extend_from_slice(&encode_tagged_row(&ROW_KEY, 1, 2, 0, &row("moved")).unwrap());
            bytes.push(b'\n');
            fs::write(outbox_path(&path), bytes).unwrap();
            assert!(matches!(
                check_outbox_commitment(&path, store.as_ref()),
                Err(WriterError::OutboxRowsMissing {
                    recorded: 1,
                    found: 2
                })
            ));
            fs::write(outbox_path(&path), b"{\"k\":\"gen\"}\n").unwrap();
            assert!(matches!(
                check_outbox_commitment(&path, store.as_ref()),
                Err(WriterError::OutboxUnusable {
                    line: 1,
                    column: 1,
                    reason: "tagged record that does not parse"
                })
            ));
        }
    }

    /// A failed key read refuses with a static reason and preserves the queue.
    #[test]
    fn owner_verify_reports_a_failed_key_read() {
        let (_dir, path, store, writer) = cut_over_fixture();
        drop(writer);
        store.set_reload(Err("private-marker"));
        let before = OpenEvidence::read(&path, &store);
        let error = check_outbox_commitment(&path, store.as_ref()).unwrap_err();
        assert_eq!(
            error.to_string(),
            "audit.tip_anchor_unavailable: audit log tip anchor unavailable: audit tip anchor store: audit key reload failed"
        );
        assert!(!format!("{error:?}").contains("private-marker"));
        assert_eq!(OpenEvidence::read(&path, &store), before);
    }

    fn capture_verification(
        path: &Path,
        store: &InMemoryTipAnchorStore,
    ) -> (Result<(), WriterError>, String) {
        let capture = stellar_agent_test_support::CaptureWriter::new();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_max_level(tracing::Level::WARN)
            .with_writer(capture.clone())
            .finish();
        let result = tracing::subscriber::with_default(subscriber, || {
            tracing::callsite::rebuild_interest_cache();
            check_outbox_commitment(path, store)
        });
        (result, capture.captured_str())
    }

    /// Recovery and a lone fence pass with the publication warning; a changed
    /// closed batch refuses.
    #[test]
    fn owner_verify_reports_publication_pending() {
        let (_dir, path, store, mut writer) = cut_over_fixture();
        enqueue(&path, &store, &["one", "two"]);
        test_seam::arm_stop(&outbox_path(&path), test_seam::Stop::OwnerStored);
        assert!(writer.drain_outbox().is_err());
        drop(writer);
        store.set_reload(Ok(Some(ROW_KEY)));
        let before = OpenEvidence::read(&path, &store);
        let (result, warning) = capture_verification(&path, &store);
        result.unwrap();
        assert!(
            warning.contains("audit outbox publication pending; the next drain completes it"),
            "{warning}"
        );
        assert_eq!(OpenEvidence::read(&path, &store), before);
        let queue = outbox_bytes(&path);
        let mut lines = parse_lines(&queue)
            .lines
            .iter()
            .map(|line| line.to_vec())
            .collect::<Vec<_>>();
        lines[1] = encode_tagged_row(&ROW_KEY, 1, 1, 0, &row("alternate")).unwrap();
        fs::write(
            outbox_path(&path),
            lines
                .into_iter()
                .flat_map(|mut line| {
                    line.push(b'\n');
                    line
                })
                .collect::<Vec<_>>(),
        )
        .unwrap();
        assert!(matches!(
            check_outbox_commitment(&path, store.as_ref()),
            Err(WriterError::OutboxRowsMissing {
                recorded: 2,
                found: 2
            })
        ));
        let (_dir, path, store, writer) = cut_over_fixture();
        drop(writer);
        let mut rotation = AuditWriter::open_for_key_rotation(
            path.clone(),
            Some(Zeroizing::new(ROW_KEY)),
            store.clone(),
            crate::audit_log::BindingHistory::NotRecorded,
        )
        .unwrap();
        rotation.fence_outbox_for_key_change().unwrap();
        drop(rotation);
        store.set_reload(Ok(Some(ROW_KEY)));
        let before = OpenEvidence::read(&path, &store);
        let (result, warning) = capture_verification(&path, &store);
        result.unwrap();
        assert!(
            warning.contains("audit outbox publication pending; the next drain completes it"),
            "{warning}"
        );
        assert_eq!(OpenEvidence::read(&path, &store), before);
    }

    /// Verification reads the owner state of its locked carrier generation.
    #[test]
    fn owner_verification_reads_the_locked_generation() {
        let (_dir, path, store, writer) = cut_over_fixture();
        drop(writer);
        let mut binding = AuditWriter::open_for_carrier_binding(
            path.clone(),
            KeyedAuditAccess::new(Zeroizing::new(ROW_KEY), store.clone()),
        )
        .unwrap();
        assert_eq!(binding.bind_carriers().unwrap().generation, 2);
        drop(binding);
        store.store_outbox_owner_state(0, "invalid-zero").unwrap();
        store
            .store_outbox_owner_state(1, "invalid-retired")
            .unwrap();
        let mut record = store.load_carrier_record().unwrap().unwrap();
        record.retired.as_mut().unwrap().state =
            super::super::lock::owner_watch("invalid-retired", 0);
        store.store_carrier_record(&record).unwrap();
        check_outbox_commitment(&path, store.as_ref()).unwrap();
    }

    /// A valid owner queue has no loss; a misplaced row reports its missing
    /// authenticated prefix.
    #[test]
    fn the_generation_line_states() {
        // A row after the generation line takes position 1 at physical line 2.
        let (_dir, path, store, mut writer) = cut_over_fixture();
        enqueue(&path, &store, &["after"]);
        let lines_of = |path: &Path| {
            parse_lines(&outbox_bytes(path))
                .lines
                .iter()
                .map(|line| line.to_vec())
                .collect::<Vec<_>>()
        };
        let lines = lines_of(&path);
        assert_eq!(lines.len(), 2);
        let after: serde_json::Value = serde_json::from_slice(&lines[1]).unwrap();
        let entry: AuditEntry = serde_json::from_value(after["body"].clone()).unwrap();
        assert_eq!(entry.request_id, "after");
        assert_eq!(
            lines[1],
            encode_tagged_row(&ROW_KEY, 1, 1, 0, &entry).unwrap()
        );
        // Verification accepts the published queue, and refuses a row of
        // another generation or a nonzero commitment. A valid queue has
        // no loss.
        check_outbox_commitment(&path, store.as_ref()).unwrap();
        assert_eq!(writer.outbox_loss().unwrap(), None);
        let published = outbox_bytes(&path);
        let mut moved = header(1);
        moved.extend_from_slice(&encode_tagged_row(&ROW_KEY, 2, 1, 0, &entry).unwrap());
        moved.push(b'\n');
        fs::write(outbox_path(&path), &moved).unwrap();
        assert!(matches!(
            check_outbox_commitment(&path, store.as_ref()),
            Err(WriterError::OutboxRowsMissing {
                recorded: 1,
                found: 1
            })
        ));
        assert_eq!(
            writer.outbox_loss().unwrap(),
            Some(OutboxLoss {
                expected_rows: 1,
                found_rows: 0
            })
        );
        fs::write(outbox_path(&path), &published).unwrap();
        commit_every_line(&path, &store);
        let error = check_outbox_commitment(&path, store.as_ref()).unwrap_err();
        assert_eq!(
            format!("{error:?}"),
            format!(
                "{:?}",
                unusable("legacy outbox state changed in the owner state")
            )
        );
        store
            .store_outbox_state(1, &OutboxState::default())
            .unwrap();
        // A generation line past the first line is out of place.
        let before = fs::read(&path).unwrap();
        let mut planted = outbox_bytes(&path);
        planted.extend_from_slice(&header(1));
        fs::write(outbox_path(&path), &planted).unwrap();
        let error = writer.drain_outbox().unwrap_err();
        assert!(
            matches!(
                error,
                WriterError::OutboxUnusable {
                    line: 3,
                    column: 1,
                    reason: "generation line out of place"
                }
            ),
            "{error:?}"
        );
        assert_eq!(fs::read(&path).unwrap(), before);
        assert_eq!(outbox_bytes(&path), planted);
        drop(writer);

        // The generation line takes no quota slot: 64 rows fit after it.
        let (_dir, path, store, _writer) = cut_over_fixture();
        let outbox = keyed_outbox(&path, &store);
        for index in 0..MAX_OUTBOX_ROWS {
            outbox.append(&row(&format!("row-{index}"))).unwrap();
        }
        let full = outbox_bytes(&path);
        assert!(matches!(
            outbox.append(&row("over")),
            Err(WriterError::OutboxFull {
                queued: 64,
                cap: 64
            })
        ));
        assert_eq!(outbox_bytes(&path), full);
        assert_eq!(parse_lines(&full).lines.len(), MAX_OUTBOX_ROWS + 1);

        // The last generation cannot advance: the drain refuses before any
        // append.
        let (_dir, path, store, mut writer) = keyed_fixture();
        store
            .store_outbox_owner_state(1, &test_seam::owner_value(u64::MAX, None))
            .unwrap();
        fs::write(outbox_path(&path), header(u64::MAX)).unwrap();
        enqueue(&path, &store, &["last"]);
        let lines = lines_of(&path);
        let last: serde_json::Value = serde_json::from_slice(&lines[1]).unwrap();
        assert_eq!(
            (last["g"].as_u64(), last["s"].as_u64()),
            (Some(u64::MAX), Some(1))
        );
        let log = fs::read(&path).unwrap();
        let queued = outbox_bytes(&path);
        let error = writer.drain_outbox().unwrap_err();
        assert_eq!(
            format!("{error:?}"),
            format!("{:?}", unusable("queue generation overflows"))
        );
        assert_eq!(fs::read(&path).unwrap(), log);
        assert_eq!(outbox_bytes(&path), queued);
        drop(writer);

        // A leftover replacement is never a queued row and never blocks open.
        let (_dir, path, store, writer) = keyed_fixture();
        enqueue(&path, &store, &["kept"]);
        let next = replacement_path(&outbox_path(&path));
        fs::write(
            &next,
            encode_tagged_row(&ROW_KEY, 0, 2, 0, &row("leftover")).unwrap(),
        )
        .unwrap();
        assert_eq!(inspect_outbox(&path).unwrap().pending, 1);
        drop(writer);
        let _writer = reopen(&path, &store);
        assert_eq!(delivered(&path, "kept"), 1);
        assert_eq!(delivered(&path, "leftover"), 0);
        assert!(!next.exists());
        assert_eq!(outbox_bytes(&path), header(1));

        // An append between the rename and the directory sync queues under
        // the published generation, and the next drain delivers it.
        let (_dir, path, store, mut writer) = keyed_fixture();
        enqueue(&path, &store, &["first"]);
        test_seam::arm_stop(&outbox_path(&path), test_seam::Stop::Renamed);
        assert!(matches!(writer.drain_outbox(), Err(WriterError::Io(_))));
        assert_eq!(outbox_bytes(&path), header(1));
        enqueue(&path, &store, &["window"]);
        let lines = lines_of(&path);
        let window: serde_json::Value = serde_json::from_slice(&lines[1]).unwrap();
        assert_eq!(
            (window["g"].as_u64(), window["s"].as_u64()),
            (Some(1), Some(1))
        );
        assert_eq!(writer.drain_outbox().unwrap(), 1);
        assert_eq!(delivered(&path, "first"), 1);
        assert_eq!(delivered(&path, "window"), 1);
        assert_eq!(outbox_bytes(&path), header(2));
        assert_eq!(owner_summary(&store), (2, Some((1, 1))));
    }

    #[test]
    fn the_queue_path_never_accesses_either_item() {
        use crate::audit_log::tip_anchor::RetiredOutbox;
        let (_dir, path, store, _writer) = keyed_fixture();
        // A retired generation makes a retired watch read its commitment.
        let mut record = store.load_carrier_record().unwrap().unwrap();
        record.retired = Some(RetiredOutbox {
            generation: 0,
            state: String::new(),
            file: None,
        });
        store.store_carrier_record(&record).unwrap();
        store.forbid_outbox_items(true);
        let accesses = store.outbox_item_accesses();
        let outbox = keyed_outbox(&path, &store);
        for id in ["one", "two", "three"] {
            outbox.append(&row(id)).unwrap();
        }
        assert_eq!(store.outbox_item_accesses(), accesses, "no item access");
        assert_eq!(parse_lines(&outbox_bytes(&path)).lines.len(), 3);
        // The unkeyed path reads its commitment and the retired watch.
        let error = AuditOutbox::for_log(&path, store.clone())
            .append(&row("raw"))
            .unwrap_err();
        assert!(matches!(error, WriterError::TipAnchorStore(_)), "{error:?}");
        assert!(store.outbox_item_accesses() > accesses);
        store.forbid_outbox_items(false);
        assert!(store.outbox_item_writes().is_empty());
    }

    #[test]
    fn generation_tag_mismatch_reloads_once() {
        let (_dir, path, store, mut writer) = cut_over_fixture();
        let stale = AuditOutbox::for_log_keyed(&path, store.clone(), Zeroizing::new([0x11; 32]));
        // A held key that verifies the generation line reloads nothing.
        keyed_outbox(&path, &store).append(&row("current")).unwrap();
        assert_eq!(store.reload_count(), 0);
        store.set_reload(Ok(Some(ROW_KEY)));
        stale.append(&row("reloaded")).unwrap();
        assert_eq!(store.reload_count(), 1);
        stale.append(&row("again")).unwrap();
        assert_eq!(store.reload_count(), 2, "the outbox keeps its own key");
        let bytes = outbox_bytes(&path);
        let lines = parse_lines(&bytes).lines;
        for (index, id) in ["current", "reloaded", "again"].into_iter().enumerate() {
            let value: serde_json::Value = serde_json::from_slice(lines[index + 1]).unwrap();
            let entry: AuditEntry = serde_json::from_value(value["body"].clone()).unwrap();
            assert_eq!(entry.request_id, id);
            assert_eq!(
                lines[index + 1],
                encode_tagged_row(&ROW_KEY, 1, index as u64 + 1, 0, &entry)
                    .unwrap()
                    .as_slice(),
                "the row is tagged under the reloaded key"
            );
        }
        for (reload, expected) in [
            (Ok(None), unusable("tagged record without an audit key")),
            (
                Ok(Some([0x22; 32])),
                unusable("tagged record whose tag does not verify"),
            ),
            (
                Err("backend"),
                WriterError::TipAnchorStore(TipAnchorStoreError::new("audit key reload failed")),
            ),
        ] {
            store.set_reload(reload);
            let count = store.reload_count();
            let error = stale.append(&row("refused")).unwrap_err();
            assert_eq!(format!("{error:?}"), format!("{expected:?}"));
            assert_eq!(store.reload_count(), count + 1, "one reload per append");
            assert_eq!(outbox_bytes(&path), bytes);
        }
        assert_eq!(writer.drain_outbox().unwrap(), 3);
    }

    #[test]
    fn keyed_queue_faults_leave_no_successful_row() {
        use super::super::writer::MAX_ROW_BYTES;
        use test_seam::SyncStep;
        let (_dir, path, store, _writer) = keyed_fixture();
        let outbox = keyed_outbox(&path, &store);
        // The creating append syncs the directory; its failure rolls back.
        test_seam::arm_sync_failure(outbox.path(), SyncStep::Directory);
        assert!(matches!(
            outbox.append(&row("created")),
            Err(WriterError::Io(_))
        ));
        assert!(outbox_bytes(&path).is_empty());
        outbox.append(&row("kept")).unwrap();
        let before = outbox_bytes(&path);
        test_seam::arm_partial_write(outbox.path(), 9);
        assert!(matches!(
            outbox.append(&row("torn")),
            Err(WriterError::Io(_))
        ));
        assert_eq!(outbox_bytes(&path), before);
        test_seam::arm_sync_failure(outbox.path(), SyncStep::File);
        assert!(matches!(
            outbox.append(&row("unsynced")),
            Err(WriterError::Io(_))
        ));
        assert_eq!(outbox_bytes(&path), before);
        // A failed rollback still refuses; the orphan line stays.
        test_seam::arm_sync_failure(outbox.path(), SyncStep::File);
        test_seam::arm_sync_failure(outbox.path(), SyncStep::Rollback);
        assert!(matches!(
            outbox.append(&row("orphan")),
            Err(WriterError::Io(_))
        ));
        let orphaned = outbox_bytes(&path);
        assert_eq!(parse_lines(&orphaned).lines.len(), 2);
        assert!(orphaned.starts_with(&before));
        fs::write(outbox_path(&path), &before).unwrap();
        // The row cap refuses before writing.
        let over = consent_row_of_len("over", MAX_ROW_BYTES + 1);
        assert!(matches!(
            outbox.append(&over),
            Err(WriterError::OutboxRowTooLarge {
                cap: MAX_ROW_BYTES,
                ..
            })
        ));
        assert_eq!(outbox_bytes(&path), before);
        // The queue cap refuses the row past it.
        for index in 1..MAX_OUTBOX_ROWS {
            outbox.append(&row(&format!("row-{index}"))).unwrap();
        }
        let full = outbox_bytes(&path);
        assert!(matches!(
            outbox.append(&row("over")),
            Err(WriterError::OutboxFull {
                queued: 64,
                cap: 64
            })
        ));
        assert_eq!(outbox_bytes(&path), full);
    }

    #[test]
    fn a_legacy_tagged_suffix_authenticates_after_the_prefix() {
        let (_dir, path, store, mut writer) = keyed_fixture();
        AuditOutbox::for_log(&path, store.clone())
            .append(&row("raw"))
            .unwrap();
        enqueue(&path, &store, &["two", "three"]);
        let valid = outbox_bytes(&path);
        let lines = parse_lines(&valid).lines;
        let suffix: Vec<_> = lines[1..].iter().map(|line| line.to_vec()).collect();
        assert!(suffix[0].starts_with(b"{\"k\":\"row\",\"g\":0,\"s\":2,"));
        check_outbox_commitment(&path, store.as_ref()).unwrap();
        assert_eq!(writer.outbox_loss().unwrap(), None);

        // A changed prefix refuses first, whatever follows it.
        let mut forged = suffix[0].clone();
        let end = forged.len();
        forged[end - 3] = if forged[end - 3] == b'0' { b'1' } else { b'0' };
        let mut changed = serde_json::to_vec(&row("changed")).unwrap();
        changed.push(b'\n');
        for line in [&forged, &suffix[1]] {
            changed.extend_from_slice(line);
            changed.push(b'\n');
        }
        fs::write(outbox_path(&path), &changed).unwrap();
        let missing = WriterError::OutboxRowsMissing {
            recorded: 1,
            found: 3,
        };
        let error = check_outbox_commitment(&path, store.as_ref()).unwrap_err();
        assert_eq!(format!("{error:?}"), format!("{missing:?}"));
        let error = writer.drain_outbox().unwrap_err();
        assert_eq!(format!("{error:?}"), format!("{missing:?}"));

        // A forged suffix tag passes the keyless check and refuses keyed.
        let mut tampered = valid[..lines[0].len() + 1].to_vec();
        for line in [&forged, &suffix[1]] {
            tampered.extend_from_slice(line);
            tampered.push(b'\n');
        }
        fs::write(outbox_path(&path), &tampered).unwrap();
        check_outbox_commitment(&path, store.as_ref()).unwrap();
        let tag = WriterError::OutboxUnusable {
            line: 2,
            column: 1,
            reason: "tagged record whose tag does not verify",
        };
        let error = writer.drain_outbox().unwrap_err();
        assert_eq!(format!("{error:?}"), format!("{tag:?}"));
        let loss = writer.outbox_loss().unwrap().unwrap();
        assert_eq!((loss.expected_rows, loss.found_rows), (1, 3));

        // An untagged line past the prefix refuses at its position.
        let mut raw_suffix = valid.clone();
        raw_suffix.extend_from_slice(&serde_json::to_vec(&row("raw-suffix")).unwrap());
        raw_suffix.push(b'\n');
        fs::write(outbox_path(&path), &raw_suffix).unwrap();
        let untagged = WriterError::OutboxRowsMissing {
            recorded: 4,
            found: 0,
        };
        let error = check_outbox_commitment(&path, store.as_ref()).unwrap_err();
        assert_eq!(format!("{error:?}"), format!("{untagged:?}"));
        let error = writer.drain_outbox().unwrap_err();
        assert_eq!(format!("{error:?}"), format!("{untagged:?}"));
        assert!(log_rows(&path).iter().all(|row| row["request_id"] != "raw"));

        // Binding selects the prefix and the authenticated suffix verbatim.
        fs::write(outbox_path(&path), &valid).unwrap();
        drop(writer);
        let access = KeyedAuditAccess::new(Zeroizing::new(ROW_KEY), store.clone());
        let mut binding = AuditWriter::open_for_carrier_binding(path.clone(), access).unwrap();
        let report = binding.bind_carriers().unwrap();
        assert_eq!((report.generation, report.carried_rows), (2, 3));
        assert_eq!(outbox_bytes(&path), valid);
    }

    #[test]
    fn first_tagged_drain_cuts_over_in_order() {
        // An empty startup and a raw-only queue stay legacy.
        let (_dir, path, store, mut writer) = keyed_fixture();
        assert_eq!(writer.drain_outbox().unwrap(), 0);
        assert_eq!(store.load_outbox_owner_state(1).unwrap(), None);
        AuditOutbox::for_log(&path, store.clone())
            .append(&row("raw-only"))
            .unwrap();
        assert_eq!(writer.drain_outbox().unwrap(), 1);
        assert_eq!(store.load_outbox_owner_state(1).unwrap(), None);
        assert!(outbox_bytes(&path).is_empty());
        assert!(
            store
                .outbox_item_writes()
                .iter()
                .all(|(kind, _)| *kind == "legacy")
        );
        drop(writer);

        // A tagged row cuts over: appends, anchor, owner, zero v1, header.
        let (_dir, path, store, mut writer) = keyed_fixture();
        AuditOutbox::for_log(&path, store.clone())
            .append(&row("raw"))
            .unwrap();
        enqueue(&path, &store, &["tagged"]);
        let legacy = store.load_outbox_state(1).unwrap().unwrap();
        let writes = store.outbox_item_writes().len();
        test_seam::arm_stop(&outbox_path(&path), test_seam::Stop::AnchorChecked);
        assert!(matches!(writer.drain_outbox(), Err(WriterError::Io(_))));
        assert_eq!(
            request_ids(&path)[request_ids(&path).len() - 2..],
            ["raw", "tagged"]
        );
        assert_eq!(store.load_outbox_owner_state(1).unwrap(), None);
        assert_eq!(store.outbox_item_writes().len(), writes);
        test_seam::arm_stop(&outbox_path(&path), test_seam::Stop::OwnerStored);
        assert!(matches!(writer.drain_outbox(), Err(WriterError::Io(_))));
        let owner = owner_state(&store).unwrap();
        assert_eq!(owner.g, 1);
        assert_eq!(
            owner.legacy,
            Some(Sha256::digest(legacy.to_keyring_value().as_bytes()).into())
        );
        let bytes = outbox_bytes(&path);
        let lines = parse_lines(&bytes).lines;
        let raw = decode_raw(lines[0], 1).unwrap();
        let tagged = test_seam::delivered_row_digest(lines[1]).unwrap();
        let closed = owner.closed.unwrap();
        assert_eq!((closed.g, closed.n), (0, 2));
        assert_eq!(
            closed.batch,
            batch_digest(&[(0, row_digest(0, 1, 0, &raw).unwrap()), tagged])
        );
        assert_eq!(store.load_outbox_state(1).unwrap(), Some(legacy));
        assert_eq!(writer.drain_outbox().unwrap(), 0);
        assert_eq!(
            store.outbox_item_writes()[writes..],
            [("owner", 1), ("legacy", 1)],
            "the owner state precedes the zero commitment"
        );
        assert_eq!(
            store.load_outbox_state(1).unwrap(),
            Some(OutboxState::default())
        );
        assert_eq!(outbox_bytes(&path), header(1));
        for id in ["raw", "tagged"] {
            assert_eq!(
                delivered(&path, id),
                2,
                "delivered before and after the stop"
            );
        }

        // Without a commitment the owner records none.
        let (_dir, path, store, mut writer) = keyed_fixture();
        assert_eq!(store.load_outbox_state(1).unwrap(), None);
        enqueue(&path, &store, &["absent"]);
        assert_eq!(writer.drain_outbox().unwrap(), 1);
        assert_eq!(owner_state(&store).unwrap().legacy, None);
        assert_eq!(
            store.load_outbox_state(1).unwrap(),
            Some(OutboxState::default())
        );
    }

    #[test]
    fn cutover_recovers_every_boundary() {
        use test_seam::Stop;
        for (stop, repeated) in [
            (Stop::BeforeAppends, 0),
            (Stop::AfterAppend(1), 1),
            (Stop::AfterAppend(2), 2),
            (Stop::AnchorChecked, 3),
            (Stop::OwnerStored, 0),
            (Stop::LegacyZeroed, 0),
            (Stop::ReplacementSynced, 0),
            (Stop::Renamed, 0),
            (Stop::DirectorySynced, 0),
        ] {
            let (_dir, path, store, mut writer) = keyed_fixture();
            AuditOutbox::for_log(&path, store.clone())
                .append(&row("raw"))
                .unwrap();
            enqueue(&path, &store, &["two", "three"]);
            test_seam::arm_stop(&outbox_path(&path), stop);
            assert!(
                matches!(writer.drain_outbox(), Err(WriterError::Io(_))),
                "{stop:?}"
            );
            drop(writer);
            let mut writer = reopen(&path, &store);
            assert_eq!(writer.drain_outbox().unwrap(), 0, "{stop:?}");
            for (index, id) in ["raw", "two", "three"].into_iter().enumerate() {
                let times = if index < repeated { 2 } else { 1 };
                assert_eq!(delivered(&path, id), times, "{stop:?}: {id}");
            }
            assert_eq!(outbox_bytes(&path), header(1), "{stop:?}");
            assert_eq!(owner_summary(&store), (1, Some((0, 3))), "{stop:?}");
            assert_eq!(
                store.load_outbox_state(1).unwrap(),
                Some(OutboxState::default()),
                "{stop:?}"
            );
        }
    }

    #[test]
    fn an_old_client_rewrite_refuses_unusable() {
        let refusal = unusable("legacy outbox state changed in the owner state");
        // Stopped after the owner store: the commitment still hashes to L.
        let (_dir, path, store, mut writer) = keyed_fixture();
        AuditOutbox::for_log(&path, store.clone())
            .append(&row("raw"))
            .unwrap();
        enqueue(&path, &store, &["tagged"]);
        test_seam::arm_stop(&outbox_path(&path), test_seam::Stop::OwnerStored);
        assert!(matches!(writer.drain_outbox(), Err(WriterError::Io(_))));
        // An unkeyed client imports a raw row and commits every line.
        plant_uncommitted(&path, b"not JSON");
        commit_every_line(&path, &store);
        let log = fs::read(&path).unwrap();
        let queued = outbox_bytes(&path);
        let owner = store.load_outbox_owner_state(1).unwrap();
        let error = writer.drain_outbox().unwrap_err();
        assert_eq!(format!("{error:?}"), format!("{refusal:?}"));
        assert_eq!(fs::read(&path).unwrap(), log);
        assert_eq!(outbox_bytes(&path), queued);
        assert_eq!(store.load_outbox_owner_state(1).unwrap(), owner);
        drop(writer);

        // After the cutover completed, a rewritten commitment refuses too.
        let (_dir, path, store, mut writer) = cut_over_fixture();
        plant_uncommitted(&path, &serde_json::to_vec(&row("imported")).unwrap());
        commit_every_line(&path, &store);
        let log = fs::read(&path).unwrap();
        let error = writer.drain_outbox().unwrap_err();
        assert_eq!(format!("{error:?}"), format!("{refusal:?}"));
        assert_eq!(fs::read(&path).unwrap(), log);
        assert_eq!(delivered(&path, "imported"), 0);
    }

    #[test]
    fn owner_rows_require_tags_and_current_positions() {
        let body = fixed_row().canonical_json_body().unwrap();
        let noncanonical = String::from_utf8(body.clone())
            .unwrap()
            .replacen('{', "{ ", 1)
            .into_bytes();
        let mut forged = sign_row(1, 1, 0, &body);
        let end = forged.len();
        forged[end - 3] = if forged[end - 3] == b'0' { b'1' } else { b'0' };
        let cases: Vec<(Vec<u8>, Vec<u8>, WriterError)> = vec![
            (
                header(1),
                serde_json::to_vec(&fixed_row()).unwrap(),
                WriterError::OutboxRowsMissing {
                    recorded: 1,
                    found: 0,
                },
            ),
            (
                header(1),
                line_of(&sign_row(1, 1, 0, &body))
                    .replace("\"g\":1", "\"g\":00")
                    .into_bytes(),
                WriterError::OutboxRowsMissing {
                    recorded: 1,
                    found: 0,
                },
            ),
            (
                header(1),
                sign_row(0, 1, 0, &body),
                WriterError::OutboxRowsMissing {
                    recorded: 1,
                    found: 1,
                },
            ),
            (
                header(1),
                sign_row(1, 2, 0, &body),
                WriterError::OutboxRowsMissing {
                    recorded: 1,
                    found: 2,
                },
            ),
            (
                header(5),
                sign_row(5, 1, 0, &body),
                WriterError::OutboxRowsMissing {
                    recorded: 0,
                    found: 1,
                },
            ),
            (
                test_seam::generation_line(&[0x11; 32], 1),
                sign_row(1, 1, 0, &body),
                unusable("tagged record whose tag does not verify"),
            ),
            (
                header(1),
                b"{\"k\":\"row\"}".to_vec(),
                WriterError::OutboxUnusable {
                    line: 2,
                    column: 1,
                    reason: "tagged record that does not parse",
                },
            ),
            (
                header(1),
                forged,
                WriterError::OutboxUnusable {
                    line: 2,
                    column: 1,
                    reason: "tagged record whose tag does not verify",
                },
            ),
            (
                header(1),
                sign_row(1, 1, 0, &noncanonical),
                WriterError::OutboxUnusable {
                    line: 2,
                    column: 1,
                    reason: "tagged record that is not canonical",
                },
            ),
            (
                header(1),
                encode_tagged_row(&ROW_KEY, 1, 1, 0, &own_row("own")).unwrap(),
                WriterError::OutboxRowKindRefused { line: 2 },
            ),
        ];
        for (first, second, expected) in cases {
            let (_dir, path, store, mut writer) = cut_over_fixture();
            let mut bytes = first;
            bytes.extend_from_slice(&second);
            bytes.push(b'\n');
            fs::write(outbox_path(&path), &bytes).unwrap();
            let log = fs::read(&path).unwrap();
            let owner = store.load_outbox_owner_state(1).unwrap();
            let error = writer.drain_outbox().unwrap_err();
            assert_eq!(format!("{error:?}"), format!("{expected:?}"));
            assert_eq!(fs::read(&path).unwrap(), log);
            assert_eq!(outbox_bytes(&path), bytes);
            assert_eq!(store.load_outbox_owner_state(1).unwrap(), owner);
        }
    }

    fn line_of(bytes: &[u8]) -> String {
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[test]
    fn generation_advance_recovers_every_crash_boundary() {
        use test_seam::Stop;
        // An empty live drain commits nothing and keeps the generation.
        let (_dir, path, store, mut writer) = cut_over_fixture();
        let writes = store.outbox_item_writes();
        assert_eq!(writer.drain_outbox().unwrap(), 0);
        assert_eq!(store.outbox_item_writes(), writes);
        assert_eq!(outbox_bytes(&path), header(1));
        drop(writer);
        for (stop, repeated) in [
            (Stop::BeforeAppends, 0),
            (Stop::AfterAppend(1), 1),
            (Stop::AfterAppend(2), 2),
            (Stop::AnchorChecked, 2),
            (Stop::OwnerStored, 0),
            (Stop::ReplacementSynced, 0),
            (Stop::Renamed, 0),
            (Stop::DirectorySynced, 0),
        ] {
            let (_dir, path, store, mut writer) = cut_over_fixture();
            enqueue(&path, &store, &["one", "two"]);
            test_seam::arm_stop(&outbox_path(&path), stop);
            assert!(
                matches!(writer.drain_outbox(), Err(WriterError::Io(_))),
                "{stop:?}"
            );
            let committed = !matches!(
                stop,
                Stop::BeforeAppends | Stop::AfterAppend(_) | Stop::AnchorChecked
            );
            assert_eq!(
                owner_summary(&store),
                if committed {
                    (2, Some((1, 2)))
                } else {
                    (1, Some((0, 1)))
                },
                "{stop:?}"
            );
            drop(writer);
            let mut writer = reopen(&path, &store);
            assert_eq!(writer.drain_outbox().unwrap(), 0, "{stop:?}");
            for (index, id) in ["one", "two"].into_iter().enumerate() {
                let times = if index < repeated { 2 } else { 1 };
                assert_eq!(delivered(&path, id), times, "{stop:?}: {id}");
            }
            assert_eq!(outbox_bytes(&path), header(2), "{stop:?}");
            assert_eq!(owner_summary(&store), (2, Some((1, 2))), "{stop:?}");
        }
    }

    #[test]
    fn the_window_suffix_is_delivered_not_cleared() {
        let (_dir, path, store, mut writer) = cut_over_fixture();
        enqueue(&path, &store, &["one", "two"]);
        test_seam::arm_stop(&outbox_path(&path), test_seam::Stop::OwnerStored);
        assert!(matches!(writer.drain_outbox(), Err(WriterError::Io(_))));
        assert_eq!(owner_summary(&store), (2, Some((1, 2))));
        // An appender still sees generation 1 and appends at position 3.
        enqueue(&path, &store, &["three"]);
        let flagged = encode_tagged_row(&ROW_KEY, 1, 4, 1, &row("four")).unwrap();
        plant_uncommitted(&path, &flagged);
        let bytes = outbox_bytes(&path);
        let lines = parse_lines(&bytes).lines;
        let three: serde_json::Value = serde_json::from_slice(lines[3]).unwrap();
        assert_eq!(
            (three["g"].as_u64(), three["s"].as_u64()),
            (Some(1), Some(3))
        );
        let digests: Vec<_> = lines[1..]
            .iter()
            .map(|line| test_seam::delivered_row_digest(line).unwrap())
            .collect();
        assert_eq!(writer.drain_outbox().unwrap(), 2);
        for id in ["one", "two", "three", "four"] {
            assert_eq!(delivered(&path, id), 1, "{id}");
        }
        let owner = owner_state(&store).unwrap();
        let closed = owner.closed.clone().unwrap();
        assert_eq!((owner.g, closed.g, closed.n), (2, 1, 4));
        assert_eq!(closed.batch, batch_digest(&digests));
        assert_eq!(owner.recent, vec![digests[3].1]);
        assert_eq!(outbox_bytes(&path), header(2));
    }

    #[test]
    fn a_restored_row_at_closed_coordinates_refuses() {
        let (_dir, path, store, mut writer) = cut_over_fixture();
        enqueue(&path, &store, &["one", "two"]);
        test_seam::arm_stop(&outbox_path(&path), test_seam::Stop::OwnerStored);
        assert!(matches!(writer.drain_outbox(), Err(WriterError::Io(_))));
        let bytes = outbox_bytes(&path);
        let lines = parse_lines(&bytes).lines;
        let mut restored = [lines[0], lines[1]].join(&b'\n');
        restored.push(b'\n');
        restored.extend_from_slice(&encode_tagged_row(&ROW_KEY, 1, 2, 0, &row("other")).unwrap());
        restored.push(b'\n');
        fs::write(outbox_path(&path), &restored).unwrap();
        let log = fs::read(&path).unwrap();
        let owner = store.load_outbox_owner_state(1).unwrap();
        let error = writer.drain_outbox().unwrap_err();
        assert!(
            matches!(
                error,
                WriterError::OutboxRowsMissing {
                    recorded: 2,
                    found: 2
                }
            ),
            "{error:?}"
        );
        assert!(error.to_string().starts_with("audit.outbox_rows_missing"));
        assert_eq!(fs::read(&path).unwrap(), log);
        assert_eq!(outbox_bytes(&path), restored);
        assert_eq!(store.load_outbox_owner_state(1).unwrap(), owner);
    }

    #[test]
    fn a_failed_anchor_write_commits_no_evidence() {
        let (_dir, path, store, mut writer) = keyed_fixture();
        enqueue(&path, &store, &["anchored"]);
        let queued = outbox_bytes(&path);
        let legacy = store.load_outbox_state(1).unwrap();
        // The append's anchor write and its in-line retry fail, and so does
        // the strict check's retry after the appends.
        store.fail_next_writes(3);
        let error = writer.drain_outbox().unwrap_err();
        assert!(matches!(error, WriterError::TipAnchorStore(_)), "{error:?}");
        assert_eq!(delivered(&path, "anchored"), 1);
        assert_eq!(store.load_outbox_owner_state(1).unwrap(), None);
        assert_eq!(store.load_outbox_state(1).unwrap(), legacy);
        assert_eq!(outbox_bytes(&path), queued);
        assert!(store.outbox_item_writes().is_empty());
        assert_eq!(writer.drain_outbox().unwrap(), 1);
        assert_eq!(
            delivered(&path, "anchored"),
            2,
            "redelivered with its request id"
        );
        assert_eq!(outbox_bytes(&path), header(1));
    }

    /// A store with only the default owner-state support.
    #[derive(Debug)]
    struct DefaultOwnerStore(Arc<InMemoryTipAnchorStore>);

    impl TipAnchorStore for DefaultOwnerStore {
        fn reads_audit_key(&self) -> bool {
            false
        }
        fn load_carrier_record(
            &self,
        ) -> Result<Option<crate::audit_log::tip_anchor::CarrierRecord>, TipAnchorStoreError>
        {
            self.0.load_carrier_record()
        }
        fn store_carrier_record(
            &self,
            record: &crate::audit_log::tip_anchor::CarrierRecord,
        ) -> Result<(), TipAnchorStoreError> {
            self.0.store_carrier_record(record)
        }
        fn load_outbox_state(
            &self,
            generation: u64,
        ) -> Result<Option<OutboxState>, TipAnchorStoreError> {
            self.0.load_outbox_state(generation)
        }
        fn store_outbox_state(
            &self,
            generation: u64,
            value: &OutboxState,
        ) -> Result<(), TipAnchorStoreError> {
            self.0.store_outbox_state(generation, value)
        }
        fn load_anchor(
            &self,
        ) -> Result<Option<crate::audit_log::tip_anchor::TipAnchor>, TipAnchorStoreError> {
            self.0.load_anchor()
        }
        fn load_raw(&self) -> Result<Option<String>, TipAnchorStoreError> {
            self.0.load_raw()
        }
        fn store_anchor(
            &self,
            anchor: &crate::audit_log::tip_anchor::TipAnchor,
        ) -> Result<(), TipAnchorStoreError> {
            self.0.store_anchor(anchor)
        }
        fn bump_reanchor_count(&self) -> Result<u64, TipAnchorStoreError> {
            self.0.bump_reanchor_count()
        }
        fn reanchor_count(&self) -> Result<Option<u64>, TipAnchorStoreError> {
            self.0.reanchor_count()
        }
    }

    #[test]
    fn tagged_owner_store_failure_repeats_rows() {
        let (_dir, path, store, mut writer) = keyed_fixture();
        enqueue(&path, &store, &["one", "two"]);
        let queued = outbox_bytes(&path);
        let legacy = store.load_outbox_state(1).unwrap();
        store.set_owner_failing(false, true);
        let error = writer.drain_outbox().unwrap_err();
        assert_eq!(
            format!("{error:?}"),
            format!(
                "{:?}",
                WriterError::TipAnchorStore(TipAnchorStoreError::new("owner write fault"))
            )
        );
        assert_eq!(outbox_bytes(&path), queued);
        assert_eq!(store.load_outbox_state(1).unwrap(), legacy);
        store.set_owner_failing(false, false);
        assert_eq!(writer.drain_outbox().unwrap(), 2);
        for id in ["one", "two"] {
            assert_eq!(delivered(&path, id), 2, "{id}");
        }
        assert_eq!(outbox_bytes(&path), header(1));
        drop(writer);

        // A store without owner support delivers once per attempt.
        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);
        let inner = Arc::new(InMemoryTipAnchorStore::new());
        let store: Arc<dyn TipAnchorStore> = Arc::new(DefaultOwnerStore(inner.clone()));
        let mut writer = AuditWriter::open(
            path.clone(),
            Some(KeyedAuditAccess::new(
                Zeroizing::new(ROW_KEY),
                store.clone(),
            )),
        )
        .unwrap();
        AuditOutbox::for_log_keyed(&path, store.clone(), Zeroizing::new(ROW_KEY))
            .append(&row("default"))
            .unwrap();
        let queued = outbox_bytes(&path);
        let unsupported = WriterError::TipAnchorStore(TipAnchorStoreError::new(
            "outbox owner state is unsupported",
        ));
        for attempt in 1..=2 {
            let error = writer.drain_outbox().unwrap_err();
            assert_eq!(format!("{error:?}"), format!("{unsupported:?}"));
            assert_eq!(delivered(&path, "default"), attempt);
            assert_eq!(outbox_bytes(&path), queued, "nothing is cleared");
        }
    }

    fn evidence_snapshot(writer: &AuditWriter) -> OutboxEvidence {
        writer.outbox_evidence().unwrap().unwrap()
    }

    fn seed_records(path: &Path, store: &InMemoryTipAnchorStore, count: usize, expired: bool) {
        let batch = OutboxBatch::read_locked(path, store).unwrap();
        batch
            .commit_evidence_change(path, store, &ROW_KEY, false, |image, _| {
                image.records = (0..count)
                    .map(|index| {
                        let mut record = evidence_record(index as u32);
                        record.state = RecordState::Reserved;
                        record.digest = [0; 32];
                        record.generation = 0;
                        record.sequence = 0;
                        if expired && index == 0 {
                            record.expires_at_ms = 10;
                        }
                        record
                    })
                    .collect();
                Ok(())
            })
            .unwrap();
    }

    fn reserve_row(outbox: &AuditOutbox, identity: [u8; 32], name: &str) -> OutboxRowRef {
        let reservation = outbox.reserve_evidence(identity, 9_000, 0).unwrap();
        outbox
            .clone()
            .with_evidence_reservation(reservation)
            .append_queued(&row(name))
            .unwrap()
    }

    #[test]
    #[serial_test::serial]
    fn require_delivery_drains_then_checks_exact_membership() {
        let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
        let (_dir, path, store, mut writer) = initialized();
        let outbox = keyed_outbox(&path, &store);
        let reference = reserve_row(&outbox, [1; 32], "late");
        assert_eq!(delivered(&path, "late"), 0);
        assert_eq!(
            require_consent_delivered(&mut writer, &[1; 32], Some(&reference), "delivery").unwrap(),
            0,
            "a late append is drained"
        );
        assert_eq!(delivered(&path, "late"), 1);
        let mut different = reference;
        different.digest[0] ^= 1;
        for (id, row) in [([1; 32], different), ([2; 32], reference)] {
            let error =
                require_consent_delivered(&mut writer, &id, Some(&row), "delivery").unwrap_err();
            assert!(
                matches!(error, WalletError::Approval(ApprovalFailure::ConsentUndelivered { generation, sequence }) if generation == row.generation() && sequence == row.sequence()),
                "exact identity and full digest: {error}"
            );
        }
        let dropped = reserve_row(&outbox, [3; 32], "dropped");
        fs::write(
            outbox.path(),
            encode_generation_line(&ROW_KEY, dropped.generation()),
        )
        .unwrap();
        let error = require_consent_delivered(&mut writer, &[3; 32], Some(&dropped), "delivery")
            .expect_err("a dropped Queued row is not Delivered");
        assert_eq!(error.code(), "approval.consent_undelivered");
        assert!(
            matches!(error, WalletError::Approval(ApprovalFailure::ConsentUndelivered { generation, sequence }) if generation == dropped.generation() && sequence == dropped.sequence()),
            "dropped row retains g/s"
        );
        outbox.advance_evidence_floor(80).unwrap();
        assert_eq!(
            require_consent_delivered(&mut writer, &[1; 32], None, "delivery").unwrap(),
            80
        );
    }

    #[test]
    #[serial_test::serial]
    fn require_delivery_needs_an_owner_even_for_direct() {
        let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
        for legacy in [false, true] {
            let (_dir, path, store, mut writer) = keyed_fixture();
            if legacy {
                keyed_outbox(&path, &store).append(&row("legacy")).unwrap();
                writer.drain_outbox().unwrap();
            }
            let error = require_consent_delivered(&mut writer, &[1; 32], None, "delivery")
                .expect_err("direct requires v2 evidence");
            assert_eq!(error.code(), "audit.outbox_evidence_unusable");
            assert!(error.to_string().contains("evidence owner is absent"));
        }
    }

    #[test]
    fn maintainer_protocol_states_the_boundary() {
        let doc = include_str!("../../../../docs/maintainers/audit-log-recovery.md");
        for sentence in [
            "An actor with file access and without the MAC key cannot forge, reorder or replay a queued row unnoticed, and cannot drop a consent row without the consumption refusing.",
            "An actor that holds the MAC key is inside the trust boundary of the audit log.",
            "It can append authentic rows by design, and the protocol claims nothing against it.",
            "A dropped tail of rows that carry no reference, such as halt and resume, is not detected before delivery.",
            "The CLI reports such a row as `queued`, never as `written`.",
        ] {
            assert_eq!(
                doc.matches(sentence).count(),
                1,
                "one exact boundary sentence: {sentence}"
            );
            assert!(sentence.split_whitespace().count() < 30);
        }
        assert_eq!(doc.matches("**Legacy state only.**").count(), 4);
        for rule in [
            "These rules hold while the log has no owner item.",
            "across generation gaps",
            "max(wall_time, evidence_floor)",
            "reserve before ceremony",
            "retry the existing grant without another ceremony",
            "All four production kind capabilities are disabled",
        ] {
            assert!(doc.contains(rule), "protocol rule: {rule}");
        }
    }

    #[test]
    fn consent_delivery_user_contract() {
        let profiles = include_str!("../../../../docs/profiles.md");
        let troubleshooting =
            include_str!("../../../../skills/stellar-agent-wallet/references/troubleshooting.md");
        for (code, meaning) in [
            (
                "approval.consent_undelivered",
                "Exact Delivered evidence is missing for this approval's queued row.",
            ),
            (
                "approval.evidence_capacity",
                "All 4,096 evidence slots are occupied.",
            ),
            (
                "audit.outbox_evidence_unusable",
                "The authenticated evidence image cannot be selected or used.",
            ),
            (
                "audit.outbox_queued",
                "Consent succeeded and its audit row is queued.",
            ),
        ] {
            for doc in [profiles, troubleshooting] {
                let row = doc
                    .lines()
                    .find(|line| line.starts_with(&format!("| `{code}` |")))
                    .unwrap();
                assert!(row.contains(meaning), "meaning of {code}");
            }
        }
        for doc in [
            include_str!("../../../../docs/cli-reference/profile-and-governance.md"),
            include_str!("../../../../skills/stellar-agent-wallet/references/cli-reference.md"),
            include_str!(
                "../../../../skills/stellar-agent-wallet/references/approvals-and-audit.md"
            ),
        ] {
            for sentence in [
                "Queued success exits zero and includes `audit_code: audit.outbox_queued`; Written omits `audit_code`.",
                "It returns immediately after persistence, without waiting for delivery.",
                "Legacy queues commit a count and chain head; owner queues authenticate tagged rows and commit delivered batches.",
                "For an enforced kind, recoverable delivery and evidence errors retry the existing grant without another ceremony.",
            ] {
                assert!(doc.contains(sentence), "user contract: {sentence}");
            }
        }
    }

    #[test]
    #[serial_test::serial]
    fn require_delivery_preserves_drain_and_query_refusals() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
        let (_dir, path, store, mut writer) = initialized();
        let queries = Arc::new(AtomicUsize::new(0));
        let count = queries.clone();
        let _query_hook = test_seam::on_delivery_query(&path, move || {
            count.fetch_add(1, Ordering::SeqCst);
        });
        let held = lock_outbox(&outbox_lock_path(&path), store.as_ref()).unwrap();
        let error = require_consent_delivered(&mut writer, &[1; 32], None, "delivery").unwrap_err();
        assert_eq!(error.code(), "audit.chain_key_unavailable");
        assert!(error.to_string().contains("audit.outbox_busy"));
        assert_eq!(
            queries.load(Ordering::SeqCst),
            0,
            "a refused drain performs no query"
        );
        drop(held);
        require_consent_delivered(&mut writer, &[1; 32], None, "delivery").unwrap();
        assert_eq!(queries.load(Ordering::SeqCst), 1);
        let fault = store.clone();
        let _fault_hook =
            test_seam::on_delivery_query(&path, move || fault.set_owner_failing(true, false));
        let error = require_consent_delivered(&mut writer, &[1; 32], None, "delivery").unwrap_err();
        let expected = super::super::writer::audit_writer_refusal(
            "delivery",
            &WriterError::TipAnchorStore(TipAnchorStoreError::new("owner read fault")),
        );
        assert_eq!(
            error.code(),
            expected.code(),
            "query storage errors keep their code"
        );
        assert_eq!(error.to_string(), expected.to_string());
    }

    #[test]
    #[serial_test::serial]
    fn admission_refuses_the_4097th_identity() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());

        let (_dir, path, store, writer) = initialized();
        seed_records(&path, &store, MAX_EVIDENCE_ENTRIES, false);
        let before = evidence_snapshot(&writer);
        let outbox = keyed_outbox(&path, &store);
        let error = outbox.reserve_evidence([255; 32], 10_000, 0).unwrap_err();
        assert_eq!(error.code(), "approval.evidence_capacity");
        assert_eq!(
            error.to_string(),
            "Consent evidence capacity is full; retry after an existing approval ends."
        );
        assert_eq!(
            evidence_snapshot(&writer),
            before,
            "all admitted identities survive refusal"
        );
        assert_eq!(outbox_bytes(&path), header(1));
        assert_eq!(
            outbox
                .reserve_evidence([255; 32], 10_000, 1)
                .unwrap_err()
                .code(),
            "approval.evidence_capacity"
        );
        assert_eq!(evidence_snapshot(&writer).records(), before.records());
        assert_eq!(evidence_snapshot(&writer).time_floor_ms(), 1);
    }

    #[test]
    #[serial_test::serial]
    fn admission_is_idempotent_and_fact_bound() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());

        let (_dir, path, store, writer) = initialized();
        let outbox = keyed_outbox(&path, &store);
        let reservation = outbox.reserve_evidence([1; 32], 100, 1).unwrap();
        let before = (slots(&path), store.outbox_item_writes());
        assert_eq!(
            outbox.reserve_evidence([1; 32], 100, 1).unwrap(),
            reservation
        );
        assert_eq!((slots(&path), store.outbox_item_writes()), before);
        assert!(
            outbox.reserve_evidence([1; 32], 101, 1).is_err(),
            "conflicting expiry refuses"
        );
        assert!(outbox.reserve_evidence([2; 32], 1, 1).is_err());
        assert_eq!(evidence_snapshot(&writer).records().len(), 1);
        assert_eq!(
            EvidenceReservation::deadline(100, u64::MAX).unwrap(),
            900_100
        );
        assert_eq!(EvidenceReservation::deadline(100, 20).unwrap(), 120);
        assert!(EvidenceReservation::deadline(u64::MAX, 1).is_err());
        let plain = AuditOutbox::for_log(&path, store.clone());
        assert!(plain.reserve_evidence([2; 32], 100, 1).is_err());
        assert_eq!((slots(&path), store.outbox_item_writes()), before);
    }

    #[test]
    #[serial_test::serial]
    fn queued_binding_precedes_row_write() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());

        for rollback_fails in [false, true] {
            let (_dir, path, store, mut writer) = initialized();
            let outbox = keyed_outbox(&path, &store);
            let reservation = outbox.reserve_evidence([1; 32], 100, 0).unwrap();
            let outbox = outbox.with_evidence_reservation(reservation);
            let before = outbox_bytes(&path);
            test_seam::arm_sync_failure(outbox.path(), test_seam::SyncStep::File);
            if rollback_fails {
                test_seam::arm_sync_failure(outbox.path(), test_seam::SyncStep::Rollback);
            }
            assert!(matches!(
                outbox.append_queued(&row("failed")),
                Err(WriterError::Io(_))
            ));
            let evidence = evidence_snapshot(&writer);
            assert_eq!(
                evidence.records()[0].state,
                RecordState::Queued,
                "Queued precedes the row write"
            );
            if rollback_fails {
                assert_ne!(outbox_bytes(&path), before);
                assert_eq!(writer.drain_outbox().unwrap(), 1);
                assert_eq!(
                    evidence_snapshot(&writer).records()[0].state,
                    RecordState::Delivered
                );
            } else {
                assert_eq!(outbox_bytes(&path), before);
            }
            assert_eq!(delivered(&path, "failed"), usize::from(rollback_fails));
        }
    }

    #[test]
    #[serial_test::serial]
    fn queued_binding_rejects_retargeting() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());

        let (_dir, path, store, mut writer) = initialized();
        let outbox = keyed_outbox(&path, &store);
        let reservation = outbox.reserve_evidence([1; 32], 100, 0).unwrap();
        let outbox = outbox.with_evidence_reservation(reservation);
        let first = outbox.append_queued(&row("first")).unwrap();
        let before = (
            outbox_bytes(&path),
            slots(&path),
            store.outbox_item_writes(),
        );
        assert!(
            outbox.append_queued(&row("other")).is_err(),
            "a drainable digest cannot be retargeted"
        );
        assert_eq!(
            (
                outbox_bytes(&path),
                slots(&path),
                store.outbox_item_writes()
            ),
            before
        );
        assert_eq!(
            evidence_snapshot(&writer).records()[0].digest,
            *first.digest()
        );
        assert_eq!(writer.drain_outbox().unwrap(), 1);
        let delivered_state = (
            outbox_bytes(&path),
            slots(&path),
            store.load_outbox_owner_state(1).unwrap(),
        );
        assert!(
            outbox.append_queued(&row("again")).is_err(),
            "a Delivered record cannot be retargeted"
        );
        assert_eq!(
            (
                outbox_bytes(&path),
                slots(&path),
                store.load_outbox_owner_state(1).unwrap()
            ),
            delivered_state
        );
        let record = evidence_snapshot(&writer).records()[0].clone();
        assert_eq!(
            (record.state, record.digest),
            (RecordState::Delivered, *first.digest()),
            "Delivered stays at the first digest"
        );
    }

    #[test]
    #[serial_test::serial]
    fn a_refused_row_write_permits_a_retargeted_retry() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());

        let (_dir, path, store, mut writer) = initialized();
        let outbox = keyed_outbox(&path, &store);
        let reservation = outbox.reserve_evidence([1; 32], 100, 0).unwrap();
        let outbox = outbox.with_evidence_reservation(reservation);
        test_seam::arm_sync_failure(outbox.path(), test_seam::SyncStep::File);
        assert!(outbox.append_queued(&row("failed")).is_err());
        let first = evidence_snapshot(&writer).records()[0].digest;
        let reference = outbox
            .append_queued(&row("retry"))
            .expect("an absent row permits retargeting");
        assert_ne!(first, *reference.digest());
        assert_eq!(writer.drain_outbox().unwrap(), 1);
        assert!(evidence_snapshot(&writer).contains_delivered(&[1; 32], &reference));
        assert_eq!(delivered(&path, "failed"), 0);
        assert_eq!(delivered(&path, "retry"), 1);
    }

    #[test]
    #[serial_test::serial]
    fn a_full_file_reclaims_expired_entries_before_refusing() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());

        let (_dir, path, store, writer) = initialized();
        seed_records(&path, &store, MAX_EVIDENCE_ENTRIES, true);
        keyed_outbox(&path, &store)
            .reserve_evidence([255; 32], 10_000, 10)
            .expect("expiry GC precedes admission");
        let evidence = evidence_snapshot(&writer);
        assert_eq!(evidence.records().len(), MAX_EVIDENCE_ENTRIES);
        assert!(
            !evidence
                .records()
                .iter()
                .any(|record| record.identity == evidence_record(0).identity)
        );
        assert_eq!(evidence.time_floor_ms(), 10);
    }

    #[test]
    #[serial_test::serial]
    fn reservation_refuses_another_scope() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());

        let (_dir, path, store, writer) = initialized();
        let outbox = keyed_outbox(&path, &store);
        outbox.reserve_evidence([1; 32], 100, 0).unwrap();
        let (_other_dir, other_path, other_store, mut other_writer) = keyed_fixture();
        other_store.set_evidence_scope([99; 32]);
        other_writer.initialize_consent_evidence().unwrap();
        let reservation = keyed_outbox(&other_path, &other_store)
            .reserve_evidence([1; 32], 100, 0)
            .unwrap();
        let before = (
            slots(&path),
            outbox_bytes(&path),
            store.outbox_item_writes(),
        );
        assert!(
            outbox
                .with_evidence_reservation(reservation)
                .append_queued(&row("foreign"))
                .is_err(),
            "a foreign scope refuses"
        );
        assert_eq!(
            (
                slots(&path),
                outbox_bytes(&path),
                store.outbox_item_writes()
            ),
            before
        );
        assert_eq!(
            evidence_snapshot(&writer).records()[0].state,
            RecordState::Reserved
        );
    }

    #[test]
    #[serial_test::serial]
    fn a_drain_without_consent_rows_leaves_evidence_untouched() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());

        let (_dir, path, store, mut writer) = initialized();
        plant(&path, 0, b"broken");
        plant(&path, 1, b"broken");
        let before = (slots(&path), committed(&store));
        keyed_outbox(&path, &store).append(&row("plain")).unwrap();
        assert_eq!(
            writer.drain_outbox().unwrap(),
            1,
            "ordinary rows need no evidence read"
        );
        assert_eq!((slots(&path), committed(&store)), before);
        drop(writer);
        let (_dir, path, store, mut rotation, old) = rotation_fixture(storage_sandbox.path());
        rotation.fence_outbox_for_key_change().unwrap();
        store.set_reload(Ok(Some(NEXT_KEY)));
        drop(rotation);
        let mut rotation = restart_rotation(&path, &store, NEXT_KEY);
        assert_eq!(rotation.drain_outbox().unwrap(), 0);
        assert_rotated(&path, &store, &old, 8, &NEXT_KEY);
    }

    #[test]
    #[serial_test::serial]
    fn rollback_deferred_drain_preserves_queued_consent() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());

        assert_damaged_image_refuses_loss_classification();
        let (_dir, path, store, mut writer) = initialized();
        reserve_row(&keyed_outbox(&path, &store), [1; 32], "waiting");
        keyed_outbox(&path, &store)
            .append(&row("mixed-plain"))
            .unwrap();
        plant(&path, 0, &sealed(&store, 9, &[3]));
        plant(&path, 1, &sealed(&store, 9, &[4]));
        let before = (
            slots(&path),
            outbox_bytes(&path),
            owner_state(&store),
            store.outbox_item_writes(),
        );
        assert_eq!(
            writer.drain_outbox().unwrap(),
            0,
            "rollback defers the batch"
        );
        assert_eq!(
            (
                slots(&path),
                outbox_bytes(&path),
                owner_state(&store),
                store.outbox_item_writes()
            ),
            before
        );
        assert_eq!(delivered(&path, "waiting"), 0);
        assert_eq!(delivered(&path, "mixed-plain"), 0);
        assert_eq!(evidence_refusal(writer.outbox_evidence()), "owner rollback");
        assert!(
            writer.outbox_loss().is_err(),
            "classification refuses before revocation"
        );
    }

    /// Loss classification beside queued consent refuses a missing or damaged
    /// selected image with its integrity reason, writing nothing.
    fn assert_damaged_image_refuses_loss_classification() {
        for (damage, reason) in [("missing", "missing image"), ("corrupt", "head")] {
            let (_dir, path, store, writer) = initialized();
            reserve_row(&keyed_outbox(&path, &store), [1; 32], "waiting");
            let active = active_slot(&path, &store);
            let slot = &consent_evidence::slot_paths(&path)[active];
            if damage == "missing" {
                for slot in consent_evidence::slot_paths(&path) {
                    fs::remove_file(slot).unwrap();
                }
            } else {
                let mut bytes = fs::read(slot).unwrap();
                bytes[200] ^= 1;
                fs::write(slot, bytes).unwrap();
            }
            let before = (
                slots(&path),
                outbox_bytes(&path),
                owner_state(&store),
                store.outbox_item_writes(),
            );
            assert_eq!(
                evidence_refusal(writer.outbox_loss().map(|_| None)),
                reason,
                "{damage}: loss classification refuses before revocation"
            );
            assert_eq!(
                (
                    slots(&path),
                    outbox_bytes(&path),
                    owner_state(&store),
                    store.outbox_item_writes()
                ),
                before,
                "{damage}"
            );
        }
    }

    #[test]
    #[serial_test::serial]
    fn evidence_time_floor_is_write_free() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());

        let (_dir, path, store, writer) = initialized();
        let outbox = keyed_outbox(&path, &store);
        assert_eq!(outbox.advance_evidence_floor(80).unwrap(), 80);
        let before = (
            slots(&path),
            owner_state(&store),
            store.outbox_item_writes(),
        );
        assert_eq!(outbox.evidence_time_floor().unwrap(), 80);
        assert_eq!(
            (
                slots(&path),
                owner_state(&store),
                store.outbox_item_writes()
            ),
            before
        );
        let newer = sealed(&store, 9, &[9]);
        plant(&path, 0, &newer);
        assert_eq!(outbox.evidence_time_floor().unwrap(), 90);
        assert_eq!(
            committed(&store).unwrap().head,
            consent_evidence::head(&newer)
        );
        drop(writer);
        let (_dir, path, store, _writer) = keyed_fixture();
        let outbox = keyed_outbox(&path, &store);
        assert_eq!(outbox.evidence_time_floor().unwrap(), 0);
        plant(&path, 0, b"orphan");
        assert!(matches!(
            outbox.evidence_time_floor(),
            Err(WriterError::OutboxEvidenceUnusable {
                reason: "evidence image without owner"
            })
        ));
    }

    #[test]
    #[serial_test::serial]
    fn queued_is_not_delivered() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());

        let (_dir, path, store, mut writer) = initialized();
        let reference = reserve_row(&keyed_outbox(&path, &store), [1; 32], "queued");
        assert!(
            !evidence_snapshot(&writer).contains_delivered(&[1; 32], &reference),
            "Queued is not Delivered"
        );
        assert_eq!(writer.drain_outbox().unwrap(), 1);
        assert!(evidence_snapshot(&writer).contains_delivered(&[1; 32], &reference));
        assert!(!evidence_snapshot(&writer).contains_delivered(&[2; 32], &reference));
    }

    #[test]
    #[serial_test::serial]
    fn anchor_failure_commits_no_delivery() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());

        let (_dir, path, store, mut writer) = initialized();
        let reference = reserve_row(&keyed_outbox(&path, &store), [1; 32], "anchored");
        let before = (slots(&path), owner_state(&store), outbox_bytes(&path));
        store.fail_next_writes(3);
        assert!(
            matches!(writer.drain_outbox(), Err(WriterError::TipAnchorStore(_))),
            "a failed anchor refuses delivery"
        );
        assert_eq!(
            (slots(&path), owner_state(&store), outbox_bytes(&path)),
            before
        );
        assert!(!evidence_snapshot(&writer).contains_delivered(&[1; 32], &reference));
        assert_eq!(writer.drain_outbox().unwrap(), 1);
        assert!(evidence_snapshot(&writer).contains_delivered(&[1; 32], &reference));
        assert_eq!(delivered(&path, "anchored"), 2);
    }

    #[test]
    #[serial_test::serial]
    fn unreserved_orphan_does_not_consume_capacity() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());

        let (_dir, path, store, mut writer) = initialized();
        keyed_outbox(&path, &store)
            .append_queued(&row("orphan"))
            .unwrap();
        assert_eq!(writer.drain_outbox().unwrap(), 1);
        assert!(
            evidence_snapshot(&writer).records().is_empty(),
            "unreserved rows create no record"
        );
        assert_eq!(delivered(&path, "orphan"), 1);
    }

    #[test]
    #[serial_test::serial]
    fn old_live_evidence_survives_full_drains() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());

        let (_dir, path, store, mut writer) = initialized();
        let outbox = keyed_outbox(&path, &store);
        let oldest = reserve_row(&outbox, evidence_record(0).identity, "oldest");
        writer.drain_outbox().unwrap();
        for batch in 0..4 {
            for index in 0..MAX_OUTBOX_ROWS {
                let n = 1 + batch * MAX_OUTBOX_ROWS + index;
                reserve_row(
                    &outbox,
                    evidence_record(n as u32).identity,
                    &format!("row-{n}"),
                );
            }
            assert_eq!(writer.drain_outbox().unwrap(), MAX_OUTBOX_ROWS);
            assert!(
                evidence_snapshot(&writer)
                    .contains_delivered(&evidence_record(0).identity, &oldest),
                "the oldest live grant survives full drains"
            );
        }
        assert_eq!(evidence_snapshot(&writer).records().len(), 257);
    }

    #[test]
    #[serial_test::serial]
    fn publication_stops_preserve_delivery() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());

        use test_seam::Stop;
        for stop in [
            Stop::EvidenceOwnerStored,
            Stop::OwnerStored,
            Stop::ReplacementSynced,
            Stop::Renamed,
            Stop::DirectorySynced,
        ] {
            let (dir, path, store, mut writer) = initialized();
            let outbox = keyed_outbox(&path, &store);
            outbox.append(&row("plain")).unwrap();
            let reference = reserve_in_process(dir.path(), &store, 1, "published");
            let bytes = outbox_bytes(&path);
            let digests: Vec<_> = parse_lines(&bytes).lines[1..]
                .iter()
                .map(|line| test_seam::delivered_row_digest(line).unwrap())
                .collect();
            test_seam::arm_stop(&outbox_path(&path), stop);
            assert!(writer.drain_outbox().is_err());
            let owner = owner_state(&store).unwrap();
            let closed = owner.closed.as_ref().unwrap();
            assert_eq!((owner.g, closed.g, closed.n), (2, 1, 2));
            assert_eq!(
                closed.batch,
                batch_digest(&digests),
                "closed includes every ordered digest"
            );
            assert!(evidence_snapshot(&writer).contains_delivered(&[1; 32], &reference));
            let suffix = reserve_in_process(dir.path(), &store, 2, "suffix");
            drop(writer);
            let writer = reopen(&path, &store);
            assert!(evidence_snapshot(&writer).contains_delivered(&[1; 32], &reference));
            assert!(evidence_snapshot(&writer).contains_delivered(&[2; 32], &suffix));
            assert_eq!(delivered(&path, "suffix"), 1);
            assert_eq!(delivered(&path, "plain"), 1);
            assert_eq!(
                delivered(&path, "published"),
                1,
                "a committed prefix is not repeated: {stop:?}"
            );
        }
    }

    #[test]
    #[serial_test::serial]
    fn precommit_stops_allow_at_least_once_delivery() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());

        use test_seam::Stop;
        for stop in [
            Stop::BeforeAppends,
            Stop::AfterAppend(1),
            Stop::AnchorChecked,
            Stop::EvidenceCandidateSynced,
        ] {
            let (_dir, path, store, mut writer) = initialized();
            let reference = reserve_row(&keyed_outbox(&path, &store), [1; 32], "pending");
            let root = committed(&store);
            test_seam::arm_stop(&outbox_path(&path), stop);
            assert!(writer.drain_outbox().is_err());
            assert_eq!(committed(&store), root, "owner stays old before commit");
            let evidence = evidence_snapshot(&writer);
            assert_eq!(
                evidence.contains_delivered(&[1; 32], &reference),
                stop == Stop::EvidenceCandidateSynced,
                "only a post-anchor durable candidate supplies recovered coverage"
            );
            drop(writer);
            let writer = reopen(&path, &store);
            assert!(evidence_snapshot(&writer).contains_delivered(&[1; 32], &reference));
            assert_eq!(
                delivered(&path, "pending"),
                if stop == Stop::BeforeAppends { 1 } else { 2 }
            );
        }
        let (_dir, path, store, mut writer) = initialized();
        let reference = reserve_row(&keyed_outbox(&path, &store), [1; 32], "store-fault");
        let root = committed(&store);
        let queued = outbox_bytes(&path);
        store.set_owner_failing(false, true);
        assert!(matches!(
            writer.drain_outbox(),
            Err(WriterError::TipAnchorStore(_))
        ));
        assert_eq!(committed(&store), root);
        assert_eq!(outbox_bytes(&path), queued);
        assert!(slots(&path).iter().all(Option::is_some));
        assert!(matches!(
            writer.outbox_evidence(),
            Err(WriterError::TipAnchorStore(_))
        ));
        store.set_owner_failing(false, false);
        assert!(evidence_snapshot(&writer).contains_delivered(&[1; 32], &reference));
        assert_eq!(writer.drain_outbox().unwrap(), 1);
        assert_eq!(delivered(&path, "store-fault"), 2);
    }

    #[test]
    #[serial_test::serial]
    fn release_follows_final_use() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());

        let (_dir, path, store, mut writer) = initialized();
        let outbox = keyed_outbox(&path, &store);
        let reference = reserve_row(&outbox, [1; 32], "retryable");
        writer.drain_outbox().unwrap();
        outbox.reserve_evidence([2; 32], 9_000, 1).unwrap();
        assert!(
            evidence_snapshot(&writer).contains_delivered(&[1; 32], &reference),
            "retryable consumed grants retain proof"
        );
        outbox.release_evidence([1; 32]).unwrap();
        assert!(!evidence_snapshot(&writer).contains_delivered(&[1; 32], &reference));
        let before = (slots(&path), store.outbox_item_writes());
        outbox.release_evidence([1; 32]).unwrap();
        assert_eq!((slots(&path), store.outbox_item_writes()), before);
    }

    #[test]
    #[serial_test::serial]
    fn expiry_floor_prevents_clock_revival() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());

        let (_dir, path, store, writer) = initialized();
        let outbox = keyed_outbox(&path, &store);
        let reservation = outbox.reserve_evidence([1; 32], 100, 10).unwrap();
        assert_eq!(outbox.advance_evidence_floor(99).unwrap(), 99);
        assert_eq!(evidence_snapshot(&writer).records().len(), 1);
        assert_eq!(outbox.advance_evidence_floor(100).unwrap(), 100);
        assert!(evidence_snapshot(&writer).records().is_empty());
        let before = (
            outbox_bytes(&path),
            slots(&path),
            store.outbox_item_writes(),
        );
        let cached = outbox
            .clone()
            .with_evidence_reservation(reservation)
            .append_queued(&row("revived"));
        assert!(
            matches!(
                cached,
                Err(WriterError::OutboxEvidenceUnusable {
                    reason: "reservation scope or expiry"
                })
            ),
            "a reservation held past its collection names the expiry: {cached:?}"
        );
        assert_eq!(
            (
                outbox_bytes(&path),
                slots(&path),
                store.outbox_item_writes()
            ),
            before
        );
        assert_eq!(
            outbox.advance_evidence_floor(1).unwrap(),
            100,
            "the floor never decreases"
        );
        assert!(outbox.reserve_evidence([1; 32], 100, 1).is_err());
        assert!(evidence_snapshot(&writer).records().is_empty());
    }

    #[test]
    #[serial_test::serial]
    fn legacy_pins_survive_floor_advancement() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());

        let (_dir, path, store, writer) = initialized();
        let batch = OutboxBatch::read_locked(&path, store.as_ref()).unwrap();
        let pin = EvidenceRecord::legacy_pin([7; 32]);
        batch
            .commit_evidence_change(&path, store.as_ref(), &ROW_KEY, false, |image, _| {
                image.records.push(pin.clone());
                Ok(())
            })
            .unwrap();
        drop(batch);
        let outbox = keyed_outbox(&path, &store);
        let owner = store.load_outbox_owner_state(1).unwrap();
        assert_eq!(
            outbox
                .reserve_evidence(pin.identity, u64::MAX, 0)
                .unwrap_err()
                .to_string(),
            evidence_wallet_error(&path, "conflicting reservation"),
            "a pin's identity refuses a reservation with its own expiry"
        );
        assert_eq!(store.load_outbox_owner_state(1).unwrap(), owner);
        assert_eq!(
            evidence_snapshot(&writer).records(),
            std::slice::from_ref(&pin)
        );
        assert_eq!(outbox.advance_evidence_floor(u64::MAX).unwrap(), u64::MAX);
        assert_eq!(
            evidence_snapshot(&writer).records(),
            std::slice::from_ref(&pin),
            "pins survive every clock"
        );
        assert!(outbox.release_evidence(pin.identity).is_err());
    }

    #[test]
    #[serial_test::serial]
    fn a_full_file_still_queues_and_delivers_existing_grants() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());

        let (_dir, path, store, mut writer) = initialized();
        seed_records(&path, &store, MAX_EVIDENCE_ENTRIES, false);
        let outbox = keyed_outbox(&path, &store);
        let before = evidence_snapshot(&writer).records()[1..].to_vec();
        let reference = reserve_row(&outbox, evidence_record(0).identity, "last");
        assert_eq!(writer.drain_outbox().unwrap(), 1);
        let evidence = evidence_snapshot(&writer);
        assert!(evidence.contains_delivered(&evidence_record(0).identity, &reference));
        assert_eq!(evidence.records().len(), MAX_EVIDENCE_ENTRIES);
        assert_eq!(evidence.records()[1..], before);
    }

    #[test]
    #[serial_test::serial]
    fn a_reserved_reference_waits_for_owner_commit() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());

        let (_dir, path, store, mut writer) = initialized();
        let outbox = keyed_outbox(&path, &store);
        let reference = reserve_row(&outbox, [1; 32], "anchored");
        let queued = evidence_snapshot(&writer);
        assert_eq!(
            queued.records()[0].state,
            RecordState::Queued,
            "an append binds Queued and never Delivered"
        );
        assert!(!queued.contains_delivered(&[1; 32], &reference));
        let root = committed(&store).unwrap().head;
        store.set_owner_failing(false, true);
        let result = writer.drain_outbox();
        assert!(
            matches!(result, Err(WriterError::TipAnchorStore(_))),
            "{result:?}"
        );
        store.set_owner_failing(false, false);
        assert_eq!(
            committed(&store).unwrap().head,
            root,
            "a failed owner store commits no delivery"
        );
        assert_eq!(writer.drain_outbox().unwrap(), 1);
        assert!(evidence_snapshot(&writer).contains_delivered(&[1; 32], &reference));
        assert_eq!(delivered(&path, "anchored"), 2);
        assert_eq!(writer.drain_outbox().unwrap(), 0);
    }

    #[test]
    #[serial_test::serial]
    fn appender_evidence_apis_refuse_a_rotation_fence() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());

        let (_dir, path, store, mut writer, _old) = rotation_fixture(storage_sandbox.path());
        writer.fence_outbox_for_key_change().unwrap();
        drop(writer);
        store.set_reload(Ok(Some(ROW_KEY)));
        let images = slots(&path);
        let writes = owner_writes(&store);
        let outbox = keyed_outbox(&path, &store);
        let fence = tagged_refusal(1, "tagged record whose tag does not verify");
        let refused = outbox.reserve_evidence([200; 32], 9_000, 0);
        assert_eq!(
            refused.map_err(|error| error.to_string()),
            Err(super::super::writer::audit_writer_refusal(&basename(&path), &fence).to_string()),
            "a fence refuses admission"
        );
        for result in [
            outbox.release_evidence(evidence_record(2).identity),
            outbox.advance_evidence_floor(80).map(drop),
            outbox.evidence_time_floor().map(drop),
        ] {
            assert_eq!(
                result.map_err(|error| error.to_string()),
                Err(fence.to_string())
            );
        }
        assert_eq!(slots(&path), images);
        assert_eq!(owner_writes(&store), writes);
    }

    #[test]
    #[serial_test::serial]
    fn acknowledgement_covers_only_selected_rows() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());

        let (_dir, path, store, mut writer) = initialized();
        let outbox = keyed_outbox(&path, &store);
        let retained = reserve_row(&outbox, [1; 32], "retained");
        writer.drain_outbox().unwrap();
        let selected = reserve_row(&outbox, [2; 32], "selected");
        let discarded = reserve_row(&outbox, [3; 32], "discarded");
        let bytes = outbox_bytes(&path);
        let lines = parse_lines(&bytes).lines;
        let mut damaged = [lines[0], lines[1]].join(&b'\n');
        damaged.extend_from_slice(b"\n{\"k\":\"row\"}\n");
        fs::write(outbox.path(), damaged).unwrap();
        drop(writer);
        let mut writer = AuditWriter::open_for_outbox_acknowledgement(
            path.clone(),
            Some(Zeroizing::new(ROW_KEY)),
            store.clone(),
            crate::audit_log::BindingHistory::NotRecorded,
        )
        .unwrap();
        assert!(writer.outbox_loss().unwrap().is_some());
        let report = writer
            .acknowledge_outbox_loss("verified revocation", Default::default())
            .unwrap();
        assert_eq!((report.drained, report.discarded), (1, 1));
        let evidence = evidence_snapshot(&writer);
        assert!(evidence.contains_delivered(&[1; 32], &retained));
        assert!(evidence.contains_delivered(&[2; 32], &selected));
        assert!(
            !evidence.contains_delivered(&[3; 32], &discarded),
            "discarded rows receive no delivery evidence"
        );
        assert_eq!(evidence.records().len(), 3);
        assert_eq!(delivered(&path, "selected"), 1);
        assert_eq!(delivered(&path, "discarded"), 0);
    }

    #[test]
    #[serial_test::serial]
    fn rotation_fence_recommits_newer_candidate() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());

        let (_dir, path, store, mut writer, _old) = rotation_fixture(storage_sandbox.path());
        let newer = sealed(&store, 9, &[2, 9]);
        plant(&path, 1, &newer);
        let writes = owner_writes(&store);
        writer.fence_outbox_for_key_change().unwrap();
        assert_eq!(
            committed(&store).unwrap().head,
            consent_evidence::head(&newer),
            "fencing recommits the selected candidate"
        );
        assert_eq!(owner_writes(&store), writes + 1);
        assert_eq!(slots(&path), [Some(newer.clone()), Some(newer.clone())]);
        store.set_reload(Ok(Some(NEXT_KEY)));
        writer
            .switch_entry_tag_key(Zeroizing::new(NEXT_KEY), "rotation")
            .unwrap();
        assert_rotated(&path, &store, &newer, 10, &NEXT_KEY);
        drop(writer);
        let (_dir, path, _store, mut writer, _old) = rotation_fixture(storage_sandbox.path());
        fs::write(outbox_path(&path), encode_generation_line(&NEXT_KEY, 1)).unwrap();
        let error = writer.fence_outbox_for_key_change().unwrap_err();
        assert!(matches!(
            error,
            WriterError::OutboxUnusable {
                reason: "queue not drained before a key change",
                ..
            }
        ));
    }

    #[test]
    #[serial_test::serial]
    fn rotation_uncertain_retag_owner_resolves_actual_commit() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());

        for outcome in 0..3 {
            let (_dir, path, store, writer, old) = rotation_fixture(storage_sandbox.path());
            drop(writer);
            let uncertain = Arc::new(UncertainStore {
                inner: store.clone(),
                reread_fails: outcome == 2,
                stored: std::sync::atomic::AtomicBool::new(false),
            });
            let mut writer = AuditWriter::open_for_key_rotation(
                path.clone(),
                Some(Zeroizing::new(ROW_KEY)),
                uncertain,
                crate::audit_log::BindingHistory::NotRecorded,
            )
            .unwrap();
            writer.fence_outbox_for_key_change().unwrap();
            store.set_owner_failing(false, outcome == 1);
            store.set_reload(Ok(Some(NEXT_KEY)));
            let result = writer.switch_entry_tag_key(Zeroizing::new(NEXT_KEY), "rotation");
            if outcome == 0 {
                assert!(
                    result.is_ok(),
                    "a persisted retag confirms an uncertain owner store: {result:?}"
                );
                assert_rotated(&path, &store, &old, 8, &NEXT_KEY);
            } else {
                assert!(
                    matches!(result, Err(WriterError::TipAnchorStore(_))),
                    "rejected or unreadable stores remain storage failures"
                );
                assert_eq!(outbox_bytes(&path), encode_fence_line(1));
                assert_eq!(
                    committed(&store).unwrap().g,
                    if outcome == 1 { 7 } else { 8 }
                );
                assert_eq!(slots(&path)[0].as_ref(), Some(&old));
            }
            drop(writer);
            store.set_owner_failing(false, false);
            let _writer = restart_rotation(&path, &store, NEXT_KEY);
            assert_rotated(&path, &store, &old, 8, &NEXT_KEY);
        }
    }

    #[test]
    fn evidence_protocol_documents_lifetime() {
        const DOC: &str = include_str!("../../../../docs/maintainers/audit-log-recovery.md");
        for sentence in [
            "Every admitted approval retains its slot throughout every permitted use.",
            "The 4,096 slots count Reserved, Queued, Delivered, and unresolved migration pins together.",
            "Only an anchored writer marks a matching Queued record Delivered.",
            "A read-only recommit is exempt from that overflow check.",
            "The caller authenticates the approval identity, the full queue reference, the scope association, and the conservative deadline before it calls.",
            "`audit verify` authenticates both evidence files under the one stored key it reads and changes no file or protected item.",
        ] {
            assert!(DOC.contains(sentence), "{sentence}");
        }
    }

    // Migration pin adoption.

    /// A log whose v1 owner kept two queued references as recent evidence,
    /// initialized so that each became a migration pin.
    fn pinned() -> (
        TempDir,
        PathBuf,
        Arc<InMemoryTipAnchorStore>,
        AuditWriter,
        [OutboxRowRef; 2],
    ) {
        let (dir, path, store, mut writer) = keyed_fixture();
        let outbox = keyed_outbox(&path, &store);
        let first = outbox.append_queued(&row("first")).unwrap();
        let second = outbox.append_queued(&row("second")).unwrap();
        assert_eq!(writer.drain_outbox().unwrap(), 2);
        writer.initialize_consent_evidence().unwrap();
        (dir, path, store, writer, [first, second])
    }

    type Durable = (
        [Option<Vec<u8>>; 2],
        Vec<u8>,
        Option<String>,
        Vec<(&'static str, u64)>,
        usize,
    );

    /// Both slots, the queue, the active owner, and the item and record writes.
    fn durable(path: &Path, store: &InMemoryTipAnchorStore) -> Durable {
        let generation = store
            .load_carrier_record()
            .unwrap()
            .map_or(0, |record| record.generation);
        (
            slots(path),
            outbox_bytes(path),
            store.load_outbox_owner_state(generation).unwrap(),
            store.outbox_item_writes(),
            store.carrier_record_writes(),
        )
    }

    fn evidence_wallet_error(path: &Path, reason: &'static str) -> String {
        super::super::writer::audit_writer_refusal(&basename(path), &evidence_unusable(reason))
            .to_string()
    }

    /// The index of the slot whose head the owner commits.
    fn active_slot(path: &Path, store: &InMemoryTipAnchorStore) -> usize {
        let head = committed(store).unwrap().head;
        slots(path)
            .iter()
            .position(|slot| slot.as_deref().map(consent_evidence::head) == Some(head))
            .unwrap()
    }

    fn reserved_record(n: u32) -> EvidenceRecord {
        EvidenceRecord {
            digest: [0; 32],
            generation: 0,
            sequence: 0,
            state: RecordState::Reserved,
            ..evidence_record(n)
        }
    }

    fn adopted(identity: [u8; 32], reference: &OutboxRowRef, expires_at_ms: u64) -> EvidenceRecord {
        EvidenceRecord {
            identity,
            digest: reference.digest,
            expires_at_ms,
            generation: reference.generation,
            sequence: reference.sequence,
            state: RecordState::Delivered,
        }
    }

    #[test]
    #[serial_test::serial]
    fn migration_adoption_checks_context() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());

        let (_dir, path, store, writer, [first, _]) = pinned();
        let identity = [0xa1; 32];
        let before = durable(&path, &store);
        let unkeyed = AuditOutbox::for_log(&path, store.clone())
            .adopt_evidence_pin(identity, &first, 9_000)
            .unwrap_err();
        assert_eq!(
            unkeyed.to_string(),
            super::super::writer::audit_writer_refusal(&basename(&path), &queued_key_required())
                .to_string()
        );
        assert_eq!(durable(&path, &store), before);
        let outbox = keyed_outbox(&path, &store);
        assert_eq!(outbox.advance_evidence_floor(500).unwrap(), 500);
        let floored = durable(&path, &store);
        assert_eq!(
            outbox
                .adopt_evidence_pin(identity, &first, 500)
                .unwrap_err()
                .to_string(),
            evidence_wallet_error(&path, "expired reservation"),
            "an expiry equal to the floor refuses"
        );
        assert_eq!(durable(&path, &store), floored);
        let scope = store.outbox_evidence_scope().unwrap();
        store.set_evidence_scope([0x99; 32]);
        assert_eq!(
            outbox
                .adopt_evidence_pin(identity, &first, 501)
                .unwrap_err()
                .to_string(),
            evidence_wallet_error(&path, "scope"),
            "an image of another scope refuses"
        );
        assert_eq!(durable(&path, &store), floored);
        store.set_evidence_scope(scope);
        outbox.adopt_evidence_pin(identity, &first, 501).unwrap();
        assert!(evidence_snapshot(&writer).contains_delivered(&identity, &first));
        drop(writer);

        let (_dir, path, store, writer, [first, _]) = pinned();
        drop(writer);
        rotation_writer(&path, &store)
            .fence_outbox_for_key_change()
            .unwrap();
        let fenced = durable(&path, &store);
        assert_eq!(
            keyed_outbox(&path, &store)
                .adopt_evidence_pin(identity, &first, 9_000)
                .unwrap_err()
                .to_string(),
            super::super::writer::audit_writer_refusal(
                &basename(&path),
                &tagged_refusal(1, "tagged record whose tag does not verify")
            )
            .to_string(),
            "a rotation fence refuses adoption"
        );
        assert_eq!(durable(&path, &store), fenced);
    }

    #[test]
    #[serial_test::serial]
    fn migration_adopts_exact_verified_reference() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());

        let (_dir, path, store, writer, [first, second]) = pinned();
        let outbox = keyed_outbox(&path, &store);
        let identity = [0xa1; 32];
        let before = durable(&path, &store);
        let mut wrong = first;
        wrong.digest = [0xee; 32];
        assert_eq!(
            outbox
                .adopt_evidence_pin(identity, &wrong, 9_000)
                .unwrap_err()
                .to_string(),
            evidence_wallet_error(&path, "missing migration pin"),
            "a different digest proves nothing"
        );
        let mut unsequenced = first;
        unsequenced.sequence = 0;
        assert_eq!(
            outbox
                .adopt_evidence_pin(identity, &unsequenced, 9_000)
                .unwrap_err()
                .to_string(),
            evidence_wallet_error(&path, "layout"),
            "a delivered record needs a positive sequence"
        );
        assert_eq!(durable(&path, &store), before);
        let batch = OutboxBatch::read_locked(&path, store.as_ref()).unwrap();
        batch
            .commit_evidence_change(&path, store.as_ref(), &ROW_KEY, false, |image, _| {
                image.records.extend((0..4094).map(reserved_record));
                image.records.sort_by_key(|record| record.identity);
                Ok(())
            })
            .unwrap();
        drop(batch);
        let full = evidence_snapshot(&writer).records().to_vec();
        assert_eq!(full.len(), MAX_EVIDENCE_ENTRIES);
        let second_pin = EvidenceRecord::legacy_pin(*second.digest());
        outbox.adopt_evidence_pin(identity, &first, 9_000).unwrap();
        let evidence = evidence_snapshot(&writer);
        let mut expected: Vec<EvidenceRecord> = full
            .iter()
            .filter(|record| record.digest != *first.digest())
            .cloned()
            .chain([adopted(identity, &first, 9_000)])
            .collect();
        expected.sort_by_key(|record| record.identity);
        assert_eq!(
            evidence.records(),
            expected.as_slice(),
            "only the matching pin changes"
        );
        assert!(evidence.contains_delivered(&identity, &first));
        assert!(evidence.records().contains(&second_pin));
        outbox
            .adopt_evidence_pin(second_pin.identity, &second, 9_000)
            .unwrap();
        let evidence = evidence_snapshot(&writer);
        assert!(
            evidence.contains_delivered(&second_pin.identity, &second),
            "a verified identity may equal the replaced pin's identity"
        );
        assert_eq!(evidence.records().len(), MAX_EVIDENCE_ENTRIES);
        assert!(
            slots(&path)
                .iter()
                .all(|slot| slot.as_ref().map(Vec::len) == Some(consent_evidence::SLOT_BYTES))
        );
    }

    #[test]
    #[serial_test::serial]
    fn migration_adoption_is_fact_bound() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());

        let (_dir, path, store, mut writer, [first, second]) = pinned();
        let outbox = keyed_outbox(&path, &store);
        let identity = [0xa1; 32];
        let reservation = outbox.adopt_evidence_pin(identity, &first, 9_000).unwrap();
        let before = durable(&path, &store);
        assert_eq!(
            outbox.adopt_evidence_pin(identity, &first, 9_000).unwrap(),
            reservation,
            "an exact retry returns the same reservation"
        );
        assert_eq!(
            durable(&path, &store),
            before,
            "an exact retry writes nothing"
        );
        let mut moved = first;
        moved.sequence += 1;
        for (name, reference, expires_at_ms) in [
            ("expiry", &first, 9_001),
            ("coordinates", &moved, 9_000),
            ("digest", &second, 9_000),
        ] {
            assert_eq!(
                outbox
                    .adopt_evidence_pin(identity, reference, expires_at_ms)
                    .unwrap_err()
                    .to_string(),
                evidence_wallet_error(&path, "conflicting reservation"),
                "conflicting {name}"
            );
        }
        assert_eq!(
            outbox
                .adopt_evidence_pin([0xa2; 32], &first, 9_000)
                .unwrap_err()
                .to_string(),
            evidence_wallet_error(&path, "missing migration pin"),
            "an adopted reference has no pin left"
        );
        assert_eq!(durable(&path, &store), before);
        outbox.reserve_evidence([0xb1; 32], 9_000, 0).unwrap();
        reserve_row(&outbox, [0xb3; 32], "delivered");
        writer.drain_outbox().unwrap();
        reserve_row(&outbox, [0xb2; 32], "queued");
        let occupied = durable(&path, &store);
        for (state, occupant) in [
            (RecordState::Reserved, [0xb1; 32]),
            (RecordState::Queued, [0xb2; 32]),
            (RecordState::Delivered, [0xb3; 32]),
        ] {
            let evidence = evidence_snapshot(&writer);
            assert!(
                evidence
                    .records()
                    .iter()
                    .any(|record| record.identity == occupant && record.state == state),
                "{state:?}"
            );
            assert_eq!(
                outbox
                    .adopt_evidence_pin(occupant, &second, 9_000)
                    .unwrap_err()
                    .to_string(),
                evidence_wallet_error(&path, "conflicting reservation"),
                "an occupied {state:?} identity refuses"
            );
        }
        assert_eq!(durable(&path, &store), occupied);

        // At the last evidence generation an exact retry keeps the inherited
        // overflow refusal; the image stays readable.
        let active = active_slot(&path, &store);
        let mut image =
            consent_evidence::decode(slots(&path)[active].as_ref().unwrap(), &ROW_KEY).unwrap();
        image.generation = u64::MAX;
        plant(&path, 1 - active, &image.seal(&ROW_KEY));
        outbox.evidence_time_floor().unwrap();
        assert_eq!(committed(&store).unwrap().g, u64::MAX);
        let last = durable(&path, &store);
        assert_eq!(
            outbox
                .adopt_evidence_pin(identity, &first, 9_000)
                .unwrap_err()
                .to_string(),
            evidence_wallet_error(&path, "evidence-generation overflow")
        );
        assert_eq!(durable(&path, &store), last);
    }

    #[test]
    #[serial_test::serial]
    fn migration_adoption_survives_interruption() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let identity = [0xa1; 32];

        // A partial candidate leaves the selected pin.
        let (_dir, path, store, writer, [first, _]) = pinned();
        let outbox = keyed_outbox(&path, &store);
        let root = committed(&store);
        let active = active_slot(&path, &store);
        let pins = evidence_snapshot(&writer).records().to_vec();
        arm_evidence_fault(&path, 1 - active, 1);
        assert!(outbox.adopt_evidence_pin(identity, &first, 9_000).is_err());
        assert_eq!(
            committed(&store),
            root,
            "a partial candidate commits nothing"
        );
        assert_eq!(
            consent_evidence::decode(slots(&path)[active].as_ref().unwrap(), &ROW_KEY)
                .unwrap()
                .records,
            pins
        );
        assert_eq!(evidence_snapshot(&writer).records(), pins.as_slice());
        outbox.adopt_evidence_pin(identity, &first, 9_000).unwrap();
        assert!(evidence_snapshot(&writer).contains_delivered(&identity, &first));
        drop(writer);

        // A complete candidate is recommitted by the next keyed query.
        let (_dir, path, store, writer, [first, _]) = pinned();
        let outbox = keyed_outbox(&path, &store);
        let root = committed(&store);
        let active = active_slot(&path, &store);
        test_seam::arm_stop(
            &outbox_path(&path),
            test_seam::Stop::EvidenceCandidateSynced,
        );
        assert!(outbox.adopt_evidence_pin(identity, &first, 9_000).is_err());
        assert_eq!(committed(&store), root, "the owner still commits the pin");
        let candidate = slots(&path)[1 - active].clone().unwrap();
        assert!(
            consent_evidence::decode(&candidate, &ROW_KEY)
                .unwrap()
                .records
                .contains(&adopted(identity, &first, 9_000))
        );
        outbox.evidence_time_floor().unwrap();
        assert_eq!(
            committed(&store).unwrap().head,
            consent_evidence::head(&candidate)
        );
        let writes = owner_writes(&store);
        outbox.adopt_evidence_pin(identity, &first, 9_000).unwrap();
        assert_eq!(owner_writes(&store), writes, "the exact retry is a no-op");
        assert!(evidence_snapshot(&writer).contains_delivered(&identity, &first));
        drop(writer);

        // Persisted, rejected, and unreadable owner stores.
        for outcome in 0..3 {
            let (_dir, path, store, writer, [first, _]) = pinned();
            let root = committed(&store);
            store.set_owner_failing(false, outcome == 1);
            let uncertain = Arc::new(UncertainStore {
                inner: store.clone(),
                reread_fails: outcome == 2,
                stored: std::sync::atomic::AtomicBool::new(false),
            });
            let result = AuditOutbox::for_log_keyed(&path, uncertain, Zeroizing::new(ROW_KEY))
                .adopt_evidence_pin(identity, &first, 9_000);
            match outcome {
                0 => assert!(
                    result.is_ok(),
                    "a persisted store confirms the uncertain write: {result:?}"
                ),
                1 => {
                    assert_eq!(
                        result.unwrap_err().to_string(),
                        super::super::writer::audit_writer_refusal(
                            &basename(&path),
                            &WriterError::TipAnchorStore(TipAnchorStoreError::new(
                                "owner write fault"
                            ))
                        )
                        .to_string()
                    );
                    assert_eq!(committed(&store), root);
                }
                _ => assert_eq!(
                    result.unwrap_err().to_string(),
                    super::super::writer::audit_writer_refusal(
                        &basename(&path),
                        &WriterError::TipAnchorStore(TipAnchorStoreError::new(
                            "owner reread fault"
                        ))
                    )
                    .to_string()
                ),
            }
            store.set_owner_failing(false, false);
            keyed_outbox(&path, &store)
                .adopt_evidence_pin(identity, &first, 9_000)
                .unwrap();
            let evidence = evidence_snapshot(&writer);
            assert!(evidence.contains_delivered(&identity, &first), "{outcome}");
            assert_eq!(
                evidence
                    .records()
                    .iter()
                    .filter(|record| record.state == RecordState::Delivered)
                    .count(),
                1,
                "{outcome}: exactly one adopted record"
            );
            assert_eq!(evidence.records().len(), 2, "{outcome}");
        }
    }

    #[test]
    #[serial_test::serial]
    fn admission_distinguishes_uninitialized_evidence() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());

        let (_dir, path, store, _writer) = keyed_fixture();
        assert_eq!(
            keyed_outbox(&path, &store)
                .reserve_evidence([1; 32], 100, 0)
                .unwrap_err()
                .to_string(),
            evidence_wallet_error(&path, "evidence not initialized")
        );
        assert_eq!(slots(&path), [None, None]);
        assert!(owner_state(&store).is_none_or(|owner| owner.e.is_none()));

        let (_dir, path, store, _writer) = initialized();
        for slot in consent_evidence::slot_paths(&path) {
            fs::remove_file(slot).unwrap();
        }
        assert_eq!(
            keyed_outbox(&path, &store)
                .reserve_evidence([1; 32], 100, 0)
                .unwrap_err()
                .to_string(),
            evidence_wallet_error(&path, "missing image"),
            "committed evidence without its files stays damaged"
        );

        let (_dir, path, store, _writer) = keyed_fixture();
        plant(&path, 0, b"orphan");
        assert_eq!(
            keyed_outbox(&path, &store)
                .reserve_evidence([1; 32], 100, 0)
                .unwrap_err()
                .to_string(),
            evidence_wallet_error(&path, "evidence image without owner")
        );
    }

    #[test]
    #[serial_test::serial]
    fn admission_errors_identify_the_log() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());

        let (_dir, path, store, _writer, [first, _]) = pinned();
        let outbox = keyed_outbox(&path, &store);
        let parent = path.parent().unwrap().to_string_lossy().into_owned();
        let owner_fault =
            WriterError::TipAnchorStore(TipAnchorStoreError::new("owner write fault"));
        let inactive = 1 - active_slot(&path, &store);
        let io_fault = || {
            test_seam::arm_sync_failure(
                &consent_evidence::slot_paths(&path)[inactive],
                test_seam::SyncStep::Create,
            );
        };
        // The I/O faults precede any candidate write; the store faults leave
        // candidates behind, so they run last.
        for (name, fault) in [("io", Some(&io_fault)), ("store", None)] {
            for adopt in [false, true] {
                match fault {
                    Some(arm) => arm(),
                    None => store.set_owner_failing(false, true),
                }
                let error = if adopt {
                    outbox.adopt_evidence_pin([0xa1; 32], &first, 9_000)
                } else {
                    outbox.reserve_evidence([1; 32], 9_000, 0)
                }
                .unwrap_err();
                store.set_owner_failing(false, false);
                let profile = match &error {
                    WalletError::Validation(
                        crate::error::ValidationError::AuditLogUnusable { profile, .. }
                        | crate::error::ValidationError::AuditWriterOpenFailed { profile },
                    ) => profile.clone(),
                    other => panic!("{name}: a profile-bearing refusal, got {other:?}"),
                };
                assert_eq!(profile, basename(&path), "{name} adopt={adopt}");
                assert!(!error.to_string().contains(&parent), "{name} adopt={adopt}");
                if fault.is_none() {
                    assert_eq!(
                        error.code(),
                        super::super::writer::audit_writer_refusal("log", &owner_fault).code(),
                        "{name} adopt={adopt}"
                    );
                }
            }
        }
    }

    #[test]
    #[serial_test::serial]
    fn migration_adoption_survives_binding_and_rotation() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());

        let (_dir, path, store, writer, [first, second]) = pinned();
        let outbox = keyed_outbox(&path, &store);
        outbox
            .adopt_evidence_pin([0xa1; 32], &first, 9_000)
            .unwrap();
        assert_eq!(outbox.advance_evidence_floor(70).unwrap(), 70);
        let expected = evidence_snapshot(&writer);
        assert!(
            expected
                .records()
                .contains(&EvidenceRecord::legacy_pin(*second.digest()))
        );
        drop(writer);
        AuditWriter::open_for_carrier_binding(
            path.clone(),
            KeyedAuditAccess::new(Zeroizing::new(ROW_KEY), store.clone()),
        )
        .unwrap()
        .bind_carriers()
        .unwrap();
        let mut rotation = rotation_writer(&path, &store);
        rotation.fence_outbox_for_key_change().unwrap();
        test_seam::arm_stop(
            &outbox_path(&path),
            test_seam::Stop::EvidenceCandidateSynced,
        );
        store.set_reload(Ok(Some(NEXT_KEY)));
        assert!(
            rotation
                .switch_entry_tag_key(Zeroizing::new(NEXT_KEY), "rotation")
                .is_err()
        );
        drop(rotation);
        let rotated = restart_rotation(&path, &store, NEXT_KEY);
        let evidence = rotated.outbox_evidence().unwrap().unwrap();
        assert_eq!(
            evidence, expected,
            "adopted and unresolved records and the floor survive"
        );
        assert!(evidence.contains_delivered(&[0xa1; 32], &first));
        for slot in slots(&path) {
            consent_evidence::decode(slot.as_ref().unwrap(), &NEXT_KEY).unwrap();
        }
    }

    // Locked verification of the evidence the owner commits.

    #[test]
    #[serial_test::serial]
    fn verification_authenticates_evidence_without_repair() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());

        let (_dir, path, store, writer) = initialized();
        drop(writer);
        store.set_reload(Ok(Some(ROW_KEY)));
        check_outbox_commitment(&path, store.as_ref()).expect("an empty queue passes");
        reserve_row(&keyed_outbox(&path, &store), [1; 32], "queued");
        let before = durable(&path, &store);
        check_outbox_commitment(&path, store.as_ref()).expect("queued consent passes");
        assert_eq!(durable(&path, &store), before);

        let active = active_slot(&path, &store);
        let older = slots(&path)[1 - active].clone().unwrap();
        plant(&path, 1 - active, b"invalid inactive candidate");
        let candidate = durable(&path, &store);
        check_outbox_commitment(&path, store.as_ref())
            .expect("an invalid inactive candidate beside the current image passes");
        assert_eq!(durable(&path, &store), candidate);

        plant(&path, 1 - active, &older);
        let mut damaged = slots(&path)[active].clone().unwrap();
        damaged[200] ^= 1;
        plant(&path, active, &damaged);
        let corrupt = durable(&path, &store);
        let refused = check_outbox_commitment(&path, store.as_ref());
        assert!(
            matches!(
                refused,
                Err(WriterError::OutboxEvidenceUnusable { reason: "head" })
            ),
            "a corrupt selected image refuses: {refused:?}"
        );
        assert_eq!(
            durable(&path, &store),
            corrupt,
            "the refusal writes nothing"
        );

        for slot in consent_evidence::slot_paths(&path) {
            fs::remove_file(slot).unwrap();
        }
        let missing = durable(&path, &store);
        assert!(matches!(
            check_outbox_commitment(&path, store.as_ref()),
            Err(WriterError::OutboxEvidenceUnusable {
                reason: "missing image"
            })
        ));
        assert_eq!(durable(&path, &store), missing);

        // Evidence files beside a missing or version 1 owner refuse, as an
        // ordinary evidence read does; without them verification is unchanged.
        for v1 in [false, true] {
            let (_dir, path, store, mut writer) = keyed_fixture();
            if v1 {
                keyed_outbox(&path, &store)
                    .append_queued(&row("v1"))
                    .unwrap();
                assert_eq!(writer.drain_outbox().unwrap(), 1);
                assert!(owner_state(&store).unwrap().e.is_none());
            }
            drop(writer);
            store.set_reload(Ok(Some(ROW_KEY)));
            check_outbox_commitment(&path, store.as_ref()).unwrap();
            plant(&path, 0, b"orphan");
            let orphan = durable(&path, &store);
            let refused = check_outbox_commitment(&path, store.as_ref());
            assert!(
                matches!(
                    refused,
                    Err(WriterError::OutboxEvidenceUnusable {
                        reason: "evidence image without owner"
                    })
                ),
                "v1 {v1}: {refused:?}"
            );
            assert_eq!(durable(&path, &store), orphan, "v1 {v1}");
        }
    }

    #[test]
    #[serial_test::serial]
    fn verification_refuses_a_pending_owner_recommit() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());

        for case in ["immediate", "gapped", "unlinked", "equal copies"] {
            let (_dir, path, store, writer) = initialized();
            drop(writer);
            store.set_reload(Ok(Some(ROW_KEY)));
            let current = slots(&path)[0].clone().unwrap();
            let mut image = consent_evidence::decode(&current, &ROW_KEY).unwrap();
            image.generation = if case == "gapped" { 6 } else { 2 };
            image.predecessor = if case == "unlinked" {
                [0x11; 32]
            } else {
                consent_evidence::head(&current)
            };
            image.records = vec![evidence_record(5)];
            let newer = image.seal(&ROW_KEY);
            plant(&path, 1, &newer);
            if case == "equal copies" {
                plant(&path, 0, &newer);
            }
            let before = durable(&path, &store);
            let refused = check_outbox_commitment(&path, store.as_ref());
            assert!(
                matches!(
                    refused,
                    Err(WriterError::OutboxEvidenceUnusable {
                        reason: "owner recommit required"
                    })
                ),
                "{case}: {refused:?}"
            );
            assert_eq!(durable(&path, &store), before, "{case}: nothing repaired");
            locked_owner_evidence(&path, store.as_ref(), Some(&ROW_KEY)).unwrap();
            assert_eq!(
                committed(&store).unwrap().head,
                consent_evidence::head(&newer)
            );
            check_outbox_commitment(&path, store.as_ref())
                .unwrap_or_else(|error| panic!("{case}: the keyed query repaired it: {error:?}"));
        }

        let (_dir, path, store, writer) = initialized();
        drop(writer);
        store.set_reload(Ok(Some(ROW_KEY)));
        plant(&path, 0, &sealed(&store, 3, &[3]));
        plant(&path, 1, &sealed(&store, 3, &[4]));
        let before = durable(&path, &store);
        assert!(matches!(
            check_outbox_commitment(&path, store.as_ref()),
            Err(WriterError::OutboxEvidenceUnusable {
                reason: "owner rollback"
            })
        ));
        assert_eq!(durable(&path, &store), before);

        // A current image at the last generation verifies.
        let mut image = consent_evidence::decode(&sealed(&store, 3, &[6]), &ROW_KEY).unwrap();
        image.generation = u64::MAX;
        let max = image.seal(&ROW_KEY);
        plant(&path, 0, &max);
        plant(&path, 1, &max);
        let owner = owner_state(&store)
            .unwrap()
            .with_evidence(u64::MAX, consent_evidence::head(&max));
        store
            .store_outbox_owner_state(1, &owner.to_keyring_value())
            .unwrap();
        check_outbox_commitment(&path, store.as_ref()).unwrap();
    }

    #[test]
    #[serial_test::serial]
    fn verification_and_binding_refuse_old_tag_evidence() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());

        let (_dir, path, store, mut rotation, old) = rotation_fixture(storage_sandbox.path());
        rotation.fence_outbox_for_key_change().unwrap();
        drop(rotation);
        let fenced = durable(&path, &store);
        let current = check_outbox_commitment(&path, store.as_ref());
        assert!(current.is_ok(), "{current:?}");
        assert_eq!(
            durable(&path, &store),
            fenced,
            "a lone fence stays read-only"
        );

        store.set_reload(Ok(Some(NEXT_KEY)));
        let refused = check_outbox_commitment(&path, store.as_ref());
        assert!(
            matches!(
                refused,
                Err(WriterError::OutboxEvidenceUnusable { reason: "tag" })
            ),
            "old-key evidence refuses under the new stored key: {refused:?}"
        );
        let binding = AuditWriter::open_for_carrier_binding(
            path.clone(),
            KeyedAuditAccess::new(Zeroizing::new(NEXT_KEY), store.clone()),
        );
        assert!(binding.is_err(), "a binding never retags evidence");
        assert_eq!(durable(&path, &store), fenced);

        let rotated = restart_rotation(&path, &store, NEXT_KEY);
        assert_rotated(&path, &store, &old, 8, &NEXT_KEY);
        drop(rotated);
        check_outbox_commitment(&path, store.as_ref()).unwrap();
    }

    // Consent evidence storage.

    use crate::audit_log::consent_evidence::tests::delivered as evidence_record;

    fn slots(path: &Path) -> [Option<Vec<u8>>; 2] {
        consent_evidence::slot_paths(path).map(|slot| consent_evidence::read_slot(&slot).unwrap())
    }

    fn sealed(store: &InMemoryTipAnchorStore, generation: u64, records: &[u32]) -> Vec<u8> {
        EvidenceImage {
            scope: store.outbox_evidence_scope().unwrap(),
            generation,
            floor_ms: generation * 10,
            predecessor: [0; 32],
            records: records.iter().copied().map(evidence_record).collect(),
        }
        .seal(&ROW_KEY)
    }

    fn plant(path: &Path, index: usize, bytes: &[u8]) {
        fs::write(&consent_evidence::slot_paths(path)[index], bytes).unwrap();
    }

    fn owner_writes(store: &InMemoryTipAnchorStore) -> usize {
        store
            .outbox_item_writes()
            .iter()
            .filter(|(kind, _)| *kind == "owner")
            .count()
    }

    fn committed(store: &InMemoryTipAnchorStore) -> Option<EvidenceCommitment> {
        owner_state(store).unwrap().e
    }

    fn initialized() -> (TempDir, PathBuf, Arc<InMemoryTipAnchorStore>, AuditWriter) {
        let (dir, path, store, mut writer) = keyed_fixture();
        writer.initialize_consent_evidence().unwrap();
        (dir, path, store, writer)
    }

    fn evidence_refusal(result: Result<Option<OutboxEvidence>, WriterError>) -> &'static str {
        match result {
            Err(WriterError::OutboxEvidenceUnusable { reason }) => reason,
            other => panic!("expected an evidence refusal, got {other:?}"),
        }
    }

    fn rotation_writer(path: &Path, store: &Arc<InMemoryTipAnchorStore>) -> AuditWriter {
        store.set_reload(Ok(Some(ROW_KEY)));
        AuditWriter::open_for_key_rotation(
            path.to_path_buf(),
            Some(Zeroizing::new(ROW_KEY)),
            store.clone(),
            crate::audit_log::BindingHistory::NotRecorded,
        )
        .unwrap()
    }

    #[test]
    fn owner_v2_vector_and_budget() {
        let owner = OutboxOwnerState {
            g: 7,
            closed: Some(ClosedBatch {
                g: 6,
                n: 2,
                batch: [0xbb; 32],
            }),
            legacy: Some([0xcc; 32]),
            recent: Vec::new(),
            e: Some(EvidenceCommitment {
                g: 3,
                head: [0xdd; 32],
            }),
        };
        let raw = owner.to_keyring_value();
        assert_eq!(
            raw,
            format!(
                r#"{{"v":2,"g":7,"closed":{{"g":6,"n":2,"batch":"{}"}},"legacy":"{}","e":{{"g":3,"head":"{}"}}}}"#,
                "bb".repeat(32),
                "cc".repeat(32),
                "dd".repeat(32)
            )
        );
        assert_eq!(OutboxOwnerState::parse(&raw).unwrap(), owner);
        let largest = OutboxOwnerState {
            g: u64::MAX,
            closed: Some(ClosedBatch {
                g: u64::MAX,
                n: u64::MAX,
                batch: [0xff; 32],
            }),
            legacy: Some([0xff; 32]),
            recent: Vec::new(),
            e: Some(EvidenceCommitment {
                g: u64::MAX,
                head: [0xff; 32],
            }),
        }
        .to_keyring_value();
        assert_eq!(largest.len(), 349);
        assert_eq!(largest.encode_utf16().count() * 2, 698);
        assert!(OutboxOwnerState::parse(&largest).is_ok());
    }

    #[test]
    fn owner_v2_has_one_spelling() {
        let head = "dd".repeat(32);
        let raw =
            format!(r#"{{"v":2,"g":1,"closed":null,"legacy":null,"e":{{"g":3,"head":"{head}"}}}}"#);
        assert!(OutboxOwnerState::parse(&raw).is_ok());
        for other in [
            format!(r#"{{"v":2,"g":1,"closed":null,"e":{{"g":3,"head":"{head}"}},"legacy":null}}"#),
            format!(
                r#"{{"v":2, "g":1,"closed":null,"legacy":null,"e":{{"g":3,"head":"{head}"}}}}"#
            ),
            format!(r#"{{"v":2,"g":1,"closed":null,"legacy":null,"e":{{"head":"{head}","g":3}}}}"#),
            raw.replace(&head, &"DD".repeat(32)),
            raw.replace(r#""g":3"#, r#""g":3,"x":1"#),
            raw.replace(r#","e":{"g":3,"#, r#","recent":[],"e":{"g":3,"#),
            r#"{"v":2,"g":1,"closed":null,"legacy":null}"#.to_owned(),
            raw.replace(r#""v":2"#, r#""v":1"#),
            raw.replace(r#""v":2,"g":1"#, r#""v":2,"g":1,"g":1"#),
        ] {
            assert!(OutboxOwnerState::parse(&other).is_err(), "{other}");
        }
    }

    #[test]
    fn migration_preserves_unresolved_pins() {
        let (_dir, path, store, mut writer) = keyed_fixture();
        let outbox = keyed_outbox(&path, &store);
        let first = outbox.append_queued(&row("first")).unwrap();
        let second = outbox.append_queued(&row("second")).unwrap();
        assert_eq!(writer.drain_outbox().unwrap(), 2);
        let mut v1 = owner_state(&store).unwrap();
        assert_eq!(v1.recent, vec![*first.digest(), *second.digest()]);
        v1.recent.push(*first.digest());
        store
            .store_outbox_owner_state(1, &v1.to_keyring_value())
            .unwrap();
        writer.initialize_consent_evidence().unwrap();
        let owner = owner_state(&store).unwrap();
        assert_eq!((owner.g, owner.closed.clone()), (v1.g, v1.closed.clone()));
        assert!(owner.recent.is_empty());
        let evidence = writer.outbox_evidence().unwrap().unwrap();
        let mut expected: Vec<EvidenceRecord> = [first.digest(), second.digest()]
            .into_iter()
            .map(|digest| EvidenceRecord::legacy_pin(*digest))
            .collect();
        expected.sort_by_key(|record| record.identity);
        assert_eq!(evidence.records(), expected.as_slice());
        for (record, reference) in expected.iter().zip([&first, &second]) {
            assert!(!evidence.contains_delivered(&record.identity, reference));
        }
    }

    #[test]
    fn initialization_publishes_a_recoverable_generation() {
        let (_dir, path, store, writer) = initialized();
        assert_eq!(outbox_bytes(&path), header(1));
        let owner = owner_state(&store).unwrap();
        assert_eq!(
            (owner.g, owner.closed.map(|c| (c.g, c.n))),
            (1, Some((0, 0)))
        );
        let [first, second] = slots(&path);
        assert_eq!(first, second);
        assert_eq!(
            committed(&store).unwrap(),
            EvidenceCommitment {
                g: 1,
                head: consent_evidence::head(first.as_ref().unwrap()),
            }
        );
        let evidence = writer.outbox_evidence().unwrap().unwrap();
        assert!(evidence.records().is_empty());
        assert_eq!(evidence.time_floor_ms(), 0);
        drop(writer);

        // A stop after the owner store leaves the generation line to the
        // closed-prefix recovery of the next drain.
        let (_dir, path, store, mut writer) = keyed_fixture();
        test_seam::arm_stop(&outbox_path(&path), test_seam::Stop::OwnerStored);
        assert!(writer.initialize_consent_evidence().is_err());
        assert!(committed(&store).is_some());
        assert_eq!(outbox_bytes(&path), b"");
        drop(writer);
        let mut writer = reopen(&path, &store);
        assert_eq!(outbox_bytes(&path), header(1));
        let writes = store.outbox_item_writes();
        let images = slots(&path);
        writer.initialize_consent_evidence().unwrap();
        assert_eq!(
            store.outbox_item_writes(),
            writes,
            "a repeat writes nothing"
        );
        assert_eq!(slots(&path), images);

        // A file fault on the first slot is completed by the retry.
        let (_dir, path, store, mut writer) = keyed_fixture();
        test_seam::arm_sync_failure(
            &consent_evidence::slot_paths(&path)[0],
            test_seam::SyncStep::File,
        );
        assert!(matches!(
            writer.initialize_consent_evidence(),
            Err(WriterError::Io(_))
        ));
        assert!(owner_state(&store).is_none());
        writer.initialize_consent_evidence().unwrap();
        assert_eq!(outbox_bytes(&path), header(1));
    }

    #[test]
    fn initialization_reserves_both_image_budgets() {
        for step in [test_seam::SyncStep::File, test_seam::SyncStep::Directory] {
            let (_dir, path, store, mut writer) = keyed_fixture();
            let second = consent_evidence::slot_paths(&path)[1].clone();
            test_seam::arm_sync_failure(&second, step);
            let error = writer.initialize_consent_evidence().unwrap_err();
            assert!(matches!(error, WriterError::Io(_)), "{step:?}: {error:?}");
            assert!(owner_state(&store).is_none(), "{step:?}");
            writer.initialize_consent_evidence().unwrap();
            let [first, second] = slots(&path);
            assert_eq!(
                first.as_ref().map(Vec::len),
                Some(consent_evidence::SLOT_BYTES)
            );
            assert_eq!(first, second, "{step:?}");
        }
    }

    #[test]
    fn initialization_refuses_an_image_without_owner() {
        let (_dir, path, store, mut writer) = keyed_fixture();
        let initial = sealed(&store, 1, &[]);
        let mut initial_image = consent_evidence::decode(&initial, &ROW_KEY).unwrap();
        initial_image.floor_ms = 0;
        let initial = initial_image.seal(&ROW_KEY);
        plant(&path, 0, b"other evidence");
        assert_eq!(
            evidence_refusal(writer.initialize_consent_evidence().map(|()| None)),
            "evidence image without owner"
        );
        assert_eq!(slots(&path), [Some(b"other evidence".to_vec()), None]);
        assert!(owner_state(&store).is_none());
        assert_eq!(
            evidence_refusal(writer.outbox_evidence()),
            "evidence image without owner"
        );
        plant(&path, 0, &initial[..1000]);
        plant(&path, 1, &initial);
        writer.initialize_consent_evidence().unwrap();
        assert_eq!(slots(&path), [Some(initial.clone()), Some(initial)]);
    }

    #[test]
    fn a_v1_owner_beside_evidence_files_defers_consent() {
        let (_dir, path, store, mut writer) = keyed_fixture();
        let outbox = keyed_outbox(&path, &store);
        outbox.append_queued(&row("first")).unwrap();
        assert_eq!(writer.drain_outbox().unwrap(), 1, "no evidence file exists");
        assert!(owner_state(&store).unwrap().e.is_none());
        assert_eq!(writer.outbox_evidence().unwrap(), None);
        plant(&path, 1, &sealed(&store, 3, &[1]));
        outbox.append_queued(&row("second")).unwrap();
        let queued = outbox_bytes(&path);
        let owner = store.load_outbox_owner_state(1).unwrap();
        assert_eq!(writer.drain_outbox().unwrap(), 0);
        assert_eq!(outbox_bytes(&path), queued);
        assert_eq!(store.load_outbox_owner_state(1).unwrap(), owner);
        assert_eq!(delivered(&path, "second"), 0);
        assert_eq!(
            evidence_refusal(writer.outbox_evidence()),
            "evidence image without owner"
        );
        drop(writer);
        let (_dir, path, store, mut writer) = keyed_fixture();
        plant(&path, 0, b"x");
        keyed_outbox(&path, &store).append(&row("plain")).unwrap();
        assert_eq!(
            writer.drain_outbox().unwrap(),
            1,
            "rows without evidence deliver"
        );
    }

    #[test]
    #[serial_test::serial]
    fn evidence_refuses_an_incomplete_binding() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());

        let (_dir, path, store, writer) = initialized();
        plant(&path, 1, &sealed(&store, 2, &[1]));
        let raw = store.load_outbox_owner_state(1).unwrap().unwrap();
        store.store_outbox_owner_state(2, &raw).unwrap();
        let writes = owner_writes(&store);
        let images = slots(&path);
        assert!(matches!(
            writer.outbox_evidence(),
            Err(WriterError::CarrierRecoveryRequired { .. })
        ));
        assert_eq!(owner_writes(&store), writes);
        assert_eq!(store.load_outbox_owner_state(1).unwrap().unwrap(), raw);
        assert_eq!(slots(&path), images);
        drop(writer);

        // Real binding stops before and after the record switch. The binding
        // holder is gone, so direct callers meet only the evidence guard.
        for stop in [2, 4] {
            let (_dir, path, store, writer, [first, _]) = pinned();
            let outbox = keyed_outbox(&path, &store);
            let reservation = outbox.reserve_evidence([1; 32], 9_000, 0).unwrap();
            drop(writer);
            let mut binding = AuditWriter::open_for_carrier_binding(
                path.clone(),
                KeyedAuditAccess::new(Zeroizing::new(ROW_KEY), store.clone()),
            )
            .unwrap();
            assert!(binding.bind_carriers_with_fault(stop).is_err());
            drop(binding);
            store.set_reload(Ok(Some(ROW_KEY)));
            let before = durable(&path, &store);
            let incomplete = super::super::writer::audit_writer_refusal(
                &basename(&path),
                &WriterError::CarrierRecoveryRequired {
                    detail: WriterError::CarrierBindingIncomplete.to_string(),
                },
            )
            .to_string();
            for (call, result) in [
                (
                    "reserve",
                    outbox
                        .reserve_evidence([2; 32], 9_000, 0)
                        .map(drop)
                        .map_err(|error| error.to_string()),
                ),
                (
                    "adopt",
                    outbox
                        .adopt_evidence_pin([3; 32], &first, 9_000)
                        .map(drop)
                        .map_err(|error| error.to_string()),
                ),
            ] {
                assert_eq!(result, Err(incomplete.clone()), "stop {stop}: {call}");
            }
            for (call, result) in [
                ("release", outbox.release_evidence([1; 32])),
                ("advance", outbox.advance_evidence_floor(5).map(drop)),
                ("floor", outbox.evidence_time_floor().map(drop)),
                (
                    "append",
                    outbox
                        .clone()
                        .with_evidence_reservation(reservation.clone())
                        .append_queued(&row("staged"))
                        .map(drop),
                ),
                ("verify", check_outbox_commitment(&path, store.as_ref())),
            ] {
                assert!(
                    matches!(result, Err(WriterError::CarrierRecoveryRequired { .. })),
                    "stop {stop}: {call}: {result:?}"
                );
            }
            assert_eq!(durable(&path, &store), before, "stop {stop}");
        }
    }

    #[test]
    fn a_keyless_v2_evidence_read_refuses() {
        let (_dir, path, store, _writer) = initialized();
        assert!(matches!(
            locked_owner_evidence(&path, store.as_ref(), None),
            Err(WriterError::KeyedLogNeedsKey { .. })
        ));
        assert!(
            locked_owner_evidence(&path, store.as_ref(), Some(&ROW_KEY))
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn an_owner_restored_many_generations_recommits_the_newest_image() {
        let (_dir, path, store, writer) = initialized();
        plant(&path, 0, &sealed(&store, 2, &[2]));
        let newest = sealed(&store, 4, &[4]);
        plant(&path, 1, &newest);
        let writes = owner_writes(&store);
        let evidence = writer.outbox_evidence().unwrap().unwrap();
        assert_eq!(evidence.records(), &[evidence_record(4)]);
        assert_eq!(evidence.time_floor_ms(), 40);
        assert_eq!(owner_writes(&store), writes + 1);
        assert_eq!(
            committed(&store).unwrap(),
            EvidenceCommitment {
                g: 4,
                head: consent_evidence::head(&newest),
            }
        );
        assert_eq!(writer.outbox_evidence().unwrap().unwrap(), evidence);
        assert_eq!(
            owner_writes(&store),
            writes + 1,
            "the current root writes nothing"
        );
    }

    #[test]
    fn concurrent_owner_roll_forward_has_one_winner() {
        use std::sync::mpsc;
        let (_dir, path, store, writer) = initialized();
        drop(writer);
        plant(&path, 1, &sealed(&store, 2, &[2]));
        let before = owner_writes(&store);
        let (loaded_tx, loaded_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let (done_tx, done_rx) = mpsc::channel::<()>();
        test_seam::on_evidence_loaded(&path, move || {
            loaded_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        });
        let worker = |path: PathBuf, store: Arc<InMemoryTipAnchorStore>, done: mpsc::Sender<()>| {
            std::thread::spawn(move || {
                let evidence = locked_owner_evidence(&path, store.as_ref(), Some(&ROW_KEY));
                let _ = done.send(());
                evidence.unwrap().unwrap()
            })
        };
        let a = worker(path.clone(), store.clone(), done_tx.clone());
        loaded_rx.recv().unwrap();
        let on_contention = release_tx.clone();
        test_seam::on_contended(&outbox_lock_path(&path), move || {
            let _ = on_contention.send(());
        });
        let watched = store.clone();
        test_seam::on_evidence_loaded(&path, move || {
            if owner_writes(&watched) == before {
                let _ = release_tx.send(());
                done_rx.recv().unwrap();
            }
        });
        let b = worker(path.clone(), store.clone(), done_tx);
        let (a, b) = (a.join().unwrap(), b.join().unwrap());
        assert_eq!(a, b);
        assert_eq!(a.records(), &[evidence_record(2)]);
        assert_eq!(
            owner_writes(&store),
            before + 1,
            "one holder stores the successor"
        );
    }

    #[test]
    fn roll_forward_before_recommit_exposes_nothing() {
        let (_dir, path, store, writer) = initialized();
        plant(&path, 1, &sealed(&store, 2, &[2]));
        let raw = store.load_outbox_owner_state(1).unwrap();
        store.set_owner_failing(false, true);
        let error = writer.outbox_evidence().unwrap_err();
        assert!(matches!(error, WriterError::TipAnchorStore(_)), "{error:?}");
        assert_eq!(store.load_outbox_owner_state(1).unwrap(), raw);
        store.set_owner_failing(false, false);
        assert_eq!(
            writer.outbox_evidence().unwrap().unwrap().records(),
            &[evidence_record(2)]
        );
    }

    /// A store whose owner stores persist and then report failure, and whose
    /// reread after such a store can fail too.
    #[derive(Debug)]
    struct UncertainStore {
        inner: Arc<InMemoryTipAnchorStore>,
        reread_fails: bool,
        stored: std::sync::atomic::AtomicBool,
    }

    impl TipAnchorStore for UncertainStore {
        fn reads_audit_key(&self) -> bool {
            false
        }
        fn load_carrier_record(
            &self,
        ) -> Result<Option<crate::audit_log::tip_anchor::CarrierRecord>, TipAnchorStoreError>
        {
            self.inner.load_carrier_record()
        }
        fn store_carrier_record(
            &self,
            record: &crate::audit_log::tip_anchor::CarrierRecord,
        ) -> Result<(), TipAnchorStoreError> {
            self.inner.store_carrier_record(record)
        }
        fn load_outbox_state(
            &self,
            generation: u64,
        ) -> Result<Option<OutboxState>, TipAnchorStoreError> {
            self.inner.load_outbox_state(generation)
        }
        fn store_outbox_state(
            &self,
            generation: u64,
            value: &OutboxState,
        ) -> Result<(), TipAnchorStoreError> {
            self.inner.store_outbox_state(generation, value)
        }
        fn load_outbox_owner_state(
            &self,
            generation: u64,
        ) -> Result<Option<String>, TipAnchorStoreError> {
            if self.reread_fails && self.stored.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(TipAnchorStoreError::new("owner reread fault"));
            }
            self.inner.load_outbox_owner_state(generation)
        }
        fn store_outbox_owner_state(
            &self,
            generation: u64,
            value: &str,
        ) -> Result<(), TipAnchorStoreError> {
            self.inner.store_outbox_owner_state(generation, value)?;
            self.stored.store(true, std::sync::atomic::Ordering::SeqCst);
            Err(TipAnchorStoreError::new("owner write uncertain"))
        }
        fn outbox_evidence_scope(&self) -> Result<[u8; 32], TipAnchorStoreError> {
            self.inner.outbox_evidence_scope()
        }
        fn load_anchor(
            &self,
        ) -> Result<Option<crate::audit_log::tip_anchor::TipAnchor>, TipAnchorStoreError> {
            self.inner.load_anchor()
        }
        fn load_raw(&self) -> Result<Option<String>, TipAnchorStoreError> {
            self.inner.load_raw()
        }
        fn store_anchor(
            &self,
            anchor: &crate::audit_log::tip_anchor::TipAnchor,
        ) -> Result<(), TipAnchorStoreError> {
            self.inner.store_anchor(anchor)
        }
        fn bump_reanchor_count(&self) -> Result<u64, TipAnchorStoreError> {
            self.inner.bump_reanchor_count()
        }
        fn reanchor_count(&self) -> Result<Option<u64>, TipAnchorStoreError> {
            self.inner.reanchor_count()
        }
    }

    #[test]
    fn roll_forward_uncertain_recommit_rereads_owner() {
        for reread_fails in [false, true] {
            let (_dir, path, store, writer) = initialized();
            drop(writer);
            let newest = sealed(&store, 2, &[2]);
            plant(&path, 1, &newest);
            let images = slots(&path);
            let uncertain = UncertainStore {
                inner: store.clone(),
                reread_fails,
                stored: std::sync::atomic::AtomicBool::new(false),
            };
            let result = locked_owner_evidence(&path, &uncertain, Some(&ROW_KEY));
            if reread_fails {
                let error = result.unwrap_err();
                assert_eq!(
                    format!("{error:?}"),
                    format!(
                        "{:?}",
                        WriterError::TipAnchorStore(TipAnchorStoreError::new("owner reread fault"))
                    )
                );
                assert_eq!(slots(&path), images, "both slots stay");
            } else {
                assert_eq!(result.unwrap().unwrap().records(), &[evidence_record(2)]);
            }
            assert_eq!(
                committed(&store).unwrap().head,
                consent_evidence::head(&newest)
            );
        }
    }

    #[test]
    fn roll_forward_crash_after_recommit_is_idempotent() {
        let (_dir, path, store, writer) = initialized();
        let newest = sealed(&store, 2, &[2]);
        plant(&path, 1, &newest);
        test_seam::arm_stop(&outbox_path(&path), test_seam::Stop::EvidenceRecommitted);
        assert!(matches!(writer.outbox_evidence(), Err(WriterError::Io(_))));
        assert_eq!(committed(&store).unwrap().g, 2, "the successor is current");
        drop(writer);
        let writes = owner_writes(&store);
        let writer = reopen(&path, &store);
        assert_eq!(
            writer.outbox_evidence().unwrap().unwrap().records(),
            &[evidence_record(2)]
        );
        assert_eq!(owner_writes(&store), writes, "the retry stores nothing");
        assert_eq!(slots(&path)[1].as_deref(), Some(newest.as_slice()));
    }

    #[test]
    fn current_evidence_query_is_write_free_and_lock_aware() {
        let (_dir, path, store, writer) = initialized();
        drop(writer);
        let rotation = rotation_writer(&path, &store);
        let writes = store.outbox_item_writes();
        let images = slots(&path);
        let evidence = rotation.outbox_evidence().unwrap().unwrap();
        assert!(evidence.records().is_empty());
        assert_eq!(store.outbox_item_writes(), writes);
        assert_eq!(slots(&path), images);
    }

    #[test]
    #[serial_test::serial]
    fn ordinary_delivery_ignores_evidence_refusal() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let (_dir, path, store, mut writer) = initialized();
        plant(&path, 0, &sealed(&store, 3, &[3]));
        plant(&path, 1, &sealed(&store, 3, &[4]));
        assert_eq!(evidence_refusal(writer.outbox_evidence()), "owner rollback");
        let root = committed(&store);
        writer.write_entry(own_row("allow")).unwrap();
        assert_eq!(writer.drain_outbox().unwrap(), 0);
        let outbox = keyed_outbox(&path, &store);
        outbox.append(&row("plain")).unwrap();
        assert_eq!(writer.drain_outbox().unwrap(), 1);
        outbox.append_queued(&row("consent")).unwrap();
        let queued = outbox_bytes(&path);
        assert_eq!(writer.drain_outbox().unwrap(), 0);
        writer.write_entry(own_row("after")).unwrap();
        for id in ["allow", "plain", "after"] {
            assert_eq!(delivered(&path, id), 1, "{id}");
        }
        assert_eq!(delivered(&path, "consent"), 0);
        assert_eq!(outbox_bytes(&path), queued);
        assert_eq!(committed(&store), root);
        assert_eq!(evidence_refusal(writer.outbox_evidence()), "owner rollback");
    }

    fn rotation_fixture(
        home: &Path,
    ) -> (
        TempDir,
        PathBuf,
        Arc<InMemoryTipAnchorStore>,
        AuditWriter,
        Vec<u8>,
    ) {
        let dir = tempfile::tempdir_in(home).unwrap();
        let path = log_path(&dir);
        let store = Arc::new(InMemoryTipAnchorStore::new());
        let mut writer = AuditWriter::open(
            path.clone(),
            Some(KeyedAuditAccess::new(
                Zeroizing::new(ROW_KEY),
                store.clone(),
            )),
        )
        .unwrap();
        writer.initialize_consent_evidence().unwrap();
        let mut image =
            consent_evidence::decode(slots(&path)[0].as_ref().unwrap(), &ROW_KEY).unwrap();
        image.generation = 7;
        image.floor_ms = 73;
        image.records = vec![evidence_record(2), evidence_record(9)];
        let old = image.seal(&ROW_KEY);
        plant(&path, 0, &old);
        let owner = owner_state(&store)
            .unwrap()
            .with_evidence(7, consent_evidence::head(&old));
        store
            .store_outbox_owner_state(1, &owner.to_keyring_value())
            .unwrap();
        drop(writer);
        let rotation = rotation_writer(&path, &store);
        (dir, path, store, rotation, old)
    }

    fn change_evidence(path: &Path, store: &dyn TipAnchorStore) -> Result<(), WriterError> {
        let batch = OutboxBatch::read_locked(path, store)?;
        batch.commit_evidence_change(path, store, &ROW_KEY, false, |image, _| {
            image.floor_ms += 1;
            Ok(())
        })?;
        Ok(())
    }

    fn reserve_existing(
        path: &Path,
        store: Arc<dyn TipAnchorStore>,
    ) -> Result<EvidenceReservation, WalletError> {
        AuditOutbox::for_log_keyed(path, store, Zeroizing::new(ROW_KEY)).reserve_evidence(
            evidence_record(2).identity,
            9_000,
            74,
        )
    }

    fn arm_evidence_fault(path: &Path, index: usize, fault: usize) {
        let slot = &consent_evidence::slot_paths(path)[index];
        match fault {
            0 => test_seam::arm_sync_failure(slot, test_seam::SyncStep::Create),
            1 => test_seam::arm_partial_write(slot, 1000),
            2 => test_seam::arm_sync_failure(slot, test_seam::SyncStep::File),
            3 => test_seam::arm_sync_failure(slot, test_seam::SyncStep::Directory),
            _ => unreachable!(),
        }
    }

    fn clear_evidence_fault(path: &Path, index: usize, fault: usize) {
        let slot = &consent_evidence::slot_paths(path)[index];
        if fault == 1 {
            test_seam::disarm(slot);
        } else {
            let step = match fault {
                0 => test_seam::SyncStep::Create,
                2 => test_seam::SyncStep::File,
                _ => test_seam::SyncStep::Directory,
            };
            assert!(test_seam::check_sync(slot, step).is_err());
        }
    }

    fn restart_rotation(
        path: &Path,
        store: &Arc<InMemoryTipAnchorStore>,
        key: [u8; 32],
    ) -> AuditWriter {
        store.set_reload(Ok(Some(key)));
        AuditWriter::open_for_key_rotation(
            path.to_path_buf(),
            Some(Zeroizing::new(key)),
            store.clone(),
            crate::audit_log::BindingHistory::NotRecorded,
        )
        .unwrap()
    }

    fn assert_rotated(
        path: &Path,
        store: &InMemoryTipAnchorStore,
        old: &[u8],
        generation: u64,
        key: &[u8; 32],
    ) {
        let images = slots(path);
        assert_eq!(images[0], images[1]);
        let bytes = images[0].as_ref().unwrap();
        let image = consent_evidence::decode(bytes, key).unwrap();
        let old = consent_evidence::decode_layout(old).unwrap();
        assert_eq!(image.records, old.records);
        assert_eq!(image.floor_ms, old.floor_ms);
        assert_eq!(image.generation, generation);
        assert_eq!(
            committed(store).unwrap(),
            EvidenceCommitment {
                g: generation,
                head: consent_evidence::head(bytes)
            }
        );
        assert_eq!(
            outbox_bytes(path),
            encode_generation_line(key, owner_state(store).unwrap().g)
        );
    }
    #[test]
    #[serial_test::serial]
    fn candidate_failures_preserve_selected_image() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());

        for fault in [1, 0, 2, 3] {
            let (_dir, path, store, writer, old) = rotation_fixture(storage_sandbox.path());
            drop(writer);
            arm_evidence_fault(&path, 0, fault);
            arm_evidence_fault(&path, 1, fault);
            assert!(reserve_existing(&path, store.clone()).is_err());
            assert_eq!(
                slots(&path)[0].as_ref(),
                Some(&old),
                "selected bytes survive"
            );
            clear_evidence_fault(&path, 0, fault);
            let image = consent_evidence::decode(&old, &ROW_KEY).unwrap();
            assert_eq!(
                committed(&store).unwrap().head,
                consent_evidence::head(&old)
            );
            assert_eq!(image.records, vec![evidence_record(2), evidence_record(9)]);
            assert_eq!(image.floor_ms, 73);
            let recovered = locked_owner_evidence(&path, store.as_ref(), Some(&ROW_KEY))
                .unwrap()
                .unwrap();
            assert_eq!(recovered.records(), image.records);
            assert_eq!(recovered.time_floor_ms(), if fault >= 2 { 74 } else { 73 });
        }
        let (_dir, path, store, writer, old) = rotation_fixture(storage_sandbox.path());
        drop(writer);
        let batch = OutboxBatch::read_locked(&path, store.as_ref()).unwrap();
        let before = (slots(&path), store.outbox_item_writes());
        let refused =
            batch.commit_evidence_change(&path, store.as_ref(), &ROW_KEY, false, |image, _| {
                image.records.push(image.records[0].clone());
                Ok(())
            });
        assert!(matches!(
            refused,
            Err(WriterError::OutboxEvidenceUnusable { reason: "layout" })
        ));
        assert_eq!(
            (slots(&path), store.outbox_item_writes()),
            before,
            "invalid transformation writes nothing"
        );
        let next = batch
            .commit_evidence_change(&path, store.as_ref(), &ROW_KEY, false, |image, owner| {
                image.floor_ms = 74;
                owner.g = 2;
                owner.record_delivery(1, &[]);
                Ok(())
            })
            .unwrap();
        assert_eq!(
            owner_state(&store).unwrap(),
            next.owner,
            "queue fields and evidence commit together"
        );
        assert_eq!(next.image.predecessor, consent_evidence::head(&old));
    }

    #[test]
    #[serial_test::serial]
    fn uncertain_owner_write_selects_actual_commit() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());

        for reread_fails in [false, true] {
            let (_dir, path, store, writer, old) = rotation_fixture(storage_sandbox.path());
            drop(writer);
            let uncertain = Arc::new(UncertainStore {
                inner: store.clone(),
                reread_fails,
                stored: std::sync::atomic::AtomicBool::new(false),
            });
            let result = reserve_existing(&path, uncertain);
            if reread_fails {
                assert_eq!(
                    result.unwrap_err().to_string(),
                    super::super::writer::audit_writer_refusal(
                        &basename(&path),
                        &WriterError::TipAnchorStore(TipAnchorStoreError::new(
                            "owner reread fault"
                        ))
                    )
                    .to_string()
                );
            } else {
                assert!(
                    result.is_ok(),
                    "the persisted successor confirms the uncertain write"
                );
            }
            assert_eq!(committed(&store).unwrap().g, 8);
            assert_eq!(slots(&path)[0].as_ref(), Some(&old));
            let evidence = locked_owner_evidence(&path, store.as_ref(), Some(&ROW_KEY))
                .unwrap()
                .unwrap();
            assert_eq!(evidence.time_floor_ms(), 74);
            assert_eq!(
                evidence.records(),
                &[evidence_record(2), evidence_record(9)]
            );
        }
        let (_dir, path, store, writer, old) = rotation_fixture(storage_sandbox.path());
        drop(writer);
        store.set_owner_failing(false, true);
        let error = reserve_existing(&path, store.clone()).unwrap_err();
        assert_eq!(
            error.to_string(),
            super::super::writer::audit_writer_refusal(
                &basename(&path),
                &WriterError::TipAnchorStore(TipAnchorStoreError::new("owner write fault"))
            )
            .to_string()
        );
        assert_eq!(
            committed(&store).unwrap().head,
            consent_evidence::head(&old)
        );
        let images = slots(&path);
        assert_eq!(images[0].as_ref(), Some(&old));
        assert_eq!(
            consent_evidence::decode(images[1].as_ref().unwrap(), &ROW_KEY)
                .unwrap()
                .generation,
            8
        );
        store.set_owner_failing(false, false);
        let recovered = locked_owner_evidence(&path, store.as_ref(), Some(&ROW_KEY))
            .unwrap()
            .unwrap();
        assert_eq!(recovered.time_floor_ms(), 74);
        assert_eq!(
            slots(&path),
            images,
            "a failed store keeps both images for recovery"
        );
    }

    #[test]
    #[serial_test::serial]
    fn evidence_generation_overflow_is_write_free() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());

        for current in [false, true] {
            let (_dir, path, store, mut writer, old) = rotation_fixture(storage_sandbox.path());
            let mut image = consent_evidence::decode(&old, &ROW_KEY).unwrap();
            image.generation = u64::MAX;
            let max = image.seal(&ROW_KEY);
            plant(&path, 1, &max);
            if current {
                let owner = owner_state(&store)
                    .unwrap()
                    .with_evidence(u64::MAX, consent_evidence::head(&max));
                store
                    .store_outbox_owner_state(1, &owner.to_keyring_value())
                    .unwrap();
            }
            let before = (
                slots(&path),
                store.outbox_item_writes(),
                outbox_bytes(&path),
            );
            let error = writer.fence_outbox_for_key_change().unwrap_err();
            assert!(matches!(
                error,
                WriterError::OutboxEvidenceUnusable {
                    reason: "evidence-generation overflow"
                }
            ));
            assert_eq!(
                crate::audit_log::writer::audit_writer_refusal("fixture", &error).code(),
                "audit.outbox_evidence_unusable"
            );
            assert_eq!(
                (
                    slots(&path),
                    store.outbox_item_writes(),
                    outbox_bytes(&path)
                ),
                before
            );
            drop(writer);
            assert!(matches!(
                change_evidence(&path, store.as_ref()),
                Err(WriterError::OutboxEvidenceUnusable {
                    reason: "evidence-generation overflow"
                })
            ));
            assert_eq!(
                (
                    slots(&path),
                    store.outbox_item_writes(),
                    outbox_bytes(&path)
                ),
                before
            );
            let evidence = locked_owner_evidence(&path, store.as_ref(), Some(&ROW_KEY))
                .unwrap()
                .unwrap();
            assert_eq!(
                evidence.time_floor_ms(),
                73,
                "maximum generation remains readable"
            );
        }
    }

    #[test]
    #[serial_test::serial]
    fn roll_forward_syncs_a_recovered_candidate() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());

        let (_dir, path, store, writer, old) = rotation_fixture(storage_sandbox.path());
        drop(writer);
        let candidate = consent_evidence::slot_paths(&path)[1].clone();
        test_seam::arm_sync_failure(&candidate, test_seam::SyncStep::Directory);
        assert!(change_evidence(&path, store.as_ref()).is_err());
        test_seam::record_syncs(&candidate);
        test_seam::arm_sync_failure(&candidate, test_seam::SyncStep::Directory);
        assert!(matches!(
            locked_owner_evidence(&path, store.as_ref(), Some(&ROW_KEY)),
            Err(WriterError::Io(_))
        ));
        assert_eq!(
            committed(&store).unwrap().head,
            consent_evidence::head(&old),
            "sync precedes recommit"
        );
        assert_eq!(
            test_seam::take_syncs(&candidate),
            vec![test_seam::SyncStep::File]
        );
        test_seam::record_syncs(&candidate);
        let evidence = locked_owner_evidence(&path, store.as_ref(), Some(&ROW_KEY))
            .unwrap()
            .unwrap();
        assert_eq!(evidence.time_floor_ms(), 74);
        let expected: &[test_seam::SyncStep] = if cfg!(unix) {
            &[test_seam::SyncStep::File, test_seam::SyncStep::Directory]
        } else {
            &[test_seam::SyncStep::File]
        };
        assert_eq!(test_seam::take_syncs(&candidate), expected);
        assert_eq!(committed(&store).unwrap().g, 8);
    }

    #[test]
    #[serial_test::serial]
    fn rotation_preserves_tag_authenticated_evidence() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());

        let (_dir, path, store, mut writer, old) = rotation_fixture(storage_sandbox.path());
        let owner = owner_state(&store).unwrap();
        writer.fence_outbox_for_key_change().unwrap();
        assert_eq!(slots(&path), [Some(old.clone()), Some(old.clone())]);
        store.set_reload(Ok(Some(NEXT_KEY)));
        writer
            .switch_entry_tag_key(Zeroizing::new(NEXT_KEY), "rotation")
            .unwrap();
        assert_rotated(&path, &store, &old, 8, &NEXT_KEY);
        let next = owner_state(&store).unwrap();
        assert_eq!(
            (next.g, next.closed, next.legacy),
            (owner.g, owner.closed, owner.legacy)
        );
        let first = slots(&path)[0].clone().unwrap();
        assert_ne!(&first[92..124], &old[92..124]);
        assert_ne!(consent_evidence::head(&first), consent_evidence::head(&old));
        drop(writer);
        let mut again = restart_rotation(&path, &store, NEXT_KEY);
        again.fence_outbox_for_key_change().unwrap();
        let third = [0x67; 32];
        store.set_reload(Ok(Some(third)));
        again
            .switch_entry_tag_key(Zeroizing::new(third), "another rotation")
            .unwrap();
        assert_rotated(&path, &store, &first, 9, &third);
    }

    #[test]
    #[serial_test::serial]
    fn rotation_fence_crash_preserves_the_committed_source() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());

        for fault in [1, 0, 2, 3] {
            let (_dir, path, store, mut writer, old) = rotation_fixture(storage_sandbox.path());
            // Either possible destination is faulted, so writing the selected slot tears it.
            arm_evidence_fault(&path, 0, fault);
            arm_evidence_fault(&path, 1, fault);
            assert!(writer.fence_outbox_for_key_change().is_err());
            assert_eq!(
                slots(&path)[0].as_ref(),
                Some(&old),
                "the committed source survives the mirror"
            );
            assert_eq!(outbox_bytes(&path), encode_fence_line(1));
            clear_evidence_fault(&path, 0, fault);
            drop(writer);
            let resumed = restart_rotation(&path, &store, ROW_KEY);
            assert_eq!(slots(&path), [Some(old.clone()), Some(old)]);
            assert_eq!(committed(&store).unwrap().g, 7);
            assert_eq!(outbox_bytes(&path), header(1));
            drop(resumed);
        }
    }

    #[test]
    #[serial_test::serial]
    fn rotation_mirror_precedes_key_replacement() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());

        let (_dir, path, store, mut writer, old) = rotation_fixture(storage_sandbox.path());
        let inactive = consent_evidence::slot_paths(&path)[1].clone();
        test_seam::record_syncs(&inactive);
        writer.fence_outbox_for_key_change().unwrap();
        assert_eq!(
            slots(&path),
            [Some(old.clone()), Some(old)],
            "both old images precede key replacement"
        );
        let expected: &[test_seam::SyncStep] = if cfg!(unix) {
            &[test_seam::SyncStep::File, test_seam::SyncStep::Directory]
        } else {
            &[test_seam::SyncStep::File]
        };
        assert_eq!(test_seam::take_syncs(&inactive), expected);
        assert_eq!(outbox_bytes(&path), encode_fence_line(1));
        let images = slots(&path);
        let writes = owner_writes(&store);
        drop(writer);
        let _resumed = restart_rotation(&path, &store, ROW_KEY);
        assert_eq!(slots(&path), images);
        assert_eq!(committed(&store).unwrap().g, 7);
        assert_eq!(
            owner_writes(&store),
            writes,
            "old key recovery adds no generation"
        );
        assert_eq!(outbox_bytes(&path), header(1));
    }

    #[test]
    #[serial_test::serial]
    fn rotation_key_write_crash_recovers_without_old_key() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());

        let (_dir, path, store, mut writer, old) = rotation_fixture(storage_sandbox.path());
        writer.fence_outbox_for_key_change().unwrap();
        store.set_reload(Ok(Some(NEXT_KEY)));
        drop(writer);
        let resumed = restart_rotation(&path, &store, NEXT_KEY);
        assert_rotated(&path, &store, &old, 8, &NEXT_KEY);
        drop(resumed);
        let writes = store.outbox_item_writes();
        let _resumed = restart_rotation(&path, &store, NEXT_KEY);
        assert_eq!(store.outbox_item_writes(), writes);
    }

    #[test]
    #[serial_test::serial]
    fn rotation_first_retag_failure_preserves_old_source() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());

        for fault in [1, 0, 2, 3] {
            let (_dir, path, store, mut writer, old) = rotation_fixture(storage_sandbox.path());
            writer.fence_outbox_for_key_change().unwrap();
            arm_evidence_fault(&path, 0, fault);
            arm_evidence_fault(&path, 1, fault);
            store.set_reload(Ok(Some(NEXT_KEY)));
            assert!(
                writer
                    .switch_entry_tag_key(Zeroizing::new(NEXT_KEY), "rotation")
                    .is_err()
            );
            assert_eq!(
                slots(&path)[0].as_ref(),
                Some(&old),
                "first retag preserves the selected source"
            );
            assert_eq!(outbox_bytes(&path), encode_fence_line(1));
            assert_eq!(committed(&store).unwrap().g, 7);
            clear_evidence_fault(&path, 0, fault);
            drop(writer);
            let _resumed = restart_rotation(&path, &store, NEXT_KEY);
            assert_rotated(&path, &store, &old, 8, &NEXT_KEY);
        }
    }

    #[test]
    #[serial_test::serial]
    fn rotation_first_retag_sync_precedes_owner() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());

        let (_dir, path, store, mut writer, old) = rotation_fixture(storage_sandbox.path());
        writer.fence_outbox_for_key_change().unwrap();
        test_seam::arm_sync_failure(
            &consent_evidence::slot_paths(&path)[1],
            test_seam::SyncStep::Directory,
        );
        store.set_reload(Ok(Some(NEXT_KEY)));
        assert!(
            writer
                .switch_entry_tag_key(Zeroizing::new(NEXT_KEY), "rotation")
                .is_err()
        );
        assert_eq!(
            committed(&store).unwrap().head,
            consent_evidence::head(&old),
            "owner stays old until candidate directory sync"
        );
        assert_eq!(outbox_bytes(&path), encode_fence_line(1));
        drop(writer);
        let _resumed = restart_rotation(&path, &store, NEXT_KEY);
        assert_rotated(&path, &store, &old, 8, &NEXT_KEY);
    }

    #[test]
    #[serial_test::serial]
    fn rotation_candidate_crash_recommits_once() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());

        let (_dir, path, store, mut writer, old) = rotation_fixture(storage_sandbox.path());
        writer.fence_outbox_for_key_change().unwrap();
        test_seam::arm_stop(
            &outbox_path(&path),
            test_seam::Stop::EvidenceCandidateSynced,
        );
        store.set_reload(Ok(Some(NEXT_KEY)));
        assert!(
            writer
                .switch_entry_tag_key(Zeroizing::new(NEXT_KEY), "rotation")
                .is_err()
        );
        assert_eq!(committed(&store).unwrap().g, 7);
        assert_eq!(outbox_bytes(&path), encode_fence_line(1));
        drop(writer);
        let writes = owner_writes(&store);
        let resumed = restart_rotation(&path, &store, NEXT_KEY);
        assert_rotated(&path, &store, &old, 8, &NEXT_KEY);
        assert_eq!(owner_writes(&store), writes + 1);
        drop(resumed);
        let _again = restart_rotation(&path, &store, NEXT_KEY);
        assert_eq!(owner_writes(&store), writes + 1);
    }

    #[test]
    #[serial_test::serial]
    fn rotation_owner_crash_keeps_the_second_copy_pending() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());

        let (_dir, path, store, mut writer, old) = rotation_fixture(storage_sandbox.path());
        writer.fence_outbox_for_key_change().unwrap();
        test_seam::arm_stop(&outbox_path(&path), test_seam::Stop::EvidenceOwnerStored);
        store.set_reload(Ok(Some(NEXT_KEY)));
        assert!(
            writer
                .switch_entry_tag_key(Zeroizing::new(NEXT_KEY), "rotation")
                .is_err()
        );
        assert_eq!(
            slots(&path)[0].as_ref(),
            Some(&old),
            "the second copy follows the owner commit"
        );
        assert_eq!(committed(&store).unwrap().g, 8);
        assert_eq!(outbox_bytes(&path), encode_fence_line(1));
        drop(writer);
        let writes = owner_writes(&store);
        let _resumed = restart_rotation(&path, &store, NEXT_KEY);
        assert_rotated(&path, &store, &old, 8, &NEXT_KEY);
        assert_eq!(
            owner_writes(&store),
            writes,
            "a committed successor is only mirrored"
        );
    }

    #[test]
    #[serial_test::serial]
    fn rotation_second_retag_failure_keeps_the_fence() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());

        for fault in 0..4 {
            let (_dir, path, store, mut writer, old) = rotation_fixture(storage_sandbox.path());
            writer.fence_outbox_for_key_change().unwrap();
            arm_evidence_fault(&path, 0, fault);
            store.set_reload(Ok(Some(NEXT_KEY)));
            assert!(
                writer
                    .switch_entry_tag_key(Zeroizing::new(NEXT_KEY), "rotation")
                    .is_err()
            );
            assert_eq!(
                outbox_bytes(&path),
                encode_fence_line(1),
                "second copy failure keeps the fence"
            );
            assert_eq!(committed(&store).unwrap().g, 8);
            drop(writer);
            let writes = owner_writes(&store);
            let _resumed = restart_rotation(&path, &store, NEXT_KEY);
            assert_rotated(&path, &store, &old, 8, &NEXT_KEY);
            assert_eq!(owner_writes(&store), writes);
        }

        let (_dir, path, store, mut writer, _old) = rotation_fixture(storage_sandbox.path());
        writer.fence_outbox_for_key_change().unwrap();
        let slot = consent_evidence::slot_paths(&path)[0].clone();
        let written = slot.clone();
        test_seam::on_replacement_synced(&slot, move || {
            let bytes = fs::read(&written).unwrap();
            let mut image = consent_evidence::decode(&bytes, &NEXT_KEY).unwrap();
            image.floor_ms += 1;
            fs::write(&written, image.seal(&NEXT_KEY)).unwrap();
        });
        store.set_reload(Ok(Some(NEXT_KEY)));
        assert!(
            matches!(
                writer.switch_entry_tag_key(Zeroizing::new(NEXT_KEY), "rotation"),
                Err(WriterError::OutboxEvidenceUnusable { reason: "head" })
            ),
            "a changed second copy refuses before the queue reopens"
        );
        assert_eq!(
            outbox_bytes(&path),
            encode_fence_line(1),
            "a changed second copy keeps the fence"
        );
        assert_eq!(committed(&store).unwrap().g, 8);
    }

    #[test]
    #[serial_test::serial]
    fn rotation_both_retags_crash_only_reopens_the_queue() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());

        let (_dir, path, store, mut writer, old) = rotation_fixture(storage_sandbox.path());
        writer.fence_outbox_for_key_change().unwrap();
        test_seam::arm_stop(&outbox_path(&path), test_seam::Stop::EvidenceCopiesSynced);
        store.set_reload(Ok(Some(NEXT_KEY)));
        assert!(
            writer
                .switch_entry_tag_key(Zeroizing::new(NEXT_KEY), "rotation")
                .is_err()
        );
        assert_eq!(outbox_bytes(&path), encode_fence_line(1));
        let images = slots(&path);
        assert_eq!(images[0], images[1]);
        drop(writer);
        let writes = owner_writes(&store);
        for slot in consent_evidence::slot_paths(&path) {
            test_seam::arm_sync_failure(&slot, test_seam::SyncStep::Create);
            test_seam::record_syncs(&slot);
        }
        let _resumed = restart_rotation(&path, &store, NEXT_KEY);
        let expected: &[test_seam::SyncStep] = if cfg!(unix) {
            &[test_seam::SyncStep::File, test_seam::SyncStep::Directory]
        } else {
            &[test_seam::SyncStep::File]
        };
        for slot in consent_evidence::slot_paths(&path) {
            assert_eq!(
                test_seam::take_syncs(&slot),
                expected,
                "each complete copy is synced before the queue reopens"
            );
        }
        assert_eq!(
            slots(&path),
            images,
            "complete copies need no evidence write"
        );
        assert_eq!(owner_writes(&store), writes);
        assert_rotated(&path, &store, &old, 8, &NEXT_KEY);
    }

    #[test]
    #[serial_test::serial]
    fn rotation_refuses_uncommitted_retag_sources() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());

        for shape in 0..10 {
            let (_dir, path, store, mut writer, old) = rotation_fixture(storage_sandbox.path());
            writer.fence_outbox_for_key_change().unwrap();
            let mut image = consent_evidence::decode(&old, &ROW_KEY).unwrap();
            let bad = match shape {
                0 => {
                    image.floor_ms += 1;
                    image.seal(&ROW_KEY)
                }
                1 => old[..1000].to_vec(),
                2 => {
                    image.scope = [0xff; 32];
                    image.seal(&ROW_KEY)
                }
                3 => {
                    image.generation += 1;
                    image.seal(&ROW_KEY)
                }
                4 => Vec::new(),
                _ => old.clone(),
            };
            if shape < 5 {
                plant(&path, 0, &bad);
                plant(&path, 1, &bad);
                if matches!(shape, 2 | 3) {
                    let owner = owner_state(&store)
                        .unwrap()
                        .with_evidence(7, consent_evidence::head(&bad));
                    store
                        .store_outbox_owner_state(1, &owner.to_keyring_value())
                        .unwrap();
                }
            } else if shape < 8 {
                let mut fence = encode_fence_line(if shape == 5 { 2 } else { 1 });
                if shape == 6 {
                    fence.extend_from_slice(b"torn");
                }
                if shape == 7 {
                    let at = fence.iter().rposition(|byte| *byte == b'0').unwrap();
                    fence[at] = b'1';
                }
                fs::write(outbox_path(&path), fence).unwrap();
            } else if shape == 8 {
                let mut invalid = old.clone();
                invalid[0] = b'X';
                consent_evidence::apply_tag(&mut invalid, &ROW_KEY);
                plant(&path, 0, &invalid);
                plant(&path, 1, &invalid);
                let owner = owner_state(&store)
                    .unwrap()
                    .with_evidence(7, consent_evidence::head(&invalid));
                store
                    .store_outbox_owner_state(1, &owner.to_keyring_value())
                    .unwrap();
            } else {
                for slot in consent_evidence::slot_paths(&path) {
                    fs::rename(&slot, slot.with_extension("saved")).unwrap();
                }
            }
            let before = (
                slots(&path),
                store.outbox_item_writes(),
                outbox_bytes(&path),
            );
            store.set_reload(Ok(Some(NEXT_KEY)));
            assert!(
                writer
                    .switch_entry_tag_key(Zeroizing::new(NEXT_KEY), "rotation")
                    .is_err(),
                "uncommitted source or inexact fence refuses"
            );
            assert!(
                writer.drain_outbox().is_err(),
                "recovery also refuses the source or fence"
            );
            assert_eq!(
                (
                    slots(&path),
                    store.outbox_item_writes(),
                    outbox_bytes(&path)
                ),
                before
            );
        }
    }

    #[test]
    #[serial_test::serial]
    fn watch_only_acknowledgement_preserves_images() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());

        let (_dir, path, store, writer, _old) = rotation_fixture(storage_sandbox.path());
        drop(writer);
        let mut record = store.load_carrier_record().unwrap().unwrap();
        record.retired = Some(crate::audit_log::tip_anchor::RetiredOutbox {
            generation: 0,
            state: String::new(),
            file: None,
        });
        store.store_carrier_record(&record).unwrap();
        store
            .store_outbox_state(0, &OutboxState::default())
            .unwrap();
        let mut writer = AuditWriter::open_for_outbox_acknowledgement(
            path.clone(),
            Some(Zeroizing::new(ROW_KEY)),
            store.clone(),
            crate::audit_log::BindingHistory::NotRecorded,
        )
        .unwrap();
        let before = (
            slots(&path),
            owner_state(&store),
            store.outbox_item_writes(),
        );
        let result = writer
            .acknowledge_outbox_loss("inspection", Default::default())
            .unwrap();
        assert_eq!(result.drained, 0);
        assert_eq!(
            (
                slots(&path),
                owner_state(&store),
                store.outbox_item_writes()
            ),
            before,
            "watch only acknowledgement preserves evidence"
        );
    }

    #[test]
    #[serial_test::serial]
    fn evidence_transaction_checks_carrier_before_owner_store() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let (_dir, path, store, writer, old) = rotation_fixture(storage_sandbox.path());
        drop(writer);
        let before = owner_writes(&store);
        let watched = store.clone();
        test_seam::on_replacement_synced(&consent_evidence::slot_paths(&path)[1], move || {
            let mut record = watched.load_carrier_record().unwrap().unwrap();
            record.generation += 1;
            watched.store_carrier_record(&record).unwrap();
        });
        assert_eq!(
            reserve_existing(&path, store.clone())
                .unwrap_err()
                .to_string(),
            super::super::writer::audit_writer_refusal(
                &basename(&path),
                &WriterError::CarrierGenerationChanged {
                    held: 1,
                    current: 2
                }
            )
            .to_string()
        );
        assert_eq!(
            owner_writes(&store),
            before,
            "a changed carrier stores no owner"
        );
        assert_eq!(
            committed(&store).unwrap().head,
            consent_evidence::head(&old)
        );
        assert_eq!(slots(&path)[0].as_ref(), Some(&old));
    }

    #[test]
    #[serial_test::serial]
    fn keyless_rotation_refuses_orphaned_evidence() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let dir = tempfile::tempdir_in(storage_sandbox.path()).unwrap();
        let path = log_path(&dir);
        let store = Arc::new(InMemoryTipAnchorStore::new());
        let mut writer = AuditWriter::open_for_key_rotation(
            path.clone(),
            None,
            store.clone(),
            crate::audit_log::BindingHistory::NotRecorded,
        )
        .unwrap();
        plant(&path, 0, b"orphaned evidence");
        let before = (
            slots(&path),
            store.outbox_item_writes(),
            outbox_bytes(&path),
        );
        assert!(
            matches!(
                writer.fence_outbox_for_key_change(),
                Err(WriterError::OutboxEvidenceUnusable {
                    reason: "evidence image without owner"
                })
            ),
            "orphaned slots refuse before the first key write"
        );
        assert!(matches!(
            writer.switch_entry_tag_key(Zeroizing::new(NEXT_KEY), "first key"),
            Err(WriterError::OutboxEvidenceUnusable {
                reason: "evidence image without owner"
            })
        ));
        assert_eq!(
            (
                slots(&path),
                store.outbox_item_writes(),
                outbox_bytes(&path)
            ),
            before
        );
    }

    fn reserve_in_process(
        root: &Path,
        store: &InMemoryTipAnchorStore,
        identity: u8,
        request: &str,
    ) -> OutboxRowRef {
        fs::write(
            root.join("owner-1"),
            store.load_outbox_owner_state(1).unwrap().unwrap(),
        )
        .unwrap();
        fs::write(
            root.join("carrier"),
            serde_json::to_vec(&store.load_carrier_record().unwrap().unwrap()).unwrap(),
        )
        .unwrap();
        fs::write(root.join("scope"), store.outbox_evidence_scope().unwrap()).unwrap();
        let child_home = root.join("child-home");
        stellar_agent_test_support::sandbox::mark_sandbox(&child_home).unwrap();
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "audit_log::outbox::tests::reserved_append_process",
            ])
            .env("RESERVED_PROCESS_ROOT", root)
            .env("RESERVED_PROCESS_ID", identity.to_string())
            .env("RESERVED_PROCESS_REQUEST", request)
            .env("STELLAR_AGENT_HOME", child_home)
            .output()
            .unwrap();
        assert!(
            child.status.success(),
            "child: {}; stderr: {}; stdout: {}",
            child.status,
            String::from_utf8_lossy(&child.stderr),
            String::from_utf8_lossy(&child.stdout)
        );
        store
            .store_outbox_owner_state(1, &fs::read_to_string(root.join("owner-1")).unwrap())
            .unwrap();
        serde_json::from_slice(&fs::read(root.join("reference")).unwrap()).unwrap()
    }

    #[test]
    #[serial_test::serial]
    fn reserved_append_process() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let Ok(root) = std::env::var("RESERVED_PROCESS_ROOT") else {
            return;
        };
        let root = PathBuf::from(root);
        let identity: u8 = std::env::var("RESERVED_PROCESS_ID")
            .unwrap()
            .parse()
            .unwrap();
        let request = std::env::var("RESERVED_PROCESS_REQUEST").unwrap();
        let store = Arc::new(ProcessEvidenceStore {
            root: root.clone(),
            exit_after_store: false,
        });
        let outbox = AuditOutbox::for_log_keyed(
            &root.join("audit/audit.jsonl"),
            store,
            Zeroizing::new(ROW_KEY),
        );
        let reference = reserve_row(&outbox, [identity; 32], &request);
        fs::write(
            root.join("reference"),
            serde_json::to_vec(&reference).unwrap(),
        )
        .unwrap();
    }

    #[derive(Debug)]
    struct ProcessEvidenceStore {
        root: PathBuf,
        exit_after_store: bool,
    }

    #[test]
    #[serial_test::serial]
    fn routed_admissions_are_serializable_across_processes() {
        use std::io::{BufRead, Read};
        use std::process::{Command, Stdio};
        let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
        if let Ok(root) = std::env::var("ADMISSION_RACE_ROOT") {
            let root = PathBuf::from(root);
            let id: u8 = std::env::var("ADMISSION_RACE_ID").unwrap().parse().unwrap();
            let outbox = AuditOutbox::for_log_keyed(
                &root.join("audit/audit.jsonl"),
                Arc::new(ProcessEvidenceStore {
                    root: root.clone(),
                    exit_after_store: false,
                }),
                Zeroizing::new(ROW_KEY),
            );
            assert!(outbox.evidence().unwrap().is_some());
            std::io::stdout().write_all(b"admission ready\n").unwrap();
            std::io::stdout().flush().unwrap();
            std::io::stdin().read_exact(&mut [0]).unwrap();
            let result = outbox
                .reserve_evidence([id; 32], 100_000, 1)
                .map_err(|error| error.code().to_owned())
                .map(|reservation| {
                    outbox
                        .with_evidence_reservation(reservation)
                        .append_queued(&row(&format!("admission-{id}")))
                        .unwrap()
                });
            fs::write(
                root.join(format!("result-{id}")),
                serde_json::to_vec(&result).unwrap(),
            )
            .unwrap();
            return;
        }
        for occupied in [0, MAX_EVIDENCE_ENTRIES - 1] {
            let (dir, path, store, mut writer) = keyed_fixture();
            writer.initialize_consent_evidence().unwrap();
            seed_records(&path, &store, occupied, false);
            let root = dir.path();
            fs::write(
                root.join("owner-1"),
                store.load_outbox_owner_state(1).unwrap().unwrap(),
            )
            .unwrap();
            fs::write(
                root.join("carrier"),
                serde_json::to_vec(&store.load_carrier_record().unwrap().unwrap()).unwrap(),
            )
            .unwrap();
            fs::write(root.join("scope"), store.outbox_evidence_scope().unwrap()).unwrap();
            let child_home = root.join("child-home");
            stellar_agent_test_support::sandbox::mark_sandbox(&child_home).unwrap();
            let mut children = Vec::new();
            for id in [0x77_u8, 0x88] {
                let mut child = Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", "audit_log::outbox::tests::routed_admissions_are_serializable_across_processes", "--nocapture"])
                    .env("ADMISSION_RACE_ROOT", root).env("ADMISSION_RACE_ID", id.to_string())
                    .env("STELLAR_AGENT_HOME", &child_home)
                    .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
                let mut output = std::io::BufReader::new(child.stdout.take().unwrap());
                loop {
                    let mut line = String::new();
                    assert_ne!(
                        output.read_line(&mut line).unwrap(),
                        0,
                        "child reaches the stale-read barrier"
                    );
                    if line.contains("admission ready") {
                        break;
                    }
                }
                children.push((child, output));
            }
            for (child, _) in &mut children {
                child.stdin.take().unwrap().write_all(&[1]).unwrap();
            }
            for (child, _stdout) in children {
                let output = child.wait_with_output().unwrap();
                assert!(
                    output.status.success(),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            store
                .store_outbox_owner_state(1, &fs::read_to_string(root.join("owner-1")).unwrap())
                .unwrap();
            let results: Vec<Result<OutboxRowRef, String>> = [0x77_u8, 0x88]
                .iter()
                .map(|id| {
                    serde_json::from_slice(&fs::read(root.join(format!("result-{id}"))).unwrap())
                        .unwrap()
                })
                .collect();
            assert_eq!(
                results.iter().filter(|r| r.is_ok()).count(),
                if occupied == 0 { 2 } else { 1 },
                "every available slot is admitted exactly once"
            );
            for error in results.iter().filter_map(|r| r.as_ref().err()) {
                assert_eq!(
                    error, "approval.evidence_capacity",
                    "the final slot has one typed loser"
                );
            }
            writer.drain_outbox().unwrap();
            let evidence = writer.outbox_evidence().unwrap().unwrap();
            assert_eq!(
                evidence.records().len(),
                occupied + results.iter().filter(|r| r.is_ok()).count(),
                "a stale reader cannot erase prior admissions"
            );
            for (id, result) in [0x77_u8, 0x88].into_iter().zip(results) {
                if let Ok(reference) = result {
                    assert!(
                        evidence.contains_delivered(&[id; 32], &reference),
                        "every successful process publishes its exact reserved row"
                    );
                }
            }
        }
    }

    impl TipAnchorStore for ProcessEvidenceStore {
        fn reads_audit_key(&self) -> bool {
            false
        }
        fn load_carrier_record(
            &self,
        ) -> Result<Option<crate::audit_log::tip_anchor::CarrierRecord>, TipAnchorStoreError>
        {
            Ok(Some(
                serde_json::from_slice(&fs::read(self.root.join("carrier")).unwrap()).unwrap(),
            ))
        }
        fn store_carrier_record(
            &self,
            _: &crate::audit_log::tip_anchor::CarrierRecord,
        ) -> Result<(), TipAnchorStoreError> {
            unreachable!()
        }
        fn load_outbox_state(&self, _: u64) -> Result<Option<OutboxState>, TipAnchorStoreError> {
            Ok(None)
        }
        fn store_outbox_state(&self, _: u64, _: &OutboxState) -> Result<(), TipAnchorStoreError> {
            unreachable!()
        }
        fn load_outbox_owner_state(
            &self,
            generation: u64,
        ) -> Result<Option<String>, TipAnchorStoreError> {
            match fs::read_to_string(self.root.join(format!("owner-{generation}"))) {
                Ok(value) => Ok(Some(value)),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(_) => Err(TipAnchorStoreError::new("fixture owner read")),
            }
        }
        fn store_outbox_owner_state(
            &self,
            generation: u64,
            value: &str,
        ) -> Result<(), TipAnchorStoreError> {
            let mut file = File::create(self.root.join(format!("owner-{generation}"))).unwrap();
            file.write_all(value.as_bytes()).unwrap();
            file.sync_all().unwrap();
            let mut count = OpenOptions::new()
                .create(true)
                .append(true)
                .open(self.root.join("stores"))
                .unwrap();
            count.write_all(b"1").unwrap();
            count.sync_all().unwrap();
            #[cfg(unix)]
            File::open(&self.root).unwrap().sync_all().unwrap();
            if self.exit_after_store {
                std::process::exit(0);
            }
            Ok(())
        }
        fn outbox_evidence_scope(&self) -> Result<[u8; 32], TipAnchorStoreError> {
            Ok(fs::read(self.root.join("scope"))
                .unwrap()
                .try_into()
                .unwrap())
        }
        fn load_anchor(
            &self,
        ) -> Result<Option<crate::audit_log::tip_anchor::TipAnchor>, TipAnchorStoreError> {
            Ok(None)
        }
        fn load_raw(&self) -> Result<Option<String>, TipAnchorStoreError> {
            Ok(None)
        }
        fn store_anchor(
            &self,
            _: &crate::audit_log::tip_anchor::TipAnchor,
        ) -> Result<(), TipAnchorStoreError> {
            unreachable!()
        }
        fn bump_reanchor_count(&self) -> Result<u64, TipAnchorStoreError> {
            unreachable!()
        }
        fn reanchor_count(&self) -> Result<Option<u64>, TipAnchorStoreError> {
            Ok(None)
        }
    }

    #[test]
    #[serial_test::serial]
    fn evidence_succession_process() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let Ok(root) = std::env::var("EVIDENCE_PROCESS_ROOT") else {
            return;
        };
        let root = PathBuf::from(root);
        let role = std::env::var("EVIDENCE_PROCESS_ROLE").unwrap();
        let path = root.join("audit/audit.jsonl");
        if role == "a" {
            test_seam::on_evidence_loaded(&path, || {
                let mut output = std::io::stdout();
                writeln!(output, "loaded").unwrap();
                output.flush().unwrap();
                std::io::stdin().read_exact(&mut [0]).unwrap();
            });
        } else if role == "b" {
            test_seam::on_contended(&outbox_lock_path(&path), || {
                let mut output = std::io::stdout();
                writeln!(output, "contended").unwrap();
                output.flush().unwrap();
            });
        }
        let store = ProcessEvidenceStore {
            root,
            exit_after_store: role == "a",
        };
        let evidence = locked_owner_evidence(&path, &store, Some(&ROW_KEY))
            .unwrap()
            .unwrap();
        assert_eq!(evidence.records(), &[evidence_record(9)]);
        assert_eq!(evidence.time_floor_ms(), 90);
        writeln!(std::io::stdout(), "returned newest evidence").unwrap();
    }

    #[test]
    #[serial_test::serial]
    fn stale_owner_succession_across_processes() {
        use std::io::{BufRead, BufReader};
        use std::process::{Command, Stdio};
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let (dir, path, store, writer, _old) = rotation_fixture(storage_sandbox.path());
        drop(writer);
        let root = dir.path();
        // The fixture log name is used by every child through the shared root.
        assert_eq!(path, root.join("audit/audit.jsonl"));
        let newest = sealed(&store, 9, &[9]);
        plant(&path, 1, &newest);
        let images = slots(&path);
        fs::write(
            root.join("owner-1"),
            store.load_outbox_owner_state(1).unwrap().unwrap(),
        )
        .unwrap();
        fs::write(
            root.join("carrier"),
            serde_json::to_vec(&store.load_carrier_record().unwrap().unwrap()).unwrap(),
        )
        .unwrap();
        fs::write(root.join("scope"), store.outbox_evidence_scope().unwrap()).unwrap();
        let child_home = root.join("child-home");
        stellar_agent_test_support::sandbox::mark_sandbox(&child_home).unwrap();
        let spawn = |role: &str| {
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "audit_log::outbox::tests::evidence_succession_process",
                    "--nocapture",
                ])
                .env("EVIDENCE_PROCESS_ROOT", root)
                .env("EVIDENCE_PROCESS_ROLE", role)
                .env("STELLAR_AGENT_HOME", &child_home)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap()
        };
        let wait_for = |reader: &mut BufReader<std::process::ChildStdout>, marker: &str| {
            let mut line = String::new();
            loop {
                line.clear();
                assert_ne!(
                    reader.read_line(&mut line).unwrap(),
                    0,
                    "child reaches {marker}"
                );
                if line.trim() == marker {
                    break;
                }
            }
        };
        let mut a = spawn("a");
        let mut a_output = BufReader::new(a.stdout.take().unwrap());
        wait_for(&mut a_output, "loaded");
        let mut b = spawn("b");
        let mut b_output = BufReader::new(b.stdout.take().unwrap());
        wait_for(&mut b_output, "contended");
        a.stdin.take().unwrap().write_all(b"1").unwrap();
        let a = a.wait_with_output().unwrap();
        assert!(
            a.status.success(),
            "child a: {}; stderr: {}",
            a.status,
            String::from_utf8_lossy(&a.stderr)
        );
        wait_for(&mut b_output, "returned newest evidence");
        let b = b.wait_with_output().unwrap();
        assert!(
            b.status.success(),
            "child b: {}; stderr: {}",
            b.status,
            String::from_utf8_lossy(&b.stderr)
        );
        assert_eq!(
            fs::read(root.join("stores")).unwrap(),
            b"1",
            "exactly one successor owner store"
        );
        let actual =
            OutboxOwnerState::parse(&fs::read_to_string(root.join("owner-1")).unwrap()).unwrap();
        assert_eq!(
            actual.e.unwrap(),
            EvidenceCommitment {
                g: 9,
                head: consent_evidence::head(&newest)
            }
        );
        assert_eq!(slots(&path), images);
        let restarted = spawn("restart").wait_with_output().unwrap();
        assert!(
            restarted.status.success(),
            "child restart: {}; stderr: {}",
            restarted.status,
            String::from_utf8_lossy(&restarted.stderr)
        );
        assert!(String::from_utf8_lossy(&restarted.stdout).contains("returned newest evidence"));
        assert_eq!(
            fs::read(root.join("stores")).unwrap(),
            b"1",
            "restart stores nothing"
        );
        assert_eq!(slots(&path), images);
    }

    #[test]
    fn storage_protocol_documents_owner_recovery() {
        const DOC: &str = include_str!("../../../../docs/maintainers/audit-log-recovery.md");
        for sentence in [
            "Any authenticated image above the committed generation proves an older owner entry, and the next keyed read recommits the newest one.",
            "Two distinct authenticated images of that generation refuse with `owner rollback`.",
            "Restore the most recent trusted owner value at its `-owner` account with the platform keyring tool, then retry a keyed acquisition.",
            "Never fabricate an owner value or erase an evidence file.",
        ] {
            assert!(DOC.contains(sentence), "{sentence}");
        }
    }

    #[test]
    fn rotation_refuses_beside_the_slots_of_a_restored_v1_owner() {
        let (_dir, path, store, mut writer) = keyed_fixture();
        keyed_outbox(&path, &store)
            .append_queued(&row("first"))
            .unwrap();
        assert_eq!(writer.drain_outbox().unwrap(), 1);
        let v1 = store.load_outbox_owner_state(1).unwrap().unwrap();
        writer.initialize_consent_evidence().unwrap();
        drop(writer);
        store.store_outbox_owner_state(1, &v1).unwrap();
        let mut rotation = rotation_writer(&path, &store);
        assert_eq!(
            outbox_bytes(&path),
            header(1),
            "the queue is empty and valid"
        );
        let writes = store.outbox_item_writes();
        let images = slots(&path);
        assert!(matches!(
            rotation.fence_outbox_for_key_change(),
            Err(WriterError::OutboxEvidenceUnusable {
                reason: "evidence image without owner"
            })
        ));
        assert_eq!(outbox_bytes(&path), header(1));
        assert_eq!(store.outbox_item_writes(), writes);
        assert_eq!(store.load_outbox_owner_state(1).unwrap().unwrap(), v1);
        assert_eq!(slots(&path), images);
        for image in slots(&path) {
            assert!(consent_evidence::decode(&image.unwrap(), &ROW_KEY).is_ok());
        }
    }

    /// Fails the owner store of a first initialization after both slots hold
    /// the initial image, and returns those slots.
    fn interrupt_first_initialization(
        path: &Path,
        store: &InMemoryTipAnchorStore,
        writer: &mut AuditWriter,
    ) -> [Option<Vec<u8>>; 2] {
        store.set_owner_failing(false, true);
        assert!(writer.initialize_consent_evidence().is_err());
        store.set_owner_failing(false, false);
        assert!(owner_state(store).is_none());
        let images = slots(path);
        assert!(
            images.iter().all(Option::is_some),
            "the initial image is written"
        );
        images
    }

    /// Queues the consent row `id` through `append_queued` from a child
    /// process and returns its reference.
    #[cfg(unix)]
    fn queue_from_child(
        dir: &TempDir,
        path: &Path,
        store: &InMemoryTipAnchorStore,
        id: &str,
    ) -> OutboxRowRef {
        use std::io::{BufRead as _, BufReader, Write as _};
        use std::os::unix::net::UnixListener;
        let socket = dir.path().join(format!("{id}.sock"));
        let listener = UnixListener::bind(&socket).unwrap();
        let record = store
            .load_carrier_record()
            .unwrap()
            .unwrap()
            .to_keyring_value()
            .unwrap();
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "audit_log::outbox::tests::queued_append_process",
                "--nocapture",
            ])
            .env("QUEUED_TEST_LOG", path)
            .env("QUEUED_TEST_RECORD", &record)
            .env("QUEUED_TEST_SOCKET", &socket)
            .env("QUEUED_TEST_ID", id)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut stream = BufReader::new(listener.accept().unwrap().0);
        let mut wire = String::new();
        stream.read_line(&mut wire).unwrap();
        stream.get_mut().write_all(b"received\n").unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_str(&wire).unwrap()
    }

    /// A second process that appends one queue shape and prints the
    /// commitment it stored, as the shared keyring would hold it.
    #[test]
    fn gap_append_process() {
        let Ok(log) = std::env::var("GAP_TEST_LOG") else {
            return;
        };
        let path = PathBuf::from(log);
        let state = Arc::new(InMemoryTipAnchorStore::new());
        let record = crate::audit_log::tip_anchor::CarrierRecord::parse(
            &std::env::var("GAP_TEST_RECORD").unwrap(),
        )
        .unwrap();
        state.store_carrier_record(&record).unwrap();
        let committed = std::env::var("GAP_TEST_STATE").unwrap();
        if !committed.is_empty() {
            state
                .store_outbox_state(record.generation, &OutboxState::parse(&committed).unwrap())
                .unwrap();
        }
        let shape = std::env::var("GAP_TEST_SHAPE").unwrap();
        if shape == "raw" || shape == "mixed" {
            AuditOutbox::for_log(&path, state.clone())
                .append(&row("gap-raw"))
                .unwrap();
        }
        if shape == "tagged" || shape == "mixed" {
            keyed_outbox(&path, &state)
                .append_queued(&row("gap-tagged"))
                .unwrap();
        }
        if shape == "foreign" {
            let mut file = OpenOptions::new()
                .append(true)
                .create(true)
                .open(outbox_path(&path))
                .unwrap();
            file.write_all(b"{\"k\":\"row\"}\n").unwrap();
        }
        let stored = state.load_outbox_state(record.generation).unwrap();
        writeln!(
            std::io::stdout(),
            "STATE:{}",
            stored.map(|s| s.to_keyring_value()).unwrap_or_default()
        )
        .unwrap();
    }

    /// Runs [`gap_append_process`] for `shape` and stores its commitment.
    fn gap_append(path: &Path, store: &InMemoryTipAnchorStore, shape: &str) {
        let record = store.load_carrier_record().unwrap().unwrap();
        let committed = store
            .load_outbox_state(record.generation)
            .unwrap()
            .map(|s| s.to_keyring_value())
            .unwrap_or_default();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "audit_log::outbox::tests::gap_append_process",
                "--nocapture",
            ])
            .env("GAP_TEST_LOG", path)
            .env("GAP_TEST_RECORD", record.to_keyring_value().unwrap())
            .env("GAP_TEST_STATE", committed)
            .env("GAP_TEST_SHAPE", shape)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        let stored = stdout
            .lines()
            .find_map(|line| line.strip_prefix("STATE:"))
            .unwrap();
        if !stored.is_empty() {
            store
                .store_outbox_state(record.generation, &OutboxState::parse(stored).unwrap())
                .unwrap();
        }
    }

    #[test]
    fn initialization_retry_takes_rows_queued_after_the_preliminary_drain() {
        let (_clean_dir, clean_path, clean_store, mut clean) = keyed_fixture();
        clean.initialize_consent_evidence().unwrap();
        for (shape, gap) in [
            ("raw", &["gap-raw"][..]),
            ("tagged", &["gap-tagged"][..]),
            ("mixed", &["gap-raw", "gap-tagged"][..]),
        ] {
            let (_dir, path, store, mut writer) = keyed_fixture();
            AuditOutbox::for_log(&path, store.clone())
                .append(&row("first"))
                .unwrap();
            let (hook_path, hook_store) = (path.clone(), store.clone());
            test_seam::on_initialization_retry(&path, move || {
                gap_append(&hook_path, &hook_store, shape);
            });
            writer.initialize_consent_evidence().unwrap();
            let ids = request_ids(&path);
            let queued: Vec<&str> = ids
                .iter()
                .map(String::as_str)
                .filter(|id| *id == "first" || gap.contains(id))
                .collect();
            let mut expected = vec!["first"];
            expected.extend_from_slice(gap);
            assert_eq!(queued, expected, "{shape}: once each, in file order");
            assert_eq!(outbox_bytes(&path), header(1), "{shape}");
            assert_eq!(slots(&path), slots(&clean_path), "{shape}");
            assert_eq!(committed(&store), committed(&clean_store), "{shape}");
            assert_eq!(
                writer.outbox_evidence().unwrap(),
                clean.outbox_evidence().unwrap(),
                "{shape}"
            );
        }
        let (_dir, path, store, mut writer) = keyed_fixture();
        AuditOutbox::for_log(&path, store.clone())
            .append(&row("first"))
            .unwrap();
        let (hook_path, hook_store) = (path.clone(), store.clone());
        test_seam::on_initialization_retry(&path, move || {
            gap_append(&hook_path, &hook_store, "foreign");
        });
        let error = writer.initialize_consent_evidence().unwrap_err();
        assert!(
            matches!(
                error,
                WriterError::OutboxEvidenceUnusable {
                    reason: "queue not drained"
                }
            ),
            "{error:?}"
        );
        assert_eq!(audit_writer_code(&error), "audit.outbox_evidence_unusable");
        assert_eq!(slots(&path), [None, None], "nothing is written");
        assert!(owner_state(&store).is_none());
    }

    fn audit_writer_code(error: &WriterError) -> &'static str {
        crate::audit_log::writer::audit_writer_refusal("fixture", error).code()
    }

    #[cfg(unix)]
    #[test]
    fn an_interrupted_initialization_keeps_a_legacy_prefix_and_its_tagged_suffix() {
        let (dir, path, store, mut writer) = keyed_fixture();
        let images = interrupt_first_initialization(&path, &store, &mut writer);
        AuditOutbox::for_log(&path, store.clone())
            .append(&row("raw"))
            .unwrap();
        let reference = queue_from_child(&dir, &path, &store, "consent");
        assert_eq!((reference.generation(), reference.sequence()), (0, 2));

        writer.initialize_consent_evidence().unwrap();
        let ids = request_ids(&path);
        let delivered_ids: Vec<&str> = ids
            .iter()
            .map(String::as_str)
            .filter(|id| ["raw", "consent"].contains(id))
            .collect();
        assert_eq!(
            delivered_ids,
            ["raw", "consent"],
            "once each, in file order"
        );
        assert_eq!(outbox_bytes(&path), header(1));
        assert_eq!(slots(&path), images);

        let (_clean_dir, clean_path, clean_store, mut clean) = keyed_fixture();
        clean.initialize_consent_evidence().unwrap();
        assert_eq!(slots(&path), slots(&clean_path), "the same evidence images");
        assert_eq!(committed(&store), committed(&clean_store));
        assert_eq!(
            writer.outbox_evidence().unwrap(),
            clean.outbox_evidence().unwrap()
        );
    }

    #[cfg(unix)]
    #[test]
    fn an_interrupted_initialization_completes_beside_a_queued_row() {
        use std::io::{BufRead as _, BufReader, Write as _};
        use std::os::unix::net::UnixListener;
        let (dir, path, store, mut writer) = keyed_fixture();
        let images = interrupt_first_initialization(&path, &store, &mut writer);

        let socket = dir.path().join("evidence.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let record = store
            .load_carrier_record()
            .unwrap()
            .unwrap()
            .to_keyring_value()
            .unwrap();
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "audit_log::outbox::tests::queued_append_process",
                "--nocapture",
            ])
            .env("QUEUED_TEST_LOG", &path)
            .env("QUEUED_TEST_RECORD", &record)
            .env("QUEUED_TEST_SOCKET", &socket)
            .env("QUEUED_TEST_ID", "queued-in-between")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut stream = BufReader::new(listener.accept().unwrap().0);
        let mut wire = String::new();
        stream.read_line(&mut wire).unwrap();
        let reference: OutboxRowRef = serde_json::from_str(&wire).unwrap();
        stream.get_mut().write_all(b"received\n").unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!((reference.generation(), reference.sequence()), (0, 1));

        writer.initialize_consent_evidence().unwrap();
        assert_eq!(delivered(&path, "queued-in-between"), 1, "the row survives");
        assert_eq!(outbox_bytes(&path), header(1));
        assert_eq!(slots(&path), images);
        assert_eq!(
            committed(&store).unwrap().head,
            consent_evidence::head(images[0].as_ref().unwrap())
        );
        assert!(writer.outbox_evidence().unwrap().is_some());
    }

    #[test]
    fn initialization_refuses_foreign_slots_before_draining() {
        for keyed in [false, true] {
            let (_dir, path, store, mut writer) = keyed_fixture();
            plant(&path, 0, b"foreign evidence");
            if keyed {
                keyed_outbox(&path, &store).append(&row("queued")).unwrap();
            } else {
                AuditOutbox::for_log(&path, store.clone())
                    .append(&row("queued"))
                    .unwrap();
            }
            let queue = outbox_bytes(&path);
            let writes = store.outbox_item_writes();
            assert_eq!(
                evidence_refusal(writer.initialize_consent_evidence().map(|()| None)),
                "evidence image without owner",
                "keyed: {keyed}"
            );
            assert_eq!(outbox_bytes(&path), queue, "the row stays queued");
            assert_eq!(delivered(&path, "queued"), 0);
            assert_eq!(store.outbox_item_writes(), writes);
            assert_eq!(slots(&path), [Some(b"foreign evidence".to_vec()), None]);
        }
    }
}
