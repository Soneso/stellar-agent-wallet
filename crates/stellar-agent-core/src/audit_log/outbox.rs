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
//! The owner drain retains delivery evidence for those consent rows.
//! The body is the entry's canonical JSON. The tag is lowercase hex HMAC-SHA256
//! over `stellar-agent-outbox-row:v2`, big-endian u64 generation and sequence,
//! one evidence byte, and the exact body bytes, without separators or newline.
//! Without a generation line, G is zero and S is the one-based line number,
//! untagged lines included. With one, G is its generation and S is the row's
//! position after it. Both are assigned under the outbox lock.
//!
//! A keyed append neither reads nor writes a keyring commitment or owner
//! state. Under the outbox lock it reads an existing file, checks the carrier
//! generation, authenticates a first generation line and checks the quota.
//! It then measures and encodes its row. A generation line that does not
//! verify under the held key triggers one reload of the audit key; the
//! reloaded key then also tags this row. It writes and syncs its row, syncs
//! the directory, and checks the carrier generation again. The directory
//! sync makes the file's name durable before the row is acknowledged, also
//! after a publication whose own directory sync failed.
//!
//! An unkeyed append writes the serialized entry. The v1 commitment covers every
//! line's bytes in file order, and its stored representation stays v1.
//! Under the outbox lock it first checks the keyring commitment against the
//! complete lines as read. A committed line that lost its newline or its tail
//! therefore refuses the append with the file unchanged. After its row is
//! written and synced, it stores the new count and chain head.
//!
//! Every append follows one rule. A refusal before the first write changes
//! nothing: the checks, the row's measure and its encoding all run first. The
//! first write creates a missing file or drops a torn tail, a final segment
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
//! The owner value records a queue generation, a closed batch, a legacy-state
//! digest, and at most 15 requested row digests, oldest first.
//! Recent evidence includes only rows whose evidence flag is one.
//! The legacy digest hashes the exact v1 commitment value at cutover.
//! Batch commitments hash ordered binary row digests. A row digest hashes the
//! row's bytes without its tag and newline. An untagged row of a cutover
//! prefix hashes as a row of generation zero at its line with evidence zero.
//! Owner accounts follow carrier generations, independently of the queue
//! generation inside the value. Only writers holding the writer and outbox
//! carriers write owner state. Locked verification may read owner state
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

use super::entry::AuditEntry;
use super::lock::{AuditWriterLock, BoundCarrierLock, Carrier};
use super::schema::EventKind;
use super::writer::{WriterError, basename_lossy_path as basename, sidecar_path};

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
        struct Stored {
            v: u64,
            g: u64,
            #[serde(deserialize_with = "serde::Deserialize::deserialize")]
            closed: Option<StoredClosed>,
            #[serde(deserialize_with = "serde::Deserialize::deserialize")]
            legacy: Option<String>,
            recent: Vec<String>,
        }
        let invalid = || TipAnchorStoreError::new("outbox owner state is unusable");
        let hash = |text: &str| bare_hash(text.as_bytes()).ok_or_else(invalid);
        let stored: Stored = serde_json::from_str(raw).map_err(|_| invalid())?;
        if stored.v != 1 || stored.recent.len() > 15 {
            return Err(invalid());
        }
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
            recent: stored
                .recent
                .iter()
                .map(|text| hash(text))
                .collect::<Result<_, _>>()?,
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
        }
    }

    fn record_delivery(&mut self, g: u64, rows: &[(u8, [u8; 32])]) {
        self.close(g, rows, 0);
    }

    /// Closes generation `g` over `rows`, of which the first `delivered`
    /// already count in the recent evidence.
    fn close(&mut self, g: u64, rows: &[(u8, [u8; 32])], delivered: usize) {
        for (r, digest) in rows.get(delivered..).unwrap_or_default() {
            if *r == 1 {
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

/// Checks the outbox's committed prefix under its lock, taken through the
/// carrier record.
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
    match batch.owner(store)? {
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
    path: PathBuf,
    lock_path: PathBuf,
    state: Arc<dyn TipAnchorStore>,
    key: Option<Zeroizing<[u8; 32]>>,
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
            path: outbox_path(log_path),
            lock_path: outbox_lock_path(log_path),
            state,
            key: None,
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
            lock,
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
            lock,
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
    lock: BoundCarrierLock,
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
        let lines = parse_lines(&self.bytes).lines;
        match self.owner(store)? {
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
            if g == owner.g && rows.is_empty() && clean {
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
        match &self._guard {
            BatchGuard::Bound(lock) => lock.check_generation(store)?,
            BatchGuard::Retained(lock) => lock.check_generation(store)?,
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
            }
        }
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
}

impl OwnerDelivery {
    fn publish_only(g: u64) -> Self {
        Self {
            entries: Vec::new(),
            owner: None,
            zero_legacy: false,
            publish: Some(g),
        }
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
    fn a_queued_reference_survives_completed_key_rotation() {
        let (_dir, path, store, writer) = cut_over_fixture();
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
            let append = scope.spawn(|| keyed_outbox(&path, &store).append_queued(&row("rotated")));
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
        assert_eq!(
            owner_state(&store).unwrap().recent,
            vec![*reference.digest()]
        );
        assert_eq!(writer.drain_outbox().unwrap(), 0);
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
    fn owner_verify_reads_the_stored_key_once() {
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
}
