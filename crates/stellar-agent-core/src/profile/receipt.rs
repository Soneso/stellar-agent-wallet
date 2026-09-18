//! Profile-local submission receipt store.
//!
//! Records `{ envelope_hash → SubmissionReceipt }` for every transaction the
//! wallet has attempted to submit. The store is backed by a profile-local JSON
//! file (`<profile_dir>/receipts/<profile_name>.json`) and an in-memory
//! `Arc<Mutex<HashMap>>` cache for concurrent access.
//!
//! `SubmissionReceipt` carries `recorded_at_ledger` and `max_time` consumed by
//! the retention-aware polling and re-org reconciliation path
//! (`reconcile_receipt` in `stellar-agent-network::idempotent_submit`).
//!
//! # Idempotency key (`envelope_hash` field semantics)
//!
//! The `envelope_hash` field holds an **opaque idempotency key** whose exact
//! meaning depends on the submission path:
//!
//! - **Classic (V1) path**: `SHA-256(signed TransactionEnvelope XDR)` — a
//!   signature-sensitive digest over the full `TransactionEnvelope` (including
//!   signatures).  Using the signed envelope as the key means that an identical
//!   resubmit (same envelope bytes, same signatures) maps to the same receipt,
//!   while a re-signed copy of the same unsigned transaction does not collide.
//!
//! - **Fee-bump path** (`fee_bump_retry::submit_fee_bump_idempotent`):
//!   `"feebump-inner:" ‖ hex(inner_tx_hash)` — a prefixed inner tx hash.
//!   The prefix namespaces fee-bump keys away from classic-path keys in the
//!   same store.  The inner tx hash is the canonical Stellar replay-protection
//!   identity (`SHA-256(network_id ‖ ENVELOPE_TYPE_TX ‖ inner-tx-body)`).
//!   This enables retry-with-higher-fee: a second call with a different outer
//!   fee produces a different outer envelope but the same inner key, so at most
//!   one receipt is ever recorded per inner tx.
//!
//! In both cases `envelope_hash` is distinct from `tx_hash`: the latter holds
//! the on-chain RPC poll handle.  The two fields serve different purposes and
//! MUST NOT be confused.
//!
//! # Concurrency model
//!
//! Two layers protect the store, one per contention domain.
//!
//! In-process, the state is protected by a `std::sync::Mutex`.  `parking_lot`
//! is not a workspace dependency; adding it solely for this module would be
//! disproportionate.  `std::sync::Mutex` is sufficient here because the lock
//! is held for the duration of one store operation (file read, in-memory map
//! update, file write), never across an `.await`.  If `parking_lot` is adopted
//! workspace-wide, this module should migrate at the same time.
//!
//! Cross-process, every mutating operation acquires an exclusive advisory lock
//! on a sidecar file next to the store file (`<store>.json.lock`), mirroring
//! `crate::audit_log::lock::AuditWriterLock` and
//! `stellar_agent_network::policy_state::lock::WindowStoreLock`.  Contention
//! is absorbed by a bounded retry ([`RECEIPT_LOCK_ATTEMPTS`] attempts,
//! [`RECEIPT_LOCK_BACKOFF`] apart, the same settings the pending-approval
//! store uses); an exhausted retry surfaces as
//! [`ReceiptStoreError::WriterLocked`].  The lock is taken per operation and
//! released when that operation returns, so it is never held across a network
//! send.
//!
//! Every operation re-reads the file before acting on it, so a receipt another
//! process wrote is visible immediately.  Mutating operations do this under
//! the sidecar lock, which makes the read-modify-write sequence atomic against
//! other processes.  Read-only lookups skip the sidecar lock: the file is only
//! ever replaced by an atomic rename, so a concurrent reader observes either
//! the old file or the new one, never a torn one.
//!
//! Under the pool's concurrent submissions, the first task to call `try_begin`
//! for a given envelope hash becomes the **winner** and proceeds to submit. Any
//! subsequent task that calls `try_begin` for the same hash is the **loser**
//! and receives `BeginOutcome::AlreadyPresent`.  The loser must not submit; it
//! should poll the store (or `getTransaction`) until the winner records a
//! terminal status.
//!
//! # Lookup indexes
//!
//! The map is keyed on `envelope_hash`, but two other identities have to be
//! resolved to a receipt:
//!
//! - `tx_hash`, so `stellar_transaction_status` and `tx status` can find the
//!   record for a hash an agent holds.
//! - `(source account, sequence)`, so a second submission for a sequence a
//!   pending submission already consumed is refused whatever its fee or bytes.
//!
//! Both are in-memory maps from the secondary identity to the `envelope_hash`,
//! rebuilt from the map whenever it is read from disk or mutated.  Every
//! lookup resolves through the map, so a receipt's status always comes from
//! the map rather than from anything cached in an index.
//!
//! # Re-org reconciliation
//!
//! A `ReceiptStatus::Success` receipt may later be demoted to
//! `ReceiptStatus::Reorged` when a `getTransaction` reconciliation pass finds
//! the transaction is no longer present at its recorded ledger. The demotion is
//! recorded via [`ReceiptStore::finalize_reorged`], which also preserves the
//! prior `Success` ledger in `prior_ledger` so callers can detect "it was
//! confirmed, then rewound".
//!
//! Reconciliation is **lazy** — it runs when a previously-`Success` receipt is
//! re-queried, not via a background poller.
//!
//! # Secret-material discipline
//!
//! The store holds **only** envelope hashes, tx hashes, status, ledger, and
//! `max_time`. No signed envelope XDR is stored. No key material is stored.
//! Tx hashes are not logged (but appear in the persisted file as non-secret
//! public identifiers).
//!
//! # Atomicity
//!
//! Persistence uses the temp-file-then-rename pattern (same as
//! `profile::loader::save`): the JSON is written to a temp file in the same
//! directory, then atomically renamed over the destination. On POSIX
//! single-filesystem mounts, `rename(2)` is atomic; on Windows, `persist()`
//! from `tempfile` uses `MoveFileExW(MOVEFILE_REPLACE_EXISTING)`.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Sidecar lock settings
// ─────────────────────────────────────────────────────────────────────────────

/// Number of sidecar-lock acquisition attempts per store operation.
///
/// Matches `stellar_agent_core::approval::retry::DEFAULT_RETRY_ATTEMPTS`: the
/// two stores contend for the same reason (short operations by two processes
/// serving one profile) and resolve it with the same bounded wait.
pub const RECEIPT_LOCK_ATTEMPTS: u32 = 5;

/// Wait between sidecar-lock acquisition attempts.
///
/// Matches `stellar_agent_core::approval::retry::DEFAULT_RETRY_BACKOFF`, so a
/// fully contended operation blocks for at most four backoffs before
/// surfacing [`ReceiptStoreError::WriterLocked`].
pub const RECEIPT_LOCK_BACKOFF: Duration = Duration::from_millis(20);

// ─────────────────────────────────────────────────────────────────────────────
// ReceiptStatus
// ─────────────────────────────────────────────────────────────────────────────

/// The current state of a submitted transaction.
///
/// `#[non_exhaustive]` because `Ambiguous` and `Reorged` may be joined by
/// additional states; downstream matchers must include a wildcard arm.
///
/// The `Failed { code }` string is a `WalletError::code()`-style stable wire
/// string (e.g. `"ledger.op_failed"`, `"submission.feebump_inner_rejected"`)
/// so the receipt store and the live error path cannot drift.
///
/// # Variant lifecycle
///
/// The submission path produces and consumes: `Pending`, `Success`, `Failed`.
/// `Ambiguous` and `Reorged` are defined here for the full schema but are only
/// **set** by the retention-aware polling path.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum ReceiptStatus {
    /// Submission has been attempted but no terminal response received yet.
    ///
    /// A `Pending` entry written before submission enables crash-recovery:
    /// if the process dies after `sendTransaction` but before the terminal
    /// write, the next call sees the stale `Pending` and can poll
    /// `getTransaction` to recover the true status.
    Pending,

    /// Transaction confirmed on-chain (`getTransaction` returned SUCCESS).
    Success,

    /// Transaction rejected on-chain (`getTransaction` returned FAILED).
    ///
    /// `code` is the stable wire code from the error path (e.g.
    /// `"ledger.insufficient_balance"`, `"ledger.trustline_missing"`).
    Failed {
        /// Stable wire error code from `WalletError::code()`.
        code: String,
    },

    /// Transaction status is unknown.
    ///
    /// Set by:
    /// - The stale-Pending crash-recovery path when `getTransaction` returns
    ///   `NOT_FOUND` after `max_time` has elapsed, or when the stored `tx_hash`
    ///   is the all-zeros sentinel (unknown true hash — no resubmit is safe).
    /// - The retention-aware polling path when the RPC retention window closes
    ///   before a terminal response is received.
    ///
    /// The caller may safely resubmit **after** `max_time` has elapsed (the
    /// original is then structurally too late; a replay cannot double-apply).
    Ambiguous,

    /// A previously-confirmed transaction was evicted by a ledger re-org.
    ///
    /// Set by the re-org reconciliation path; not set by the initial submit path.
    /// Distinct from `Failed` so the caller can detect "it was rewound"
    /// separately from "it was rejected".
    Reorged,

    /// An operator acknowledged an unresolvable submission and released its
    /// hold on the spending window.
    ///
    /// Written by `tx receipt clear --acknowledge` for the two states
    /// reconciliation cannot settle: a submitted `Pending` receipt whose
    /// transaction `getTransaction` reports `NOT_FOUND`, and an `Ambiguous`
    /// receipt whose window reservation is still open because the submission
    /// ledger has fallen outside the endpoint's retention window.
    ///
    /// The receipt is marked, not removed, so the envelope keeps its
    /// idempotency anchor: a byte-identical resubmission still gets
    /// [`BeginOutcome::AlreadyPresent`] from [`ReceiptStore::try_begin`].
    ClearedByOperator,
}

impl ReceiptStatus {
    /// Returns `true` if the status is terminal (no further state transition
    /// expected from the normal submission path).
    ///
    /// `Pending` is non-terminal. `Ambiguous`, `Reorged` and
    /// `ClearedByOperator` are terminal for the purposes of idempotency
    /// checking (they will not transition to Success/Failed via the standard
    /// poll path).
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Success
                | Self::Failed { .. }
                | Self::Ambiguous
                | Self::Reorged
                | Self::ClearedByOperator
        )
    }

    /// Returns `true` when the status records an outcome the network itself
    /// reported: `Success` or `Failed`.
    ///
    /// Only a definitive `getTransaction` answer produces one, which is what
    /// makes these the two statuses [`ReceiptStore::finalize`] accepts for a
    /// receipt whose outcome is otherwise recorded as unknown.
    #[must_use]
    pub fn is_definitive_outcome(&self) -> bool {
        matches!(self, Self::Success | Self::Failed { .. })
    }

    /// Returns `true` when an operator may clear a receipt in this status.
    ///
    /// The two states reconciliation cannot settle: a `Pending` receipt, whose
    /// transaction the endpoint does not report, and an `Ambiguous` one, whose
    /// submission ledger has fallen outside the endpoint's retention window. A
    /// receipt the network answered for is refused, because it needs no
    /// acknowledgement.
    ///
    /// The chain-side half of the rule is the caller's: clearing states that
    /// the transaction did not move value, and only the endpoint can
    /// contradict that. `stellar-agent tx receipt clear` evaluates this
    /// predicate first, so a clear it will refuse releases nothing and writes
    /// no row, then asks the endpoint before it accepts.
    #[must_use]
    pub fn is_operator_clearable(&self) -> bool {
        matches!(self, Self::Pending | Self::Ambiguous)
    }

    /// Returns the stable wire tag for this status.
    ///
    /// The same string the serde tag writes, so a diagnostic naming a status
    /// and the persisted file cannot drift.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Success => "success",
            Self::Failed { .. } => "failed",
            Self::Ambiguous => "ambiguous",
            Self::Reorged => "reorged",
            Self::ClearedByOperator => "cleared_by_operator",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SubmissionReceipt
// ─────────────────────────────────────────────────────────────────────────────

/// A persisted record of a transaction submission attempt.
///
/// Keyed by `envelope_hash` inside [`ReceiptStore`]. All fields are public
/// identifiers — no secret material.
///
/// # Field semantics
///
/// `envelope_hash` = opaque idempotency key (see module-level doc for both
/// variants: classic `SHA-256(signed XDR)` and fee-bump
/// `"feebump-inner:" ‖ hex(inner_tx_hash)`).
/// `tx_hash` = canonical `SHA-256(network_id ‖ ENVELOPE_TYPE_TX ‖ unsigned-tx-body)` hex
/// (classic path) OR the OUTER fee-bump tx hash (fee-bump path; used as the
/// `getTransaction` poll handle — stellar-rpc indexes a fee-bump by both outer
/// and inner hash, `stellar-rpc db/transaction.go:102-107`).
/// `max_time` = absolute unix seconds from `TimeBounds.maxTime`
/// (`rs-stellar-xdr 26.0.1 curr/generated.rs:35620`); `0` means unbounded.
/// For the fee-bump path this is the INNER tx's `maxTime` (a fee-bump has no
/// `cond` of its own per CAP-15).
///
/// # Re-org tracking
///
/// When a `Success` receipt is demoted to `Reorged` by
/// [`ReceiptStore::finalize_reorged`], the `prior_ledger` field retains the
/// ledger sequence at which the transaction was originally confirmed.  This
/// allows callers to detect "it WAS confirmed in ledger N, then the chain
/// re-orged it away" — distinguishable from a never-confirmed failure.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmissionReceipt {
    /// Opaque idempotency key rendered as a lowercase ASCII string.
    ///
    /// The exact value depends on the submission path:
    ///
    /// - **Classic (V1) path**: `SHA-256(signed TransactionEnvelope XDR)` hex
    ///   (64 lowercase hex chars).  Signature-sensitive; the same signed
    ///   envelope always maps to the same hash.
    ///
    /// - **Fee-bump path** (`fee_bump_retry::submit_fee_bump_idempotent`):
    ///   `"feebump-inner:" ‖ hex(inner_tx_hash)` (prefix + 64 hex chars).
    ///   The inner tx hash is the canonical Stellar replay-protection identity
    ///   (`SHA-256(network_id ‖ ENVELOPE_TYPE_TX ‖ inner-tx-body)`; the same
    ///   hash regardless of the outer fee or outer signer, enabling
    ///   retry-with-higher-fee).
    ///
    /// Always distinct from `tx_hash` (the on-chain RPC poll handle).
    pub envelope_hash: String,

    /// Canonical transaction hash (64-character lowercase hex).
    ///
    /// Derived as `SHA-256(network_id ‖ ENVELOPE_TYPE_TX ‖ unsigned-tx-body)`.
    /// Used for `getTransaction` polling during stale-Pending recovery.
    pub tx_hash: String,

    /// The account whose sequence number this transaction consumes, as a
    /// `G...` strkey. For a fee-bump this is the INNER transaction's source.
    ///
    /// Together with [`Self::sequence`] this is the replay identity the
    /// network enforces: at most one transaction per `(source, sequence)` can
    /// ever apply. A second submission for a pair a pending receipt already
    /// holds is refused whatever its fee or bytes.
    ///
    /// Empty on a receipt written before the pair was recorded; such a receipt
    /// is not indexed by the pair and never produces a duplicate refusal.
    #[serde(default)]
    pub source: String,

    /// The sequence number this transaction consumes. For a fee-bump this is
    /// the INNER transaction's sequence.
    ///
    /// Meaningful only when [`Self::source`] is non-empty.
    #[serde(default)]
    pub sequence: i64,

    /// Current state of the submission.
    pub status: ReceiptStatus,

    /// Ledger sequence in which the transaction was included (if known).
    ///
    /// `None` while `Pending`; `Some(ledger)` after terminal confirmation.
    /// For `Reorged` receipts this field is `None` (the ledger was rewound);
    /// use `prior_ledger` to access the pre-reorg confirmation ledger.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ledger: Option<u32>,

    /// Ledger sequence at which `try_begin` was called (the "recorded-at" ledger).
    ///
    /// Used by retention-aware polling: if `recorded_at_ledger` is below the
    /// RPC's `oldest_ledger`, the transaction has fallen outside the retention
    /// window.
    pub recorded_at_ledger: u32,

    /// `TimeBounds.maxTime` from the envelope, in absolute unix seconds.
    ///
    /// `0` means no time bound (`Preconditions::None` or unbounded).
    ///
    /// Cited: `rs-stellar-xdr 26.0.1 curr/generated.rs:35620`
    /// (`TimeBounds { min_time: TimePoint(u64), max_time: TimePoint(u64) }`).
    ///
    /// A resubmit after `max_time` is structurally safe because the network
    /// rejects the original as `tx_too_late`.
    pub max_time: u64,

    /// Ledger sequence at which this receipt was previously `Success`, before
    /// a ledger re-org evicted it.
    ///
    /// # Dual-state contract
    ///
    /// - When `status` is `Reorged`: `prior_ledger` holds the ledger sequence
    ///   at which the transaction was previously confirmed (`Success`) before
    ///   the re-org evicted it, and `ledger` is cleared to `None`.  This lets
    ///   callers detect "it WAS confirmed in ledger N, then the chain re-orged
    ///   it away" — distinguishable from a never-confirmed failure.
    /// - All other states: `prior_ledger` is `None`.
    ///
    /// This field is additive and `skip_serializing_if = "Option::is_none"`,
    /// so older serialised receipts deserialise cleanly with `prior_ledger = None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prior_ledger: Option<u32>,

    /// Ledger at which the FIRST `NOT_FOUND` was observed during re-org
    /// reconciliation.
    ///
    /// `None` initially.  Set by `reconcile_receipt` on the first `NOT_FOUND`
    /// response for a `Success` receipt, recording the RPC `latest_ledger`
    /// at that moment.  A second `NOT_FOUND` at `latest_ledger ≥ first + 1`
    /// (at least one ledger has closed since the first miss) promotes the
    /// receipt to `Reorged`.  This 2-poll confirmation rule reduces false
    /// positives from read-replica lag.
    ///
    /// Reset to `None` when the receipt is demoted (i.e. once `Reorged` is
    /// written the field is no longer needed).
    ///
    /// This field is internal bookkeeping — `skip_serializing_if = "Option::is_none"`
    /// keeps the persisted JSON clean; absent means "no pending first-miss".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reorg_pending_at_ledger: Option<u32>,

    /// Whether `sendTransaction` has been called for this receipt.
    ///
    /// Set to `false` by `try_begin`; set to `true` by
    /// `submit_with_retention_poll` immediately before `send_transaction` is
    /// called.  `abandon_pre_submit` removes the receipt only when this is
    /// `false`, preventing abandonment of an already-submitted transaction.
    ///
    /// # Safety invariant
    ///
    /// Once `submitted` is `true`, the transaction MAY have reached the
    /// network.  Removing the receipt at that point would silently lose the
    /// crash-recovery anchor, creating a double-apply window.
    /// `abandon_pre_submit` enforces this by refusing to remove entries where
    /// `submitted == true`.
    ///
    /// # Deserialisation default
    ///
    /// Absent or unknown receipts (e.g. written by an older binary that predates
    /// this field) deserialise as `true`.  This is the conservative posture:
    /// a receipt whose submission state is unknown is treated as already-sent,
    /// making it un-abandonable.  `abandon_pre_submit` therefore refuses to
    /// remove any receipt that was not created by `try_begin` in the current
    /// process (where `submitted` is explicitly written as `false`).
    ///
    /// `false` IS written to disk when `try_begin` creates a fresh Pending
    /// entry — the `skip_serializing_if` attribute is intentionally absent so
    /// a fresh receipt reloaded after a crash keeps `submitted = false` and
    /// remains a valid abandon candidate until `mark_submitted` flips it.
    #[serde(default = "receipt_submitted_default")]
    pub submitted: bool,

    /// Approval reserved by this submission. Its presence prevents reuse even
    /// when the approval-store tombstone is still owed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_nonce: Option<String>,

    /// The approval store durably contains the terminal consumption state.
    #[serde(default)]
    pub approval_consumed: bool,

    /// Identity recovered from an authenticated spending-window reservation.
    /// Approval metadata is unknown when the original receipt is absent.
    #[serde(default)]
    pub recovered_from_reservation: bool,
}

/// Serde default for [`SubmissionReceipt::submitted`].
///
/// Returns `true` so that a receipt deserialised from a JSON row that lacks the
/// `"submitted"` field (written by an older binary) is treated as
/// already-submitted, preventing `abandon_pre_submit` from removing it.
/// This is the conservative posture for an unknown submission state.
fn receipt_submitted_default() -> bool {
    true
}

// ─────────────────────────────────────────────────────────────────────────────
// BeginOutcome
// ─────────────────────────────────────────────────────────────────────────────

/// The result of a [`ReceiptStore::try_begin`] call.
///
/// Exactly one concurrent caller is the winner for any given envelope hash;
/// all others receive [`BeginOutcome::AlreadyPresent`].
#[non_exhaustive]
#[derive(Debug)]
pub enum BeginOutcome {
    /// The caller is the winner: a fresh `Pending` receipt was inserted.
    ///
    /// The winner MUST proceed to call `sendTransaction` and then
    /// [`ReceiptStore::finalize`] with the terminal status.
    Winner,

    /// The caller is a loser (or an idempotent hit): an entry already exists.
    ///
    /// The caller MUST NOT submit. It should poll the store (or
    /// `getTransaction`) until the winner records a terminal status.
    AlreadyPresent(SubmissionReceipt),
}

// ─────────────────────────────────────────────────────────────────────────────
// BeginSubmissionOutcome
// ─────────────────────────────────────────────────────────────────────────────

/// The result of a [`ReceiptStore::begin_submission`] call.
///
/// The variants are ordered by the checks that produce them: the replay
/// identity is settled first, the envelope identity second.
///
/// Deliberately exhaustive: every caller decides whether to send on this
/// answer, so a new variant has to make each of them fail to compile rather
/// than fall into a catch-all whose disposition nobody chose.
#[derive(Debug)]
pub enum BeginSubmissionOutcome {
    /// A fresh `Pending` receipt was written and the caller may send.
    Recorded,

    /// A receipt already exists for this envelope hash. The caller MUST NOT
    /// send; the carried receipt holds the outcome recorded for it.
    AlreadyPresent(SubmissionReceipt),

    /// A pending receipt already holds this `(source, sequence)` pair under a
    /// different envelope hash. The caller MUST NOT send: at most one
    /// transaction per pair can apply, and the pending one may still be
    /// in flight. The carried receipt names the transaction to reconcile.
    DuplicateSequence(SubmissionReceipt),

    /// Another submission holds this approval nonce. The caller must reconcile
    /// that submission and must not spend the approval again.
    DuplicateApproval(SubmissionReceipt),
}

// ─────────────────────────────────────────────────────────────────────────────
// ReceiptStoreError
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced by [`ReceiptStore`] operations.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum ReceiptStoreError {
    /// The receipt directory could not be created or written.
    #[error("receipt store I/O error at '{path}': {source}")]
    Io {
        /// The file system path that triggered the error.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// The JSON serialisation or deserialisation step failed.
    #[error("receipt store JSON error at '{path}': {source}")]
    Json {
        /// The file system path involved.
        path: PathBuf,
        /// The underlying serde_json error.
        #[source]
        source: serde_json::Error,
    },

    /// The in-memory Mutex was poisoned by a previous panic.
    ///
    /// This should not occur in production; it indicates a bug (a panic while
    /// holding the lock). The store is unusable after this.
    #[error("receipt store mutex poisoned")]
    MutexPoisoned,

    /// Another process held the sidecar write lock for the whole bounded
    /// retry window.
    #[error("receipt store writer is locked by another process")]
    WriterLocked,

    /// A status transition the store refuses.
    ///
    /// The receipt's recorded outcome may not be replaced by the requested
    /// one: a receipt never returns to `Pending`, and a receipt whose outcome
    /// is recorded as unknown moves only to a definitive network answer.
    #[error("receipt status transition from '{from}' to '{to}' is refused")]
    InvalidTransition {
        /// The status the receipt currently holds.
        from: &'static str,
        /// The status the caller asked to write.
        to: &'static str,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// ReceiptStore
// ─────────────────────────────────────────────────────────────────────────────

/// Profile-local, in-memory-backed, file-persisted submission receipt store.
///
/// Cheap to clone — the inner state is `Arc`-shared.
///
/// # Thread safety
///
/// All public methods acquire a `Mutex` guard for the duration of the
/// operation, including the file write.  The lock is released before any
/// async boundary.
#[derive(Debug, Clone)]
pub struct ReceiptStore {
    state: Arc<Mutex<StoreState>>,
}

#[derive(Debug)]
struct StoreState {
    /// In-memory map from `envelope_hash` to receipt, refreshed from the file
    /// at the start of every operation.
    map: HashMap<String, SubmissionReceipt>,
    /// `tx_hash` to `envelope_hash`, derived from `map`. A pending receipt
    /// wins a transaction hash more than one receipt claims.
    by_tx_hash: HashMap<String, String>,
    /// `(source, sequence)` to `envelope_hash`, derived from `map`. Holds
    /// PENDING receipts only, and none whose `source` is empty.
    by_source_sequence: HashMap<(String, i64), String>,
    /// Path to the persisted JSON file.
    file_path: PathBuf,
    /// Path to the sidecar advisory-lock file.
    lock_path: PathBuf,
}

impl StoreState {
    /// Rebuilds both secondary indexes from `map`.
    ///
    /// Called after every read from disk and after every mutation, so an
    /// index entry can never outlive the receipt it points at.
    ///
    /// # One slot, several claimants
    ///
    /// Each index holds one envelope hash per key, and more than one receipt
    /// can claim a key. Re-signing one transaction produces the same
    /// transaction hash under a fresh envelope hash, and a settled submission
    /// leaves its receipt behind when a replacement is built at the same
    /// sequence. `map` is a `HashMap`, so which receipt a bare insert loop
    /// leaves in the slot changes from one read to the next. Two rules make
    /// the answer the same on every pass:
    ///
    /// - `by_source_sequence` indexes PENDING receipts only. A settled receipt
    ///   no longer holds its source account's sequence: either the network
    ///   applied the transaction, and the account has moved past that number,
    ///   or it did not, and a replacement at that number is what the agent is
    ///   expected to build.
    /// - `by_tx_hash` indexes every receipt, because a settled one is what
    ///   `tx status` reports on, and a pending claimant wins the slot: it is
    ///   the one reconciliation still has work to do on. Equal claimants are
    ///   ordered by envelope hash, which is unique.
    fn rebuild_indexes(&mut self) {
        let mut by_tx_hash: HashMap<String, String> = HashMap::new();
        let mut by_source_sequence: HashMap<(String, i64), String> = HashMap::new();

        let mut envelope_hashes: Vec<&String> = self.map.keys().collect();
        envelope_hashes.sort_unstable();

        for envelope_hash in envelope_hashes {
            let Some(receipt) = self.map.get(envelope_hash) else {
                continue;
            };
            if !receipt.tx_hash.is_empty() {
                let held_is_pending = by_tx_hash
                    .get(&receipt.tx_hash)
                    .and_then(|held| self.map.get(held))
                    .is_some_and(|held| held.status == ReceiptStatus::Pending);
                if !held_is_pending {
                    by_tx_hash.insert(receipt.tx_hash.clone(), envelope_hash.clone());
                }
            }
            if !receipt.source.is_empty() && receipt.status == ReceiptStatus::Pending {
                by_source_sequence.insert(
                    (receipt.source.clone(), receipt.sequence),
                    envelope_hash.clone(),
                );
            }
        }

        self.by_tx_hash = by_tx_hash;
        self.by_source_sequence = by_source_sequence;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Sidecar lock
// ─────────────────────────────────────────────────────────────────────────────

/// An exclusive advisory lock over the receipt store's sidecar lock file.
///
/// The store file itself is never locked: `File::try_lock` maps to
/// `LockFileEx` on Windows, whose exclusivity is enforced against all I/O
/// through any other handle to the same file, which would make a concurrent
/// reader fail. Locking a sidecar file keeps cross-process exclusivity
/// without placing an OS lock on the data readers touch.
struct ReceiptStoreLock {
    /// The open lock file. Closing it (on drop) releases the lock.
    _file: File,
}

impl std::fmt::Debug for ReceiptStoreLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReceiptStoreLock").finish_non_exhaustive()
    }
}

impl ReceiptStoreLock {
    /// Acquires the exclusive advisory lock, retrying a bounded number of
    /// times while another holder owns it.
    ///
    /// Only contention is retried: any other failure to open or lock the file
    /// is returned from the first attempt that produces it.
    fn acquire_with_retry(
        path: &Path,
        attempts: u32,
        backoff: Duration,
    ) -> Result<Self, ReceiptStoreError> {
        let attempts = attempts.max(1);
        let mut attempt = 0_u32;
        loop {
            attempt += 1;
            match Self::try_acquire(path) {
                Ok(lock) => return Ok(lock),
                Err(ReceiptStoreError::WriterLocked) if attempt < attempts => {
                    std::thread::sleep(backoff);
                }
                Err(e) => return Err(e),
            }
        }
    }

    fn try_acquire(path: &Path) -> Result<Self, ReceiptStoreError> {
        #[cfg(unix)]
        let file = {
            use std::os::unix::fs::OpenOptionsExt as _;
            OpenOptions::new()
                .create(true)
                .write(true)
                // Do NOT truncate: the lock file is only an advisory-lock
                // carrier; its content is irrelevant.
                .truncate(false)
                .mode(0o600)
                .open(path)
                .map_err(|e| ReceiptStoreError::Io {
                    path: path.to_path_buf(),
                    source: e,
                })?
        };
        #[cfg(not(unix))]
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(path)
            .map_err(|e| ReceiptStoreError::Io {
                path: path.to_path_buf(),
                source: e,
            })?;

        // Acquire the lock BEFORE any content check — a pre-lock check is a
        // TOCTOU race.
        file.try_lock().map_err(|e| match e {
            std::fs::TryLockError::WouldBlock => ReceiptStoreError::WriterLocked,
            std::fs::TryLockError::Error(io_err) => ReceiptStoreError::Io {
                path: path.to_path_buf(),
                source: io_err,
            },
        })?;

        Ok(Self { _file: file })
    }
}

/// Derives the sidecar lock path for a store file: the store path with
/// `.lock` appended, so it sits next to the file it protects.
fn lock_path_for(file_path: &Path) -> PathBuf {
    let mut p = file_path.to_path_buf();
    let name = p
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("receipts.json")
        .to_owned();
    p.set_file_name(format!("{name}.lock"));
    p
}

/// Reads the store file into a map. A missing file is an empty store.
fn read_map(file_path: &Path) -> Result<HashMap<String, SubmissionReceipt>, ReceiptStoreError> {
    match std::fs::read_to_string(file_path) {
        Ok(raw) => serde_json::from_str(&raw).map_err(|e| ReceiptStoreError::Json {
            path: file_path.to_path_buf(),
            source: e,
        }),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(HashMap::new()),
        Err(e) => Err(ReceiptStoreError::Io {
            path: file_path.to_path_buf(),
            source: e,
        }),
    }
}

/// A store operation in progress: the in-process guard, and the sidecar lock
/// when the operation mutates.
struct Session<'a> {
    guard: MutexGuard<'a, StoreState>,
    /// Held for the operation's duration; `None` for read-only operations,
    /// which never mutate and so need no cross-process exclusion.
    _lock: Option<ReceiptStoreLock>,
}

impl ReceiptStore {
    /// Opens (or creates) the receipt store for `profile_name` in the
    /// OS-conventional profile directory.
    ///
    /// The file is located at `<canonical_data_root>/receipts/<profile_name>.json`.
    /// If the file does not exist it is treated as an empty store.
    ///
    /// # Errors
    ///
    /// - [`ReceiptStoreError::Io`] if the receipts directory cannot be created.
    /// - [`ReceiptStoreError::Json`] if an existing file contains invalid JSON.
    pub fn open(profile_name: &str) -> Result<Self, ReceiptStoreError> {
        let dir = default_receipts_dir().map_err(|e| ReceiptStoreError::Io {
            path: PathBuf::from("<receipts-dir>"),
            source: e,
        })?;
        Self::open_at(&dir, profile_name)
    }

    /// Opens (or creates) the receipt store with an explicit directory path.
    ///
    /// The file is located at `<dir>/<profile_name>.json`.
    /// Used in tests and for dependency-injection in the idempotent submit path.
    ///
    /// # Errors
    ///
    /// - [`ReceiptStoreError::Io`] if `dir` cannot be created.
    /// - [`ReceiptStoreError::Json`] if an existing file contains invalid JSON.
    pub fn open_at(dir: &Path, profile_name: &str) -> Result<Self, ReceiptStoreError> {
        std::fs::create_dir_all(dir).map_err(|e| ReceiptStoreError::Io {
            path: dir.to_path_buf(),
            source: e,
        })?;

        let file_path = dir.join(format!("{profile_name}.json"));
        let lock_path = lock_path_for(&file_path);

        let map = read_map(&file_path)?;

        let mut state = StoreState {
            map,
            by_tx_hash: HashMap::new(),
            by_source_sequence: HashMap::new(),
            file_path,
            lock_path,
        };
        state.rebuild_indexes();

        Ok(Self {
            state: Arc::new(Mutex::new(state)),
        })
    }

    /// Returns the stored receipt for `envelope_hash`, if any.
    ///
    /// Re-reads the store file first, so a receipt another process wrote is
    /// visible.
    ///
    /// # Errors
    ///
    /// - [`ReceiptStoreError::MutexPoisoned`] if the internal lock is poisoned.
    /// - [`ReceiptStoreError::Io`] or [`ReceiptStoreError::Json`] if the store
    ///   file cannot be read.
    pub fn get(&self, envelope_hash: &str) -> Result<Option<SubmissionReceipt>, ReceiptStoreError> {
        let session = self.read_session()?;
        Ok(session.guard.map.get(envelope_hash).cloned())
    }

    /// Returns the receipt whose `tx_hash` is `tx_hash`, if any.
    ///
    /// The transaction hash is the identity an agent holds after a timeout,
    /// so this is how `stellar_transaction_status` and `tx status` reach the
    /// record. The receipt comes from the map, so its status is the current
    /// one however the index was built.
    ///
    /// # Errors
    ///
    /// - [`ReceiptStoreError::MutexPoisoned`] if the internal lock is poisoned.
    /// - [`ReceiptStoreError::Io`] or [`ReceiptStoreError::Json`] if the store
    ///   file cannot be read.
    pub fn find_by_tx_hash(
        &self,
        tx_hash: &str,
    ) -> Result<Option<SubmissionReceipt>, ReceiptStoreError> {
        let session = self.read_session()?;
        let Some(envelope_hash) = session.guard.by_tx_hash.get(tx_hash) else {
            return Ok(None);
        };
        Ok(session.guard.map.get(envelope_hash).cloned())
    }

    /// Returns the `Pending` receipt holding `(source, sequence)`, if any.
    ///
    /// A terminal receipt for the pair is not returned: its transaction can no
    /// longer be in flight, so it does not stand in the way of a fresh
    /// submission at the same sequence.
    ///
    /// # Errors
    ///
    /// - [`ReceiptStoreError::MutexPoisoned`] if the internal lock is poisoned.
    /// - [`ReceiptStoreError::Io`] or [`ReceiptStoreError::Json`] if the store
    ///   file cannot be read.
    pub fn find_pending_by_source_sequence(
        &self,
        source: &str,
        sequence: i64,
    ) -> Result<Option<SubmissionReceipt>, ReceiptStoreError> {
        let session = self.read_session()?;
        Ok(find_pending_for_pair(&session.guard, source, sequence))
    }

    /// Returns every receipt currently held, in unspecified order.
    ///
    /// Used by the operator-facing status verbs, which report on all of a
    /// profile's outstanding submissions.
    ///
    /// # Errors
    ///
    /// - [`ReceiptStoreError::MutexPoisoned`] if the internal lock is poisoned.
    /// - [`ReceiptStoreError::Io`] or [`ReceiptStoreError::Json`] if the store
    ///   file cannot be read.
    pub fn all(&self) -> Result<Vec<SubmissionReceipt>, ReceiptStoreError> {
        let session = self.read_session()?;
        Ok(session.guard.map.values().cloned().collect())
    }

    /// Atomically inserts a `Pending` receipt for `envelope_hash` or returns the
    /// existing entry.
    ///
    /// Winner/loser gate:
    ///
    /// - If no entry exists, inserts `Pending` (with `tx_hash`, `max_time`,
    ///   `recorded_at_ledger`) and returns [`BeginOutcome::Winner`].  The
    ///   caller MUST proceed to submit and then call [`Self::finalize`].
    /// - If an entry already exists (any status), returns
    ///   [`BeginOutcome::AlreadyPresent`].  The caller MUST NOT submit.
    ///
    /// The map update and file write happen under the same lock hold so that no
    /// concurrent caller can observe the entry without the file also reflecting it.
    /// The lock is not held across any I/O that could block for unbounded time.
    ///
    /// # Errors
    ///
    /// - [`ReceiptStoreError::MutexPoisoned`] if the lock is poisoned.
    /// - [`ReceiptStoreError::Io`] or [`ReceiptStoreError::Json`] on persist failure.
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use stellar_agent_core::profile::receipt::{BeginOutcome, ReceiptStore};
    ///
    /// # fn run() -> Result<(), Box<dyn std::error::Error>> {
    /// let store = ReceiptStore::open("default")?;
    /// match store.try_begin("aabb...", "ccdd...", "GSOURCE", 7, 0, 100)? {
    ///     BeginOutcome::Winner => { /* submit */ }
    ///     BeginOutcome::AlreadyPresent(_r) => { /* return cached */ }
    ///     _ => {}
    /// }
    /// # Ok(()) }
    /// ```
    pub fn try_begin(
        &self,
        envelope_hash: &str,
        tx_hash: &str,
        source: &str,
        sequence: i64,
        max_time: u64,
        recorded_at_ledger: u32,
    ) -> Result<BeginOutcome, ReceiptStoreError> {
        let mut session = self.write_session()?;

        // Atomic check-and-insert under the lock.
        if let Some(existing) = session.guard.map.get(envelope_hash) {
            return Ok(BeginOutcome::AlreadyPresent(existing.clone()));
        }

        insert_pending(
            &mut session.guard,
            envelope_hash,
            tx_hash,
            source,
            sequence,
            max_time,
            recorded_at_ledger,
            None,
        )?;

        Ok(BeginOutcome::Winner)
    }

    /// Restores an absent receipt from a verified reservation after an operator
    /// has checked `NOT_FOUND` beyond retention and acknowledged no value moved.
    /// Existing matching receipts are returned without overwriting their state.
    ///
    /// # Errors
    /// Returns a store error on read/write failure or a conflicting identity.
    pub fn recover_from_reservation(
        &self,
        envelope_hash: &str,
        tx_hash: &str,
        source: &str,
        sequence: i64,
        max_time: u64,
        recorded_at_ledger: u32,
    ) -> Result<SubmissionReceipt, ReceiptStoreError> {
        let mut session = self.write_session()?;
        if let Some(existing) = session.guard.map.get(envelope_hash) {
            if existing.tx_hash != tx_hash
                || existing.source != source
                || existing.sequence != sequence
                || existing.max_time != max_time
                || existing.recorded_at_ledger != recorded_at_ledger
            {
                return Err(ReceiptStoreError::InvalidTransition {
                    from: "conflicting identity",
                    to: "recovered",
                });
            }
            return Ok(existing.clone());
        }
        let receipt = SubmissionReceipt {
            envelope_hash: envelope_hash.to_owned(),
            tx_hash: tx_hash.to_owned(),
            source: source.to_owned(),
            sequence,
            max_time,
            recorded_at_ledger,
            status: ReceiptStatus::Ambiguous,
            ledger: None,
            prior_ledger: None,
            reorg_pending_at_ledger: None,
            submitted: true,
            approval_nonce: None,
            approval_consumed: false,
            recovered_from_reservation: true,
        };
        session
            .guard
            .map
            .insert(envelope_hash.to_owned(), receipt.clone());
        session.guard.rebuild_indexes();
        persist_locked(&mut session.guard)?;
        Ok(receipt)
    }

    /// Records a submission about to be sent, refusing a second envelope for a
    /// `(source, sequence)` pair a pending receipt already holds.
    ///
    /// The two checks run under one lock hold, in this order:
    ///
    /// 1. `(source, sequence)`: a pending receipt for the pair means a
    ///    transaction that consumes this sequence may still be in flight, and
    ///    at most one transaction per pair can ever apply. Answered with
    ///    [`BeginSubmissionOutcome::DuplicateSequence`].
    /// 2. `envelope_hash`: an existing receipt for these exact bytes is the
    ///    winner/loser gate, answered with
    ///    [`BeginSubmissionOutcome::AlreadyPresent`].
    ///
    /// The order is load-bearing. Step 2 inserts this submission's own
    /// receipt, which holds this submission's `(source, sequence)`; running it
    /// first would make step 1 find that receipt and refuse the very
    /// submission that created it.
    ///
    /// The replay identity is what the network enforces, so the refusal holds
    /// whatever the fee or the byte layout: a rebuilt envelope for the same
    /// intent picks up a fresh fee from live fee stats and hashes differently,
    /// yet still cannot apply once the pending one has.
    ///
    /// # Errors
    ///
    /// - [`ReceiptStoreError::MutexPoisoned`] if the lock is poisoned.
    /// - [`ReceiptStoreError::WriterLocked`] if another process holds the
    ///   sidecar lock for the whole retry window.
    /// - [`ReceiptStoreError::Io`] or [`ReceiptStoreError::Json`] on read or
    ///   persist failure.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub fn begin_submission(
        &self,
        envelope_hash: &str,
        tx_hash: &str,
        source: &str,
        sequence: i64,
        max_time: u64,
        recorded_at_ledger: u32,
    ) -> Result<BeginSubmissionOutcome, ReceiptStoreError> {
        self.begin_submission_with_approval(
            envelope_hash,
            tx_hash,
            source,
            sequence,
            max_time,
            recorded_at_ledger,
            None,
        )
    }

    /// Atomically reserves the submission identity and its approval nonce.
    ///
    /// The approval hold is durable before any bytes can leave. Concurrent
    /// submissions using different source sequences still share this guard.
    ///
    /// # Errors
    ///
    /// Returns a receipt-store error if the identity cannot be read or persisted.
    #[allow(
        clippy::too_many_arguments,
        reason = "the receipt identity and approval are persisted atomically"
    )]
    pub fn begin_submission_with_approval(
        &self,
        envelope_hash: &str,
        tx_hash: &str,
        source: &str,
        sequence: i64,
        max_time: u64,
        recorded_at_ledger: u32,
        approval_nonce: Option<&str>,
    ) -> Result<BeginSubmissionOutcome, ReceiptStoreError> {
        let mut session = self.write_session()?;
        if let Some(nonce) = approval_nonce
            && let Some(existing) = session
                .guard
                .map
                .values()
                .find(|r| r.approval_nonce.as_deref() == Some(nonce))
        {
            return Ok(BeginSubmissionOutcome::DuplicateApproval(existing.clone()));
        }

        if let Some(pending) = find_pending_for_pair(&session.guard, source, sequence) {
            return Ok(BeginSubmissionOutcome::DuplicateSequence(pending));
        }

        if let Some(existing) = session.guard.map.get(envelope_hash) {
            return Ok(BeginSubmissionOutcome::AlreadyPresent(existing.clone()));
        }

        insert_pending(
            &mut session.guard,
            envelope_hash,
            tx_hash,
            source,
            sequence,
            max_time,
            recorded_at_ledger,
            approval_nonce,
        )?;

        Ok(BeginSubmissionOutcome::Recorded)
    }

    /// Finds the submission that holds an approval, including an owed tombstone.
    ///
    /// # Errors
    ///
    /// Returns a receipt-store error if the current file cannot be read.
    pub fn find_by_approval_nonce(
        &self,
        nonce: &str,
    ) -> Result<Option<SubmissionReceipt>, ReceiptStoreError> {
        Ok(self
            .all()?
            .into_iter()
            .find(|r| r.approval_nonce.as_deref() == Some(nonce)))
    }

    /// Acknowledges a durably written approval tombstone.
    ///
    /// # Errors
    ///
    /// Returns a receipt-store error if the receipt is absent or cannot be persisted.
    pub fn mark_approval_consumed(&self, envelope_hash: &str) -> Result<(), ReceiptStoreError> {
        self.acknowledge_approval_consumption(envelope_hash)
    }

    /// Records a definitive send refusal and releases its approval atomically.
    ///
    /// # Errors
    ///
    /// Returns a receipt-store error if the receipt is absent, settled, or cannot be persisted.
    pub fn finalize_send_refusal(
        &self,
        envelope_hash: &str,
        code: &str,
    ) -> Result<(), ReceiptStoreError> {
        let mut session = self.write_session()?;
        let receipt = session.guard.map.get_mut(envelope_hash).ok_or(
            ReceiptStoreError::InvalidTransition {
                from: "absent",
                to: "failed",
            },
        )?;
        let status = ReceiptStatus::Failed {
            code: code.to_owned(),
        };
        check_transition(&receipt.status, &status)?;
        receipt.status = status;
        receipt.ledger = None;
        receipt.approval_nonce = None;
        receipt.approval_consumed = false;
        session.guard.rebuild_indexes();
        persist_locked(&mut session.guard)
    }

    fn acknowledge_approval_consumption(
        &self,
        envelope_hash: &str,
    ) -> Result<(), ReceiptStoreError> {
        let mut session = self.write_session()?;
        let receipt = session.guard.map.get_mut(envelope_hash).ok_or(
            ReceiptStoreError::InvalidTransition {
                from: "absent",
                to: "approval_settled",
            },
        )?;
        receipt.approval_consumed = true;
        persist_locked(&mut session.guard)
    }

    /// Updates or inserts a terminal receipt (upsert semantics).
    ///
    /// If an entry already exists for `envelope_hash`, its `status` and
    /// `ledger` fields are updated.  If no entry exists, a minimal receipt is
    /// inserted so that a winner's terminal status is never dropped when a
    /// Pending row was lost (e.g. due to a failed `try_begin` persist).
    ///
    /// The upsert is performed under the mutex and the sidecar lock, and
    /// persisted atomically (temp-file + fsync + rename) before both are
    /// released.
    ///
    /// # Transition rule
    ///
    /// A receipt never returns to `Pending`, and a receipt whose outcome is
    /// recorded as unknown (`Ambiguous`, `ClearedByOperator`) moves only to a
    /// status the network itself reported, which is `Success` or `Failed`.
    /// Only a definitive `getTransaction` answer produces one of those, so an
    /// unknown outcome is settled by reconciliation against the chain and by
    /// nothing else. A transition the rule refuses returns
    /// [`ReceiptStoreError::InvalidTransition`] and leaves the receipt as it
    /// stands; writing the status a receipt already holds is accepted and
    /// refreshes its ledger.
    ///
    /// # Errors
    ///
    /// - [`ReceiptStoreError::InvalidTransition`] if the transition is refused
    ///   by the rule above.
    /// - [`ReceiptStoreError::MutexPoisoned`] if the lock is poisoned.
    /// - [`ReceiptStoreError::WriterLocked`] if another process holds the
    ///   sidecar lock for the whole retry window.
    /// - [`ReceiptStoreError::Io`] or [`ReceiptStoreError::Json`] on persist failure.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub fn finalize(
        &self,
        envelope_hash: &str,
        status: ReceiptStatus,
        ledger: Option<u32>,
    ) -> Result<(), ReceiptStoreError> {
        let mut session = self.write_session()?;

        if let Some(existing) = session.guard.map.get(envelope_hash) {
            check_transition(&existing.status, &status)?;
        }

        // Upsert: update existing entry or insert a minimal terminal receipt.
        // Inserting is safe because terminal statuses carry no sub-fields that
        // a Pending entry would have populated (tx_hash, max_time,
        // recorded_at_ledger); the caller can always re-derive these from
        // context if needed. A missing-entry-silent-noop would silently drop
        // terminal status when a Pending row was lost after a failed persist.
        session
            .guard
            .map
            .entry(envelope_hash.to_owned())
            .and_modify(|r| {
                r.status = status.clone();
                r.ledger = ledger;
            })
            .or_insert_with(|| SubmissionReceipt {
                envelope_hash: envelope_hash.to_owned(),
                tx_hash: String::new(),
                source: String::new(),
                sequence: 0,
                status,
                ledger,
                recorded_at_ledger: 0,
                max_time: 0,
                prior_ledger: None,
                reorg_pending_at_ledger: None,
                submitted: true, // upsert on finalize: sendTransaction has already been called
                approval_nonce: None,
                approval_consumed: false,
                recovered_from_reservation: false,
            });

        session.guard.rebuild_indexes();
        persist_locked(&mut session.guard)?;
        Ok(())
    }

    /// Marks a receipt cleared by an operator and releases it from the states
    /// reconciliation cannot settle.
    ///
    /// The accepted states are the ones [`ReceiptStatus::is_operator_clearable`]
    /// names: any `Pending` receipt, and an `Ambiguous` one. A receipt the
    /// network has answered for is refused, because it needs no
    /// acknowledgement.
    ///
    /// An unsent `Pending` receipt is accepted as well as a sent one. A
    /// submission the wallet recorded and then never sent — a process killed
    /// between the two steps — holds its source account's sequence with
    /// nothing else able to free it, and "the wallet never sent it and the
    /// chain has never seen it" is the plainest case an operator can
    /// acknowledge.
    ///
    /// This method reads the receipt and nothing else, so the chain-side half
    /// of the rule belongs to the caller: `stellar-agent tx receipt clear`
    /// asks the endpoint what became of the transaction and refuses a
    /// `SUCCESS` or `FAILED` answer before it gets here, and refuses too when
    /// the endpoint cannot answer at all. That caller also evaluates
    /// [`ReceiptStatus::is_operator_clearable`] before it takes any other
    /// step, so nothing is released and no row is written for a clear this
    /// method will refuse.
    ///
    /// # Errors
    ///
    /// - [`ReceiptStoreError::InvalidTransition`] if the receipt's status is
    ///   not one the rule accepts.
    /// - [`ReceiptStoreError::MutexPoisoned`] if the lock is poisoned.
    /// - [`ReceiptStoreError::WriterLocked`] if another process holds the
    ///   sidecar lock for the whole retry window.
    /// - [`ReceiptStoreError::Io`] or [`ReceiptStoreError::Json`] on read or
    ///   persist failure.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub fn clear_by_operator(
        &self,
        envelope_hash: &str,
    ) -> Result<SubmissionReceipt, ReceiptStoreError> {
        let mut session = self.write_session()?;

        let Some(existing) = session.guard.map.get(envelope_hash) else {
            return Err(ReceiptStoreError::InvalidTransition {
                from: "absent",
                to: ReceiptStatus::ClearedByOperator.label(),
            });
        };

        if !existing.status.is_operator_clearable() {
            return Err(ReceiptStoreError::InvalidTransition {
                from: existing.status.label(),
                to: ReceiptStatus::ClearedByOperator.label(),
            });
        }

        let cleared = {
            let Some(r) = session.guard.map.get_mut(envelope_hash) else {
                return Err(ReceiptStoreError::InvalidTransition {
                    from: "absent",
                    to: ReceiptStatus::ClearedByOperator.label(),
                });
            };
            r.status = ReceiptStatus::ClearedByOperator;
            r.ledger = None;
            r.clone()
        };

        session.guard.rebuild_indexes();
        persist_locked(&mut session.guard)?;
        Ok(cleared)
    }

    /// Demotes a previously-`Success` receipt to `Reorged`, preserving the
    /// prior confirmation ledger in `prior_ledger`.
    ///
    /// Callers invoke this when `getTransaction` returns `NOT_FOUND` for a
    /// receipt that was previously recorded as `Success` AND `get_health`
    /// confirms the prior confirmation ledger is still within the live retention
    /// window (i.e. the eviction is plausibly a genuine re-org, not a
    /// retention-drop).
    ///
    /// The transition records:
    /// - `status` → `Reorged`
    /// - `ledger` → `None` (the confirmed ledger was rewound)
    /// - `prior_ledger` → the ledger from the former `Success` state
    ///
    /// # Success-only guard
    ///
    /// Only receipts with `status == Success` are demotable to `Reorged`.
    /// If the entry is missing **or** has any other status (`Pending`, `Failed`,
    /// `Ambiguous`, already `Reorged`), this method is a **clean no-op** —
    /// it returns `Ok(())` without modifying the store.  This ensures that
    /// already-terminal non-Success states cannot be corrupted by a stale
    /// reconciliation call.
    ///
    /// # Errors
    ///
    /// - [`ReceiptStoreError::MutexPoisoned`] if the lock is poisoned.
    /// - [`ReceiptStoreError::Io`] or [`ReceiptStoreError::Json`] on persist failure.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub fn finalize_reorged(&self, envelope_hash: &str) -> Result<(), ReceiptStoreError> {
        let mut session = self.write_session()?;

        // Determine whether the entry is Success and capture the prior ledger
        // before taking a mutable reference (borrow-split to allow persist_locked).
        let prior = match session.guard.map.get(envelope_hash) {
            Some(r) if r.status == ReceiptStatus::Success => r.ledger,
            // Non-Success or missing: no-op.
            _ => return Ok(()),
        };

        // Apply the demotion.
        if let Some(r) = session.guard.map.get_mut(envelope_hash) {
            r.prior_ledger = prior;
            r.status = ReceiptStatus::Reorged;
            r.ledger = None;
        }

        persist_locked(&mut session.guard)
    }

    /// Marks the receipt for `envelope_hash` as submitted (sets `submitted = true`).
    ///
    /// Called by `submit_with_retention_poll` and the fee-bump path immediately
    /// **before** `send_transaction` is called, so that crash-recovery can
    /// distinguish "Pending but never sent" (safe to abandon) from "Pending and
    /// possibly on the network" (must be polled / cannot be abandoned).
    ///
    /// If the entry does not exist or is already in a terminal state, this is a
    /// clean no-op.
    ///
    /// # Errors
    ///
    /// - [`ReceiptStoreError::MutexPoisoned`] if the lock is poisoned.
    /// - [`ReceiptStoreError::Io`] or [`ReceiptStoreError::Json`] on persist failure.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub fn mark_submitted(&self, envelope_hash: &str) -> Result<(), ReceiptStoreError> {
        let mut session = self.write_session()?;

        let should_update = matches!(
            session.guard.map.get(envelope_hash),
            Some(r) if !r.submitted
        );

        if should_update {
            if let Some(r) = session.guard.map.get_mut(envelope_hash) {
                r.submitted = true;
            }
            persist_locked(&mut session.guard)?;
        }

        Ok(())
    }

    /// Removes a `Pending` receipt that was never submitted to the network.
    ///
    /// Only receipts with `status == Pending` AND `submitted == false` are
    /// eligible for removal.  If the entry does not exist, is non-Pending, or
    /// has `submitted == true`, this is a clean no-op — the receipt is preserved.
    ///
    /// # Design invariant
    ///
    /// `submitted == false` means `send_transaction` was never called, so there
    /// is no double-apply risk: the inner transaction was never exposed to the
    /// network.  Removing the receipt allows a subsequent call for the same key
    /// to re-enter as winner and retry (e.g. after a transient signing failure).
    ///
    /// `submitted == true` means the transaction MAY have reached the network;
    /// removing the receipt would silently lose the crash-recovery anchor.
    /// This method refuses to remove such entries.
    ///
    /// # Errors
    ///
    /// - [`ReceiptStoreError::MutexPoisoned`] if the lock is poisoned.
    /// - [`ReceiptStoreError::Io`] or [`ReceiptStoreError::Json`] on persist failure.
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use stellar_agent_core::profile::receipt::{BeginOutcome, ReceiptStore};
    ///
    /// # fn run() -> Result<(), Box<dyn std::error::Error>> {
    /// let store = ReceiptStore::open("default")?;
    /// // Winner path: try_begin sets submitted=false.
    /// // If signing fails before sendTransaction, abandon the Pending entry
    /// // so a retry can be winner again.
    /// store.abandon_pre_submit("aabb...")?;
    /// # Ok(()) }
    /// ```
    pub fn abandon_pre_submit(&self, envelope_hash: &str) -> Result<(), ReceiptStoreError> {
        let mut session = self.write_session()?;

        let should_remove = matches!(
            session.guard.map.get(envelope_hash),
            Some(r) if r.status == ReceiptStatus::Pending && !r.submitted
        );

        if should_remove {
            session.guard.map.remove(envelope_hash);
            session.guard.rebuild_indexes();
            persist_locked(&mut session.guard)?;
        }

        Ok(())
    }

    /// Records the RPC `latest_ledger` at which the first `NOT_FOUND` re-org
    /// check was observed for a `Success` receipt.
    ///
    /// Sets `reorg_pending_at_ledger = Some(latest_ledger_at_first_miss)` only
    /// when the entry exists and currently has `status == Success` and
    /// `reorg_pending_at_ledger == None`.  If the entry is missing, non-Success,
    /// or already has a first-miss recorded, this is a clean no-op — idempotent.
    ///
    /// The stored value is used by `reconcile_receipt` (in `stellar-agent-network`) to require that at least
    /// one ledger has closed between the first and second `NOT_FOUND` before
    /// demoting to `Reorged`, reducing false positives from read-replica lag.
    ///
    /// # Errors
    ///
    /// - [`ReceiptStoreError::MutexPoisoned`] if the lock is poisoned.
    /// - [`ReceiptStoreError::Io`] or [`ReceiptStoreError::Json`] on persist failure.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub fn mark_reorg_pending(
        &self,
        envelope_hash: &str,
        latest_ledger_at_first_miss: u32,
    ) -> Result<(), ReceiptStoreError> {
        let mut session = self.write_session()?;

        let should_update = matches!(
            session.guard.map.get(envelope_hash),
            Some(r) if r.status == ReceiptStatus::Success && r.reorg_pending_at_ledger.is_none()
        );

        if should_update {
            if let Some(r) = session.guard.map.get_mut(envelope_hash) {
                r.reorg_pending_at_ledger = Some(latest_ledger_at_first_miss);
            }
            persist_locked(&mut session.guard)?;
        }

        Ok(())
    }

    /// Clears the `reorg_pending_at_ledger` anchor on a `Success` receipt.
    ///
    /// Called by `reconcile_receipt` when `getTransaction` returns `SUCCESS`
    /// for a receipt that had a first-miss anchor set by [`ReceiptStore::mark_reorg_pending`].
    /// Clearing the anchor resets the 2-poll confirmation window so that a
    /// future transient miss does not reuse a stale anchor and prematurely
    /// demote to `Reorged`.
    ///
    /// No-op when:
    /// - The entry does not exist.
    /// - The entry is not `Success`.
    /// - `reorg_pending_at_ledger` is already `None`.
    ///
    /// # Errors
    ///
    /// - [`ReceiptStoreError::MutexPoisoned`] if the lock is poisoned.
    /// - [`ReceiptStoreError::Io`] or [`ReceiptStoreError::Json`] on persist failure.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub fn clear_reorg_pending(&self, envelope_hash: &str) -> Result<(), ReceiptStoreError> {
        let mut session = self.write_session()?;

        let should_update = matches!(
            session.guard.map.get(envelope_hash),
            Some(r) if r.status == ReceiptStatus::Success && r.reorg_pending_at_ledger.is_some()
        );

        if should_update {
            if let Some(r) = session.guard.map.get_mut(envelope_hash) {
                r.reorg_pending_at_ledger = None;
            }
            persist_locked(&mut session.guard)?;
        }

        Ok(())
    }

    /// Returns the path to the backing JSON file (for tests and diagnostics).
    ///
    /// # Errors
    ///
    /// - [`ReceiptStoreError::MutexPoisoned`] if the lock is poisoned.
    pub fn file_path(&self) -> Result<PathBuf, ReceiptStoreError> {
        Ok(self.lock()?.file_path.clone())
    }

    /// Returns the path to the sidecar advisory-lock file (for tests and
    /// diagnostics).
    ///
    /// # Errors
    ///
    /// - [`ReceiptStoreError::MutexPoisoned`] if the internal lock is poisoned.
    pub fn lock_file_path(&self) -> Result<PathBuf, ReceiptStoreError> {
        Ok(self.lock()?.lock_path.clone())
    }

    // ── Private ──────────────────────────────────────────────────────────────

    fn lock(&self) -> Result<MutexGuard<'_, StoreState>, ReceiptStoreError> {
        self.state
            .lock()
            .map_err(|_| ReceiptStoreError::MutexPoisoned)
    }

    /// Opens a mutating operation: in-process guard, sidecar lock with bounded
    /// retry, then the file re-read so the mutation is applied to the state
    /// every process shares.
    fn write_session(&self) -> Result<Session<'_>, ReceiptStoreError> {
        let mut guard = self.lock()?;
        if let Some(parent) = guard.lock_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| ReceiptStoreError::Io {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }
        let lock = ReceiptStoreLock::acquire_with_retry(
            &guard.lock_path,
            RECEIPT_LOCK_ATTEMPTS,
            RECEIPT_LOCK_BACKOFF,
        )?;
        refresh_locked(&mut guard)?;
        Ok(Session {
            guard,
            _lock: Some(lock),
        })
    }

    /// Opens a read-only operation: in-process guard and the file re-read. No
    /// sidecar lock is taken; the file is only ever replaced by an atomic
    /// rename, so a reader observes one whole version of it.
    fn read_session(&self) -> Result<Session<'_>, ReceiptStoreError> {
        let mut guard = self.lock()?;
        refresh_locked(&mut guard)?;
        Ok(Session { guard, _lock: None })
    }
}

/// Re-reads the store file into the guarded state and rebuilds the indexes.
fn refresh_locked(guard: &mut MutexGuard<'_, StoreState>) -> Result<(), ReceiptStoreError> {
    let map = read_map(&guard.file_path)?;
    guard.map = map;
    guard.rebuild_indexes();
    Ok(())
}

/// Returns the `Pending` receipt holding `(source, sequence)`, if any.
///
/// An empty `source` matches nothing: it marks a receipt whose replay identity
/// was not recorded, and such a receipt must not stand in for another's.
fn find_pending_for_pair(
    state: &StoreState,
    source: &str,
    sequence: i64,
) -> Option<SubmissionReceipt> {
    if source.is_empty() {
        return None;
    }
    let envelope_hash = state
        .by_source_sequence
        .get(&(source.to_owned(), sequence))?;
    let receipt = state.map.get(envelope_hash)?;
    // The index holds pending receipts only; the status check restates that
    // rather than relying on it.
    (receipt.status == ReceiptStatus::Pending).then(|| receipt.clone())
}

/// Inserts a fresh `Pending` receipt, rebuilds the indexes, and persists.
///
/// Persisting under the same lock hold means no reader sees an in-memory entry
/// without the file also reflecting it.
#[allow(
    clippy::too_many_arguments,
    reason = "the receipt identity and approval are persisted atomically"
)]
fn insert_pending(
    guard: &mut MutexGuard<'_, StoreState>,
    envelope_hash: &str,
    tx_hash: &str,
    source: &str,
    sequence: i64,
    max_time: u64,
    recorded_at_ledger: u32,
    approval_nonce: Option<&str>,
) -> Result<(), ReceiptStoreError> {
    let receipt = SubmissionReceipt {
        envelope_hash: envelope_hash.to_owned(),
        tx_hash: tx_hash.to_owned(),
        source: source.to_owned(),
        sequence,
        status: ReceiptStatus::Pending,
        ledger: None,
        recorded_at_ledger,
        max_time,
        prior_ledger: None,
        reorg_pending_at_ledger: None,
        submitted: false,
        approval_nonce: approval_nonce.map(str::to_owned),
        approval_consumed: false,
        recovered_from_reservation: false,
    };

    guard.map.insert(envelope_hash.to_owned(), receipt);
    guard.rebuild_indexes();
    persist_locked(guard)
}

/// Applies the [`ReceiptStore::finalize`] transition rule.
fn check_transition(from: &ReceiptStatus, to: &ReceiptStatus) -> Result<(), ReceiptStoreError> {
    if from == to {
        return Ok(());
    }
    let allowed = if *to == ReceiptStatus::Pending {
        // A submission that has been recorded never becomes un-recorded.
        false
    } else {
        match from {
            // A receipt that has not settled yet accepts any recorded outcome.
            ReceiptStatus::Pending => true,
            // An unknown outcome is settled only by an answer from the chain.
            ReceiptStatus::Ambiguous | ReceiptStatus::ClearedByOperator => {
                to.is_definitive_outcome()
            }
            // A recorded network answer stands; a re-org demotion has its own
            // entry point, which carries the prior ledger this one would drop.
            ReceiptStatus::Success | ReceiptStatus::Failed { .. } | ReceiptStatus::Reorged => false,
        }
    };
    if allowed {
        Ok(())
    } else {
        Err(ReceiptStoreError::InvalidTransition {
            from: from.label(),
            to: to.label(),
        })
    }
}

/// Persists the current in-memory map to the backing file atomically.
///
/// Writes to a temp file in the same directory, calls `sync_all` to flush
/// kernel buffers to durable storage, then renames over the destination.
///
/// The `sync_all` call is critical for the crash-recovery invariant: the
/// Pending receipt MUST be durable before `submit_transaction_idempotent`
/// calls `sendTransaction`.  Without it, a power-loss between the write and
/// the rename can silently lose the Pending row; a fresh-process invocation
/// then has no stale-Pending guard and resubmits → double-apply window for
/// envelopes with `max_time == 0`.
///
/// Note: `profile::loader::save` uses the same temp+rename pattern but omits
/// `sync_all` because profile TOML files are not crash-recovery-critical
/// (a lost profile write is a nuisance; a lost receipt is a safety invariant
/// violation).  Consistency is intentionally asymmetric here.
///
/// Must be called with the guard already held.
fn persist_locked(guard: &mut MutexGuard<'_, StoreState>) -> Result<(), ReceiptStoreError> {
    let json = serde_json::to_string_pretty(&guard.map).map_err(|e| ReceiptStoreError::Json {
        path: guard.file_path.clone(),
        source: e,
    })?;

    let dir = guard
        .file_path
        .parent()
        .unwrap_or(std::path::Path::new("."));

    let mut tmp = tempfile::NamedTempFile::new_in(dir).map_err(|e| ReceiptStoreError::Io {
        path: dir.to_path_buf(),
        source: e,
    })?;

    use std::io::Write as _;
    tmp.write_all(json.as_bytes())
        .map_err(|e| ReceiptStoreError::Io {
            path: guard.file_path.clone(),
            source: e,
        })?;

    // Flush to durable storage before rename.  This ensures the Pending entry
    // is on-disk before sendTransaction is called, making stale-Pending
    // crash-recovery reliable (see module-level doc).
    tmp.as_file()
        .sync_all()
        .map_err(|e| ReceiptStoreError::Io {
            path: guard.file_path.clone(),
            source: e,
        })?;

    tmp.persist(&guard.file_path)
        .map_err(|e| ReceiptStoreError::Io {
            path: guard.file_path.clone(),
            source: e.error,
        })?;

    #[cfg(unix)]
    File::open(dir)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| ReceiptStoreError::Io {
            path: dir.to_path_buf(),
            source,
        })?;

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Directory helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Returns the OS-conventional receipts directory.
///
/// `<canonical_data_root>/receipts` — see
/// [`crate::profile::schema::canonical_data_root`] for the per-platform root.
///
/// # Errors
///
/// Returns an [`io::Error`] when the platform directories library cannot
/// determine the user's data directory (rare; typically means `$HOME` is unset).
pub fn default_receipts_dir() -> Result<PathBuf, io::Error> {
    crate::profile::schema::canonical_data_root()
        .map(|root| root.join("receipts"))
        .map_err(|_| {
            io::Error::other("could not determine OS-conventional data directory for stellar-agent")
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
        clippy::panic,
        reason = "test-only"
    )]

    use super::*;

    const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const TX_HASH_A: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const HASH_B: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const TX_HASH_B: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    const SOURCE_A: &str = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";
    const SOURCE_B: &str = "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL";
    const HASH_C: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    const TX_HASH_C: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    const SEQ_A: i64 = 7;
    const SEQ_B: i64 = 11;

    fn open_temp_store() -> (tempfile::TempDir, ReceiptStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = ReceiptStore::open_at(dir.path(), "test").unwrap();
        (dir, store)
    }

    /// `get` returns `None` for an unknown hash.
    #[test]
    fn get_unknown_returns_none() {
        let (_dir, store) = open_temp_store();
        assert!(store.get(HASH_A).unwrap().is_none());
    }

    /// `try_begin` on a fresh hash inserts `Pending` and returns `Winner`.
    #[test]
    fn try_begin_fresh_returns_winner() {
        let (_dir, store) = open_temp_store();
        let outcome = store
            .try_begin(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 100)
            .unwrap();
        assert!(matches!(outcome, BeginOutcome::Winner));
    }

    /// Second `try_begin` on the same hash returns `AlreadyPresent`.
    #[test]
    fn try_begin_duplicate_returns_already_present() {
        let (_dir, store) = open_temp_store();
        store
            .try_begin(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 100)
            .unwrap();
        let outcome = store
            .try_begin(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 100)
            .unwrap();
        assert!(matches!(outcome, BeginOutcome::AlreadyPresent(_)));
    }

    /// `try_begin` followed by `get` returns the `Pending` receipt.
    #[test]
    fn get_after_try_begin_returns_pending() {
        let (_dir, store) = open_temp_store();
        store
            .try_begin(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 30_000, 99)
            .unwrap();
        let receipt = store.get(HASH_A).unwrap().unwrap();
        assert_eq!(receipt.envelope_hash, HASH_A);
        assert_eq!(receipt.tx_hash, TX_HASH_A);
        assert_eq!(receipt.status, ReceiptStatus::Pending);
        assert_eq!(receipt.ledger, None);
        assert_eq!(receipt.recorded_at_ledger, 99);
        assert_eq!(receipt.max_time, 30_000);
    }

    /// `finalize` updates status to `Success` and persists.
    #[test]
    fn finalize_success_updates_status() {
        let (_dir, store) = open_temp_store();
        store
            .try_begin(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 100)
            .unwrap();
        store
            .finalize(HASH_A, ReceiptStatus::Success, Some(1234))
            .unwrap();
        let receipt = store.get(HASH_A).unwrap().unwrap();
        assert_eq!(receipt.status, ReceiptStatus::Success);
        assert_eq!(receipt.ledger, Some(1234));
    }

    /// `finalize` with `Failed { code }` stores the wire code.
    #[test]
    fn finalize_failed_stores_code() {
        let (_dir, store) = open_temp_store();
        store
            .try_begin(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 100)
            .unwrap();
        store
            .finalize(
                HASH_A,
                ReceiptStatus::Failed {
                    code: "ledger.insufficient_balance".to_owned(),
                },
                None,
            )
            .unwrap();
        let receipt = store.get(HASH_A).unwrap().unwrap();
        assert!(matches!(
            receipt.status,
            ReceiptStatus::Failed { ref code } if code == "ledger.insufficient_balance"
        ));
    }

    /// A terminal receipt (Success) is returned by `get`.
    #[test]
    fn terminal_receipt_returned_by_get() {
        let (_dir, store) = open_temp_store();
        store
            .try_begin(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 100)
            .unwrap();
        store
            .finalize(HASH_A, ReceiptStatus::Success, Some(99))
            .unwrap();
        let receipt = store.get(HASH_A).unwrap().unwrap();
        assert!(receipt.status.is_terminal());
    }

    /// After `finalize`, a second `try_begin` returns `AlreadyPresent`
    /// (idempotency: a terminal entry is not overwritten).
    #[test]
    fn try_begin_after_finalize_returns_already_present() {
        let (_dir, store) = open_temp_store();
        store
            .try_begin(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 100)
            .unwrap();
        store
            .finalize(HASH_A, ReceiptStatus::Success, Some(42))
            .unwrap();
        let outcome = store
            .try_begin(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 101)
            .unwrap();
        assert!(matches!(outcome, BeginOutcome::AlreadyPresent(_)));
    }

    /// Atomic-rename persist survives reopen: data loaded from disk on next open.
    #[test]
    fn persist_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();

        // Write a receipt in the first store instance.
        {
            let store = ReceiptStore::open_at(dir.path(), "ptest").unwrap();
            store
                .try_begin(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 50)
                .unwrap();
            store
                .finalize(HASH_A, ReceiptStatus::Success, Some(77))
                .unwrap();
        }

        // Open a new instance and verify the data was persisted.
        let store2 = ReceiptStore::open_at(dir.path(), "ptest").unwrap();
        let receipt = store2.get(HASH_A).unwrap().unwrap();
        assert_eq!(receipt.status, ReceiptStatus::Success);
        assert_eq!(receipt.ledger, Some(77));
    }

    /// Multiple different hashes are stored independently.
    #[test]
    fn multiple_hashes_independent() {
        let (_dir, store) = open_temp_store();
        store
            .try_begin(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 100)
            .unwrap();
        store
            .try_begin(HASH_B, TX_HASH_B, SOURCE_B, SEQ_B, 0, 100)
            .unwrap();
        store
            .finalize(HASH_A, ReceiptStatus::Success, Some(1))
            .unwrap();
        // HASH_B is still Pending
        let rb = store.get(HASH_B).unwrap().unwrap();
        assert_eq!(rb.status, ReceiptStatus::Pending);
        let ra = store.get(HASH_A).unwrap().unwrap();
        assert_eq!(ra.status, ReceiptStatus::Success);
    }

    /// `finalize` on an unknown hash upserts a minimal terminal receipt.
    ///
    /// Upsert semantics: even when no `Pending` entry was written first, a
    /// terminal status is never silently dropped.  A minimal receipt is inserted
    /// so that a subsequent `store.get()` can observe the terminal state.
    #[test]
    fn finalize_unknown_hash_upserts_terminal_receipt() {
        let (_dir, store) = open_temp_store();
        // No prior try_begin.
        store
            .finalize(HASH_A, ReceiptStatus::Success, Some(42))
            .unwrap();
        // Upsert: a receipt now exists.
        let receipt = store.get(HASH_A).unwrap().unwrap();
        assert_eq!(receipt.status, ReceiptStatus::Success);
        assert_eq!(receipt.ledger, Some(42));
        // Minimal receipt: tx_hash is empty, recorded_at_ledger and max_time are 0.
        assert_eq!(receipt.tx_hash, "");
        assert_eq!(receipt.recorded_at_ledger, 0);
    }

    /// `ReceiptStatus::is_terminal()` correctly classifies each variant.
    #[test]
    fn receipt_status_is_terminal_classifications() {
        assert!(!ReceiptStatus::Pending.is_terminal());
        assert!(ReceiptStatus::Success.is_terminal());
        assert!(
            ReceiptStatus::Failed {
                code: "x".to_owned()
            }
            .is_terminal()
        );
        assert!(ReceiptStatus::Ambiguous.is_terminal());
        assert!(ReceiptStatus::Reorged.is_terminal());
    }

    // ── `submitted` serde default tests ──────────────────────────────────────

    /// A JSON receipt row WITHOUT the `"submitted"` field deserialises with
    /// `submitted == true` (belt-and-braces: unknown submission state ⇒
    /// treated as already-sent ⇒ un-abandonable).
    ///
    /// Note: `ReceiptStatus` uses `#[serde(tag = "state")]` so the status field
    /// is serialised as `{"state": "pending"}` not a bare string.
    #[test]
    fn submitted_absent_in_json_deserialises_as_true() {
        let json = r#"{
            "envelope_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "tx_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "status": {"state": "pending"},
            "recorded_at_ledger": 100,
            "max_time": 0
        }"#;
        let receipt: SubmissionReceipt = serde_json::from_str(json).unwrap();
        assert!(
            receipt.submitted,
            "absent 'submitted' field must deserialise as true (un-abandonable default)"
        );
    }

    /// A JSON receipt row WITH `"submitted": false` deserialises with
    /// `submitted == false` (fresh pre-submit receipt round-trips correctly).
    #[test]
    fn submitted_explicit_false_in_json_deserialises_as_false() {
        let json = r#"{
            "envelope_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "tx_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "status": {"state": "pending"},
            "submitted": false,
            "recorded_at_ledger": 100,
            "max_time": 0
        }"#;
        let receipt: SubmissionReceipt = serde_json::from_str(json).unwrap();
        assert!(
            !receipt.submitted,
            "explicit submitted=false must round-trip as false (abandon-candidate preserved)"
        );
    }

    /// `try_begin` writes `submitted = false` to disk; a reload of that file
    /// sees `submitted == false` (the field is NOT skip_serializing_if'd).
    #[test]
    fn try_begin_persists_submitted_false_survives_reload() {
        let (dir, store) = open_temp_store();
        store
            .try_begin(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 100)
            .unwrap();

        // Reload from the same file.
        let store2 = ReceiptStore::open_at(dir.path(), "test").unwrap();
        let receipt = store2.get(HASH_A).unwrap().unwrap();
        assert!(
            !receipt.submitted,
            "submitted=false written by try_begin must survive a store reload \
             (field is not skip_serializing_if'd)"
        );
        drop(dir);
    }

    // ── mark_submitted ────────────────────────────────────────────────────────

    /// `mark_submitted` flips `submitted` to `true` on a Pending receipt.
    #[test]
    fn mark_submitted_sets_submitted_true() {
        let (_dir, store) = open_temp_store();
        store
            .try_begin(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 100)
            .unwrap();

        // Initially false after try_begin.
        let before = store.get(HASH_A).unwrap().unwrap();
        assert!(!before.submitted, "try_begin must create submitted=false");

        store.mark_submitted(HASH_A).unwrap();

        let after = store.get(HASH_A).unwrap().unwrap();
        assert!(
            after.submitted,
            "mark_submitted must flip submitted to true"
        );
        // Status remains Pending — mark_submitted does not alter status.
        assert_eq!(after.status, ReceiptStatus::Pending);
    }

    /// `mark_submitted` on an unknown hash is a clean no-op.
    #[test]
    fn mark_submitted_unknown_hash_is_noop() {
        let (_dir, store) = open_temp_store();
        // Must not error.
        store.mark_submitted(HASH_A).unwrap();
        // Still absent.
        assert!(store.get(HASH_A).unwrap().is_none());
    }

    /// `mark_submitted` on an already-submitted receipt is idempotent.
    #[test]
    fn mark_submitted_idempotent() {
        let (_dir, store) = open_temp_store();
        store
            .try_begin(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 100)
            .unwrap();
        store.mark_submitted(HASH_A).unwrap();
        // Second call must not error.
        store.mark_submitted(HASH_A).unwrap();
        let r = store.get(HASH_A).unwrap().unwrap();
        assert!(r.submitted);
    }

    /// `mark_submitted` on a terminal (Success) receipt is a no-op.
    #[test]
    fn mark_submitted_on_terminal_receipt_is_noop() {
        let (_dir, store) = open_temp_store();
        store
            .try_begin(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 100)
            .unwrap();
        store
            .finalize(HASH_A, ReceiptStatus::Success, Some(5))
            .unwrap();

        // The finalize upsert writes submitted=true for an existing entry.
        // Call mark_submitted again — should be a no-op and not error.
        store.mark_submitted(HASH_A).unwrap();
        let r = store.get(HASH_A).unwrap().unwrap();
        assert_eq!(r.status, ReceiptStatus::Success);
    }

    /// `mark_submitted` result survives a store reload.
    #[test]
    fn mark_submitted_persists_across_reload() {
        let dir = tempfile::tempdir().unwrap();
        {
            let store = ReceiptStore::open_at(dir.path(), "ms").unwrap();
            store
                .try_begin(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 1)
                .unwrap();
            store.mark_submitted(HASH_A).unwrap();
        }
        let store2 = ReceiptStore::open_at(dir.path(), "ms").unwrap();
        let r = store2.get(HASH_A).unwrap().unwrap();
        assert!(r.submitted, "mark_submitted must be persisted to disk");
    }

    // ── abandon_pre_submit ────────────────────────────────────────────────────

    /// `abandon_pre_submit` removes a Pending + submitted=false receipt.
    #[test]
    fn abandon_pre_submit_removes_pending_not_yet_submitted() {
        let (_dir, store) = open_temp_store();
        store
            .try_begin(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 100)
            .unwrap();
        // submitted is false after try_begin — eligible for abandonment.
        store.abandon_pre_submit(HASH_A).unwrap();
        // Receipt must be gone.
        assert!(store.get(HASH_A).unwrap().is_none());
    }

    /// `abandon_pre_submit` must not remove a Pending receipt that has been submitted.
    #[test]
    fn abandon_pre_submit_refuses_already_submitted() {
        let (_dir, store) = open_temp_store();
        store
            .try_begin(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 100)
            .unwrap();
        store.mark_submitted(HASH_A).unwrap();

        // Attempt to abandon — must be a no-op.
        store.abandon_pre_submit(HASH_A).unwrap();

        // Receipt must still be present with status Pending and submitted=true.
        let r = store.get(HASH_A).unwrap().unwrap();
        assert_eq!(r.status, ReceiptStatus::Pending);
        assert!(r.submitted, "receipt must not have been removed");
    }

    /// `abandon_pre_submit` on an unknown hash is a clean no-op.
    #[test]
    fn abandon_pre_submit_unknown_hash_is_noop() {
        let (_dir, store) = open_temp_store();
        store.abandon_pre_submit(HASH_A).unwrap();
        assert!(store.get(HASH_A).unwrap().is_none());
    }

    /// `abandon_pre_submit` on a terminal Success receipt is a no-op.
    #[test]
    fn abandon_pre_submit_on_terminal_receipt_is_noop() {
        let (_dir, store) = open_temp_store();
        store
            .try_begin(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 100)
            .unwrap();
        store
            .finalize(HASH_A, ReceiptStatus::Success, Some(1))
            .unwrap();

        store.abandon_pre_submit(HASH_A).unwrap();

        // Receipt must still be present.
        let r = store.get(HASH_A).unwrap().unwrap();
        assert_eq!(r.status, ReceiptStatus::Success);
    }

    /// After `abandon_pre_submit`, a new `try_begin` for the same key wins again
    /// (re-entry gate: the slot is free).
    #[test]
    fn abandon_pre_submit_allows_re_entry() {
        let (_dir, store) = open_temp_store();
        store
            .try_begin(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 100)
            .unwrap();
        store.abandon_pre_submit(HASH_A).unwrap();

        // Same envelope hash can now win again.
        let outcome = store
            .try_begin(HASH_A, TX_HASH_B, SOURCE_A, SEQ_A, 0, 101)
            .unwrap();
        assert!(
            matches!(outcome, BeginOutcome::Winner),
            "a second try_begin after abandon must win"
        );
        let r = store.get(HASH_A).unwrap().unwrap();
        // The new winner used TX_HASH_B.
        assert_eq!(r.tx_hash, TX_HASH_B);
        assert_eq!(r.recorded_at_ledger, 101);
    }

    /// `abandon_pre_submit` removal is persisted: a reopened store does not find
    /// the abandoned entry.
    #[test]
    fn abandon_pre_submit_persists_removal_across_reload() {
        let dir = tempfile::tempdir().unwrap();
        {
            let store = ReceiptStore::open_at(dir.path(), "aps").unwrap();
            store
                .try_begin(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 10)
                .unwrap();
            store.abandon_pre_submit(HASH_A).unwrap();
        }
        let store2 = ReceiptStore::open_at(dir.path(), "aps").unwrap();
        assert!(
            store2.get(HASH_A).unwrap().is_none(),
            "abandoned receipt must not reappear after reload"
        );
    }

    // ── finalize_reorged ──────────────────────────────────────────────────────

    /// `finalize_reorged` demotes a Success receipt to Reorged, captures
    /// `prior_ledger`, and clears `ledger`.
    #[test]
    fn finalize_reorged_demotes_success_to_reorged() {
        let (_dir, store) = open_temp_store();
        store
            .try_begin(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 100)
            .unwrap();
        store
            .finalize(HASH_A, ReceiptStatus::Success, Some(42))
            .unwrap();

        store.finalize_reorged(HASH_A).unwrap();

        let r = store.get(HASH_A).unwrap().unwrap();
        assert_eq!(r.status, ReceiptStatus::Reorged);
        assert_eq!(
            r.prior_ledger,
            Some(42),
            "prior_ledger must hold the pre-reorg confirmation ledger"
        );
        assert_eq!(
            r.ledger, None,
            "ledger must be cleared after demotion to Reorged"
        );
    }

    /// `finalize_reorged` on a Pending receipt is a no-op (guard: Success-only).
    #[test]
    fn finalize_reorged_on_pending_is_noop() {
        let (_dir, store) = open_temp_store();
        store
            .try_begin(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 100)
            .unwrap();

        store.finalize_reorged(HASH_A).unwrap();

        let r = store.get(HASH_A).unwrap().unwrap();
        assert_eq!(
            r.status,
            ReceiptStatus::Pending,
            "Pending must not be demoted"
        );
    }

    /// `finalize_reorged` on a Failed receipt is a no-op.
    #[test]
    fn finalize_reorged_on_failed_is_noop() {
        let (_dir, store) = open_temp_store();
        store
            .try_begin(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 100)
            .unwrap();
        store
            .finalize(
                HASH_A,
                ReceiptStatus::Failed {
                    code: "ledger.insufficient_balance".to_owned(),
                },
                None,
            )
            .unwrap();

        store.finalize_reorged(HASH_A).unwrap();

        let r = store.get(HASH_A).unwrap().unwrap();
        assert!(
            matches!(r.status, ReceiptStatus::Failed { .. }),
            "Failed must not be demoted to Reorged"
        );
    }

    /// `finalize_reorged` on an Ambiguous receipt is a no-op.
    #[test]
    fn finalize_reorged_on_ambiguous_is_noop() {
        let (_dir, store) = open_temp_store();
        store
            .try_begin(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 100)
            .unwrap();
        store
            .finalize(HASH_A, ReceiptStatus::Ambiguous, None)
            .unwrap();

        store.finalize_reorged(HASH_A).unwrap();

        let r = store.get(HASH_A).unwrap().unwrap();
        assert_eq!(
            r.status,
            ReceiptStatus::Ambiguous,
            "Ambiguous must not be demoted"
        );
    }

    /// `finalize_reorged` on a missing hash is a clean no-op.
    #[test]
    fn finalize_reorged_on_missing_hash_is_noop() {
        let (_dir, store) = open_temp_store();
        store.finalize_reorged(HASH_A).unwrap();
        assert!(store.get(HASH_A).unwrap().is_none());
    }

    /// Calling `finalize_reorged` twice on a Success receipt is idempotent on the
    /// second call (already Reorged, no-op).
    #[test]
    fn finalize_reorged_idempotent_second_call() {
        let (_dir, store) = open_temp_store();
        store
            .try_begin(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 100)
            .unwrap();
        store
            .finalize(HASH_A, ReceiptStatus::Success, Some(77))
            .unwrap();

        store.finalize_reorged(HASH_A).unwrap();
        // Second call — already Reorged, so this is a no-op.
        store.finalize_reorged(HASH_A).unwrap();

        let r = store.get(HASH_A).unwrap().unwrap();
        assert_eq!(r.status, ReceiptStatus::Reorged);
        assert_eq!(r.prior_ledger, Some(77));
    }

    /// `finalize_reorged` result survives a store reload.
    #[test]
    fn finalize_reorged_persists_across_reload() {
        let dir = tempfile::tempdir().unwrap();
        {
            let store = ReceiptStore::open_at(dir.path(), "fr").unwrap();
            store
                .try_begin(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 10)
                .unwrap();
            store
                .finalize(HASH_A, ReceiptStatus::Success, Some(55))
                .unwrap();
            store.finalize_reorged(HASH_A).unwrap();
        }
        let store2 = ReceiptStore::open_at(dir.path(), "fr").unwrap();
        let r = store2.get(HASH_A).unwrap().unwrap();
        assert_eq!(r.status, ReceiptStatus::Reorged);
        assert_eq!(r.prior_ledger, Some(55));
        assert_eq!(r.ledger, None);
    }

    // ── mark_reorg_pending / clear_reorg_pending ──────────────────────────────

    /// `mark_reorg_pending` sets `reorg_pending_at_ledger` on a Success receipt.
    #[test]
    fn mark_reorg_pending_sets_first_miss_ledger() {
        let (_dir, store) = open_temp_store();
        store
            .try_begin(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 100)
            .unwrap();
        store
            .finalize(HASH_A, ReceiptStatus::Success, Some(10))
            .unwrap();

        store.mark_reorg_pending(HASH_A, 200).unwrap();

        let r = store.get(HASH_A).unwrap().unwrap();
        assert_eq!(
            r.reorg_pending_at_ledger,
            Some(200),
            "reorg_pending_at_ledger must hold the first-miss RPC latest_ledger"
        );
        // Status is still Success — the first miss does not demote.
        assert_eq!(r.status, ReceiptStatus::Success);
    }

    /// `mark_reorg_pending` is idempotent: a second call does not overwrite an
    /// already-recorded first-miss anchor.
    #[test]
    fn mark_reorg_pending_idempotent_does_not_overwrite() {
        let (_dir, store) = open_temp_store();
        store
            .try_begin(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 100)
            .unwrap();
        store
            .finalize(HASH_A, ReceiptStatus::Success, Some(10))
            .unwrap();

        store.mark_reorg_pending(HASH_A, 200).unwrap();
        // A second call with a different ledger must not overwrite the first.
        store.mark_reorg_pending(HASH_A, 999).unwrap();

        let r = store.get(HASH_A).unwrap().unwrap();
        assert_eq!(
            r.reorg_pending_at_ledger,
            Some(200),
            "second mark_reorg_pending must not overwrite the first-miss anchor"
        );
    }

    /// `mark_reorg_pending` on a Pending receipt is a no-op.
    #[test]
    fn mark_reorg_pending_on_pending_is_noop() {
        let (_dir, store) = open_temp_store();
        store
            .try_begin(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 100)
            .unwrap();

        store.mark_reorg_pending(HASH_A, 200).unwrap();

        let r = store.get(HASH_A).unwrap().unwrap();
        assert_eq!(r.reorg_pending_at_ledger, None);
        assert_eq!(r.status, ReceiptStatus::Pending);
    }

    /// `mark_reorg_pending` on a missing hash is a no-op.
    #[test]
    fn mark_reorg_pending_missing_hash_is_noop() {
        let (_dir, store) = open_temp_store();
        store.mark_reorg_pending(HASH_A, 200).unwrap();
        assert!(store.get(HASH_A).unwrap().is_none());
    }

    /// `clear_reorg_pending` clears `reorg_pending_at_ledger` on a Success receipt.
    #[test]
    fn clear_reorg_pending_clears_first_miss_anchor() {
        let (_dir, store) = open_temp_store();
        store
            .try_begin(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 100)
            .unwrap();
        store
            .finalize(HASH_A, ReceiptStatus::Success, Some(10))
            .unwrap();
        store.mark_reorg_pending(HASH_A, 200).unwrap();

        // Simulate getTransaction returning SUCCESS again — clear the anchor.
        store.clear_reorg_pending(HASH_A).unwrap();

        let r = store.get(HASH_A).unwrap().unwrap();
        assert_eq!(
            r.reorg_pending_at_ledger, None,
            "clear_reorg_pending must reset the first-miss anchor to None"
        );
        // Status unchanged.
        assert_eq!(r.status, ReceiptStatus::Success);
    }

    /// `clear_reorg_pending` on a Success receipt with no anchor set is a no-op.
    #[test]
    fn clear_reorg_pending_no_anchor_is_noop() {
        let (_dir, store) = open_temp_store();
        store
            .try_begin(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 100)
            .unwrap();
        store
            .finalize(HASH_A, ReceiptStatus::Success, Some(10))
            .unwrap();

        // No mark_reorg_pending was called — reorg_pending_at_ledger is already None.
        store.clear_reorg_pending(HASH_A).unwrap();

        let r = store.get(HASH_A).unwrap().unwrap();
        assert_eq!(r.reorg_pending_at_ledger, None);
    }

    /// `clear_reorg_pending` on a Pending receipt is a no-op (Success-only guard).
    #[test]
    fn clear_reorg_pending_on_pending_is_noop() {
        let (_dir, store) = open_temp_store();
        store
            .try_begin(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 100)
            .unwrap();

        store.clear_reorg_pending(HASH_A).unwrap();

        let r = store.get(HASH_A).unwrap().unwrap();
        assert_eq!(r.status, ReceiptStatus::Pending);
    }

    /// `clear_reorg_pending` on a missing hash is a no-op.
    #[test]
    fn clear_reorg_pending_missing_hash_is_noop() {
        let (_dir, store) = open_temp_store();
        store.clear_reorg_pending(HASH_A).unwrap();
        assert!(store.get(HASH_A).unwrap().is_none());
    }

    /// Full 2-poll re-org detection cycle:
    /// `mark_reorg_pending` (first miss) → `finalize_reorged` (second miss confirmed).
    #[test]
    fn reorg_detection_two_poll_cycle() {
        let (_dir, store) = open_temp_store();
        store
            .try_begin(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 1_000_000, 100)
            .unwrap();
        store
            .finalize(HASH_A, ReceiptStatus::Success, Some(110))
            .unwrap();

        // Poll 1: NOT_FOUND — record first miss at RPC latest_ledger=112.
        store.mark_reorg_pending(HASH_A, 112).unwrap();
        let after_first = store.get(HASH_A).unwrap().unwrap();
        assert_eq!(after_first.reorg_pending_at_ledger, Some(112));
        assert_eq!(after_first.status, ReceiptStatus::Success); // not yet demoted

        // Poll 2: NOT_FOUND again at a later ledger — confirm re-org.
        store.finalize_reorged(HASH_A).unwrap();
        let after_second = store.get(HASH_A).unwrap().unwrap();
        assert_eq!(after_second.status, ReceiptStatus::Reorged);
        assert_eq!(after_second.prior_ledger, Some(110));
        assert_eq!(after_second.ledger, None);
    }

    // ── file_path ─────────────────────────────────────────────────────────────

    /// `file_path` returns `<dir>/<profile_name>.json`.
    #[test]
    fn file_path_returns_correct_path() {
        let dir = tempfile::tempdir().unwrap();
        let store = ReceiptStore::open_at(dir.path(), "myprofile").unwrap();
        let fp = store.file_path().unwrap();
        assert_eq!(fp, dir.path().join("myprofile.json"));
    }

    // ── Clone / Arc-sharing ───────────────────────────────────────────────────

    /// Cloning a `ReceiptStore` shares the same underlying state.
    #[test]
    fn clone_shares_state() {
        let (_dir, store) = open_temp_store();
        let store2 = store.clone();

        store
            .try_begin(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 50)
            .unwrap();

        // The clone must see the entry written via the original.
        let r = store2.get(HASH_A).unwrap().unwrap();
        assert_eq!(r.status, ReceiptStatus::Pending);
    }

    // ── JSON round-trip of full receipt ───────────────────────────────────────

    /// A `SubmissionReceipt` with all optional fields set round-trips through
    /// JSON correctly, including `prior_ledger` and `reorg_pending_at_ledger`.
    #[test]
    fn submission_receipt_full_json_round_trip() {
        let original = SubmissionReceipt {
            envelope_hash: HASH_A.to_owned(),
            tx_hash: TX_HASH_A.to_owned(),
            source: SOURCE_A.to_owned(),
            sequence: SEQ_A,
            status: ReceiptStatus::Reorged,
            ledger: None,
            recorded_at_ledger: 1234,
            max_time: 9_999_999,
            prior_ledger: Some(1200),
            reorg_pending_at_ledger: Some(1210),
            submitted: true,
            approval_nonce: None,
            approval_consumed: false,
            recovered_from_reservation: false,
        };

        let json = serde_json::to_string(&original).unwrap();
        let decoded: SubmissionReceipt = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.envelope_hash, HASH_A);
        assert_eq!(decoded.tx_hash, TX_HASH_A);
        assert_eq!(decoded.status, ReceiptStatus::Reorged);
        assert_eq!(decoded.ledger, None);
        assert_eq!(decoded.recorded_at_ledger, 1234);
        assert_eq!(decoded.max_time, 9_999_999);
        assert_eq!(decoded.source, SOURCE_A);
        assert_eq!(decoded.sequence, SEQ_A);
        assert_eq!(decoded.prior_ledger, Some(1200));
        assert_eq!(decoded.reorg_pending_at_ledger, Some(1210));
        assert!(decoded.submitted);
    }

    /// A `SubmissionReceipt` with `ledger = None`, `prior_ledger = None`, and
    /// `reorg_pending_at_ledger = None` omits those fields in serialised JSON
    /// (skip_serializing_if = "Option::is_none").
    #[test]
    fn submission_receipt_none_fields_omitted_from_json() {
        let r = SubmissionReceipt {
            envelope_hash: HASH_A.to_owned(),
            tx_hash: TX_HASH_A.to_owned(),
            source: SOURCE_A.to_owned(),
            sequence: SEQ_A,
            status: ReceiptStatus::Pending,
            ledger: None,
            recorded_at_ledger: 1,
            max_time: 0,
            prior_ledger: None,
            reorg_pending_at_ledger: None,
            submitted: false,
            approval_nonce: None,
            approval_consumed: false,
            recovered_from_reservation: false,
        };

        let json = serde_json::to_string(&r).unwrap();
        assert!(
            !json.contains("\"ledger\""),
            "ledger must be absent from JSON when None; got: {json}"
        );
        assert!(
            !json.contains("\"prior_ledger\""),
            "prior_ledger must be absent from JSON when None; got: {json}"
        );
        assert!(
            !json.contains("\"reorg_pending_at_ledger\""),
            "reorg_pending_at_ledger must be absent from JSON when None; got: {json}"
        );
    }

    // ── ReceiptStatus JSON tag shapes ─────────────────────────────────────────

    /// `ReceiptStatus` variants serialise with the correct `"state"` tag shapes.
    #[test]
    fn receipt_status_serde_tag_shapes() {
        // Pending
        let json = serde_json::to_string(&ReceiptStatus::Pending).unwrap();
        assert_eq!(json, r#"{"state":"pending"}"#);

        // Success
        let json = serde_json::to_string(&ReceiptStatus::Success).unwrap();
        assert_eq!(json, r#"{"state":"success"}"#);

        // Failed
        let json = serde_json::to_string(&ReceiptStatus::Failed {
            code: "ledger.op_failed".to_owned(),
        })
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["state"], "failed");
        assert_eq!(v["code"], "ledger.op_failed");

        // Ambiguous
        let json = serde_json::to_string(&ReceiptStatus::Ambiguous).unwrap();
        assert_eq!(json, r#"{"state":"ambiguous"}"#);

        // Reorged
        let json = serde_json::to_string(&ReceiptStatus::Reorged).unwrap();
        assert_eq!(json, r#"{"state":"reorged"}"#);
    }

    // ── Fee-bump key format ───────────────────────────────────────────────────

    /// A fee-bump envelope hash key (`"feebump-inner:" prefix) is stored and
    /// retrieved like any other key — the store is key-agnostic.
    #[test]
    fn fee_bump_key_format_stored_and_retrieved() {
        let (_dir, store) = open_temp_store();
        let inner_tx_hex = TX_HASH_A; // 64 hex chars
        let feebump_key = format!("feebump-inner:{inner_tx_hex}");

        let outcome = store
            .try_begin(&feebump_key, inner_tx_hex, SOURCE_A, SEQ_A, 0, 300)
            .unwrap();
        assert!(matches!(outcome, BeginOutcome::Winner));

        let r = store.get(&feebump_key).unwrap().unwrap();
        assert_eq!(r.envelope_hash, feebump_key);
        assert_eq!(r.tx_hash, inner_tx_hex);
        assert_eq!(r.status, ReceiptStatus::Pending);
    }

    // ── finalize upsert — submitted=true in minimal receipt ───────────────────

    /// A finalized-without-prior-begin minimal receipt has `submitted = true`
    /// (conservative posture: an unknown submission state is treated as
    /// already-sent and therefore un-abandonable).
    #[test]
    fn finalize_upsert_minimal_receipt_has_submitted_true() {
        let (_dir, store) = open_temp_store();
        store
            .finalize(HASH_B, ReceiptStatus::Success, Some(7))
            .unwrap();
        let r = store.get(HASH_B).unwrap().unwrap();
        assert!(
            r.submitted,
            "minimal receipt created by finalize upsert must have submitted=true"
        );
    }

    // ── Ambiguous status is terminal ──────────────────────────────────────────

    /// `finalize` with `Ambiguous` status stores the variant and `is_terminal` is true.
    #[test]
    fn finalize_ambiguous_stores_and_is_terminal() {
        let (_dir, store) = open_temp_store();
        store
            .try_begin(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 100)
            .unwrap();
        store
            .finalize(HASH_A, ReceiptStatus::Ambiguous, None)
            .unwrap();
        let r = store.get(HASH_A).unwrap().unwrap();
        assert_eq!(r.status, ReceiptStatus::Ambiguous);
        assert!(r.status.is_terminal());
        assert_eq!(r.ledger, None);
    }

    // ── open_at creates directory if absent ───────────────────────────────────

    /// `open_at` creates the receipts directory when it does not yet exist.
    #[test]
    fn open_at_creates_directory() {
        let base = tempfile::tempdir().unwrap();
        let new_dir = base.path().join("deep").join("path");
        // Directory must not exist yet.
        assert!(!new_dir.exists());
        ReceiptStore::open_at(&new_dir, "x").unwrap();
        assert!(new_dir.exists(), "open_at must create the directory");
    }

    // ── Multiple distinct profiles in the same directory ──────────────────────

    /// Two profiles in the same directory are stored in independent files and do
    /// not interfere with each other.
    #[test]
    fn two_profiles_same_dir_are_independent() {
        let dir = tempfile::tempdir().unwrap();
        let s1 = ReceiptStore::open_at(dir.path(), "profile-a").unwrap();
        let s2 = ReceiptStore::open_at(dir.path(), "profile-b").unwrap();

        s1.try_begin(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 1)
            .unwrap();
        s2.try_begin(HASH_B, TX_HASH_B, SOURCE_B, SEQ_B, 0, 2)
            .unwrap();

        // s1 has only HASH_A.
        assert!(s1.get(HASH_A).unwrap().is_some());
        assert!(s1.get(HASH_B).unwrap().is_none());

        // s2 has only HASH_B.
        assert!(s2.get(HASH_B).unwrap().is_some());
        assert!(s2.get(HASH_A).unwrap().is_none());

        // File names are distinct.
        assert_ne!(s1.file_path().unwrap(), s2.file_path().unwrap());
    }

    // ── secondary indexes ────────────────────────────────────────────────

    /// A receipt is found by the transaction hash it carries, even though the
    /// store is keyed on the envelope hash.
    #[test]
    fn tx_hash_lookup_finds_a_receipt_stored_under_its_envelope_hash() {
        let (_dir, store) = open_temp_store();
        store
            .try_begin(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 100)
            .unwrap();

        let found = store
            .find_by_tx_hash(TX_HASH_A)
            .unwrap()
            .expect("the transaction hash must reach the receipt");
        assert_eq!(found.envelope_hash, HASH_A);
        assert!(
            store.find_by_tx_hash(TX_HASH_B).unwrap().is_none(),
            "a hash no receipt carries finds nothing"
        );
    }

    /// The lookup reports the receipt's current status, so a settled receipt
    /// is never reported as still pending.
    #[test]
    fn tx_hash_lookup_reports_the_settled_status() {
        let (_dir, store) = open_temp_store();
        store
            .try_begin(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 100)
            .unwrap();
        store
            .finalize(HASH_A, ReceiptStatus::Success, Some(42))
            .unwrap();

        let found = store.find_by_tx_hash(TX_HASH_A).unwrap().unwrap();
        assert_eq!(
            found.status,
            ReceiptStatus::Success,
            "the lookup resolves through the map, so it cannot report a stale status"
        );
        assert_eq!(found.ledger, Some(42));
    }

    /// The `(source, sequence)` pair finds a pending receipt whatever envelope
    /// hash it is stored under: the pair is the identity the network enforces.
    #[test]
    fn source_sequence_lookup_finds_a_pending_receipt_under_another_envelope_hash() {
        let (_dir, store) = open_temp_store();
        store
            .try_begin(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 100)
            .unwrap();

        let found = store
            .find_pending_by_source_sequence(SOURCE_A, SEQ_A)
            .unwrap()
            .expect("the replay identity must reach the receipt");
        assert_eq!(found.envelope_hash, HASH_A);
        assert!(
            store
                .find_pending_by_source_sequence(SOURCE_B, SEQ_A)
                .unwrap()
                .is_none(),
            "another account's sequence is a different replay identity"
        );
        assert!(
            store
                .find_pending_by_source_sequence(SOURCE_A, SEQ_B)
                .unwrap()
                .is_none(),
            "another sequence on the same account is a different replay identity"
        );
    }

    /// A settled receipt does not hold its `(source, sequence)` pair: its
    /// transaction can no longer be in flight.
    #[test]
    fn a_settled_receipt_stops_holding_its_replay_identity() {
        let (_dir, store) = open_temp_store();
        store
            .try_begin(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 100)
            .unwrap();
        store
            .finalize(
                HASH_A,
                ReceiptStatus::Failed {
                    code: "ledger.op_failed".to_owned(),
                },
                None,
            )
            .unwrap();

        assert!(
            store
                .find_pending_by_source_sequence(SOURCE_A, SEQ_A)
                .unwrap()
                .is_none(),
            "a settled receipt does not stand in the way of a fresh submission"
        );
    }

    /// A receipt with no recorded replay identity matches nothing, so it never
    /// stands in for another submission's.
    #[test]
    fn a_receipt_without_a_source_holds_no_replay_identity() {
        let (_dir, store) = open_temp_store();
        store.try_begin(HASH_A, TX_HASH_A, "", 0, 0, 100).unwrap();
        assert!(
            store
                .find_pending_by_source_sequence("", 0)
                .unwrap()
                .is_none(),
            "an empty source matches nothing"
        );
    }

    // ── begin_submission ─────────────────────────────────────────────────

    /// A first submission with an empty store is recorded and may be sent.
    ///
    /// The ordering is what makes this true: the replay-identity check runs
    /// before the insert, so it cannot find the receipt the insert is about to
    /// write.
    #[test]
    fn a_first_submission_is_recorded() {
        let (_dir, store) = open_temp_store();
        let outcome = store
            .begin_submission(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 100)
            .unwrap();
        assert!(
            matches!(outcome, BeginSubmissionOutcome::Recorded),
            "a first submission must be recorded, not refused; got {outcome:?}"
        );
        let receipt = store.get(HASH_A).unwrap().unwrap();
        assert_eq!(receipt.status, ReceiptStatus::Pending);
        assert!(!receipt.submitted, "nothing has been sent yet");
    }

    /// A second submission for a `(source, sequence)` a pending receipt holds
    /// is refused, whatever bytes it carries.
    #[test]
    fn a_second_submission_at_the_same_sequence_is_refused() {
        let (_dir, store) = open_temp_store();
        store
            .begin_submission(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 100)
            .unwrap();

        let outcome = store
            .begin_submission(HASH_B, TX_HASH_B, SOURCE_A, SEQ_A, 0, 100)
            .unwrap();
        match outcome {
            BeginSubmissionOutcome::DuplicateSequence(existing) => {
                assert_eq!(
                    existing.tx_hash, TX_HASH_A,
                    "the refusal names the transaction to reconcile"
                );
            }
            other => {
                panic!("a second submission at the same sequence must be refused; got {other:?}")
            }
        }
        assert!(
            store.get(HASH_B).unwrap().is_none(),
            "a refused submission writes no receipt"
        );
    }

    /// A settled receipt does not block a fresh submission at the same
    /// sequence: its transaction can no longer apply.
    #[test]
    fn a_settled_receipt_does_not_block_the_same_sequence() {
        let (_dir, store) = open_temp_store();
        store
            .begin_submission(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 100)
            .unwrap();
        store
            .finalize(
                HASH_A,
                ReceiptStatus::Failed {
                    code: "submission.tx_malformed".to_owned(),
                },
                None,
            )
            .unwrap();

        let outcome = store
            .begin_submission(HASH_B, TX_HASH_B, SOURCE_A, SEQ_A, 0, 100)
            .unwrap();
        assert!(
            matches!(outcome, BeginSubmissionOutcome::Recorded),
            "a refused send leaves the sequence free for a fresh attempt; got {outcome:?}"
        );
    }

    /// The same envelope twice is the winner/loser gate, reported separately
    /// from the replay-identity refusal.
    #[test]
    fn the_same_envelope_twice_reports_already_present() {
        let (_dir, store) = open_temp_store();
        store
            .begin_submission(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 100)
            .unwrap();
        store
            .finalize(HASH_A, ReceiptStatus::Success, Some(9))
            .unwrap();

        let outcome = store
            .begin_submission(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 100)
            .unwrap();
        match outcome {
            BeginSubmissionOutcome::AlreadyPresent(existing) => {
                assert_eq!(existing.status, ReceiptStatus::Success);
            }
            other => panic!("the same envelope must report AlreadyPresent; got {other:?}"),
        }
    }

    // ── transition rule ──────────────────────────────────────────────────

    /// A definitive answer from the chain settles an unknown outcome.
    #[test]
    fn a_definitive_answer_settles_an_ambiguous_receipt() {
        let (_dir, store) = open_temp_store();
        store
            .try_begin(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 100)
            .unwrap();
        store.mark_submitted(HASH_A).unwrap();
        store
            .finalize(HASH_A, ReceiptStatus::Ambiguous, None)
            .unwrap();

        store
            .finalize(HASH_A, ReceiptStatus::Success, Some(77))
            .unwrap();
        let receipt = store.get(HASH_A).unwrap().unwrap();
        assert_eq!(receipt.status, ReceiptStatus::Success);
        assert_eq!(receipt.ledger, Some(77));
    }

    /// An unknown outcome never returns to pending: the submission has been
    /// recorded and cannot become un-recorded.
    #[test]
    fn an_ambiguous_receipt_never_returns_to_pending() {
        let (_dir, store) = open_temp_store();
        store
            .try_begin(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 100)
            .unwrap();
        store
            .finalize(HASH_A, ReceiptStatus::Ambiguous, None)
            .unwrap();

        let err = store
            .finalize(HASH_A, ReceiptStatus::Pending, None)
            .expect_err("an ambiguous receipt must not return to pending");
        assert!(
            matches!(
                err,
                ReceiptStoreError::InvalidTransition {
                    from: "ambiguous",
                    to: "pending"
                }
            ),
            "the refusal must name both states; got {err:?}"
        );
        assert_eq!(
            store.get(HASH_A).unwrap().unwrap().status,
            ReceiptStatus::Ambiguous,
            "a refused transition leaves the receipt as it stands"
        );
    }

    /// A recorded network answer stands: it is not replaced by another.
    #[test]
    fn a_recorded_network_answer_is_not_replaced() {
        let (_dir, store) = open_temp_store();
        store
            .try_begin(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 100)
            .unwrap();
        store
            .finalize(HASH_A, ReceiptStatus::Success, Some(5))
            .unwrap();

        let err = store
            .finalize(
                HASH_A,
                ReceiptStatus::Failed {
                    code: "ledger.op_failed".to_owned(),
                },
                None,
            )
            .expect_err("a confirmed receipt must not be overwritten");
        assert!(matches!(
            err,
            ReceiptStoreError::InvalidTransition {
                from: "success",
                to: "failed"
            }
        ));
    }

    // ── operator clear ───────────────────────────────────────────────────

    /// A submitted pending receipt is clearable: the endpoint cannot account
    /// for its transaction.
    #[test]
    fn clear_accepts_a_submitted_pending_receipt() {
        let (_dir, store) = open_temp_store();
        store
            .try_begin(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 100)
            .unwrap();
        store.mark_submitted(HASH_A).unwrap();

        let cleared = store.clear_by_operator(HASH_A).unwrap();
        assert_eq!(cleared.status, ReceiptStatus::ClearedByOperator);
        assert_eq!(cleared.tx_hash, TX_HASH_A, "the record keeps its identity");
        assert!(
            store.get(HASH_A).unwrap().unwrap().status.is_terminal(),
            "a cleared receipt is terminal"
        );
    }

    /// An ambiguous receipt is clearable: reconciliation has already reported
    /// that the endpoint cannot answer.
    #[test]
    fn clear_accepts_an_ambiguous_receipt() {
        let (_dir, store) = open_temp_store();
        store
            .try_begin(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 100)
            .unwrap();
        store.mark_submitted(HASH_A).unwrap();
        store
            .finalize(HASH_A, ReceiptStatus::Ambiguous, None)
            .unwrap();

        let cleared = store.clear_by_operator(HASH_A).unwrap();
        assert_eq!(cleared.status, ReceiptStatus::ClearedByOperator);
    }

    /// A receipt the chain has answered for needs no acknowledgement.
    #[test]
    fn clear_refuses_a_receipt_the_chain_answered_for() {
        let (_dir, store) = open_temp_store();
        store
            .try_begin(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 100)
            .unwrap();
        store
            .finalize(HASH_A, ReceiptStatus::Success, Some(3))
            .unwrap();

        let err = store
            .clear_by_operator(HASH_A)
            .expect_err("a confirmed submission is not cleared by an operator");
        assert!(matches!(
            err,
            ReceiptStoreError::InvalidTransition {
                from: "success",
                ..
            }
        ));
    }

    /// A receipt for a submission that was never sent is clearable, and the
    /// pair it holds is freed.
    ///
    /// A process killed between the record and the send leaves exactly this
    /// shape. It holds its source account's sequence, and the account's
    /// sequence never advances because nothing applied, so every rebuild at
    /// that number is refused. The operator verb establishes what the chain
    /// says before it gets here; "never sent and never seen" is the plainest
    /// case there is.
    #[test]
    fn clear_accepts_a_receipt_that_was_never_sent() {
        let (_dir, store) = open_temp_store();
        store
            .begin_submission(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 100)
            .unwrap();
        assert!(
            !store.get(HASH_A).unwrap().unwrap().submitted,
            "the fixture is an unsent receipt"
        );

        let cleared = store.clear_by_operator(HASH_A).unwrap();
        assert_eq!(cleared.status, ReceiptStatus::ClearedByOperator);

        let outcome = store
            .begin_submission(HASH_B, TX_HASH_B, SOURCE_A, SEQ_A, 0, 100)
            .unwrap();
        assert!(
            matches!(outcome, BeginSubmissionOutcome::Recorded),
            "clearing frees the pair the unsent receipt held; got {outcome:?}"
        );
    }

    /// A cleared receipt keeps its idempotency anchor: the same bytes are
    /// still recognised.
    #[test]
    fn a_cleared_receipt_still_answers_for_its_envelope() {
        let (_dir, store) = open_temp_store();
        store
            .try_begin(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 100)
            .unwrap();
        store.mark_submitted(HASH_A).unwrap();
        store.clear_by_operator(HASH_A).unwrap();

        let outcome = store
            .try_begin(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 100)
            .unwrap();
        assert!(
            matches!(outcome, BeginOutcome::AlreadyPresent(_)),
            "the cleared receipt is marked, not removed; got {outcome:?}"
        );
    }

    /// A cleared receipt stops holding its replay identity, so a fresh
    /// submission at the same sequence proceeds.
    #[test]
    fn a_cleared_receipt_frees_its_sequence() {
        let (_dir, store) = open_temp_store();
        store
            .begin_submission(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 100)
            .unwrap();
        store.mark_submitted(HASH_A).unwrap();
        store.clear_by_operator(HASH_A).unwrap();

        let outcome = store
            .begin_submission(HASH_B, TX_HASH_B, SOURCE_A, SEQ_A, 0, 100)
            .unwrap();
        assert!(
            matches!(outcome, BeginSubmissionOutcome::Recorded),
            "clearing is what frees the sequence for a fresh attempt; got {outcome:?}"
        );
    }

    // ── cross-process lock ───────────────────────────────────────────────

    /// A mutating operation refuses while another holder owns the sidecar
    /// lock, after the bounded retry is exhausted.
    ///
    /// The holder takes the lock through its own descriptor, which is what a
    /// second process does: an OS advisory lock is held per open file, not per
    /// process, so the contention this produces is the same one.
    #[test]
    fn a_held_sidecar_lock_refuses_a_write_after_the_bounded_retry() {
        let (_dir, store) = open_temp_store();
        // A write first, so the lock file exists and the store is initialised.
        store
            .try_begin(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 100)
            .unwrap();

        let lock_path = store.lock_file_path().unwrap();
        let holder = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .unwrap();
        holder.try_lock().expect("the holder must take the lock");

        let err = store
            .try_begin(HASH_B, TX_HASH_B, SOURCE_B, SEQ_B, 0, 100)
            .expect_err("a held lock must refuse the write");
        assert!(
            matches!(err, ReceiptStoreError::WriterLocked),
            "an exhausted retry surfaces as WriterLocked; got {err:?}"
        );

        drop(holder);
        store
            .try_begin(HASH_B, TX_HASH_B, SOURCE_B, SEQ_B, 0, 100)
            .expect("the write succeeds once the holder releases");
    }

    /// A read sees what another writer has already committed to the file.
    #[test]
    fn a_read_sees_another_writers_committed_receipt() {
        let dir = tempfile::tempdir().unwrap();
        let writer = ReceiptStore::open_at(dir.path(), "shared").unwrap();
        let reader = ReceiptStore::open_at(dir.path(), "shared").unwrap();

        assert!(reader.get(HASH_A).unwrap().is_none());
        writer
            .try_begin(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 100)
            .unwrap();

        let seen = reader
            .get(HASH_A)
            .unwrap()
            .expect("a reader must see a receipt another holder wrote");
        assert_eq!(seen.tx_hash, TX_HASH_A);
    }

    /// A write applies to the state the file holds, not to a stale in-memory
    /// copy: a receipt another holder wrote is not lost.
    #[test]
    fn a_write_does_not_discard_another_holders_receipt() {
        let dir = tempfile::tempdir().unwrap();
        let first = ReceiptStore::open_at(dir.path(), "shared").unwrap();
        let second = ReceiptStore::open_at(dir.path(), "shared").unwrap();

        first
            .try_begin(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 100)
            .unwrap();
        second
            .try_begin(HASH_B, TX_HASH_B, SOURCE_B, SEQ_B, 0, 100)
            .unwrap();

        assert!(
            first.get(HASH_B).unwrap().is_some() && first.get(HASH_A).unwrap().is_some(),
            "both receipts survive: each write re-reads the file under the lock"
        );
    }

    /// `ClearedByOperator` is terminal, alongside the other settled states.
    #[test]
    fn cleared_by_operator_is_terminal() {
        assert!(ReceiptStatus::ClearedByOperator.is_terminal());
        assert!(!ReceiptStatus::ClearedByOperator.is_definitive_outcome());
        assert_eq!(
            ReceiptStatus::ClearedByOperator.label(),
            "cleared_by_operator"
        );
    }

    /// The submitted flag survives the send marker, which is what makes a
    /// timed-out submission un-abandonable.
    #[test]
    fn a_timed_out_submission_stays_pending_and_submitted() {
        let (_dir, store) = open_temp_store();
        store
            .try_begin(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 100)
            .unwrap();
        store.mark_submitted(HASH_A).unwrap();

        // A timeout settles nothing, so nothing is written.
        let receipt = store.get(HASH_A).unwrap().unwrap();
        assert_eq!(receipt.status, ReceiptStatus::Pending);
        assert!(receipt.submitted);

        store.abandon_pre_submit(HASH_A).unwrap();
        assert!(
            store.get(HASH_A).unwrap().is_some(),
            "a submitted receipt is never abandoned"
        );
    }

    // ── index determinism ────────────────────────────────────────────────

    /// A third envelope at a pair one pending receipt holds is refused on
    /// every read, whichever envelope hash the settled receipt carries.
    ///
    /// The index holds one envelope hash per pair and the store's map is a
    /// `HashMap`, so a settled receipt sharing the pair would otherwise win
    /// the slot on some reads and not others, and the refusal would turn on
    /// iteration order. Both hash orderings are exercised: a rule that only
    /// happened to prefer the lower hash would pass one and fail the other.
    /// The store is re-opened on every iteration so each answer comes from a
    /// fresh index build.
    #[test]
    fn a_pair_a_pending_receipt_holds_is_refused_on_every_read() {
        for (settled_hash, settled_tx, pending_hash, pending_tx) in [
            (HASH_A, TX_HASH_A, HASH_B, TX_HASH_B),
            (HASH_B, TX_HASH_B, HASH_A, TX_HASH_A),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let store = ReceiptStore::open_at(dir.path(), "test").unwrap();

            // The state the recovery flows produce: a settled receipt and a
            // pending one on one (source, sequence).
            store
                .begin_submission(settled_hash, settled_tx, SOURCE_A, SEQ_A, 0, 100)
                .unwrap();
            store
                .finalize(
                    settled_hash,
                    ReceiptStatus::Failed {
                        code: "x".to_owned(),
                    },
                    None,
                )
                .unwrap();
            store
                .begin_submission(pending_hash, pending_tx, SOURCE_A, SEQ_A, 0, 100)
                .unwrap();
            store.mark_submitted(pending_hash).unwrap();

            for iteration in 0..200 {
                let reopened = ReceiptStore::open_at(dir.path(), "test").unwrap();
                let found = reopened
                    .find_pending_by_source_sequence(SOURCE_A, SEQ_A)
                    .unwrap();
                assert_eq!(
                    found.as_ref().map(|r| r.envelope_hash.as_str()),
                    Some(pending_hash),
                    "the pending receipt answers for the pair on read {iteration} \
                     (settled {settled_hash}, pending {pending_hash})"
                );
                let outcome = reopened
                    .begin_submission(HASH_C, TX_HASH_C, SOURCE_A, SEQ_A, 0, 100)
                    .unwrap();
                assert!(
                    matches!(outcome, BeginSubmissionOutcome::DuplicateSequence(_)),
                    "read {iteration} admitted a third envelope at a held pair \
                     (settled {settled_hash}, pending {pending_hash}): {outcome:?}"
                );
            }
        }
    }

    /// Settling the pending receipt frees the pair on every read.
    #[test]
    fn a_pair_frees_on_every_read_once_its_pending_receipt_settles() {
        let dir = tempfile::tempdir().unwrap();
        let store = ReceiptStore::open_at(dir.path(), "test").unwrap();

        store
            .begin_submission(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 0, 100)
            .unwrap();
        store
            .finalize(
                HASH_A,
                ReceiptStatus::Failed {
                    code: "x".to_owned(),
                },
                None,
            )
            .unwrap();
        store
            .begin_submission(HASH_B, TX_HASH_B, SOURCE_A, SEQ_A, 0, 100)
            .unwrap();
        store.mark_submitted(HASH_B).unwrap();
        store
            .finalize(HASH_B, ReceiptStatus::Success, Some(4))
            .unwrap();

        for iteration in 0..200 {
            let reopened = ReceiptStore::open_at(dir.path(), "test").unwrap();
            assert!(
                reopened
                    .find_pending_by_source_sequence(SOURCE_A, SEQ_A)
                    .unwrap()
                    .is_none(),
                "no receipt holds the pair on read {iteration}"
            );
        }
        let reopened = ReceiptStore::open_at(dir.path(), "test").unwrap();
        let outcome = reopened
            .begin_submission(HASH_C, TX_HASH_C, SOURCE_A, SEQ_A, 0, 100)
            .unwrap();
        assert!(
            matches!(outcome, BeginSubmissionOutcome::Recorded),
            "a settled pair admits a fresh submission: {outcome:?}"
        );
    }

    /// A transaction hash two receipts claim answers with the pending one on
    /// every read, whichever envelope hash each carries.
    ///
    /// Two signatures over one transaction give the same transaction hash
    /// under different envelope bytes, so `tx status` would otherwise report
    /// on whichever receipt the iteration reached last.
    #[test]
    fn a_shared_transaction_hash_answers_with_the_pending_receipt() {
        for (settled_hash, pending_hash) in [(HASH_A, HASH_B), (HASH_B, HASH_A)] {
            let dir = tempfile::tempdir().unwrap();
            let store = ReceiptStore::open_at(dir.path(), "test").unwrap();

            store
                .try_begin(settled_hash, TX_HASH_A, SOURCE_A, SEQ_A, 0, 100)
                .unwrap();
            store
                .finalize(
                    settled_hash,
                    ReceiptStatus::Failed {
                        code: "x".to_owned(),
                    },
                    None,
                )
                .unwrap();
            store
                .try_begin(pending_hash, TX_HASH_A, SOURCE_B, SEQ_B, 0, 100)
                .unwrap();
            store.mark_submitted(pending_hash).unwrap();

            for iteration in 0..200 {
                let reopened = ReceiptStore::open_at(dir.path(), "test").unwrap();
                let found = reopened.find_by_tx_hash(TX_HASH_A).unwrap().unwrap();
                assert_eq!(
                    found.envelope_hash, pending_hash,
                    "the pending receipt answers for the transaction hash on read \
                     {iteration} (settled {settled_hash})"
                );
            }
        }
    }
    #[test]
    fn approval_hold_survives_reopen_and_refuses_another_sequence() {
        let dir = tempfile::tempdir().unwrap();
        let store = ReceiptStore::open_at(dir.path(), "approval-hold").unwrap();
        assert!(matches!(
            store
                .begin_submission_with_approval(
                    "first",
                    &"a".repeat(64),
                    "source",
                    1,
                    0,
                    100,
                    Some("approval"),
                )
                .unwrap(),
            BeginSubmissionOutcome::Recorded
        ));
        store.mark_submitted("first").unwrap();
        drop(store);
        let store = ReceiptStore::open_at(dir.path(), "approval-hold").unwrap();
        let receipt = store.find_by_approval_nonce("approval").unwrap().unwrap();
        assert!(!receipt.approval_consumed);
        assert!(matches!(
            store
                .begin_submission_with_approval(
                    "second",
                    &"b".repeat(64),
                    "source",
                    2,
                    0,
                    100,
                    Some("approval"),
                )
                .unwrap(),
            BeginSubmissionOutcome::DuplicateApproval(_)
        ));
        assert!(store.get("second").unwrap().is_none());
        store.mark_approval_consumed("first").unwrap();
        let reopened = ReceiptStore::open_at(dir.path(), "approval-hold").unwrap();
        assert!(
            reopened
                .find_by_approval_nonce("approval")
                .unwrap()
                .unwrap()
                .approval_consumed
        );
    }

    #[test]
    fn definitive_send_refusal_releases_approval_in_the_receipt_write() {
        let dir = tempfile::tempdir().unwrap();
        let store = ReceiptStore::open_at(dir.path(), "approval-refusal").unwrap();
        store
            .begin_submission_with_approval(
                "first",
                &"a".repeat(64),
                "source",
                1,
                0,
                100,
                Some("approval"),
            )
            .unwrap();
        store.mark_submitted("first").unwrap();
        store
            .finalize_send_refusal("first", "submission.tx_malformed")
            .unwrap();
        let reopened = ReceiptStore::open_at(dir.path(), "approval-refusal").unwrap();
        assert!(
            reopened
                .find_by_approval_nonce("approval")
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            reopened.get("first").unwrap().unwrap().status,
            ReceiptStatus::Failed { .. }
        ));
        assert!(matches!(
            reopened
                .begin_submission_with_approval(
                    "second",
                    &"b".repeat(64),
                    "source",
                    1,
                    0,
                    100,
                    Some("approval"),
                )
                .unwrap(),
            BeginSubmissionOutcome::Recorded
        ));
    }
}
