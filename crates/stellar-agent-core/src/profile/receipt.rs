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
//! The in-memory state is protected by a `std::sync::Mutex`.  `parking_lot`
//! is not a workspace dependency; adding it solely for this module would be
//! disproportionate.  `std::sync::Mutex` is sufficient here because the lock
//! is held for microseconds (in-memory map update + file write), never across
//! an `.await`.  If `parking_lot` is adopted workspace-wide, this module
//! should migrate at the same time.
//!
//! The atomic check-and-insert operation (`try_begin`) holds the lock, inserts
//! or reads the entry, writes the file under the same lock, and then releases
//! it.  The lock is **never** held across an `.await` boundary.
//!
//! Under the pool's concurrent submissions, the first task to call `try_begin`
//! for a given envelope hash becomes the **winner** and proceeds to submit. Any
//! subsequent task that calls `try_begin` for the same hash is the **loser**
//! and receives `BeginOutcome::AlreadyPresent`.  The loser must not submit; it
//! should poll the store (or `getTransaction`) until the winner records a
//! terminal status.
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
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use serde::{Deserialize, Serialize};

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
}

impl ReceiptStatus {
    /// Returns `true` if the status is terminal (no further state transition
    /// expected from the normal submission path).
    ///
    /// `Pending` is non-terminal. `Ambiguous` and `Reorged` are considered
    /// terminal for the purposes of idempotency checking (they will not
    /// transition to Success/Failed via the standard poll path).
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Success | Self::Failed { .. } | Self::Ambiguous | Self::Reorged
        )
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
    /// In-memory map from `envelope_hash` to receipt.
    map: HashMap<String, SubmissionReceipt>,
    /// Path to the persisted JSON file.
    file_path: PathBuf,
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

        let map: HashMap<String, SubmissionReceipt> = if file_path.exists() {
            let raw = std::fs::read_to_string(&file_path).map_err(|e| ReceiptStoreError::Io {
                path: file_path.clone(),
                source: e,
            })?;
            serde_json::from_str(&raw).map_err(|e| ReceiptStoreError::Json {
                path: file_path.clone(),
                source: e,
            })?
        } else {
            HashMap::new()
        };

        Ok(Self {
            state: Arc::new(Mutex::new(StoreState { map, file_path })),
        })
    }

    /// Returns the stored receipt for `envelope_hash`, if any.
    ///
    /// # Errors
    ///
    /// - [`ReceiptStoreError::MutexPoisoned`] if the internal lock is poisoned.
    pub fn get(&self, envelope_hash: &str) -> Result<Option<SubmissionReceipt>, ReceiptStoreError> {
        let guard = self.lock()?;
        Ok(guard.map.get(envelope_hash).cloned())
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
    /// match store.try_begin("aabb...", "ccdd...", 0, 100)? {
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
        max_time: u64,
        recorded_at_ledger: u32,
    ) -> Result<BeginOutcome, ReceiptStoreError> {
        let mut guard = self.lock()?;

        // Atomic check-and-insert under the lock.
        if let Some(existing) = guard.map.get(envelope_hash) {
            return Ok(BeginOutcome::AlreadyPresent(existing.clone()));
        }

        let receipt = SubmissionReceipt {
            envelope_hash: envelope_hash.to_owned(),
            tx_hash: tx_hash.to_owned(),
            status: ReceiptStatus::Pending,
            ledger: None,
            recorded_at_ledger,
            max_time,
            prior_ledger: None,
            reorg_pending_at_ledger: None,
            submitted: false,
        };

        guard.map.insert(envelope_hash.to_owned(), receipt);

        // Persist under the same lock so no reader sees an in-memory entry
        // without the file also reflecting it.
        persist_locked(&mut guard)?;

        Ok(BeginOutcome::Winner)
    }

    /// Updates or inserts a terminal receipt (upsert semantics).
    ///
    /// If an entry already exists for `envelope_hash`, its `status` and
    /// `ledger` fields are updated.  If no entry exists, a minimal receipt is
    /// inserted so that a winner's terminal status is never dropped when a
    /// Pending row was lost (e.g. due to a failed `try_begin` persist).
    ///
    /// The upsert is performed under the mutex and persisted atomically
    /// (temp-file + fsync + rename) before the lock is released.
    ///
    /// # Errors
    ///
    /// - [`ReceiptStoreError::MutexPoisoned`] if the lock is poisoned.
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
        let mut guard = self.lock()?;

        // Upsert: update existing entry or insert a minimal terminal receipt.
        // Inserting is safe because terminal statuses carry no sub-fields that
        // a Pending entry would have populated (tx_hash, max_time,
        // recorded_at_ledger); the caller can always re-derive these from
        // context if needed. A missing-entry-silent-noop would silently drop
        // terminal status when a Pending row was lost after a failed persist.
        guard
            .map
            .entry(envelope_hash.to_owned())
            .and_modify(|r| {
                r.status = status.clone();
                r.ledger = ledger;
            })
            .or_insert_with(|| SubmissionReceipt {
                envelope_hash: envelope_hash.to_owned(),
                tx_hash: String::new(),
                status,
                ledger,
                recorded_at_ledger: 0,
                max_time: 0,
                prior_ledger: None,
                reorg_pending_at_ledger: None,
                submitted: true, // upsert on finalize: sendTransaction has already been called
            });

        persist_locked(&mut guard)?;
        Ok(())
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
        let mut guard = self.lock()?;

        // Determine whether the entry is Success and capture the prior ledger
        // before taking a mutable reference (borrow-split to allow persist_locked).
        let prior = match guard.map.get(envelope_hash) {
            Some(r) if r.status == ReceiptStatus::Success => r.ledger,
            // Non-Success or missing: no-op.
            _ => return Ok(()),
        };

        // Apply the demotion.
        if let Some(r) = guard.map.get_mut(envelope_hash) {
            r.prior_ledger = prior;
            r.status = ReceiptStatus::Reorged;
            r.ledger = None;
        }

        persist_locked(&mut guard)
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
        let mut guard = self.lock()?;

        let should_update = matches!(
            guard.map.get(envelope_hash),
            Some(r) if !r.submitted
        );

        if should_update {
            if let Some(r) = guard.map.get_mut(envelope_hash) {
                r.submitted = true;
            }
            persist_locked(&mut guard)?;
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
        let mut guard = self.lock()?;

        let should_remove = matches!(
            guard.map.get(envelope_hash),
            Some(r) if r.status == ReceiptStatus::Pending && !r.submitted
        );

        if should_remove {
            guard.map.remove(envelope_hash);
            persist_locked(&mut guard)?;
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
        let mut guard = self.lock()?;

        let should_update = matches!(
            guard.map.get(envelope_hash),
            Some(r) if r.status == ReceiptStatus::Success && r.reorg_pending_at_ledger.is_none()
        );

        if should_update {
            if let Some(r) = guard.map.get_mut(envelope_hash) {
                r.reorg_pending_at_ledger = Some(latest_ledger_at_first_miss);
            }
            persist_locked(&mut guard)?;
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
        let mut guard = self.lock()?;

        let should_update = matches!(
            guard.map.get(envelope_hash),
            Some(r) if r.status == ReceiptStatus::Success && r.reorg_pending_at_ledger.is_some()
        );

        if should_update {
            if let Some(r) = guard.map.get_mut(envelope_hash) {
                r.reorg_pending_at_ledger = None;
            }
            persist_locked(&mut guard)?;
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

    // ── Private ──────────────────────────────────────────────────────────────

    fn lock(&self) -> Result<MutexGuard<'_, StoreState>, ReceiptStoreError> {
        self.state
            .lock()
            .map_err(|_| ReceiptStoreError::MutexPoisoned)
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
        let outcome = store.try_begin(HASH_A, TX_HASH_A, 0, 100).unwrap();
        assert!(matches!(outcome, BeginOutcome::Winner));
    }

    /// Second `try_begin` on the same hash returns `AlreadyPresent`.
    #[test]
    fn try_begin_duplicate_returns_already_present() {
        let (_dir, store) = open_temp_store();
        store.try_begin(HASH_A, TX_HASH_A, 0, 100).unwrap();
        let outcome = store.try_begin(HASH_A, TX_HASH_A, 0, 100).unwrap();
        assert!(matches!(outcome, BeginOutcome::AlreadyPresent(_)));
    }

    /// `try_begin` followed by `get` returns the `Pending` receipt.
    #[test]
    fn get_after_try_begin_returns_pending() {
        let (_dir, store) = open_temp_store();
        store.try_begin(HASH_A, TX_HASH_A, 30_000, 99).unwrap();
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
        store.try_begin(HASH_A, TX_HASH_A, 0, 100).unwrap();
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
        store.try_begin(HASH_A, TX_HASH_A, 0, 100).unwrap();
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
        store.try_begin(HASH_A, TX_HASH_A, 0, 100).unwrap();
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
        store.try_begin(HASH_A, TX_HASH_A, 0, 100).unwrap();
        store
            .finalize(HASH_A, ReceiptStatus::Success, Some(42))
            .unwrap();
        let outcome = store.try_begin(HASH_A, TX_HASH_A, 0, 101).unwrap();
        assert!(matches!(outcome, BeginOutcome::AlreadyPresent(_)));
    }

    /// Atomic-rename persist survives reopen: data loaded from disk on next open.
    #[test]
    fn persist_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();

        // Write a receipt in the first store instance.
        {
            let store = ReceiptStore::open_at(dir.path(), "ptest").unwrap();
            store.try_begin(HASH_A, TX_HASH_A, 0, 50).unwrap();
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
        store.try_begin(HASH_A, TX_HASH_A, 0, 100).unwrap();
        store.try_begin(HASH_B, TX_HASH_B, 0, 100).unwrap();
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
        store.try_begin(HASH_A, TX_HASH_A, 0, 100).unwrap();

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
        store.try_begin(HASH_A, TX_HASH_A, 0, 100).unwrap();

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
        store.try_begin(HASH_A, TX_HASH_A, 0, 100).unwrap();
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
        store.try_begin(HASH_A, TX_HASH_A, 0, 100).unwrap();
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
            store.try_begin(HASH_A, TX_HASH_A, 0, 1).unwrap();
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
        store.try_begin(HASH_A, TX_HASH_A, 0, 100).unwrap();
        // submitted is false after try_begin — eligible for abandonment.
        store.abandon_pre_submit(HASH_A).unwrap();
        // Receipt must be gone.
        assert!(store.get(HASH_A).unwrap().is_none());
    }

    /// `abandon_pre_submit` must not remove a Pending receipt that has been submitted.
    #[test]
    fn abandon_pre_submit_refuses_already_submitted() {
        let (_dir, store) = open_temp_store();
        store.try_begin(HASH_A, TX_HASH_A, 0, 100).unwrap();
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
        store.try_begin(HASH_A, TX_HASH_A, 0, 100).unwrap();
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
        store.try_begin(HASH_A, TX_HASH_A, 0, 100).unwrap();
        store.abandon_pre_submit(HASH_A).unwrap();

        // Same envelope hash can now win again.
        let outcome = store.try_begin(HASH_A, TX_HASH_B, 0, 101).unwrap();
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
            store.try_begin(HASH_A, TX_HASH_A, 0, 10).unwrap();
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
        store.try_begin(HASH_A, TX_HASH_A, 0, 100).unwrap();
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
        store.try_begin(HASH_A, TX_HASH_A, 0, 100).unwrap();

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
        store.try_begin(HASH_A, TX_HASH_A, 0, 100).unwrap();
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
        store.try_begin(HASH_A, TX_HASH_A, 0, 100).unwrap();
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
        store.try_begin(HASH_A, TX_HASH_A, 0, 100).unwrap();
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
            store.try_begin(HASH_A, TX_HASH_A, 0, 10).unwrap();
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
        store.try_begin(HASH_A, TX_HASH_A, 0, 100).unwrap();
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
        store.try_begin(HASH_A, TX_HASH_A, 0, 100).unwrap();
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
        store.try_begin(HASH_A, TX_HASH_A, 0, 100).unwrap();

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
        store.try_begin(HASH_A, TX_HASH_A, 0, 100).unwrap();
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
        store.try_begin(HASH_A, TX_HASH_A, 0, 100).unwrap();
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
        store.try_begin(HASH_A, TX_HASH_A, 0, 100).unwrap();

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
        store.try_begin(HASH_A, TX_HASH_A, 1_000_000, 100).unwrap();
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

        store.try_begin(HASH_A, TX_HASH_A, 0, 50).unwrap();

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
            status: ReceiptStatus::Reorged,
            ledger: None,
            recorded_at_ledger: 1234,
            max_time: 9_999_999,
            prior_ledger: Some(1200),
            reorg_pending_at_ledger: Some(1210),
            submitted: true,
        };

        let json = serde_json::to_string(&original).unwrap();
        let decoded: SubmissionReceipt = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.envelope_hash, HASH_A);
        assert_eq!(decoded.tx_hash, TX_HASH_A);
        assert_eq!(decoded.status, ReceiptStatus::Reorged);
        assert_eq!(decoded.ledger, None);
        assert_eq!(decoded.recorded_at_ledger, 1234);
        assert_eq!(decoded.max_time, 9_999_999);
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
            status: ReceiptStatus::Pending,
            ledger: None,
            recorded_at_ledger: 1,
            max_time: 0,
            prior_ledger: None,
            reorg_pending_at_ledger: None,
            submitted: false,
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

        let outcome = store.try_begin(&feebump_key, inner_tx_hex, 0, 300).unwrap();
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
        store.try_begin(HASH_A, TX_HASH_A, 0, 100).unwrap();
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

        s1.try_begin(HASH_A, TX_HASH_A, 0, 1).unwrap();
        s2.try_begin(HASH_B, TX_HASH_B, 0, 2).unwrap();

        // s1 has only HASH_A.
        assert!(s1.get(HASH_A).unwrap().is_some());
        assert!(s1.get(HASH_B).unwrap().is_none());

        // s2 has only HASH_B.
        assert!(s2.get(HASH_B).unwrap().is_some());
        assert!(s2.get(HASH_A).unwrap().is_none());

        // File names are distinct.
        assert_ne!(s1.file_path().unwrap(), s2.file_path().unwrap());
    }
}
