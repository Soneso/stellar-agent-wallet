//! Audit-log reader that reconstructs signer-set state from the hash-chained log.
//!
//! Provides [`AuditReader`] — a read-side companion to [`AuditWriter`] that
//! scans the rotated log-file chain in reverse-chronological order to find the
//! most-recent signer-set state row for a rule of a smart account, of either
//! row version.
//!
//! # Shared-mutex discipline
//!
//! `AuditReader` holds a clone of the same `Arc<Mutex<AuditWriter>>` that the
//! write path uses. The reader acquires the mutex for the entire duration of a
//! scan, which eliminates intra-process reader/writer races: a writer cannot
//! append a new entry while the reader is traversing the log.
//!
//! Because the writer holds the file-system advisory lock for its lifetime, and
//! the reader acquires the writer mutex before reading, multi-process isolation
//! is also guaranteed for the single-writer invariant.
//!
//! # The verified-tip bound
//!
//! Every scan reads under the caller's writer guard and stops at that
//! writer's verified tip. The active file is read only up to
//! `AuditWriter::end_offset`; its first row must chain from the segment start
//! the writer holds, and its last row read must hash to the writer's
//! `last_entry_hash`. Each archive's in-file chain must verify, and its last
//! row must hash to the `previous_entry_hash` of the first row of the next
//! newer file. A broken link is [`AuditLogIntegrityError::ChainBroken`] with
//! reason `bridge_mismatch` or `tip_mismatch`. Rows that an
//! `audit_entries_quarantined` row covers are dropped. No key is read.
//!
//! A row appended to the file outside the writer therefore never reaches a
//! scan: it lies past the bound. The one exception is
//! [`scan_all_context_rule_pin_records_unanchored`], which takes no writer,
//! reads the whole active file, and feeds only operator-facing warnings.
//!
//! # Scan order
//!
//! The active file is scanned first (most-recent entries), then rotated files
//! from newest to oldest. Within each file, entries are scanned from first to
//! last (oldest-to-newest within that file) and the most-recent match across all
//! files is captured. This implements "newest overall" semantics without
//! reversing within a file.
//!
//! # Integrity contract
//!
//! Integrity errors (`ChainBroken`, `RotationGap`, `HmacMismatch`,
//! `HmacSidecarMissing`, `ParseError`) MUST propagate and MUST NOT be
//! reinterpreted as `Ok(None)`. `Ok(None)` is reserved for "full chain
//! traversal completed cleanly with no matching row" — it never silently masks
//! integrity violations.
//!
//! # Reader consistency posture
//!
//! `AuditWriter` places no OS lock on the log file itself (the exclusive lock
//! lives on a sidecar file — see `writer::lock_sidecar_path` and
//! `crate::audit_log::lock`), so a reader may observe the log directory
//! mid-write or mid-rotation, on every platform:
//!
//! - **Mid-append** (a write in progress): the guard the scan holds keeps
//!   this process's writer from appending, and the bound stops at the last
//!   row that writer committed. A bound that ends inside a line refuses with
//!   [`AuditLogIntegrityError::ChainBroken`] reason `tip_mismatch`, never
//!   `Ok(None)`.
//!
//! - **Mid-rotation** (the active file transiently absent): `AuditWriter::rotate`
//!   renames the active file to its archive name and then creates the new
//!   active file as two separate filesystem operations; a reader can observe
//!   the directory in the microsecond-scale window between them, in which the
//!   active path does not exist even though the log is not actually empty.
//!   `collect_files_newest_first` tolerates this: when the active file is
//!   absent but rotated siblings are present, it re-scans the directory a
//!   small bounded number of times (never indefinitely) WHILE the writer's
//!   sidecar lock is observably held by a live writer (probed by
//!   `writer::wait_out_transient_rotation_window`, shared with
//!   `verify::verify_log`'s equivalent tolerance), on the theory that the
//!   combination of "no active file" + "a writer is currently alive" is far
//!   more likely to be this transient window than out-of-band tampering. If
//!   the file reappears, the scan proceeds normally with the fresh file
//!   listing. If the bound is exhausted, or no writer is alive to begin with,
//!   the absence is treated exactly as before: [`AuditLogIntegrityError::RotationGap`]
//!   for a non-active missing file, or "empty log" for an active file absent
//!   with no rotated siblings. This bounded tolerance never turns a genuine
//!   integrity violation into `Ok` — it only delays, by a few milliseconds at
//!   most, the point at which a still-absent file is reported as a gap.

use std::{
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use sha2::{Digest as _, Sha256};

use super::{
    chain::{ZERO_BLOCK_HASH, compute_entry_hash},
    entry::AuditEntry,
    schema::{EventKind, ExecutableRefPin, ExecutableRefPinFirst8, ValueLegRecord, WasmHashPin},
    signer_set::{ObservedSignerSet, SignerSetSnapshotV2, SignerSetView, SignerSetViewPayload},
    verify::VerifyError,
    writer::{AuditWriter, is_rotated_sibling, wait_out_transient_rotation_window},
};

/// The complete pin record of one rule: every pinned verifier and policy
/// hash in full, the executable-reference pins aligned with them, and the
/// override flags.
///
/// Read from the rule's newest pin row when that row is a version-2 row
/// (`SaContextRuleCreatedV2`, `SaContextRulePinsUpdatedV2`), or a version-1
/// row that pins no hash. The signing-time drift check compares a live
/// executable with these hashes in all 32 bytes.
///
/// # Invariants
///
/// An executable-reference list is empty or has the length of its hash
/// list, and each `Some` entry's resolved hash equals the aligned hash; the
/// reader refuses a row that breaks either as a parse error.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PinnedHashesRecord {
    /// Full hash of each pinned verifier. Empty when the rule pins no
    /// verifier.
    pub pinned_verifier_hashes: Vec<WasmHashPin>,
    /// Full hash of each pinned policy. Empty when the rule pins no policy.
    pub pinned_policy_hashes: Vec<WasmHashPin>,
    /// `true` if `--accept-mutable-verifier` admitted a pinned contract.
    pub mutable_override: bool,
    /// `true` if `--accept-unknown-verifier` admitted a pinned contract.
    pub unknown_override: bool,
    /// Executable-reference pins aligned by position with
    /// `pinned_verifier_hashes`, or empty when no pinned verifier is an
    /// external reference.
    pub pinned_verifier_executable_refs: Vec<Option<ExecutableRefPin>>,
    /// Executable-reference pins aligned by position with
    /// `pinned_policy_hashes`, with the same invariants as
    /// `pinned_verifier_executable_refs`.
    pub pinned_policy_executable_refs: Vec<Option<ExecutableRefPin>>,
}

impl PinnedHashesRecord {
    /// Returns the executable-reference pin recorded for the verifier at
    /// `position` in `pinned_verifier_hashes`, or `None` when that verifier
    /// was pinned by its Wasm hash.
    #[must_use]
    pub fn verifier_executable_ref(&self, position: usize) -> Option<&ExecutableRefPin> {
        self.pinned_verifier_executable_refs
            .get(position)
            .and_then(Option::as_ref)
    }

    /// Returns the executable-reference pin recorded for the policy at
    /// `position` in `pinned_policy_hashes`, or `None` when that policy was
    /// pinned by its Wasm hash.
    #[must_use]
    pub fn policy_executable_ref(&self, position: usize) -> Option<&ExecutableRefPin> {
        self.pinned_policy_executable_refs
            .get(position)
            .and_then(Option::as_ref)
    }
}

/// The inspection-only form of a version-1 pin record that holds at least
/// one hash: each pinned hash is known by its first eight bytes only.
///
/// The missing 24 bytes of each hash cannot be recovered from the chain or
/// from the allowlist, so no signature is made against this record; the
/// signing-time check refuses the rule until it is reinstalled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IncompletePinRecord {
    /// Wire tag of the row that carries the record.
    pub row_kind: &'static str,
    /// First eight bytes of each pinned verifier hash, as 16 hex characters.
    pub pinned_verifier_hashes_first8: Vec<String>,
    /// First eight bytes of each pinned policy hash, as 16 hex characters.
    pub pinned_policy_hashes_first8: Vec<String>,
    /// The row's mutable-contract override flag.
    pub mutable_override: bool,
    /// The row's unknown-hash override flag.
    pub unknown_override: bool,
    /// The row's verifier executable-reference pins, aligned with
    /// `pinned_verifier_hashes_first8` or empty.
    pub pinned_verifier_executable_refs: Vec<Option<ExecutableRefPinFirst8>>,
    /// The row's policy executable-reference pins, aligned with
    /// `pinned_policy_hashes_first8` or empty.
    pub pinned_policy_executable_refs: Vec<Option<ExecutableRefPinFirst8>>,
}

/// The pin record of one rule, as its newest pin row records it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ContextRulePinRecord {
    /// Every pinned hash is known in full.
    Complete(PinnedHashesRecord),
    /// The newest pin row is a version-1 row that pins at least one hash by
    /// its first eight bytes only.
    Incomplete(IncompletePinRecord),
}

/// The pin lists of one pin row, in the row's version.
enum PinRowLists<'a> {
    /// A version-1 row: first-8 projections.
    First8 {
        verifier: &'a [String],
        policy: &'a [String],
        verifier_refs: &'a [Option<ExecutableRefPinFirst8>],
        policy_refs: &'a [Option<ExecutableRefPinFirst8>],
    },
    /// A version-2 row: full hashes.
    Full {
        verifier: &'a [WasmHashPin],
        policy: &'a [WasmHashPin],
        verifier_refs: &'a [Option<ExecutableRefPin>],
        policy_refs: &'a [Option<ExecutableRefPin>],
    },
}

/// The pin fields of one `SaContextRuleCreated`, `SaContextRuleCreatedV2`,
/// `SaContextRulePinsUpdated` or `SaContextRulePinsUpdatedV2` row.
struct PinRow<'a> {
    rule_id: u32,
    smart_account: &'a str,
    /// Wire tag of the row kind, named in parse-error details.
    row_kind: &'static str,
    mutable_override: bool,
    unknown_override: bool,
    lists: PinRowLists<'a>,
}

impl<'a> PinRow<'a> {
    /// Returns the pin fields of `event_kind` when it is one of the four row
    /// kinds that carry a rule's pin record, `None` for every other kind.
    fn from_event_kind(event_kind: &'a EventKind) -> Option<Self> {
        match event_kind {
            EventKind::SaContextRuleCreated {
                rule_id,
                smart_account,
                pinned_verifier_wasm_hashes_first8,
                pinned_policy_wasm_hashes_first8,
                mutable_override,
                unknown_override,
                pinned_verifier_executable_refs,
                pinned_policy_executable_refs,
                ..
            } => Some(Self {
                rule_id: *rule_id,
                smart_account,
                row_kind: "sa_context_rule_created",
                mutable_override: *mutable_override,
                unknown_override: *unknown_override,
                lists: PinRowLists::First8 {
                    verifier: pinned_verifier_wasm_hashes_first8,
                    policy: pinned_policy_wasm_hashes_first8,
                    verifier_refs: pinned_verifier_executable_refs,
                    policy_refs: pinned_policy_executable_refs,
                },
            }),
            EventKind::SaContextRulePinsUpdated {
                rule_id,
                smart_account,
                pinned_verifier_wasm_hashes_first8,
                pinned_policy_wasm_hashes_first8,
                mutable_override,
                unknown_override,
                pinned_verifier_executable_refs,
                pinned_policy_executable_refs,
                ..
            } => Some(Self {
                rule_id: *rule_id,
                smart_account,
                row_kind: "sa_context_rule_pins_updated",
                mutable_override: *mutable_override,
                unknown_override: *unknown_override,
                lists: PinRowLists::First8 {
                    verifier: pinned_verifier_wasm_hashes_first8,
                    policy: pinned_policy_wasm_hashes_first8,
                    verifier_refs: pinned_verifier_executable_refs,
                    policy_refs: pinned_policy_executable_refs,
                },
            }),
            EventKind::SaContextRuleCreatedV2 {
                rule_id,
                smart_account,
                pinned_verifier_wasm_hashes,
                pinned_policy_wasm_hashes,
                mutable_override,
                unknown_override,
                pinned_verifier_executable_refs,
                pinned_policy_executable_refs,
                ..
            } => Some(Self {
                rule_id: *rule_id,
                smart_account,
                row_kind: "sa_context_rule_created_v2",
                mutable_override: *mutable_override,
                unknown_override: *unknown_override,
                lists: PinRowLists::Full {
                    verifier: pinned_verifier_wasm_hashes,
                    policy: pinned_policy_wasm_hashes,
                    verifier_refs: pinned_verifier_executable_refs,
                    policy_refs: pinned_policy_executable_refs,
                },
            }),
            EventKind::SaContextRulePinsUpdatedV2 {
                rule_id,
                smart_account,
                pinned_verifier_wasm_hashes,
                pinned_policy_wasm_hashes,
                mutable_override,
                unknown_override,
                pinned_verifier_executable_refs,
                pinned_policy_executable_refs,
                ..
            } => Some(Self {
                rule_id: *rule_id,
                smart_account,
                row_kind: "sa_context_rule_pins_updated_v2",
                mutable_override: *mutable_override,
                unknown_override: *unknown_override,
                lists: PinRowLists::Full {
                    verifier: pinned_verifier_wasm_hashes,
                    policy: pinned_policy_wasm_hashes,
                    verifier_refs: pinned_verifier_executable_refs,
                    policy_refs: pinned_policy_executable_refs,
                },
            }),
            _ => None,
        }
    }

    /// Builds the [`ContextRulePinRecord`] this row carries, refusing a
    /// record the wallet never writes.
    ///
    /// An executable-reference list must be empty or aligned with its hash
    /// list, and every pin must have the shape its constructor produces. In
    /// a version-2 row every pin's resolved hash must equal the aligned hash
    /// in all 32 bytes; in a version-1 row its first-8 must equal the
    /// aligned first-8. The signing-time drift check reads the pin at the
    /// position it checks, so a misaligned or inconsistent record could pair
    /// a hash with the wrong reference; it is refused as a parse error at
    /// `line` naming the row kind.
    ///
    /// A version-1 row that pins a hash is [`ContextRulePinRecord::Incomplete`];
    /// one that pins none carries no truncated value and is complete.
    fn record(&self, line: usize) -> Result<ContextRulePinRecord, AuditLogIntegrityError> {
        match self.lists {
            PinRowLists::Full {
                verifier,
                policy,
                verifier_refs,
                policy_refs,
            } => {
                for (kind, hashes, refs) in [
                    ("verifier", verifier, verifier_refs),
                    ("policy", policy, policy_refs),
                ] {
                    self.check_alignment(line, kind, hashes.len(), refs.len())?;
                    for (position, pin) in refs.iter().enumerate() {
                        let Some(pin) = pin else { continue };
                        self.check_pin(
                            line,
                            kind,
                            position,
                            pin.is_well_formed(),
                            hashes.get(position) == Some(&pin.resolved_hash),
                        )?;
                    }
                }
                Ok(ContextRulePinRecord::Complete(PinnedHashesRecord {
                    pinned_verifier_hashes: verifier.to_vec(),
                    pinned_policy_hashes: policy.to_vec(),
                    mutable_override: self.mutable_override,
                    unknown_override: self.unknown_override,
                    pinned_verifier_executable_refs: verifier_refs.to_vec(),
                    pinned_policy_executable_refs: policy_refs.to_vec(),
                }))
            }
            PinRowLists::First8 {
                verifier,
                policy,
                verifier_refs,
                policy_refs,
            } => {
                for (kind, first8, refs) in [
                    ("verifier", verifier, verifier_refs),
                    ("policy", policy, policy_refs),
                ] {
                    self.check_alignment(line, kind, first8.len(), refs.len())?;
                    for (position, pin) in refs.iter().enumerate() {
                        let Some(pin) = pin else { continue };
                        self.check_pin(
                            line,
                            kind,
                            position,
                            pin.is_well_formed(),
                            first8.get(position) == Some(&pin.resolved_hash_first8),
                        )?;
                    }
                }
                if verifier.is_empty() && policy.is_empty() {
                    return Ok(ContextRulePinRecord::Complete(PinnedHashesRecord {
                        mutable_override: self.mutable_override,
                        unknown_override: self.unknown_override,
                        ..PinnedHashesRecord::default()
                    }));
                }
                Ok(ContextRulePinRecord::Incomplete(IncompletePinRecord {
                    row_kind: self.row_kind,
                    pinned_verifier_hashes_first8: verifier.to_vec(),
                    pinned_policy_hashes_first8: policy.to_vec(),
                    mutable_override: self.mutable_override,
                    unknown_override: self.unknown_override,
                    pinned_verifier_executable_refs: verifier_refs.to_vec(),
                    pinned_policy_executable_refs: policy_refs.to_vec(),
                }))
            }
        }
    }

    /// Refuses a non-empty reference list whose length differs from its
    /// hash list's.
    fn check_alignment(
        &self,
        line: usize,
        kind: &str,
        hashes: usize,
        refs: usize,
    ) -> Result<(), AuditLogIntegrityError> {
        if refs != 0 && refs != hashes {
            return Err(AuditLogIntegrityError::ParseError {
                line,
                detail: format!(
                    "{}: {refs} {kind} executable-reference pins for {hashes} pinned {kind} \
                     hashes",
                    self.row_kind
                ),
            });
        }
        Ok(())
    }

    /// Refuses a malformed reference pin, or one whose resolved hash differs
    /// from the aligned hash.
    fn check_pin(
        &self,
        line: usize,
        kind: &str,
        position: usize,
        well_formed: bool,
        matches_aligned_hash: bool,
    ) -> Result<(), AuditLogIntegrityError> {
        if !well_formed {
            return Err(AuditLogIntegrityError::ParseError {
                line,
                detail: format!(
                    "{}: malformed {kind} executable-reference pin at position {position}",
                    self.row_kind
                ),
            });
        }
        if !matches_aligned_hash {
            return Err(AuditLogIntegrityError::ParseError {
                line,
                detail: format!(
                    "{}: {kind} executable-reference pin at position {position} does not match \
                     the pinned {kind} hash",
                    self.row_kind
                ),
            });
        }
        Ok(())
    }
}

/// Re-export of [`VerifyError`] under a reader-oriented name.
///
/// Integrity error returned by audit-log read paths.
///
/// Wire codes are preserved verbatim (`audit.chain_broken`,
/// `audit.rotation_gap`, `audit.hmac_mismatch`, `audit.hmac_sidecar_missing`,
/// `audit.parse_error`, `audit.too_many_rotated_files`,
/// `audit.non_regular_file_log_path`, `audit.path_contract`,
/// `audit.io_error`, `audit.signer_set_canonical_body`).
pub type AuditLogIntegrityError = VerifyError;

// ── AuditReader ───────────────────────────────────────────────────────────────

/// Read-side companion to [`AuditWriter`] for signer-set baseline reconstruction.
///
/// Holds a clone of the shared `Arc<Mutex<AuditWriter>>` to eliminate
/// intra-process reader/writer races.
///
/// Obtain via [`AuditReader::new`]; then call
/// [`AuditReader::find_latest_signer_set_view`] to scan the rotated log chain.
pub struct AuditReader {
    /// Shared writer mutex — acquired for the full duration of each scan.
    ///
    /// Sharing the writer's mutex eliminates intra-process reader/writer races:
    /// a writer cannot append while the reader traverses the log. Because the
    /// writer also holds the OS advisory lock for its lifetime, multi-process
    /// isolation is guaranteed by the single-writer invariant.
    writer: Arc<Mutex<AuditWriter>>,

    /// Optional HMAC key for chain-root sidecar verification.
    ///
    /// When `Some`, every scan checks each walked file's chain-root sidecar
    /// under it, with the check `verify_log` applies. When `None`, the
    /// sidecars are not checked; the hash chain still is.
    hmac_key: Option<[u8; 32]>,
}

impl AuditReader {
    /// Constructs a new `AuditReader` from the shared writer mutex and an
    /// optional HMAC key.
    ///
    /// Construction takes no lock. Each scan holds the writer's mutex for its
    /// whole traversal and reads the log path and the bound from the guard;
    /// a poisoned mutex fails that scan with [`AuditLogIntegrityError::Io`].
    #[must_use]
    pub fn new(writer: Arc<Mutex<AuditWriter>>, hmac_key: Option<[u8; 32]>) -> Self {
        Self { writer, hmac_key }
    }

    /// Acquires the shared writer's guard for one scan.
    ///
    /// A poisoned mutex is an [`AuditLogIntegrityError::Io`]: the reader may
    /// see a half-written state from the panicking writer, so silent recovery
    /// via `into_inner()` is unsound.
    fn lock_writer(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, AuditWriter>, AuditLogIntegrityError> {
        self.writer.lock().map_err(|_| {
            AuditLogIntegrityError::Io(std::io::Error::other(
                "audit-log writer mutex is poisoned; a prior write path panicked \
                 mid-write; audit-log integrity is unknown; restart the process",
            ))
        })
    }

    /// Finds the completion event for one pool lifecycle across the verified
    /// active and rotated log. The shared writer excludes concurrent appends.
    ///
    /// The log is verified first, with the active file read only up to the
    /// writer's verified tip, so bytes appended past that tip outside the
    /// writer change neither the verification nor the result; the rows are
    /// then read through the writer's bound (see the module documentation).
    ///
    /// # Errors
    /// Propagates integrity, parse, and I/O failures. Completion lookup requires
    /// a verified audit chain.
    pub fn pool_initialization_exists(
        &self,
        request_id: &str,
    ) -> Result<bool, AuditLogIntegrityError> {
        let writer = self.lock_writer()?;
        super::verify::verify_log_within(
            writer.path(),
            self.hmac_key.as_ref(),
            writer.end_offset(),
        )?;
        for file in bounded_files(&writer, self.hmac_key.as_ref())? {
            let found = file?.rows.iter().any(|(_, entry)| {
                entry.request_id == request_id
                    && matches!(entry.event_kind, EventKind::ChannelPoolInitialised { .. })
            });
            if found {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Scans the rotated chain backwards for the most-recent signer-set state
    /// row of rule `rule_id` of one smart account, of either row version.
    ///
    /// A version-1 row (`SaSignerAdded`, `SaSignerRemoved`,
    /// `SaThresholdChanged`, `SaSignerSetBaselined`) matches on
    /// `(rule_id, smart_account_redacted)` and is returned as
    /// [`SignerSetView::V1`], reconstructed from its `resulting_*` /
    /// `observed_*` fields. A version-2 row (`SaSignerAddedV2`,
    /// `SaSignerRemovedV2`, `SaThresholdChangedV2`, `SaSignerSetBaselinedV2`)
    /// matches on `(rule_id, account_digest)` and is returned as
    /// [`SignerSetView::V2`]. The keys differ because a version-1 row names
    /// the account only by its first-5-last-5 redacted strkey, which many
    /// accounts share and which names no network, while a version-2 row
    /// carries the account digest of the network passphrase and the full
    /// strkey (`signer_set::account_digest`), which binds exactly one account
    /// on one network.
    ///
    /// Every version-2 state row the scan reads, for any rule or account,
    /// must pass [`super::signer_set::SignerSetSnapshotV2::validate`]; a row
    /// that fails is a [`AuditLogIntegrityError::ParseError`] at its line,
    /// as a malformed JSON line is.
    ///
    /// # Scan semantics
    ///
    /// The scan reads the writer's bounded walk: the active file up to the
    /// writer's verified tip, then rotated files newest-first, with
    /// quarantined rows removed. Within each file entries are read
    /// first-to-last. The most-recent matching entry across the chain is
    /// returned. HMAC integrity is checked when `hmac_key` is set.
    ///
    /// # Returns
    ///
    /// - `Ok(Some(payload))`: matching row found; `payload.row_hash()` is the
    ///   SHA-256 of the canonical JSON body of the row (body with
    ///   `previous_entry_hash = ""` and no entry tag), suitable for binding
    ///   into `FrozenChainStateTuple`, and `payload.file()` /
    ///   `payload.line()` name the row.
    /// - `Ok(None)`: the walk completed cleanly with no matching row
    ///   (reserved for "no baseline"; never silently masks integrity errors).
    ///
    /// # Errors
    ///
    /// - [`AuditLogIntegrityError::ChainBroken`] — hash chain break at a
    ///   specific line, or a broken bridge or tip (integrity violation, not a
    ///   configuration error).
    /// - [`AuditLogIntegrityError::RotationGap`] — a rotated file in the chain
    ///   is missing, or the active file is missing while archives exist.
    /// - [`AuditLogIntegrityError::HmacMismatch`] — chain-root HMAC tag did
    ///   not verify (only when `hmac_key` is `Some`).
    /// - [`AuditLogIntegrityError::HmacSidecarMissing`] — HMAC key provided
    ///   but per-file sidecar is absent (integrity violation).
    /// - [`AuditLogIntegrityError::ParseError`]: a log line inside the bound
    ///   could not be parsed as an [`AuditEntry`], or a version-2 state row
    ///   carries a malformed snapshot.
    /// - [`AuditLogIntegrityError::Io`]: ambient filesystem failure, or a
    ///   poisoned writer mutex (a prior writer thread panicked while holding
    ///   the lock; process restart is the only safe recovery).
    pub fn find_latest_signer_set_view(
        &self,
        rule_id: u32,
        smart_account_redacted: &str,
        account_digest: &[u8; 32],
    ) -> Result<Option<SignerSetViewPayload>, AuditLogIntegrityError> {
        let writer = self.lock_writer()?;
        let key = SignerSetKey {
            rule_id,
            smart_account_redacted,
            account_digest,
        };
        for file in bounded_files(&writer, self.hmac_key.as_ref())? {
            let file = file?;
            if let Some(payload) = latest_signer_set_view(&file, key)? {
                return Ok(Some(payload));
            }
        }
        Ok(None)
    }

    /// Scans the rotated chain for the rule's pin record: the most-recent
    /// pin row matching `(rule_id, smart_account_redacted)`, of either
    /// version (`SaContextRuleCreated`, `SaContextRulePinsUpdated`,
    /// `SaContextRuleCreatedV2`, `SaContextRulePinsUpdatedV2`).
    ///
    /// Used by `managers::verifiers::verify_pinned_verifier_against_chain` and
    /// `verify_pinned_policy_against_chain` to derive the audit-log-expected hash
    /// at signing time. Only the newest matching row inside the writer's
    /// bound is the record: an incomplete newest row is returned as such and
    /// never replaced by an older row, and a row past the writer's verified
    /// tip or a quarantined row is never read.
    ///
    /// # Returns
    ///
    /// - `Ok(Some(ContextRulePinRecord::Complete(record)))`: the newest pin
    ///   row is a version-2 row, or a version-1 row that pins no hash; the
    ///   record carries every pinned hash in full. Either list may be empty.
    /// - `Ok(Some(ContextRulePinRecord::Incomplete(record)))`: the newest pin
    ///   row is a version-1 row that pins at least one hash by its first
    ///   eight bytes.
    /// - `Ok(None)`: no matching row of any pin kind found. Callers treat this
    ///   as "no pin recorded" and may skip drift-detection.
    ///
    /// # Integrity contract
    ///
    /// Integrity errors propagate the same as `find_latest_signer_set_view`;
    /// `Ok(None)` is NEVER used to mask an integrity failure.
    ///
    /// # Errors
    ///
    /// Same error variants as [`AuditReader::find_latest_signer_set_view`]:
    /// `ChainBroken`, `RotationGap`, `HmacMismatch`, `HmacSidecarMissing`,
    /// `ParseError`, `Io`.
    pub fn find_latest_context_rule_pinned_hashes(
        &self,
        rule_id: u32,
        smart_account_redacted: &str,
    ) -> Result<Option<ContextRulePinRecord>, AuditLogIntegrityError> {
        let writer = self.lock_writer()?;
        for file in bounded_files(&writer, self.hmac_key.as_ref())? {
            let file = file?;
            if let Some(record) = latest_pin_record(&file, rule_id, smart_account_redacted)? {
                return Ok(Some(record));
            }
        }
        Ok(None)
    }

    /// Scans the full rotated chain and returns ALL pin records (the pin rows
    /// of both versions), deduplicated to the most-recent row per
    /// `(rule_id, smart_account_redacted)`.
    ///
    /// Reads the writer's bounded walk, so rows past the writer's verified tip
    /// and quarantined rows are not part of the result. Unlike
    /// `find_latest_context_rule_pinned_hashes`, this method does NOT filter by
    /// a specific `(rule_id, smart_account_redacted)` pair — it collects ALL
    /// rules across the full log chain.
    ///
    /// # Deduplication
    ///
    /// If the same `(rule_id, smart_account_redacted)` appears more than once
    /// (e.g. after a rule reinstall), the MOST RECENT row wins. Scan order is
    /// newest-file-first, newest-entry-last-within-file — same as the other
    /// `find_latest_*` methods.
    ///
    /// # Returns
    ///
    /// A `Vec` of `(rule_id, smart_account_redacted, ContextRulePinRecord)` tuples,
    /// deduplicated to the most-recent row per `(rule_id, smart_account)` — the
    /// newest file wins on conflict — and sorted by `(rule_id, smart_account)`
    /// ascending for deterministic output. Empty when the log is absent or
    /// contains no pin-record rows.
    ///
    /// # Errors
    ///
    /// Same integrity error variants as [`AuditReader::find_latest_signer_set_view`]:
    /// `ChainBroken`, `RotationGap`, `HmacMismatch`, `HmacSidecarMissing`,
    /// `ParseError`, `Io`.
    pub fn scan_all_context_rule_pin_records(
        &self,
    ) -> Result<Vec<(u32, String, ContextRulePinRecord)>, AuditLogIntegrityError> {
        let writer = self.lock_writer()?;
        all_pin_records(bounded_files(&writer, self.hmac_key.as_ref())?)
    }

    /// Returns the set of context-rule IDs that the local audit log records as
    /// installed on `sa_address_redacted` but NOT subsequently deleted.
    ///
    /// Reads the writer's bounded walk for all `SaContextRuleCreated` and
    /// `SaContextRuleCreatedV2` rows whose `smart_account` field matches
    /// `sa_address_redacted`, then subtracts any
    /// `rule_id` that also has a matching `SaContextRuleDeleted` row for the
    /// same address. The result is the audit-log's best view of "live" rule IDs
    /// on this smart account.
    ///
    /// Used by `ContextRuleManager::list_active_context_rules` to cross-check
    /// the on-chain enumeration against the local audit record: a malicious RPC
    /// that drops a live rule from its enumeration response will cause that
    /// rule's ID to appear in `ActiveContextRuleEnumeration::audit_log_missing`.
    ///
    /// # Returns
    ///
    /// - `Ok(ids)` — sorted `Vec<u32>` of rule IDs the audit log believes are
    ///   installed. Empty when no matching rows exist or when every
    ///   `SaContextRuleCreated` entry for this address has a corresponding
    ///   `SaContextRuleDeleted` entry.
    /// - `Err(AuditLogIntegrityError)` — integrity violation or I/O error; MUST
    ///   NOT be silently mapped to `Ok(vec![])`.
    ///
    /// # Errors
    ///
    /// Same variants as [`AuditReader::find_latest_signer_set_view`].
    pub fn find_installed_context_rule_ids(
        &self,
        sa_address_redacted: &str,
    ) -> Result<Vec<u32>, AuditLogIntegrityError> {
        let writer = self.lock_writer()?;
        let mut created_ids: std::collections::HashSet<u32> = std::collections::HashSet::new();
        let mut deleted_ids: std::collections::HashSet<u32> = std::collections::HashSet::new();
        for file in bounded_files(&writer, self.hmac_key.as_ref())? {
            for (_, entry) in &file?.rows {
                match &entry.event_kind {
                    EventKind::SaContextRuleCreated {
                        rule_id,
                        smart_account,
                        ..
                    }
                    | EventKind::SaContextRuleCreatedV2 {
                        rule_id,
                        smart_account,
                        ..
                    } if smart_account == sa_address_redacted => {
                        created_ids.insert(*rule_id);
                    }
                    EventKind::SaContextRuleDeleted {
                        rule_id,
                        smart_account,
                    } if smart_account == sa_address_redacted => {
                        deleted_ids.insert(*rule_id);
                    }
                    _ => {}
                }
            }
        }
        // Live = created - deleted.
        let mut live: Vec<u32> = created_ids.difference(&deleted_ids).copied().collect();
        live.sort_unstable();
        Ok(live)
    }

    /// Scans the audit log for pending timelock operations on a given timelock
    /// contract and returns them as `(operation_id_full_hex, request_id, timelock_redacted)`
    /// tuples.
    ///
    /// A "pending" operation is one that has a `SaTimelockScheduled` row but
    /// no corresponding `SaTimelockCancelled` or `SaTimelockExecuted` row with
    /// the same `operation_id_full_hex`, inside the writer's bounded walk.
    ///
    /// The `timelock_contract_strkey` parameter is matched against the
    /// `timelock_contract_redacted` field in each row. Because the audit log
    /// stores the redacted form, callers MUST supply the redacted form of the
    /// timelock contract address (first-5-last-5 C-strkey).
    ///
    /// # Returns
    ///
    /// - `Ok(vec)` — a possibly-empty list of `(operation_id_full_hex,
    ///   scheduled_request_id, timelock_redacted)` tuples for operations that
    ///   do not have a corresponding cancel or execute row.
    ///
    /// # Errors
    ///
    /// - [`AuditLogIntegrityError::ParseError`] — a log line could not be parsed.
    /// - [`AuditLogIntegrityError::ChainBroken`] — hash chain break detected.
    /// - [`AuditLogIntegrityError::Io`] — filesystem or mutex-poison error.
    pub fn find_pending_timelock_operations(
        &self,
        timelock_contract_redacted: &str,
    ) -> Result<Vec<(String, String, String)>, AuditLogIntegrityError> {
        let writer = self.lock_writer()?;
        // scheduled_ops: map from operation_id_full_hex → (request_id, timelock_redacted).
        // cancelled_or_executed: operation ids that have been cancelled or
        // executed.
        let mut scheduled_ops: std::collections::HashMap<String, (String, String)> =
            std::collections::HashMap::new();
        let mut cancelled_or_executed: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        for file in bounded_files(&writer, self.hmac_key.as_ref())? {
            for (_, entry) in &file?.rows {
                match &entry.event_kind {
                    EventKind::SaTimelockScheduled {
                        operation_id_full_hex,
                        timelock_contract_redacted: tl_redacted,
                        audit_request_id,
                        ..
                    } if tl_redacted.as_str() == timelock_contract_redacted => {
                        scheduled_ops
                            .entry(operation_id_full_hex.clone())
                            .or_insert_with(|| {
                                (audit_request_id.clone(), tl_redacted.as_str().to_owned())
                            });
                    }
                    // Cancel and execute rows carry `operation_id_full_hex`,
                    // so dedupe uses the exact 64-hex match instead of the
                    // redacted form.
                    EventKind::SaTimelockCancelled {
                        operation_id_full_hex,
                        timelock_contract_redacted: tl_redacted,
                        ..
                    }
                    | EventKind::SaTimelockExecuted {
                        operation_id_full_hex,
                        timelock_contract_redacted: tl_redacted,
                        ..
                    } if tl_redacted.as_str() == timelock_contract_redacted => {
                        scheduled_ops.remove(operation_id_full_hex.as_str());
                        cancelled_or_executed.insert(operation_id_full_hex.clone());
                    }
                    _ => {}
                }
            }
        }
        // Pending = scheduled - (cancelled ∪ executed).
        let pending: Vec<(String, String, String)> = scheduled_ops
            .into_iter()
            .filter(|(op_id, _)| !cancelled_or_executed.contains(op_id))
            .map(|(op_id, (request_id, tl_redacted))| (op_id, request_id, tl_redacted))
            .collect();
        Ok(pending)
    }
}

/// Collects every pin record of `files`, deduplicated to the newest row per
/// `(rule_id, smart_account_redacted)` and sorted by that key.
///
/// Files come newest first; within a file the last row of a key wins, and
/// across files the newest file's.
fn all_pin_records(
    files: BoundedFiles<'_>,
) -> Result<Vec<(u32, String, ContextRulePinRecord)>, AuditLogIntegrityError> {
    let mut latest: std::collections::HashMap<(u32, String), ContextRulePinRecord> =
        std::collections::HashMap::new();
    for file in files {
        let file = file?;
        let mut this_file: std::collections::HashMap<(u32, String), ContextRulePinRecord> =
            std::collections::HashMap::new();
        for (line, entry) in &file.rows {
            if let Some(row) = PinRow::from_event_kind(&entry.event_kind) {
                this_file.insert(
                    (row.rule_id, row.smart_account.to_owned()),
                    row.record(*line)?,
                );
            }
        }
        // Keep the first-seen (newest) row per key, so a reinstall in a newer
        // file wins over an older file's.
        for (key, record) in this_file {
            latest.entry(key).or_insert(record);
        }
    }
    let mut result: Vec<(u32, String, ContextRulePinRecord)> = latest
        .into_iter()
        .map(|((rule_id, account), record)| (rule_id, account, record))
        .collect();
    result.sort_by_key(|(rule_id, account, _)| (*rule_id, account.clone()));
    Ok(result)
}

/// Every pin record of the log at `log_path`, as
/// [`AuditReader::scan_all_context_rule_pin_records`] returns them, read
/// without a writer and without its bound.
///
/// Takes no lock: it serves the startup advisory when no writer can be
/// opened, for example on a keyed log whose key did not load, and its result
/// feeds operator-facing warnings only. Each file's in-file chain, the bridge
/// between consecutive files, and quarantine rows are applied; rows past the
/// last verified tip are read like every other row, since there is no writer
/// to name that tip.
///
/// # Errors
///
/// The integrity errors of the reader's walk: `ChainBroken`, `RotationGap`,
/// `ParseError`, `Io`.
pub fn scan_all_context_rule_pin_records_unanchored(
    log_path: &Path,
) -> Result<Vec<(u32, String, ContextRulePinRecord)>, AuditLogIntegrityError> {
    all_pin_records(unbounded_files(log_path)?)
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Returns log files in scan order: active file first, then rotated siblings
/// newest-first (by filename / timestamp, descending).
///
/// This is the reverse of `verify.rs::collect_file_chain` (which returns
/// oldest-first). We want newest-first to stop at the first match without
/// scanning the entire chain.
///
/// # Filename-ordering invariant
///
/// Rotated filenames use the strict `<stem>.<YYYYMMDDTHHMMSSmmm>` pattern,
/// with a fixed-width counter appended when the clock does not place a
/// rotation after the newest archive. The writer names each archive so it
/// sorts after every existing one (`audit_log/writer.rs::next_archive_suffix`),
/// so the lexicographic order equals the order the archives were created in.
/// Consequently, `rotated.sort(); rotated.reverse()` correctly yields
/// newest-first ordering.
///
/// This invariant is verified by the `rotation_suffix_lex_sort_matches_chronological`
/// unit test in `audit_log/rotation.rs::tests`.
///
/// # Rotation-window tolerance
///
/// If the active file is absent from the listing but rotated siblings are
/// present, re-scans the directory a small bounded number of times while the
/// writer's sidecar lock is observably held by a live writer, tolerating the
/// microsecond-scale window `AuditWriter::rotate` opens between archiving the
/// old active file and creating the new one — see the module-level "Reader
/// consistency posture" section. This never masks a genuine gap: callers
/// still see the active file missing (and, when siblings are present, still
/// get `RotationGap`) if it never reappears within the bound.
pub(super) fn collect_files_newest_first(
    log_path: &Path,
) -> Result<Vec<PathBuf>, AuditLogIntegrityError> {
    let chain = scan_files_newest_first(log_path)?;
    if chain.len() > 1 && !chain[0].exists() {
        return wait_out_transient_rotation_window(
            log_path,
            chain,
            |chain: &Vec<PathBuf>| !chain[0].exists(),
            || scan_files_newest_first(log_path),
        );
    }
    Ok(chain)
}

/// Performs one directory scan, returning the active file first followed by
/// rotated siblings newest-first. See `collect_files_newest_first` for the
/// scan-order contract; this function performs no retry.
fn scan_files_newest_first(log_path: &Path) -> Result<Vec<PathBuf>, AuditLogIntegrityError> {
    let dir = log_path
        .parent()
        .ok_or_else(|| AuditLogIntegrityError::PathContract {
            detail: "audit log path must have a parent directory component".to_owned(),
        })?;
    let stem = log_path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| AuditLogIntegrityError::PathContract {
            detail: "audit log path has no UTF-8 file name".to_owned(),
        })?;

    let mut rotated: Vec<PathBuf> = Vec::new();
    if dir.exists() {
        for entry_result in std::fs::read_dir(dir).map_err(AuditLogIntegrityError::Io)? {
            let path = entry_result.map_err(AuditLogIntegrityError::Io)?.path();
            let is_rotated = path
                .file_name()
                .and_then(|s| s.to_str())
                .map(|name| is_rotated_sibling(stem, name))
                .unwrap_or(false);
            if is_rotated {
                rotated.push(path);
            }
        }
    }

    // Sort rotated files oldest-first, then reverse to get newest-first.
    rotated.sort();
    rotated.reverse();

    // Scan order: active file first, then rotated newest-first.
    let mut chain = vec![log_path.to_path_buf()];
    chain.extend(rotated);
    Ok(chain)
}

// ── Bounded walk ─────────────────────────────────────────────────────────────

/// [`AuditLogIntegrityError::ChainBroken`] reason for a file whose last entry
/// is not the entry the next newer file chains from, or whose first entry
/// does not chain from the segment start the writer holds.
const BRIDGE_MISMATCH_REASON: &str = "bridge_mismatch";

/// [`AuditLogIntegrityError::ChainBroken`] reason for an active file whose
/// last entry inside the bound is not the writer's tip.
const TIP_MISMATCH_REASON: &str = "tip_mismatch";

/// One file of a reader walk, newest file first.
struct BoundedFile {
    /// The file's basename.
    name: String,
    /// The file's entries inside the walk's bound, oldest first, with their
    /// one-based lines, and without the entries an `audit_entries_quarantined`
    /// row covers.
    rows: Vec<(usize, AuditEntry)>,
}

/// What the writer verified about the active file: where it ends, what its
/// first entry chains from, and its last entry's hash.
struct WriterBound {
    end_offset: u64,
    segment_start: String,
    last_hash: String,
}

/// The files of one log, newest first, read and checked one at a time.
///
/// Built by [`bounded_files`] under a writer guard, or by
/// [`unbounded_files`] without one. Each item is one file's rows; the first
/// error ends the walk.
struct BoundedFiles<'k> {
    log_path: PathBuf,
    files: std::vec::IntoIter<PathBuf>,
    has_rotated: bool,
    bound: Option<WriterBound>,
    hmac_key: Option<&'k [u8; 32]>,
    /// The hash the next older file must end on, once a newer file named it.
    expected_tip: Option<String>,
    failed: bool,
}

/// The writer-bounded walk of the log `writer` holds, under the caller's guard
/// of that writer.
///
/// The active file is read only up to [`AuditWriter::end_offset`]. Its first
/// entry must chain from the segment start the writer holds and its last
/// entry inside the bound must hash to [`AuditWriter::last_entry_hash`]; an
/// empty bound must have the segment start as the writer's tip. Each archive's
/// in-file chain must verify, and its last entry must hash to the
/// `previous_entry_hash` of the first entry of the next newer file, or to the
/// segment start when the active file is empty. A broken link is
/// [`AuditLogIntegrityError::ChainBroken`] with reason `bridge_mismatch` or
/// `tip_mismatch`. Rows an `audit_entries_quarantined` row inside the bound
/// covers are dropped. No key is read; `hmac_key` checks each file's
/// chain-root sidecar when given.
///
/// # Errors
///
/// [`AuditLogIntegrityError::PathContract`] and the listing errors of the
/// file walk.
fn bounded_files<'k>(
    writer: &AuditWriter,
    hmac_key: Option<&'k [u8; 32]>,
) -> Result<BoundedFiles<'k>, AuditLogIntegrityError> {
    let bound = WriterBound {
        end_offset: writer.end_offset(),
        segment_start: super::chain::encode_hash(writer.segment_start_hash()),
        last_hash: writer.last_entry_hash().to_owned(),
    };
    walk_files(writer.path(), Some(bound), hmac_key)
}

/// The walk of the log at `log_path` without a writer: the whole active file
/// is read, and no tip is checked. Chains, bridges and quarantine rows apply
/// as in [`bounded_files`].
///
/// # Errors
///
/// [`AuditLogIntegrityError::PathContract`] and the listing errors of the
/// file walk.
fn unbounded_files(log_path: &Path) -> Result<BoundedFiles<'static>, AuditLogIntegrityError> {
    walk_files(log_path, None, None)
}

fn walk_files<'k>(
    log_path: &Path,
    bound: Option<WriterBound>,
    hmac_key: Option<&'k [u8; 32]>,
) -> Result<BoundedFiles<'k>, AuditLogIntegrityError> {
    let files = collect_files_newest_first(log_path)?;
    Ok(BoundedFiles {
        log_path: log_path.to_path_buf(),
        has_rotated: files.len() > 1,
        files: files.into_iter(),
        bound,
        hmac_key,
        expected_tip: None,
        failed: false,
    })
}

impl Iterator for BoundedFiles<'_> {
    type Item = Result<BoundedFile, AuditLogIntegrityError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        let path = self.files.next()?;
        let result = if path == self.log_path {
            self.read_active(&path)
        } else {
            self.read_archive(&path)
        };
        self.failed = result.is_err();
        Some(result)
    }
}

impl BoundedFiles<'_> {
    /// Reads the active file, the first item of every walk.
    fn read_active(&mut self, path: &Path) -> Result<BoundedFile, AuditLogIntegrityError> {
        let name = basename(path);
        if !path.exists() {
            // A writer always creates the active file, so its absence beside
            // archives is a gap, never permission to read archived rows as the
            // newest state.
            if self.has_rotated {
                return Err(AuditLogIntegrityError::RotationGap { file: name });
            }
            if let Some(bound) = &self.bound
                && (bound.end_offset != 0 || bound.last_hash != bound.segment_start)
            {
                return Err(chain_broken(&name, 1, TIP_MISMATCH_REASON));
            }
            return Ok(BoundedFile {
                name,
                rows: Vec::new(),
            });
        }
        let limit = self.bound.as_ref().map(|bound| bound.end_offset);
        let first_prev = match &self.bound {
            Some(bound) => Some(bound.segment_start.clone()),
            None if !self.has_rotated => Some(ZERO_BLOCK_HASH.to_owned()),
            None => None,
        };
        let read = read_file_rows(path, limit, first_prev.as_deref(), self.hmac_key)?;
        if let Some(bound) = &self.bound {
            let tip = read.last_hash.as_deref().unwrap_or(&bound.segment_start);
            if tip != bound.last_hash {
                return Err(chain_broken(&name, read.last_line, TIP_MISMATCH_REASON));
            }
        }
        self.expected_tip = match (&read.first_prev, &self.bound) {
            (Some(first_prev), _) => Some(first_prev.clone()),
            (None, Some(bound)) => Some(bound.segment_start.clone()),
            (None, None) => None,
        };
        Ok(BoundedFile {
            name,
            rows: drop_quarantined(read.rows),
        })
    }

    /// Reads one archive, checking that it ends where the next newer file
    /// starts.
    fn read_archive(&mut self, path: &Path) -> Result<BoundedFile, AuditLogIntegrityError> {
        let name = basename(path);
        if !path.exists() {
            return Err(AuditLogIntegrityError::RotationGap { file: name });
        }
        let read = read_file_rows(path, None, None, self.hmac_key)?;
        if let Some(expected) = &self.expected_tip
            && read.last_hash.as_deref() != Some(expected.as_str())
        {
            return Err(chain_broken(&name, read.last_line, BRIDGE_MISMATCH_REASON));
        }
        self.expected_tip = read.first_prev.clone();
        Ok(BoundedFile {
            name,
            rows: drop_quarantined(read.rows),
        })
    }
}

/// One file's entries as read, before quarantine filtering.
#[derive(Debug)]
struct FileRows {
    rows: Vec<(usize, AuditEntry)>,
    /// The first entry's `previous_entry_hash`.
    first_prev: Option<String>,
    /// The last entry's chain hash.
    last_hash: Option<String>,
    /// The last entry's one-based line, or 1 for a file with no entry.
    last_line: usize,
}

/// Reads the entries of `path`, up to `limit` bytes when given, verifying the
/// in-file chain: every entry after the first names the hash of the entry
/// before it, and the first names `first_prev` when given. With `hmac_key`,
/// the first entry's chain-root sidecar must verify.
///
/// A `limit` is where the writer's last entry ends, just past its newline, so
/// bytes there that do not end a line show the file changed inside the bound:
/// [`AuditLogIntegrityError::ChainBroken`] with reason `tip_mismatch`.
fn read_file_rows(
    path: &Path,
    limit: Option<u64>,
    first_prev: Option<&str>,
    hmac_key: Option<&[u8; 32]>,
) -> Result<FileRows, AuditLogIntegrityError> {
    use std::io::Read as _;

    let name = basename(path);
    let file = open_regular_file(path)?;
    let mut reader = BufReader::new(file.take(limit.unwrap_or(u64::MAX)));
    let mut rows = Vec::new();
    let mut expected_prev = first_prev.map(str::to_owned);
    let mut first = None;
    let mut last_hash = None;
    let mut last_line = 1;
    let mut raw = Vec::new();
    let mut line_number = 0usize;
    loop {
        raw.clear();
        if reader
            .read_until(b'\n', &mut raw)
            .map_err(AuditLogIntegrityError::Io)?
            == 0
        {
            break;
        }
        line_number += 1;
        if limit.is_some() && raw.last() != Some(&b'\n') {
            return Err(chain_broken(&name, line_number, TIP_MISMATCH_REASON));
        }
        if raw.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let parse_error = |detail: String| AuditLogIntegrityError::ParseError {
            line: line_number,
            detail,
        };
        let entry: AuditEntry =
            serde_json::from_slice(&raw).map_err(|e| parse_error(e.to_string()))?;
        let body = entry
            .canonical_json_body()
            .map_err(|e| parse_error(e.to_string()))?;
        if first.is_none() {
            if let Some(key) = hmac_key {
                super::verify::verify_root_sidecar(path, key, &body)?;
            }
            first = Some(entry.previous_entry_hash.clone());
        }
        if let Some(expected) = &expected_prev
            && entry.previous_entry_hash != *expected
        {
            let reason = if rows.is_empty() {
                BRIDGE_MISMATCH_REASON
            } else {
                "previous_entry_hash mismatch"
            };
            return Err(chain_broken(&name, line_number, reason));
        }
        let hash = compute_entry_hash(&body, &entry.previous_entry_hash)
            .map_err(|e| parse_error(format!("chain hash computation failed: {e}")))?;
        expected_prev = Some(hash.clone());
        last_hash = Some(hash);
        last_line = line_number;
        rows.push((line_number, entry));
    }
    Ok(FileRows {
        rows,
        first_prev: first,
        last_hash,
        last_line,
    })
}

/// Drops the entries the `audit_entries_quarantined` rows of one file cover,
/// as [`super::verify::quarantine_coverage`] decides it: a quarantine row
/// covers the entries directly before it only when no later quarantine row
/// that takes effect covers it.
fn drop_quarantined(rows: Vec<(usize, AuditEntry)>) -> Vec<(usize, AuditEntry)> {
    let quarantine: Vec<Option<u64>> = rows
        .iter()
        .map(|(_, entry)| match entry.event_kind {
            EventKind::AuditEntriesQuarantined { quarantined_count } => Some(quarantined_count),
            _ => None,
        })
        .collect();
    let covered = super::verify::quarantine_coverage(&quarantine);
    rows.into_iter()
        .zip(covered)
        .filter_map(|(row, covered)| (!covered).then_some(row))
        .collect()
}

/// The basename of `path`, or an empty string.
fn basename(path: &Path) -> String {
    path.file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_owned()
}

fn chain_broken(file: &str, line: usize, reason: &'static str) -> AuditLogIntegrityError {
    AuditLogIntegrityError::ChainBroken {
        line,
        file: file.to_owned(),
        reason,
    }
}

/// The newest signer-set state row of `file` matching `key`.
///
/// Every version-2 snapshot in the file must validate, for every rule and
/// account, so every reader of the file sees the same verdict.
fn latest_signer_set_view(
    file: &BoundedFile,
    key: SignerSetKey<'_>,
) -> Result<Option<SignerSetViewPayload>, AuditLogIntegrityError> {
    let mut best = None;
    for (line, entry) in &file.rows {
        if let Some(snapshot) = v2_snapshot(&entry.event_kind)
            && let Err(e) = snapshot.validate()
        {
            return Err(AuditLogIntegrityError::ParseError {
                line: *line,
                detail: e.to_string(),
            });
        }
        if let Some(view) = extract_signer_set_view(&entry.event_kind, key) {
            let body =
                entry
                    .canonical_json_body()
                    .map_err(|e| AuditLogIntegrityError::ParseError {
                        line: *line,
                        detail: e.to_string(),
                    })?;
            let row_hash: [u8; 32] = Sha256::digest(&body).into();
            best = Some(SignerSetViewPayload::new(
                view,
                row_hash,
                *line,
                file.name.clone(),
            ));
        }
    }
    Ok(best)
}

/// The pin record of the newest pin row of `file` for
/// `(rule_id, smart_account_redacted)`, of either version.
fn latest_pin_record(
    file: &BoundedFile,
    rule_id: u32,
    smart_account_redacted: &str,
) -> Result<Option<ContextRulePinRecord>, AuditLogIntegrityError> {
    let mut best = None;
    for (line, entry) in &file.rows {
        // The file is read oldest to newest, so the last match is the newest
        // record.
        if let Some(row) = PinRow::from_event_kind(&entry.event_kind)
            && row.rule_id == rule_id
            && row.smart_account == smart_account_redacted
        {
            best = Some(row.record(*line)?);
        }
    }
    Ok(best)
}

/// The keys a signer-set state row is matched on: the rule, the redacted
/// account for version-1 rows and the account digest for version-2 rows.
#[derive(Clone, Copy)]
struct SignerSetKey<'a> {
    rule_id: u32,
    smart_account_redacted: &'a str,
    account_digest: &'a [u8; 32],
}

/// The snapshot of a version-2 signer-set state row, for any rule or account.
fn v2_snapshot(kind: &EventKind) -> Option<&SignerSetSnapshotV2> {
    match kind {
        EventKind::SaSignerSetBaselinedV2 { snapshot, .. }
        | EventKind::SaSignerAddedV2 { snapshot, .. }
        | EventKind::SaSignerRemovedV2 { snapshot, .. }
        | EventKind::SaThresholdChangedV2 { snapshot, .. } => Some(snapshot),
        _ => None,
    }
}

/// Extracts the [`SignerSetView`] of a signer-set state row that matches
/// `key`: a version-1 row on `(rule_id, smart_account_redacted)`, a
/// version-2 row on `(rule_id, account_digest)`.
///
/// Returns `None` if the event is not a signer-set state row or does not
/// match its key.
///
/// # Validation contract
///
/// A returned version-2 snapshot has passed
/// [`SignerSetSnapshotV2::validate`] in the scan. A returned version-1
/// state is structurally valid as deserialized: deserialization enforces the
/// variant tag and field shapes (JSON type correctness). However,
/// the `External` variant's `verifier_contract` C-strkey is NOT validated as a
/// well-formed strkey here — that validation happens downstream in
/// [`signer_set::signer_pubkey_canonical_body`] when the canonical body is
/// computed. Consumers that call `signer_pubkey_canonical_body` on values
/// derived from this function must handle the
/// [`signer_set::SignerSetCanonicalBodyError`] error path.
fn extract_signer_set_view(kind: &EventKind, key: SignerSetKey<'_>) -> Option<SignerSetView> {
    let SignerSetKey {
        rule_id,
        smart_account_redacted,
        account_digest,
    } = key;
    match kind {
        EventKind::SaSignerAdded {
            rule_id: rid,
            smart_account_redacted: sa,
            resulting_signer_count,
            resulting_threshold,
            resulting_signer_ids,
            resulting_signer_pubkeys,
            ..
        } if *rid == rule_id && sa == smart_account_redacted => {
            Some(SignerSetView::V1(ObservedSignerSet {
                signer_count: *resulting_signer_count,
                threshold: *resulting_threshold,
                signer_ids: resulting_signer_ids.clone(),
                signer_pubkeys: resulting_signer_pubkeys.clone(),
            }))
        }
        EventKind::SaSignerRemoved {
            rule_id: rid,
            smart_account_redacted: sa,
            resulting_signer_count,
            resulting_threshold,
            resulting_signer_ids,
            resulting_signer_pubkeys,
            ..
        } if *rid == rule_id && sa == smart_account_redacted => {
            Some(SignerSetView::V1(ObservedSignerSet {
                signer_count: *resulting_signer_count,
                threshold: *resulting_threshold,
                signer_ids: resulting_signer_ids.clone(),
                signer_pubkeys: resulting_signer_pubkeys.clone(),
            }))
        }
        EventKind::SaThresholdChanged {
            rule_id: rid,
            smart_account_redacted: sa,
            resulting_threshold,
            resulting_signer_count,
            resulting_signer_ids,
            resulting_signer_pubkeys,
            ..
        } if *rid == rule_id && sa == smart_account_redacted => {
            Some(SignerSetView::V1(ObservedSignerSet {
                signer_count: *resulting_signer_count,
                threshold: *resulting_threshold,
                signer_ids: resulting_signer_ids.clone(),
                signer_pubkeys: resulting_signer_pubkeys.clone(),
            }))
        }
        EventKind::SaSignerSetBaselined {
            rule_id: rid,
            smart_account_redacted: sa,
            observed_signer_count,
            observed_threshold,
            observed_signer_ids,
            observed_signer_pubkeys,
            ..
        } if *rid == rule_id && sa == smart_account_redacted => {
            Some(SignerSetView::V1(ObservedSignerSet {
                signer_count: *observed_signer_count,
                threshold: *observed_threshold,
                signer_ids: observed_signer_ids.clone(),
                signer_pubkeys: observed_signer_pubkeys.clone(),
            }))
        }
        EventKind::SaSignerSetBaselinedV2 {
            rule_id: rid,
            account_digest: digest,
            snapshot,
            ..
        }
        | EventKind::SaSignerAddedV2 {
            rule_id: rid,
            account_digest: digest,
            snapshot,
            ..
        }
        | EventKind::SaSignerRemovedV2 {
            rule_id: rid,
            account_digest: digest,
            snapshot,
            ..
        }
        | EventKind::SaThresholdChangedV2 {
            rule_id: rid,
            account_digest: digest,
            snapshot,
            ..
        } if *rid == rule_id && digest == account_digest => {
            Some(SignerSetView::V2(snapshot.clone()))
        }
        _ => None,
    }
}

/// Opens a path as a regular file (rejects symlinks and directories).
fn open_regular_file(path: &Path) -> Result<std::fs::File, AuditLogIntegrityError> {
    let metadata = std::fs::symlink_metadata(path).map_err(AuditLogIntegrityError::Io)?;
    if !metadata.file_type().is_file() {
        return Err(AuditLogIntegrityError::NonRegularFileLogPath {
            path: path.to_path_buf(),
        });
    }
    std::fs::File::open(path).map_err(AuditLogIntegrityError::Io)
}

// ─────────────────────────────────────────────────────────────────────────────
// Pending value-action lookup
// ─────────────────────────────────────────────────────────────────────────────

/// What a `value_action_pending` row recorded for one submission.
///
/// The reconciliation surfaces settle a submission whose confirmation never
/// arrived, and the row they write has to carry the SAME value legs the gate
/// sized. Those legs were written once, by the pending row, so they are read
/// back from it rather than re-derived.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PendingValueAction {
    /// Witness preserved from the pending row during reconciliation.
    pub witness: Option<super::schema::CrossCheckRecord>,
    /// The verb that made the submission, as it appears on the outer entry.
    pub tool: String,
    /// CAIP-2 chain identifier from the outer entry.
    pub chain_id: Option<String>,
    /// The value legs the policy gate sized.
    pub legs: Vec<ValueLegRecord>,
    /// The commit nonce prefix the pending row carried.
    pub nonce_id: Option<String>,
    /// The submission gate's decision from the pending row.
    pub policy_decision: super::PolicyDecision,
    /// Approval nonce bound to the pending submission.
    pub approval_nonce: Option<String>,
}

/// What a submission's value action still owes the retained audit history.
///
/// Reconciliation is an operator-repeatable verb. A settled row anywhere in the
/// retained history means the submission is already accounted for, which is
/// what keeps a second run from appending a second row for one spend.
/// [`try_value_action_settlement`] states which files the lookup reads and the
/// limits of that read.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(
    clippy::large_enum_variant,
    reason = "one owned pending row preserves the recovery API"
)]
pub enum ValueActionSettlement {
    /// A retained pending row is unsettled. Its value legs are the ones the
    /// policy gate sized.
    Owed(PendingValueAction),
    /// No settlement row and no pending row for the submission survives in the
    /// retained history, so the submission is still owed a settled row and its
    /// legs are not recoverable.
    ///
    /// The row is written anyway, with no legs, because the submission's
    /// outcome belongs in the log whether or not its sizing survived. Legs from
    /// a different submission would be worse than none.
    OwedWithoutLegs,
    /// A settled row already accounts for the submission.
    Settled,
}

/// Reports what the value action for `envelope_hash` still owes the log.
///
/// A match is a `value_action_pending`, `value_action_submitted`, or
/// `value_action_failed` row carrying the hash. Tool-invocation and
/// operator-clear rows that carry it are skipped, so the walk never stops in a
/// file that holds no settlement row. Files are visited newest first, and the
/// walk stops at the first file holding a match, leaving older files
/// unvisited. The last match in that file wins.
///
/// `writer` is the caller's guard of the profile's writer, held across the
/// lookup and the append that follows it. The lookup reads the writer's
/// bounded walk: the active file only up to the writer's verified tip, each
/// archive bridged to the file after it, and quarantined rows dropped. A row
/// appended outside the writer, past that tip, is never read. No key is read
/// and no chain-root sidecar is checked.
///
/// The eleventh rotation deletes the oldest archive, so a submission whose
/// rows only that archive held reads as
/// [`ValueActionSettlement::OwedWithoutLegs`].
///
/// # Errors
///
/// Returns a read, parse, rotation-gap, in-file chain, bridge, or tip
/// integrity error.
pub fn try_value_action_settlement(
    writer: &AuditWriter,
    envelope_hash: &str,
) -> Result<ValueActionSettlement, AuditLogIntegrityError> {
    Ok(
        find_latest_value_row(writer, envelope_hash, |entry| match &entry.event_kind {
            EventKind::ValueActionSubmitted { .. } | EventKind::ValueActionFailed { .. } => {
                Some(ValueActionSettlement::Settled)
            }
            EventKind::ValueActionPending {
                witness,
                legs,
                approval_nonce,
                ..
            } => Some(ValueActionSettlement::Owed(PendingValueAction {
                witness: witness.clone(),
                legs: legs.clone(),
                tool: entry.tool.clone(),
                chain_id: entry.chain_id.clone(),
                nonce_id: entry.nonce_id.clone(),
                policy_decision: entry.policy_decision.clone(),
                approval_nonce: approval_nonce.clone(),
            })),
            _ => None,
        })?
        .unwrap_or(ValueActionSettlement::OwedWithoutLegs),
    )
}

/// Reports whether the retained history carries an operator-clear row for
/// `envelope_hash`.
///
/// `stellar-agent tx receipt clear` writes its row before it marks the
/// receipt, so that a failure at the mark leaves a reservation already
/// released rather than one stranded under a receipt no verb accepts again.
/// The cost of that order is that a re-run after such a failure would append a
/// second row for one clear. This lookup is what makes the re-run complete the
/// mark instead.
///
/// The walk, the writer guard and the limits are those of
/// [`try_value_action_settlement`], with a `submission_receipt_cleared` row as
/// the only match.
///
/// # Errors
///
/// Returns a read, parse, rotation-gap, in-file chain, bridge, or tip
/// integrity error.
pub fn try_submission_receipt_cleared_exists(
    writer: &AuditWriter,
    envelope_hash: &str,
) -> Result<bool, AuditLogIntegrityError> {
    Ok(find_latest_value_row(writer, envelope_hash, |entry| {
        matches!(entry.event_kind, EventKind::SubmissionReceiptCleared { .. }).then_some(())
    })?
    .is_some())
}

/// Walks the writer's bounded files newest first and returns what `select`
/// maps from the last matching row of the first file that holds one.
///
/// A missing active file is an empty log only while no archive exists. With
/// archives it is a rotation gap, so archived rows never stand in for the
/// active file.
fn find_latest_value_row<T>(
    writer: &AuditWriter,
    envelope_hash: &str,
    select: impl Fn(&AuditEntry) -> Option<T>,
) -> Result<Option<T>, AuditLogIntegrityError> {
    for file in bounded_files(writer, None)? {
        let found = file?
            .rows
            .iter()
            .rev()
            .filter(|(_, entry)| entry.envelope_hash.as_deref() == Some(envelope_hash))
            .find_map(|(_, entry)| select(entry));
        if found.is_some() {
            return Ok(found);
        }
    }
    Ok(None)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only"
    )]
    use super::*;
    use crate::audit_log::{
        entry::{AuditEntry, NewToolInvocation},
        schema::PolicyDecision,
        signer_set::{
            BaselineReason, SignerEntryV2, SignerIdentityV2, SignerPubkey, SignerSetSnapshotV2,
            ThresholdObservation,
        },
        writer::{
            AuditWriter, ROTATION_WINDOW_RETRY_ATTEMPTS, install_rotation_window_retry_observer,
        },
    };
    use crate::observability::RedactedStrkey;
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::sync::Arc;
    use tempfile::TempDir;

    // ── Helper: build a log path in a tempdir ─────────────────────────────────

    fn tmp_log(dir: &TempDir) -> PathBuf {
        dir.path().join("audit.jsonl")
    }

    fn open_writer(path: PathBuf) -> Arc<Mutex<AuditWriter>> {
        Arc::new(Mutex::new(AuditWriter::open(path, None).unwrap()))
    }

    // ── Helpers: value-action rows for the settlement lookup ─────────────────

    const SETTLE_ENVELOPE: &str = "aa";
    const OTHER_ENVELOPE: &str = "bb";

    fn pending_row(envelope_hash: &str) -> AuditEntry {
        AuditEntry::new_value_action_pending(
            "stellar_pay",
            Some("stellar:testnet".to_owned()),
            vec![ValueLegRecord {
                action: crate::audit_log::schema::ValueActionKind::Payment,
                amount: Some(10_000_000),
                asset: Some("native".to_owned()),
                destination_redacted: Some("GDNYY...B2PKP".to_owned()),
            }],
            "6ba7aaac...69060003",
            "GAOTC...PZ6X4",
            7,
            PolicyDecision::Allow,
            Some(envelope_hash.to_owned()),
            None,
            None,
            "req-pending",
            None,
        )
    }

    fn submitted_row(envelope_hash: &str) -> AuditEntry {
        AuditEntry::new_value_action_submitted(
            "stellar_pay",
            Some("stellar:testnet".to_owned()),
            vec![],
            "6ba7aaac...69060003",
            9,
            PolicyDecision::Allow,
            Some(envelope_hash.to_owned()),
            None,
            None,
            "req-submitted",
            None,
        )
    }

    /// A pending row with nothing after it is owed a settled row, and reports
    /// the legs the gate sized.
    #[test]
    fn a_pending_row_awaiting_settlement_is_found_with_its_legs() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());
        writer
            .lock()
            .unwrap()
            .write_entry(pending_row(SETTLE_ENVELOPE))
            .unwrap();

        let ValueActionSettlement::Owed(found) =
            try_value_action_settlement(&writer.lock().unwrap(), SETTLE_ENVELOPE).unwrap()
        else {
            panic!("a pending row with no settled row is owed one");
        };
        assert_eq!(found.tool, "stellar_pay");
        assert_eq!(found.chain_id.as_deref(), Some("stellar:testnet"));
        assert_eq!(found.legs.len(), 1, "the gate's legs are carried through");
    }

    /// A submission a settled row already accounts for is owed nothing.
    ///
    /// Reconciliation is repeatable by the operator, and a second run that
    /// appended a second row would count one spend twice.
    #[test]
    fn a_settled_submission_is_owed_no_further_row() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());
        {
            let mut guard = writer.lock().unwrap();
            guard.write_entry(pending_row(SETTLE_ENVELOPE)).unwrap();
            guard.write_entry(submitted_row(SETTLE_ENVELOPE)).unwrap();
        }

        assert_eq!(
            try_value_action_settlement(&writer.lock().unwrap(), SETTLE_ENVELOPE).unwrap(),
            ValueActionSettlement::Settled,
            "a submission already accounted for is owed no second row"
        );
    }

    /// A settled row for a different submission does not settle this one.
    #[test]
    fn another_submissions_settled_row_does_not_settle_this_one() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());
        {
            let mut guard = writer.lock().unwrap();
            guard.write_entry(pending_row(SETTLE_ENVELOPE)).unwrap();
            guard.write_entry(pending_row(OTHER_ENVELOPE)).unwrap();
            guard.write_entry(submitted_row(OTHER_ENVELOPE)).unwrap();
        }

        let guard = writer.lock().unwrap();
        assert!(
            matches!(
                try_value_action_settlement(&guard, SETTLE_ENVELOPE).unwrap(),
                ValueActionSettlement::Owed(_)
            ),
            "the settled row names a different submission"
        );
        assert_eq!(
            try_value_action_settlement(&guard, OTHER_ENVELOPE).unwrap(),
            ValueActionSettlement::Settled
        );
    }

    /// A submission absent from retained history is owed a row without legs.
    #[test]
    fn an_absent_submission_is_owed_a_row_without_legs() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());
        writer
            .lock()
            .unwrap()
            .write_entry(pending_row(OTHER_ENVELOPE))
            .unwrap();

        assert_eq!(
            try_value_action_settlement(&writer.lock().unwrap(), SETTLE_ENVELOPE).unwrap(),
            ValueActionSettlement::OwedWithoutLegs
        );
    }

    fn cleared_row() -> AuditEntry {
        AuditEntry::new_submission_receipt_cleared(
            "tx_receipt_clear",
            Some("stellar:testnet".to_owned()),
            "hash...tail",
            "pending",
            true,
            None,
            Some(SETTLE_ENVELOPE.to_owned()),
            "clear",
        )
    }

    #[test]
    fn a_pending_row_in_an_archive_keeps_its_legs() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());
        let mut guard = writer.lock().unwrap();
        guard.write_entry(pending_row(SETTLE_ENVELOPE)).unwrap();
        guard.force_rotate_for_test().unwrap();
        guard.write_entry(cleared_row()).unwrap();
        let ValueActionSettlement::Owed(found) =
            try_value_action_settlement(&guard, SETTLE_ENVELOPE).unwrap()
        else {
            panic!("the archived pending row is still owed with its legs");
        };
        assert_eq!(found.legs.len(), 1);
        assert_eq!(found.legs[0].amount, Some(10_000_000));
    }

    #[test]
    fn a_settled_row_in_an_archive_prevents_another_settlement() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());
        let mut guard = writer.lock().unwrap();
        guard.write_entry(pending_row(SETTLE_ENVELOPE)).unwrap();
        guard.write_entry(submitted_row(SETTLE_ENVELOPE)).unwrap();
        guard.force_rotate_for_test().unwrap();
        guard.write_entry(cleared_row()).unwrap();
        assert_eq!(
            try_value_action_settlement(&guard, SETTLE_ENVELOPE).unwrap(),
            ValueActionSettlement::Settled
        );
    }

    #[test]
    fn a_cleared_row_is_found_in_active_and_archived_history() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());
        let mut guard = writer.lock().unwrap();
        guard.write_entry(cleared_row()).unwrap();
        assert!(try_submission_receipt_cleared_exists(&guard, SETTLE_ENVELOPE).unwrap());
        guard.force_rotate_for_test().unwrap();
        assert!(try_submission_receipt_cleared_exists(&guard, SETTLE_ENVELOPE).unwrap());
    }

    #[test]
    fn a_broken_visited_archive_refuses_both_lookups() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());
        let mut guard = writer.lock().unwrap();
        guard.write_entry(pending_row(SETTLE_ENVELOPE)).unwrap();
        guard.write_entry(cleared_row()).unwrap();
        guard.force_rotate_for_test().unwrap();
        let archive = collect_files_newest_first(&path).unwrap().remove(1);
        let raw = std::fs::read_to_string(&archive).unwrap();
        let mut rows: Vec<AuditEntry> = raw
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        rows[1].tool = "changed".to_owned();
        let changed = rows
            .iter()
            .map(|row| serde_json::to_string(row).unwrap() + "\n")
            .collect::<String>();
        std::fs::write(&archive, changed).unwrap();
        assert!(matches!(
            try_value_action_settlement(&guard, SETTLE_ENVELOPE),
            Err(AuditLogIntegrityError::ChainBroken { line: 3, .. })
        ));
        assert!(matches!(
            try_submission_receipt_cleared_exists(&guard, SETTLE_ENVELOPE),
            Err(AuditLogIntegrityError::ChainBroken { line: 3, .. })
        ));
    }

    #[test]
    fn a_missing_active_file_with_archives_refuses_both_lookups() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());
        let mut guard = writer.lock().unwrap();
        guard.write_entry(pending_row(SETTLE_ENVELOPE)).unwrap();
        guard.force_rotate_for_test().unwrap();
        std::fs::remove_file(&path).unwrap();
        assert!(matches!(
            try_value_action_settlement(&guard, SETTLE_ENVELOPE),
            Err(AuditLogIntegrityError::RotationGap { .. })
        ));
        assert!(matches!(
            try_submission_receipt_cleared_exists(&guard, SETTLE_ENVELOPE),
            Err(AuditLogIntegrityError::RotationGap { .. })
        ));
    }

    #[test]
    fn a_matching_file_leaves_older_corrupt_archives_unvisited() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());
        let mut guard = writer.lock().unwrap();
        guard.write_entry(pending_row(OTHER_ENVELOPE)).unwrap();
        guard.force_rotate_for_test().unwrap();
        guard.write_entry(submitted_row(SETTLE_ENVELOPE)).unwrap();
        guard.write_entry(cleared_row()).unwrap();
        let archive = collect_files_newest_first(&path).unwrap().remove(1);
        std::fs::write(&archive, "corrupt\n").unwrap();
        assert_eq!(
            try_value_action_settlement(&guard, SETTLE_ENVELOPE).unwrap(),
            ValueActionSettlement::Settled
        );
        assert!(try_submission_receipt_cleared_exists(&guard, SETTLE_ENVELOPE).unwrap());
    }

    /// A one-file log whose only row names `predecessor`, rewritten in place
    /// under the writer that appended it.
    fn one_row_log(
        row: AuditEntry,
        predecessor: &str,
    ) -> (TempDir, PathBuf, Arc<Mutex<AuditWriter>>) {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());
        writer.lock().unwrap().write_entry(row).unwrap();
        let written = std::fs::read_to_string(&path).unwrap();
        let mut entry: AuditEntry = serde_json::from_str(written.trim()).unwrap();
        entry.previous_entry_hash = predecessor.to_owned();
        std::fs::write(&path, serde_json::to_string(&entry).unwrap() + "\n").unwrap();
        (dir, path, writer)
    }

    /// The only row of a log with no archives is the root of the whole chain,
    /// so a settled row that names any predecessor but the zero hash refuses.
    #[test]
    fn a_lone_settled_row_with_a_nonzero_predecessor_refuses_the_settlement_lookup() {
        let (_root, _rooted, root_writer) =
            one_row_log(submitted_row(SETTLE_ENVELOPE), ZERO_BLOCK_HASH);
        assert_eq!(
            try_value_action_settlement(&root_writer.lock().unwrap(), SETTLE_ENVELOPE).unwrap(),
            ValueActionSettlement::Settled
        );
        let (_dir, _path, writer) = one_row_log(submitted_row(SETTLE_ENVELOPE), &"1".repeat(64));
        assert!(matches!(
            try_value_action_settlement(&writer.lock().unwrap(), SETTLE_ENVELOPE),
            Err(AuditLogIntegrityError::ChainBroken { line: 1, .. })
        ));
    }

    /// The clear lookup applies the same root rule as the settlement lookup.
    #[test]
    fn a_lone_cleared_row_with_a_nonzero_predecessor_refuses_the_clear_lookup() {
        let (_root, _rooted, root_writer) = one_row_log(cleared_row(), ZERO_BLOCK_HASH);
        assert!(
            try_submission_receipt_cleared_exists(&root_writer.lock().unwrap(), SETTLE_ENVELOPE)
                .unwrap()
        );
        let (_dir, _path, writer) = one_row_log(cleared_row(), &"1".repeat(64));
        assert!(matches!(
            try_submission_receipt_cleared_exists(&writer.lock().unwrap(), SETTLE_ENVELOPE),
            Err(AuditLogIntegrityError::ChainBroken { line: 1, .. })
        ));
    }

    /// A walk through every retained file that finds no match answers the
    /// not-found outcome, not an error.
    #[test]
    fn a_walk_through_an_archive_without_a_match_reports_not_found() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());
        let mut guard = writer.lock().unwrap();
        guard.write_entry(pending_row(SETTLE_ENVELOPE)).unwrap();
        guard.force_rotate_for_test().unwrap();
        guard.write_entry(submitted_row(SETTLE_ENVELOPE)).unwrap();
        assert!(!try_submission_receipt_cleared_exists(&guard, SETTLE_ENVELOPE).unwrap());
        assert_eq!(
            try_value_action_settlement(&guard, OTHER_ENVELOPE).unwrap(),
            ValueActionSettlement::OwedWithoutLegs
        );
    }

    /// When two archives both hold a match, the newer archive answers and the
    /// older one is never read.
    #[test]
    fn the_newest_archive_with_a_match_answers_and_older_archives_stay_unvisited() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());
        let mut guard = writer.lock().unwrap();
        guard.write_entry(pending_row(SETTLE_ENVELOPE)).unwrap();
        guard.write_entry(cleared_row()).unwrap();
        guard.force_rotate_for_test().unwrap();
        guard.write_entry(submitted_row(SETTLE_ENVELOPE)).unwrap();
        guard.write_entry(cleared_row()).unwrap();
        guard.force_rotate_for_test().unwrap();
        guard.write_entry(pending_row(OTHER_ENVELOPE)).unwrap();
        assert_eq!(
            try_value_action_settlement(&guard, SETTLE_ENVELOPE).unwrap(),
            ValueActionSettlement::Settled
        );
        let files = collect_files_newest_first(&path).unwrap();
        assert_eq!(files.len(), 3);
        std::fs::write(&files[2], "corrupt\n").unwrap();
        assert_eq!(
            try_value_action_settlement(&guard, SETTLE_ENVELOPE).unwrap(),
            ValueActionSettlement::Settled
        );
        assert!(try_submission_receipt_cleared_exists(&guard, SETTLE_ENVELOPE).unwrap());
    }

    /// A tool-invocation row carrying the hash is not a settlement row, so it
    /// neither settles the submission nor stops the walk short of the archived
    /// pending row.
    #[test]
    fn a_same_hash_tool_invocation_row_does_not_stop_the_settlement_walk() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());
        let mut guard = writer.lock().unwrap();
        guard.write_entry(pending_row(SETTLE_ENVELOPE)).unwrap();
        guard.force_rotate_for_test().unwrap();
        let mut invocation = AuditEntry::new_tool_invocation(NewToolInvocation::new(
            "stellar_pay",
            "stellar:testnet",
            vec!["destination".to_owned()],
            PolicyDecision::Allow,
            "req-invocation",
        ));
        invocation.envelope_hash = Some(SETTLE_ENVELOPE.to_owned());
        guard.write_entry(invocation).unwrap();
        let ValueActionSettlement::Owed(found) =
            try_value_action_settlement(&guard, SETTLE_ENVELOPE).unwrap()
        else {
            panic!("the tool-invocation row must not settle the archived pending row");
        };
        assert_eq!(found.legs.len(), 1);
    }

    /// A failed row settles its submission, and the clear lookup walks past it
    /// to the archived operator-clear row.
    #[test]
    fn a_failed_row_settles_and_the_clear_lookup_walks_past_it() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());
        let mut guard = writer.lock().unwrap();
        guard.write_entry(pending_row(SETTLE_ENVELOPE)).unwrap();
        guard.write_entry(cleared_row()).unwrap();
        guard.force_rotate_for_test().unwrap();
        guard
            .write_entry(AuditEntry::new_value_action_failed(
                "stellar_pay",
                Some("stellar:testnet".to_owned()),
                vec![],
                "6ba7aaac...69060003",
                "submission.failed",
                PolicyDecision::Allow,
                Some(SETTLE_ENVELOPE.to_owned()),
                None,
                None,
                "req-failed",
            ))
            .unwrap();
        assert_eq!(
            try_value_action_settlement(&guard, SETTLE_ENVELOPE).unwrap(),
            ValueActionSettlement::Settled
        );
        assert!(try_submission_receipt_cleared_exists(&guard, SETTLE_ENVELOPE).unwrap());
    }

    /// A failed row is not an operator clear: with no clear row anywhere in
    /// the retained history, the clear lookup answers `false` for a
    /// submission whose only row is a failed row.
    #[test]
    fn a_failed_row_alone_is_not_an_operator_clear() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());
        let mut guard = writer.lock().unwrap();
        guard.write_entry(pending_row(OTHER_ENVELOPE)).unwrap();
        guard.force_rotate_for_test().unwrap();
        guard
            .write_entry(AuditEntry::new_value_action_failed(
                "stellar_pay",
                Some("stellar:testnet".to_owned()),
                vec![],
                "6ba7aaac...69060003",
                "submission.record_unavailable",
                PolicyDecision::Allow,
                Some(SETTLE_ENVELOPE.to_owned()),
                None,
                None,
                "req-failed",
            ))
            .unwrap();
        assert_eq!(collect_files_newest_first(&path).unwrap().len(), 2);
        assert_eq!(
            try_value_action_settlement(&guard, SETTLE_ENVELOPE).unwrap(),
            ValueActionSettlement::Settled
        );
        assert!(!try_submission_receipt_cleared_exists(&guard, SETTLE_ENVELOPE).unwrap());
    }

    // ── Helper: build a SaSignerSetBaselined EventKind ────────────────────────

    fn baselined_event(
        rule_id: u32,
        sa_redacted: &str,
        signer_count: u32,
        threshold: u32,
    ) -> EventKind {
        let ids: Vec<u32> = (0..signer_count).collect();
        let pubkeys: Vec<SignerPubkey> = ids
            .iter()
            .map(|i| SignerPubkey::Ed25519 {
                pubkey: {
                    let mut k = [0u8; 32];
                    k[0] = (*i) as u8;
                    k
                },
            })
            .collect();
        // For Ed25519, first-8 bytes of the 32-byte pubkey.
        let pubkeys_first8: Vec<String> = pubkeys
            .iter()
            .map(|pk| match pk {
                SignerPubkey::Ed25519 { pubkey } => {
                    pubkey[..8].iter().map(|b| format!("{b:02x}")).collect()
                }
                _ => "0000000000000000".to_owned(),
            })
            .collect();
        EventKind::SaSignerSetBaselined {
            rule_id,
            observed_signer_count: signer_count,
            observed_threshold: threshold,
            observed_signer_ids: ids,
            observed_signer_pubkeys: pubkeys,
            observed_signer_pubkeys_first8: pubkeys_first8,
            observed_at_ledger_seq: 1_000,
            observed_at_unix_ms: 1_700_000_000_000,
            baseline_reason: BaselineReason::first_observation(),
            prev_chain_tip_hash: [0u8; 32],
            smart_account_redacted: RedactedStrkey::from_already_redacted(sa_redacted),
        }
    }

    /// The account digest passed where a test writes only version-1 rows,
    /// which the reader keys on the redacted account.
    const NO_DIGEST: [u8; 32] = [0u8; 32];

    /// The version-1 state of a payload; panics on a version-2 view.
    fn v1_state(payload: &SignerSetViewPayload) -> &ObservedSignerSet {
        match payload.view() {
            SignerSetView::V1(state) => state,
            SignerSetView::V2(_) => panic!("expected a version-1 view, got {payload:?}"),
        }
    }

    // ── Helper: write an EventKind entry to a writer ──────────────────────────

    fn write_event(writer: &mut AuditWriter, kind: EventKind) {
        let mut entry = AuditEntry::new_tool_invocation(NewToolInvocation::new(
            "smart-account.signers.list",
            Option::<String>::None,
            vec![],
            PolicyDecision::Allow,
            uuid::Uuid::new_v4().to_string(),
        ));
        // Replace the ToolInvocation kind with the signer-set kind.
        entry.event_kind = kind;
        writer.write_entry(entry).unwrap();
    }

    // ── 1. Basic find in active file ──────────────────────────────────────────

    #[test]
    fn find_latest_signer_set_view_returns_most_recent_in_active_file() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        {
            let mut w = writer.lock().unwrap();
            // Write two baseline rows for the same (rule_id, smart_account).
            write_event(&mut w, baselined_event(1, "CDABC...12345", 2, 2));
            write_event(&mut w, baselined_event(1, "CDABC...12345", 3, 2)); // more recent
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let result = reader
            .find_latest_signer_set_view(1, "CDABC...12345", &NO_DIGEST)
            .unwrap();

        let payload = result.expect("should find the most-recent row");
        assert_eq!(
            v1_state(&payload).signer_count,
            3,
            "should return the most-recent row"
        );
        assert_eq!(v1_state(&payload).threshold, 2);
        assert_ne!(*payload.row_hash(), [0u8; 32], "row_hash must be non-zero");
    }

    // ── 2. Returns None when no matching row ──────────────────────────────────

    #[test]
    fn find_latest_signer_set_view_returns_none_for_unmatched_rule() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        {
            let mut w = writer.lock().unwrap();
            write_event(&mut w, baselined_event(1, "CDABC...12345", 2, 2));
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        // Different rule_id — should not match.
        let result = reader
            .find_latest_signer_set_view(99, "CDABC...12345", &NO_DIGEST)
            .unwrap();
        assert!(result.is_none(), "should return None for unmatched rule_id");
    }

    #[test]
    fn find_latest_signer_set_view_returns_none_for_unmatched_smart_account() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        {
            let mut w = writer.lock().unwrap();
            write_event(&mut w, baselined_event(1, "CDABC...12345", 2, 2));
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let result = reader
            .find_latest_signer_set_view(1, "COTHER...OTHER", &NO_DIGEST)
            .unwrap();
        assert!(
            result.is_none(),
            "should return None for unmatched smart_account"
        );
    }

    // ── 3. Finds baseline row in a rotated file ───────────────────────────────

    #[test]
    fn find_latest_signer_set_view_discovers_baseline_in_rotated_file() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        {
            let mut w = writer.lock().unwrap();
            write_event(&mut w, baselined_event(1, "CDABC...12345", 2, 2));
            // Use the test-only force-rotate helper to trigger rotation
            // without writing 10 MiB of filler data.
            w.force_rotate_for_test().unwrap();
            // Write a non-matching entry in the new (active) file.
            write_event(&mut w, baselined_event(99, "COTHER...OTHER", 1, 1));
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let result = reader
            .find_latest_signer_set_view(1, "CDABC...12345", &NO_DIGEST)
            .unwrap();

        let payload = result.expect("should find baseline row in rotated file");
        assert_eq!(v1_state(&payload).signer_count, 2);
    }

    // ── 4. Torn-tail returns integrity error not None ─────────────────────────

    #[test]
    fn find_latest_signer_set_view_on_a_torn_tip_returns_tip_mismatch_not_none() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        {
            let mut w = writer.lock().unwrap();
            write_event(&mut w, baselined_event(1, "CDABC...12345", 2, 2));
        }

        // Capture the actual last-line length at write time, then truncate by
        // last_line_len / 2 bytes. Self-adapting — works regardless of future
        // schema changes to the entry layout.
        {
            use std::io::{BufRead, BufReader, Seek};
            let mut f = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();
            let total_len = f.seek(std::io::SeekFrom::End(0)).unwrap();
            f.seek(std::io::SeekFrom::Start(0)).unwrap();
            // Find the length of the last line.
            let reader_tmp = BufReader::new(&mut f);
            let last_line_len = reader_tmp
                .lines()
                .last()
                .and_then(|r| r.ok())
                .map(|l| l.len() + 1) // +1 for the newline
                .unwrap_or(20) as u64;
            let truncate_by = (last_line_len / 2).max(4); // at least 4 bytes into JSON
            let truncate_to = total_len.saturating_sub(truncate_by);
            if truncate_to > 0 {
                f.set_len(truncate_to).unwrap();
            }
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let result = reader.find_latest_signer_set_view(1, "CDABC...12345", &NO_DIGEST);

        // Must return an error, NOT Ok(None): the writer's last entry no
        // longer ends where the writer wrote it.
        assert!(
            result.is_err(),
            "torn tail must return Err, not Ok(None): {result:?}"
        );
        match result.unwrap_err() {
            AuditLogIntegrityError::ChainBroken {
                line: 1, reason, ..
            } if reason == TIP_MISMATCH_REASON => {}
            other => panic!("expected ChainBroken with tip_mismatch, got: {other:?}"),
        }
    }

    // ── 5. Concurrent-write race — truly races writers vs reader ─────────

    #[test]
    fn concurrent_write_and_read_no_torn_state() {
        // The test truly races writers against a reader rather than
        // joining the writer thread before reading. The assertion is that the
        // reader never sees a torn/parse-error state — it sees either a matching
        // row or no row, never corruption.
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        // Pre-write one baseline row so the reader always has something to scan.
        {
            let mut w = writer.lock().unwrap();
            write_event(&mut w, baselined_event(1, "CDABC...12345", 2, 2));
        }

        // Spawn a writer thread that appends 100 baseline entries, releasing
        // the mutex between each write to allow the reader to interleave.
        let writer_clone = Arc::clone(&writer);
        let writer_thread = std::thread::spawn(move || {
            for i in 0u32..100 {
                {
                    let mut w = writer_clone.lock().unwrap();
                    write_event(&mut w, baselined_event(1, "CDABC...12345", 2 + (i % 3), 2));
                }
                std::thread::yield_now();
            }
        });

        // Reader runs concurrently. The shared mutex ensures the reader always
        // sees fully-written entries (no torn lines).
        let reader = AuditReader::new(Arc::clone(&writer), None);
        for _ in 0..100 {
            let result = reader.find_latest_signer_set_view(1, "CDABC...12345", &NO_DIGEST);
            assert!(
                result.is_ok(),
                "reader saw a torn / parse-error state under concurrent write: {result:?}"
            );
            std::thread::yield_now();
        }

        writer_thread.join().unwrap();

        // After all writes complete, the reader must see a valid row.
        let final_result = reader
            .find_latest_signer_set_view(1, "CDABC...12345", &NO_DIGEST)
            .unwrap();
        assert!(
            final_result.is_some(),
            "row must be visible after all writes"
        );
    }

    // ── 6. AuditLogIntegrityError wire-code coverage ─────────────────────────

    #[test]
    fn audit_log_integrity_error_wire_codes_cover_all_variants() {
        // Use an exhaustive `match` so adding a new VerifyError variant forces
        // a compile error (no wildcard arm). A Vec approach would silently miss
        // new variants.
        fn wire_code_by_match(e: &AuditLogIntegrityError) -> &'static str {
            match e {
                AuditLogIntegrityError::ChainBroken { .. } => "audit.chain_broken",
                AuditLogIntegrityError::RotationGap { .. } => "audit.rotation_gap",
                AuditLogIntegrityError::HmacMismatch { .. } => "audit.hmac_mismatch",
                AuditLogIntegrityError::HmacSidecarMissing { .. } => "audit.hmac_sidecar_missing",
                AuditLogIntegrityError::TooManyRotatedFiles { .. } => {
                    "audit.too_many_rotated_files"
                }
                AuditLogIntegrityError::NonRegularFileLogPath { .. } => {
                    "audit.non_regular_file_log_path"
                }
                AuditLogIntegrityError::ParseError { .. } => "audit.parse_error",
                AuditLogIntegrityError::PathContract { .. } => "audit.path_contract",
                AuditLogIntegrityError::LogNotFound { .. } => "audit.log_not_found",
                AuditLogIntegrityError::Io(_) => "audit.io_error",
                AuditLogIntegrityError::SignerSetCanonicalBody(_) => {
                    "audit.signer_set_canonical_body"
                }
                AuditLogIntegrityError::PartialRotation { .. } => "audit.partial_rotation",
                AuditLogIntegrityError::TipAnchorMismatch { .. } => "audit.tip_anchor_mismatch",
                AuditLogIntegrityError::TipAnchorMissing { .. } => "audit.tip_anchor_missing",
                AuditLogIntegrityError::EntryTagInvalid { .. } => "audit.entry_tag_invalid",
            }
        }

        let errors = [
            AuditLogIntegrityError::ChainBroken {
                line: 1,
                file: "f".to_owned(),
                reason: "test",
            },
            AuditLogIntegrityError::RotationGap {
                file: "f".to_owned(),
            },
            AuditLogIntegrityError::HmacMismatch {
                file: "f".to_owned(),
            },
            AuditLogIntegrityError::HmacSidecarMissing {
                file: "f".to_owned(),
            },
            AuditLogIntegrityError::TooManyRotatedFiles { found: 22, cap: 21 },
            AuditLogIntegrityError::NonRegularFileLogPath {
                path: PathBuf::from("/dev/null"),
            },
            AuditLogIntegrityError::ParseError {
                line: 1,
                detail: "bad json".to_owned(),
            },
            AuditLogIntegrityError::PathContract {
                detail: "no parent".to_owned(),
            },
            AuditLogIntegrityError::LogNotFound {
                path: "/tmp/audit.jsonl".to_owned(),
            },
            AuditLogIntegrityError::Io(std::io::Error::other("ambient")),
            AuditLogIntegrityError::SignerSetCanonicalBody(
                crate::audit_log::signer_set::SignerSetCanonicalBodyError::MalformedObservedSignerSet {
                    reason: "signer_ids.len() != signer_pubkeys.len()",
                },
            ),
            AuditLogIntegrityError::PartialRotation {
                state: crate::audit_log::PartialRotationState::MidRename {
                    tmp_path: PathBuf::from("/tmp/audit.tmp"),
                    size_bytes: 42,
                },
                recovery_hint: "see runbook".to_owned(),
            },
            AuditLogIntegrityError::TipAnchorMismatch {
                expected_count: 12,
                expected_offset: 3400,
                actual_count: 9,
                actual_offset: 2600,
                reason: "test",
            },
            AuditLogIntegrityError::TipAnchorMissing {
                evidence: crate::audit_log::PriorAnchoring::BindingRecorded,
                actual_count: 9,
                actual_offset: 2600,
            },
            AuditLogIntegrityError::EntryTagInvalid {
                file: "f".to_owned(),
                line: 3,
                reason: "missing",
            },
        ];

        for err in &errors {
            // The match-derived code must equal the wire_code() method's output.
            let match_code = wire_code_by_match(err);
            let method_code = err.wire_code();
            assert!(
                !match_code.is_empty(),
                "every VerifyError variant must have a non-empty wire code"
            );
            assert!(
                match_code.starts_with("audit."),
                "wire code must start with 'audit.': {match_code}"
            );
            assert_eq!(
                match_code, method_code,
                "match-derived wire code must equal wire_code() method output"
            );
        }
    }

    // ── 7. Chain-hash tampering returns ChainBroken, not Ok(None) ────────────

    #[test]
    fn chain_hash_tampering_returns_chain_broken_not_none() {
        // If a row's `previous_entry_hash` is mutated after writing (simulating
        // an attacker editing the log), the reader must return
        // AuditLogIntegrityError::ChainBroken, NOT Ok(None).
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        {
            let mut w = writer.lock().unwrap();
            // Write two entries: the first (row 1) is the baseline, the second
            // (row 2) must reference row 1's hash. We then tamper row 2's
            // `previous_entry_hash` in the file.
            write_event(&mut w, baselined_event(1, "CDABC...12345", 2, 2));
            write_event(&mut w, baselined_event(1, "CDABC...12345", 3, 2));
        }

        // Tamper: read the file, locate the second JSON line, and replace its
        // `"previous_entry_hash":"sha256:..."` with a corrupted prefix to break
        // the chain link. The replacement targets the SHA-256 prefix so that the
        // hash value no longer matches `compute_entry_hash` output. The body
        // (JSON) remains parseable, so the reader reaches the chain-hash check
        // and returns ChainBroken — not ParseError.
        {
            let contents = std::fs::read_to_string(&path).unwrap();
            let mut lines: Vec<String> = contents.lines().map(|l| l.to_owned()).collect();
            // Row 2 is at index 1 (0-based). If only one row was written, skip.
            if lines.len() >= 2 {
                let tampered_row = lines[1].replace(
                    "\"previous_entry_hash\":\"sha256:",
                    "\"previous_entry_hash\":\"sha256:AAAA",
                );
                // Only write back if the substitution actually changed the line
                // (i.e. the pattern was found and replaced).
                if tampered_row != lines[1] {
                    lines[1] = tampered_row;
                    let new_contents = lines.join("\n") + "\n";
                    std::fs::write(&path, new_contents).unwrap();
                }
            }
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let result = reader.find_latest_signer_set_view(1, "CDABC...12345", &NO_DIGEST);

        // Must return exactly ChainBroken: the tamper mutates body bytes that
        // survive JSON parsing, so the chain-hash check fires — not ParseError.
        // Wire codes are distinct; ChainBroken is the correct variant for a
        // hash mismatch that passes parse-level validation.
        match result {
            Err(AuditLogIntegrityError::ChainBroken { .. }) => {
                // Correct: chain-hash mismatch propagated as expected.
            }
            Ok(None) => panic!("tampered chain must not return Ok(None)"),
            Ok(Some(_)) => panic!("tampered chain must not return Ok(Some(...))"),
            Err(other) => panic!("expected ChainBroken, got: {other:?}"),
        }
    }

    // ── 8. Missing active file with rotated siblings → RotationGap ────────

    #[test]
    fn missing_active_file_with_rotated_siblings_returns_rotation_gap() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        {
            let mut w = writer.lock().unwrap();
            write_event(&mut w, baselined_event(1, "CDABC...12345", 2, 2));
            // Force rotation to create a rotated sibling.
            w.force_rotate_for_test().unwrap();
            // Write one entry in the new active file to confirm it exists.
            write_event(&mut w, baselined_event(99, "COTHER...OTHER", 1, 1));
        }

        // Remove the active file to simulate out-of-band deletion / tampering.
        // `writer` stays alive (and its sidecar lock held) for the rest of the
        // test, so this exercises the "genuinely missing, not a transient
        // rotation window" path of `wait_out_transient_rotation_window`: the
        // lock IS held, so the scan retries up to its bound before giving up.
        // The observer never restores the file, so every retry iteration fires
        // it; the recorded sequence pins that the loop probes exactly the full
        // bound (indices 0..ROTATION_WINDOW_RETRY_ATTEMPTS) before reporting the
        // gap, rather than giving up early or looping unbounded.
        std::fs::remove_file(&path).unwrap();

        let observed_attempts = Rc::new(RefCell::new(Vec::<u32>::new()));
        let observed_for_hook = Rc::clone(&observed_attempts);
        let _observer_guard = install_rotation_window_retry_observer(move |attempt| {
            observed_for_hook.borrow_mut().push(attempt);
        });

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let result = reader.find_latest_signer_set_view(1, "CDABC...12345", &NO_DIGEST);

        match result {
            Err(AuditLogIntegrityError::RotationGap { .. }) => {
                // Correct: missing active file with rotated siblings is a gap.
            }
            other => {
                panic!("expected RotationGap for missing active file with siblings, got: {other:?}")
            }
        }
        assert_eq!(
            *observed_attempts.borrow(),
            (0..ROTATION_WINDOW_RETRY_ATTEMPTS).collect::<Vec<u32>>(),
            "a lock-held, never-reappearing active file must probe exactly the full retry bound"
        );
    }

    // ── 8a. Missing active file with NO live writer → immediate give-up ──────

    /// The reader's rotation-window tolerance gives up on its first iteration
    /// when the sidecar lock is not held by a live writer: an absent active
    /// file with no writer is a genuine gap, not a live rotation in progress,
    /// so waiting would only delay the eventual error. The observer is asserted
    /// to fire ZERO times because the give-up break sits before it.
    ///
    /// This drives `collect_files_newest_first` directly — the reader's
    /// tolerance entry point — because the public reader API
    /// (`find_latest_signer_set_view`) requires a live `Arc<Mutex<AuditWriter>>`
    /// for the scan's duration, which necessarily holds the sidecar lock and so
    /// cannot reach the unheld-lock branch.
    #[test]
    fn missing_active_no_writer_gives_up_immediately() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);

        {
            let writer = open_writer(path.clone());
            let mut w = writer.lock().unwrap();
            write_event(&mut w, baselined_event(1, "CDABC...12345", 2, 2));
            w.force_rotate_for_test().unwrap();
            write_event(&mut w, baselined_event(99, "COTHER...OTHER", 1, 1));
            // `w` then `writer` drop at the end of this block, releasing the
            // sidecar lock: no live writer remains.
        }

        // Active file absent, rotated sibling present, no live writer.
        std::fs::remove_file(&path).unwrap();

        let observed_attempts = Rc::new(RefCell::new(Vec::<u32>::new()));
        let observed_for_hook = Rc::clone(&observed_attempts);
        let _observer_guard = install_rotation_window_retry_observer(move |attempt| {
            observed_for_hook.borrow_mut().push(attempt);
        });

        let chain = collect_files_newest_first(&path).unwrap();

        assert!(
            observed_attempts.borrow().is_empty(),
            "an unheld lock must give up before the observer runs; observed: {:?}",
            observed_attempts.borrow()
        );
        assert_eq!(
            chain[0], path,
            "the active file is always the first scan entry"
        );
        assert!(
            !chain[0].exists(),
            "the tolerance must not resurrect a genuinely absent active file"
        );
        assert!(
            chain.len() > 1,
            "the rotated sibling must remain in the chain"
        );
    }

    // ── 8b. Active file transiently absent during a live rotation ────────────

    /// Pins the rotation-window tolerance: if the active file reappears
    /// before the retry bound is exhausted, the scan proceeds normally
    /// instead of surfacing a spurious `RotationGap`.
    ///
    /// Simulates the window `AuditWriter::rotate` opens between archiving the
    /// old active file and creating the new one by removing the active file and
    /// restoring its real content from inside the retry loop, on the scanning
    /// thread, via the test-only retry observer. Restoring at attempt index 1
    /// means the following rescan observes the file present and the loop exits
    /// on attempt index 2's absence check — a deterministic sequence that does
    /// not depend on wall-clock timing, so it is immune to scheduling load. The
    /// writer — and its sidecar lock — stays alive throughout, exactly as a
    /// live writer's rotation would.
    #[test]
    fn active_file_transient_absence_while_writer_alive_recovers() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        {
            let mut w = writer.lock().unwrap();
            write_event(&mut w, baselined_event(1, "CDABC...12345", 2, 2));
            // Force rotation to create a rotated sibling.
            w.force_rotate_for_test().unwrap();
            write_event(&mut w, baselined_event(1, "CDABC...12345", 3, 3));
        }

        let saved_active_contents = std::fs::read(&path).unwrap();
        std::fs::remove_file(&path).unwrap();

        let observed_attempts = Rc::new(RefCell::new(Vec::<u32>::new()));
        let observed_for_hook = Rc::clone(&observed_attempts);
        let restore_path = path.clone();
        let _observer_guard = install_rotation_window_retry_observer(move |attempt| {
            observed_for_hook.borrow_mut().push(attempt);
            if attempt == 1 {
                std::fs::write(&restore_path, &saved_active_contents).unwrap();
            }
        });

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let result = reader.find_latest_signer_set_view(1, "CDABC...12345", &NO_DIGEST);

        let payload = result
            .expect("transient rotation-window absence must not surface as RotationGap")
            .expect("row must still be found once the active file reappears");
        assert_eq!(v1_state(&payload).signer_count, 3);
        assert_eq!(
            *observed_attempts.borrow(),
            vec![0, 1],
            "attempt 0 observes the still-absent file, attempt 1 restores it, \
             attempt 2's absence check exits before reaching the observer"
        );
    }

    // ── 9. Single-row predecessor-hash tamper → ChainBroken ──────────────────

    // ── Helper: build a SaSignerAdded EventKind ───────────────────────────────

    fn signer_added_event(
        rule_id: u32,
        sa_redacted: &str,
        count: u32,
        threshold: u32,
    ) -> EventKind {
        let ids: Vec<u32> = (0..count).collect();
        let pubkeys: Vec<SignerPubkey> = ids
            .iter()
            .map(|i| SignerPubkey::Ed25519 {
                pubkey: {
                    let mut k = [0u8; 32];
                    k[0] = *i as u8;
                    k
                },
            })
            .collect();
        let pubkeys_first8: Vec<String> = pubkeys
            .iter()
            .map(|pk| match pk {
                SignerPubkey::Ed25519 { pubkey } => {
                    pubkey[..8].iter().map(|b| format!("{b:02x}")).collect()
                }
                _ => "0000000000000000".to_owned(),
            })
            .collect();
        EventKind::SaSignerAdded {
            rule_id,
            signer_id: count.saturating_sub(1),
            resulting_signer_count: count,
            resulting_threshold: threshold,
            resulting_signer_ids: ids,
            resulting_signer_pubkeys: pubkeys,
            resulting_signer_pubkeys_first8: pubkeys_first8,
            smart_account_redacted: RedactedStrkey::from_already_redacted(sa_redacted),
        }
    }

    // ── Helper: build a SaSignerRemoved EventKind ─────────────────────────────

    fn signer_removed_event(
        rule_id: u32,
        sa_redacted: &str,
        count: u32,
        threshold: u32,
    ) -> EventKind {
        let ids: Vec<u32> = (0..count).collect();
        let pubkeys: Vec<SignerPubkey> = ids
            .iter()
            .map(|i| SignerPubkey::Ed25519 {
                pubkey: {
                    let mut k = [0u8; 32];
                    k[0] = *i as u8;
                    k
                },
            })
            .collect();
        let pubkeys_first8: Vec<String> = pubkeys
            .iter()
            .map(|pk| match pk {
                SignerPubkey::Ed25519 { pubkey } => {
                    pubkey[..8].iter().map(|b| format!("{b:02x}")).collect()
                }
                _ => "0000000000000000".to_owned(),
            })
            .collect();
        EventKind::SaSignerRemoved {
            rule_id,
            signer_id: count,
            resulting_signer_count: count,
            resulting_threshold: threshold,
            resulting_signer_ids: ids,
            resulting_signer_pubkeys: pubkeys,
            resulting_signer_pubkeys_first8: pubkeys_first8,
            smart_account_redacted: RedactedStrkey::from_already_redacted(sa_redacted),
        }
    }

    // ── Helper: build a SaThresholdChanged EventKind ──────────────────────────

    fn threshold_changed_event(
        rule_id: u32,
        sa_redacted: &str,
        count: u32,
        new_threshold: u32,
    ) -> EventKind {
        let ids: Vec<u32> = (0..count).collect();
        let pubkeys: Vec<SignerPubkey> = ids
            .iter()
            .map(|i| SignerPubkey::Ed25519 {
                pubkey: {
                    let mut k = [0u8; 32];
                    k[0] = *i as u8;
                    k
                },
            })
            .collect();
        let pubkeys_first8: Vec<String> = pubkeys
            .iter()
            .map(|pk| match pk {
                SignerPubkey::Ed25519 { pubkey } => {
                    pubkey[..8].iter().map(|b| format!("{b:02x}")).collect()
                }
                _ => "0000000000000000".to_owned(),
            })
            .collect();
        EventKind::SaThresholdChanged {
            rule_id,
            old_threshold: 1,
            new_threshold,
            resulting_threshold: new_threshold,
            resulting_signer_count: count,
            resulting_signer_ids: ids,
            resulting_signer_pubkeys: pubkeys,
            resulting_signer_pubkeys_first8: pubkeys_first8,
            smart_account_redacted: RedactedStrkey::from_already_redacted(sa_redacted),
        }
    }

    // ── Helpers: build pin rows of both versions ─────────────────────────────

    /// A full pin whose 32 bytes all equal `byte`.
    fn h(byte: u8) -> WasmHashPin {
        WasmHashPin::new([byte; 32])
    }

    /// The pinned hash of the pin-width tests and a hash sharing its first
    /// eight bytes that differs in every later byte.
    fn pinned_and_twin() -> ([u8; 32], [u8; 32]) {
        let pinned = [0x42u8; 32];
        let mut twin = pinned;
        twin[8..].fill(0x43);
        (pinned, twin)
    }

    fn context_rule_created_event(
        rule_id: u32,
        sa_redacted: &str,
        verifier_hashes: Vec<WasmHashPin>,
        policy_hashes: Vec<WasmHashPin>,
        mutable_override: bool,
        unknown_override: bool,
    ) -> EventKind {
        EventKind::SaContextRuleCreatedV2 {
            smart_account: sa_redacted.to_owned(),
            rule_id,
            context_type: "default".to_owned(),
            signers_count: 1,
            policies_count: policy_hashes.len() as u32,
            valid_until: None,
            pinned_verifier_wasm_hashes: verifier_hashes,
            pinned_policy_wasm_hashes: policy_hashes,
            mutable_override,
            unknown_override,
            pinned_verifier_executable_refs: vec![],
            pinned_policy_executable_refs: vec![],
        }
    }

    fn v1_created_event(
        rule_id: u32,
        sa_redacted: &str,
        verifier_first8: Vec<String>,
        policy_first8: Vec<String>,
        verifier_refs: Vec<Option<ExecutableRefPinFirst8>>,
    ) -> EventKind {
        EventKind::SaContextRuleCreated {
            smart_account: sa_redacted.to_owned(),
            rule_id,
            context_type: "default".to_owned(),
            signers_count: 1,
            policies_count: policy_first8.len() as u32,
            valid_until: None,
            pinned_verifier_wasm_hashes_first8: verifier_first8,
            pinned_policy_wasm_hashes_first8: policy_first8,
            mutable_override: true,
            unknown_override: false,
            pinned_verifier_executable_refs: verifier_refs,
            pinned_policy_executable_refs: vec![],
        }
    }

    fn v1_pins_updated_event(
        rule_id: u32,
        sa_redacted: &str,
        verifier_first8: Vec<String>,
        policy_first8: Vec<String>,
    ) -> EventKind {
        EventKind::SaContextRulePinsUpdated {
            smart_account: sa_redacted.to_owned(),
            rule_id,
            pinned_verifier_wasm_hashes_first8: verifier_first8,
            pinned_policy_wasm_hashes_first8: policy_first8,
            mutable_override: false,
            unknown_override: true,
            pinned_verifier_executable_refs: vec![],
            pinned_policy_executable_refs: vec![],
            reason: crate::audit_log::schema::PinsUpdateReason::SignerAdded,
        }
    }

    /// Unwraps a found, complete pin record.
    fn complete(record: Option<ContextRulePinRecord>) -> PinnedHashesRecord {
        match record.expect("the rule has a pin record") {
            ContextRulePinRecord::Complete(record) => record,
            other => panic!("expected a complete record, got {other:?}"),
        }
    }

    /// Unwraps a found, incomplete pin record.
    fn incomplete(record: Option<ContextRulePinRecord>) -> IncompletePinRecord {
        match record.expect("the rule has a pin record") {
            ContextRulePinRecord::Incomplete(record) => record,
            other => panic!("expected an incomplete record, got {other:?}"),
        }
    }

    // ── Helper: build a SaContextRuleDeleted EventKind ───────────────────────

    fn context_rule_deleted_event(rule_id: u32, sa_redacted: &str) -> EventKind {
        EventKind::SaContextRuleDeleted {
            smart_account: sa_redacted.to_owned(),
            rule_id,
        }
    }

    // ── Helper: build a SaTimelockScheduled EventKind ────────────────────────

    fn timelock_scheduled_event(
        op_id_full_hex: &str,
        tl_redacted: &str,
        request_id: &str,
    ) -> EventKind {
        EventKind::SaTimelockScheduled {
            operation_id_redacted: format!("{}...{}", &op_id_full_hex[..8], &op_id_full_hex[56..]),
            operation_id_full_hex: op_id_full_hex.to_owned(),
            timelock_contract_redacted: RedactedStrkey::from_already_redacted(tl_redacted),
            target_redacted: RedactedStrkey::from_already_redacted("CAAAA...BBBBB"),
            function: "upgrade".to_owned(),
            delay_ledgers: 100,
            proposer_redacted: RedactedStrkey::from_already_redacted("GAAA1...11111"),
            schedule_tx_hash_redacted: "aabbccdd...11223344".to_owned(),
            audit_request_id: request_id.to_owned(),
        }
    }

    // ── Helper: build a SaTimelockCancelled EventKind ────────────────────────

    fn timelock_cancelled_event(op_id_full_hex: &str, tl_redacted: &str) -> EventKind {
        EventKind::SaTimelockCancelled {
            operation_id_redacted: format!("{}...{}", &op_id_full_hex[..8], &op_id_full_hex[56..]),
            operation_id_full_hex: op_id_full_hex.to_owned(),
            timelock_contract_redacted: RedactedStrkey::from_already_redacted(tl_redacted),
            canceller_redacted: RedactedStrkey::from_already_redacted("GAAA1...22222"),
            cancel_tx_hash_redacted: "aabbccdd...99887766".to_owned(),
            audit_request_id: uuid::Uuid::new_v4().to_string(),
        }
    }

    // ── Helper: build a SaTimelockExecuted EventKind ─────────────────────────

    fn timelock_executed_event(op_id_full_hex: &str, tl_redacted: &str) -> EventKind {
        EventKind::SaTimelockExecuted {
            operation_id_redacted: format!("{}...{}", &op_id_full_hex[..8], &op_id_full_hex[56..]),
            operation_id_full_hex: op_id_full_hex.to_owned(),
            timelock_contract_redacted: RedactedStrkey::from_already_redacted(tl_redacted),
            executor_redacted: None,
            execute_tx_hash_redacted: "aabbccdd...77665544".to_owned(),
            audit_request_id: uuid::Uuid::new_v4().to_string(),
        }
    }

    // ── 10. SaSignerAdded is picked up by find_latest_signer_set_view ────────

    #[test]
    fn find_latest_signer_set_view_picks_up_signer_added_event() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        {
            let mut w = writer.lock().unwrap();
            // Write a baseline, then a signer-added event that supersedes it.
            write_event(&mut w, baselined_event(1, "CDABC...12345", 2, 2));
            write_event(&mut w, signer_added_event(1, "CDABC...12345", 3, 2));
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let result = reader
            .find_latest_signer_set_view(1, "CDABC...12345", &NO_DIGEST)
            .unwrap();

        let payload = result.expect("should find signer-added event");
        assert_eq!(
            v1_state(&payload).signer_count,
            3,
            "SaSignerAdded resulting count must be returned"
        );
        assert_eq!(v1_state(&payload).threshold, 2);
        assert_eq!(
            v1_state(&payload).signer_ids.len(),
            3,
            "signer_ids length must match resulting_signer_count"
        );
    }

    // ── 11. SaSignerRemoved is picked up by find_latest_signer_set_view ──────

    #[test]
    fn find_latest_signer_set_view_picks_up_signer_removed_event() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        {
            let mut w = writer.lock().unwrap();
            write_event(&mut w, baselined_event(1, "CDABC...12345", 3, 2));
            write_event(&mut w, signer_removed_event(1, "CDABC...12345", 2, 2));
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let payload = reader
            .find_latest_signer_set_view(1, "CDABC...12345", &NO_DIGEST)
            .unwrap()
            .expect("should find signer-removed event");

        assert_eq!(
            v1_state(&payload).signer_count,
            2,
            "SaSignerRemoved resulting count must be returned"
        );
    }

    // ── 12. SaThresholdChanged is picked up by find_latest_signer_set_view ───

    #[test]
    fn find_latest_signer_set_view_picks_up_threshold_changed_event() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        {
            let mut w = writer.lock().unwrap();
            write_event(&mut w, baselined_event(1, "CDABC...12345", 2, 1));
            write_event(&mut w, threshold_changed_event(1, "CDABC...12345", 2, 2));
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let payload = reader
            .find_latest_signer_set_view(1, "CDABC...12345", &NO_DIGEST)
            .unwrap()
            .expect("should find threshold-changed event");

        assert_eq!(
            v1_state(&payload).threshold,
            2,
            "SaThresholdChanged resulting threshold must be returned"
        );
        assert_eq!(
            v1_state(&payload).signer_count,
            2,
            "signer count must be unchanged by threshold change"
        );
    }

    // ── 13. find_latest_context_rule_pinned_hashes: basic round-trip ──────────

    #[test]
    fn find_latest_context_rule_pinned_hashes_returns_pinned_hashes() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());
        let (pinned, twin) = pinned_and_twin();

        {
            let mut w = writer.lock().unwrap();
            write_event(
                &mut w,
                context_rule_created_event(
                    5,
                    "CDABC...12345",
                    vec![WasmHashPin::new(pinned)],
                    vec![WasmHashPin::new(twin)],
                    false,
                    false,
                ),
            );
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let record = complete(
            reader
                .find_latest_context_rule_pinned_hashes(5, "CDABC...12345")
                .unwrap(),
        );
        assert_eq!(record.pinned_verifier_hashes[0].as_bytes(), &pinned);
        assert_eq!(record.pinned_policy_hashes[0].as_bytes(), &twin);
        assert!(!record.mutable_override);
        assert!(!record.unknown_override);
    }

    fn executable_ref_pin(tag: &[u8], resolved: [u8; 32]) -> ExecutableRefPin {
        use stellar_xdr::{ContractId, Hash, ScAddress, ScString};
        ExecutableRefPin::new(
            &ScAddress::Contract(ContractId(Hash([9u8; 32]))),
            &ScString(tag.to_vec().try_into().unwrap()),
            &resolved,
        )
        .unwrap()
    }

    fn first8_ref_pin(tag: &[u8], resolved: [u8; 32]) -> ExecutableRefPinFirst8 {
        use stellar_xdr::{ContractId, Hash, ScAddress, ScString};
        ExecutableRefPinFirst8::new(
            &ScAddress::Contract(ContractId(Hash([9u8; 32]))),
            &ScString(tag.to_vec().try_into().unwrap()),
            &resolved,
        )
        .unwrap()
    }

    fn context_rule_created_event_with_refs(
        rule_id: u32,
        verifier_hashes: Vec<WasmHashPin>,
        verifier_refs: Vec<Option<ExecutableRefPin>>,
        policy_hashes: Vec<WasmHashPin>,
        policy_refs: Vec<Option<ExecutableRefPin>>,
    ) -> EventKind {
        let EventKind::SaContextRuleCreatedV2 {
            smart_account,
            rule_id,
            context_type,
            signers_count,
            policies_count,
            valid_until,
            pinned_verifier_wasm_hashes,
            pinned_policy_wasm_hashes,
            mutable_override,
            unknown_override,
            ..
        } = context_rule_created_event(
            rule_id,
            "CDABC...12345",
            verifier_hashes,
            policy_hashes,
            true,
            false,
        )
        else {
            unreachable!("context_rule_created_event builds SaContextRuleCreatedV2");
        };
        EventKind::SaContextRuleCreatedV2 {
            smart_account,
            rule_id,
            context_type,
            signers_count,
            policies_count,
            valid_until,
            pinned_verifier_wasm_hashes,
            pinned_policy_wasm_hashes,
            mutable_override,
            unknown_override,
            pinned_verifier_executable_refs: verifier_refs,
            pinned_policy_executable_refs: policy_refs,
        }
    }

    /// The record carries the executable-reference pins at their positions,
    /// and the position accessors return them.
    #[test]
    fn find_latest_context_rule_pinned_hashes_returns_executable_refs() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());
        let verifier_pin = executable_ref_pin(b"verifier", [0xaau8; 32]);
        let policy_pin = executable_ref_pin(b"policy", [0xbbu8; 32]);
        {
            let mut w = writer.lock().unwrap();
            write_event(
                &mut w,
                context_rule_created_event_with_refs(
                    5,
                    vec![h(0x11), h(0xaa)],
                    vec![None, Some(verifier_pin.clone())],
                    vec![h(0xbb)],
                    vec![Some(policy_pin.clone())],
                ),
            );
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let record = complete(
            reader
                .find_latest_context_rule_pinned_hashes(5, "CDABC...12345")
                .unwrap(),
        );
        assert_eq!(
            record.pinned_verifier_executable_refs,
            vec![None, Some(verifier_pin.clone())]
        );
        assert_eq!(record.verifier_executable_ref(0), None);
        assert_eq!(record.verifier_executable_ref(1), Some(&verifier_pin));
        assert_eq!(record.policy_executable_ref(0), Some(&policy_pin));
        assert_eq!(record.policy_executable_ref(1), None);

        let all = reader.scan_all_context_rule_pin_records().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(
            complete(Some(all[0].2.clone())).pinned_policy_executable_refs,
            vec![Some(policy_pin)]
        );
    }

    /// A record whose executable-reference list is misaligned with its hash
    /// list, whose pin's resolved hash differs from the aligned hash (an
    /// equal-prefix twin included), or whose pin does not have the
    /// constructor's shape is refused as a parse error by both readers, in
    /// both row versions.
    #[test]
    fn find_latest_context_rule_pinned_hashes_refuses_malformed_executable_refs() {
        let (pinned, twin) = pinned_and_twin();
        let pin = executable_ref_pin(b"verifier", pinned);
        let mut malformed_pin = pin.clone();
        malformed_pin.ref_key_hex = "zz".to_owned();
        let first8_pin = first8_ref_pin(b"verifier", pinned);
        let cases = [
            (
                "misaligned verifier list",
                context_rule_created_event_with_refs(
                    5,
                    vec![h(0x11), WasmHashPin::new(pinned)],
                    vec![Some(pin.clone())],
                    vec![],
                    vec![],
                ),
            ),
            (
                "misaligned policy list",
                context_rule_created_event_with_refs(5, vec![], vec![], vec![], vec![None]),
            ),
            (
                "pin disagrees with the aligned hash",
                context_rule_created_event_with_refs(
                    5,
                    vec![h(0x11)],
                    vec![Some(pin.clone())],
                    vec![],
                    vec![],
                ),
            ),
            (
                "pin resolves to an equal-prefix twin of the aligned hash",
                context_rule_created_event_with_refs(
                    5,
                    vec![WasmHashPin::new(twin)],
                    vec![Some(pin.clone())],
                    vec![],
                    vec![],
                ),
            ),
            (
                "malformed pin",
                context_rule_created_event_with_refs(
                    5,
                    vec![WasmHashPin::new(pinned)],
                    vec![Some(malformed_pin)],
                    vec![],
                    vec![],
                ),
            ),
            (
                "version-1 pin disagrees with its first-8",
                v1_created_event(
                    5,
                    "CDABC...12345",
                    vec!["1111111111111111".to_owned()],
                    vec![],
                    vec![Some(first8_pin.clone())],
                ),
            ),
            (
                "misaligned version-1 list",
                v1_created_event(
                    5,
                    "CDABC...12345",
                    vec!["4242424242424242".to_owned(), "1111111111111111".to_owned()],
                    vec![],
                    vec![Some(first8_pin)],
                ),
            ),
        ];
        for (case, event) in cases {
            let dir = TempDir::new().unwrap();
            let path = tmp_log(&dir);
            let writer = open_writer(path.clone());
            {
                let mut w = writer.lock().unwrap();
                write_event(&mut w, event);
            }
            let reader = AuditReader::new(Arc::clone(&writer), None);
            let err = reader
                .find_latest_context_rule_pinned_hashes(5, "CDABC...12345")
                .expect_err(case);
            assert!(
                matches!(err, AuditLogIntegrityError::ParseError { line: 1, .. }),
                "{case}: {err:?}"
            );
            let err = reader.scan_all_context_rule_pin_records().expect_err(case);
            assert!(
                matches!(err, AuditLogIntegrityError::ParseError { line: 1, .. }),
                "{case}: {err:?}"
            );
        }
    }

    /// A version-2 row holding a 16-character hash is a parse error for both
    /// readers: the row is never read as a pin record.
    #[test]
    fn a_version_2_row_with_a_prefix_hash_is_a_parse_error() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());
        {
            let mut w = writer.lock().unwrap();
            write_event(
                &mut w,
                context_rule_created_event(5, "CDABC...12345", vec![h(0x42)], vec![], false, false),
            );
        }
        // The only row of the log keeps its zero predecessor, so the read
        // reaches the row content and refuses the 16-character hash there.
        let written = std::fs::read_to_string(&path).unwrap();
        let mut value: serde_json::Value = serde_json::from_str(written.trim()).unwrap();
        value["pinned_verifier_wasm_hashes"] = serde_json::json!(["4242424242424242"]);
        std::fs::write(&path, serde_json::to_string(&value).unwrap() + "\n").unwrap();
        let reader = AuditReader::new(Arc::clone(&writer), None);
        let err = reader
            .find_latest_context_rule_pinned_hashes(5, "CDABC...12345")
            .expect_err("a prefix hash in a version-2 row is refused");
        assert!(
            matches!(err, AuditLogIntegrityError::ParseError { line: 1, .. }),
            "{err:?}"
        );
        assert!(matches!(
            reader.scan_all_context_rule_pin_records(),
            Err(AuditLogIntegrityError::ParseError { line: 1, .. })
        ));
    }

    // ── 14. find_latest_context_rule_pinned_hashes: mutable/unknown overrides ──

    #[test]
    fn find_latest_context_rule_pinned_hashes_returns_override_flags() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        {
            let mut w = writer.lock().unwrap();
            write_event(
                &mut w,
                context_rule_created_event(7, "CDABC...12345", vec![h(0xab)], vec![], true, true),
            );
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let record = complete(
            reader
                .find_latest_context_rule_pinned_hashes(7, "CDABC...12345")
                .unwrap(),
        );

        assert!(
            record.mutable_override,
            "mutable_override must be true when set at install"
        );
        assert!(
            record.unknown_override,
            "unknown_override must be true when set at install"
        );
    }

    // ── 14b. SaContextRulePinsUpdatedV2: the newest pin-record row wins ───────

    #[allow(
        clippy::too_many_arguments,
        reason = "test helper mirroring the pin-record fields"
    )]
    fn pins_updated_event(
        rule_id: u32,
        sa_redacted: &str,
        verifier_hashes: Vec<WasmHashPin>,
        policy_hashes: Vec<WasmHashPin>,
        mutable_override: bool,
        unknown_override: bool,
        verifier_refs: Vec<Option<ExecutableRefPin>>,
        reason: crate::audit_log::schema::PinsUpdateReason,
    ) -> EventKind {
        EventKind::SaContextRulePinsUpdatedV2 {
            smart_account: sa_redacted.to_owned(),
            rule_id,
            pinned_verifier_wasm_hashes: verifier_hashes,
            pinned_policy_wasm_hashes: policy_hashes,
            mutable_override,
            unknown_override,
            pinned_verifier_executable_refs: verifier_refs,
            pinned_policy_executable_refs: vec![],
            reason,
        }
    }

    /// A pins-updated row written after the rule's created row is the rule's
    /// pin record for both readers, with its own override flags and
    /// reference pins; a pins-updated row for another rule or another smart
    /// account changes nothing.
    #[test]
    fn pin_record_reads_a_newer_pins_updated_row() {
        use crate::audit_log::schema::PinsUpdateReason;

        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());
        let pin = executable_ref_pin(b"verifier", [0xbbu8; 32]);
        {
            let mut w = writer.lock().unwrap();
            write_event(
                &mut w,
                context_rule_created_event(
                    5,
                    "CDABC...12345",
                    vec![h(0xaa)],
                    vec![h(0x11)],
                    false,
                    false,
                ),
            );
            write_event(
                &mut w,
                pins_updated_event(
                    5,
                    "CDABC...12345",
                    vec![h(0xbb)],
                    vec![h(0x11)],
                    true,
                    false,
                    vec![Some(pin.clone())],
                    PinsUpdateReason::VerifierMigrated,
                ),
            );
            write_event(
                &mut w,
                pins_updated_event(
                    6,
                    "CDABC...12345",
                    vec![h(0xcc)],
                    vec![],
                    false,
                    true,
                    vec![],
                    PinsUpdateReason::SignerAdded,
                ),
            );
            write_event(
                &mut w,
                pins_updated_event(
                    5,
                    "CDXYZ...99999",
                    vec![h(0xdd)],
                    vec![],
                    false,
                    false,
                    vec![],
                    PinsUpdateReason::SignerAdded,
                ),
            );
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let record = complete(
            reader
                .find_latest_context_rule_pinned_hashes(5, "CDABC...12345")
                .unwrap(),
        );
        assert_eq!(record.pinned_verifier_hashes, vec![h(0xbb)]);
        assert_eq!(record.pinned_policy_hashes, vec![h(0x11)]);
        assert!(record.mutable_override);
        assert!(!record.unknown_override);
        assert_eq!(record.verifier_executable_ref(0), Some(&pin));

        let all = reader.scan_all_context_rule_pin_records().unwrap();
        let rule5 = all
            .iter()
            .find(|(rid, sa, _)| *rid == 5 && sa == "CDABC...12345")
            .expect("rule 5 is listed");
        assert_eq!(
            complete(Some(rule5.2.clone())).pinned_verifier_hashes,
            vec![h(0xbb)]
        );
        assert_eq!(all.len(), 3, "one record per (rule, smart account)");
    }

    /// A created row written after a pins-updated row for the same key is the
    /// newer record and wins.
    #[test]
    fn pin_record_reads_a_created_row_that_postdates_a_pins_updated_row() {
        use crate::audit_log::schema::PinsUpdateReason;

        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());
        {
            let mut w = writer.lock().unwrap();
            write_event(
                &mut w,
                pins_updated_event(
                    5,
                    "CDABC...12345",
                    vec![h(0xbb)],
                    vec![],
                    true,
                    true,
                    vec![],
                    PinsUpdateReason::SignerAdded,
                ),
            );
            write_event(
                &mut w,
                context_rule_created_event(5, "CDABC...12345", vec![h(0xaa)], vec![], false, false),
            );
        }
        let reader = AuditReader::new(Arc::clone(&writer), None);
        let record = complete(
            reader
                .find_latest_context_rule_pinned_hashes(5, "CDABC...12345")
                .unwrap(),
        );
        assert_eq!(record.pinned_verifier_hashes, vec![h(0xaa)]);
        assert!(!record.mutable_override);
    }

    /// A pins-updated row a `signers refresh` wrote, which adds a verifier pin
    /// to a record that pinned none, is the rule's pin record for both
    /// readers.
    #[test]
    fn pin_record_reads_a_baseline_refreshed_pins_row() {
        use crate::audit_log::schema::PinsUpdateReason;

        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());
        {
            let mut w = writer.lock().unwrap();
            write_event(
                &mut w,
                context_rule_created_event(4, "CDABC...12345", vec![], vec![h(0x11)], false, false),
            );
            write_event(
                &mut w,
                pins_updated_event(
                    4,
                    "CDABC...12345",
                    vec![h(0xaa)],
                    vec![h(0x11)],
                    false,
                    true,
                    vec![],
                    PinsUpdateReason::BaselineRefreshed,
                ),
            );
        }
        let reader = AuditReader::new(Arc::clone(&writer), None);
        let record = complete(
            reader
                .find_latest_context_rule_pinned_hashes(4, "CDABC...12345")
                .unwrap(),
        );
        assert_eq!(record.pinned_verifier_hashes, vec![h(0xaa)]);
        assert_eq!(record.pinned_policy_hashes, vec![h(0x11)]);
        assert!(record.unknown_override);
        let all = reader.scan_all_context_rule_pin_records().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(
            complete(Some(all[0].2.clone())).pinned_verifier_hashes,
            vec![h(0xaa)]
        );
    }

    /// A pins-updated row in the newer file of a rotated chain wins over the
    /// created row in the older file.
    #[test]
    fn pin_record_reads_a_pins_updated_row_across_rotation() {
        use crate::audit_log::schema::PinsUpdateReason;

        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());
        {
            let mut w = writer.lock().unwrap();
            write_event(
                &mut w,
                context_rule_created_event(1, "CDABC...12345", vec![h(0xaa)], vec![], false, false),
            );
            w.force_rotate_for_test().unwrap();
            write_event(
                &mut w,
                pins_updated_event(
                    1,
                    "CDABC...12345",
                    vec![h(0xbb)],
                    vec![],
                    false,
                    false,
                    vec![],
                    PinsUpdateReason::VerifierMigrated,
                ),
            );
        }
        let reader = AuditReader::new(Arc::clone(&writer), None);
        let record = complete(
            reader
                .find_latest_context_rule_pinned_hashes(1, "CDABC...12345")
                .unwrap(),
        );
        assert_eq!(record.pinned_verifier_hashes, vec![h(0xbb)]);
        let all = reader.scan_all_context_rule_pin_records().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(
            complete(Some(all[0].2.clone())).pinned_verifier_hashes,
            vec![h(0xbb)]
        );
    }

    /// A malformed pins-updated row written after a valid created row for the
    /// same rule fails the read closed: the older created row is never used
    /// in its place.
    #[test]
    fn pin_record_fails_closed_on_a_malformed_newer_row_over_a_valid_older_one() {
        use crate::audit_log::schema::PinsUpdateReason;

        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());
        let pin = executable_ref_pin(b"verifier", [0xaau8; 32]);
        {
            let mut w = writer.lock().unwrap();
            write_event(
                &mut w,
                context_rule_created_event(5, "CDABC...12345", vec![h(0xaa)], vec![], false, false),
            );
            write_event(
                &mut w,
                pins_updated_event(
                    5,
                    "CDABC...12345",
                    vec![h(0x11)],
                    vec![],
                    false,
                    false,
                    vec![Some(pin)],
                    PinsUpdateReason::PolicyAdded,
                ),
            );
        }
        let reader = AuditReader::new(Arc::clone(&writer), None);
        let err = reader
            .find_latest_context_rule_pinned_hashes(5, "CDABC...12345")
            .expect_err("a malformed newer record is refused");
        assert!(
            matches!(err, AuditLogIntegrityError::ParseError { line: 2, .. }),
            "{err:?}"
        );
        let err = reader
            .scan_all_context_rule_pin_records()
            .expect_err("a malformed newer record is refused");
        assert!(
            matches!(err, AuditLogIntegrityError::ParseError { line: 2, .. }),
            "{err:?}"
        );
    }

    /// A pins-updated row whose reference pin disagrees with its hash list
    /// is refused as a parse error naming its own row kind.
    #[test]
    fn pin_record_refuses_a_malformed_pins_updated_row() {
        use crate::audit_log::schema::PinsUpdateReason;

        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());
        let pin = executable_ref_pin(b"verifier", [0xaau8; 32]);
        {
            let mut w = writer.lock().unwrap();
            write_event(
                &mut w,
                pins_updated_event(
                    5,
                    "CDABC...12345",
                    vec![h(0x11)],
                    vec![],
                    false,
                    false,
                    vec![Some(pin)],
                    PinsUpdateReason::SignerAdded,
                ),
            );
        }
        let reader = AuditReader::new(Arc::clone(&writer), None);
        let err = reader
            .find_latest_context_rule_pinned_hashes(5, "CDABC...12345")
            .expect_err("an inconsistent record is refused");
        match err {
            AuditLogIntegrityError::ParseError { line: 1, detail } => assert!(
                detail.starts_with("sa_context_rule_pins_updated_v2:"),
                "{detail}"
            ),
            other => panic!("expected ParseError at line 1, got {other:?}"),
        }
    }

    // ── 14c. Version-1 rows: incomplete records and mixed-format selection ─────

    /// A version-1 row that pins a hash reads as an incomplete record holding
    /// its first-8 values for inspection, in both readers; a version-1 row
    /// that pins no hash reads as a complete, empty record with its flags.
    #[test]
    fn a_version_1_row_with_hashes_is_an_incomplete_record() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());
        let (pinned, _) = pinned_and_twin();
        let first8_pin = first8_ref_pin(b"verifier", pinned);
        {
            let mut w = writer.lock().unwrap();
            write_event(
                &mut w,
                v1_created_event(
                    5,
                    "CDABC...12345",
                    vec!["4242424242424242".to_owned()],
                    vec!["1111111111111111".to_owned()],
                    vec![Some(first8_pin.clone())],
                ),
            );
            write_event(
                &mut w,
                v1_created_event(6, "CDABC...12345", vec![], vec![], vec![]),
            );
            write_event(
                &mut w,
                v1_pins_updated_event(
                    7,
                    "CDABC...12345",
                    vec![],
                    vec!["1111111111111111".to_owned()],
                ),
            );
        }
        let reader = AuditReader::new(Arc::clone(&writer), None);
        let record = incomplete(
            reader
                .find_latest_context_rule_pinned_hashes(5, "CDABC...12345")
                .unwrap(),
        );
        assert_eq!(record.row_kind, "sa_context_rule_created");
        assert_eq!(
            record.pinned_verifier_hashes_first8,
            vec!["4242424242424242"]
        );
        assert_eq!(record.pinned_policy_hashes_first8, vec!["1111111111111111"]);
        assert_eq!(
            record.pinned_verifier_executable_refs,
            vec![Some(first8_pin)]
        );
        assert!(record.mutable_override);

        let empty = complete(
            reader
                .find_latest_context_rule_pinned_hashes(6, "CDABC...12345")
                .unwrap(),
        );
        assert!(empty.pinned_verifier_hashes.is_empty());
        assert!(empty.pinned_policy_hashes.is_empty());
        assert!(empty.mutable_override, "the flags of the row are kept");

        let policy_only = incomplete(
            reader
                .find_latest_context_rule_pinned_hashes(7, "CDABC...12345")
                .unwrap(),
        );
        assert_eq!(policy_only.row_kind, "sa_context_rule_pins_updated");

        let all = reader.scan_all_context_rule_pin_records().unwrap();
        assert_eq!(all.len(), 3);
        assert!(matches!(all[0].2, ContextRulePinRecord::Incomplete(_)));
        assert!(matches!(all[1].2, ContextRulePinRecord::Complete(_)));
        assert!(matches!(all[2].2, ContextRulePinRecord::Incomplete(_)));
    }

    /// Selection takes the newest pin row across both versions, in one file
    /// and across rotation, and an incomplete newest record is returned as
    /// such: the read never falls back to an older complete row.
    #[test]
    fn pin_record_selection_spans_both_versions_without_fallback() {
        use crate::audit_log::schema::PinsUpdateReason;

        let full_then_prefix = |w: &mut AuditWriter, rotate: bool| {
            write_event(
                w,
                context_rule_created_event(5, "CDABC...12345", vec![h(0x42)], vec![], false, false),
            );
            if rotate {
                w.force_rotate_for_test().unwrap();
            }
            write_event(
                w,
                v1_pins_updated_event(
                    5,
                    "CDABC...12345",
                    vec!["4242424242424242".to_owned()],
                    vec![],
                ),
            );
        };
        let prefix_then_full = |w: &mut AuditWriter, rotate: bool| {
            write_event(
                w,
                v1_created_event(
                    5,
                    "CDABC...12345",
                    vec!["4242424242424242".to_owned()],
                    vec![],
                    vec![],
                ),
            );
            if rotate {
                w.force_rotate_for_test().unwrap();
            }
            write_event(
                w,
                pins_updated_event(
                    5,
                    "CDABC...12345",
                    vec![h(0x42)],
                    vec![],
                    false,
                    false,
                    vec![],
                    PinsUpdateReason::BaselineRefreshed,
                ),
            );
        };
        for rotate in [false, true] {
            let dir = TempDir::new().unwrap();
            let writer = open_writer(tmp_log(&dir));
            full_then_prefix(&mut writer.lock().unwrap(), rotate);
            let reader = AuditReader::new(Arc::clone(&writer), None);
            let record = incomplete(
                reader
                    .find_latest_context_rule_pinned_hashes(5, "CDABC...12345")
                    .unwrap(),
            );
            assert_eq!(
                record.row_kind, "sa_context_rule_pins_updated",
                "rotate={rotate}"
            );
            let all = reader.scan_all_context_rule_pin_records().unwrap();
            assert_eq!(all.len(), 1);
            assert!(
                matches!(all[0].2, ContextRulePinRecord::Incomplete(_)),
                "rotate={rotate}"
            );

            let dir = TempDir::new().unwrap();
            let writer = open_writer(tmp_log(&dir));
            prefix_then_full(&mut writer.lock().unwrap(), rotate);
            let reader = AuditReader::new(Arc::clone(&writer), None);
            let record = complete(
                reader
                    .find_latest_context_rule_pinned_hashes(5, "CDABC...12345")
                    .unwrap(),
            );
            assert_eq!(
                record.pinned_verifier_hashes,
                vec![h(0x42)],
                "rotate={rotate}"
            );
            let all = reader.scan_all_context_rule_pin_records().unwrap();
            assert_eq!(all.len(), 1);
            assert!(
                matches!(all[0].2, ContextRulePinRecord::Complete(_)),
                "rotate={rotate}"
            );
        }
    }

    // ── 15. find_latest_context_rule_pinned_hashes: returns None when no match ─

    #[test]
    fn find_latest_context_rule_pinned_hashes_returns_none_when_no_match() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        {
            let mut w = writer.lock().unwrap();
            write_event(
                &mut w,
                context_rule_created_event(1, "CDABC...12345", vec![], vec![], false, false),
            );
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        // Different rule_id — must not match.
        let result = reader
            .find_latest_context_rule_pinned_hashes(99, "CDABC...12345")
            .unwrap();
        assert!(result.is_none());
    }

    // ── 16. find_latest_context_rule_pinned_hashes: most-recent row wins ───────

    #[test]
    fn find_latest_context_rule_pinned_hashes_returns_most_recent_row() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());
        let (pinned, twin) = pinned_and_twin();

        {
            let mut w = writer.lock().unwrap();
            write_event(
                &mut w,
                context_rule_created_event(
                    1,
                    "CDABC...12345",
                    vec![WasmHashPin::new(pinned)],
                    vec![],
                    false,
                    false,
                ),
            );
            // Reinstall under the same rule id with an equal-prefix twin.
            write_event(
                &mut w,
                context_rule_created_event(
                    1,
                    "CDABC...12345",
                    vec![WasmHashPin::new(twin)],
                    vec![],
                    false,
                    false,
                ),
            );
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let record = complete(
            reader
                .find_latest_context_rule_pinned_hashes(1, "CDABC...12345")
                .unwrap(),
        );

        assert_eq!(
            record.pinned_verifier_hashes,
            vec![WasmHashPin::new(twin)],
            "most-recent reinstall hash must win"
        );
    }

    // ── 17. scan_all_context_rule_pin_records: collects all rules ─────────────────

    #[test]
    fn scan_all_context_rule_pin_records_collects_all_rules_deduped() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        {
            let mut w = writer.lock().unwrap();
            // Rule 1 on account A — installed twice; most-recent wins.
            write_event(
                &mut w,
                context_rule_created_event(1, "CAAA1...11111", vec![h(0xaa)], vec![], false, false),
            );
            write_event(
                &mut w,
                context_rule_created_event(1, "CAAA1...11111", vec![h(0xbb)], vec![], false, false),
            );
            // Rule 2 on account B — installed once.
            write_event(
                &mut w,
                context_rule_created_event(
                    2,
                    "CBBB2...22222",
                    vec![h(0xcc)],
                    vec![h(0xdd)],
                    false,
                    false,
                ),
            );
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let mut results = reader.scan_all_context_rule_pin_records().unwrap();
        // Results are sorted by (rule_id, smart_account).
        results.sort_by_key(|(rid, sa, _)| (*rid, sa.clone()));

        assert_eq!(results.len(), 2, "two distinct (rule_id, sa) pairs");

        let (r0_id, r0_sa, r0_rec) = &results[0];
        assert_eq!(*r0_id, 1);
        assert_eq!(r0_sa, "CAAA1...11111");
        assert_eq!(
            complete(Some(r0_rec.clone())).pinned_verifier_hashes,
            vec![h(0xbb)],
            "most-recent reinstall must win for rule 1"
        );

        let (r1_id, r1_sa, r1_rec) = &results[1];
        assert_eq!(*r1_id, 2);
        assert_eq!(r1_sa, "CBBB2...22222");
        let r1_rec = complete(Some(r1_rec.clone()));
        assert_eq!(r1_rec.pinned_verifier_hashes, vec![h(0xcc)]);
        assert_eq!(r1_rec.pinned_policy_hashes, vec![h(0xdd)]);
    }

    // ── 18. scan_all_context_rule_pin_records: empty log returns empty vec ─────────

    #[test]
    fn scan_all_context_rule_pin_records_returns_empty_for_empty_log() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        // Write a row of another kind so the log file exists but has no
        // matching rows.
        {
            let mut w = writer.lock().unwrap();
            write_event(&mut w, baselined_event(1, "CDABC...12345", 1, 1));
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let results = reader.scan_all_context_rule_pin_records().unwrap();
        assert!(results.is_empty(), "no pin rows → empty result");
    }

    // ── 19. find_installed_context_rule_ids: basic lifecycle ──────────────────

    #[test]
    fn find_installed_context_rule_ids_returns_created_minus_deleted() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        {
            let mut w = writer.lock().unwrap();
            // Install rules 1, 2, 3 then delete rule 2.
            write_event(
                &mut w,
                context_rule_created_event(1, "CDABC...12345", vec![], vec![], false, false),
            );
            write_event(
                &mut w,
                context_rule_created_event(2, "CDABC...12345", vec![], vec![], false, false),
            );
            write_event(
                &mut w,
                context_rule_created_event(3, "CDABC...12345", vec![], vec![], false, false),
            );
            write_event(&mut w, context_rule_deleted_event(2, "CDABC...12345"));
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let live_ids = reader
            .find_installed_context_rule_ids("CDABC...12345")
            .unwrap();

        assert_eq!(live_ids, vec![1, 3], "rule 2 deleted; rules 1 and 3 live");
    }

    // ── 20. find_installed_context_rule_ids: all deleted returns empty ─────────

    #[test]
    fn find_installed_context_rule_ids_returns_empty_when_all_deleted() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        {
            let mut w = writer.lock().unwrap();
            write_event(
                &mut w,
                context_rule_created_event(1, "CDABC...12345", vec![], vec![], false, false),
            );
            write_event(&mut w, context_rule_deleted_event(1, "CDABC...12345"));
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let live_ids = reader
            .find_installed_context_rule_ids("CDABC...12345")
            .unwrap();

        assert!(
            live_ids.is_empty(),
            "all installed rules deleted → empty result"
        );
    }

    // ── 21. find_installed_context_rule_ids: no rows returns empty ────────────

    #[test]
    fn find_installed_context_rule_ids_returns_empty_for_different_account() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        {
            let mut w = writer.lock().unwrap();
            // Rows exist but for a different smart account.
            write_event(
                &mut w,
                context_rule_created_event(1, "COTHER...OTHER", vec![], vec![], false, false),
            );
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let live_ids = reader
            .find_installed_context_rule_ids("CDABC...12345")
            .unwrap();

        assert!(
            live_ids.is_empty(),
            "rows for different SA must not appear in result"
        );
    }

    // ── 22. find_pending_timelock_operations: basic scheduled→pending ──────────

    #[test]
    fn find_pending_timelock_operations_returns_scheduled_ops() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        let op_id = "a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1";
        let tl_redacted = "CAAAA...BBBBB";
        let req_id = uuid::Uuid::new_v4().to_string();

        {
            let mut w = writer.lock().unwrap();
            write_event(
                &mut w,
                timelock_scheduled_event(op_id, tl_redacted, &req_id),
            );
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let pending = reader
            .find_pending_timelock_operations(tl_redacted)
            .unwrap();

        assert_eq!(pending.len(), 1, "one pending op");
        let (found_op_id, found_req_id, found_tl) = &pending[0];
        assert_eq!(found_op_id, op_id, "operation_id_full_hex must match");
        assert_eq!(found_req_id, &req_id, "request_id must match");
        assert_eq!(found_tl, tl_redacted, "timelock_redacted must match");
    }

    // ── 23. find_pending_timelock_operations: cancelled removes from pending ───

    #[test]
    fn find_pending_timelock_operations_cancelled_op_is_not_pending() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        let op_id = "1111111111111111111111111111111111111111111111111111111111111111";
        let tl_redacted = "CTLLL...TTTTT";

        {
            let mut w = writer.lock().unwrap();
            write_event(
                &mut w,
                timelock_scheduled_event(op_id, tl_redacted, "req-sched-1"),
            );
            write_event(&mut w, timelock_cancelled_event(op_id, tl_redacted));
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let pending = reader
            .find_pending_timelock_operations(tl_redacted)
            .unwrap();

        assert!(
            pending.is_empty(),
            "cancelled op must not appear in pending list"
        );
    }

    // ── 24. find_pending_timelock_operations: executed removes from pending ────

    #[test]
    fn find_pending_timelock_operations_executed_op_is_not_pending() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        let op_id = "2222222222222222222222222222222222222222222222222222222222222222";
        let tl_redacted = "CTLLL...TTTTT";

        {
            let mut w = writer.lock().unwrap();
            write_event(
                &mut w,
                timelock_scheduled_event(op_id, tl_redacted, "req-sched-2"),
            );
            write_event(&mut w, timelock_executed_event(op_id, tl_redacted));
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let pending = reader
            .find_pending_timelock_operations(tl_redacted)
            .unwrap();

        assert!(
            pending.is_empty(),
            "executed op must not appear in pending list"
        );
    }

    // ── 25. find_pending_timelock_operations: two ops; one cancelled ──────────

    #[test]
    fn find_pending_timelock_operations_mixed_ops_only_pending_returned() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        let op1 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let op2 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let tl_redacted = "CTLLL...TTTTT";
        let req1 = "req-a";
        let req2 = "req-b";

        {
            let mut w = writer.lock().unwrap();
            write_event(&mut w, timelock_scheduled_event(op1, tl_redacted, req1));
            write_event(&mut w, timelock_scheduled_event(op2, tl_redacted, req2));
            // Cancel op1; op2 remains pending.
            write_event(&mut w, timelock_cancelled_event(op1, tl_redacted));
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let pending = reader
            .find_pending_timelock_operations(tl_redacted)
            .unwrap();

        assert_eq!(pending.len(), 1, "only op2 is still pending");
        let (found_op_id, found_req_id, _) = &pending[0];
        assert_eq!(found_op_id, op2, "pending op must be op2");
        assert_eq!(found_req_id, req2);
    }

    // ── 26. find_pending_timelock_operations: different timelock addr ignored ──

    #[test]
    fn find_pending_timelock_operations_ignores_different_timelock_address() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        let op_id = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let tl_a = "CTAAA...AAAAA";
        let tl_b = "CTBBB...BBBBB";

        {
            let mut w = writer.lock().unwrap();
            // Schedule on timelock A; query for timelock B.
            write_event(&mut w, timelock_scheduled_event(op_id, tl_a, "req-diff-tl"));
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let pending = reader.find_pending_timelock_operations(tl_b).unwrap();

        assert!(
            pending.is_empty(),
            "ops on a different timelock must not appear"
        );
    }

    // ── 27. find_latest_context_rule_pinned_hashes: chain broken in active file

    #[test]
    fn find_latest_context_rule_pinned_hashes_chain_broken_propagates() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        {
            let mut w = writer.lock().unwrap();
            write_event(
                &mut w,
                context_rule_created_event(1, "CDABC...12345", vec![], vec![], false, false),
            );
            write_event(
                &mut w,
                context_rule_created_event(1, "CDABC...12345", vec![], vec![], false, false),
            );
        }

        // Tamper: corrupt the second row's `previous_entry_hash` field.
        {
            let contents = std::fs::read_to_string(&path).unwrap();
            let mut lines: Vec<String> = contents.lines().map(|l| l.to_owned()).collect();
            if lines.len() >= 2 {
                let tampered = lines[1].replace(
                    "\"previous_entry_hash\":\"sha256:",
                    "\"previous_entry_hash\":\"sha256:FFFF",
                );
                if tampered != lines[1] {
                    lines[1] = tampered;
                    std::fs::write(&path, lines.join("\n") + "\n").unwrap();
                }
            }
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let result = reader.find_latest_context_rule_pinned_hashes(1, "CDABC...12345");

        match result {
            Err(AuditLogIntegrityError::ChainBroken { .. }) => {}
            other => panic!("expected ChainBroken for tampered hash, got: {other:?}"),
        }
    }

    // ── 28. find_installed_context_rule_ids: chain broken propagates ──────────

    #[test]
    fn find_installed_context_rule_ids_chain_broken_propagates() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        {
            let mut w = writer.lock().unwrap();
            write_event(
                &mut w,
                context_rule_created_event(1, "CDABC...12345", vec![], vec![], false, false),
            );
            write_event(
                &mut w,
                context_rule_created_event(2, "CDABC...12345", vec![], vec![], false, false),
            );
        }

        // Tamper: corrupt the second row's `previous_entry_hash`.
        {
            let contents = std::fs::read_to_string(&path).unwrap();
            let mut lines: Vec<String> = contents.lines().map(|l| l.to_owned()).collect();
            if lines.len() >= 2 {
                let tampered = lines[1].replace(
                    "\"previous_entry_hash\":\"sha256:",
                    "\"previous_entry_hash\":\"sha256:FFFF",
                );
                if tampered != lines[1] {
                    lines[1] = tampered;
                    std::fs::write(&path, lines.join("\n") + "\n").unwrap();
                }
            }
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let result = reader.find_installed_context_rule_ids("CDABC...12345");

        match result {
            Err(AuditLogIntegrityError::ChainBroken { .. }) => {}
            other => panic!("expected ChainBroken for tampered hash, got: {other:?}"),
        }
    }

    // ── 29. find_pending_timelock_operations: chain broken propagates ──────────

    #[test]
    fn find_pending_timelock_operations_chain_broken_propagates() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        let op_id = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
        let tl_redacted = "CTLLL...TTTTT";

        {
            let mut w = writer.lock().unwrap();
            write_event(
                &mut w,
                timelock_scheduled_event(op_id, tl_redacted, "req-chain-break"),
            );
            write_event(
                &mut w,
                timelock_scheduled_event(op_id, tl_redacted, "req-chain-break-2"),
            );
        }

        // Tamper: corrupt the second row's `previous_entry_hash`.
        {
            let contents = std::fs::read_to_string(&path).unwrap();
            let mut lines: Vec<String> = contents.lines().map(|l| l.to_owned()).collect();
            if lines.len() >= 2 {
                let tampered = lines[1].replace(
                    "\"previous_entry_hash\":\"sha256:",
                    "\"previous_entry_hash\":\"sha256:FFFF",
                );
                if tampered != lines[1] {
                    lines[1] = tampered;
                    std::fs::write(&path, lines.join("\n") + "\n").unwrap();
                }
            }
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let result = reader.find_pending_timelock_operations(tl_redacted);

        match result {
            Err(AuditLogIntegrityError::ChainBroken { .. }) => {}
            other => panic!("expected ChainBroken for tampered hash, got: {other:?}"),
        }
    }

    // ── 30. Empty active log (no entries yet) → all methods return Ok empty ────

    #[test]
    fn empty_log_all_methods_return_ok_empty() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        // Open writer without writing any entries — creates the file but leaves it empty.
        let writer = open_writer(path.clone());

        let reader = AuditReader::new(Arc::clone(&writer), None);

        let ss = reader
            .find_latest_signer_set_view(1, "CDABC...12345", &NO_DIGEST)
            .unwrap();
        assert!(
            ss.is_none(),
            "empty log: find_latest_signer_set_view must be None"
        );

        let pins = reader
            .find_latest_context_rule_pinned_hashes(1, "CDABC...12345")
            .unwrap();
        assert!(
            pins.is_none(),
            "empty log: find_latest_context_rule_pinned_hashes must be None"
        );

        let all_rules = reader.scan_all_context_rule_pin_records().unwrap();
        assert!(
            all_rules.is_empty(),
            "empty log: scan_all_context_rule_pin_records must be empty"
        );

        let ids = reader
            .find_installed_context_rule_ids("CDABC...12345")
            .unwrap();
        assert!(
            ids.is_empty(),
            "empty log: find_installed_context_rule_ids must be empty"
        );

        let pending = reader
            .find_pending_timelock_operations("CTLLL...TTTTT")
            .unwrap();
        assert!(
            pending.is_empty(),
            "empty log: find_pending_timelock_operations must be empty"
        );
    }

    // ── 31. row_hash is the body-only SHA-256, not the chain-link hash ─────────

    #[test]
    fn row_hash_is_body_only_sha256_not_chain_link_hash() {
        // The SignerSetViewPayload row_hash is SHA-256(canonical_body with
        // previous_entry_hash=""), NOT the chain-link hash which also covers
        // the previous_entry_hash bytes. For the first row in a fresh log the
        // chain-link hash equals SHA-256(body || ZERO_BLOCK_HASH_bytes), but the
        // row_hash is SHA-256(body || "") (body-only canonical form).
        // We can verify by writing two entries for the same key; if both return
        // distinct row_hashes the second row's hash is NOT the same as the first.
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        {
            let mut w = writer.lock().unwrap();
            write_event(&mut w, baselined_event(1, "CDABC...12345", 2, 2));
            write_event(&mut w, baselined_event(1, "CDABC...12345", 3, 2));
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);

        // Query returns the most-recent row.
        let payload = reader
            .find_latest_signer_set_view(1, "CDABC...12345", &NO_DIGEST)
            .unwrap()
            .expect("must find a row");

        // The row_hash must be non-zero (not the zero-block placeholder).
        assert_ne!(
            *payload.row_hash(),
            [0u8; 32],
            "row_hash must be a real SHA-256, not the zero sentinel"
        );

        // The row_hash must be exactly 32 bytes (SHA-256 output size).
        assert_eq!(payload.row_hash().len(), 32, "row_hash must be 32 bytes");

        // The state fields must match the most-recent entry's payload.
        assert_eq!(v1_state(&payload).signer_count, 3);
    }

    // ── 32. scan_all_context_rule_pin_records: newest-file-first ordering ──────────

    #[test]
    fn scan_all_context_rule_pin_records_newest_file_wins_after_rotation() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        {
            let mut w = writer.lock().unwrap();
            // Install rule 1 with an 0xaa verifier hash in the first (to-be-rotated) file.
            write_event(
                &mut w,
                context_rule_created_event(1, "CDABC...12345", vec![h(0xaa)], vec![], false, false),
            );
            w.force_rotate_for_test().unwrap();
            // Reinstall rule 1 with an 0xbb verifier hash in the new active file.
            write_event(
                &mut w,
                context_rule_created_event(1, "CDABC...12345", vec![h(0xbb)], vec![], false, false),
            );
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let results = reader.scan_all_context_rule_pin_records().unwrap();

        // Exactly one (rule_id=1, sa) pair, with the most-recent (active-file) hash.
        assert_eq!(results.len(), 1, "deduped to one entry");
        let (_, _, rec) = &results[0];
        assert_eq!(
            complete(Some(rec.clone())).pinned_verifier_hashes,
            vec![h(0xbb)],
            "reinstall in newer file must win over older file's entry"
        );
    }

    // ── 33. find_installed_context_rule_ids: result is sorted ─────────────────

    #[test]
    fn find_installed_context_rule_ids_result_is_sorted() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        {
            let mut w = writer.lock().unwrap();
            // Install rules in non-sorted order: 3, 1, 2.
            write_event(
                &mut w,
                context_rule_created_event(3, "CDABC...12345", vec![], vec![], false, false),
            );
            write_event(
                &mut w,
                context_rule_created_event(1, "CDABC...12345", vec![], vec![], false, false),
            );
            write_event(
                &mut w,
                context_rule_created_event(2, "CDABC...12345", vec![], vec![], false, false),
            );
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let ids = reader
            .find_installed_context_rule_ids("CDABC...12345")
            .unwrap();

        assert_eq!(ids, vec![1, 2, 3], "result must be sorted ascending");
    }

    // ── 34. Non-regular file at log path → NonRegularFileLogPath ──────────────

    #[cfg(unix)]
    #[test]
    fn symlink_at_log_path_returns_non_regular_file_error() {
        use std::os::unix::fs::symlink;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let target = dir.path().join("does_not_exist_target");

        // Create a dangling symlink at the log path.
        symlink(&target, &path).unwrap();

        // Every walk reads a file through `read_file_rows`, which opens it with
        // `open_regular_file`; that open rejects the symlink.
        let result = read_file_rows(&path, None, None, None);

        match result {
            Err(AuditLogIntegrityError::NonRegularFileLogPath { .. }) => {}
            Err(AuditLogIntegrityError::Io(_)) => {
                // Acceptable: some OS configurations return an Io error when
                // symlink_metadata fails on a dangling symlink.
            }
            other => panic!("expected NonRegularFileLogPath or Io for symlink, got: {other:?}"),
        }
    }

    // ── 35. collect_files_newest_first: active-only = single-element vec ───────

    #[test]
    fn collect_files_newest_first_active_only_returns_single_path() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        // Create the file to satisfy `dir.exists()` in collect_files_newest_first.
        std::fs::File::create(&path).unwrap();

        let chain = collect_files_newest_first(&path).unwrap();
        assert_eq!(chain.len(), 1, "no rotated siblings → only active file");
        assert_eq!(chain[0], path, "first element must be the active path");
    }

    // ── 36. find_latest_signer_set_view: active-file-only, no rotated files ───

    #[test]
    fn find_latest_signer_set_view_no_rows_no_rotated_files_returns_none() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        // Open writer; do NOT write anything.
        let writer = open_writer(path.clone());

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let result = reader
            .find_latest_signer_set_view(1, "CDABC...12345", &NO_DIGEST)
            .unwrap();

        assert!(
            result.is_none(),
            "fresh wallet with no entries must return None, not an error"
        );
    }

    #[test]
    fn single_row_active_file_previous_hash_tamper_returns_chain_broken() {
        // A file with exactly one row has no row-2 chain check to detect
        // tampering of that row. The first-row check enforces that the single
        // row's stored `previous_entry_hash` field equals ZERO_BLOCK_HASH (the
        // only valid predecessor for the first row in a single-file chain).
        //
        // What this test covers: `previous_entry_hash` field tampering on a
        // single-row baseline file. An attacker rewrites the stored
        // `previous_entry_hash` from ZERO_BLOCK_HASH to an arbitrary hash.
        // The first-row check in `scan_file_for_signer_set` catches this via
        // `expected_first_row_prev: Some(ZERO_BLOCK_HASH)` and returns `ChainBroken`.
        //
        // What this test does NOT cover: pure body-field tamper (e.g. mutating
        // `observed_signer_count` while leaving `previous_entry_hash` legitimate).
        // For a single-row file there is no row-2 chain link to catch body-field
        // tamper via hash-chain alone. Body-tamper detection for single-row
        // baseline files is layered: (a) HMAC sidecar when `hmac_key: Some(_)`;
        // (b) two-RPC divergence check at next-signing time. The audit-log
        // chain-only primitive does not detect pure body-tamper of a single-row
        // file; that is a defence-in-depth property of the layered model.
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());

        {
            let mut w = writer.lock().unwrap();
            // Write exactly ONE baseline row — the fresh-wallet scenario.
            write_event(&mut w, baselined_event(1, "CDABC...12345", 2, 2));
        }

        // Tamper: rewrite the single row's `previous_entry_hash` field from
        // ZERO_BLOCK_HASH to an attacker-chosen value. The first-row check in
        // `scan_file_for_signer_set` must catch this and return ChainBroken.
        // Without the check, this single-row file would return Ok(Some(...)).
        //
        // ZERO_BLOCK_HASH = sha256:66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925
        let tamper_applied;
        {
            let contents = std::fs::read_to_string(&path).unwrap();
            let mut lines: Vec<String> = contents.lines().map(|l| l.to_owned()).collect();
            assert_eq!(lines.len(), 1, "single-row precondition");
            // Replace the verbatim ZERO_BLOCK_HASH value stored in the JSON row's
            // `previous_entry_hash` field with an all-F hash.
            let original = lines[0].clone();
            let tampered = lines[0].replace(
                ZERO_BLOCK_HASH,
                "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            );
            tamper_applied = tampered != original;
            if tamper_applied {
                lines[0] = tampered;
                std::fs::write(&path, lines.join("\n") + "\n").unwrap();
            }
        }

        // Assert the tamper was applied. If ZERO_BLOCK_HASH no longer appears
        // verbatim in the stored row (schema drift), this test must fail loudly
        // rather than silently no-op. A silent skip would leave the first-row
        // check unverified for the new schema.
        assert!(
            tamper_applied,
            "schema drift: ZERO_BLOCK_HASH no longer appears verbatim in row; \
             this regression test must be re-authored for the new schema"
        );

        {
            let reader = AuditReader::new(Arc::clone(&writer), None);
            let result = reader.find_latest_signer_set_view(1, "CDABC...12345", &NO_DIGEST);

            // Must return ChainBroken — NOT Ok(None) (which would hide the tamper)
            // and NOT Ok(Some(...)) (which would return unmodified signer-set state
            // silently ignoring the tampered predecessor hash).
            match result {
                Err(AuditLogIntegrityError::ChainBroken { .. }) => {
                    // Correct: tampered `previous_entry_hash` on the single-row
                    // baseline file detected as expected.
                }
                Ok(None) => panic!("single-row tamper must not return Ok(None)"),
                Ok(Some(p)) => panic!(
                    "single-row tamper must not return Ok(Some(...)): signer_count={}",
                    v1_state(&p).signer_count
                ),
                Err(other) => panic!("expected ChainBroken, got: {other:?}"),
            }
        }
    }

    // ── Version-2 state rows ──────────────────────────────────────────────────

    const READER_DIGEST: [u8; 32] = [0xd1; 32];
    const OTHER_DIGEST: [u8; 32] = [0xd2; 32];

    /// A version-2 snapshot of `signer_count` Ed25519 signers with ids
    /// `0..signer_count` and a threshold observation of `threshold`.
    fn ed25519_snapshot(signer_count: u32, threshold: u32) -> SignerSetSnapshotV2 {
        SignerSetSnapshotV2 {
            signers: (0..signer_count)
                .map(|id| SignerEntryV2 {
                    id,
                    identity: SignerIdentityV2::Ed25519 {
                        pubkey: [u8::try_from(id).unwrap() + 1; 32],
                    },
                })
                .collect(),
            threshold: Some(ThresholdObservation {
                policy: [0x77; 32],
                threshold,
            }),
        }
    }

    fn baselined_v2_event(
        rule_id: u32,
        sa_redacted: &str,
        account_digest: [u8; 32],
        snapshot: SignerSetSnapshotV2,
    ) -> EventKind {
        EventKind::SaSignerSetBaselinedV2 {
            rule_id,
            snapshot,
            observed_at_ledger_seq: 1_000,
            observed_at_unix_ms: 1_700_000_000_000,
            baseline_reason: BaselineReason::confirmed_install(),
            prev_chain_tip_hash: [0u8; 32],
            account_digest,
            smart_account_redacted: RedactedStrkey::from_already_redacted(sa_redacted),
        }
    }

    /// The version-2 snapshot of a payload; panics on a version-1 view.
    fn v2_state(payload: &SignerSetViewPayload) -> &SignerSetSnapshotV2 {
        match payload.view() {
            SignerSetView::V2(snapshot) => snapshot,
            SignerSetView::V1(_) => panic!("expected a version-2 view, got {payload:?}"),
        }
    }

    #[test]
    fn find_latest_signer_set_view_returns_v2_baseline_with_line_and_file() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());
        {
            let mut w = writer.lock().unwrap();
            write_event(&mut w, baselined_event(9, "CDABC...12345", 1, 1));
            write_event(
                &mut w,
                baselined_v2_event(1, "CDABC...12345", READER_DIGEST, ed25519_snapshot(2, 2)),
            );
            write_event(&mut w, baselined_event(8, "CDABC...12345", 1, 1));
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let payload = reader
            .find_latest_signer_set_view(1, "CDABC...12345", &READER_DIGEST)
            .unwrap()
            .expect("the v2 baseline row is found");
        assert_eq!(payload.view().version(), 2);
        assert_eq!(v2_state(&payload), &ed25519_snapshot(2, 2));
        assert_eq!(payload.line(), 2);
        assert_eq!(payload.file(), "audit.jsonl");
        assert_ne!(*payload.row_hash(), [0u8; 32]);
    }

    #[test]
    fn find_latest_signer_set_view_newer_v2_row_wins_over_older_v1_row() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());
        {
            let mut w = writer.lock().unwrap();
            write_event(&mut w, baselined_event(1, "CDABC...12345", 2, 2));
            write_event(
                &mut w,
                baselined_v2_event(1, "CDABC...12345", READER_DIGEST, ed25519_snapshot(3, 2)),
            );
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let payload = reader
            .find_latest_signer_set_view(1, "CDABC...12345", &READER_DIGEST)
            .unwrap()
            .unwrap();
        assert_eq!(v2_state(&payload).signer_count(), 3);
        assert_eq!(payload.line(), 2);
    }

    #[test]
    fn find_latest_signer_set_view_newer_v1_row_wins_over_older_v2_row() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());
        {
            let mut w = writer.lock().unwrap();
            write_event(
                &mut w,
                baselined_v2_event(1, "CDABC...12345", READER_DIGEST, ed25519_snapshot(3, 2)),
            );
            write_event(&mut w, baselined_event(1, "CDABC...12345", 2, 2));
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let payload = reader
            .find_latest_signer_set_view(1, "CDABC...12345", &READER_DIGEST)
            .unwrap()
            .unwrap();
        assert_eq!(payload.view().version(), 1);
        assert_eq!(v1_state(&payload).signer_count, 2);
        assert_eq!(payload.line(), 2);
    }

    /// A version-2 row is keyed on the account digest: a newer row with the
    /// same rule and redacted account but another digest belongs to another
    /// account or network and is skipped.
    #[test]
    fn find_latest_signer_set_view_skips_v2_row_with_another_account_digest() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());
        {
            let mut w = writer.lock().unwrap();
            write_event(&mut w, baselined_event(1, "CDABC...12345", 2, 1));
            write_event(
                &mut w,
                baselined_v2_event(1, "CDABC...12345", OTHER_DIGEST, ed25519_snapshot(4, 3)),
            );
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let payload = reader
            .find_latest_signer_set_view(1, "CDABC...12345", &READER_DIGEST)
            .unwrap()
            .unwrap();
        assert_eq!(payload.view().version(), 1, "{payload:?}");
        assert_eq!(v1_state(&payload).signer_count, 2);
        assert_eq!(payload.line(), 1);
    }

    /// A version-1 row is keyed on the redacted account: a newer row for
    /// another redacted account is skipped and the older version-2 row with
    /// the reader's digest is returned.
    #[test]
    fn find_latest_signer_set_view_skips_v1_row_for_another_redacted_account() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());
        {
            let mut w = writer.lock().unwrap();
            write_event(
                &mut w,
                baselined_v2_event(1, "CDABC...12345", READER_DIGEST, ed25519_snapshot(2, 1)),
            );
            write_event(&mut w, baselined_event(1, "COTHE...OTHER", 5, 5));
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let payload = reader
            .find_latest_signer_set_view(1, "CDABC...12345", &READER_DIGEST)
            .unwrap()
            .unwrap();
        assert_eq!(v2_state(&payload), &ed25519_snapshot(2, 1));
        assert_eq!(payload.line(), 1);
    }

    /// A version-2 row is keyed on the rule as well as the account digest: a
    /// newer row for another rule with the reader's digest is skipped, and
    /// each rule reads its own newest row.
    #[test]
    fn find_latest_signer_set_view_keys_v2_rows_on_the_rule() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());
        {
            let mut w = writer.lock().unwrap();
            write_event(&mut w, baselined_event(1, "CDABC...12345", 2, 1));
            write_event(
                &mut w,
                baselined_v2_event(2, "CDABC...12345", READER_DIGEST, ed25519_snapshot(3, 2)),
            );
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let rule_1 = reader
            .find_latest_signer_set_view(1, "CDABC...12345", &READER_DIGEST)
            .unwrap()
            .unwrap();
        assert_eq!(rule_1.line(), 1, "{rule_1:?}");
        assert_eq!(v1_state(&rule_1).signer_count, 2);

        let rule_2 = reader
            .find_latest_signer_set_view(2, "CDABC...12345", &READER_DIGEST)
            .unwrap()
            .unwrap();
        assert_eq!(rule_2.line(), 2, "{rule_2:?}");
        assert_eq!(v2_state(&rule_2), &ed25519_snapshot(3, 2));
    }

    /// A version-2 row with duplicate signer ids is an integrity error for
    /// every reader of the file, including one looking for another rule.
    #[test]
    fn find_latest_signer_set_view_refuses_v2_row_with_duplicate_ids_for_another_rule() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());
        let mut duplicate = ed25519_snapshot(2, 1);
        duplicate.signers[1].id = duplicate.signers[0].id;
        {
            let mut w = writer.lock().unwrap();
            write_event(&mut w, baselined_event(1, "CDABC...12345", 2, 1));
            write_event(
                &mut w,
                baselined_v2_event(7, "CDABC...12345", OTHER_DIGEST, duplicate),
            );
        }

        let reader = AuditReader::new(Arc::clone(&writer), None);
        match reader.find_latest_signer_set_view(1, "CDABC...12345", &READER_DIGEST) {
            Err(AuditLogIntegrityError::ParseError { line, detail }) => {
                assert_eq!(line, 2);
                assert!(detail.contains("duplicate signer id"), "{detail}");
            }
            other => panic!("expected ParseError at line 2, got {other:?}"),
        }
    }

    /// A version-2 row whose snapshot omits the `threshold` key does not
    /// deserialize and is an integrity error at its line.
    #[test]
    fn find_latest_signer_set_view_refuses_v2_row_without_threshold_key() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());
        {
            let mut w = writer.lock().unwrap();
            write_event(&mut w, baselined_event(1, "CDABC...12345", 2, 1));
            write_event(
                &mut w,
                baselined_v2_event(1, "CDABC...12345", READER_DIGEST, ed25519_snapshot(2, 1)),
            );
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
        let mut row: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(&lines[1]).unwrap();
        let removed = row
            .get_mut("snapshot")
            .and_then(serde_json::Value::as_object_mut)
            .and_then(|snapshot| snapshot.remove("threshold"));
        assert!(removed.is_some(), "the row spells the threshold key");
        lines[1] = serde_json::to_string(&row).unwrap();
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();

        let reader = AuditReader::new(Arc::clone(&writer), None);
        match reader.find_latest_signer_set_view(1, "CDABC...12345", &READER_DIGEST) {
            Err(AuditLogIntegrityError::ParseError { line, detail }) => {
                assert_eq!(line, 2);
                assert!(detail.contains("missing field `threshold`"), "{detail}");
            }
            other => panic!("expected ParseError at line 2, got {other:?}"),
        }
    }

    #[test]
    fn find_latest_signer_set_view_discovers_v2_row_in_rotated_file() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());
        {
            let mut w = writer.lock().unwrap();
            write_event(&mut w, baselined_event(1, "CDABC...12345", 1, 1));
            write_event(
                &mut w,
                baselined_v2_event(1, "CDABC...12345", READER_DIGEST, ed25519_snapshot(2, 2)),
            );
            w.force_rotate_for_test().unwrap();
            write_event(
                &mut w,
                baselined_v2_event(1, "CDABC...12345", OTHER_DIGEST, ed25519_snapshot(1, 1)),
            );
        }
        let rotated: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|name| is_rotated_sibling("audit.jsonl", name))
            .collect();
        assert_eq!(rotated.len(), 1, "{rotated:?}");

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let payload = reader
            .find_latest_signer_set_view(1, "CDABC...12345", &READER_DIGEST)
            .unwrap()
            .expect("the v2 row in the rotated file is found");
        assert_eq!(v2_state(&payload), &ed25519_snapshot(2, 2));
        assert_eq!(payload.file(), rotated[0]);
        assert_eq!(payload.line(), 2);
    }
    // ── bounded walk ─────────────────────────────────────────────────────

    /// An entry carrying `kind`, as a smart-account verb writes it.
    fn event_entry(kind: EventKind) -> AuditEntry {
        let mut entry = AuditEntry::new_tool_invocation(NewToolInvocation::new(
            "smart-account.forged",
            Option::<String>::None,
            vec![],
            PolicyDecision::Allow,
            uuid::Uuid::new_v4().to_string(),
        ));
        entry.event_kind = kind;
        entry
    }

    /// Appends `entry` to `path` past the tip, chained and untagged, as a
    /// process without the writer would.
    fn forge(path: &Path, entry: AuditEntry) {
        crate::audit_log::test_helpers::append_forged_entry(path, entry, |_| None);
    }

    fn failed_row(envelope_hash: &str) -> AuditEntry {
        AuditEntry::new_value_action_failed(
            "stellar_pay",
            Some("stellar:testnet".to_owned()),
            vec![],
            "6ba7aaac...69060003",
            "submission.failed",
            PolicyDecision::Allow,
            Some(envelope_hash.to_owned()),
            None,
            None,
            "req-forged-failed",
        )
    }

    /// A failed row appended past the writer's verified tip is not read: the
    /// pending row stays owed. Inside the bound of a writer that replayed it,
    /// the same row settles the submission.
    #[test]
    fn a_forged_failed_row_past_the_verified_tip_leaves_settlement_owed() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());
        writer
            .lock()
            .unwrap()
            .write_entry(pending_row(SETTLE_ENVELOPE))
            .unwrap();
        forge(&path, failed_row(SETTLE_ENVELOPE));
        assert!(matches!(
            try_value_action_settlement(&writer.lock().unwrap(), SETTLE_ENVELOPE).unwrap(),
            ValueActionSettlement::Owed(_)
        ));
        drop(writer);
        let reopened = open_writer(path);
        assert_eq!(
            try_value_action_settlement(&reopened.lock().unwrap(), SETTLE_ENVELOPE).unwrap(),
            ValueActionSettlement::Settled
        );
    }

    /// The version-2 pin the writer wrote wins over a newer forged pin row
    /// past the verified tip.
    #[test]
    fn a_forged_pin_row_past_the_verified_tip_is_ignored() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());
        write_event(
            &mut writer.lock().unwrap(),
            context_rule_created_event(1, "CDABC...12345", vec![h(0x11)], vec![], false, false),
        );
        forge(
            &path,
            event_entry(pins_updated_event(
                1,
                "CDABC...12345",
                vec![h(0x22)],
                vec![],
                false,
                false,
                vec![],
                crate::audit_log::schema::PinsUpdateReason::SignerAdded,
            )),
        );
        let reader = AuditReader::new(Arc::clone(&writer), None);
        let record = complete(
            reader
                .find_latest_context_rule_pinned_hashes(1, "CDABC...12345")
                .unwrap(),
        );
        assert_eq!(record.pinned_verifier_hashes, vec![h(0x11)]);
    }

    /// One forged row per scan, past the verified tip, leaves every result as
    /// it was.
    #[test]
    fn every_reader_scan_stops_at_the_verified_tip() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());
        {
            let mut guard = writer.lock().unwrap();
            write_event(&mut guard, baselined_event(1, "CDABC...12345", 2, 2));
            write_event(
                &mut guard,
                context_rule_created_event(1, "CDABC...12345", vec![h(0x11)], vec![], false, false),
            );
        }
        let reader = AuditReader::new(Arc::clone(&writer), None);
        let op = "ab".repeat(32);
        let signer_set = reader
            .find_latest_signer_set_view(1, "CDABC...12345", &NO_DIGEST)
            .unwrap();
        let all_pins = reader.scan_all_context_rule_pin_records().unwrap();
        let rule_ids = reader
            .find_installed_context_rule_ids("CDABC...12345")
            .unwrap();
        let timelock = reader
            .find_pending_timelock_operations("CDTLK...54321")
            .unwrap();
        assert!(timelock.is_empty());
        assert!(!reader.pool_initialization_exists("pool-forged").unwrap());
        assert!(
            !try_submission_receipt_cleared_exists(&writer.lock().unwrap(), SETTLE_ENVELOPE)
                .unwrap()
        );

        forge(
            &path,
            event_entry(baselined_event(1, "CDABC...12345", 5, 3)),
        );
        forge(
            &path,
            event_entry(context_rule_created_event(
                2,
                "CDABC...12345",
                vec![h(0x33)],
                vec![],
                false,
                false,
            )),
        );
        forge(
            &path,
            event_entry(timelock_scheduled_event(&op, "CDTLK...54321", "req-forged")),
        );
        let mut pool = AuditEntry::new_channel_pool_initialised(
            "GFUND...FUNDR",
            2,
            "txhash...tail",
            1,
            "pool-forged",
        );
        pool.request_id = "pool-forged".to_owned();
        forge(&path, pool);
        forge(&path, cleared_row());

        // Every scan reads the writer's bound, which ends before the forged rows.
        let unchanged = || {
            assert_eq!(
                reader
                    .find_latest_signer_set_view(1, "CDABC...12345", &NO_DIGEST)
                    .unwrap(),
                signer_set
            );
            assert_eq!(
                reader.scan_all_context_rule_pin_records().unwrap(),
                all_pins
            );
            assert_eq!(
                reader
                    .find_installed_context_rule_ids("CDABC...12345")
                    .unwrap(),
                rule_ids
            );
            assert!(
                reader
                    .find_pending_timelock_operations("CDTLK...54321")
                    .unwrap()
                    .is_empty()
            );
            assert!(!reader.pool_initialization_exists("pool-forged").unwrap());
            assert!(
                !try_submission_receipt_cleared_exists(&writer.lock().unwrap(), SETTLE_ENVELOPE)
                    .unwrap()
            );
        };
        unchanged();
    }

    /// An archive rewritten with a chain that verifies on its own does not
    /// end on the entry the next file chains from.
    #[test]
    fn a_rewritten_archive_fails_the_bridge() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let writer = open_writer(path.clone());
        {
            let mut guard = writer.lock().unwrap();
            write_event(
                &mut guard,
                context_rule_created_event(1, "CDABC...12345", vec![], vec![], false, false),
            );
            guard.force_rotate_for_test().unwrap();
            write_event(
                &mut guard,
                context_rule_created_event(2, "CDABC...12345", vec![], vec![], false, false),
            );
        }
        let archive = collect_files_newest_first(&path).unwrap().remove(1);
        // Rewrite the archive's first row and chain every later row, the
        // handoff included, onto it again: the archive's own chain verifies.
        let rows: Vec<AuditEntry> = std::fs::read_to_string(&archive)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let mut previous = rows[0].previous_entry_hash.clone();
        let mut rewritten = String::new();
        for (index, mut row) in rows.into_iter().enumerate() {
            if index == 0 {
                row.request_id = "rewritten".to_owned();
            }
            row.previous_entry_hash = previous.clone();
            let body = row.canonical_json_body().unwrap();
            previous = compute_entry_hash(&body, &row.previous_entry_hash).unwrap();
            rewritten.push_str(&serde_json::to_string(&row).unwrap());
            rewritten.push('\n');
        }
        std::fs::write(&archive, rewritten).unwrap();

        let reader = AuditReader::new(Arc::clone(&writer), None);
        let err = reader
            .find_installed_context_rule_ids("CDABC...12345")
            .unwrap_err();
        assert!(
            matches!(
                err,
                AuditLogIntegrityError::ChainBroken { reason, .. } if reason == BRIDGE_MISMATCH_REASON
            ),
            "{err:?}"
        );
    }

    /// Entries an `audit_entries_quarantined` row covers are invisible to
    /// every scan: the quarantined pin row and the quarantined failed row
    /// read as absent.
    #[test]
    fn quarantined_rows_are_skipped_by_every_scan() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        {
            let writer = open_writer(path.clone());
            writer
                .lock()
                .unwrap()
                .write_entry(pending_row(SETTLE_ENVELOPE))
                .unwrap();
        }
        forge(
            &path,
            event_entry(context_rule_created_event(
                1,
                "CDABC...12345",
                vec![h(0x44)],
                vec![],
                false,
                false,
            )),
        );
        forge(&path, failed_row(SETTLE_ENVELOPE));
        let writer = open_writer(path.clone());
        writer
            .lock()
            .unwrap()
            .write_entry(AuditEntry::new_audit_entries_quarantined(2, "quarantine"))
            .unwrap();

        let reader = AuditReader::new(Arc::clone(&writer), None);
        assert_eq!(
            reader
                .find_latest_context_rule_pinned_hashes(1, "CDABC...12345")
                .unwrap(),
            None
        );
        assert!(
            reader
                .scan_all_context_rule_pin_records()
                .unwrap()
                .is_empty()
        );
        assert!(
            reader
                .find_installed_context_rule_ids("CDABC...12345")
                .unwrap()
                .is_empty()
        );
        assert!(matches!(
            try_value_action_settlement(&writer.lock().unwrap(), SETTLE_ENVELOPE).unwrap(),
            ValueActionSettlement::Owed(_)
        ));
    }

    /// The audit key of the keyed reader fixtures.
    const KEYED_READER_KEY: [u8; 32] = [0x2b; 32];

    /// Opens a keyed, anchored writer on `path` under [`KEYED_READER_KEY`].
    fn open_keyed_writer(
        path: &Path,
        store: &Arc<crate::audit_log::tip_anchor::InMemoryTipAnchorStore>,
    ) -> AuditWriter {
        AuditWriter::open(
            path.to_path_buf(),
            Some(crate::audit_log::KeyedAuditAccess::new(
                zeroize::Zeroizing::new(KEYED_READER_KEY),
                Arc::clone(store) as Arc<dyn crate::audit_log::TipAnchorStore>,
            )),
        )
        .unwrap()
    }

    /// Re-anchors the log at `path`, keeping and quarantining its
    /// unauthenticated tail.
    fn reanchor_quarantining(
        path: &Path,
        store: &Arc<crate::audit_log::tip_anchor::InMemoryTipAnchorStore>,
    ) -> u64 {
        use crate::audit_log::writer::ReanchorAcknowledgement;

        let mut writer = AuditWriter::open_for_reanchor(
            path.to_path_buf(),
            Some(zeroize::Zeroizing::new(KEYED_READER_KEY)),
            Arc::clone(store) as Arc<dyn crate::audit_log::TipAnchorStore>,
        )
        .unwrap();
        writer
            .reanchor_acknowledging(&[
                ReanchorAcknowledgement::UnauthenticatedTail,
                ReanchorAcknowledgement::Rollback,
            ])
            .unwrap()
            .quarantined
    }

    /// A planted quarantine row whose count reaches back over an authentic
    /// pending row hides nothing once a genuine quarantine row covers it: the
    /// pending row stays owed and keyed verify passes. A genuine earlier
    /// quarantine row that nothing covers still drops the row it covers.
    #[test]
    fn a_covered_forged_quarantine_row_hides_nothing() {
        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let store = Arc::new(crate::audit_log::tip_anchor::InMemoryTipAnchorStore::new());
        open_keyed_writer(&path, &store)
            .write_entry(pending_row(SETTLE_ENVELOPE))
            .unwrap();
        forge(
            &path,
            event_entry(context_rule_created_event(
                1,
                "CDABC...12345",
                vec![h(0x44)],
                vec![],
                false,
                false,
            )),
        );
        assert_eq!(reanchor_quarantining(&path, &store), 1);
        forge(
            &path,
            AuditEntry::new_audit_entries_quarantined(1_000, "req-forged-quarantine"),
        );
        assert_eq!(reanchor_quarantining(&path, &store), 1);

        let writer = Arc::new(Mutex::new(open_keyed_writer(&path, &store)));
        assert!(
            matches!(
                try_value_action_settlement(&writer.lock().unwrap(), SETTLE_ENVELOPE).unwrap(),
                ValueActionSettlement::Owed(_)
            ),
            "the authentic pending row is still read"
        );
        let reader = AuditReader::new(Arc::clone(&writer), Some(KEYED_READER_KEY));
        assert!(
            reader
                .find_installed_context_rule_ids("CDABC...12345")
                .unwrap()
                .is_empty(),
            "the earlier genuine quarantine row still drops the forged pin row"
        );
        assert_eq!(
            reader
                .find_latest_context_rule_pinned_hashes(1, "CDABC...12345")
                .unwrap(),
            None
        );
        drop(reader);
        drop(writer);
        let verified =
            crate::audit_log::verify::verify_log(&path, Some(&KEYED_READER_KEY)).unwrap();
        assert!(verified.entry_tags_verified, "{verified:?}");
        // Verify reports the two genuine quarantines and nothing for the
        // covered directive, with the key and without it.
        for verified in [
            verified,
            crate::audit_log::verify::verify_log(&path, None).unwrap(),
        ] {
            let quarantined: Vec<u64> = verified
                .warnings
                .iter()
                .filter_map(|warning| match warning {
                    crate::audit_log::VerifyWarning::EntriesQuarantined {
                        quarantined_count,
                        ..
                    } => Some(*quarantined_count),
                    _ => None,
                })
                .collect();
            assert_eq!(quarantined, [1, 1], "{:?}", verified.warnings);
        }
    }

    /// An anchor store over an in-memory store that refuses every write from
    /// its `fail_from`-th on, counting anchor, re-anchor counter and outbox
    /// commitment writes: a keyring that stops answering partway through.
    #[derive(Debug)]
    struct WritesFailFrom {
        inner: Arc<crate::audit_log::tip_anchor::InMemoryTipAnchorStore>,
        writes: std::sync::atomic::AtomicUsize,
        fail_from: usize,
    }

    impl WritesFailFrom {
        fn write(&self) -> Result<(), crate::audit_log::TipAnchorStoreError> {
            let call = self
                .writes
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                + 1;
            if call >= self.fail_from {
                return Err(crate::audit_log::TipAnchorStoreError::new(
                    "test fault: the store refuses writes",
                ));
            }
            Ok(())
        }
    }

    impl crate::audit_log::TipAnchorStore for WritesFailFrom {
        fn load_outbox_state(
            &self,
        ) -> Result<
            Option<crate::audit_log::outbox::OutboxState>,
            crate::audit_log::TipAnchorStoreError,
        > {
            self.inner.load_outbox_state()
        }
        fn store_outbox_state(
            &self,
            state: &crate::audit_log::outbox::OutboxState,
        ) -> Result<(), crate::audit_log::TipAnchorStoreError> {
            self.write()?;
            self.inner.store_outbox_state(state)
        }
        fn load_anchor(
            &self,
        ) -> Result<Option<crate::audit_log::TipAnchor>, crate::audit_log::TipAnchorStoreError>
        {
            self.inner.load_anchor()
        }
        fn load_raw(&self) -> Result<Option<String>, crate::audit_log::TipAnchorStoreError> {
            self.inner.load_raw()
        }
        fn store_anchor(
            &self,
            anchor: &crate::audit_log::TipAnchor,
        ) -> Result<(), crate::audit_log::TipAnchorStoreError> {
            self.write()?;
            self.inner.store_anchor(anchor)
        }
        fn bump_reanchor_count(&self) -> Result<u64, crate::audit_log::TipAnchorStoreError> {
            self.write()?;
            self.inner.bump_reanchor_count()
        }
        fn reanchor_count(&self) -> Result<Option<u64>, crate::audit_log::TipAnchorStoreError> {
            self.inner.reanchor_count()
        }
    }

    /// Where a re-anchor of a forged tail is interrupted.
    #[derive(Debug, Clone, Copy)]
    enum ReanchorFault {
        /// Every store write from this one on is refused. With no earlier
        /// refusal the writes run: the quarantine row's anchor, the repaired
        /// anchor, the re-anchor counter, the acknowledgement row's anchor; a
        /// refused anchor write of a row is retried once, and the retry counts.
        StoreWritesFrom(usize),
        /// The quarantine row's append is refused before it writes.
        QuarantineRefused,
        /// The quarantine row's bytes reach the file and its fsync fails.
        QuarantineSync,
        /// The missing chain-root sidecar cannot be written.
        SidecarRepair,
        /// The acknowledgement row's append is refused.
        AcknowledgementRow,
    }

    /// Whether `path` holds, directly after the forged pin row, the
    /// quarantine row covering both forged rows.
    fn forged_rows_are_quarantined(path: &Path) -> bool {
        let rows: Vec<AuditEntry> = std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let pin = rows
            .iter()
            .position(|row| row.request_id == "req-forged-pin")
            .unwrap();
        rows.get(pin + 1).is_some_and(|row| {
            matches!(
                row.event_kind,
                EventKind::AuditEntriesQuarantined {
                    quarantined_count: 2
                }
            )
        })
    }

    /// Asserts that `writer` reads none of the forged rows: the pending row
    /// stays owed and no forged pin row is installed.
    fn reads_no_forged_row(writer: AuditWriter) {
        let writer = Arc::new(Mutex::new(writer));
        assert!(matches!(
            try_value_action_settlement(&writer.lock().unwrap(), SETTLE_ENVELOPE).unwrap(),
            ValueActionSettlement::Owed(_)
        ));
        let reader = AuditReader::new(Arc::clone(&writer), Some(KEYED_READER_KEY));
        assert!(
            reader
                .find_installed_context_rule_ids("CDABC...12345")
                .unwrap()
                .is_empty()
        );
        assert!(
            reader
                .scan_all_context_rule_pin_records()
                .unwrap()
                .is_empty()
        );
    }

    /// A re-anchor that quarantines a forged tail and fails after any of its
    /// writes leaves no forged row readable through an ordinary keyed open
    /// and none that keyed verify accepts without the quarantine row
    /// covering it, and a rerun completes the repair with one quarantine row.
    #[test]
    fn a_reanchor_interrupted_after_any_write_never_exposes_the_forged_tail() {
        use crate::audit_log::writer::ReanchorAcknowledgement;

        let acknowledged = [
            ReanchorAcknowledgement::UnauthenticatedTail,
            ReanchorAcknowledgement::Rollback,
        ];
        for fault in [
            ReanchorFault::StoreWritesFrom(1),
            ReanchorFault::StoreWritesFrom(2),
            ReanchorFault::StoreWritesFrom(3),
            ReanchorFault::StoreWritesFrom(4),
            ReanchorFault::QuarantineRefused,
            ReanchorFault::QuarantineSync,
            ReanchorFault::SidecarRepair,
            ReanchorFault::AcknowledgementRow,
        ] {
            let dir = TempDir::new().unwrap();
            let path = tmp_log(&dir);
            let store = Arc::new(crate::audit_log::tip_anchor::InMemoryTipAnchorStore::new());
            open_keyed_writer(&path, &store)
                .write_entry(pending_row(SETTLE_ENVELOPE))
                .unwrap();
            forge(&path, failed_row(SETTLE_ENVELOPE));
            let mut pin = event_entry(context_rule_created_event(
                1,
                "CDABC...12345",
                vec![h(0x44)],
                vec![],
                false,
                false,
            ));
            pin.request_id = "req-forged-pin".to_owned();
            forge(&path, pin);
            if matches!(fault, ReanchorFault::SidecarRepair) {
                std::fs::remove_file(crate::audit_log::writer::hmac_sidecar_path(&path)).unwrap();
            }

            let fail_from = match fault {
                ReanchorFault::StoreWritesFrom(call) => call,
                _ => usize::MAX,
            };
            let faulting = Arc::new(WritesFailFrom {
                inner: Arc::clone(&store),
                writes: std::sync::atomic::AtomicUsize::new(0),
                fail_from,
            });
            let mut repair = AuditWriter::open_for_reanchor(
                path.clone(),
                Some(zeroize::Zeroizing::new(KEYED_READER_KEY)),
                faulting as Arc<dyn crate::audit_log::TipAnchorStore>,
            )
            .unwrap();
            match fault {
                ReanchorFault::StoreWritesFrom(_) => {}
                ReanchorFault::QuarantineRefused => repair.set_appends_before_fault(Some(0)),
                ReanchorFault::QuarantineSync => repair.set_fail_sync_after_entry_write(true),
                ReanchorFault::SidecarRepair => repair.set_fail_root_sidecar_repair(true),
                ReanchorFault::AcknowledgementRow => repair.set_appends_before_fault(Some(1)),
            }
            let interrupted = repair.reanchor_acknowledging(&acknowledged);
            drop(repair);

            if crate::audit_log::verify::verify_log(&path, Some(&KEYED_READER_KEY)).is_ok() {
                assert!(
                    forged_rows_are_quarantined(&path),
                    "{fault:?}: keyed verify passed over forged rows no quarantine row covers"
                );
            }
            match AuditWriter::open(
                path.clone(),
                Some(crate::audit_log::KeyedAuditAccess::new(
                    zeroize::Zeroizing::new(KEYED_READER_KEY),
                    Arc::clone(&store) as Arc<dyn crate::audit_log::TipAnchorStore>,
                )),
            ) {
                Ok(writer) => reads_no_forged_row(writer),
                Err(err) => assert!(
                    matches!(
                        &err,
                        crate::audit_log::WriterError::TipAnchorMismatch { reason, .. }
                            if reason.starts_with("unauthenticated_tail")
                    ),
                    "{fault:?} ({interrupted:?}): {err:?}"
                ),
            }

            reanchor_quarantining(&path, &store);
            let quarantine_rows = std::fs::read_to_string(&path)
                .unwrap()
                .lines()
                .filter(|line| line.contains("\"audit_entries_quarantined\""))
                .count();
            assert_eq!(quarantine_rows, 1, "{fault:?}");
            assert!(forged_rows_are_quarantined(&path), "{fault:?}");
            reads_no_forged_row(open_keyed_writer(&path, &store));
            let verified =
                crate::audit_log::verify::verify_log(&path, Some(&KEYED_READER_KEY)).unwrap();
            assert!(verified.entry_tags_verified, "{fault:?}");
        }
    }

    /// The pool-initialization lookup of a keyed writer reads the log up to
    /// the writer's verified tip only: an untagged forged completion row and a
    /// malformed line past that tip each leave the result as it is without
    /// them.
    #[test]
    fn the_pool_initialization_lookup_ignores_bytes_past_the_verified_tip() {
        use std::io::Write as _;

        let dir = TempDir::new().unwrap();
        let path = tmp_log(&dir);
        let store = Arc::new(crate::audit_log::tip_anchor::InMemoryTipAnchorStore::new());
        let writer = Arc::new(Mutex::new(open_keyed_writer(&path, &store)));
        let completion = |request_id: &str| {
            AuditEntry::new_channel_pool_initialised(
                "GFUND...FUNDR",
                2,
                "txhash...tail",
                1,
                request_id,
            )
        };
        writer
            .lock()
            .unwrap()
            .write_entry(completion("pool-written"))
            .unwrap();
        let reader = AuditReader::new(Arc::clone(&writer), Some(KEYED_READER_KEY));
        let results = |reader: &AuditReader| {
            (
                reader.pool_initialization_exists("pool-written").unwrap(),
                reader.pool_initialization_exists("pool-forged").unwrap(),
            )
        };
        let before = results(&reader);
        assert_eq!(before, (true, false));

        forge(&path, completion("pool-forged"));
        assert_eq!(results(&reader), before, "an untagged row past the tip");
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"{\"not\": \"an audit row\"}\n")
            .unwrap();
        assert_eq!(results(&reader), before, "a malformed line past the tip");
    }
}
