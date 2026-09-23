//! Persisted per-profile policy window-state store.
//!
//! Backs the stateful policy criteria (`per_period_cap`, `rate_limit`,
//! `bundle_per_period_cap`, `bundle_rate_limit`): the in-memory
//! [`stellar_agent_core::policy::v1::PolicyStateStore`] `PolicyEngineV1` owns
//! is reconstructed fresh at process start with no accumulated history, so
//! without a durable backing store those criteria evaluate every call against
//! zero history and never actually cap anything across calls.
//!
//! [`PersistedWindowStore`] closes that gap: one HMAC-protected, single-writer
//! JSON file per profile at
//! [`stellar_agent_core::profile::schema::default_policy_window_state_path_for`]
//! (`<state>/stellar-agent/policy/<profile>.window`), shared by every process
//! (MCP server, CLI) that evaluates or records against that profile.
//!
//! # Crate placement
//!
//! This store lives in `stellar-agent-network`, not `stellar-agent-core`,
//! because it needs [`crate::keyring::rotate_keyring_secret_32`] /
//! [`crate::keyring::load_hmac_key_32`] to mint and load its HMAC key, and
//! `stellar-agent-core` does not (and must not) depend on
//! `stellar-agent-network` (the dependency runs the other way — verified via
//! the workspace `Cargo.toml` dependency graph). [`stellar_agent_core::policy::v1::PolicyStateStore`]
//! stays the engine-facing in-memory type, unchanged.
//!
//! # Refresh shape (per-process-lifetime discipline)
//!
//! The CLI is a fresh process per invocation: `PolicyEngineV1::new_with_store`
//! is constructed once, hydrated once via [`PersistedWindowStore::load_into`],
//! evaluates, and — on a confirmed commit — records and exits. There is
//! nothing to go stale within that lifetime.
//!
//! The MCP server is a LONG-LIVED process: a single `PolicyEngineV1` instance
//! serves every dispatch for the life of the server. Hydrating it once at
//! construction and never again would mean a CLI-written (or a sibling MCP
//! request's) accumulated entry never becomes visible to this process's
//! evaluations — the server would silently evaluate stateful criteria against
//! a startup-frozen snapshot. `dispatch_gate_inner`
//! (`stellar-agent-mcp::tools::common`) closes this: before every evaluation,
//! it calls [`stellar_agent_core::policy::PolicyEngine::window_state_store`]
//! to reach the engine's in-memory store, `clear()`s it, and re-populates it
//! via `load_into` from the CURRENT on-disk file. This is a REPLACE, not a
//! merge: clearing before re-loading is what prevents an entry a concurrent
//! process has already pruned or a reset has cleared from lingering in this
//! process's view. Construction-time hydration is kept in addition (not
//! replaced by the per-dispatch refresh): it makes the server refuse to
//! start at all on a tampered/unparseable store file, rather than deferring
//! that discovery to first dispatch.
//!
//! # Admission
//!
//! A call passes through the window in three steps.
//!
//! 1. **Evaluation at dispatch.** The policy gate reads this store into the
//!    engine's in-memory view and evaluates the call against it, before the
//!    transaction is built and signed.
//! 2. **Reservation under the lock.** Immediately before the send,
//!    [`PersistedWindowStore::record_pending`] takes the store's exclusive
//!    lock, re-reads and verifies the file, and re-applies the governing
//!    criterion's own comparison against what the file holds at that moment.
//!    Time passes between the two steps, and the profile is shared by every
//!    process on the host, so the state the gate read is not necessarily the
//!    state the reservation meets. A batch any bucket can no longer admit is
//!    refused as [`WindowStoreError::PolicyDenied`], carrying the denial the
//!    criterion produces for that condition, and nothing is written. Each
//!    entry carries the limit that governs it
//!    ([`stellar_agent_core::policy::v1::criteria::state_store::WindowLimit`]),
//!    which is policy rather than history and is never persisted.
//! 3. **Settlement on confirmation.** The reservation counts against every
//!    window criterion while it stands and becomes confirmed spend, or is
//!    released, when the chain answers.
//!
//! Admission is whole-batch: the entries of one submission are written
//! together or not at all, and entries of one batch on one key are measured
//! against each other, so a single call cannot overshoot a bucket by spreading
//! its spend across legs.
//!
//! # Reservation settlement
//!
//! Pending records count regardless of age. Confirmation requires the applying
//! transaction's `created_at` ledger close time; missing time leaves the hold
//! pending. Confirmed records age from that close time.
//!
//! A NOT_FOUND releases only within retention after observing a consumed
//! sequence or a ledger close time strictly past a nonzero maxTime, followed
//! by a fresh NOT_FOUND. A fresh SUCCESS or FAILED settles that chain outcome.
//! The pass shares one bounded getLedgers observation; unavailable or invalid
//! chain time closes the time arm. The host clock only controls minimum age.
//! Receiptless holds beyond retention carry an authenticated operator marker,
//! retain their debit, and are excluded from automatic selection.
//!
//! # Wire format
//!
//! `[32-byte HMAC-SHA256 tag] || [canonical JSON body]`, mirroring
//! [`crate::counterparty::cache`]'s embedded-tag convention (tag prefix, not a
//! sidecar file) — chosen because, like the counterparty cache, this store has
//! exactly one file per profile and no cross-file chain to protect, so an
//! embedded tag needs no extra file-discovery bookkeeping. `i128` amounts
//! serialise as decimal strings (the `wire_stroops::i128` / audit
//! `i128_decimal_str` convention), never a bare JSON number, so no value is
//! silently truncated by a JSON-number-as-f64 reader. The body also carries a
//! `generation: u64` field; see "Anti-rollback" below. Version 3 includes the
//! operator marker and optional prepared settlement. Versions 1 and 2 remain readable; absent status means
//! confirmed spend and an absent operator marker means automatic selection.
//!
//! # Integrity
//!
//! HMAC-SHA256 over a context-separation label plus the exact JSON body
//! bytes, keyed by the profile's `policy_window_state_key_id` keyring
//! coordinate ([`stellar_agent_core::profile::schema::KeyringEntryRef::default_policy_window_state_key`]).
//! A verification failure (mismatched tag, truncated file, or unparseable
//! JSON) is fail-closed: [`load_into`](PersistedWindowStore::load_into)
//! returns an error rather than a partial or empty read, so the stateful
//! criteria that would consult it deny via
//! [`stellar_agent_core::policy::PolicyError::CriterionEvaluationFailed`]
//! instead of silently under-counting.
//!
//! # Anti-rollback: the generation counter
//!
//! HMAC integrity alone does not detect a VALID-LOOKING file from the wrong
//! point in time: an attacker (or an operator's backup/restore tooling) with
//! filesystem access can delete the store file (silently resetting
//! accumulated history to empty) or restore an older, genuinely-signed
//! snapshot (silently rewinding accumulated history) — both bypass every cap
//! without ever failing the HMAC check, because the restored bytes are
//! authentic.
//!
//! A second keyring entry — derived from `policy_window_state_key_id` by
//! suffixing `-generation` onto its `account` field, same `service` — holds a
//! monotonic generation and a SHA-256 commitment to its canonical body, updated
//! together. Numeric counters remain readable for version 1 and 2 files.
//! Appending a debit commits the trusted state before replacing the file, so
//! failure cannot expose a smaller total. Settlement writes both the current
//! and candidate snapshots before committing the candidate's generation and
//! digest; either crash checkpoint retains an authenticated, readable state.
//! An abandoned candidate cannot substitute for a different committed body
//! sharing its generation. Readers reject missing, rolled-back, or substituted
//! state. Initialisation and reset also commit the counter first and fail closed
//! if their file write fails. Key rotation re-signs the existing body while
//! preserving its trusted commitment.
//!
//! # Concurrency
//!
//! [`lock::WindowStoreLock`] — an OFD-advisory exclusive flock at
//! `<store-file>.lock`, mirroring [`crate::counterparty::lock::CacheLock`] —
//! serialises every read-modify-write against the file (record, reset,
//! resign). [`load_into`](PersistedWindowStore::load_into) does not take the
//! lock: the file is only ever replaced via atomic rename (temp file +
//! `sync_data` + rename + parent-directory fsync, mirroring
//! [`stellar_agent_core::audit_log`]'s rotation `write_sidecar_atomic`
//! precedent), so a concurrent reader never observes a torn write.
//!
//! # Retention
//!
//! Entries older than the largest supported criterion window (`1w` =
//! 604,800 s) are pruned on every write once confirmed. Pending records are retained.

pub mod lock;
pub mod store;

pub use store::{
    MintOutcome, PersistedWindowStore, RECONCILE_BUDGET, RECONCILE_MIN_AGE_MS, ReconcileReport,
    SettledSubmission, WindowReservation,
};

/// Records a confirmed call's contribution into `engine`'s window state and
/// persists the new entries to the on-disk store for `profile_name`.
///
/// Records unconditionally, without admission, for spend that has already
/// applied on-chain. Authorized external settlement records through
/// [`record_authorized_window_state`] instead. `value`
/// MUST be the SAME [`stellar_agent_core::policy::v1::ValueClass`] the
/// original gate evaluated — the single-derivation invariant, matching the
/// audit-row `value_action_submitted` emission this call is always paired
/// with.
///
/// Non-fatal by design, mirroring the audit-row emission discipline: the
/// on-chain action already committed and is irreversible, so a recording
/// failure here is surfaced via `tracing::warn!` rather than propagated. A
/// failed record means the NEXT call under-counts against the accumulated
/// window — that is loud in the log, not silent.
pub fn record_confirmed_window_state(
    engine: &dyn stellar_agent_core::policy::PolicyEngine,
    tool: &stellar_agent_core::policy::ToolDescriptor,
    profile: &stellar_agent_core::profile::schema::Profile,
    profile_name: &str,
    value: &stellar_agent_core::policy::v1::ValueClass,
) {
    let recorded = match engine.record_confirmed(tool, profile, value) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                profile = %profile_name,
                tool = %tool.name,
                error = %e,
                "policy window-state record_confirmed failed post-confirm; the next call's \
                 accumulated window total under-counts this one"
            );
            return;
        }
    };
    if recorded.is_empty() {
        return;
    }
    let window_store = PersistedWindowStore::for_profile(profile_name);
    if let Err(e) = window_store.record_and_persist(profile, &recorded) {
        tracing::warn!(
            profile = %profile_name,
            tool = %tool.name,
            error = ?e,
            "policy window-state persist failed post-confirm; the next call's accumulated \
             window total under-counts this one"
        );
    }
}

/// Records authorized external-settlement value before payment signing and
/// propagates every failure to the caller.
///
/// MPP and x402 call this before constructing payment credentials, so an
/// accounting refusal withholds the authorization.
///
/// # Errors
///
/// Returns a typed window-store error when in-memory accounting or durable
/// persistence fails, or the shared window cannot admit the authorization.
pub fn record_authorized_window_state(
    engine: &dyn stellar_agent_core::policy::PolicyEngine,
    tool: &stellar_agent_core::policy::ToolDescriptor,
    profile: &stellar_agent_core::profile::schema::Profile,
    profile_name: &str,
    value: &stellar_agent_core::policy::v1::ValueClass,
) -> Result<(), WindowStoreError> {
    let recorded = engine
        .record_confirmed(tool, profile, value)
        .map_err(|error| WindowStoreError::Invalid {
            detail: format!("policy authorization accounting failed: {error}"),
        })?;
    if recorded.is_empty() {
        return Ok(());
    }
    PersistedWindowStore::for_profile(profile_name)
        .record_authorized(profile, &recorded)
        .map(|_outcome| ())
}

/// Error variants for [`PersistedWindowStore`] operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WindowStoreError {
    /// Another process or task holds the exclusive write lock.
    #[error("policy window-state store writer is locked by another process")]
    WriterLocked,

    /// An I/O error occurred reading or writing the store file or lock file.
    #[error("policy window-state store I/O error: {kind:?}")]
    Io {
        /// The underlying I/O error kind.
        kind: std::io::ErrorKind,
    },

    /// The store file is structurally invalid (truncated, missing the
    /// expected HMAC prefix, or not valid JSON).
    #[error("policy window-state store file is invalid: {detail}")]
    Invalid {
        /// Operator-facing detail. MUST NOT include key material.
        detail: String,
    },

    /// The store file's HMAC tag does not match the recomputed value —
    /// tampering, corruption, or a stale key.
    #[error("policy window-state store HMAC mismatch — possible tampering or rotation")]
    HmacMismatch,

    /// The store file's `generation` does not match the keyring-held
    /// generation counter, or one of the two is present without the other —
    /// a deleted-and-recreated file, a restored older snapshot, or a deleted
    /// generation counter. See the module docs' "Anti-rollback" section.
    #[error(
        "policy window-state store generation mismatch — possible deletion or rollback; \
         run `profile reset-window-state` to recover"
    )]
    GenerationMismatch,

    /// The HMAC keyring entry could not be loaded or minted.
    #[error("policy window-state store keyring error: {detail}")]
    Keyring {
        /// Operator-facing detail. MUST NOT include key material.
        detail: String,
    },

    /// A window bucket cannot admit the reservation.
    ///
    /// Produced by [`PersistedWindowStore::record_pending`] when it re-applies
    /// the governing criterion's comparison under the store's lock, against
    /// the state the file holds at that moment, and the batch would take a
    /// bucket past its limit. Nothing is written: the batch is admitted whole
    /// or refused whole.
    ///
    /// `reason` is the denial the criterion itself produces for the same
    /// condition, built from the limit the entry carries, so the surface that
    /// reports it names the gate's own wire code.
    #[error("policy denied this reservation: {}", reason.wire_code())]
    PolicyDenied {
        /// The typed denial, built from the refused entry's limit.
        reason: Box<stellar_agent_core::policy::DenyReason>,
    },
}
