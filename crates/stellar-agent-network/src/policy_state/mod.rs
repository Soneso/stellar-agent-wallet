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
//! ## Known race: concurrent in-flight calls within one process
//!
//! Recording happens AFTER a confirmed on-chain submit — necessarily so,
//! since only a confirmed submit is real spend. Two concurrent MCP dispatches
//! for the SAME profile can both refresh-and-evaluate against the identical
//! pre-submit window total (neither has recorded yet), both pass a
//! `per_period_cap` check that is individually correct, both submit, and both
//! record afterward. The window can therefore be jointly overshot by AT MOST
//! the smaller of the two calls' own amounts — each call remains individually
//! bounded by `per_tx_cap` (a rule combining both criteria is unaffected by
//! this race; only `per_period_cap` alone, under concurrent load, admits this
//! bounded overshoot). This is an accepted, DELIBERATE trade-off: closing it
//! would require holding a cross-request lock across the submit round-trip,
//! serialising unrelated calls behind a single profile's on-chain latency.
//! The on-disk file total is never wrong — both records land, in some order,
//! under the single-writer lock — so the very next call after the race sees
//! the true, fully-accumulated history and is capped correctly from then on.
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
//! `generation: u64` field — see "Anti-rollback" below.
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
//! monotonic `u64` counter, independent of the HMAC key. EVERY write
//! ([`PersistedWindowStore::record_and_persist`] and
//! [`PersistedWindowStore::reset`]) increments the keyring counter FIRST,
//! then stamps that exact value into the file body's `generation` field
//! before signing. On load, the file's `generation` MUST equal the keyring's
//! CURRENT counter value:
//!
//! - File generation < keyring generation → an older snapshot was restored,
//!   or the current file predates a crash between the keyring bump and the
//!   file write — fail closed (`WindowStoreError::GenerationMismatch`).
//! - File exists but no keyring generation entry exists → the counter itself
//!   was deleted (or never existed for a file that does) — fail closed.
//! - File is missing but a keyring generation entry exists → the file was
//!   deleted after at least one write — fail closed (deletion detected).
//! - File is missing AND no keyring generation entry exists → genuine first
//!   run for this profile — empty history, `Ok`.
//!
//! Keyring-first ordering means a crash between the two writes always leaves
//! the file BEHIND the keyring, never ahead of it — the conservative
//! direction: the failure mode is always "fail closed, operator must
//! `reset-window-state`", never "silently accept a state the keyring never
//! actually reached". `reset-window-state` re-baselines both the file (to
//! empty) and the keyring counter (bumped past whatever the last legitimate
//! or illegitimate value was) in one operation.
//! `rotate-policy-state-key` — a DIFFERENT keyring entry (the HMAC key, not
//! the generation counter) — leaves the generation counter untouched: it
//! re-signs the existing body (including its `generation` field) under the
//! new key, so rotation does not itself look like a rollback.
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
//! 604,800 s) are pruned on every write.

pub mod lock;
pub mod store;

pub use store::{MintOutcome, PersistedWindowStore};

/// Records a confirmed call's contribution into `engine`'s window state and
/// persists the new entries to the on-disk store for `profile_name`.
///
/// This is the single call site every value-moving dispatch site uses after a
/// confirmed on-chain submit (or, for x402, after authorization signing — see
/// the call sites' own doc comments for the exact confirmation point). `value`
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
}
