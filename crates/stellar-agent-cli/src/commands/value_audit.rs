//! Shared audit emission for value-moving CLI commands.
//!
//! Value verbs (pay, claim, create-account, trustline, trade) record a
//! hash-chained, HMAC-signed `ValueActionSubmitted` row after the on-chain
//! action confirms. Emission is NON-FATAL post-success: the transaction has
//! already committed, so a row-write failure logs a `tracing::warn!` and never
//! changes the command result or exit code.
//!
//! The legs carried in a row are the SAME `ValueEffects` the policy gate sized
//! (single-derivation invariant); this module only serialises what the caller
//! supplies and never derives value. Rows are written under the profile's audit
//! chain-root HMAC key so `stellar-agent audit verify` covers them.
//!
//! # Pre-flight (fail-closed) vs. post-confirm (fail-open)
//!
//! [`require_value_audit_writer`] is the fail-closed pre-flight every
//! value-moving signing verb calls BEFORE any signing key is touched or
//! transaction submitted: it proves the audit writer is acquirable, refusing
//! with `audit.chain_key_unavailable` if not. The verb then threads the
//! returned writer into [`emit_value_action_submitted_row_with_writer`] /
//! [`emit_value_audit_row_with_writer`] for the post-confirm row — no second
//! acquisition, no re-acquisition race.
//!
//! [`emit_value_audit_row`] (acquire-then-write) remains for the one
//! legitimately non-signing caller of this module
//! (`profile::reset_window_state`, an operator command, not a value-signing
//! verb): its emission stays non-fatal and unchanged by this pre-flight.
//!
//! # Origin-aware pre-flight for the zero-config classic verbs
//!
//! `pay`, `claim`, and `accounts create` accept a profile that is either
//! persisted (an authored `<name>.toml` file) or synthesized in-memory when no
//! such file exists (see
//! [`crate::commands::policy_engine::load_profile_or_synthesize_testnet`]).
//! [`require_value_audit_writer_for_origin`] applies the pre-flight only to
//! the persisted case; the synthesized zero-config profile keeps the
//! pre-existing warn-only emission path so the documented zero-config
//! quickstart is never blocked by a fail-closed audit-key requirement the
//! operator never opted into.

use std::sync::{Arc, Mutex};

use stellar_agent_core::audit_log::{AuditEntry, AuditWriter, AuditWriterRegistry};
use stellar_agent_core::error::{ValidationError, WalletError};
use stellar_agent_core::profile::schema::Profile;

use crate::commands::profile::audit_emit::load_audit_hmac_key;

/// Requires the per-profile audit writer to be acquirable under the profile's
/// audit chain-root HMAC key — the fail-closed pre-flight for value-moving
/// signing verbs.
///
/// Callers invoke this BEFORE any signing key is touched and BEFORE any
/// transaction is submitted (see the module docs). On success, the returned
/// writer MUST be reused for the verb's post-confirm emission
/// ([`emit_value_action_submitted_row_with_writer`] /
/// [`emit_value_audit_row_with_writer`]) rather than re-acquired.
///
/// This is the CLI twin of `stellar_agent_mcp::tools::value_audit::require_value_audit_writer`
/// (crate-private there, so not directly linkable): the two implementations
/// MUST stay wire-identical — same wire code on the same underlying failure,
/// same fail-closed semantics — so a `pay`/`claim`/`trustline`/`trade`
/// refusal reads the same whether it came from the CLI verb or its MCP tool
/// counterpart.
///
/// # Errors
///
/// Returns [`WalletError::Validation`] wrapping one of two variants — both
/// carry the same wire code (`audit.chain_key_unavailable`) but distinct
/// operator-facing remedies, since the two failure modes have different
/// fixes:
/// - [`ValidationError::AuditChainKeyUnavailable`] when the profile's audit
///   chain-root HMAC key cannot be loaded from the platform keyring — an
///   `init`-minted profile has no audit chain-root key until
///   `stellar-agent profile rotate-audit-key <profile>` mints one.
/// - [`ValidationError::AuditWriterOpenFailed`] when the key loaded but the
///   audit writer could not be opened at `profile.audit_log_path` (e.g. a
///   registry path/key mismatch against an earlier open in this process) —
///   rotating the audit key does not fix this.
pub(crate) fn require_value_audit_writer(
    profile: &Profile,
    profile_name: &str,
) -> Result<Arc<Mutex<AuditWriter>>, WalletError> {
    let hmac_key = load_audit_hmac_key(profile).map_err(|e| {
        tracing::warn!(
            profile = %profile_name,
            error = %e,
            "value audit: could not load audit chain key; refusing before signing/submit"
        );
        audit_chain_key_unavailable(profile_name)
    })?;
    AuditWriterRegistry::get_or_open(profile_name, &profile.audit_log_path, Some(hmac_key)).map_err(
        |e| {
            tracing::warn!(
                profile = %profile_name,
                error = %e,
                "value audit: could not open audit writer; refusing before signing/submit"
            );
            audit_writer_open_failed(profile_name)
        },
    )
}

fn audit_chain_key_unavailable(profile_name: &str) -> WalletError {
    WalletError::Validation(ValidationError::AuditChainKeyUnavailable {
        profile: profile_name.to_owned(),
    })
}

fn audit_writer_open_failed(profile_name: &str) -> WalletError {
    WalletError::Validation(ValidationError::AuditWriterOpenFailed {
        profile: profile_name.to_owned(),
    })
}

/// Origin-aware fail-closed pre-flight for `pay`, `claim`, and
/// `accounts create`, whose resolved profile may be either persisted or the
/// in-memory zero-config synthesized profile (see
/// [`crate::commands::policy_engine::load_profile_or_synthesize_testnet`]).
///
/// - [`ProfileOrigin::Persisted`] delegates to [`require_value_audit_writer`]:
///   fails closed with `audit.chain_key_unavailable` when the writer cannot be
///   acquired. An operator who authored a profile file is expected to run
///   `stellar-agent profile rotate-audit-key <name>` before signing.
/// - [`ProfileOrigin::Synthesized`] is the zero-config quickstart path — no
///   profile file, no `rotate-audit-key` step to run. The writer is acquired
///   opportunistically (a `tracing::warn!` on failure, no refusal), matching
///   the pre-existing zero-config behavior. Returns `Ok(None)` when the writer
///   could not be acquired; the caller then skips the post-confirm row rather
///   than treating the operation as unaudited — there was no audit guarantee
///   to defeat here, since the operator never persisted a profile in the
///   first place.
///
/// # Errors
///
/// Returns `Err` only for [`ProfileOrigin::Persisted`]; see
/// [`require_value_audit_writer`].
pub(crate) fn require_value_audit_writer_for_origin(
    profile: &Profile,
    profile_name: &str,
    origin: crate::commands::policy_engine::ProfileOrigin,
) -> Result<Option<Arc<Mutex<AuditWriter>>>, WalletError> {
    use crate::commands::policy_engine::ProfileOrigin;
    match origin {
        ProfileOrigin::Persisted => require_value_audit_writer(profile, profile_name).map(Some),
        ProfileOrigin::Synthesized => Ok(acquire_value_audit_writer(profile, profile_name)),
    }
}

/// Best-effort keyed-first writer acquisition for callers that need a
/// writer OBJECT but must not fail closed: the synthesized zero-config
/// profile (manager-based smart-account commands cannot run without a
/// writer), and read-only commands that neither sign nor submit and are
/// exempt from the fail-closed pre-flight regardless of origin.
///
/// Keyed when the profile's chain-root key loads; otherwise falls back to an
/// UNKEYED open at the profile's configured audit path. The unkeyed
/// registration cannot brick a later keyed open in the same process: keyed
/// acquisition requires the key to load, which is exactly what failed here,
/// and a long-lived MCP server resolves its profile once at startup.
///
/// # Errors
///
/// Returns [`WalletError`] only when even the unkeyed open fails (I/O).
pub(crate) fn acquire_best_effort_audit_writer(
    profile: &Profile,
    profile_name: &str,
) -> Result<Arc<Mutex<AuditWriter>>, WalletError> {
    if let Some(writer) = acquire_value_audit_writer(profile, profile_name) {
        return Ok(writer);
    }
    tracing::warn!(
        profile = %profile_name,
        "value audit: keyed acquisition unavailable; \
         opening the audit writer unkeyed (rows not covered by audit verify)"
    );
    AuditWriterRegistry::get_or_open(profile_name, &profile.audit_log_path, None)
        .map_err(|e| audit_writer_open_failed_io(profile_name, &e))
}

fn audit_writer_open_failed_io(profile_name: &str, e: &impl std::fmt::Display) -> WalletError {
    tracing::warn!(
        profile = %profile_name,
        error = %e,
        "value audit: unkeyed audit writer open failed"
    );
    audit_writer_open_failed(profile_name)
}

/// Acquires the per-profile audit writer opened under the profile's audit
/// chain-root HMAC key.
///
/// Returns `None` (with a `tracing::warn!`) if the key cannot be loaded or the
/// writer cannot be opened. Private: the callers are [`emit_value_audit_row`]
/// (the one exempt, non-signing call site),
/// [`require_value_audit_writer_for_origin`]'s
/// [`ProfileOrigin::Synthesized`](crate::commands::policy_engine::ProfileOrigin::Synthesized)
/// arm (the zero-config quickstart's warn-only path), and
/// [`acquire_best_effort_audit_writer`]'s keyed attempt. Every
/// persisted-profile signing verb uses [`require_value_audit_writer`]
/// instead, which fails closed.
fn acquire_value_audit_writer(
    profile: &Profile,
    profile_name: &str,
) -> Option<Arc<Mutex<AuditWriter>>> {
    let hmac_key = match load_audit_hmac_key(profile) {
        Ok(k) => Some(k),
        Err(e) => {
            tracing::warn!(
                profile = %profile_name,
                error = %e,
                "value audit: could not load audit chain key; writer NOT acquired"
            );
            return None;
        }
    };
    match AuditWriterRegistry::get_or_open(profile_name, &profile.audit_log_path, hmac_key) {
        Ok(arc) => Some(arc),
        Err(e) => {
            tracing::warn!(
                profile = %profile_name,
                error = %e,
                "value audit: could not open audit writer; writer NOT acquired"
            );
            None
        }
    }
}

/// Constructs and emits the allow-path `value_action_submitted` row for a
/// confirmed CLI submit, using an audit writer the caller already acquired via
/// [`require_value_audit_writer`] — no second acquisition, no re-acquisition
/// race.
///
/// The legs are the SAME `ValueEffects` the policy gate sized
/// (single-derivation invariant), the redacted transaction hash, and the
/// confirmed ledger. Non-fatal past this point: the transaction already
/// committed, so a write failure logs a `tracing::warn!` via
/// [`emit_value_audit_row_with_writer`] and never changes the command result.
pub(crate) fn emit_value_action_submitted_row_with_writer(
    writer: &Arc<Mutex<AuditWriter>>,
    profile_name: &str,
    tool: &'static str,
    chain_id: &str,
    effects: Option<&stellar_agent_core::policy::v1::ValueEffects>,
    tx_hash: &str,
    ledger: u32,
) {
    let legs: Vec<stellar_agent_core::audit_log::ValueLegRecord> = effects
        .map(|e| e.legs().iter().map(Into::into).collect())
        .unwrap_or_default();
    let request_id = uuid::Uuid::new_v4().to_string();
    let tx_redacted = stellar_agent_network::submit::redact_tx_hash(tx_hash);
    let entry = AuditEntry::new_value_action_submitted(
        tool,
        chain_id,
        legs,
        tx_redacted.as_str(),
        ledger,
        stellar_agent_core::audit_log::PolicyDecision::Allow,
        None,
        None,
        &request_id,
    );
    emit_value_audit_row_with_writer(writer, profile_name, entry);
}

/// Writes `entry` through an audit writer the caller already acquired (via
/// [`require_value_audit_writer`]).
///
/// Non-fatal: the write has nothing left to gate — the transaction already
/// committed — so a failure to take the lock or append the row logs a
/// `tracing::warn!` and returns without disturbing the caller.
pub(crate) fn emit_value_audit_row_with_writer(
    writer: &Arc<Mutex<AuditWriter>>,
    profile_name: &str,
    entry: AuditEntry,
) {
    match writer.lock() {
        Ok(mut guard) => {
            if let Err(e) = guard.write_entry(entry) {
                tracing::warn!(
                    profile = %profile_name,
                    error = %e,
                    "value audit: write_entry failed; row NOT emitted"
                );
            }
        }
        Err(_) => {
            tracing::warn!(
                profile = %profile_name,
                "value audit: audit writer mutex poisoned; row NOT emitted"
            );
        }
    }
}

/// Writes a value-audit `entry` for `profile` under its audit chain-root HMAC
/// key, acquiring the writer internally via [`acquire_value_audit_writer`].
///
/// Non-fatal: a failure to load the key, open the writer, take the lock, or
/// append the row logs a `tracing::warn!` and returns without disturbing the
/// caller. Reserved for the one non-signing caller of this module
/// (`profile::reset_window_state`); value-moving signing verbs call
/// [`require_value_audit_writer`] first and then
/// [`emit_value_audit_row_with_writer`] to reuse that acquisition.
pub(crate) fn emit_value_audit_row(profile: &Profile, profile_name: &str, entry: AuditEntry) {
    let Some(writer_arc) = acquire_value_audit_writer(profile, profile_name) else {
        return;
    };
    emit_value_audit_row_with_writer(&writer_arc, profile_name, entry);
}

/// Writes an authorization row and propagates failures while the caller can
/// still withhold the credential.
pub(crate) fn emit_value_audit_row_strict(
    profile: &Profile,
    profile_name: &str,
    entry: AuditEntry,
) -> Result<(), ()> {
    let key = load_audit_hmac_key(profile).map_err(|_| ())?;
    let writer = AuditWriterRegistry::get_or_open(profile_name, &profile.audit_log_path, Some(key))
        .map_err(|_| ())?;
    let mut guard = writer.lock().map_err(|_| ())?;
    guard.write_entry(entry).map_err(|_| ())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only"
)]
mod tests {
    use std::io::BufRead as _;

    use serial_test::serial;
    use stellar_agent_core::audit_log::AuditEntry;
    use stellar_agent_core::profile::schema::Profile;
    use stellar_agent_test_support::keyring_mock;

    use super::*;

    /// End-to-end emission through the REAL acquisition path: the row is written
    /// under the profile's audit chain-root HMAC key loaded from the (mock)
    /// keyring via [`load_audit_hmac_key`] → `AuditWriterRegistry::get_or_open`,
    /// NOT a pre-built writer handle. This guards the shared CLI/MCP emission
    /// plumbing (loader → registry → append) in push CI: a break in key
    /// acquisition, the registry open, or the fingerprint discipline fails here
    /// rather than only in the testnet acceptance run.
    #[test]
    #[serial]
    fn emit_value_audit_row_writes_through_real_acquisition_path() {
        keyring_mock::install().expect("mock keyring store");

        let dir = tempfile::tempdir().expect("tmp dir");
        let mut profile = Profile::builder_testnet("e2e-emit", "acct", "n-svc", "n-acct").build();
        profile.audit_log_path = dir.path().join("audit.jsonl");

        // Seed a real 32-byte chain-root key at the profile's audit coordinate so
        // the loader has a key to acquire (the WRITE counterpart of the loader).
        let coord = &profile.audit_log_hash_chain_key_id;
        stellar_agent_network::keyring::rotate_keyring_secret_32(&coord.service, &coord.account)
            .expect("seed audit key");

        let entry = AuditEntry::new_value_action_submitted(
            "stellar_pay",
            "stellar:testnet",
            Vec::new(),
            "abcd1234…wxyz5678",
            7,
            stellar_agent_core::audit_log::PolicyDecision::Allow,
            None,
            None,
            "req-e2e-1",
        );
        emit_value_audit_row(&profile, "e2e-emit", entry);

        let file = std::fs::File::open(&profile.audit_log_path).expect("audit.jsonl exists");
        let rows: Vec<serde_json::Value> = std::io::BufReader::new(file)
            .lines()
            .map(|l| serde_json::from_str(&l.expect("line")).expect("valid JSON row"))
            .collect();

        assert_eq!(
            rows.len(),
            1,
            "one row written through the real loader path"
        );
        assert_eq!(rows[0]["kind"], "value_action_submitted", "row kind");
        assert_eq!(rows[0]["tool"], "stellar_pay", "outer tool identity");
    }

    // ── require_value_audit_writer — the fail-closed pre-flight ──────────────

    /// With no audit chain-root key seeded at the profile's keyring
    /// coordinate (the `profile init`-only state, before `rotate-audit-key`
    /// ever runs), `require_value_audit_writer` refuses with the typed
    /// `audit.chain_key_unavailable` error rather than proceeding with a
    /// warning.
    #[test]
    #[serial]
    fn require_value_audit_writer_refuses_when_key_unminted() {
        keyring_mock::install().expect("mock keyring store");

        let dir = tempfile::tempdir().expect("tmp dir");
        let mut profile =
            Profile::builder_testnet("require-unminted", "acct", "n-svc", "n-acct").build();
        profile.audit_log_path = dir.path().join("audit.jsonl");

        // No `rotate_keyring_secret_32` seeding here — the coordinate exists
        // (minted by `builder_testnet`) but no key material was ever written,
        // mirroring an init-minted profile that never ran `rotate-audit-key`.
        let err = require_value_audit_writer(&profile, "require-unminted")
            .expect_err("unminted audit key must refuse");
        assert_eq!(
            err.code(),
            "audit.chain_key_unavailable",
            "must carry the typed audit wire code, got {err:?}"
        );
    }

    /// With a real 32-byte chain-root key seeded (the post-`rotate-audit-key`
    /// state), `require_value_audit_writer` returns `Ok` with a writer that
    /// writes through to the profile's audit log — the same acquisition
    /// [`emit_value_audit_row`] performs internally, exposed so the caller can
    /// reuse it for the post-confirm emission.
    #[test]
    #[serial]
    fn require_value_audit_writer_returns_writer_when_key_seeded() {
        keyring_mock::install().expect("mock keyring store");

        let dir = tempfile::tempdir().expect("tmp dir");
        let mut profile =
            Profile::builder_testnet("require-seeded", "acct", "n-svc", "n-acct").build();
        profile.audit_log_path = dir.path().join("audit.jsonl");

        let coord = &profile.audit_log_hash_chain_key_id;
        stellar_agent_network::keyring::rotate_keyring_secret_32(&coord.service, &coord.account)
            .expect("seed audit key");

        let writer =
            require_value_audit_writer(&profile, "require-seeded").expect("seeded key must open");

        let entry = AuditEntry::new_value_action_submitted(
            "stellar_pay",
            "stellar:testnet",
            Vec::new(),
            "abcd1234…wxyz5678",
            9,
            stellar_agent_core::audit_log::PolicyDecision::Allow,
            None,
            None,
            "req-require-1",
        );
        emit_value_audit_row_with_writer(&writer, "require-seeded", entry);

        let file = std::fs::File::open(&profile.audit_log_path).expect("audit.jsonl exists");
        let rows: Vec<serde_json::Value> = std::io::BufReader::new(file)
            .lines()
            .map(|l| serde_json::from_str(&l.expect("line")).expect("valid JSON row"))
            .collect();
        assert_eq!(
            rows.len(),
            1,
            "the writer returned by require_value_audit_writer must write through"
        );
    }

    // ── require_value_audit_writer_for_origin — origin-aware dispatch ───────

    use crate::commands::policy_engine::ProfileOrigin;

    /// A [`ProfileOrigin::Persisted`] profile with no audit key seeded fails
    /// closed exactly like [`require_value_audit_writer`] — the origin-aware
    /// wrapper does not relax the persisted-profile invariant.
    #[test]
    #[serial]
    fn for_origin_persisted_refuses_when_key_unminted() {
        keyring_mock::install().expect("mock keyring store");

        let dir = tempfile::tempdir().expect("tmp dir");
        let mut profile =
            Profile::builder_testnet("origin-persisted-unminted", "acct", "n-svc", "n-acct")
                .build();
        profile.audit_log_path = dir.path().join("audit.jsonl");

        let err = require_value_audit_writer_for_origin(
            &profile,
            "origin-persisted-unminted",
            ProfileOrigin::Persisted,
        )
        .expect_err("a persisted profile with an unminted audit key must refuse");
        assert_eq!(
            err.code(),
            "audit.chain_key_unavailable",
            "must carry the typed audit wire code, got {err:?}"
        );
    }

    /// A [`ProfileOrigin::Synthesized`] profile with no audit key seeded stays
    /// fail-open: `Ok(None)`, no refusal — the zero-config quickstart keeps
    /// working even though no audit row can be written for it.
    #[test]
    #[serial]
    fn for_origin_synthesized_stays_fail_open_when_key_unminted() {
        keyring_mock::install().expect("mock keyring store");

        let dir = tempfile::tempdir().expect("tmp dir");
        let mut profile =
            Profile::builder_testnet("origin-synth-unminted", "acct", "n-svc", "n-acct").build();
        profile.audit_log_path = dir.path().join("audit.jsonl");

        let result = require_value_audit_writer_for_origin(
            &profile,
            "origin-synth-unminted",
            ProfileOrigin::Synthesized,
        )
        .expect("a synthesized profile must never refuse, even with no audit key");
        assert!(
            result.is_none(),
            "with no audit key acquirable, the synthesized-origin path returns Ok(None), \
             not a writer"
        );
    }

    /// A [`ProfileOrigin::Synthesized`] profile with a seeded audit key still
    /// returns a writer that writes through — the zero-config path opts INTO
    /// auditing whenever the key happens to be acquirable; it only tolerates
    /// its absence.
    #[test]
    #[serial]
    fn for_origin_synthesized_returns_writer_when_key_seeded() {
        keyring_mock::install().expect("mock keyring store");

        let dir = tempfile::tempdir().expect("tmp dir");
        let mut profile =
            Profile::builder_testnet("origin-synth-seeded", "acct", "n-svc", "n-acct").build();
        profile.audit_log_path = dir.path().join("audit.jsonl");

        let coord = &profile.audit_log_hash_chain_key_id;
        stellar_agent_network::keyring::rotate_keyring_secret_32(&coord.service, &coord.account)
            .expect("seed audit key");

        let writer = require_value_audit_writer_for_origin(
            &profile,
            "origin-synth-seeded",
            ProfileOrigin::Synthesized,
        )
        .expect("must not error")
        .expect("a seeded key must yield a writer even on the synthesized path");

        let entry = AuditEntry::new_value_action_submitted(
            "stellar_pay",
            "stellar:testnet",
            Vec::new(),
            "abcd1234…wxyz5678",
            11,
            stellar_agent_core::audit_log::PolicyDecision::Allow,
            None,
            None,
            "req-origin-synth-1",
        );
        emit_value_audit_row_with_writer(&writer, "origin-synth-seeded", entry);

        let file = std::fs::File::open(&profile.audit_log_path).expect("audit.jsonl exists");
        let rows: Vec<serde_json::Value> = std::io::BufReader::new(file)
            .lines()
            .map(|l| serde_json::from_str(&l.expect("line")).expect("valid JSON row"))
            .collect();
        assert_eq!(
            rows.len(),
            1,
            "the writer returned on the synthesized path must write through"
        );
    }
}
