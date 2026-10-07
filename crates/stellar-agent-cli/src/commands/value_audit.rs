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
//! returned writer into [`emit_value_audit_row_with_writer`] for the post-confirm
//! row, reusing the acquired writer.
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
//! [`crate::common::profile_access::load_profile_or_synthesize_testnet`]).
//! [`require_value_audit_writer_for_origin`] applies the pre-flight only to
//! the persisted case; the synthesized zero-config profile keeps the
//! pre-existing warn-only emission path so the documented zero-config
//! quickstart is never blocked by a fail-closed audit-key requirement the
//! operator never opted into. A changed audit binding refuses on both
//! origins, before any signing.

use std::sync::{Arc, Mutex};

use stellar_agent_core::audit_log::{
    AuditEntry, AuditWriter, AuditWriterRegistry, BindingCheck, WriterError, audit_writer_refusal,
};
use stellar_agent_core::error::{ValidationError, WalletError};
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_network::keyring::keyed_audit_access;

use crate::common::profile_access::ProfileOrigin;

/// Requires the per-profile audit writer to be acquirable under the profile's
/// audit chain-root HMAC key — the fail-closed pre-flight for value-moving
/// signing verbs.
///
/// Callers invoke this BEFORE any signing key is touched and BEFORE any
/// transaction is submitted (see the module docs). A verb with a post-confirm
/// row reuses the returned writer for it ([`emit_value_audit_row_with_writer`])
/// rather than re-acquiring it. A verb whose row is written strictly before a
/// transmission discards the handle, and the strict write acquires again.
/// [`drain_consent_rows_before_signing`] discards it too: that acquisition
/// exists for its drain.
///
/// This is the CLI twin of `stellar_agent_mcp::tools::value_audit::require_value_audit_writer`
/// (crate-private there, so not directly linkable). The two stay
/// wire-identical: the same underlying failure gets the same wire code, and
/// both fail closed. A refusal therefore reads the same whether it came from
/// the CLI verb or its MCP tool counterpart.
///
/// # Errors
///
/// Returns [`WalletError::Validation`] wrapping one of these variants, each
/// with its own operator-facing remedy:
/// - [`ValidationError::AuditChainKeyUnavailable`], code
///   `audit.chain_key_unavailable`, when the profile's audit chain-root HMAC
///   key cannot be loaded from the platform keyring, or when the key or its
///   coordinate is refused as the owner key. The `warn` line names that
///   refusal. An `init`-minted profile has no audit chain-root key until
///   `stellar-agent profile rotate-audit-key <profile>` mints one.
/// - [`ValidationError::AuditLogUnusable`], code `audit.chain_key_unavailable`,
///   when the key loaded but the log cannot be used. The message names the
///   condition by its `audit.*` sub-code, including `audit.io_error`,
///   `audit.outbox_busy`, and `audit.outbox_unusable`.
/// - [`ValidationError::AuditWriterOpenFailed`], code
///   `audit.chain_key_unavailable`, when the key loaded but the registry holds
///   a conflicting path or key registration for this profile name. Rotating
///   the audit key does not fix this.
/// - [`ValidationError::AuditTipAnchorMismatch`], code
///   `audit.tip_anchor_mismatch`, when the log's chain tip is not the one its
///   keyring-held anchor names: the log was rolled back, truncated, or
///   replaced. The registry runs that check on every keyed acquisition,
///   because cached writers stay live for the process lifetime and the file
///   can be replaced while they are open.
/// - [`ValidationError::AuditLogBindingChanged`], code
///   `audit.log_binding_changed`, when the profile names a log path or audit
///   key other than the binding recorded in the keyring. The profile is
///   persisted, so an absent binding is recorded.
pub(crate) fn require_value_audit_writer(
    profile: &Profile,
    profile_name: &str,
) -> Result<Arc<Mutex<AuditWriter>>, WalletError> {
    acquire_keyed_audit_writer(profile, profile_name, BindingCheck::Enforce)
        .map_err(|e| e.into_wallet_error(profile_name))
}

/// Acquires the keyed audit writer after a verb read an approval and before it
/// loads the signing key.
///
/// The acquisition drains the audit outbox, at open or on the registry cache
/// hit, so a consent row `stellar-agent approve` queued for the approval is in
/// the log before the key is touched. The handle is not kept. This is not the
/// verb's audit pre-flight, which precedes the approval read.
///
/// # Errors
///
/// Every error of [`require_value_audit_writer`].
pub(crate) fn drain_consent_rows_before_signing(
    profile: &Profile,
    profile_name: &str,
) -> Result<(), WalletError> {
    require_value_audit_writer(profile, profile_name).map(|_writer| ())
}

/// Why a keyed audit-writer acquisition failed, kept typed so a caller can
/// branch on the failure class rather than on its rendered detail.
#[derive(Debug)]
pub(crate) enum KeyedAcquireError {
    /// The profile's audit chain-root key could not be loaded.
    KeyUnavailable,
    /// The profile differs from its recorded audit binding.
    BindingChanged(WalletError),
    /// The writer registry refused with this error.
    Writer(WriterError),
}

impl KeyedAcquireError {
    /// The wallet error [`require_value_audit_writer`] reports for this
    /// failure.
    pub(crate) fn into_wallet_error(self, profile_name: &str) -> WalletError {
        match self {
            Self::BindingChanged(e) => e,
            Self::KeyUnavailable => audit_chain_key_unavailable(profile_name),
            Self::Writer(e) => audit_writer_acquisition_error(profile_name, &e),
        }
    }
}

/// Acquires the keyed writer with the caller's binding policy and keeps
/// failures typed. Persisted profiles use [`BindingCheck::Enforce`];
/// synthesized profiles use [`BindingCheck::CheckOnly`].
///
/// # Errors
///
/// [`KeyedAcquireError::KeyUnavailable`] when the chain-root key cannot be
/// loaded, [`KeyedAcquireError::BindingChanged`] when the binding differs,
/// and [`KeyedAcquireError::Writer`] with the registry's error otherwise.
pub(crate) fn acquire_keyed_audit_writer(
    profile: &Profile,
    profile_name: &str,
    binding: BindingCheck,
) -> Result<Arc<Mutex<AuditWriter>>, KeyedAcquireError> {
    let access = keyed_audit_access(profile, profile_name, binding).map_err(|e| {
        // A binding refusal keeps its own code and remedy.
        if is_binding_refusal(&e) {
            tracing::warn!(
                profile = %profile_name,
                code = %e.code(),
                "value audit: audit binding changed; refusing"
            );
            return KeyedAcquireError::BindingChanged(e);
        }
        tracing::warn!(
            profile = %profile_name,
            error = %e,
            "value audit: could not load audit chain key; refusing"
        );
        KeyedAcquireError::KeyUnavailable
    })?;
    AuditWriterRegistry::get_or_open_keyed(profile_name, &profile.audit_log_path, access)
        .map_err(KeyedAcquireError::Writer)
}

/// Maps a writer-acquisition failure to the wire code that names it, through
/// [`audit_writer_refusal`], the one mapping every audit refusal uses.
fn audit_writer_acquisition_error(profile_name: &str, e: &WriterError) -> WalletError {
    let refusal = audit_writer_refusal(profile_name, e);
    tracing::warn!(
        profile = %profile_name,
        error = %e,
        code = refusal.code(),
        "value audit: audit writer unavailable; refusing"
    );
    refusal
}

/// Whether `e` is the audit binding refusal.
pub(crate) fn is_binding_refusal(e: &WalletError) -> bool {
    matches!(
        e,
        WalletError::Validation(ValidationError::AuditLogBindingChanged { .. })
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
/// [`crate::common::profile_access::load_profile_or_synthesize_testnet`]).
///
/// - [`crate::common::profile_access::ProfileOrigin::Persisted`] delegates to [`require_value_audit_writer`]:
///   fails closed with `audit.chain_key_unavailable` when the writer cannot be
///   acquired. An operator who authored a profile file is expected to run
///   `stellar-agent profile rotate-audit-key <name>` before signing.
/// - [`crate::common::profile_access::ProfileOrigin::Synthesized`] is the zero-config quickstart path — no
///   profile file, no `rotate-audit-key` step to run. The writer is acquired
///   opportunistically (a `tracing::warn!` on failure, no refusal), matching
///   the pre-existing zero-config behavior. Returns `Ok(None)` when the writer
///   could not be acquired; the caller then skips the post-confirm row rather
///   than treating the operation as unaudited — there was no audit guarantee
///   to defeat here, since the operator never persisted a profile in the
///   first place. A recorded audit binding that differs from the profile's
///   refuses: the binding check compares without recording, and its refusal
///   precedes any signing.
///
/// # Errors
///
/// For [`crate::common::profile_access::ProfileOrigin::Persisted`], see
/// [`require_value_audit_writer`]. For
/// [`crate::common::profile_access::ProfileOrigin::Synthesized`],
/// [`ValidationError::AuditLogBindingChanged`] only.
pub(crate) fn require_value_audit_writer_for_origin(
    profile: &Profile,
    profile_name: &str,
    origin: ProfileOrigin,
) -> Result<Option<Arc<Mutex<AuditWriter>>>, WalletError> {
    match origin {
        ProfileOrigin::Persisted => require_value_audit_writer(profile, profile_name).map(Some),
        ProfileOrigin::Synthesized => try_keyed_value_audit_writer(profile, profile_name, origin)
            .inspect_err(|e| {
                tracing::warn!(
                    profile = %profile_name,
                    code = %e.code(),
                    "value audit: audit binding changed; refusing before signing/submit"
                );
            }),
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
/// A binding refusal is returned rather than answered with the unkeyed
/// fallback, so nothing is written to a log the binding does not name.
///
/// # Errors
///
/// - [`ValidationError::AuditLogBindingChanged`] when the profile's audit
///   binding changed.
/// - [`WalletError`] when even the unkeyed open fails, mapped as the keyed
///   acquisition's failures are: a log that cannot be read or written carries
///   [`ValidationError::AuditLogUnusable`] with the `audit.io_error` detail.
pub(crate) fn acquire_best_effort_audit_writer(
    profile: &Profile,
    profile_name: &str,
    origin: ProfileOrigin,
) -> Result<Arc<Mutex<AuditWriter>>, WalletError> {
    if let Some(writer) = try_keyed_value_audit_writer(profile, profile_name, origin)? {
        return Ok(writer);
    }
    tracing::warn!(
        profile = %profile_name,
        "value audit: keyed acquisition unavailable; \
         opening the audit writer unkeyed (rows not covered by audit verify)"
    );
    // The unkeyed open's failure maps the way the keyed acquisition's does, so
    // a log that cannot be opened reports its `audit.*` condition.
    AuditWriterRegistry::get_or_open_unkeyed(profile_name, &profile.audit_log_path)
        .map_err(|e| audit_writer_acquisition_error(profile_name, &e))
}

/// Acquires the per-profile audit writer opened under the profile's audit
/// chain-root HMAC key.
///
/// Returns `None` (with a `tracing::warn!`) if the binding refuses, the key
/// cannot be loaded, or the writer cannot be opened. A binding refusal is
/// logged with its code and the row is skipped. `origin` selects the binding
/// check. Private: the one caller is [`emit_value_audit_row`], the exempt,
/// non-signing call site. Every signing verb uses
/// [`require_value_audit_writer`] or [`require_value_audit_writer_for_origin`]
/// instead, and both refuse a changed binding.
fn acquire_value_audit_writer(
    profile: &Profile,
    profile_name: &str,
    origin: ProfileOrigin,
) -> Option<Arc<Mutex<AuditWriter>>> {
    match try_keyed_value_audit_writer(profile, profile_name, origin) {
        Ok(writer) => writer,
        Err(e) => {
            tracing::warn!(
                profile = %profile_name,
                code = %e.code(),
                "value audit: audit binding changed; row skipped"
            );
            None
        }
    }
}

/// The keyed attempt behind [`acquire_value_audit_writer`],
/// [`acquire_best_effort_audit_writer`], and the synthesized arm of
/// [`require_value_audit_writer_for_origin`].
///
/// `Ok(None)`, with a `tracing::warn!`, when the key cannot be loaded or the
/// writer cannot be opened.
///
/// # Errors
///
/// [`ValidationError::AuditLogBindingChanged`] only, so each caller decides
/// whether a binding refusal skips its row or refuses.
fn try_keyed_value_audit_writer(
    profile: &Profile,
    profile_name: &str,
    origin: ProfileOrigin,
) -> Result<Option<Arc<Mutex<AuditWriter>>>, WalletError> {
    let access = match keyed_audit_access(profile, profile_name, origin.binding_check()) {
        Ok(access) => access,
        Err(e) if is_binding_refusal(&e) => return Err(e),
        Err(e) => {
            tracing::warn!(
                profile = %profile_name,
                error = %e,
                "value audit: could not load audit chain key; writer NOT acquired"
            );
            return Ok(None);
        }
    };
    match AuditWriterRegistry::get_or_open_keyed(profile_name, &profile.audit_log_path, access) {
        Ok(arc) => Ok(Some(arc)),
        Err(e) => {
            tracing::warn!(
                profile = %profile_name,
                error = %e,
                "value audit: could not open audit writer; writer NOT acquired"
            );
            Ok(None)
        }
    }
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

/// Appends `entry` through `writer`, logging a poisoned writer mutex or a
/// refused append at `error` with `event_kind`.
///
/// For a row whose absence does not change the command's result: the act it
/// records already happened or was already refused. The absence is never
/// silent.
pub(crate) fn write_row_logged(
    writer: &Arc<Mutex<AuditWriter>>,
    entry: AuditEntry,
    event_kind: &'static str,
    request_id: &str,
) {
    let Ok(mut guard) = writer.lock() else {
        tracing::error!(
            event_kind,
            request_id,
            "audit writer mutex poisoned; the row was not written"
        );
        return;
    };
    if let Err(e) = guard.write_entry(entry) {
        tracing::error!(
            event_kind,
            request_id,
            error = %e,
            "audit write failed; the row was not written"
        );
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
    let Some(writer_arc) =
        acquire_value_audit_writer(profile, profile_name, ProfileOrigin::Persisted)
    else {
        return;
    };
    emit_value_audit_row_with_writer(&writer_arc, profile_name, entry);
}

/// Writes an authorization row and propagates failures while the caller can
/// still withhold the credential.
///
/// Acquiring the writer runs the anchor check, so a log rolled back, truncated,
/// or replaced under a live process refuses HERE and the credential is withheld.
/// The error carries the wire code that names the condition, because the caller
/// renders it to the agent and "the state is unavailable" would send an operator
/// looking in the wrong place for a log that needs `audit reanchor`.
///
/// `binding` is the audit binding check of the profile's origin: a
/// synthesized profile passes [`BindingCheck::CheckOnly`], so the row records
/// no binding for it.
///
/// # Errors
///
/// [`WalletError::Validation`], with the same variants and wire codes
/// [`require_value_audit_writer`] produces. The append runs the checks the
/// acquisition does and maps a refusal the same way: a tip-anchor mismatch to
/// [`ValidationError::AuditTipAnchorMismatch`], a condition about the log to
/// [`ValidationError::AuditLogUnusable`], and anything else to
/// [`ValidationError::AuditWriterOpenFailed`]. A poisoned writer mutex
/// carries [`ValidationError::AuditWriterOpenFailed`].
pub(crate) fn emit_value_audit_row_strict(
    profile: &Profile,
    profile_name: &str,
    binding: BindingCheck,
    entry: AuditEntry,
) -> Result<(), WalletError> {
    let writer = acquire_keyed_audit_writer(profile, profile_name, binding)
        .map_err(|e| e.into_wallet_error(profile_name))?;
    let mut guard = writer.lock().map_err(|_| {
        tracing::warn!(
            profile = %profile_name,
            "value audit: audit writer mutex poisoned; withholding the authorization"
        );
        audit_writer_open_failed(profile_name)
    })?;
    guard.write_entry(entry).map_err(|e| {
        tracing::warn!(
            profile = %profile_name,
            error = %e,
            "value audit: authorization row NOT emitted; withholding the authorization"
        );
        // The append runs its own tip-anchor check, so a log rolled back under
        // a live writer refuses here as well as at acquisition. It carries the
        // code that names that condition, the way the acquisition path does:
        // an operator sent after a registration conflict never finds one.
        audit_writer_acquisition_error(profile_name, &e)
    })
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

    use crate::common::profile_access::ProfileOrigin;

    /// A [`crate::common::profile_access::ProfileOrigin::Persisted`] profile with no audit key seeded fails
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

    /// A [`crate::common::profile_access::ProfileOrigin::Synthesized`] profile with no audit key seeded stays
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

    /// A [`crate::common::profile_access::ProfileOrigin::Synthesized`] profile with a seeded audit key still
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

    // ── The pre-flight's failure mapping ─────────────────────────────────────

    #[test]
    fn writer_locked_refusal_names_the_holder_and_recovery_without_a_path() {
        let mapped = audit_writer_acquisition_error("default", &WriterError::FileLocked);
        assert_eq!(mapped.code(), "audit.chain_key_unavailable");
        let WalletError::Validation(ValidationError::AuditLogUnusable { profile, detail }) =
            &mapped
        else {
            panic!("writer lock must map to AuditLogUnusable");
        };
        assert_eq!(profile, "default");
        assert_eq!(
            detail,
            "audit.writer_locked: an active audit writer holds this profile's lock \
            (for example, a running stellar-agent-mcp server); stop the process using \
            this profile, retry the command, then restart the server if needed"
        );
        assert_eq!(
            mapped.message(),
            format!(
                "profile 'default' cannot be audited: {detail}; signing refuses to proceed \
             unaudited — see docs/maintainers/audit-log-recovery.md"
            )
        );
    }

    /// Every acquisition failure class maps to an operator-facing message that
    /// names the actual condition.
    ///
    /// The pre-flight is fail-closed for all of them; what differs is what the
    /// operator is told to do. Folding a held writer lock, an unusable rotation
    /// bridge or a broken chain into "the chain key is unavailable" sends them
    /// to mint or rotate a key that is not the problem, so each class carries
    /// its own `audit.*` sub-code in the detail, which is what the skill's
    /// troubleshooting table keys on.
    #[test]
    fn the_pre_flight_names_the_condition_it_refused_on() {
        let cases: &[(WriterError, &str, &str)] = &[
            (
                WriterError::FileLocked,
                "audit.chain_key_unavailable",
                "audit.writer_locked",
            ),
            (
                WriterError::OutboxBusy,
                "audit.chain_key_unavailable",
                "audit.outbox_busy",
            ),
            (
                WriterError::OutboxUnusable {
                    line: 2,
                    column: 1,
                    reason: "invalid JSON",
                },
                "audit.chain_key_unavailable",
                "audit.outbox_unusable",
            ),
            (
                WriterError::RotationBridgeUnusable {
                    archive_name: "audit.jsonl.20260913T120000000".to_owned(),
                    reason: "the archive does not end with a rotation handoff entry",
                },
                "audit.chain_key_unavailable",
                "audit.rotation_bridge_unusable",
            ),
            (
                WriterError::ChainBrokenAtOpen {
                    entry_idx: 7,
                    expected_hex: "sha256:aa".to_owned(),
                    got_hex: "sha256:bb".to_owned(),
                },
                "audit.chain_key_unavailable",
                "audit.chain_broken",
            ),
            (
                WriterError::TipAnchorStore(
                    stellar_agent_core::audit_log::TipAnchorStoreError::new("keyring locked"),
                ),
                "audit.chain_key_unavailable",
                "audit.tip_anchor_unavailable",
            ),
            (
                WriterError::TipAnchorMismatch {
                    expected_count: 3,
                    expected_offset: 900,
                    actual_len: 600,
                    reason: "file is shorter than the anchor",
                },
                "audit.tip_anchor_mismatch",
                "audit reanchor",
            ),
            (
                WriterError::TipAnchorMismatch {
                    expected_count: 3,
                    expected_offset: 900,
                    actual_len: 900,
                    reason: "the log at the path was replaced underneath the writer",
                },
                "audit.tip_anchor_mismatch",
                "audit reanchor",
            ),
        ];

        for (error, expected_code, expected_in_message) in cases {
            let mapped = audit_writer_acquisition_error("default", error);
            assert_eq!(
                mapped.code(),
                *expected_code,
                "wire code for {error:?}: {}",
                mapped.message()
            );
            assert!(
                mapped.message().contains(expected_in_message),
                "the refusal for {error:?} must name {expected_in_message}: {}",
                mapped.message()
            );
            assert!(
                !mapped.message().contains("rotate-audit-key"),
                "none of these is fixed by rotating the audit key: {}",
                mapped.message()
            );
        }

        // The two mismatch reasons must reach the operator distinguishably: the
        // remedy is the same verb, but what to look at before running it is not.
        let shorter = audit_writer_acquisition_error(
            "default",
            &WriterError::TipAnchorMismatch {
                expected_count: 3,
                expected_offset: 900,
                actual_len: 600,
                reason: "file is shorter than the anchor",
            },
        );
        let replaced = audit_writer_acquisition_error(
            "default",
            &WriterError::TipAnchorMismatch {
                expected_count: 3,
                expected_offset: 900,
                actual_len: 900,
                reason: "the log at the path was replaced underneath the writer",
            },
        );
        assert_ne!(
            shorter.message(),
            replaced.message(),
            "the reason must survive into the envelope, not only the server log"
        );
    }

    /// A registry path or key registration conflict keeps the wording that
    /// describes it, which is the one class `AuditWriterOpenFailed` is about.
    #[test]
    fn a_registration_conflict_keeps_its_own_wording() {
        let mapped = audit_writer_acquisition_error(
            "default",
            &WriterError::HmacKeyMismatch {
                profile_name: "default".to_owned(),
            },
        );
        assert_eq!(mapped.code(), "audit.chain_key_unavailable");
        assert!(
            mapped
                .message()
                .contains("conflicting audit-log path or key registration"),
            "message: {}",
            mapped.message()
        );
    }

    // ── require_value_audit_writer — the tip-anchor pre-flight ───────────────

    /// Seeds a chain-root key at the profile's audit coordinate and returns the
    /// profile, so the pre-flight has a key to acquire.
    fn keyed_profile(name: &'static str, dir: &std::path::Path) -> Profile {
        let mut profile = Profile::builder_testnet(name, "acct", "n-svc", "n-acct").build();
        profile.audit_log_path = dir.join("audit.jsonl");
        let coord = &profile.audit_log_hash_chain_key_id;
        stellar_agent_network::keyring::rotate_keyring_secret_32(&coord.service, &coord.account)
            .expect("seed audit key");
        profile
    }

    /// The pre-flight runs on EVERY acquisition, not only the first. The writer
    /// registry caches one writer per profile for the process lifetime, so a log
    /// replaced underneath a live writer must still be caught — this is the case
    /// an open-time-only check would miss.
    #[test]
    #[serial]
    fn require_value_audit_writer_refuses_after_the_log_is_replaced_underneath_it() {
        keyring_mock::install().expect("mock keyring store");

        let dir = tempfile::tempdir().expect("tmp dir");
        let profile = keyed_profile("anchor-live-swap", dir.path());

        // First acquisition: adopts (empty log), then rows are appended through
        // the writer the pre-flight returned.
        let writer = require_value_audit_writer(&profile, "anchor-live-swap")
            .expect("first acquisition must succeed");
        {
            let mut guard = writer.lock().expect("writer lock");
            guard
                .write_entry(AuditEntry::new_value_action_submitted(
                    "stellar_pay",
                    "stellar:testnet",
                    Vec::new(),
                    "abcd1234…wxyz5678",
                    7,
                    stellar_agent_core::audit_log::PolicyDecision::Allow,
                    None,
                    None,
                    None,
                    "req-anchor-1",
                ))
                .expect("append");
        }
        let snapshot = std::fs::read(&profile.audit_log_path).expect("read log");
        {
            let mut guard = writer.lock().expect("writer lock");
            guard
                .write_entry(AuditEntry::new_value_action_submitted(
                    "stellar_pay",
                    "stellar:testnet",
                    Vec::new(),
                    "abcd1234…wxyz5678",
                    8,
                    stellar_agent_core::audit_log::PolicyDecision::Allow,
                    None,
                    None,
                    None,
                    "req-anchor-2",
                ))
                .expect("append");
        }

        require_value_audit_writer(&profile, "anchor-live-swap")
            .expect("an untouched log must still acquire");

        // Roll the log back underneath the cached writer.
        std::fs::write(&profile.audit_log_path, &snapshot).expect("restore older copy");

        let err = require_value_audit_writer(&profile, "anchor-live-swap")
            .expect_err("a rolled-back log must refuse");
        assert_eq!(
            err.code(),
            "audit.tip_anchor_mismatch",
            "the refusal must name the tip-anchor check, not the chain key: {err}"
        );
    }

    /// A log with no anchor is adopted on first use with no operator action —
    /// the upgrade path for every profile that predates the anchor — and the
    /// adoption is recorded in the log itself.
    #[test]
    #[serial]
    fn require_value_audit_writer_adopts_an_existing_unanchored_log() {
        keyring_mock::install().expect("mock keyring store");

        let dir = tempfile::tempdir().expect("tmp dir");
        let profile = keyed_profile("anchor-adopt", dir.path());

        // A log written before the anchor existed: rows present, no anchor.
        {
            let key =
                crate::commands::profile::audit_emit::load_audit_hmac_key(&profile, "test-profile")
                    .expect("load key");
            let mut writer =
                stellar_agent_core::audit_log::AuditWriter::open_keyed_unanchored_for_test(
                    profile.audit_log_path.clone(),
                    key,
                )
                .expect("open unanchored writer");
            writer
                .write_entry(AuditEntry::new_value_action_submitted(
                    "stellar_pay",
                    "stellar:testnet",
                    Vec::new(),
                    "abcd1234…wxyz5678",
                    1,
                    stellar_agent_core::audit_log::PolicyDecision::Allow,
                    None,
                    None,
                    None,
                    "req-pre-anchor",
                ))
                .expect("append");
        }

        require_value_audit_writer(&profile, "anchor-adopt")
            .expect("adoption must need no operator action");

        let file = std::fs::File::open(&profile.audit_log_path).expect("audit.jsonl exists");
        let adopted = std::io::BufReader::new(file)
            .lines()
            .map(|l| {
                serde_json::from_str::<serde_json::Value>(&l.expect("line")).expect("JSON row")
            })
            .filter(|row| row["kind"] == "audit_tip_anchored" && row["reason"] == "adopted")
            .count();
        assert_eq!(adopted, 1, "adoption must leave exactly one row in the log");
    }

    // ── Audit binding ────────────────────────────────────────────────────────

    /// A keyed profile whose binding is recorded for `dir/audit.jsonl` and
    /// whose log path then moves to `dir/repointed/audit.jsonl`.
    fn bound_then_repointed(name: &'static str, dir: &std::path::Path) -> Profile {
        let mut profile = keyed_profile(name, dir);
        stellar_agent_network::keyring::KeyringAuditBindingStore::for_profile(name)
            .store(&stellar_agent_core::audit_log::AuditBinding::for_profile(
                &profile,
            ))
            .expect("record binding");
        profile.audit_log_path = dir.join("repointed").join("audit.jsonl");
        profile
    }

    fn sample_row() -> AuditEntry {
        AuditEntry::new_value_action_submitted(
            "stellar_pay",
            "stellar:testnet",
            Vec::new(),
            "abcd1234…wxyz5678",
            1,
            stellar_agent_core::audit_log::PolicyDecision::Allow,
            None,
            None,
            None,
            "req-binding",
        )
    }

    #[test]
    #[serial]
    fn the_pre_flight_passes_a_binding_refusal_through() {
        keyring_mock::install().expect("mock keyring store");
        let dir = tempfile::tempdir().expect("tmp dir");
        let profile = bound_then_repointed("binding-preflight", dir.path());
        let err = require_value_audit_writer(&profile, "binding-preflight")
            .expect_err("a changed binding refuses");
        assert_eq!(err.code(), "audit.log_binding_changed", "{err}");
        assert!(!dir.path().join("repointed").exists());
    }

    #[test]
    #[serial]
    fn the_pre_flight_records_an_absent_binding() {
        keyring_mock::install().expect("mock keyring store");
        let dir = tempfile::tempdir().expect("tmp dir");
        let profile = keyed_profile("binding-preflight-absent", dir.path());
        require_value_audit_writer(&profile, "binding-preflight-absent")
            .expect("an absent binding proceeds");
        assert_eq!(
            stellar_agent_network::keyring::KeyringAuditBindingStore::for_profile(
                "binding-preflight-absent"
            )
            .load_raw()
            .expect("read binding"),
            Some(
                stellar_agent_core::audit_log::AuditBinding::for_profile(&profile)
                    .to_keyring_value()
            ),
            "the pre-flight records an absent binding"
        );
    }

    #[test]
    #[serial]
    fn the_strict_helper_passes_a_binding_refusal_through() {
        keyring_mock::install().expect("mock keyring store");
        let dir = tempfile::tempdir().expect("tmp dir");
        let profile = bound_then_repointed("binding-strict", dir.path());
        for binding in [BindingCheck::Enforce, BindingCheck::CheckOnly] {
            let err =
                emit_value_audit_row_strict(&profile, "binding-strict", binding, sample_row())
                    .expect_err("a changed binding refuses");
            assert_eq!(err.code(), "audit.log_binding_changed", "{err}");
        }
        assert!(!dir.path().join("repointed").exists());
    }

    /// The strict helper under `CheckOnly` writes its row and records no
    /// binding.
    #[test]
    #[serial]
    fn the_strict_helper_under_check_only_records_no_binding() {
        keyring_mock::install().expect("mock keyring store");
        let dir = tempfile::tempdir().expect("tmp dir");
        let profile = keyed_profile("binding-strict-check-only", dir.path());
        emit_value_audit_row_strict(
            &profile,
            "binding-strict-check-only",
            BindingCheck::CheckOnly,
            sample_row(),
        )
        .expect("an absent binding proceeds");
        assert!(
            stellar_agent_network::keyring::KeyringAuditBindingStore::for_profile(
                "binding-strict-check-only"
            )
            .load_raw()
            .expect("read binding")
            .is_none(),
            "CheckOnly records no binding"
        );
        assert!(
            std::fs::read_to_string(&profile.audit_log_path)
                .expect("read log")
                .contains("value_action_submitted"),
            "the row is written"
        );
    }

    /// Every other keyed-access failure keeps `audit.chain_key_unavailable`
    /// on the strict helper, as on the pre-flight.
    #[test]
    #[serial]
    fn the_strict_helper_keeps_chain_key_unavailable_for_other_failures() {
        keyring_mock::install().expect("mock keyring store");
        let dir = tempfile::tempdir().expect("tmp dir");
        let mut profile = Profile::builder_testnet("binding-strict-nokey", "a", "n", "n").build();
        profile.audit_log_path = dir.path().join("audit.jsonl");
        let err = emit_value_audit_row_strict(
            &profile,
            "binding-strict-nokey",
            BindingCheck::Enforce,
            sample_row(),
        )
        .expect_err("an unminted key refuses");
        assert_eq!(err.code(), "audit.chain_key_unavailable", "{err}");
    }

    /// The best-effort acquisition returns a binding refusal rather than
    /// opening an unkeyed writer at the repointed path.
    #[test]
    #[serial]
    fn best_effort_returns_a_binding_refusal_instead_of_an_unkeyed_writer() {
        keyring_mock::install().expect("mock keyring store");
        let dir = tempfile::tempdir().expect("tmp dir");
        let profile = bound_then_repointed("binding-best-effort", dir.path());
        for origin in [ProfileOrigin::Persisted, ProfileOrigin::Synthesized] {
            let err = acquire_best_effort_audit_writer(&profile, "binding-best-effort", origin)
                .expect_err("a changed binding refuses");
            assert_eq!(err.code(), "audit.log_binding_changed", "{err}");
        }
        assert!(
            !dir.path().join("repointed").exists(),
            "no unkeyed fallback"
        );
    }

    /// An unkeyed fallback whose log cannot be opened reports the log's
    /// condition, `audit.io_error`, and no registration conflict.
    #[test]
    #[serial]
    fn an_unkeyed_open_failure_reports_the_io_condition() {
        keyring_mock::install().expect("mock keyring store");
        let dir = tempfile::tempdir().expect("tmp dir");
        let blocker = dir.path().join("not-a-directory");
        std::fs::write(&blocker, b"a file where the audit directory goes").expect("write");
        let mut profile = Profile::builder_testnet("unkeyed-io", "acct", "n-svc", "n-acct").build();
        profile.audit_log_path = blocker.join("audit").join("audit.jsonl");
        let Err(err) =
            acquire_best_effort_audit_writer(&profile, "unkeyed-io", ProfileOrigin::Synthesized)
        else {
            panic!("an audit directory that cannot be created refuses");
        };
        assert_eq!(err.code(), "audit.chain_key_unavailable", "{err}");
        assert!(
            err.message().contains("audit.io_error"),
            "{}",
            err.message()
        );
        assert!(
            !err.message()
                .contains("conflicting audit-log path or key registration"),
            "{}",
            err.message()
        );
    }

    /// The warn-only path skips its row, logs the code, and writes nothing.
    #[test]
    #[serial]
    fn the_warn_only_path_skips_its_row_and_logs_the_code() {
        keyring_mock::install().expect("mock keyring store");
        let dir = tempfile::tempdir().expect("tmp dir");
        let profile = bound_then_repointed("binding-warn-only", dir.path());
        let writer = stellar_agent_test_support::CaptureWriter::new();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(writer.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::WARN)
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            emit_value_audit_row(&profile, "binding-warn-only", sample_row());
        });
        let logs = String::from_utf8(writer.captured()).expect("utf8");
        assert!(logs.contains("audit.log_binding_changed"), "{logs}");
        assert!(!dir.path().join("repointed").exists());
    }

    /// A synthesized profile's warn-only pre-flight records no binding.
    #[test]
    #[serial]
    fn a_synthesized_origin_records_no_binding() {
        keyring_mock::install().expect("mock keyring store");
        let dir = tempfile::tempdir().expect("tmp dir");
        let profile = keyed_profile("binding-synthesized", dir.path());
        require_value_audit_writer_for_origin(
            &profile,
            "binding-synthesized",
            ProfileOrigin::Synthesized,
        )
        .expect("warn-only pre-flight");
        assert!(
            stellar_agent_network::keyring::KeyringAuditBindingStore::for_profile(
                "binding-synthesized"
            )
            .load_raw()
            .expect("read binding")
            .is_none(),
            "a synthesized origin records no binding"
        );
    }

    /// A synthesized profile's pre-flight refuses a recorded binding that
    /// differs, before any signing, and creates nothing at the path the
    /// profile names.
    #[test]
    #[serial]
    fn a_synthesized_origin_refuses_a_changed_binding() {
        keyring_mock::install().expect("mock keyring store");
        let dir = tempfile::tempdir().expect("tmp dir");
        let profile = bound_then_repointed("binding-synthesized-changed", dir.path());
        let Err(err) = require_value_audit_writer_for_origin(
            &profile,
            "binding-synthesized-changed",
            ProfileOrigin::Synthesized,
        ) else {
            panic!("a changed binding refuses on a synthesized origin");
        };
        assert_eq!(err.code(), "audit.log_binding_changed", "{err}");
        assert!(!dir.path().join("repointed").exists());
    }

    /// The unkeyed registry entry point reads and writes no binding, so an
    /// unkeyed writer opens at a path the recorded binding does not name.
    #[test]
    #[serial]
    fn get_or_open_unkeyed_records_and_checks_no_binding() {
        keyring_mock::install().expect("mock keyring store");
        let dir = tempfile::tempdir().expect("tmp dir");
        let profile = bound_then_repointed("binding-unkeyed", dir.path());
        let recorded = stellar_agent_network::keyring::KeyringAuditBindingStore::for_profile(
            "binding-unkeyed",
        )
        .load_raw()
        .expect("read binding");
        AuditWriterRegistry::get_or_open_unkeyed("binding-unkeyed", &profile.audit_log_path)
            .expect("an unkeyed open ignores the binding");
        assert!(
            stellar_agent_network::keyring::KeyringAuditBindingStore::for_profile(
                "binding-unkeyed"
            )
            .load_raw()
            .expect("read binding")
                == recorded,
            "an unkeyed open leaves the recorded binding"
        );
        let fresh = keyed_profile("binding-unkeyed-fresh", dir.path());
        AuditWriterRegistry::get_or_open_unkeyed("binding-unkeyed-fresh", &fresh.audit_log_path)
            .expect("open");
        assert!(
            stellar_agent_network::keyring::KeyringAuditBindingStore::for_profile(
                "binding-unkeyed-fresh"
            )
            .load_raw()
            .expect("read binding")
            .is_none(),
            "an unkeyed open records no binding"
        );
    }

    /// A row that is not written is never silent: a poisoned writer mutex and
    /// a refused append are each logged at `error` with the row's event kind.
    #[test]
    fn write_row_logged_logs_a_poisoned_mutex_and_a_refused_append_at_error() {
        use stellar_agent_core::audit_log::tip_anchor::{InMemoryTipAnchorStore, TipAnchorStore};
        use stellar_agent_test_support::log_capture::with_captured_logs;

        let row = || {
            AuditEntry::new_approval_rejected(
                "PaymentSimulated",
                "AAAAAAAAAAAAAAAAAAAAAA",
                "cli",
                "row-request",
            )
        };
        let dir = tempfile::tempdir().unwrap();

        let poisoned = Arc::new(Mutex::new(
            AuditWriter::open(dir.path().join("poisoned.jsonl"), None).unwrap(),
        ));
        let held = Arc::clone(&poisoned);
        let _ = std::thread::spawn(move || {
            let _guard = held.lock().unwrap();
            panic!("poison the audit writer mutex");
        })
        .join();
        let logs = with_captured_logs(|| {
            write_row_logged(&poisoned, row(), "test_poisoned_kind", "req-poisoned");
        });
        assert!(logs.contains("ERROR"), "{logs}");
        assert!(logs.contains("test_poisoned_kind"), "{logs}");
        assert!(logs.contains("req-poisoned"), "{logs}");
        assert!(logs.contains("mutex poisoned"), "{logs}");

        // An anchored writer over a log rolled back underneath it refuses
        // every append.
        let anchored_path = dir.path().join("anchored.jsonl");
        let mut anchored = AuditWriter::open_with_tip_anchor(
            anchored_path.clone(),
            None,
            Arc::new(InMemoryTipAnchorStore::new()) as Arc<dyn TipAnchorStore>,
        )
        .unwrap();
        anchored.write_entry(row()).unwrap();
        std::fs::write(&anchored_path, b"").unwrap();
        let refusing = Arc::new(Mutex::new(anchored));
        let logs = with_captured_logs(|| {
            write_row_logged(&refusing, row(), "test_refused_kind", "req-refused");
        });
        assert!(logs.contains("ERROR"), "{logs}");
        assert!(logs.contains("test_refused_kind"), "{logs}");
        assert!(logs.contains("req-refused"), "{logs}");
        assert!(logs.contains("audit write failed"), "{logs}");
        assert_eq!(std::fs::read(&anchored_path).unwrap(), b"", "no row lands");
    }
}
