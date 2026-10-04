//! Shared audit emission for value-moving MCP tools.
//!
//! Value verbs (pay, create_account, claim, trustline, the DeFi adapters, the
//! x402 authorizers, and the opaque sep43 submit) record a hash-chained,
//! HMAC-signed row after the on-chain action is confirmed — or, for x402, at
//! the point the authorization signature is produced. Emission is NON-FATAL
//! post-success: the action has already committed, so a row-write failure logs
//! a `tracing::warn!` and never changes the tool result or exit path.
//!
//! The legs carried in a row are the SAME `ValueEffects` the policy gate sized
//! (single-derivation invariant); this module only serialises what the caller
//! supplies and never derives value.
//!
//! Rows are written under the profile's audit chain-root HMAC key so
//! `stellar-agent audit verify` covers them. Every acquisition of a given
//! profile log path within the process MUST use this loader's key: the writer
//! registry validates the HMAC-key fingerprint per path, so a prior open of the
//! same path with a different (or absent) key makes the signed acquisition fail.
//!
//! # Pre-flight (fail-closed) vs. post-confirm (fail-open)
//!
//! [`require_value_audit_writer`] is the fail-closed pre-flight every
//! value-moving commit/submit tool calls BEFORE any signing key is touched or
//! transaction submitted: it proves the audit writer is acquirable, refusing
//! with `audit.chain_key_unavailable` if not. The tool then threads the
//! returned writer into [`emit_value_audit_row_with_writer`] for the
//! post-confirm row — no second acquisition, no re-acquisition race.
//! `stellar_mpp_charge_commit` is exempt: it already fails closed via
//! [`emit_value_audit_row_strict`], which refuses on the same conditions under
//! the same wire codes and carries its own withheld-authorization telemetry, so
//! a second gate would only re-check what the credential already hangs on.

use std::sync::{Arc, Mutex};

use stellar_agent_core::audit_log::{
    AuditEntry, AuditWriter, AuditWriterRegistry, BindingCheck, WriterError,
    audit_log_unusable_detail,
};
use stellar_agent_core::error::{ValidationError, WalletError};
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_network::keyring::keyed_audit_access;

/// Requires the per-profile audit writer to be acquirable under the profile's
/// audit chain-root HMAC key — the fail-closed pre-flight for value-moving
/// commit/submit MCP tools.
///
/// Callers invoke this BEFORE any signing key is touched and BEFORE any
/// transaction is submitted (see the module docs). On success, the returned
/// writer MUST be reused for the tool's post-confirm emission
/// ([`emit_value_audit_row_with_writer`]) rather than re-acquired.
///
/// This is the MCP twin of the CLI's
/// `crate::commands::value_audit::require_value_audit_writer` (in the
/// `stellar-agent-cli` crate, so not directly linkable): the two
/// implementations MUST stay wire-identical — same wire code on the same
/// underlying failure, same fail-closed semantics — so a
/// `pay`/`claim`/`trustline`/`trade` refusal reads the same whether it came
/// from the MCP tool or its CLI verb counterpart.
///
/// # Errors
///
/// Returns [`WalletError::Validation`] wrapping one of two variants — both
/// carry the same wire code (`audit.chain_key_unavailable`) but distinct
/// operator-facing remedies, since the two failure modes have different
/// fixes:
/// - [`ValidationError::AuditChainKeyUnavailable`] when the profile's audit
///   chain-root HMAC key cannot be loaded from the platform keyring — a
///   `profile init`-minted profile has no audit chain-root key until
///   `stellar-agent profile rotate-audit-key <profile>` mints one.
/// - [`ValidationError::AuditWriterOpenFailed`] when the key loaded but the
///   audit writer could not be opened at `profile.audit_log_path` (e.g. a
///   registry path/key mismatch against an earlier open in this process) —
///   rotating the audit key does not fix this.
/// - [`ValidationError::AuditTipAnchorMismatch`] when the log's chain tip is not
///   the one its keyring-held anchor names — the log was rolled back,
///   truncated, or replaced. The registry runs that check on EVERY keyed
///   acquisition, not only the first, because it caches one writer per profile
///   for the process lifetime and a check at open alone would miss a file
///   swapped underneath a live writer.
/// - [`ValidationError::AuditLogBindingChanged`] when the profile names a log
///   path or audit key other than the binding recorded in the keyring.
///   `binding` is the check the server stored at startup.
pub(crate) fn require_value_audit_writer(
    profile: &Profile,
    profile_name: &str,
    binding: BindingCheck,
) -> Result<Arc<Mutex<AuditWriter>>, WalletError> {
    let access = keyed_audit_access(profile, profile_name, binding).map_err(|e| {
        // A binding refusal keeps its own code and remedy.
        if is_binding_refusal(&e) {
            tracing::warn!(
                profile = %profile_name,
                code = %e.code(),
                "value audit: audit binding changed; refusing before signing/submit"
            );
            return e;
        }
        tracing::warn!(
            profile = %profile_name,
            error = %e,
            "value audit: could not load audit chain key; refusing before signing/submit"
        );
        audit_chain_key_unavailable(profile_name)
    })?;
    AuditWriterRegistry::get_or_open_keyed(profile_name, &profile.audit_log_path, access)
        .map_err(|e| audit_writer_acquisition_error(profile_name, &e))
}

/// Maps a writer-acquisition failure to the wire code that names it.
///
/// Three outcomes, because three different things are wrong and three different
/// things fix them:
///
/// - A tip-anchor mismatch carries `audit.tip_anchor_mismatch`: the log may have
///   been rolled back, and only `audit reanchor` addresses that.
/// - A condition about the LOG — a held writer lock, an unusable rotation
///   bridge, a broken chain, an unreadable anchor — carries
///   `ValidationError::AuditLogUnusable`, whose message names the condition by
///   its `audit.*` sub-code and points at the recovery runbook. Telling the
///   operator to rotate a key here would send them somewhere useless.
/// - Everything left is a registry path or key registration conflict, which is
///   what `AuditWriterOpenFailed`'s wording describes.
fn audit_writer_acquisition_error(profile_name: &str, e: &WriterError) -> WalletError {
    if let WriterError::TipAnchorMismatch { reason, .. } = e {
        tracing::warn!(
            profile = %profile_name,
            error = %e,
            "value audit: audit log tip anchor mismatch; refusing before signing/submit"
        );
        return WalletError::Validation(ValidationError::AuditTipAnchorMismatch {
            profile: profile_name.to_owned(),
            reason: (*reason).to_owned(),
        });
    }
    if let Some(detail) = audit_log_unusable_detail(e) {
        tracing::warn!(
            profile = %profile_name,
            error = %e,
            "value audit: audit log unusable; refusing before signing/submit"
        );
        return WalletError::Validation(ValidationError::AuditLogUnusable {
            profile: profile_name.to_owned(),
            detail,
        });
    }
    tracing::warn!(
        profile = %profile_name,
        error = %e,
        "value audit: could not open audit writer; refusing before signing/submit"
    );
    audit_writer_open_failed(profile_name)
}

/// Whether `e` is the audit binding refusal.
fn is_binding_refusal(e: &WalletError) -> bool {
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

/// Writes `entry` through an audit writer the caller already acquired (via
/// [`require_value_audit_writer`]).
///
/// Non-fatal: the write has nothing left to gate — the transaction (or, for
/// x402, the authorization signature) already committed — so a failure to
/// take the lock or append the row logs a `tracing::warn!` and returns without
/// disturbing the caller. Callers construct `entry` with the gate-derived legs
/// already in hand (e.g. [`AuditEntry::new_value_action_submitted`]).
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

/// Writes an authorization audit row and fails closed on every acquisition,
/// locking, or persistence error.
///
/// MPP calls this before releasing a credential, so unlike the post-submit
/// helper above (which writes after an action already committed and
/// therefore cannot withhold anything), failure here can and must withhold
/// the artifact.
///
/// Acquiring the writer runs the anchor check, so a log rolled back, truncated,
/// or replaced under the running server refuses HERE and nothing is released.
/// The error carries the wire code that names the condition rather than the
/// uniform state refusal: an agent told the MPP state is unavailable retries,
/// and an operator sent after the state file never finds the rolled-back log.
///
/// # Errors
///
/// [`WalletError::Validation`], with the same variants and wire codes
/// [`require_value_audit_writer`] produces. The append runs the same
/// tip-anchor check the acquisition does, so a refusal there carries
/// [`ValidationError::AuditTipAnchorMismatch`] and its reason rather than a
/// registration-conflict code; everything else carries
/// [`ValidationError::AuditWriterOpenFailed`].
pub(crate) fn emit_value_audit_row_strict(
    profile: &Profile,
    profile_name: &str,
    binding: BindingCheck,
    entry: AuditEntry,
) -> Result<(), WalletError> {
    let access = keyed_audit_access(profile, profile_name, binding).map_err(|e| {
        // A binding refusal keeps its own code and remedy.
        if is_binding_refusal(&e) {
            tracing::warn!(
                profile = %profile_name,
                code = %e.code(),
                "value audit: audit binding changed; withholding the authorization"
            );
            return e;
        }
        tracing::warn!(
            profile = %profile_name,
            error = %e,
            "value audit: could not load audit chain key; withholding the authorization"
        );
        audit_chain_key_unavailable(profile_name)
    })?;
    let writer =
        AuditWriterRegistry::get_or_open_keyed(profile_name, &profile.audit_log_path, access)
            .map_err(|e| audit_writer_acquisition_error(profile_name, &e))?;
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
    use super::*;

    /// Every acquisition failure class maps to an operator-facing message that
    /// names the actual condition.
    ///
    /// The CLI twin of this module pins the same table. The two surfaces are
    /// required to answer the same underlying failure with the same wire code
    /// and the same remedy, so the pin has to exist on both sides: a change to
    /// one mapping that is not made to the other fails here or there, never
    /// silently in production.
    #[test]
    fn the_pre_flight_names_the_condition_it_refused_on() {
        let cases: &[(WriterError, &str, &str)] = &[
            (
                WriterError::FileLocked,
                "audit.chain_key_unavailable",
                "audit.writer_locked",
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

    /// A profile that names `dir/repointed/audit.jsonl` over a binding
    /// recorded for `dir/audit.jsonl`.
    fn bound_then_repointed(name: &str, dir: &std::path::Path) -> Profile {
        let mut profile = Profile::builder_testnet_named(name, "s", "a", "n", "a").build();
        profile.audit_log_path = dir.join("audit.jsonl");
        let coordinate = &profile.audit_log_hash_chain_key_id;
        stellar_agent_network::keyring::rotate_keyring_secret_32(
            &coordinate.service,
            &coordinate.account,
        )
        .unwrap();
        stellar_agent_network::keyring::KeyringAuditBindingStore::for_profile(name)
            .store(&stellar_agent_core::audit_log::AuditBinding::for_profile(
                &profile,
            ))
            .unwrap();
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

    /// The pre-flight passes a binding refusal through under either check
    /// and creates nothing at the repointed path.
    #[test]
    #[serial_test::serial(keyring)]
    fn the_pre_flight_passes_a_binding_refusal_through() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let profile = bound_then_repointed("mcp-binding-preflight", dir.path());
        for binding in [BindingCheck::Enforce, BindingCheck::CheckOnly] {
            let err = require_value_audit_writer(&profile, "mcp-binding-preflight", binding)
                .expect_err("a changed binding refuses");
            assert_eq!(err.code(), "audit.log_binding_changed", "{err}");
        }
        assert!(!dir.path().join("repointed").exists());
    }

    /// The strict helper passes a binding refusal through and writes nothing.
    #[test]
    #[serial_test::serial(keyring)]
    fn the_strict_helper_passes_a_binding_refusal_through() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let profile = bound_then_repointed("mcp-binding-strict", dir.path());
        let err = emit_value_audit_row_strict(
            &profile,
            "mcp-binding-strict",
            BindingCheck::Enforce,
            sample_row(),
        )
        .expect_err("a changed binding refuses");
        assert_eq!(err.code(), "audit.log_binding_changed", "{err}");
        assert!(!dir.path().join("repointed").exists());
    }

    /// Every other keyed-access failure keeps `audit.chain_key_unavailable`
    /// on both helpers.
    #[test]
    #[serial_test::serial(keyring)]
    fn other_keyed_access_failures_keep_chain_key_unavailable() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut profile =
            Profile::builder_testnet_named("mcp-binding-nokey", "s", "a", "n", "a").build();
        profile.audit_log_path = dir.path().join("audit.jsonl");
        let err = require_value_audit_writer(&profile, "mcp-binding-nokey", BindingCheck::Enforce)
            .expect_err("an unminted key refuses");
        assert_eq!(err.code(), "audit.chain_key_unavailable", "{err}");
        let err = emit_value_audit_row_strict(
            &profile,
            "mcp-binding-nokey",
            BindingCheck::Enforce,
            sample_row(),
        )
        .expect_err("an unminted key refuses");
        assert_eq!(err.code(), "audit.chain_key_unavailable", "{err}");
    }
}
