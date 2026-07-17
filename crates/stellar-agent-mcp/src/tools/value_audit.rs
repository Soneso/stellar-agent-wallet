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
//! [`emit_value_audit_row_strict`], with its own withheld-authorization
//! telemetry on the same failure — the pre-flight here would only duplicate
//! (and change the wire code of) an already-fail-closed path.

use std::sync::{Arc, Mutex};

use zeroize::Zeroizing;

use stellar_agent_core::audit_log::{AuditEntry, AuditWriter, AuditWriterRegistry};
use stellar_agent_core::error::{ValidationError, WalletError};
use stellar_agent_core::profile::schema::Profile;

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

/// Loads and decodes the profile's audit-log chain-root HMAC key from the
/// platform keyring.
///
/// Thin profile adapter over [`stellar_agent_network::keyring::load_hmac_key_32`]
/// — the single source for chain-root HMAC key loading, shared with the CLI
/// audit-emit path (same keyring coordinate and fingerprint discipline). Value
/// rows are signed under this key so `audit verify` covers them.
///
/// # Errors
///
/// - [`WalletError::Auth`] if the keyring entry is unavailable.
/// - [`WalletError::Internal`] if the stored value is not valid base64 or not
///   exactly 32 bytes.
fn load_audit_hmac_key(profile: &Profile) -> Result<Zeroizing<[u8; 32]>, WalletError> {
    stellar_agent_network::keyring::load_hmac_key_32(&profile.audit_log_hash_chain_key_id)
}
