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

use std::sync::{Arc, Mutex};

use zeroize::Zeroizing;

use stellar_agent_core::audit_log::{AuditEntry, AuditWriter, AuditWriterRegistry};
use stellar_agent_core::error::WalletError;
use stellar_agent_core::profile::schema::Profile;

/// Acquires the per-profile audit writer opened under the profile's audit
/// chain-root HMAC key, for callers that write the row themselves later (e.g.
/// the DeFi adapters, which emit inside their submit Ok arm).
///
/// Returns `None` (with a `tracing::warn!`) if the key cannot be loaded or the
/// writer cannot be opened — callers treat emission as non-fatal.
pub(crate) fn acquire_value_audit_writer(
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

/// Writes a value-audit `entry` for `profile` under its audit chain-root HMAC
/// key, via the per-profile writer registry.
///
/// Non-fatal: a failure to load the key, open the writer, take the lock, or
/// append the row logs a `tracing::warn!` and returns without disturbing the
/// caller. Callers construct `entry` with the gate-derived legs already in hand
/// (e.g. [`AuditEntry::new_value_action_submitted`]).
pub(crate) fn emit_value_audit_row(profile: &Profile, profile_name: &str, entry: AuditEntry) {
    let Some(writer_arc) = acquire_value_audit_writer(profile, profile_name) else {
        return;
    };

    match writer_arc.lock() {
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
