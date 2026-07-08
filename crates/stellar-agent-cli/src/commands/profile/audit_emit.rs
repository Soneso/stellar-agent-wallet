//! Shared audit emission for profile key-writing commands.
//!
//! Each profile command that writes long-lived key material to the platform
//! keyring records a `KeyringKeyWritten` row after the write succeeds. Emission
//! is non-fatal: the key write has already committed, so a row-write failure
//! logs a warning and never changes the command's outcome or exit code. The row
//! records only WHICH key slot was written, its keyring coordinates, and — for
//! the two enroll commands — a redacted public address. It NEVER carries a key
//! value, seed, base64 key material, or any derived secret.

use zeroize::Zeroizing;

use stellar_agent_core::audit_log::{AuditEntry, AuditWriterRegistry, KeyPurpose};
use stellar_agent_core::error::WalletError;
use stellar_agent_core::observability::RedactedStrkey;
use stellar_agent_core::profile::schema::{KeyringEntryRef, Profile};

/// Emits a `KeyringKeyWritten` row for a key that was just written to the
/// keyring slot identified by `written_entry`.
///
/// Non-fatal: any failure to load the audit chain key, open the writer, or
/// append the row logs a `tracing::warn!` and returns without disturbing the
/// command result. `public_address` is `Some` only for the two enroll commands
/// (redacted at the call site); HMAC-key rotations pass `None`.
///
/// For `rotate-audit-key` this MUST be called AFTER the audit chain key has been
/// rotated AND the per-file chain-root sidecars re-signed: the helper opens the
/// writer with the CURRENT keyring key, so calling it before the re-sign would
/// append a row the freshly rotated key cannot verify.
pub(super) fn emit_keyring_key_written(
    profile: &Profile,
    profile_name: &str,
    tool: &str,
    key_purpose: KeyPurpose,
    written_entry: &KeyringEntryRef,
    public_address: Option<RedactedStrkey>,
    request_id: &str,
) {
    let hmac_key = match load_audit_hmac_key(profile) {
        Ok(k) => Some(k),
        Err(e) => {
            tracing::warn!(
                profile = %profile_name,
                error = %e,
                "key write audit: could not load audit chain key; \
                 KeyringKeyWritten NOT emitted"
            );
            return;
        }
    };

    let writer_arc =
        match AuditWriterRegistry::get_or_open(profile_name, &profile.audit_log_path, hmac_key) {
            Ok(arc) => arc,
            Err(e) => {
                tracing::warn!(
                    profile = %profile_name,
                    error = %e,
                    "key write audit: could not open audit writer; \
                     KeyringKeyWritten NOT emitted"
                );
                return;
            }
        };

    let entry = AuditEntry::new_keyring_key_written(
        tool,
        key_purpose,
        written_entry.service.clone(),
        written_entry.account.clone(),
        public_address,
        request_id,
    );

    match writer_arc.lock() {
        Ok(mut guard) => {
            if let Err(e) = guard.write_entry(entry) {
                tracing::warn!(
                    profile = %profile_name,
                    error = %e,
                    "key write audit: write_entry failed; KeyringKeyWritten NOT emitted"
                );
            }
        }
        Err(_) => {
            tracing::warn!(
                profile = %profile_name,
                "key write audit: audit writer mutex poisoned; KeyringKeyWritten NOT emitted"
            );
        }
    }
}

/// Loads and decodes the profile's audit-log chain-root HMAC key from the
/// platform keyring.
///
/// Thin profile adapter over [`stellar_agent_network::keyring::load_hmac_key_32`]
/// — the single source for chain-root HMAC key loading (same keyring-coordinate
/// discipline and secret-safe error mapping; the MCP value-audit path adapts the
/// same function). Shared by the key-write emission path and by
/// `rotate-audit-key`, which reads the freshly rotated key back to re-sign the
/// per-file chain-root sidecars.
///
/// # Errors
///
/// - [`WalletError::Auth`] if the keyring entry is unavailable.
/// - [`WalletError::Internal`] if the stored value is not valid base64 or not
///   exactly 32 bytes.
pub(crate) fn load_audit_hmac_key(profile: &Profile) -> Result<Zeroizing<[u8; 32]>, WalletError> {
    stellar_agent_network::keyring::load_hmac_key_32(&profile.audit_log_hash_chain_key_id)
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
    use stellar_agent_core::audit_log::KeyPurpose;
    use stellar_agent_test_support::keyring_mock;

    use super::*;

    /// `emit_keyring_key_written` writes exactly one `keyring_key_written` row
    /// through the real acquisition path (keyring loader → writer registry →
    /// append), recording the key purpose and keyring coordinates and NO public
    /// address for an HMAC-key rotation. Guards the #34 emission plumbing shared
    /// by the six key-writing profile commands in push CI.
    #[test]
    #[serial]
    fn emit_keyring_key_written_writes_a_key_written_row() {
        keyring_mock::install().expect("mock keyring store");

        let dir = tempfile::tempdir().expect("tmp dir");
        let mut profile = Profile::builder_testnet("k34-emit", "acct", "n-svc", "n-acct").build();
        profile.audit_log_path = dir.path().join("audit.jsonl");

        // Seed a real 32-byte chain-root key at the profile's audit coordinate.
        let coord = &profile.audit_log_hash_chain_key_id;
        stellar_agent_network::keyring::rotate_keyring_secret_32(&coord.service, &coord.account)
            .expect("seed audit key");

        let written = profile.mcp_nonce_key_alias.clone();
        emit_keyring_key_written(
            &profile,
            "k34-emit",
            "profile_rotate_nonce_key",
            KeyPurpose::NonceHmac,
            &written,
            None,
            "req-k34-1",
        );

        let file = std::fs::File::open(&profile.audit_log_path).expect("audit.jsonl exists");
        let rows: Vec<serde_json::Value> = std::io::BufReader::new(file)
            .lines()
            .map(|l| serde_json::from_str(&l.expect("line")).expect("valid JSON row"))
            .collect();

        assert_eq!(rows.len(), 1, "one keyring_key_written row");
        assert_eq!(rows[0]["kind"], "keyring_key_written", "row kind");
        assert_eq!(rows[0]["key_purpose"], "nonce_hmac", "key purpose");
        assert!(
            rows[0].get("public_address").is_none(),
            "an HMAC-key rotation row carries no public address"
        );
    }
}
