//! Shared audit emission for profile key-writing commands.
//!
//! Each profile command that writes long-lived key material to the platform
//! keyring records a `KeyringKeyWritten` row after the write succeeds. Emission
//! is non-fatal: the key write has already committed, so a row-write failure
//! logs a warning and never changes the command's outcome or exit code. The row
//! records only WHICH key slot was written, its keyring coordinates, and — for
//! the two enroll commands — a redacted public address. It NEVER carries a key
//! value, seed, base64 key material, or any derived secret.

use stellar_agent_network::keyring::keyed_audit_access;
use zeroize::Zeroizing;

use stellar_agent_core::audit_log::{AuditEntry, AuditWriter, AuditWriterRegistry, KeyPurpose};
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
    let access = match keyed_audit_access(profile) {
        Ok(access) => access,
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
        match AuditWriterRegistry::get_or_open_keyed(profile_name, &profile.audit_log_path, access)
        {
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

    match writer_arc.lock() {
        Ok(mut guard) => emit_keyring_key_written_with_writer(
            &mut guard,
            profile_name,
            tool,
            key_purpose,
            written_entry,
            public_address,
            request_id,
        ),
        Err(_) => {
            tracing::warn!(
                profile = %profile_name,
                "key write audit: audit writer mutex poisoned; KeyringKeyWritten NOT emitted"
            );
        }
    }
}

/// Emits the `KeyringKeyWritten` row through a writer the caller already holds.
///
/// `rotate-audit-key` holds the audit writer across its whole sequence so no
/// other process can append or rotate while the per-file chain-root sidecars are
/// being re-signed. It appends the row through this function rather than through
/// [`emit_keyring_key_written`], which would try to acquire the same writer and
/// deadlock on the lock the caller is holding.
///
/// Non-fatal, like its acquiring twin: the key write has already committed.
pub(super) fn emit_keyring_key_written_with_writer(
    writer: &mut AuditWriter,
    profile_name: &str,
    tool: &str,
    key_purpose: KeyPurpose,
    written_entry: &KeyringEntryRef,
    public_address: Option<RedactedStrkey>,
    request_id: &str,
) {
    let entry = AuditEntry::new_keyring_key_written(
        tool,
        key_purpose,
        written_entry.service.clone(),
        written_entry.account.clone(),
        public_address,
        request_id,
    );
    if let Err(e) = writer.write_entry(entry) {
        tracing::warn!(
            profile = %profile_name,
            error = %e,
            "key write audit: write_entry failed; KeyringKeyWritten NOT emitted"
        );
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

    /// A key-write row advances the tip anchor.
    ///
    /// This surface opens its writer KEYED, so its rows are ones `audit verify`
    /// covers — and, before the keyed open was made to carry the anchor store,
    /// ones the anchor never counted. Removing such a row left the file back at
    /// the anchored tip and every later check read Current, so the removal was
    /// undetectable.
    #[test]
    #[serial]
    fn a_key_write_row_advances_the_tip_anchor() {
        use stellar_agent_core::audit_log::TipAnchorStore as _;
        use stellar_agent_network::keyring::KeyringTipAnchorStore;

        keyring_mock::install().expect("mock keyring store");

        let dir = tempfile::tempdir().expect("tmp dir");
        let mut profile =
            Profile::builder_testnet("anchor-keywrite", "acct", "n-svc", "n-acct").build();
        profile.audit_log_path = dir.path().join("audit.jsonl");
        let coord = profile.audit_log_hash_chain_key_id.clone();
        stellar_agent_network::keyring::rotate_keyring_secret_32(&coord.service, &coord.account)
            .expect("seed audit key");

        let store = KeyringTipAnchorStore::new(&coord, &profile.audit_log_path);
        assert_eq!(
            store.load_anchor().expect("read anchor"),
            None,
            "nothing is anchored before the first row"
        );

        emit_keyring_key_written(
            &profile,
            "anchor-keywrite",
            "profile_rotate_attestation_key",
            KeyPurpose::AttestationHmac,
            &coord,
            None,
            "req-anchor-keywrite",
        );

        let anchored = store
            .load_anchor()
            .expect("read anchor")
            .expect("the row must be anchored");
        assert_eq!(anchored.entry_count, 1, "the row advanced the anchor");
        assert_eq!(
            anchored.end_offset,
            std::fs::metadata(&profile.audit_log_path)
                .expect("log exists")
                .len(),
            "the anchor names the end of the row just written"
        );
    }

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
