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

use std::sync::{Arc, Mutex};

use stellar_agent_core::audit_log::{AuditEntry, AuditWriter, AuditWriterRegistry};
use stellar_agent_core::profile::schema::Profile;

use crate::commands::profile::audit_emit::load_audit_hmac_key;

/// Acquires the per-profile audit writer opened under the profile's audit
/// chain-root HMAC key, for callers that write the row themselves later (the
/// DeFi adapters emit inside their submit Ok arm).
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
/// (e.g. [`stellar_agent_core::audit_log::AuditEntry::new_value_action_submitted`]).
/// Constructs and emits the allow-path `value_action_submitted` row for a
/// confirmed CLI submit: the SAME legs the policy gate sized
/// (single-derivation invariant), the redacted transaction hash, and the
/// confirmed ledger. Non-fatal, via [`emit_value_audit_row`].
pub(crate) fn emit_value_action_submitted_row(
    profile: &Profile,
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
    emit_value_audit_row(profile, profile_name, entry);
}

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
}
