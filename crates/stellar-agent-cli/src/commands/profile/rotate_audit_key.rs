//! `stellar-agent profile rotate-audit-key <name>` — rotate the hash-chained
//! audit-log chain-root HMAC key.
//!
//! Generates 32 bytes from `OsRng`, encodes as URL-safe base64 (no padding),
//! and atomically replaces the keyring entry identified by
//! `profile.audit_log_hash_chain_key_id`.
//!
//! # Impact on the audit log
//!
//! The chain-root key signs the **first** entry per audit-log file (the chain
//! root); the entry-to-entry chain is key-independent.  Rotation therefore
//! re-signs every existing file's chain-root sidecar with the new key so that
//! `stellar-agent audit verify` under the new key stays green over the entire
//! log — pre-rotation entries and the new `KeyringKeyWritten` row alike.  The
//! old key is destroyed by the rotation; only the new key verifies afterward.
//!
//! Ordering is load-bearing: the new key is persisted to the keyring FIRST, the
//! sidecars are re-signed SECOND, and the audit row is emitted THIRD.  Re-signing
//! before persisting would leave sidecars signed by a key the keyring no longer
//! holds.  If re-signing fails partway (some sidecars carry the new key, some the
//! old), re-running the command converges: the re-sign step recomputes every
//! sidecar deterministically.
//!
//! See `docs/runbooks/profile-migration.md` for operator guidance on key
//! rotation scheduling.
//!
//! # Output (JSON envelope)
//!
//! On success:
//!
//! ```json
//! {
//!   "ok": true,
//!   "data": {
//!     "profile": "default",
//!     "rotated": true,
//!     "key_kind": "hmac_32_bytes"
//!   },
//!   "request_id": "..."
//! }
//! ```
//!
//! # Errors
//!
//! Returns exit code `1` when the profile cannot be loaded or the keyring
//! operation fails.

use clap::Args;
use serde::Serialize;
use stellar_agent_core::audit_log::{KeyPurpose, SidecarResignError, resign_chain_root_sidecars};
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::{InternalError, ValidationError, WalletError};
use stellar_agent_core::profile::loader;
use stellar_agent_network::keyring::init_platform_keyring_store;
use uuid::Uuid;

use crate::common::render;

use super::audit_emit::{emit_keyring_key_written, load_audit_hmac_key};
use super::key_ops::rotate_hmac_like_key;

/// Arguments for `stellar-agent profile rotate-audit-key`.
#[derive(Debug, Args)]
#[non_exhaustive]
pub(crate) struct RotateAuditKeyArgs {
    /// The profile name whose audit-log chain-root key should be rotated.
    #[arg(value_name = "NAME")]
    pub(crate) name: String,
}

/// Success payload for the `rotate-audit-key` envelope.
#[derive(Debug, Serialize)]
struct RotateAuditKeyData {
    /// Name of the profile whose audit key was rotated.
    profile: String,
    /// Always `true` on success.
    rotated: bool,
    /// Cryptographic primitive kind: `"hmac_32_bytes"` identifies the stored
    /// bytes as a 32-byte HMAC key (not an ed25519 seed).
    key_kind: &'static str,
    /// Number of per-file chain-root sidecars re-signed with the new key.
    sidecars_resigned: usize,
}

/// Maps a re-sign failure to an operator-actionable error stating that the key
/// rotated but the log is not yet verifiable under it, and a re-run converges.
fn resign_failure_error(e: &SidecarResignError) -> WalletError {
    WalletError::Internal(InternalError::UnexpectedState {
        detail: format!(
            "audit.resign_incomplete: audit key rotated but chain-root re-sign failed ({e}); \
             re-run rotate-audit-key to converge"
        ),
    })
}

/// Runs `stellar-agent profile rotate-audit-key <name>`.
///
/// Returns `0` on success, `1` on error.
///
/// # Errors
///
/// Never returns `Err` — errors are captured into the exit code.
///
/// # Panics
///
/// Never panics.
pub async fn run(args: &RotateAuditKeyArgs) -> i32 {
    // ── Step 1: load the profile FIRST so a nonexistent profile never reaches
    // the keyring init.  Eliminates the process-global keyring-store race.
    let profile = match loader::load(&args.name, None) {
        Ok(p) => p,
        Err(loader::ProfileLoadError::NotFound { name, .. }) => {
            let err = WalletError::Validation(ValidationError::ProfileNotFound { name });
            render::render_json(&Envelope::err(&err));
            return 1;
        }
        Err(e) => {
            tracing::debug!(profile = %args.name, error = %e, "profile load failed");
            let err = WalletError::Validation(ValidationError::ProfileNotFound {
                name: args.name.clone(),
            });
            render::render_json(&Envelope::err(&err));
            return 1;
        }
    };

    // ── Step 2: initialise the platform keyring store.
    if let Err(e) = init_platform_keyring_store() {
        render::render_json(&Envelope::err(&e));
        return 1;
    }

    let entry_ref = &profile.audit_log_hash_chain_key_id;

    // ── Step 1: persist the new chain-root key (destroys the old key).
    if let Err(e) = rotate_hmac_like_key(entry_ref, "rotate_audit_key") {
        render::render_json(&Envelope::err(&e));
        return 1;
    }

    // ── Step 2: re-sign every existing per-file chain-root sidecar with the new
    // key so `audit verify` under the new key stays green.  Rotation does not
    // surface the generated bytes, so read the new key back from the keyring.
    let new_key = match load_audit_hmac_key(&profile) {
        Ok(k) => k,
        Err(e) => {
            tracing::error!(
                error = %e,
                "audit key rotated but could not be reloaded to re-sign sidecars; \
                 re-run rotate-audit-key to converge"
            );
            render::render_json(&Envelope::err(&e));
            return 1;
        }
    };
    let sidecars_resigned = match resign_chain_root_sidecars(&profile.audit_log_path, &new_key) {
        Ok(n) => n,
        Err(e) => {
            tracing::error!(
                error = %e,
                "audit key rotated but chain-root re-sign failed; \
                 re-run rotate-audit-key to converge"
            );
            render::render_json(&Envelope::err(&resign_failure_error(&e)));
            return 1;
        }
    };

    // ── Step 3: emit the KeyringKeyWritten row under the new key (non-fatal).
    let request_id = Uuid::new_v4().to_string();
    emit_keyring_key_written(
        &profile,
        &args.name,
        "profile_rotate_audit_key",
        KeyPurpose::AuditHashChainHmac,
        entry_ref,
        None,
        &request_id,
    );

    // Info-level log omits the keyring service name to avoid leaking it.
    tracing::info!("audit-log chain-root key rotated; chain-root sidecars re-signed under new key");
    render::render_json(&Envelope::ok(RotateAuditKeyData {
        profile: args.name.clone(),
        rotated: true,
        key_kind: "hmac_32_bytes",
        sidecars_resigned,
    }));
    0
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use serial_test::serial;

    use super::*;

    // Defensive #[serial] — see enroll_signer.rs for full rationale; the
    // test binary observes a flaky race during parallel execution that
    // clobbers sibling #[serial] keyring tests' mock store.
    #[tokio::test]
    #[serial]
    async fn rotate_audit_key_nonexistent_profile_returns_exit_1() {
        let args = RotateAuditKeyArgs {
            name: "__nonexistent_rotate_audit_key__".to_owned(),
        };
        let code = run(&args).await;
        assert_eq!(code, 1);
    }

    /// End-to-end coverage of the rotation orchestration `run` performs after
    /// the profile load and platform-store init (which need on-disk profile
    /// persistence and the real OS keychain, so are exercised separately): the
    /// load-bearing Step 1-3 sequence against a mock keyring and real audit-log
    /// files.
    ///
    /// Drives persist-before-resign in order — rotate the key, re-sign the
    /// sidecars under the freshly loaded new key, emit the `KeyringKeyWritten`
    /// row — then asserts the whole log (pre-rotation entries AND the new row)
    /// verifies green under the NEW key, the OLD key no longer verifies, and the
    /// key-write row is present. Emitting before the re-sign, or re-signing
    /// before persisting, would break one of these assertions.
    #[test]
    #[serial]
    fn rotate_audit_key_resign_keeps_verify_green_under_new_key_and_emits_row() {
        use std::io::BufRead as _;

        use stellar_agent_core::audit_log::{AuditEntry, AuditWriter, PolicyDecision, verify_log};
        use stellar_agent_core::profile::schema::Profile;
        use stellar_agent_test_support::keyring_mock;

        keyring_mock::install().expect("mock keyring store");

        let dir = tempfile::tempdir().expect("tmp dir");
        let mut profile = Profile::builder_testnet("rotate-e2e", "acct", "n-svc", "n-acct").build();
        profile.audit_log_path = dir.path().join("audit.jsonl");
        let entry_ref = profile.audit_log_hash_chain_key_id.clone();

        // Seed the OLD chain-root key and write a pre-rotation chain under it.
        rotate_hmac_like_key(&entry_ref, "test_seed").expect("seed old key");
        let old_key = load_audit_hmac_key(&profile).expect("load old key");
        {
            let mut writer =
                AuditWriter::open(profile.audit_log_path.clone(), Some(old_key.clone()))
                    .expect("open under old key");
            for ledger in 0..2u32 {
                let entry = AuditEntry::new_value_action_submitted(
                    "stellar_pay",
                    "stellar:testnet",
                    Vec::new(),
                    "abcd1234…wxyz5678",
                    ledger,
                    PolicyDecision::Allow,
                    None,
                    None,
                    "req-pre",
                );
                writer.write_entry(entry).expect("write pre-rotation entry");
            }
        }
        assert!(
            verify_log(&profile.audit_log_path, Some(&old_key))
                .expect("verify old")
                .hmac_verified,
            "pre-rotation log must verify under the old key"
        );

        // Step 1: persist the new key (destroys the old). Step 2: re-sign the
        // sidecars under the freshly loaded new key. Step 3: emit the row.
        rotate_hmac_like_key(&entry_ref, "rotate_audit_key").expect("rotate to new key");
        let new_key = load_audit_hmac_key(&profile).expect("load new key");
        let resigned = resign_chain_root_sidecars(&profile.audit_log_path, &new_key)
            .expect("re-sign sidecars");
        assert!(resigned >= 1, "at least one sidecar must be re-signed");
        emit_keyring_key_written(
            &profile,
            "rotate-e2e",
            "profile_rotate_audit_key",
            KeyPurpose::AuditHashChainHmac,
            &entry_ref,
            None,
            "req-rotate",
        );

        assert!(
            verify_log(&profile.audit_log_path, Some(&new_key))
                .expect("verify new")
                .hmac_verified,
            "the whole log must verify under the new key after re-sign + emit"
        );
        assert!(
            verify_log(&profile.audit_log_path, Some(&old_key)).is_err(),
            "the old key must no longer verify after rotation"
        );

        let file = std::fs::File::open(&profile.audit_log_path).expect("log exists");
        let has_key_row = std::io::BufReader::new(file).lines().any(|line| {
            let value: serde_json::Value =
                serde_json::from_str(&line.expect("line")).expect("valid JSON row");
            value["kind"] == "keyring_key_written"
                && value["key_purpose"] == "audit_hash_chain_hmac"
        });
        assert!(
            has_key_row,
            "a keyring_key_written row must be present under the new key"
        );
    }
}
