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
use stellar_agent_core::profile::schema::Profile;
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
    run_with_dependencies(
        args,
        |name| loader::load(name, None),
        init_platform_keyring_store,
    )
    .await
}

/// Testable core of [`run`] with the profile loader and the platform-keyring
/// initialiser injected.
///
/// Production callers use [`run`], which supplies the real profile loader and
/// [`init_platform_keyring_store`]. Tests substitute an in-memory profile
/// (backed by a temp-dir audit log) and a spy initialiser so the rotate →
/// re-sign → emit sequence can be exercised against a mock keyring store
/// without touching the OS keychain or a persisted profile file.
async fn run_with_dependencies<LoadProfile, InitKeyring>(
    args: &RotateAuditKeyArgs,
    load_profile: LoadProfile,
    init_keyring: InitKeyring,
) -> i32
where
    LoadProfile: Fn(&str) -> Result<Profile, loader::ProfileLoadError>,
    InitKeyring: Fn() -> Result<(), WalletError>,
{
    // ── Setup A: load the profile FIRST so a nonexistent profile never reaches
    // the keyring init.  Eliminates the process-global keyring-store race.
    let profile = match load_profile(&args.name) {
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

    // ── Setup B: initialise the platform keyring store.
    if let Err(e) = init_keyring() {
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

    /// End-to-end coverage of the rotation orchestration [`run_with_dependencies`]
    /// performs, driven through the real function itself (not a parallel
    /// reimplementation of its steps) with an in-memory profile, a spy keyring
    /// initialiser, a mock keyring store, and real audit-log files.
    ///
    /// Seeds an OLD chain-root key and a pre-rotation chain under it, then
    /// invokes `run_with_dependencies`, and asserts the whole log (pre-rotation
    /// entries AND the new `KeyringKeyWritten` row) verifies green under the NEW
    /// key read back from the keyring afterward, and the OLD key no longer
    /// verifies. Because the test calls the production function directly rather
    /// than re-executing its persist/re-sign/emit steps inline, reordering
    /// `run_with_dependencies`'s internal Step 1 (persist) / Step 2 (re-sign) /
    /// Step 3 (emit) sequence turns this test red: emitting before persisting
    /// the new key would leave the keyring holding an unresigned old key and
    /// `load_audit_hmac_key` would read back the stale key, or re-signing before
    /// persisting would sign sidecars with a key already destroyed.
    #[tokio::test]
    #[serial]
    async fn rotate_audit_key_run_resign_keeps_verify_green_under_new_key_and_emits_row() {
        use std::io::BufRead as _;

        use stellar_agent_core::audit_log::{AuditEntry, AuditWriter, PolicyDecision, verify_log};
        use stellar_agent_test_support::keyring_mock;

        keyring_mock::install().expect("mock keyring store");

        let dir = tempfile::tempdir().expect("tmp dir");
        let mut profile =
            Profile::builder_testnet("rotate-run-e2e", "acct", "n-svc", "n-acct").build();
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

        let args = RotateAuditKeyArgs {
            name: "rotate-run-e2e".to_owned(),
        };
        let cloned_profile = profile.clone();
        let code =
            run_with_dependencies(&args, move |_name| Ok(cloned_profile.clone()), || Ok(())).await;
        assert_eq!(code, 0, "run_with_dependencies must succeed");

        let new_key = load_audit_hmac_key(&profile).expect("load new key after rotation");
        assert_ne!(
            *new_key, *old_key,
            "rotation must replace the chain-root key"
        );

        assert!(
            verify_log(&profile.audit_log_path, Some(&new_key))
                .expect("verify new")
                .hmac_verified,
            "the whole log must verify under the new key after run_with_dependencies"
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
