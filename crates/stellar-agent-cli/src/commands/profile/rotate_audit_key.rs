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
//! root).  After rotation, new log files started by the wallet will use the
//! new key for their root signature.  Existing log files retain their chain
//! integrity — `stellar-agent audit verify` requires the key active at the
//! time each file was opened; archival verifiers must access the relevant key
//! snapshot from a secure key-history store (operator responsibility).
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
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::{ValidationError, WalletError};
use stellar_agent_core::profile::loader;
use stellar_agent_network::keyring::init_platform_keyring_store;

use crate::common::render;

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
    match rotate_hmac_like_key(entry_ref, "rotate_audit_key") {
        Ok(()) => {
            // Info-level log omits the keyring service name to avoid leaking it.
            tracing::info!("audit-log chain-root key rotated; new log files will use the new key");
            render::render_json(&Envelope::ok(RotateAuditKeyData {
                profile: args.name.clone(),
                rotated: true,
                key_kind: "hmac_32_bytes",
            }));
            0
        }
        Err(e) => {
            render::render_json(&Envelope::err(&e));
            1
        }
    }
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

    // Defensive #[serial] — see rotate_owner_key.rs for full rationale; the
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
}
