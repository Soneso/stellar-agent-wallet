//! `stellar-agent profile rotate-attestation-key <name>` — rotate the
//! wallet-owned approval spine attestation HMAC key.
//!
//! Generates 32 bytes from `OsRng`, encodes as URL-safe base64 (no padding),
//! and atomically replaces the keyring entry identified by
//! `profile.attestation_key_id`.
//!
//! # Impact on pending approvals
//!
//! Rotation changes the HMAC key used to sign attestation blobs at
//! `stellar-agent approve` time.  **All pending approvals are immediately
//! invalidated** — any `attestation_blob` produced with the old key fails
//! HMAC verify at commit time, returning `policy.approval_required`.  The
//! operator (or the issuing agent) must re-initiate the simulation + approval
//! round trip.
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

/// Arguments for `stellar-agent profile rotate-attestation-key`.
#[derive(Debug, Args)]
#[non_exhaustive]
pub(crate) struct RotateAttestationKeyArgs {
    /// The profile name whose attestation key should be rotated.
    #[arg(value_name = "NAME")]
    pub(crate) name: String,
}

/// Success payload for the `rotate-attestation-key` envelope.
#[derive(Debug, Serialize)]
struct RotateAttestationKeyData {
    /// Name of the profile whose attestation key was rotated.
    profile: String,
    /// Always `true` on success.
    rotated: bool,
    /// Cryptographic primitive kind: `"hmac_32_bytes"` identifies the stored
    /// bytes as a 32-byte HMAC key (not an ed25519 seed).
    key_kind: &'static str,
}

/// Runs `stellar-agent profile rotate-attestation-key <name>`.
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
pub async fn run(args: &RotateAttestationKeyArgs) -> i32 {
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

    let entry_ref = &profile.attestation_key_id;
    match rotate_hmac_like_key(entry_ref, "rotate_attestation_key") {
        Ok(()) => {
            // Info-level log omits the keyring service name to avoid leaking it.
            tracing::info!("attestation key rotated; pending approvals are now invalid");
            render::render_json(&Envelope::ok(RotateAttestationKeyData {
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
    async fn rotate_attestation_key_nonexistent_profile_returns_exit_1() {
        let args = RotateAttestationKeyArgs {
            name: "__nonexistent_rotate_attestation_key__".to_owned(),
        };
        let code = run(&args).await;
        assert_eq!(code, 1);
    }
}
