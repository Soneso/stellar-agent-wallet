//! `stellar-agent profile rotate-nonce-key <name>` — rotate the HMAC nonce key.
//!
//! Generates 32 bytes from `OsRng`, encodes as URL-safe base64 (no padding),
//! and atomically replaces the keyring entry for the named profile's
//! `mcp_nonce_key_alias`.
//!
//! # Output
//!
//! On success:
//!
//! ```json
//! {
//!   "ok": true,
//!   "data": { "profile": "default", "rotated": true },
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
use stellar_agent_core::audit_log::KeyPurpose;
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::{InternalError, ValidationError, WalletError};
use stellar_agent_core::profile::loader;
use stellar_agent_network::keyring::init_platform_keyring_store;
use uuid::Uuid;

use crate::common::render;

use super::audit_emit::emit_keyring_key_written;

/// Arguments for `stellar-agent profile rotate-nonce-key`.
#[derive(Debug, Args)]
#[non_exhaustive]
pub(crate) struct RotateNonceKeyArgs {
    /// The profile name whose nonce key should be rotated.
    #[arg(value_name = "NAME")]
    pub(crate) name: String,
}

/// Success payload for the `rotate-nonce-key` envelope.
#[derive(Debug, Serialize)]
struct RotateNonceKeyData {
    /// Name of the profile whose nonce key was rotated.
    profile: String,
    /// Always `true` on success.
    rotated: bool,
}

/// Runs `stellar-agent profile rotate-nonce-key <name>`.
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
pub async fn run(args: &RotateNonceKeyArgs) -> i32 {
    // Initialise the platform keyring store first (required before any keyring
    // operation — matches the pattern established in the MCP server main).
    if let Err(e) = init_platform_keyring_store() {
        render::render_json(&Envelope::err(&e));
        return 1;
    }

    // Load the profile.
    let profile = match loader::load(&args.name, None) {
        Ok(p) => p,
        Err(loader::ProfileLoadError::NotFound { name, .. }) => {
            let err = WalletError::Validation(ValidationError::ProfileNotFound { name });
            render::render_json(&Envelope::err(&err));
            return 1;
        }
        Err(e) => {
            let err = WalletError::Internal(InternalError::UnexpectedState {
                detail: format!("failed to load profile '{}': {e}", args.name),
            });
            render::render_json(&Envelope::err(&err));
            return 1;
        }
    };

    // Rotate the nonce key.
    match stellar_agent_nonce::rotate_nonce_key(&profile) {
        Ok(()) => {
            let request_id = Uuid::new_v4().to_string();
            emit_keyring_key_written(
                &profile,
                &args.name,
                "profile_rotate_nonce_key",
                KeyPurpose::NonceHmac,
                &profile.mcp_nonce_key_alias,
                None,
                &request_id,
            );
            render::render_json(&Envelope::ok(RotateNonceKeyData {
                profile: args.name.clone(),
                rotated: true,
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

    // Defensive #[serial] — see enroll_signer.rs for full rationale; the
    // test binary observes a flaky race during parallel execution that
    // clobbers sibling #[serial] keyring tests' mock store.
    #[tokio::test]
    #[serial]
    async fn rotate_nonexistent_profile_returns_exit_1() {
        let args = RotateNonceKeyArgs {
            name: "__nonexistent_rotate_nonce_key__".to_owned(),
        };
        let code = run(&args).await;
        assert_eq!(code, 1);
    }
}
