//! `stellar-agent profile rotate-owner-key <name>` — rotate the policy-file
//! owner ed25519 seed.
//!
//! Generates a fresh ed25519 signing key via `SigningKey::generate(&mut OsRng)`,
//! extracts the 32-byte seed, encodes it as URL-safe base64 (no padding), and
//! atomically replaces the keyring entry identified by
//! `profile.policy_owner_key_id`.
//!
//! The stored value is an RFC 8032 §5.1.5 ed25519 seed.  The policy engine
//! reconstructs the signing key via
//! `ed25519_dalek::SigningKey::from_bytes(&decoded_seed)`.
//!
//! # Impact on outstanding policy files
//!
//! Rotation changes the owner ed25519 key used to verify policy-file
//! signatures.  **Any policy file signed by the old owner key is rejected on
//! next load** (returns `policy.owner_signature_invalid`).  The operator must
//! re-sign all policy files with the new key before re-enabling the policy
//! engine.
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
//!     "key_kind": "ed25519_seed"
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

use super::key_ops::rotate_ed25519_seed;

/// Arguments for `stellar-agent profile rotate-owner-key`.
#[derive(Debug, Args)]
#[non_exhaustive]
pub(crate) struct RotateOwnerKeyArgs {
    /// The profile name whose owner key should be rotated.
    #[arg(value_name = "NAME")]
    pub(crate) name: String,
}

/// Success payload for the `rotate-owner-key` envelope.
#[derive(Debug, Serialize)]
struct RotateOwnerKeyData {
    /// Name of the profile whose owner key was rotated.
    profile: String,
    /// Always `true` on success.
    rotated: bool,
    /// Cryptographic primitive kind: `"ed25519_seed"` identifies the stored
    /// bytes as an RFC 8032 ed25519 seed for use with
    /// `ed25519_dalek::SigningKey::from_bytes`.
    key_kind: &'static str,
}

/// Runs `stellar-agent profile rotate-owner-key <name>`.
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
pub async fn run(args: &RotateOwnerKeyArgs) -> i32 {
    // ── Step 1: load the profile FIRST so a nonexistent profile never reaches
    // the keyring init.  This eliminates the process-global keyring-store race
    // that would occur if init_platform_keyring_store ran before the profile
    // check.
    let profile = match loader::load(&args.name, None) {
        Ok(p) => p,
        Err(loader::ProfileLoadError::NotFound { name, .. }) => {
            let err = WalletError::Validation(ValidationError::ProfileNotFound { name });
            render::render_json(&Envelope::err(&err));
            return 1;
        }
        Err(e) => {
            // Route the load error through a typed variant that does not
            // interpolate the absolute path into the error detail.
            tracing::debug!(profile = %args.name, error = %e, "profile load failed");
            let err = WalletError::Validation(ValidationError::ProfileNotFound {
                name: args.name.clone(),
            });
            render::render_json(&Envelope::err(&err));
            return 1;
        }
    };

    // ── Step 2: initialise the platform keyring store after a successful
    // profile load.
    if let Err(e) = init_platform_keyring_store() {
        render::render_json(&Envelope::err(&e));
        return 1;
    }

    let entry_ref = &profile.policy_owner_key_id;
    match rotate_ed25519_seed(entry_ref, "rotate_owner_key") {
        Ok(()) => {
            // Info-level log omits the keyring service name to avoid leaking it;
            // operator forensics are available at debug level inside
            // rotate_ed25519_seed.
            tracing::info!("owner key rotated; policy files signed by old key are now invalid");
            render::render_json(&Envelope::ok(RotateOwnerKeyData {
                profile: args.name.clone(),
                rotated: true,
                key_kind: "ed25519_seed",
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

    // Even though `run()` early-exits on `ProfileNotFound` before
    // `init_platform_keyring_store()`, the test binary observes a flaky race
    // (~1 in 30 runs) where an `Arc<CredentialStore>` swap during parallel
    // execution clobbers a sibling `#[serial]` test's mock store, surfacing as
    // `Auth(KeyringNotFound)` for the sibling.  Serialising defensively
    // eliminates the cross-test interference at trivial cost (this test
    // returns in milliseconds).
    #[tokio::test]
    #[serial]
    async fn rotate_owner_key_nonexistent_profile_returns_exit_1() {
        let args = RotateOwnerKeyArgs {
            name: "__nonexistent_rotate_owner_key__".to_owned(),
        };
        let code = run(&args).await;
        assert_eq!(code, 1);
    }
}
