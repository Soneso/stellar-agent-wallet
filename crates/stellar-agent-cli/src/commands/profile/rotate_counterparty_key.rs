//! `stellar-agent profile rotate-counterparty-key <name>` — rotate the
//! `stellar.toml` cache-integrity HMAC key.
//!
//! Generates 32 bytes from `OsRng`, encodes as URL-safe base64 (no padding),
//! and atomically replaces the keyring entry identified by
//! `profile.counterparty_cache_key_id`.
//!
//! # Impact on cached stellar.toml files
//!
//! The cache-integrity key is used to HMAC-protect each cached
//! `stellar.toml` response against post-fetch file-write tampering.
//! **After rotation, all cached
//! `stellar.toml` entries are immediately invalidated** because their stored
//! HMAC tags were computed with the old key.  The wallet will re-fetch
//! `stellar.toml` on the next counterparty-allowlist check.
//!
//! See `docs/runbooks/counterparty-cache-rotation.md` for operator guidance
//! on coordinating cache invalidation.
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
//!     "key_kind": "hmac_32_bytes",
//!     "cache_invalidated": true
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
use stellar_agent_core::audit_log::KeyPurpose;
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::{ValidationError, WalletError};
use stellar_agent_core::profile::loader;
use stellar_agent_network::keyring::init_platform_keyring_store;
use uuid::Uuid;

use crate::common::render;

use super::audit_emit::emit_keyring_key_written;
use super::key_ops::rotate_hmac_like_key;

/// Arguments for `stellar-agent profile rotate-counterparty-key`.
#[derive(Debug, Args)]
#[non_exhaustive]
pub(crate) struct RotateCounterpartyKeyArgs {
    /// The profile name whose counterparty cache-integrity key should be
    /// rotated.
    #[arg(value_name = "NAME")]
    pub(crate) name: String,
}

/// Success payload for the `rotate-counterparty-key` envelope.
#[derive(Debug, Serialize)]
struct RotateCounterpartyKeyData {
    /// Name of the profile whose counterparty key was rotated.
    profile: String,
    /// Always `true` on success.
    rotated: bool,
    /// Cryptographic primitive kind: `"hmac_32_bytes"` identifies the stored
    /// bytes as a 32-byte HMAC key (not an ed25519 seed).
    key_kind: &'static str,
    /// Indicates that all cached `stellar.toml` entries are now invalid.
    cache_invalidated: bool,
}

/// Runs `stellar-agent profile rotate-counterparty-key <name>`.
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
pub async fn run(args: &RotateCounterpartyKeyArgs) -> i32 {
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

    let entry_ref = &profile.counterparty_cache_key_id;
    match rotate_hmac_like_key(entry_ref, "rotate_counterparty_key") {
        Ok(()) => {
            let request_id = Uuid::new_v4().to_string();
            emit_keyring_key_written(
                &profile,
                &args.name,
                "profile_rotate_counterparty_key",
                KeyPurpose::CounterpartyCacheHmac,
                entry_ref,
                None,
                &request_id,
            );
            // Info-level log omits the keyring service name to avoid leaking it.
            // After HMAC key rotation the operator must re-fetch every cached
            // stellar.toml because the stored HMAC tags were computed under the
            // old key.
            tracing::info!(
                "after rotation, run `stellar-agent counterparty refresh <home-domain>` \
                 for each home domain you previously cached, OR delete the cache directory \
                 at ~/.local/state/stellar-agent/counterparty/<profile>/"
            );
            render::render_json(&Envelope::ok(RotateCounterpartyKeyData {
                profile: args.name.clone(),
                rotated: true,
                key_kind: "hmac_32_bytes",
                cache_invalidated: true,
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
    async fn rotate_counterparty_key_nonexistent_profile_returns_exit_1() {
        let args = RotateCounterpartyKeyArgs {
            name: "__nonexistent_rotate_counterparty_key__".to_owned(),
        };
        let code = run(&args).await;
        assert_eq!(code, 1);
    }
}
