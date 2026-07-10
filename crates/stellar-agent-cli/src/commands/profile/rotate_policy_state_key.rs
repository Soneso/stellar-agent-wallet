//! `stellar-agent profile rotate-policy-state-key <name>` — rotate the
//! persisted policy-window-state HMAC key.
//!
//! Generates 32 bytes from `OsRng`, encodes as URL-safe base64 (no padding),
//! and atomically replaces the keyring entry identified by
//! `profile.policy_window_state_key_id`.
//!
//! # Impact on the window-state store
//!
//! The window-state store file (`<state>/stellar-agent/policy/<profile>.window`)
//! is HMAC-tagged under this key. Rotating it invalidates the existing file's
//! tag, so the command re-signs the store file with the new key —
//! re-computing the tag over the SAME body bytes, without needing the old
//! key — so the accumulated `per_period_cap` / `rate_limit` history is not
//! lost. This mirrors `rotate-audit-key`'s chain-root sidecar re-sign.
//!
//! Ordering is load-bearing: the store file's tag is verified under the OLD
//! key FIRST (before that key is destroyed), the new key is persisted to the
//! keyring SECOND, the store file is re-signed THIRD, and the audit row is
//! emitted FOURTH.
//!
//! # Tamper-laundering closure
//!
//! Re-signing recomputes the tag over whatever body bytes are currently on
//! disk WITHOUT requiring the old key (see [`PersistedWindowStore::resign`]).
//! That is exactly right for a legitimate rotation, but it means an
//! UNVERIFIED re-sign would silently launder a tampered file: an attacker who
//! edited the body (and could not forge a valid tag under the OLD key) could
//! wait for the next legitimate rotation to have their tampered body re-signed
//! under the NEW key, at which point it becomes indistinguishable from
//! genuine history. The pre-rotation verification step closes this: the
//! command reads the CURRENT store file and confirms its tag under the OLD
//! key BEFORE that key is destroyed. A mismatch aborts the rotation entirely
//! — the old key is never destroyed, and the command directs the operator to
//! `policy reset-window-state` instead (a tampered file cannot be recovered
//! by rotation; it can only be discarded). A store file that exists but whose
//! OLD key was never minted (no keyring entry at all) is equally refused: it
//! cannot have been signed by any legitimate key, so there is nothing to
//! verify it against.
//!
//! Re-signing before persisting the new key would leave the file signed by a
//! key the keyring no longer holds. If re-signing fails after the new key is
//! persisted, re-running the command converges: the re-sign step recomputes
//! the tag deterministically from the (unchanged) body bytes.
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
use stellar_agent_core::audit_log::KeyPurpose;
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::{ValidationError, WalletError};
use stellar_agent_core::profile::loader;
use stellar_agent_network::keyring::{init_platform_keyring_store, load_hmac_key_32};
use stellar_agent_network::policy_state::PersistedWindowStore;
use uuid::Uuid;

use crate::common::render;

use super::audit_emit::emit_keyring_key_written;
use super::key_ops::rotate_hmac_like_key;

/// Arguments for `stellar-agent profile rotate-policy-state-key`.
#[derive(Debug, Args)]
#[non_exhaustive]
pub(crate) struct RotatePolicyStateKeyArgs {
    /// The profile name whose policy-window-state key should be rotated.
    #[arg(value_name = "NAME")]
    pub(crate) name: String,
}

/// Success payload for the `rotate-policy-state-key` envelope.
#[derive(Debug, Serialize)]
struct RotatePolicyStateKeyData {
    /// Name of the profile whose policy-window-state key was rotated.
    profile: String,
    /// Always `true` on success.
    rotated: bool,
    /// Cryptographic primitive kind: `"hmac_32_bytes"` identifies the stored
    /// bytes as a 32-byte HMAC key (not an ed25519 seed).
    key_kind: &'static str,
}

/// Runs `stellar-agent profile rotate-policy-state-key <name>`.
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
pub async fn run(args: &RotatePolicyStateKeyArgs) -> i32 {
    // ── Step 0: load the profile FIRST so a nonexistent profile never
    // reaches the keyring init.
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

    if let Err(e) = init_platform_keyring_store() {
        render::render_json(&Envelope::err(&e));
        return 1;
    }

    let entry_ref = &profile.policy_window_state_key_id;
    let store = PersistedWindowStore::for_profile(&args.name);

    // ── Step 1: verify the store file's tag under the OLD key BEFORE that
    // key is destroyed — closes the tamper-laundering surface (see the
    // module docs). A store file that exists under an OLD key that was
    // never minted cannot be verified against anything and is refused too.
    match load_hmac_key_32(entry_ref) {
        Ok(old_key) => {
            if let Err(e) = store.verify_tag(&old_key) {
                tracing::error!(
                    error = ?e,
                    "policy-state key rotation refused: the store file did not verify under \
                     the current key; rotating would launder a tampered file — run \
                     `policy reset-window-state` instead"
                );
                let err = WalletError::Internal(
                    stellar_agent_core::error::InternalError::UnexpectedState {
                        detail: format!(
                            "policy_window_state.pre_rotation_verify_failed: {e}; the store \
                             file did not verify under the current key — rotation refused; \
                             run `profile reset-window-state {} --reason <reason>` to recover",
                            args.name
                        ),
                    },
                );
                render::render_json(&Envelope::err(&err));
                return 1;
            }
        }
        Err(_) if store.exists() => {
            // A store file exists but no key was ever minted for this
            // profile — it cannot have been signed legitimately.
            tracing::error!(
                "policy-state key rotation refused: a store file exists but no key was ever \
                 minted for this profile; run `policy reset-window-state` instead"
            );
            let err =
                WalletError::Internal(stellar_agent_core::error::InternalError::UnexpectedState {
                    detail: format!(
                        "policy_window_state.pre_rotation_verify_failed: store file exists \
                         with no minted key — rotation refused; run \
                         `profile reset-window-state {} --reason <reason>` to recover",
                        args.name
                    ),
                });
            render::render_json(&Envelope::err(&err));
            return 1;
        }
        Err(_) => {
            // No old key, no store file: genuinely the first-ever rotation
            // for this profile. Nothing to verify; proceed.
        }
    }

    // ── Step 2: persist the new key (destroys the old key).
    if let Err(e) = rotate_hmac_like_key(entry_ref, "rotate_policy_state_key") {
        render::render_json(&Envelope::err(&e));
        return 1;
    }

    // ── Step 3: re-sign the store file with the new key so the accumulated
    // window history is not lost. Rotation does not surface the generated
    // bytes, so read the new key back from the keyring.
    let new_key = match load_hmac_key_32(entry_ref) {
        Ok(k) => k,
        Err(e) => {
            tracing::error!(
                error = %e,
                "policy-state key rotated but could not be reloaded to re-sign the store; \
                 re-run rotate-policy-state-key to converge"
            );
            render::render_json(&Envelope::err(&e));
            return 1;
        }
    };
    let store = PersistedWindowStore::for_profile(&args.name);
    if let Err(e) = store.resign(&new_key) {
        tracing::error!(
            error = ?e,
            "policy-state key rotated but store re-sign failed; \
             re-run rotate-policy-state-key to converge"
        );
        let err =
            WalletError::Internal(stellar_agent_core::error::InternalError::UnexpectedState {
                detail: format!("policy_window_state.resign_failed: {e}"),
            });
        render::render_json(&Envelope::err(&err));
        return 1;
    }

    // ── Step 4: emit the KeyringKeyWritten row under the new key (non-fatal).
    let request_id = Uuid::new_v4().to_string();
    emit_keyring_key_written(
        &profile,
        &args.name,
        "profile_rotate_policy_state_key",
        KeyPurpose::PolicyWindowStateHmac,
        entry_ref,
        None,
        &request_id,
    );

    tracing::info!(
        "policy-window-state key rotated; the accumulated window-state store was re-signed \
         under the new key"
    );
    render::render_json(&Envelope::ok(RotatePolicyStateKeyData {
        profile: args.name.clone(),
        rotated: true,
        key_kind: "hmac_32_bytes",
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
    async fn rotate_policy_state_key_nonexistent_profile_returns_exit_1() {
        let args = RotatePolicyStateKeyArgs {
            name: "__nonexistent_rotate_policy_state_key__".to_owned(),
        };
        let code = run(&args).await;
        assert_eq!(code, 1);
    }
}
