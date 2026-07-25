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

use clap::{ArgGroup, Args};
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

/// Arguments for `stellar-agent profile rotate-attestation-key`.
#[derive(Debug, Args)]
#[non_exhaustive]
#[command(group(ArgGroup::new("profile_target").args(["name", "profile"]).required(true)))]
pub(crate) struct RotateAttestationKeyArgs {
    /// Profile name whose attestation key should be rotated, positional form.
    ///
    /// Exactly one of this positional `NAME` or the `--profile <NAME>` flag is
    /// required; supplying both, or neither, is a usage error.
    #[arg(value_name = "NAME")]
    pub(crate) name: Option<String>,

    /// Profile name whose attestation key should be rotated, flag form; an
    /// alternative to the positional `NAME`.
    ///
    /// Exactly one of the positional `NAME` or this `--profile <NAME>` flag is
    /// required; supplying both, or neither, is a usage error.
    #[arg(long, value_name = "NAME")]
    pub(crate) profile: Option<String>,
}

impl RotateAttestationKeyArgs {
    /// Returns the resolved profile name.
    ///
    /// The clap arg group over the positional `NAME` and `--profile` is
    /// `required` and mutually exclusive, so a parsed invocation sets exactly
    /// one of the two fields; this returns whichever was supplied.
    fn profile_name(&self) -> &str {
        self.name
            .as_deref()
            .or(self.profile.as_deref())
            .unwrap_or_default()
    }
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
    let profile = match loader::load(args.profile_name(), None) {
        Ok(p) => p,
        Err(loader::ProfileLoadError::NotFound { name, .. }) => {
            let err = WalletError::Validation(ValidationError::ProfileNotFound { name });
            render::render_json(&Envelope::err(&err));
            return 1;
        }
        Err(e) => {
            tracing::debug!(profile = %args.profile_name(), error = %e, "profile load failed");
            let err = WalletError::Validation(ValidationError::ProfileNotFound {
                name: args.profile_name().to_owned(),
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
            let request_id = Uuid::new_v4().to_string();
            emit_keyring_key_written(
                &profile,
                args.profile_name(),
                "profile_rotate_attestation_key",
                KeyPurpose::AttestationHmac,
                entry_ref,
                None,
                &request_id,
            );
            // Info-level log omits the keyring service name to avoid leaking it.
            tracing::info!("attestation key rotated; pending approvals are now invalid");
            render::render_json(&Envelope::ok(RotateAttestationKeyData {
                profile: args.profile_name().to_owned(),
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

    use clap::Parser;
    use clap::error::ErrorKind;
    use serial_test::serial;

    use super::*;

    /// Local flatten wrapper so the `RotateAttestationKeyArgs` clap contract
    /// can be parsed in isolation from the full command tree.
    #[derive(Debug, Parser)]
    struct Wrap {
        #[command(flatten)]
        args: RotateAttestationKeyArgs,
    }

    #[test]
    fn positional_name_is_accepted() {
        let w = Wrap::try_parse_from(["prog", "acme"]).expect("positional parses");
        assert_eq!(w.args.profile_name(), "acme");
    }

    #[test]
    fn profile_flag_is_accepted() {
        let w = Wrap::try_parse_from(["prog", "--profile", "acme"]).expect("flag parses");
        assert_eq!(w.args.profile_name(), "acme");
    }

    #[test]
    fn both_positional_and_flag_is_a_conflict() {
        let err = Wrap::try_parse_from(["prog", "acme", "--profile", "other"]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn neither_positional_nor_flag_is_missing_required() {
        let err = Wrap::try_parse_from(["prog"]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
    }

    // Defensive #[serial] — see enroll_signer.rs for full rationale; the
    // test binary observes a flaky race during parallel execution that
    // clobbers sibling #[serial] keyring tests' mock store.
    #[tokio::test]
    #[serial]
    async fn rotate_attestation_key_nonexistent_profile_returns_exit_1() {
        let args = RotateAttestationKeyArgs {
            name: Some("__nonexistent_rotate_attestation_key__".to_owned()),
            profile: None,
        };
        let code = run(&args).await;
        assert_eq!(code, 1);
    }
}
