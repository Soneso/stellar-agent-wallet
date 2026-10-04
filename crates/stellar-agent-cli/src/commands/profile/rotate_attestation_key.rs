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
use stellar_agent_core::approval::attest::ATTESTATION_KEY_FIELD;
use stellar_agent_core::audit_log::KeyPurpose;
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::WalletError;
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_core::profile::{ResolvedProfileName, loader, owner_key};
use stellar_agent_network::keyring::init_platform_keyring_store;
use uuid::Uuid;

use crate::common::profile_access::{
    injected_profile_load, profile_access_envelope, reconcile_loaded_profile,
};
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
    pub(super) fn profile_name(&self) -> &str {
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
    run_with_dependencies(args, injected_profile_load, init_platform_keyring_store).await
}

/// Testable core of [`run`] with the profile loader and the platform-keyring
/// initialiser injected.
///
/// Production callers use [`run`], which supplies the real profile loader and
/// [`init_platform_keyring_store`]. Tests substitute an in-memory profile and
/// a spy initialiser over a mock keyring store.
async fn run_with_dependencies<LoadProfile, InitKeyring>(
    args: &RotateAttestationKeyArgs,
    load_profile: LoadProfile,
    init_keyring: InitKeyring,
) -> i32
where
    LoadProfile: FnOnce(&str) -> Result<Profile, loader::ProfileLoadError>,
    InitKeyring: FnOnce() -> Result<(), WalletError>,
{
    // ── Step 1: load the profile FIRST so a nonexistent profile never reaches
    // the keyring init.  Eliminates the process-global keyring-store race.
    // Reconciled in the CALLER of the injected loader: a check inside the
    // closure would be bypassed by every test that supplies its own.
    let profile = match reconcile_loaded_profile(
        load_profile(args.profile_name()),
        &ResolvedProfileName::from_flag(args.profile_name()),
    ) {
        Ok(p) => p,
        Err(e) => {
            tracing::debug!(profile = %args.profile_name(), error = %e, "profile access refused");
            render::render_json(&profile_access_envelope(&e, args.profile_name()));
            return 1;
        }
    };

    // ── Step 2: a coordinate in the owner key namespace refuses before the
    // keyring opens, so the rotation never writes over an owner entry.
    let entry_ref = &profile.attestation_key_id;
    if let Err(e) = owner_key::refuse_owner_key_coordinate(entry_ref, ATTESTATION_KEY_FIELD) {
        render::render_json(&Envelope::err(&e));
        return 1;
    }

    // ── Step 3: initialise the platform keyring store.
    if let Err(e) = init_keyring() {
        render::render_json(&Envelope::err(&e));
        return 1;
    }

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

    /// An attestation-key coordinate in the owner key namespace refuses
    /// before the keyring opens, and the owner entry is not overwritten.
    #[tokio::test]
    #[serial]
    async fn an_owner_namespace_coordinate_refuses_the_rotation() {
        use stellar_agent_core::profile::schema::KeyringEntryRef;

        stellar_agent_test_support::keyring_mock::install().unwrap();
        let name = "rotate-attestation-owner";
        let owner = KeyringEntryRef::default_owner_key(name);
        let owner_value = owner_key::encode_owner_public_key(&[0x5b; 32]);
        keyring_core::Entry::new(&owner.service, &owner.account)
            .unwrap()
            .set_password(&owner_value)
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut profile = Profile::builder_testnet_named(name, "s", "a", "n", "a").build();
        profile.audit_log_path = dir.path().join("audit.jsonl");
        profile.attestation_key_id = owner.clone();

        let args = RotateAttestationKeyArgs {
            name: Some(name.to_owned()),
            profile: None,
        };
        let init_calls = std::cell::Cell::new(0_u32);
        let code = run_with_dependencies(
            &args,
            move |_name| Ok(profile),
            || {
                init_calls.set(init_calls.get() + 1);
                Ok(())
            },
        )
        .await;
        assert!(
            keyring_core::Entry::new(&owner.service, &owner.account)
                .unwrap()
                .get_password()
                .ok()
                == Some(owner_value),
            "the owner entry is not overwritten"
        );
        assert_eq!(init_calls.get(), 0, "the refusal precedes the keyring");
        assert_eq!(code, 1);
    }
}
