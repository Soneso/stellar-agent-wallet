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
//! key before rotation. A mismatch aborts rotation and preserves the old key.
//! No verb recovers such state in this release; create a profile under a new name.
//! A missing key beside an existing file also refuses. The scope check requires
//! authenticated provenance, including a matching protected generation.
//!
//! The new key is persisted to the keyring before the store file is re-signed
//! so the keyring holds the key used for signing. A re-signing failure after
//! persistence leaves a file the new key does not authenticate, so the next
//! rotation refuses it.
//! No verb recovers such state in this release; create a profile under a new name.
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
use stellar_agent_core::error::WalletError;
use stellar_agent_core::profile::owner_key;
use stellar_agent_core::profile::{Profile, ResolvedProfileName, loader};
use stellar_agent_network::keyring::{init_platform_keyring_store, load_hmac_key_32};
use stellar_agent_network::policy_state::{POLICY_STATE_KEY_FIELD, PersistedWindowStore};
use uuid::Uuid;

use crate::common::profile_access::{
    injected_profile_load, profile_access_envelope, reconcile_loaded_profile,
};
use crate::common::render;

use super::audit_emit::emit_keyring_key_written;
use super::key_ops::rotate_hmac_like_key;

/// Arguments for `stellar-agent profile rotate-policy-state-key`.
#[derive(Debug, Args)]
#[non_exhaustive]
#[command(group(ArgGroup::new("profile_target").args(["name", "profile"]).required(true)))]
pub(crate) struct RotatePolicyStateKeyArgs {
    /// Profile name whose policy-window-state key should be rotated, positional
    /// form.
    ///
    /// Exactly one of this positional `NAME` or the `--profile <NAME>` flag is
    /// required; supplying both, or neither, is a usage error.
    #[arg(value_name = "NAME")]
    pub(crate) name: Option<String>,

    /// Profile name whose policy-window-state key should be rotated, flag form;
    /// an alternative to the positional `NAME`.
    ///
    /// Exactly one of the positional `NAME` or this `--profile <NAME>` flag is
    /// required; supplying both, or neither, is a usage error.
    #[arg(long, value_name = "NAME")]
    pub(crate) profile: Option<String>,
}

impl RotatePolicyStateKeyArgs {
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
    run_with_dependencies(args, injected_profile_load, init_platform_keyring_store).await
}

/// Runs the rotation with profile loading and keyring initialization supplied.
async fn run_with_dependencies(
    args: &RotatePolicyStateKeyArgs,
    load_profile: impl FnOnce(&str) -> Result<Profile, loader::ProfileLoadError>,
    init_keyring: impl FnOnce() -> Result<(), WalletError>,
) -> i32 {
    // ── Step 0: load the profile FIRST so a nonexistent profile never
    // reaches the keyring init.
    let profile = match reconcile_loaded_profile(
        load_profile(args.profile_name()),
        &ResolvedProfileName::from_flag(args.profile_name()),
    ) {
        Ok(p) => p,
        Err(e) => {
            tracing::debug!(error = %e, "profile access refused");
            render::render_json(&profile_access_envelope(&e));
            return 1;
        }
    };

    if let Err(e) = owner_key::refuse_installation_key_coordinate(
        &profile.policy_window_state_key_id,
        POLICY_STATE_KEY_FIELD,
    ) {
        render::render_json(&Envelope::err(&e));
        return 1;
    }

    if let Err(e) = init_keyring() {
        render::render_json(&Envelope::err(&e));
        return 1;
    }

    let entry_ref = &profile.policy_window_state_key_id;
    let store = PersistedWindowStore::for_profile(args.profile_name());

    // ── Step 1: verify the store file's tag under the OLD key BEFORE that
    // key is destroyed — closes the tamper-laundering surface (see the
    // module docs). A store file that exists under an OLD key that was
    // never minted cannot be verified against anything and is refused too.
    // An owner refusal rotates nothing, so the owner entry is never
    // overwritten.
    let old_key = match load_old_key(&profile, args.profile_name()) {
        Ok(old_key) => old_key,
        Err(e) => {
            tracing::error!(
                code = %e.code(),
                "policy-state key rotation refused before the old key was verified"
            );
            render::render_json(&Envelope::err(&e));
            return 1;
        }
    };
    if let Err(error) = verify_before_rotation(&store, &profile, old_key.as_deref()) {
        render::render_json(&Envelope::err(&error));
        return 1;
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
                "policy-state key rotated but could not be reloaded to re-sign the store"
            );
            render::render_json(&Envelope::err(&e));
            return 1;
        }
    };
    let store = PersistedWindowStore::for_profile(args.profile_name());
    if let Err(e) = store.resign(&profile, &new_key) {
        tracing::error!(
            error = ?e,
            "policy-state key rotated but store re-sign failed"
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
        args.profile_name(),
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
        profile: args.profile_name().to_owned(),
        rotated: true,
        key_kind: "hmac_32_bytes",
    }));
    0
}

/// Checks the old tag before provenance so tampering keeps its rotation diagnostic.
fn verify_before_rotation(
    store: &PersistedWindowStore,
    profile: &stellar_agent_core::profile::schema::Profile,
    old_key: Option<&[u8; 32]>,
) -> Result<(), WalletError> {
    if let Some(key) = old_key {
        store.verify_tag(key).map_err(|error| {
            WalletError::Internal(stellar_agent_core::error::InternalError::UnexpectedState {
                detail: error.with_recovery_notice(format!(
                    "policy_window_state.pre_rotation_verify_failed: {error}; rotation refused before changing the key"
                )),
            })
        })?;
    }
    store
        .require_chain_scope(
            profile,
            &stellar_agent_network::policy_state::ChainScope::for_chain(profile.chain_id),
        )
        .map_err(|error| {
            if let Some(refusal) = error.chain_validation_error() {
                return WalletError::Validation(refusal);
            }
            WalletError::Submission(
                stellar_agent_core::error::SubmissionError::RecordUnavailable {
                    detail: error.to_string(),
                },
            )
        })
}

/// Loads the old window-state key for the pre-rotation verify.
///
/// A coordinate in the owner key namespace refuses before any keyring read.
/// An old key equal to the owner public key of `profile` selected as
/// `profile_name` refuses after decoding. Both refusals carry
/// `validation.key_matches_owner_public_key`. `Ok(None)` is a key that does
/// not load, which the caller reads as never minted.
fn load_old_key(
    profile: &stellar_agent_core::profile::schema::Profile,
    profile_name: &str,
) -> Result<Option<zeroize::Zeroizing<[u8; 32]>>, WalletError> {
    let entry_ref = &profile.policy_window_state_key_id;
    owner_key::refuse_owner_key_coordinate(entry_ref, POLICY_STATE_KEY_FIELD)?;
    let Ok(old_key) = load_hmac_key_32(entry_ref) else {
        return Ok(None);
    };
    owner_key::refuse_owner_public_key(
        old_key.as_ref(),
        &owner_key::OwnerKeyContext::for_profile(profile_name, profile),
        POLICY_STATE_KEY_FIELD,
    )?;
    Ok(Some(old_key))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use clap::Parser;
    use clap::error::ErrorKind;
    use serial_test::serial;

    use super::*;

    /// Local flatten wrapper so the `RotatePolicyStateKeyArgs` clap contract
    /// can be parsed in isolation from the full command tree.
    #[derive(Debug, Parser)]
    struct Wrap {
        #[command(flatten)]
        args: RotatePolicyStateKeyArgs,
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
    async fn rotate_policy_state_key_nonexistent_profile_returns_exit_1() {
        let args = RotatePolicyStateKeyArgs {
            name: Some("__nonexistent_rotate_policy_state_key__".to_owned()),
            profile: None,
        };
        let code = run(&args).await;
        assert_eq!(code, 1);
    }

    fn put_raw(entry_ref: &stellar_agent_core::profile::schema::KeyringEntryRef, value: &str) {
        keyring_core::Entry::new(&entry_ref.service, &entry_ref.account)
            .unwrap()
            .set_password(value)
            .unwrap();
    }

    /// An old window-state key equal to the owner public key in the older
    /// form refuses with its own code, so the rotation never runs; a key
    /// that is not the owner key loads.
    #[test]
    #[serial]
    fn the_old_key_load_refuses_the_owner_key() {
        use base64::Engine as _;
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let name = "rotate-window-owner";
        let profile = stellar_agent_core::profile::schema::Profile::builder_testnet_named(
            name, "s", "a", "n", "a",
        )
        .build();
        let older_form = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x2e; 32]);
        put_raw(&profile.policy_window_state_key_id, &older_form);
        assert!(load_old_key(&profile, name).unwrap().is_some());

        put_raw(
            &stellar_agent_core::profile::schema::KeyringEntryRef::default_owner_key(name),
            &older_form,
        );
        let Err(err) = load_old_key(&profile, name) else {
            panic!("the load refuses");
        };
        assert_eq!(err.code(), "validation.key_matches_owner_public_key");
        assert!(err.to_string().contains(POLICY_STATE_KEY_FIELD), "{err}");
    }

    /// A G-strkey owner value at the window-key coordinate does not load as a
    /// key, and an owner-namespace coordinate refuses before any read.
    #[test]
    #[serial]
    fn the_old_key_load_refuses_a_g_strkey_and_an_owner_coordinate() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let name = "rotate-window-strkey";
        let mut profile = stellar_agent_core::profile::schema::Profile::builder_testnet_named(
            name, "s", "a", "n", "a",
        )
        .build();
        put_raw(
            &profile.policy_window_state_key_id,
            &stellar_agent_core::profile::owner_key::encode_owner_public_key(&[0x2f; 32]),
        );
        assert!(
            load_old_key(&profile, name).unwrap().is_none(),
            "a 42-byte value is no key"
        );

        profile.policy_window_state_key_id =
            stellar_agent_core::profile::schema::KeyringEntryRef::new(
                "stellar-agent-owner-B",
                "default",
            );
        stellar_agent_test_support::keyring_mock::inject_error(
            "stellar-agent-owner-B",
            "default",
            keyring_core::Error::PlatformFailure(Box::new(std::io::Error::other("planted"))),
        )
        .unwrap();
        let Err(err) = load_old_key(&profile, name) else {
            panic!("the load refuses");
        };
        assert_eq!(err.code(), "validation.key_matches_owner_public_key");
        let pending = keyring_core::Entry::new("stellar-agent-owner-B", "default")
            .unwrap()
            .get_password()
            .unwrap_err();
        assert!(matches!(pending, keyring_core::Error::PlatformFailure(_)));
    }

    /// Installation coordinates refuse on testnet before the keyring opens.
    #[tokio::test]
    #[serial]
    async fn installation_coordinate_refuses_without_writing() {
        crate::common::installation_key_fixture::assert_installation_profile_refusal(
            |profile| &mut profile.policy_window_state_key_id,
            async |fixture, profile, name| {
                let args = RotatePolicyStateKeyArgs {
                    name: Some(name.to_owned()),
                    profile: None,
                };
                run_with_dependencies(&args, |_| Ok(profile.clone()), || fixture.init()).await
            },
        )
        .await;
    }
    fn rotation_fixture() -> (
        tempfile::TempDir,
        stellar_agent_core::profile::schema::Profile,
        PersistedWindowStore,
    ) {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut profile = stellar_agent_core::profile::schema::Profile::builder_testnet_named(
            "rotate-scope",
            "s",
            "a",
            "n",
            "a",
        )
        .build();
        profile.audit_log_path = dir.path().join("audit.jsonl");
        let store = PersistedWindowStore::at_path(dir.path().join("policy/rotate-scope.window"));
        store.record_and_persist(&profile, &[]).unwrap();
        (dir, profile, store)
    }

    async fn assert_rotation_refuses(
        path: &std::path::Path,
        profile: &stellar_agent_core::profile::schema::Profile,
        store: &PersistedWindowStore,
    ) -> WalletError {
        let read = |entry: &stellar_agent_core::profile::schema::KeyringEntryRef| {
            keyring_core::Entry::new(&entry.service, &entry.account)
                .unwrap()
                .get_password()
                .ok()
        };
        let key = read(&profile.policy_window_state_key_id);
        let generation_entry = stellar_agent_core::profile::schema::KeyringEntryRef::new(
            &profile.policy_window_state_key_id.service,
            format!("{}-generation", profile.policy_window_state_key_id.account),
        );
        let generation = read(&generation_entry);
        let before = std::fs::read(path).ok();
        let old_key = load_old_key(profile, "rotate-scope").unwrap();
        let error = verify_before_rotation(store, profile, old_key.as_deref()).unwrap_err();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(
            path.parent().unwrap().parent().unwrap(),
        );
        let args = RotatePolicyStateKeyArgs {
            name: Some("rotate-scope".to_owned()),
            profile: None,
        };
        assert_eq!(
            run_with_dependencies(&args, |_| Ok(profile.clone()), || Ok(())).await,
            1
        );
        assert_eq!(std::fs::read(path).ok(), before);
        assert_eq!(read(&profile.policy_window_state_key_id), key);
        assert_eq!(read(&generation_entry), generation);
        error
    }

    #[tokio::test]
    #[serial]
    async fn rotation_with_a_loadable_key_checks_scope() {
        let (dir, mut profile, store) = rotation_fixture();
        profile.chain_id = stellar_agent_core::profile::caip2::Caip2::Mainnet;
        assert_eq!(
            assert_rotation_refuses(
                &dir.path().join("policy/rotate-scope.window"),
                &profile,
                &store
            )
            .await
            .code(),
            "policy.window_chain_mismatch"
        );
    }

    #[tokio::test]
    #[serial]
    async fn rotation_with_an_unloadable_key_and_file_refuses() {
        let (dir, profile, store) = rotation_fixture();
        put_raw(&profile.policy_window_state_key_id, "invalid-key");
        assert_eq!(
            assert_rotation_refuses(
                &dir.path().join("policy/rotate-scope.window"),
                &profile,
                &store
            )
            .await
            .code(),
            "submission.record_unavailable"
        );
    }

    #[tokio::test]
    #[serial]
    async fn rotation_without_key_or_file_refuses_protected_history() {
        let (dir, profile, store) = rotation_fixture();
        std::fs::remove_file(dir.path().join("policy/rotate-scope.window")).unwrap();
        keyring_core::Entry::new(
            &profile.policy_window_state_key_id.service,
            &profile.policy_window_state_key_id.account,
        )
        .unwrap()
        .delete_credential()
        .unwrap();
        assert_eq!(
            assert_rotation_refuses(
                &dir.path().join("policy/rotate-scope.window"),
                &profile,
                &store
            )
            .await
            .code(),
            "submission.record_unavailable"
        );
    }

    /// Rotation passes with nothing recorded yet, and on a verified file it
    /// leaves the store readable under the new key alone.
    #[tokio::test]
    #[serial]
    async fn rotation_passes_on_first_use_and_on_a_verified_file() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let empty = tempfile::tempdir().unwrap();
        let fresh = stellar_agent_core::profile::schema::Profile::builder_testnet_named(
            "rotate-first-use",
            "s",
            "a",
            "n",
            "a",
        )
        .build();
        let absent = PersistedWindowStore::at_path(empty.path().join("rotate-first-use.window"));
        verify_before_rotation(&absent, &fresh, None).unwrap();

        let (dir, profile, store) = rotation_fixture();
        let old_key = load_old_key(&profile, "rotate-scope").unwrap().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(dir.path());
        let args = RotatePolicyStateKeyArgs {
            name: Some("rotate-scope".to_owned()),
            profile: None,
        };
        assert_eq!(
            run_with_dependencies(&args, |_| Ok(profile.clone()), || Ok(())).await,
            0
        );
        let new_key = load_old_key(&profile, "rotate-scope").unwrap().unwrap();
        assert_ne!(new_key.as_slice(), old_key.as_slice());
        store.verify_tag(&new_key).unwrap();
        assert!(store.verify_tag(&old_key).is_err());
        store
            .load_into(
                "rotate-scope",
                &profile,
                &stellar_agent_core::policy::v1::criteria::state_store::PolicyStateStore::new(),
            )
            .unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn rotation_checks_the_tag_before_scope() {
        let (dir, mut profile, store) = rotation_fixture();
        profile.chain_id = stellar_agent_core::profile::caip2::Caip2::Mainnet;
        let mut bytes = std::fs::read(dir.path().join("policy/rotate-scope.window")).unwrap();
        bytes[0] ^= 1;
        std::fs::write(dir.path().join("policy/rotate-scope.window"), bytes).unwrap();
        let error = assert_rotation_refuses(
            &dir.path().join("policy/rotate-scope.window"),
            &profile,
            &store,
        )
        .await;
        assert_eq!(error.code(), "internal.unexpected_state");
        assert!(
            error
                .to_string()
                .contains("policy_window_state.pre_rotation_verify_failed")
                && error
                    .to_string()
                    .contains("rotation refused before changing the key")
        );
    }
}
