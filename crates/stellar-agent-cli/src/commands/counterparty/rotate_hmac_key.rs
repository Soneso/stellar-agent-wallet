//! `stellar-agent counterparty rotate-hmac-key [--profile <name>]` — rotate the
//! per-profile counterparty cache HMAC key.
//!
//! After rotation, existing cache files will fail HMAC verification and should
//! be refreshed with `stellar-agent counterparty warm-up` or targeted
//! `stellar-agent counterparty refresh <home-domain>` calls.

use clap::Args;
use serde::Serialize;
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::WalletError;
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_core::profile::{loader, owner_key};
use stellar_agent_network::keyring::{init_platform_keyring_store, rotate_keyring_secret_32};

use crate::commands::profile::key_ops::COUNTERPARTY_KEY_FIELD;
use crate::common::profile_access::{
    injected_profile_load, profile_access_envelope, reconcile_loaded_profile,
};
use crate::common::{render, resolve_profile_name};

/// Arguments for `stellar-agent counterparty rotate-hmac-key`.
#[derive(Debug, Args)]
#[non_exhaustive]
pub(crate) struct RotateHmacKeyArgs {
    /// Profile name whose counterparty cache HMAC key should be rotated.
    ///
    /// Defaults to the `STELLAR_AGENT_PROFILE` env var, then `"default"`.
    #[arg(long = "profile", value_name = "NAME")]
    pub(crate) profile: Option<String>,
}

#[derive(Debug, Serialize)]
struct RotateHmacKeyData {
    profile: String,
    rotated: bool,
    key_kind: &'static str,
    cache_invalidated: bool,
    note: &'static str,
}

fn rotate_hmac_key_envelope(profile: &str) -> Envelope<RotateHmacKeyData> {
    Envelope::ok(RotateHmacKeyData {
        profile: profile.to_owned(),
        rotated: true,
        key_kind: "hmac_32_bytes",
        cache_invalidated: true,
        note: "existing counterparty cache files must be refreshed",
    })
}

/// Runs `stellar-agent counterparty rotate-hmac-key [--profile <name>]`.
///
/// Returns `0` on success, `1` when the profile cannot be loaded, the platform
/// keyring cannot be initialized, or the keyring write fails.
pub async fn run(args: &RotateHmacKeyArgs) -> i32 {
    run_with_dependencies(args, injected_profile_load, init_platform_keyring_store).await
}

/// Testable core of [`run`] with the profile loader and the platform-keyring
/// initialiser injected.
///
/// Production callers use [`run`], which supplies the real profile loader and
/// [`init_platform_keyring_store`]. Tests substitute an in-memory profile and
/// a spy initialiser over a mock keyring store.
async fn run_with_dependencies<LoadProfile, InitKeyring>(
    args: &RotateHmacKeyArgs,
    load_profile: LoadProfile,
    init_keyring: InitKeyring,
) -> i32
where
    LoadProfile: FnOnce(&str) -> Result<Profile, loader::ProfileLoadError>,
    InitKeyring: FnOnce() -> Result<(), WalletError>,
{
    // `--profile`, then `STELLAR_AGENT_PROFILE`, then `"default"`.
    let resolved_profile = resolve_profile_name(args.profile.as_deref());
    let profile_name = resolved_profile.name.clone();

    // Reconciled: a profile file whose owner-key coordinate names a
    // different profile is refused rather than used under this name. The
    // check runs in the caller of the injected loader, so a test that
    // supplies its own loader passes through it too.
    let profile = match reconcile_loaded_profile(load_profile(&profile_name), &resolved_profile) {
        Ok(p) => p,
        Err(e) => {
            tracing::debug!(profile = %profile_name, error = %e, "profile access refused");
            render::render_json(&profile_access_envelope(&e, &profile_name));
            return 1;
        }
    };

    // A coordinate in the owner key namespace refuses before the keyring
    // opens, so the rotation never writes over an owner entry.
    let entry_ref = &profile.counterparty_cache_key_id;
    if let Err(e) = owner_key::refuse_owner_key_coordinate(entry_ref, COUNTERPARTY_KEY_FIELD) {
        render::render_json(&Envelope::err(&e));
        return 1;
    }

    if let Err(e) = init_keyring() {
        render::render_json(&Envelope::err(&e));
        return 1;
    }

    match rotate_keyring_secret_32(&entry_ref.service, &entry_ref.account) {
        Ok(()) => {
            tracing::info!(
                "counterparty HMAC key rotated; cached stellar.toml entries must be refreshed"
            );
            render::render_json(&rotate_hmac_key_envelope(&profile_name));
            0
        }
        Err(e) => {
            // The shared helper classifies keyring failures — surface its
            // error unchanged so environmental causes (a non-interactive
            // Windows session) keep their typed code instead of collapsing
            // into "not found".
            tracing::debug!(error = %e, "counterparty HMAC key rotation failed");
            render::render_json(&Envelope::err(&e));
            1
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test-only")]

    use super::*;
    use clap::Parser;
    use serial_test::serial;

    #[derive(Debug, Parser)]
    struct RotateHmacKeyArgsHarness {
        #[command(flatten)]
        args: RotateHmacKeyArgs,
    }

    #[test]
    fn parse_rotate_hmac_key_args() {
        let parsed = RotateHmacKeyArgsHarness::parse_from(["test", "--profile", "alice"]);
        assert_eq!(parsed.args.profile.as_deref(), Some("alice"));
    }

    #[test]
    fn rotate_hmac_key_envelope_shape() {
        let env = rotate_hmac_key_envelope("alice");
        assert!(env.ok);
        let data = env.data.unwrap();
        assert_eq!(data.profile, "alice");
        assert!(data.rotated);
        assert_eq!(data.key_kind, "hmac_32_bytes");
        assert!(data.cache_invalidated);
    }

    /// A counterparty-key coordinate in the owner key namespace refuses
    /// before the keyring opens, and the owner entry is not overwritten.
    #[tokio::test]
    #[serial]
    async fn an_owner_namespace_coordinate_refuses_the_rotation() {
        use stellar_agent_core::profile::schema::KeyringEntryRef;

        stellar_agent_test_support::keyring_mock::install().unwrap();
        let name = "counterparty-rotate-owner";
        let owner = KeyringEntryRef::default_owner_key(name);
        let owner_value = owner_key::encode_owner_public_key(&[0x5e; 32]);
        keyring_core::Entry::new(&owner.service, &owner.account)
            .unwrap()
            .set_password(&owner_value)
            .unwrap();
        let mut profile = Profile::builder_testnet_named(name, "s", "a", "n", "a").build();
        profile.counterparty_cache_key_id = owner.clone();

        let args = RotateHmacKeyArgs {
            profile: Some(name.to_owned()),
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
