//! Validated replacement of provisioning fields from standard input.

use crate::common::profile_access::{load_profile_reconciled, profile_access_envelope};
use crate::common::render::render_json;
use crate::common::resolve_profile_name;
use clap::Args;
use std::io::Read as _;
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::{ValidationError, WalletError};
use stellar_agent_core::profile::{
    loader::{ProfileFragmentError, apply_fragment_on_disk, default_profile_dir},
    schema::{Profile, ProviderRole},
};

const KEY_REFUSED: (&str, &str) = (
    "profile.fragment_key_refused",
    "The fragment names a protected profile field.",
);
const IO_FAILED: (&str, &str) = (
    "profile.fragment_io_failed",
    "The profile fragment cannot be read or persisted.",
);

/// Arguments for `profile apply-fragment`.
#[derive(Debug, Args)]
pub struct ApplyFragmentArgs {
    /// The persisted profile to update.
    #[arg(long, value_name = "NAME")]
    pub profile: String,
}

fn credential_roles_line(profile: &Profile) -> String {
    let mut line = String::from("credential-roles:");
    for role in [
        ProviderRole::Primary,
        ProviderRole::Secondary,
        ProviderRole::Oracle,
    ] {
        if profile
            .providers
            .as_ref()
            .and_then(|providers| providers.record_for(role))
            .is_some_and(|record| record.credential.is_some())
        {
            line.push(' ');
            line.push_str(role.as_str());
        }
    }
    line
}

#[allow(clippy::print_stderr, reason = "CLI wrapper protocol")]
fn report(result: Result<Profile, ProfileFragmentError>) -> i32 {
    match result {
        Ok(profile) => {
            render_json(&Envelope::ok(serde_json::json!({"applied": true})));
            eprintln!("{}", credential_roles_line(&profile));
            0
        }
        Err(ProfileFragmentError::Io(_)) => io_failed(),
        Err(ProfileFragmentError::KeyRefused) => refused(
            KEY_REFUSED.0,
            &Envelope::<()>::err_raw(KEY_REFUSED.0, KEY_REFUSED.1),
        ),
        Err(ProfileFragmentError::Load(error)) => {
            let error = WalletError::Validation(error.to_validation_error());
            refused(error.code(), &Envelope::<()>::err(&error))
        }
        Err(ProfileFragmentError::Syntax) => {
            let error = WalletError::Validation(ValidationError::ConfigInvalid {
                component: "profile",
                reason: "The profile fragment is not valid TOML.".into(),
            });
            refused(error.code(), &Envelope::<()>::err(&error))
        }
        Err(_) => io_failed(),
    }
}

#[allow(clippy::print_stderr, reason = "CLI wrapper protocol")]
fn refused(code: &str, envelope: &Envelope<()>) -> i32 {
    eprintln!("refused: {code}");
    render_json(envelope);
    65
}

fn io_failed() -> i32 {
    render_json(&Envelope::<()>::err_raw(IO_FAILED.0, IO_FAILED.1));
    1
}

/// Loads the current profile, applies standard input, and reports the credential roles.
pub fn run(args: &ApplyFragmentArgs) -> i32 {
    if let Err(error) = load_profile_reconciled(&resolve_profile_name(Some(&args.profile))) {
        render_json(&profile_access_envelope(&error));
        return 1;
    }
    let Ok(dir) = default_profile_dir() else {
        return io_failed();
    };
    let mut body = String::new();
    if std::io::stdin().read_to_string(&mut body).is_err() {
        return io_failed();
    }
    report(apply_fragment_on_disk(&args.profile, &dir, &body, None))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, reason = "test assertions")]
    use super::*;
    use crate::common::test_support::capture;

    const FRAGMENT: &str = "oracle_provider_url = \"https://oracle.example.invalid\"\n\n[providers.primary]\noperator = \"primary\"\nhost = \"rpc.example.invalid\"\n\n[providers.secondary]\noperator = \"secondary\"\nhost = \"secondary.example.invalid\"\nindependent_of_primary = true\n\n[providers.oracle]\noperator = \"oracle\"\nhost = \"oracle.example.invalid\"\nindependent_of_primary = true\n";

    fn profile(dir: &std::path::Path) -> std::path::PathBuf {
        let profile = Profile::builder_mainnet_named(
            "main",
            "https://rpc.example.invalid",
            "signer",
            "account",
            "nonce",
            "account",
        )
        .secondary_rpc_url(Some("https://secondary.example.invalid".to_owned()))
        .build();
        stellar_agent_core::profile::loader::save_to_dir("main", &profile, dir).unwrap()
    }

    #[test]
    fn apply_fragment_credential_roles_line() {
        if let Some((_, stderr)) = capture(
            "commands::profile::apply_fragment::tests::apply_fragment_credential_roles_line",
        ) {
            assert_eq!(
                stderr.lines().collect::<Vec<_>>(),
                [
                    "credential-roles:",
                    "credential-roles: primary",
                    "credential-roles: primary secondary oracle"
                ]
            );
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        profile(dir.path());
        for roles in [
            &[][..],
            &["primary"][..],
            &["primary", "secondary", "oracle"][..],
        ] {
            let mut fragment = FRAGMENT.to_owned();
            for role in roles {
                fragment = fragment.replace(&format!("[providers.{role}]"), &format!("[providers.{role}]\ncredential = {{ service = 'provider-{role}', account = 'key' }}\nplacement = {{ kind = 'header', name = 'X-Provider-Key' }}"));
            }
            assert_eq!(
                report(apply_fragment_on_disk("main", dir.path(), &fragment, None)),
                0
            );
        }
    }

    #[test]
    fn apply_fragment_refuses_loader_failures_unchanged() {
        if let Some((_, stderr)) = capture(
            "commands::profile::apply_fragment::tests::apply_fragment_refuses_loader_failures_unchanged",
        ) {
            assert_eq!(
                stderr.lines().collect::<Vec<_>>(),
                [
                    "refused: validation.provider_attestation_invalid",
                    "refused: validation.config_invalid",
                    "refused: validation.provider_attestation_invalid",
                    "refused: validation.provider_attestation_invalid",
                    "refused: validation.provider_attestation_invalid",
                    "refused: validation.provider_attestation_invalid",
                    "refused: validation.provider_attestation_invalid",
                ]
            );
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let path = profile(dir.path());
        let before = std::fs::read(&path).unwrap();
        for fragment in [
            FRAGMENT.replace(
                "oracle_provider_url = \"https://oracle.example.invalid\"\n",
                "",
            ),
            FRAGMENT.replace("https://oracle", "http://oracle"),
            FRAGMENT.replace("operator = \"oracle\"", "operator = \"\""),
            FRAGMENT.replace(
                "host = \"oracle.example.invalid\"",
                "host = \"wrong.example.invalid\"",
            ),
            FRAGMENT.replace("independent_of_primary = true\n", ""),
            FRAGMENT.replace("oracle.example.invalid", "rpc.example.invalid"),
            FRAGMENT.replace("operator = \"oracle\"", "operator = \"primary\""),
        ] {
            assert_eq!(
                report(apply_fragment_on_disk("main", dir.path(), &fragment, None)),
                65
            );
            assert_eq!(std::fs::read(&path).unwrap(), before);
            assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        }
    }

    #[test]
    fn apply_fragment_refuses_other_keys() {
        if let Some((_, stderr)) =
            capture("commands::profile::apply_fragment::tests::apply_fragment_refuses_other_keys")
        {
            assert_eq!(
                stderr
                    .lines()
                    .filter(|line| *line == "refused: profile.fragment_key_refused")
                    .count(),
                4
            );
            assert_eq!(
                stderr.lines().last(),
                Some("refused: validation.config_invalid")
            );
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let path = profile(dir.path());
        let before = std::fs::read(&path).unwrap();
        for fragment in [
            "rpc_url = 'protected'",
            "network_passphrase = 'protected'",
            "mcp_signer_default = 'protected'",
            "audit_log_path = 'protected'",
            "[",
        ] {
            assert_eq!(
                report(apply_fragment_on_disk("main", dir.path(), fragment, None)),
                65
            );
            assert_eq!(std::fs::read(&path).unwrap(), before);
        }
    }

    #[test]
    fn apply_fragment_ignores_environment_overlays() {
        if crate::common::test_support::capture_with_env(
            "apply_fragment_ignores_environment_overlays",
            &[("STELLAR_AGENT_SUBMIT_TIMEOUT_SECONDS", "41")],
        )
        .is_some()
        {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let path = profile(dir.path());
        let before: toml::Value = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let loaded = apply_fragment_on_disk("main", dir.path(), FRAGMENT, None).unwrap();
        assert_eq!(loaded.submit_timeout_seconds, Some(41));
        let after: toml::Value = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            after.get("submit_timeout_seconds"),
            before.get("submit_timeout_seconds")
        );
    }
}
