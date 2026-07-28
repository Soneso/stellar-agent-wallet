//! The CLI's profile-access choke point.
//!
//! Every command that may run without an authored profile file resolves it
//! here, so the rule deciding when a missing file may be replaced by the
//! synthesised zero-config profile has exactly one implementation.
//!
//! # Synthesis is keyed on PROVENANCE, never on the name
//!
//! [`load_profile_or_synthesize_testnet`] synthesises only when the operator
//! named no profile at all — [`ProfileNameSource::Default`], the case the
//! zero-config quickstart exists for. A name that came from `--profile` or
//! `STELLAR_AGENT_PROFILE` is honoured as given: if its file does not exist the
//! loader's `NotFound` is returned as an error and the command refuses.
//!
//! Comparing the resolved name against `"default"` is NOT equivalent and must
//! not be substituted: `--profile default` on a host with no `default.toml` is
//! a named profile, and a string comparison would silently replace it with the
//! permissive testnet fallback. This is the predicate
//! `stellar-agent-mcp`'s `load_selected_profile` already applies at startup.
//!
//! # The dependency-injection seam
//!
//! `pay`, `claim`, and `accounts create` inject their loader through a
//! `run_with_dependencies` seam so their tests can supply an in-memory profile
//! without touching the profile directory. The injected closure LOADS ONLY:
//! the provenance decision lives in [`load_profile_or_synthesize_testnet_with`],
//! which is production code on both the injected and the real path.
//!
//! That placement is the whole point. Several injected closures ignore the
//! name they are handed, so a decision made inside the closure would be
//! bypassed by every test that supplies one — the refusal would look pinned
//! while never running. Placing it in the caller of the closure means every
//! load, injected or real, passes through it.

use stellar_agent_core::observability::redact_path_in_message;
use stellar_agent_core::profile::loader as profile_loader;
use stellar_agent_core::profile::name::ResolvedProfileName;
use stellar_agent_core::profile::schema::{PolicyEngineKind, Profile};

/// Origin of a profile resolved by [`load_profile_or_synthesize_testnet`].
///
/// Two origin-aware behaviors key off this distinction, neither engine-aware:
/// - Platform keyring store initialisation (e.g. `pay::resolve_profile_and_keyring`,
///   the analogous helper in `claim`, and the inline attempt in `accounts
///   create`'s sponsored path) logs a `tracing::warn!` and continues past a
///   failed attempt for a [`Self::Synthesized`] profile, so a host with no
///   platform keyring store (e.g. a container without a Secret Service) never
///   blocks the zero-config quickstart's signing.
/// - The audit pre-flight (see
///   [`crate::commands::value_audit::require_value_audit_writer_for_origin`])
///   stays fail-open (warn-only) for a [`Self::Synthesized`] profile when the
///   audit chain-root key is unavailable.
///
/// A [`Self::Persisted`] profile fails closed on both conditions instead: an
/// operator who authored a profile file — under either policy engine — is
/// expected to have a working platform keyring and to have run
/// `stellar-agent profile rotate-audit-key <name>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProfileOrigin {
    /// Loaded from an operator-authored `<name>.toml` file.
    Persisted,
    /// No profile was named and no profile file exists; an in-memory
    /// `Noop`-engine testnet profile was synthesized so `pay` / `claim` /
    /// `accounts create` keep working without an authored profile.
    Synthesized,
}

/// Loads the resolved profile, falling back to an in-memory `Noop`-engine
/// testnet profile only when no profile was named and no `<name>.toml` file
/// exists.
///
/// `pay`, `claim`, and `accounts create` operate against testnet without
/// requiring an authored profile file (see the "Set up a profile" section of
/// the getting-started guide). The zero-config invariant is bounded by two
/// conditions, both required: the permissive fallback fires ONLY on
/// [`profile_loader::ProfileLoadError::NotFound`] AND only when
/// `resolved.source` is not explicit. It is forced to
/// [`PolicyEngineKind::Noop`] regardless of [`Profile::builder_testnet`]'s own
/// default (`V1`), so an unauthored profile never triggers an
/// owner-key/policy-file requirement the operator never opted into. Once an
/// operator persists a real profile — `V1` or `Noop` — that file's configured
/// engine governs instead.
///
/// Returns the resolved profile alongside its [`ProfileOrigin`], so callers
/// can apply origin-aware policy to the audit pre-flight (see
/// [`crate::commands::value_audit::require_value_audit_writer_for_origin`])
/// without re-deriving which branch fired.
///
/// # Errors
///
/// Returns `Err(message)` for any profile-load failure other than an
/// unnamed-profile `NotFound`: a malformed TOML file, an unsupported schema
/// version, and a `NotFound` for a profile the operator named through
/// `--profile` or `STELLAR_AGENT_PROFILE`.
///
/// The message is redacted with
/// [`redact_path_in_message`](stellar_agent_core::observability::redact_path_in_message)
/// before it is returned: `ProfileLoadError::NotFound`'s `Display` embeds the
/// absolute path it checked, and callers render this string into an operator
/// envelope on stdout.
pub(crate) fn load_profile_or_synthesize_testnet(
    resolved: &ResolvedProfileName,
) -> Result<(Profile, ProfileOrigin), String> {
    load_profile_or_synthesize_testnet_with(resolved, |name| profile_loader::load(name, None))
}

/// [`load_profile_or_synthesize_testnet`] with the load step injected.
///
/// The synthesis decision lives HERE — outside `load`, and therefore outside
/// every test-supplied closure — because a check placed inside the injected
/// loader is unreachable for the tests that replace it. See the module docs.
///
/// # Errors
///
/// Identical to [`load_profile_or_synthesize_testnet`]; `load`'s error is
/// rendered into the message except for the unnamed-profile `NotFound` case
/// the synthesis fallback covers.
pub(crate) fn load_profile_or_synthesize_testnet_with<Load>(
    resolved: &ResolvedProfileName,
    load: Load,
) -> Result<(Profile, ProfileOrigin), String>
where
    Load: FnOnce(&str) -> Result<Profile, profile_loader::ProfileLoadError>,
{
    let name = resolved.name.as_str();
    match load(name) {
        Ok(profile) => Ok((profile, ProfileOrigin::Persisted)),
        Err(profile_loader::ProfileLoadError::NotFound { .. })
            if !resolved.source.is_explicit() =>
        {
            let profile = Profile::builder_testnet_named(
                name,
                "stellar-agent-signer",
                name,
                "stellar-agent-nonce",
                name,
            )
            .policy_engine(PolicyEngineKind::Noop)
            .build();
            Ok((profile, ProfileOrigin::Synthesized))
        }
        // Redacted here, at the one place this message is built, so no caller
        // can render the loader's absolute path into an envelope on stdout.
        // The smart-account writer helper redacts again on its own path; the
        // second pass is a no-op on an already-redacted string.
        Err(e) => Err(redact_path_in_message(&format!(
            "profile '{name}' failed to load: {e}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::panic,
        reason = "test-only fixture construction"
    )]

    use stellar_agent_core::profile::name::ProfileNameSource;

    use super::*;

    fn resolved(name: &str, source: ProfileNameSource) -> ResolvedProfileName {
        ResolvedProfileName {
            name: name.to_owned(),
            source,
        }
    }

    /// A malformed profile TOML file must return `Err` — NOT the permissive
    /// `Noop` synthesis, which is reserved for the file-absent case only.
    #[test]
    #[serial_test::serial]
    fn malformed_profile_toml_returns_err_not_noop_synthesis() {
        let home = tempfile::TempDir::new().expect("tempdir");
        let profiles_dir = home.path().join("profiles");
        std::fs::create_dir_all(&profiles_dir).expect("create profiles dir");
        std::fs::write(
            profiles_dir.join("malformed-hazard.toml"),
            "this is not { valid toml [[[",
        )
        .expect("write malformed profile");

        let _home_guard = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());

        let result = load_profile_or_synthesize_testnet(&resolved(
            "malformed-hazard",
            ProfileNameSource::Default,
        ));
        assert!(
            result.is_err(),
            "a malformed profile TOML must return Err, not synthesize Noop"
        );
    }

    /// No name supplied and no `default.toml`: the zero-config quickstart
    /// still synthesizes the in-memory `Noop`-engine profile tagged
    /// [`ProfileOrigin::Synthesized`] — the tag the audit pre-flight relies on
    /// to stay fail-open.
    #[test]
    #[serial_test::serial]
    fn unnamed_absent_profile_still_synthesizes_noop_tagged_synthesized() {
        let home = tempfile::TempDir::new().expect("tempdir");
        let _home_guard = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());

        let (profile, origin) =
            load_profile_or_synthesize_testnet(&resolved("default", ProfileNameSource::Default))
                .expect("an unnamed absent profile must synthesize, not error");
        assert_eq!(
            origin,
            ProfileOrigin::Synthesized,
            "an unnamed absent profile must resolve as Synthesized"
        );
        assert!(
            matches!(profile.policy.engine, PolicyEngineKind::Noop),
            "the synthesized profile must force the Noop engine regardless of \
             Profile::builder_testnet's own default"
        );
    }

    /// A profile the operator NAMED but never authored must refuse. The
    /// synthesized fallback is a testnet, `Noop`-engine configuration, so
    /// substituting it for a named-but-missing profile would answer under a
    /// policy gate the operator never chose.
    #[test]
    #[serial_test::serial]
    fn named_absent_profile_refuses_from_the_flag() {
        let home = tempfile::TempDir::new().expect("tempdir");
        let _home_guard = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());

        let err = load_profile_or_synthesize_testnet(&resolved(
            "never-authored",
            ProfileNameSource::Flag,
        ))
        .expect_err("a profile named through --profile must not be synthesized");
        assert!(
            err.contains("never-authored"),
            "the refusal must name the profile the operator asked for: {err}"
        );
    }

    /// The refusal message carries no un-redacted absolute path.
    ///
    /// `ProfileLoadError::NotFound`'s `Display` embeds the full path it
    /// checked, and `pay` / `claim` / `accounts create` render this string
    /// straight into an operator envelope on stdout, so the home prefix is
    /// stripped at the one place the message is built.
    #[test]
    #[serial_test::serial]
    fn the_refusal_message_does_not_leak_the_home_directory() {
        let home_dir = std::env::var("HOME").expect("HOME is set in the test environment");
        // The profile directory the loader reports lives under $HOME on every
        // platform this suite runs on, so a leak would surface that prefix.
        let store = std::path::Path::new(&home_dir).join("stellar-agent-redaction-probe");
        let _home_guard = stellar_agent_test_support::StellarAgentHomeGuard::new(&store);

        let err = load_profile_or_synthesize_testnet(&resolved(
            "redaction-probe",
            ProfileNameSource::Flag,
        ))
        .expect_err("a named profile with no file must refuse");
        assert!(
            err.contains("redaction-probe"),
            "the refusal must still name the profile: {err}"
        );
        assert!(
            !err.contains(&home_dir),
            "the refusal must not carry the operator's home directory: {err}"
        );
        assert!(
            err.contains("<HOME>"),
            "the home prefix must be replaced by the redaction marker, proving the \
             path was rendered and then redacted rather than absent by accident: {err}"
        );
    }

    /// The same refusal when the name came from `STELLAR_AGENT_PROFILE`. The
    /// variable is an explicit input wherever it is set, so a stale value in a
    /// shell rc or a CI job selects a profile as firmly as a typed flag does
    /// and is refused on the same terms.
    #[test]
    #[serial_test::serial]
    fn named_absent_profile_refuses_from_the_environment() {
        let home = tempfile::TempDir::new().expect("tempdir");
        let _home_guard = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());

        let err =
            load_profile_or_synthesize_testnet(&resolved("never-authored", ProfileNameSource::Env))
                .expect_err("a profile named through the environment must not be synthesized");
        assert!(
            err.contains("never-authored"),
            "the refusal must name the profile the operator asked for: {err}"
        );
    }

    /// `--profile default` on a host with no `default.toml` refuses. This is
    /// the case a string comparison against `"default"` gets wrong: the name
    /// is identical to the fallback, and only the provenance distinguishes an
    /// explicitly-named profile from an absent one.
    #[test]
    #[serial_test::serial]
    fn explicitly_named_default_refuses_when_the_file_is_absent() {
        let home = tempfile::TempDir::new().expect("tempdir");
        let _home_guard = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());

        let err = load_profile_or_synthesize_testnet(&resolved("default", ProfileNameSource::Flag))
            .expect_err("an explicitly-named `default` must not be synthesized");
        assert!(
            err.contains("default"),
            "the refusal must name the profile the operator asked for: {err}"
        );
    }

    /// The decision runs in the caller of the injected loader: a closure that
    /// reports `NotFound` for an explicitly-named profile is refused even
    /// though the closure itself performs no check.
    #[test]
    fn the_injected_loader_is_not_where_the_decision_lives() {
        let not_found = |name: &str| {
            Err(profile_loader::ProfileLoadError::NotFound {
                name: name.to_owned(),
                path: std::path::PathBuf::from("/nonexistent"),
            })
        };

        let err = load_profile_or_synthesize_testnet_with(
            &resolved("seam-named", ProfileNameSource::Flag),
            not_found,
        )
        .expect_err("an explicitly-named profile must refuse through the seam too");
        assert!(err.contains("seam-named"), "refusal must name it: {err}");

        let (_profile, origin) = load_profile_or_synthesize_testnet_with(
            &resolved("default", ProfileNameSource::Default),
            not_found,
        )
        .expect("an unnamed profile must still synthesize through the seam");
        assert_eq!(origin, ProfileOrigin::Synthesized);
    }
}
