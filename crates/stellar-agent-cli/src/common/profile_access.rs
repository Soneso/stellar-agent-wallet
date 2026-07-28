//! The CLI's profile-access choke point.
//!
//! Every production profile load in this crate runs through this module, so
//! the two rules that decide whether a profile may govern a command have
//! exactly one implementation each: when a missing file may be replaced by the
//! synthesised zero-config profile, and whether the loaded file is the profile
//! the operator actually named.
//!
//! `crates/stellar-agent-cli/tests/profile_reconciliation_discipline.rs`
//! enforces the routing as a source scan: outside this module, only
//! `commands/profile/show.rs` may call the loader directly.
//!
//! # A profile that names another profile is refused
//!
//! [`load_profile_reconciled`] loads and then reconciles: a file whose
//! `policy_owner_key_id.service` names a different profile is refused rather
//! than used. Without that check, `--profile alice` on a copy of `default.toml`
//! reads `default`'s signed policy and enrols into `default`'s owner-key
//! coordinate while every message names `alice`.
//!
//! The refusal is rendered under [`CLI_STATE_LAYOUT`], because this binary
//! splits per-profile state across the two names: the signed policy file and
//! the owner-key keyring entry follow the DERIVED name, while the
//! pending-approval store, the audit log, and the policy-window state key on
//! the REQUESTED one. `stellar-agent-mcp` keys all of it on the derived name
//! and renders the same refusal under its own layout.
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

use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::{ValidationError, WalletError};
use stellar_agent_core::observability::redact_path_in_message;
use stellar_agent_core::profile::loader::{self as profile_loader, MulticallRegistryHook};
use stellar_agent_core::profile::name::{
    ProfileNameMismatch, ProfileStateLayout, ResolvedProfileName, profile_name_mismatch_refusal,
};
use stellar_agent_core::profile::schema::{PolicyEngineKind, Profile};

/// The wire code a name mismatch carries, on every surface and both rendering
/// paths.
///
/// Owned by [`ValidationError::ProfileNameMismatch`]; named here so the
/// `err_raw` verbs can report it without constructing a throwaway error value
/// just to read its code. `the_mismatch_code_matches_the_typed_variant` pins
/// the two together.
pub(crate) const PROFILE_NAME_MISMATCH_CODE: &str = "profile.name_mismatch";

/// The state layout a [`ProfileNameMismatch`] refusal is rendered under on this
/// surface.
///
/// The signed policy file (`commands::policy_engine::build_v1_policy_engine`)
/// and the owner-key keyring entry (`profile enroll-owner-key`) resolve through
/// the name derived from `policy_owner_key_id.service`; the pending-approval
/// store and the policy-window state FILE key on the requested name. A mismatch
/// therefore splits this binary's state across two profiles instead of moving
/// all of it to one, and the refusal says so.
///
/// The audit log is deliberately not claimed either way: `audit_log_path` is a
/// serialized profile field, so a copied file carries the SOURCE profile's path
/// and the rows follow the file rather than the requested name.
pub(crate) const CLI_STATE_LAYOUT: ProfileStateLayout =
    ProfileStateLayout::PolicyDerivedStateRequested;

/// Why a profile could not be made available to a command.
///
/// The two arms are distinguished because their dispositions differ at several
/// call sites: `smart-account multicall` tolerates a `NotFound` load while it
/// must refuse a mismatch, and the signer ceremony keeps its documented
/// warn-fallback for a load failure while failing closed on a mismatch. A
/// single flattened error would make either disposition impossible to write.
#[derive(Debug)]
pub(crate) enum ProfileAccessError {
    /// The loader refused: the file is absent, malformed, carries an
    /// unsupported schema version, or the name is not a usable path component.
    ///
    /// Carries the loader's own error so call sites keep the per-variant
    /// envelopes they already emit.
    Load(profile_loader::ProfileLoadError),
    /// The file loaded, but its `policy_owner_key_id.service` names a different
    /// profile than the one selected.
    NameMismatch(ProfileNameMismatch),
}

impl ProfileAccessError {
    /// The wire code for this failure on the surfaces that render a raw code.
    ///
    /// Load failures keep `profile.load_failed`; a mismatch reports the
    /// `profile.name_mismatch` code owned by
    /// [`ValidationError::ProfileNameMismatch`], so a refusal carries the same
    /// code whether the surface renders a raw code or a typed
    /// [`WalletError`].
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::Load(_) => "profile.load_failed",
            Self::NameMismatch(_) => PROFILE_NAME_MISMATCH_CODE,
        }
    }

    /// This failure as the typed error the CLI's `Envelope::err` path renders.
    ///
    /// The mapping is the one [`profile_access_envelope`] documents; call sites
    /// that already return a [`WalletError`] use this form so the mismatch
    /// keeps its own wire code through their existing rendering.
    pub(crate) fn to_wallet_error(&self, requested_name: &str) -> WalletError {
        match self {
            Self::Load(profile_loader::ProfileLoadError::NotFound { name, .. }) => {
                WalletError::Validation(ValidationError::ProfileNotFound { name: name.clone() })
            }
            Self::Load(_) => WalletError::Validation(ValidationError::ConfigInvalid {
                component: "profile",
                reason: self.message(requested_name),
            }),
            Self::NameMismatch(_) => {
                WalletError::Validation(ValidationError::ProfileNameMismatch {
                    detail: self.message(requested_name),
                })
            }
        }
    }

    /// The operator-facing message, with any absolute path redacted.
    ///
    /// `ProfileLoadError::NotFound`'s `Display` embeds the directory it
    /// checked, and callers render this string into an envelope on stdout, so
    /// the redaction happens here rather than at each call site.
    ///
    /// The mismatch arm is redacted on the same terms, not because the loader
    /// puts a path in it but because the message echoes
    /// `policy_owner_key_id.service` verbatim — an operator-editable field that
    /// can hold anything, including a home-directory path. Redacting one arm
    /// and not the other would leave the leak open on whichever arm was
    /// overlooked.
    pub(crate) fn message(&self, requested_name: &str) -> String {
        let rendered = match self {
            Self::Load(e) => format!("profile '{requested_name}' failed to load: {e}"),
            Self::NameMismatch(mismatch) => mismatch.message(CLI_STATE_LAYOUT),
        };
        redact_path_in_message(&rendered)
    }

    /// `true` when the profile file simply does not exist.
    ///
    /// The one disposition that may treat an error as "no profile configured"
    /// rather than as a refusal; a mismatch never satisfies it.
    pub(crate) fn is_not_found(&self) -> bool {
        matches!(
            self,
            Self::Load(profile_loader::ProfileLoadError::NotFound { .. })
        )
    }
}

impl std::fmt::Display for ProfileAccessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Load(e) => write!(f, "{e}"),
            Self::NameMismatch(mismatch) => {
                f.write_str(&redact_path_in_message(&mismatch.message(CLI_STATE_LAYOUT)))
            }
        }
    }
}

/// Loads the resolved profile and refuses it when its owner-key coordinate
/// names a different profile.
///
/// This is the entry point for command bodies, which hold the
/// [`ResolvedProfileName`] the resolver produced. Helpers that receive only the
/// requested name call [`load_profile_reconciled_by_requested_name`]; the
/// resolver itself is enforced separately by
/// `crates/stellar-agent-cli/tests/profile_flag_discipline.rs`.
///
/// `multicall_hook` is threaded to the loader for the one command that needs
/// the multicall registry available while the profile is parsed
/// (`smart-account multicall`); pass `None` everywhere else.
///
/// # Errors
///
/// [`ProfileAccessError::Load`] for any loader failure — including a
/// `NotFound`, which this function never replaces with a synthesised profile —
/// and [`ProfileAccessError::NameMismatch`] when the file names another
/// profile.
pub(crate) fn load_profile_reconciled(
    resolved: &ResolvedProfileName,
    multicall_hook: Option<&dyn MulticallRegistryHook>,
) -> Result<Profile, ProfileAccessError> {
    load_profile_reconciled_by_requested_name(&resolved.name, multicall_hook)
}

/// [`load_profile_reconciled`] for helpers that receive only the requested
/// name.
///
/// The reconciliation compares the requested name against the one the file
/// carries and does not consult the name's provenance, so a helper that was
/// handed `<resolved>.name` several frames down loses nothing by calling this
/// form. Threading [`ResolvedProfileName`] through every such helper —
/// the signer ceremony, the smart-account context, `list-rules`' scan-id
/// resolution — would move a value none of them read.
///
/// # Errors
///
/// Identical to [`load_profile_reconciled`].
pub(crate) fn load_profile_reconciled_by_requested_name(
    requested_name: &str,
    multicall_hook: Option<&dyn MulticallRegistryHook>,
) -> Result<Profile, ProfileAccessError> {
    let profile =
        profile_loader::load(requested_name, multicall_hook).map_err(ProfileAccessError::Load)?;
    reconcile(profile, requested_name)
}

/// The load step the `run_with_dependencies` seams inject in production.
///
/// Performs NO reconciliation: the commands that inject it reconcile in the
/// caller of the closure, through [`reconcile_loaded_profile`] or
/// [`load_profile_or_synthesize_testnet_with`]. Placing the check inside the
/// closure instead would put it behind every test-supplied substitute.
///
/// It exists so `profile::loader::load` keeps exactly one call site in this
/// crate and the discipline scan stays a structural rule rather than a
/// per-command allowlist that would have to grow with each new seam.
///
/// # Errors
///
/// The loader's error, unchanged.
pub(crate) fn injected_profile_load(
    name: &str,
) -> Result<Profile, profile_loader::ProfileLoadError> {
    profile_loader::load(name, None)
}

/// Reconciles a profile a caller has already loaded through an injected
/// dependency seam.
///
/// The `run_with_dependencies` commands replace the loader in tests, and
/// several of those substitutes ignore the name they are handed. A check
/// placed inside the injected closure would therefore be bypassed by every one
/// of them while still looking pinned. This function is called in the CALLER
/// of the closure, on its result, so injected and real loads reconcile alike.
///
/// # Errors
///
/// [`ProfileAccessError::Load`] carries `loaded`'s error unchanged;
/// [`ProfileAccessError::NameMismatch`] when the loaded file names another
/// profile.
pub(crate) fn reconcile_loaded_profile(
    loaded: Result<Profile, profile_loader::ProfileLoadError>,
    requested_name: &str,
) -> Result<Profile, ProfileAccessError> {
    reconcile(loaded.map_err(ProfileAccessError::Load)?, requested_name)
}

/// Refuses `profile` when its owner-key coordinate names a profile other than
/// `requested_name`.
///
/// Every LOADED profile in this module funnels through here, so no caller can
/// obtain a profile read from disk that has not been reconciled. The synthesis
/// branch of [`load_profile_or_synthesize_testnet_with`] does not call it, and
/// must not: that profile is built from the requested name by
/// [`Profile::builder_testnet_named`] and is self-consistent by construction.
fn reconcile(profile: Profile, requested_name: &str) -> Result<Profile, ProfileAccessError> {
    match profile_name_mismatch_refusal(&profile, requested_name) {
        Some(mismatch) => Err(ProfileAccessError::NameMismatch(mismatch)),
        None => Ok(profile),
    }
}

/// Renders a [`ProfileAccessError`] as the CLI's error envelope.
///
/// This is the mapping for the TYPED-envelope path, and it is uniform across
/// every command that uses it:
///
/// - an absent file keeps `validation.profile_not_found`;
/// - any other loader failure — malformed TOML, unsupported schema version, an
///   out-of-bounds field, a name that is not a path component — is
///   `validation.config_invalid` with the cause in the message. It is operator
///   input, so it is not `internal.*`, and the cause is carried rather than
///   flattened into "not found";
/// - a name mismatch gets [`PROFILE_NAME_MISMATCH_CODE`], because its recovery
///   is unrelated to either of the above.
///
/// The verbs that render a raw code instead — `pay`, `claim`,
/// `accounts create`, `lend`, `trade`, `vault`, `trustline` — do NOT share the
/// Load half: they collapse every loader failure to `profile.load_failed`
/// (`trustline` to `trustline.profile_load_failed`), which is the code their
/// documentation and the packaged skill already pin. Only the mismatch code is
/// uniform across both paths, which is the property this change needed.
/// Unifying the Load codes would be a wire-behaviour change for those verbs.
pub(crate) fn profile_access_envelope(
    err: &ProfileAccessError,
    requested_name: &str,
) -> Envelope<()> {
    Envelope::err(&err.to_wallet_error(requested_name))
}

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
/// A loaded [`ProfileOrigin::Persisted`] profile is reconciled against the
/// requested name exactly as [`load_profile_reconciled`] reconciles it. A
/// [`ProfileOrigin::Synthesized`] one is not, because
/// [`Profile::builder_testnet_named`] derives its owner coordinate from the
/// same name it is built under and is self-consistent by construction.
///
/// # Errors
///
/// Returns [`ProfileAccessError::Load`] for any profile-load failure other
/// than an unnamed-profile `NotFound`: a malformed TOML file, an unsupported
/// schema version, and a `NotFound` for a profile the operator named through
/// `--profile` or `STELLAR_AGENT_PROFILE`. Returns
/// [`ProfileAccessError::NameMismatch`] for a file whose owner-key coordinate
/// names a different profile.
pub(crate) fn load_profile_or_synthesize_testnet(
    resolved: &ResolvedProfileName,
) -> Result<(Profile, ProfileOrigin), ProfileAccessError> {
    load_profile_or_synthesize_testnet_with(resolved, injected_profile_load)
}

/// [`load_profile_or_synthesize_testnet`] with the load step injected.
///
/// The synthesis decision and the reconciliation both live HERE — outside
/// `load`, and therefore outside every test-supplied closure — because a check
/// placed inside the injected loader is unreachable for the tests that replace
/// it. See the module docs.
///
/// # Errors
///
/// Identical to [`load_profile_or_synthesize_testnet`].
pub(crate) fn load_profile_or_synthesize_testnet_with<Load>(
    resolved: &ResolvedProfileName,
    load: Load,
) -> Result<(Profile, ProfileOrigin), ProfileAccessError>
where
    Load: FnOnce(&str) -> Result<Profile, profile_loader::ProfileLoadError>,
{
    let name = resolved.name.as_str();
    match load(name) {
        // A file that exists and names another profile is refused, never
        // treated as absent: the synthesis fallback below answers only for a
        // profile that was neither named nor authored.
        Ok(profile) => reconcile(profile, name).map(|p| (p, ProfileOrigin::Persisted)),
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
        Err(e) => Err(ProfileAccessError::Load(e)),
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
        let message = err.message("never-authored");
        assert!(
            message.contains("never-authored"),
            "the refusal must name the profile the operator asked for: {message}"
        );
        assert_eq!(err.code(), "profile.load_failed");
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
        let message = err.message("redaction-probe");
        assert!(
            message.contains("redaction-probe"),
            "the refusal must still name the profile: {message}"
        );
        assert!(
            !message.contains(&home_dir),
            "the refusal must not carry the operator's home directory: {message}"
        );
        assert!(
            message.contains("<HOME>"),
            "the home prefix must be replaced by the redaction marker, proving the \
             path was rendered and then redacted rather than absent by accident: {message}"
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
        let message = err.message("never-authored");
        assert!(
            message.contains("never-authored"),
            "the refusal must name the profile the operator asked for: {message}"
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
        let message = err.message("default");
        assert!(
            message.contains("default"),
            "the refusal must name the profile the operator asked for: {message}"
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
        let message = err.message("seam-named");
        assert!(
            message.contains("seam-named"),
            "refusal must name it: {message}"
        );

        let (_profile, origin) = load_profile_or_synthesize_testnet_with(
            &resolved("default", ProfileNameSource::Default),
            not_found,
        )
        .expect("an unnamed profile must still synthesize through the seam");
        assert_eq!(origin, ProfileOrigin::Synthesized);
    }

    // ── Reconciliation ───────────────────────────────────────────────────────

    /// A profile whose owner-key coordinate names ANOTHER profile is refused
    /// through the synthesis helper, with the mismatch's own wire code.
    ///
    /// The refusal must beat the synthesis fallback: the file exists, so
    /// treating it as absent and substituting the permissive zero-config
    /// profile would answer under a policy gate the operator never chose.
    #[test]
    fn a_mismatched_profile_refuses_through_the_synthesis_helper() {
        let copied = |_name: &str| {
            Ok(Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
                .with_profile_name("default")
                .build())
        };

        let err = load_profile_or_synthesize_testnet_with(
            &resolved("alice", ProfileNameSource::Flag),
            copied,
        )
        .expect_err("a file naming 'default' must not serve as 'alice'");

        assert!(matches!(err, ProfileAccessError::NameMismatch(_)));
        assert_eq!(err.code(), "profile.name_mismatch");
        let message = err.message("alice");
        assert!(message.contains("'alice'"), "{message}");
        assert!(message.contains("stellar-agent-owner-default"), "{message}");
    }

    /// The same file, requested under an UNNAMED resolution: still refused,
    /// never replaced by the synthesized profile. `Default` provenance governs
    /// the absent-file fallback only; a file that exists and names another
    /// profile is a refusal on every provenance.
    #[test]
    fn a_mismatched_profile_is_not_replaced_by_synthesis_when_unnamed() {
        let copied = |_name: &str| {
            Ok(Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
                .with_profile_name("someone-else")
                .build())
        };

        let err = load_profile_or_synthesize_testnet_with(
            &resolved("default", ProfileNameSource::Default),
            copied,
        )
        .expect_err("a mismatched file must refuse even with no name supplied");
        assert!(matches!(err, ProfileAccessError::NameMismatch(_)));
    }

    /// A self-consistent profile passes: the control that proves the refusal
    /// above is not firing on every load.
    #[test]
    fn a_self_consistent_profile_is_not_refused() {
        let own = |name: &str| {
            Ok(Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
                .with_profile_name(name)
                .build())
        };

        let (profile, origin) = load_profile_or_synthesize_testnet_with(
            &resolved("alice", ProfileNameSource::Flag),
            own,
        )
        .expect("a profile that names itself must load");
        assert_eq!(origin, ProfileOrigin::Persisted);
        assert_eq!(
            profile.policy_owner_key_id.service,
            "stellar-agent-owner-alice"
        );
    }

    /// The synthesized zero-config profile reconciles against the name it was
    /// synthesized for, so the fallback is never refused by its own check.
    #[test]
    fn the_synthesized_profile_reconciles_against_its_own_name() {
        let not_found = |name: &str| {
            Err(profile_loader::ProfileLoadError::NotFound {
                name: name.to_owned(),
                path: std::path::PathBuf::from("/nonexistent"),
            })
        };

        let (profile, origin) = load_profile_or_synthesize_testnet_with(
            &resolved("default", ProfileNameSource::Default),
            not_found,
        )
        .expect("the zero-config fallback must still fire");
        assert_eq!(origin, ProfileOrigin::Synthesized);
        assert_eq!(
            stellar_agent_core::profile::name::profile_name_mismatch_refusal(&profile, "default"),
            None,
            "the synthesized profile must be self-consistent by construction"
        );
    }

    /// The reconciliation runs in the CALLER of an injected loader, so a
    /// closure that returns a mismatched profile without checking anything is
    /// still refused. A check inside the closure would be bypassed by every
    /// test that supplies one.
    #[test]
    fn the_injected_loader_is_not_where_the_reconciliation_lives() {
        let unchecked = |_name: &str| {
            Ok(Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
                .with_profile_name("default")
                .build())
        };

        let err = reconcile_loaded_profile(unchecked("ignored"), "alice")
            .expect_err("the caller reconciles what the closure returns");
        assert_eq!(err.code(), "profile.name_mismatch");
    }

    /// A `service` field without the owner-key prefix refuses rather than
    /// resolving to `default`. The MCP approval-store derivation resolves a
    /// prefix-less coordinate to the literal `"default"`; treating it as a
    /// valid name here would let a hand-written profile operate on the default
    /// profile's state under any requested name.
    #[test]
    fn a_service_without_the_prefix_refuses_rather_than_defaulting() {
        let hand_written = |_name: &str| {
            let mut profile = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
                .with_profile_name("default")
                .build();
            profile.policy_owner_key_id = stellar_agent_core::profile::schema::KeyringEntryRef::new(
                "hand-written",
                "default",
            );
            Ok(profile)
        };

        for requested in ["default", "alice"] {
            let err = load_profile_or_synthesize_testnet_with(
                &resolved(requested, ProfileNameSource::Flag),
                hand_written,
            )
            .expect_err("a prefix-less owner coordinate must refuse");
            assert_eq!(err.code(), "profile.name_mismatch");
            assert!(
                err.message(requested)
                    .contains("does not carry the 'stellar-agent-owner-' prefix"),
                "the refusal must explain the absent prefix"
            );
        }
    }

    /// The CLI renders the refusal under ITS state layout, not the MCP's.
    ///
    /// This binary keys the approval store, audit log, and window state on the
    /// requested name while the signed policy and owner key follow the derived
    /// one; a message claiming all state moves to the derived name would be
    /// untrue here.
    #[test]
    fn the_cli_refusal_states_the_cli_state_layout() {
        let copied = |_name: &str| {
            Ok(Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
                .with_profile_name("default")
                .build())
        };

        let err = load_profile_or_synthesize_testnet_with(
            &resolved("alice", ProfileNameSource::Flag),
            copied,
        )
        .expect_err("mismatch must refuse");
        let message = err.message("alice");
        assert!(
            message.contains("stay keyed on 'alice'"),
            "the CLI message must name the state that follows the requested name: {message}"
        );
        assert!(
            !message.contains("read and written under the derived name"),
            "the CLI must not ship the MCP's state-layout claim: {message}"
        );
        assert!(
            message.contains("profile init --profile alice"),
            "the recovery text is shared by both surfaces: {message}"
        );
    }

    /// The named constant and the typed variant's own code are the same string.
    ///
    /// The constant exists so the raw-code verbs do not have to build a
    /// throwaway `ValidationError` to read it; this keeps the two from drifting
    /// apart, which would split the wire code across the two rendering paths.
    #[test]
    fn the_mismatch_code_matches_the_typed_variant() {
        assert_eq!(
            PROFILE_NAME_MISMATCH_CODE,
            ValidationError::ProfileNameMismatch {
                detail: String::new()
            }
            .code()
        );
    }

    /// The mismatch message is path-redacted, exactly as the load message is.
    ///
    /// `policy_owner_key_id.service` is echoed verbatim and is operator-
    /// editable, so a home-directory path pasted into it would otherwise reach
    /// stdout through the refusal.
    #[test]
    fn the_mismatch_message_redacts_a_path_in_the_service_field() {
        let home_dir = std::env::var("HOME").expect("HOME is set in the test environment");
        let mut profile = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
            .with_profile_name("alice")
            .build();
        profile.policy_owner_key_id = stellar_agent_core::profile::schema::KeyringEntryRef::new(
            format!("{home_dir}/leaked/owner"),
            "default",
        );

        let err = reconcile_loaded_profile(Ok(profile), "alice")
            .expect_err("a prefix-less coordinate must refuse");
        let message = err.message("alice");
        assert!(
            !message.contains(&home_dir),
            "the refusal must not carry the operator's home directory: {message}"
        );
        assert!(
            message.contains("<HOME>"),
            "the home prefix must be replaced by the redaction marker, proving the field \
             was rendered and then redacted rather than absent by accident: {message}"
        );
        assert!(
            !err.to_string().contains(&home_dir),
            "the Display rendering must redact on the same terms: {err}"
        );
    }

    /// The mismatch keeps its own wire code through the typed-envelope path
    /// as well as the raw-code path, so an agent sees one code either way.
    #[test]
    fn the_mismatch_code_is_the_same_on_both_rendering_paths() {
        let copied = |_name: &str| {
            Ok(Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
                .with_profile_name("default")
                .build())
        };
        let err = load_profile_or_synthesize_testnet_with(
            &resolved("alice", ProfileNameSource::Flag),
            copied,
        )
        .expect_err("mismatch must refuse");

        let envelope = profile_access_envelope(&err, "alice");
        let rendered = envelope.error.as_ref().expect("error envelope");
        assert_eq!(rendered.code, "profile.name_mismatch");
        assert_eq!(rendered.code, err.code());
    }
}
