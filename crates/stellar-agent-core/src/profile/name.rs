//! Profile-name resolution, reconciliation, and path-component validation.
//!
//! Both binaries — `stellar-agent` and `stellar-agent-mcp` — select the profile
//! they operate on from the same two inputs, in the same order, and both turn
//! the resulting name into a filesystem path component. Keeping the resolver
//! and the validator here means neither the resolution order nor the safe-name
//! rule can drift between them.
//!
//! # Resolution order
//!
//! [`resolve_profile_name`] resolves an explicit argument first, then the
//! `STELLAR_AGENT_PROFILE` environment variable, then the literal `"default"`.
//! The order is the one documented in `docs/cli-reference/index.md`.
//!
//! # Provenance is part of the result
//!
//! The resolver returns [`ResolvedProfileName`], carrying the name **and** the
//! [`ProfileNameSource`] it came from. Callers that must behave differently for
//! an explicitly-named profile — the MCP server refuses to fall back to its
//! synthesised first-run profile when a name was given — key on the variant.
//! Comparing the resolved name against `"default"` is not equivalent: an
//! explicit `--profile default` is a named profile, and treating it as
//! unnamed reintroduces the fallback the refusal exists to prevent.
//!
//! # A profile also carries a name, and the two must agree
//!
//! A loaded [`Profile`] names itself: its `policy_owner_key_id.service` is
//! `<OWNER_KEY_SERVICE_PREFIX><profile>`, written by
//! [`KeyringEntryRef::default_owner_key`](crate::profile::schema::KeyringEntryRef::default_owner_key).
//! Both binaries derive per-profile state paths from that field rather than
//! from the name the file was loaded under, so a file whose owner coordinate
//! names another profile governs that other profile's state while reporting
//! the selected name.
//!
//! [`profile_name_mismatch_refusal`] is the single reconciliation both surfaces
//! apply. It lives here, beside the constructor of the coordinate it inverts,
//! so the two cannot drift. The refusal is independent of
//! `profile.policy.engine`: the derivations it guards run for every engine
//! kind, so attaching it to a V1-only path would skip `Noop` profiles — the
//! zero-ceremony configuration the getting-started flow recommends.
//!
//! The two surfaces do not lay their per-profile state out identically, so the
//! refusal message is rendered per surface through
//! [`ProfileNameMismatch::message`] and a [`ProfileStateLayout`] the caller
//! selects. A message that describes the wrong layout tells the operator
//! something untrue about their own files.

use crate::profile::schema::Profile;

/// Derives the approval store name from the owner key, falling back to default.
#[must_use]
pub fn profile_name_for_approval(profile: &Profile) -> String {
    derive_profile_name_from_owner_key(profile)
        .unwrap_or("default")
        .to_owned()
}

/// Quotes one argument for a POSIX shell.
#[must_use]
pub fn shell_word(word: &str) -> String {
    if !word.is_empty()
        && word
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_./:@-".contains(&b))
    {
        word.to_owned()
    } else {
        format!("'{}'", word.replace('\'', "'\\''"))
    }
}

/// Where a resolved profile name came from.
///
/// Returned as part of [`ResolvedProfileName`]. `Flag` and `Env` both mean the
/// operator named a profile; `Default` means neither input was supplied and the
/// literal `"default"` was substituted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileNameSource {
    /// An explicit command-line argument (`--profile <NAME>`).
    Flag,
    /// The `STELLAR_AGENT_PROFILE` environment variable.
    Env,
    /// Neither input was supplied; the name is the literal `"default"`.
    Default,
}

impl ProfileNameSource {
    /// Describes the selection source in a mainnet profile refusal.
    pub(crate) fn mainnet_selection_description(self) -> &'static str {
        match self {
            Self::Flag => "it was selected by `--profile`",
            Self::Env => "it was selected by the `STELLAR_AGENT_PROFILE` environment variable",
            Self::Default => "no `--profile` flag was given",
        }
    }

    /// Returns the stable short token for structured-log fields.
    ///
    /// Values are `"flag"`, `"env"`, and `"default"`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Flag => "flag",
            Self::Env => "env",
            Self::Default => "default",
        }
    }

    /// Returns `true` when the operator named a profile explicitly.
    ///
    /// Both [`Self::Flag`] and [`Self::Env`] are explicit; only [`Self::Default`]
    /// is not. This is the predicate the MCP server uses to decide whether a
    /// missing profile file may be replaced by the synthesised first-run
    /// profile.
    #[must_use]
    pub fn is_explicit(self) -> bool {
        !matches!(self, Self::Default)
    }
}

impl std::fmt::Display for ProfileNameSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A resolved profile name together with the input it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedProfileName {
    /// The effective profile name.
    pub name: String,
    /// Which input supplied it.
    pub source: ProfileNameSource,
}

impl ResolvedProfileName {
    /// Records an explicit profile name at a command-line argument boundary.
    #[must_use]
    pub fn from_flag(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            source: ProfileNameSource::Flag,
        }
    }
}

/// Requires an explicit profile flag for a mainnet profile.
/// `--profile default` has source `Flag` and passes this check.
/// The `Default` source never selects a mainnet profile.
///
/// # Errors
/// Returns `ProfileLoadError::MainnetRequiresExplicitProfile` for implicit mainnet selection.
pub fn check_mainnet_selection(
    profile: &Profile,
    resolved: &ResolvedProfileName,
) -> Result<(), super::loader::ProfileLoadError> {
    if profile.chain_id.is_mainnet() {
        match resolved.source {
            ProfileNameSource::Flag => {}
            ProfileNameSource::Env | ProfileNameSource::Default => {
                return Err(
                    super::loader::ProfileLoadError::MainnetRequiresExplicitProfile {
                        name: resolved.name.clone(),
                        named_by: resolved.source,
                    },
                );
            }
        }
    }
    Ok(())
}

/// Resolves the effective profile name from an explicit argument or the
/// `STELLAR_AGENT_PROFILE` environment variable, falling back to `"default"`.
///
/// Resolution order:
/// 1. `arg` if `Some`.
/// 2. `STELLAR_AGENT_PROFILE`.
/// 3. `"default"`.
///
/// The returned name is **not** validated as a path component; callers that
/// join it into a path either call [`validate_path_component_ascii_safe`]
/// themselves to refuse before doing work, or rely on the profile loader, which
/// validates before every join.
///
/// # Examples
///
/// ```text
/// resolve_profile_name(Some("alice")) // → { name: "alice", source: Flag }
/// resolve_profile_name(None)          // → env var (source: Env) or
///                                     //   { name: "default", source: Default }
/// ```
#[must_use]
pub fn resolve_profile_name(arg: Option<&str>) -> ResolvedProfileName {
    resolve_from_parts(arg, std::env::var(PROFILE_ENV_VAR).ok())
}

/// The environment variable naming the profile when no explicit argument is
/// supplied.
pub const PROFILE_ENV_VAR: &str = "STELLAR_AGENT_PROFILE";

/// Resolution table for [`resolve_profile_name`], with the environment read
/// lifted out.
///
/// Split from the public entry point so the whole table is unit-testable
/// without mutating process-global environment state, which this crate's
/// `#![forbid(unsafe_code)]` makes impossible in-crate under Rust 2024.
fn resolve_from_parts(arg: Option<&str>, env_value: Option<String>) -> ResolvedProfileName {
    if let Some(name) = arg {
        return ResolvedProfileName {
            name: name.to_owned(),
            source: ProfileNameSource::Flag,
        };
    }
    match env_value {
        Some(name) => ResolvedProfileName {
            name,
            source: ProfileNameSource::Env,
        },
        None => ResolvedProfileName {
            name: "default".to_owned(),
            source: ProfileNameSource::Default,
        },
    }
}

/// Validates that a string is safe to use as a filesystem path component.
///
/// Guards against path-traversal attacks on `--profile` and similar
/// operator-supplied arguments that become part of a file path.
///
/// Rules:
/// - Non-empty.
/// - At most 64 characters.
/// - Only printable ASCII (0x20–0x7E), no control characters.
/// - No `/`, `\`, `:`, `..` (path separator or traversal characters).
/// - Not equal to `.` or `..`.
/// - Does not begin with `-`.
/// - Does not name a Windows reserved device.
/// - Is not exactly `CONIN$` or `CONOUT$`.
///
/// A leading `-` is refused because the name has to be typed back into the
/// commands that operate on the profile, where an argument parser reads it as
/// the next flag rather than as the value: `stellar-agent profile init
/// --profile -x` is an unexpected-argument error from clap, and the MCP
/// server's parser reports the same token as a missing value. A name the wallet
/// accepted here could not be used to select the profile it created.
///
/// A Windows reserved device name (`CON`, `PRN`, `AUX`, `NUL`, `COM1`-`COM9`,
/// `LPT1`-`LPT9`, in any letter case, with or without an extension, and with
/// trailing spaces) is refused on every platform. `<profile_dir>/NUL.toml` opens
/// the NUL device on Windows rather than a file, so a write to that path is
/// discarded and a read returns nothing while the path itself still reports as
/// present; refusing the name everywhere keeps a profile authored on one
/// platform usable on the others.
///
/// `CONIN$` and `CONOUT$` are refused as whole names, and only as whole names.
/// Windows resolves them through the console layer on an exact match, so
/// `CONIN$.toml` is an ordinary file and stays a valid profile name, while a
/// bare `CONIN$` reaches the filesystem unprefixed as the per-profile
/// counterparty-cache directory component.
///
/// # Errors
///
/// Returns a human-readable error description on validation failure.
///
/// # Examples
///
/// ```text
/// validate_path_component_ascii_safe("default")   // Ok(())
/// validate_path_component_ascii_safe("alice-prod") // Ok(())
/// validate_path_component_ascii_safe("../etc")    // Err — path traversal
/// validate_path_component_ascii_safe("..")        // Err — reserved name
/// validate_path_component_ascii_safe("")          // Err — empty
/// validate_path_component_ascii_safe("-x")        // Err — leading '-'
/// validate_path_component_ascii_safe("nul.toml")  // Err — Windows device
/// validate_path_component_ascii_safe("CONIN$")    // Err — console device
/// ```
pub fn validate_path_component_ascii_safe(s: &str) -> Result<(), &'static str> {
    if s.is_empty() {
        return Err("must not be empty");
    }
    if s.len() > 64 {
        return Err("must be at most 64 characters");
    }
    if s == "." || s == ".." {
        return Err("must not be '.' or '..'");
    }
    for ch in s.chars() {
        if !ch.is_ascii() || ch.is_ascii_control() {
            return Err("must contain only printable ASCII characters");
        }
        if matches!(ch, '/' | '\\' | ':') {
            return Err(r"must not contain '/', '\', or ':' characters");
        }
    }
    // Reject any embedded `..` (e.g. "foo../bar").
    if s.contains("..") {
        return Err("must not contain '..' (path traversal)");
    }
    if s.starts_with('-') {
        return Err("must not begin with '-'");
    }
    if let Some(refusal) = windows_reserved_device_refusal(s) {
        return Err(refusal);
    }
    if let Some(refusal) = windows_console_device_refusal(s) {
        return Err(refusal);
    }
    Ok(())
}

/// Expands to a device table, pairing each device with the refusal that names
/// it. `$kind` is the adjective the refusal uses for that family.
///
/// The pairing is generated rather than written out so a row's refusal cannot
/// name a device other than the one that row matches.
macro_rules! windows_device_table {
    ($kind:literal; $($device:literal),+ $(,)?) => {
        [$((
            $device,
            concat!("must not be the Windows ", $kind, " device name '", $device, "'"),
        )),+]
    };
}

/// Every name NT resolves to a DOS device, paired with the refusal naming it.
///
/// `COM0`, `COM10`, and `LPT0` are absent because NT does not reserve them. The
/// superscript `COM¹` / `COM²` / `COM³` forms are absent because both consumers
/// of this table exclude non-ASCII input before reaching it — the validator by
/// its printable-ASCII rule, the path builders by mapping every character
/// outside `[A-Za-z0-9_-]` to `_`.
///
/// `CONIN$` and `CONOUT$` are not here. NT's DOS-device rule does not name them:
/// the console layer resolves them on an exact, unprefixed name, with no
/// truncation at `.` and no trailing-space trim, so matching them by stem would
/// refuse `CONIN$.toml` — a name Windows treats as an ordinary file.
/// [`WINDOWS_CONSOLE_DEVICES`] carries them under the rule they actually follow.
const WINDOWS_RESERVED_DEVICES: [(&str, &str); 22] = windows_device_table![
    "reserved";
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// The console device names, paired with the refusal naming each one.
///
/// Separate from [`WINDOWS_RESERVED_DEVICES`] because they resolve under a
/// different rule — exact name, no truncation, no trimming — not because they
/// are a lesser class of device.
const WINDOWS_CONSOLE_DEVICES: [(&str, &str); 2] =
    windows_device_table!["console"; "CONIN$", "CONOUT$"];

/// Returns the refusal for the Windows reserved device `name` resolves to, or
/// `None` when it resolves to none.
///
/// Windows resolves a reserved name to a device in any letter case and wherever
/// the name sits in a path. NT reduces the name to the device it names by
/// truncating at the first `.` or `:` and then stripping trailing spaces from
/// what is left, and this comparison applies the two steps in that order.
///
/// The order is the whole point. `"nul .toml"` ends in `l`, so trimming first
/// would change nothing and the split would then yield `"nul "`, which matches
/// no device — yet NT truncates it to `"nul "`, strips the space, and opens the
/// device. Splitting first and trimming second answers every case a
/// trim-then-split reading catches, plus that one.
///
/// `:` is in the split set for the same parity reason. The validator refuses `:`
/// earlier under its path-separator rule, so it can only be reached through the
/// path builders, but a predicate that claims to answer "does NT resolve this to
/// a device" has to truncate where NT truncates.
///
/// This is the crate's single reserved-name table, and its two consumers answer
/// differently: [`validate_path_component_ascii_safe`] refuses the name, while
/// the audit-log and policy-window path builders in
/// [`crate::profile::schema`] sanitise it by prefixing `_`. Reading one table is
/// what keeps the two from disagreeing about what is reserved. The path builders
/// pass a stem in which every character outside `[A-Za-z0-9_-]` has already
/// become `_`, so for them neither the split nor the trim can fire.
#[must_use]
pub(crate) fn windows_reserved_device_refusal(name: &str) -> Option<&'static str> {
    let truncated = name
        .split_once(['.', ':'])
        .map_or(name, |(head, _)| head)
        .trim_end_matches(' ');
    WINDOWS_RESERVED_DEVICES
        .iter()
        .find(|(device, _)| truncated.eq_ignore_ascii_case(device))
        .map(|&(_, refusal)| refusal)
}

/// Returns the refusal for the Windows console device `name` IS, or `None` when
/// it is neither.
///
/// The whole name is compared, in any letter case, with no truncation at `.` or
/// `:` and no trailing-space trim: that is how the console layer resolves
/// `CONIN$` and `CONOUT$`, and it is the difference from
/// [`windows_reserved_device_refusal`]. `CONIN$.toml`, `CONIN$ `, and `myconin$`
/// are ordinary files on Windows and stay valid profile names.
///
/// The shape this guards is `<data_root>/counterparty/<profile>`, the one path a
/// profile name reaches as a bare component. Every other derived path appends an
/// extension — `<name>.toml`, `<stem>.jsonl`, `<stem>.window`,
/// `<profile>-cert.pem` — which is exactly why a stem match would be the wrong
/// rule here: it would refuse names that are unreachable as devices.
///
/// The path builders in [`crate::profile::schema`] do not consult this and do
/// not need to: they map every character outside `[A-Za-z0-9_-]` to `_`, so
/// `CONIN$` reaches them as `CONIN_`, which names no device.
#[must_use]
pub(crate) fn windows_console_device_refusal(name: &str) -> Option<&'static str> {
    WINDOWS_CONSOLE_DEVICES
        .iter()
        .find(|(device, _)| name.eq_ignore_ascii_case(device))
        .map(|&(_, refusal)| refusal)
}

// ──────────────────────────────────────────────────────────────────────────────
// Reconciliation: the selected name vs. the name the profile carries
// ──────────────────────────────────────────────────────────────────────────────

/// The keyring `service` prefix every profile's owner-key coordinate carries.
///
/// [`KeyringEntryRef::default_owner_key`](crate::profile::schema::KeyringEntryRef::default_owner_key)
/// builds `<prefix><profile>` and is the only writer of the field; both
/// binaries recover the profile name by stripping this prefix, because the
/// coordinate's `account` half is always the literal `"default"` and is
/// therefore useless as a discriminator.
///
/// This is the single definition. A second copy in either binary would be a
/// silent trust-anchor split the moment one of them changed.
pub const OWNER_KEY_SERVICE_PREFIX: &str = "stellar-agent-owner-";

/// Returns the profile name `profile`'s owner-key coordinate names, or `None`
/// when the coordinate does not carry [`OWNER_KEY_SERVICE_PREFIX`].
///
/// `None` means the profile was not built by `profile init` and no name can be
/// recovered from it. It is never equivalent to `Some("default")`: resolving a
/// prefix-less coordinate to the default profile is exactly the silent
/// cross-profile access [`profile_name_mismatch_refusal`] exists to refuse.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::profile::name::derive_profile_name_from_owner_key;
/// use stellar_agent_core::profile::schema::Profile;
///
/// let profile = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
///     .with_profile_name("alice")
///     .build();
/// assert_eq!(derive_profile_name_from_owner_key(&profile), Some("alice"));
/// ```
#[must_use]
pub fn derive_profile_name_from_owner_key(profile: &Profile) -> Option<&str> {
    profile
        .policy_owner_key_id
        .service
        .strip_prefix(OWNER_KEY_SERVICE_PREFIX)
}

/// Which surface's per-profile state layout a [`ProfileNameMismatch`] message
/// describes.
///
/// The variants name the layout, not the binary, so each one can be checked
/// against the code that implements it. Passing the wrong variant produces a
/// refusal that misdescribes where the operator's state actually lives.
/// `#[non_exhaustive]`: a third surface with a third layout must be an additive
/// change for downstream crates, not a breaking one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProfileStateLayout {
    /// Every per-profile store resolves through the derived name — the signed
    /// policy file, the pending-approval store, and the policy-window state
    /// among them. `stellar-agent-mcp`'s layout.
    DerivedThroughout,
    /// The signed policy file and the owner-key keyring entry resolve through
    /// the derived name, while the pending-approval store and the
    /// policy-window state FILE key on the requested name. `stellar-agent`'s
    /// layout: a mismatch splits the operator's state across two profiles
    /// rather than moving all of it to one.
    ///
    /// Two stores are deliberately absent from that list because neither is
    /// unconditionally requested-keyed. `audit_log_path` is a serialized field:
    /// a copied file carries the SOURCE profile's path, and only a file that
    /// omits the field gets a name-derived one. The window-state file is
    /// requested-keyed, but the HMAC and anti-rollback keys that guard it come
    /// from the file's own `policy_window_state_key_id`. Claiming either as
    /// "stays with the requested profile" would be false for the copied-file
    /// case this refusal exists for.
    PolicyDerivedStateRequested,
}

impl ProfileStateLayout {
    /// Renders the clause describing what a mismatch does to per-profile state
    /// under this layout.
    fn consequence_clause(self) -> &'static str {
        match self {
            Self::DerivedThroughout => {
                "the signed policy file, pending-approval store, and policy-window \
                 state would be read and written under the name that field derives, \
                 not the selected one"
            }
            Self::PolicyDerivedStateRequested => {
                "the signed policy file and the owner-key keyring entry would be \
                 read under the name that field derives while the pending-approval \
                 store and the policy-window state file stay keyed on the selected \
                 name, so the run would be governed by one profile's policy and \
                 accounted against another's state"
            }
        }
    }
}

/// A loaded profile whose owner-key coordinate names a different profile than
/// the one the operator selected.
///
/// The refusal names the field the operator edits and the recovery, never the
/// selected name, the derived name, or the stored `service` value: the field
/// is operator-edited text that can hold anything, and the selected name is
/// the operator's own input. Render it with [`Self::message`] to state the
/// calling surface's own state layout; the [`std::fmt::Display`] rendering is
/// layout-independent and omits that clause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileNameMismatch {
    /// Whether `policy_owner_key_id.service` carries
    /// [`OWNER_KEY_SERVICE_PREFIX`], so that it names some other profile.
    names_another_profile: bool,
}

impl ProfileNameMismatch {
    /// Whether the loaded file's owner-key coordinate carries
    /// [`OWNER_KEY_SERVICE_PREFIX`] and so names another profile; `false`
    /// when no profile name can be derived from it.
    #[must_use]
    pub fn names_another_profile(&self) -> bool {
        self.names_another_profile
    }

    /// Renders the operator-facing refusal for a surface with the given state
    /// layout.
    ///
    /// The text names the offending field, states what the mismatch does to
    /// per-profile state under `layout`, and names the two recovery paths.
    #[must_use]
    pub fn message(&self, layout: ProfileStateLayout) -> String {
        format!(
            "{self}; {}. A profile file renamed or copied from another profile must \
             be re-created with `stellar-agent profile init --profile <name>`, or its \
             policy_owner_key_id.service corrected to '{OWNER_KEY_SERVICE_PREFIX}<name>', \
             where <name> is the selected profile name",
            layout.consequence_clause()
        )
    }
}

impl std::fmt::Display for ProfileNameMismatch {
    /// Renders the layout-independent half of the refusal: what the selected
    /// profile's owner coordinate says about the profile it belongs to.
    ///
    /// The consequence clause is layout-dependent and therefore omitted here;
    /// use [`ProfileNameMismatch::message`] to render it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.names_another_profile {
            f.write_str(
                "the selected profile's policy_owner_key_id.service names a different \
                 profile",
            )
        } else {
            write!(
                f,
                "the selected profile's policy_owner_key_id.service does not carry the \
                 '{OWNER_KEY_SERVICE_PREFIX}' prefix a profile name is derived from"
            )
        }
    }
}

/// Returns a refusal when the selected profile name disagrees with the name
/// derived from the loaded profile's `policy_owner_key_id.service`, or `None`
/// when the two agree.
///
/// Both binaries derive the name they use for per-profile state — the signed
/// policy file, the pending-approval store, the policy-window state — from the
/// profile's *contents* rather than from the name it was loaded under. When
/// those two disagree, a profile loaded as `alice` reads `default`'s signed
/// policy. Reconciling them before any of those derivations run is what keeps
/// the selected name and the state it governs the same profile.
///
/// An absent prefix is a mismatch, not a fallback: the approval-store
/// derivation resolves a prefix-less `service` to the literal `"default"`,
/// which is the same silent cross-profile access under a different guise.
///
/// The check is independent of `profile.policy.engine`. The name derivations it
/// guards run for every engine kind, so attaching it to a V1 policy-engine path
/// would skip `Noop` profiles — the zero-ceremony configuration the
/// getting-started flow recommends, and precisely the case that reaches the
/// approval-store derivation with no other guard in front of it.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::profile::name::{
///     ProfileStateLayout, profile_name_mismatch_refusal,
/// };
/// use stellar_agent_core::profile::schema::Profile;
///
/// let copied = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
///     .with_profile_name("default")
///     .build();
/// assert_eq!(profile_name_mismatch_refusal(&copied, "default"), None);
///
/// let refusal = profile_name_mismatch_refusal(&copied, "alice")
///     .expect("a profile naming 'default' must not serve as 'alice'");
/// assert!(refusal.names_another_profile());
/// assert!(
///     refusal
///         .message(ProfileStateLayout::DerivedThroughout)
///         .contains("profile init --profile <name>")
/// );
/// ```
#[must_use]
pub fn profile_name_mismatch_refusal(
    profile: &Profile,
    requested_name: &str,
) -> Option<ProfileNameMismatch> {
    let derived = derive_profile_name_from_owner_key(profile);
    if derived == Some(requested_name) {
        return None;
    }
    Some(ProfileNameMismatch {
        names_another_profile: derived.is_some(),
    })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;

    // ── validate_path_component_ascii_safe ───────────────────────────────────

    fn selection_profile(chain: super::super::caip2::Caip2, name: &str) -> Profile {
        let mut profile = Profile::builder_testnet_named(name, "s", "a", "n", "a").build();
        profile.chain_id = chain;
        profile
    }

    #[test]
    fn mainnet_selection_flag_passes_for_both_chains_and_default_name() {
        use super::super::caip2::Caip2;
        for chain in [Caip2::Testnet, Caip2::Mainnet] {
            for name in ["alice", "default"] {
                let resolved = ResolvedProfileName::from_flag(name);
                assert_eq!(resolved.source, ProfileNameSource::Flag);
                assert_eq!(resolved.name, name);
                assert!(
                    check_mainnet_selection(&selection_profile(chain, name), &resolved).is_ok()
                );
            }
        }
    }

    #[test]
    fn mainnet_selection_environment_refuses() {
        use super::super::caip2::Caip2;
        let resolved = resolve_from_parts(None, Some("alice".to_owned()));
        let err = check_mainnet_selection(&selection_profile(Caip2::Mainnet, "alice"), &resolved)
            .expect_err("implicit mainnet selection refuses");
        assert!(matches!(
            err,
            super::super::loader::ProfileLoadError::MainnetRequiresExplicitProfile {
                named_by: ProfileNameSource::Env,
                ..
            }
        ));
        assert!(
            err.to_string()
                .contains("`STELLAR_AGENT_PROFILE` environment variable")
        );
    }

    #[test]
    fn mainnet_selection_default_refuses() {
        use super::super::caip2::Caip2;
        let resolved = resolve_from_parts(None, None);
        let err = check_mainnet_selection(&selection_profile(Caip2::Mainnet, "default"), &resolved)
            .expect_err("implicit mainnet selection refuses");
        assert!(matches!(
            err,
            super::super::loader::ProfileLoadError::MainnetRequiresExplicitProfile {
                named_by: ProfileNameSource::Default,
                ..
            }
        ));
        assert!(err.to_string().contains("no `--profile` flag was given"));
    }

    #[test]
    fn testnet_selection_environment_and_default_pass() {
        use super::super::caip2::Caip2;
        for resolved in [
            resolve_from_parts(None, Some("alice".to_owned())),
            resolve_from_parts(None, None),
        ] {
            assert!(
                check_mainnet_selection(
                    &selection_profile(Caip2::Testnet, &resolved.name),
                    &resolved
                )
                .is_ok()
            );
        }
    }

    #[test]
    fn validate_path_component_accepts_simple_names() {
        assert!(validate_path_component_ascii_safe("default").is_ok());
        assert!(validate_path_component_ascii_safe("alice-prod").is_ok());
        assert!(validate_path_component_ascii_safe("profile123").is_ok());
    }

    #[test]
    fn validate_path_component_rejects_empty() {
        assert!(validate_path_component_ascii_safe("").is_err());
    }

    #[test]
    fn validate_path_component_rejects_dot_dot() {
        assert!(validate_path_component_ascii_safe("..").is_err());
    }

    #[test]
    fn validate_path_component_rejects_traversal_slash() {
        assert!(validate_path_component_ascii_safe("../foo").is_err());
    }

    #[test]
    fn validate_path_component_rejects_slash() {
        assert!(validate_path_component_ascii_safe("a/b").is_err());
    }

    #[test]
    fn validate_path_component_rejects_backslash() {
        assert!(validate_path_component_ascii_safe("a\\b").is_err());
    }

    #[test]
    fn validate_path_component_rejects_embedded_dot_dot() {
        assert!(validate_path_component_ascii_safe("foo..bar").is_err());
    }

    #[test]
    fn validate_path_component_rejects_over_64_chars() {
        let long = "a".repeat(65);
        assert!(validate_path_component_ascii_safe(&long).is_err());
    }

    // ── validate_path_component_ascii_safe: Windows reserved device names ────

    /// Returns `name` with every second character lower-cased, so a validator
    /// that compared case-sensitively passes neither the upper nor the lower
    /// form by accident.
    fn alternating_case(name: &str) -> String {
        name.char_indices()
            .map(|(index, ch)| {
                if index % 2 == 0 {
                    ch.to_ascii_uppercase()
                } else {
                    ch.to_ascii_lowercase()
                }
            })
            .collect()
    }

    #[test]
    fn every_windows_reserved_device_is_rejected_in_any_letter_case() {
        for (device, _) in WINDOWS_RESERVED_DEVICES {
            for form in [
                device.to_ascii_uppercase(),
                device.to_ascii_lowercase(),
                alternating_case(device),
            ] {
                let reason = validate_path_component_ascii_safe(&form).expect_err(
                    "a Windows reserved device name must be refused in any letter case",
                );
                assert!(
                    reason.contains(device),
                    "the refusal for '{form}' must name the device it matched: {reason}"
                );
            }
        }
    }

    #[test]
    fn a_windows_reserved_device_is_rejected_with_an_extension() {
        // Windows resolves `NUL.toml` to the device, not to a file, so an
        // extension does not make a reserved name usable.
        for (device, _) in WINDOWS_RESERVED_DEVICES {
            for suffix in [".toml", ".jsonl", ".a.b"] {
                let name = format!("{}{suffix}", device.to_ascii_lowercase());
                let reason = validate_path_component_ascii_safe(&name)
                    .expect_err("a reserved device name with an extension must be refused");
                assert!(
                    reason.contains(device),
                    "the refusal for '{name}' must name the device it matched: {reason}"
                );
            }
        }
    }

    #[test]
    fn a_windows_reserved_device_is_rejected_with_trailing_spaces_and_dots() {
        // NT truncates at the first `.` and strips trailing spaces from what is
        // left, in that order. `"nul .toml"` is the case that separates the two
        // orders: it ends in `l`, so a trim-then-split reading leaves the stem
        // `"nul "` and accepts the name, while NT opens the device.
        for name in [
            "nul ",
            "nul.",
            "NUL  ",
            "nul. ",
            "nul .",
            "nul .toml",
            "con .cfg",
            "com1 .x",
            "LPT9   .jsonl",
            "nul.toml ",
            "COM1.",
            "lpt9 .",
        ] {
            let reason = validate_path_component_ascii_safe(name).expect_err(
                "trailing spaces and dots must not smuggle a reserved device name through",
            );
            assert!(
                reason.contains("Windows reserved device name"),
                "'{name}' must be refused as a device, not for another reason: {reason}"
            );
        }

        // A doubled dot is refused earlier, by the traversal rule, whatever the
        // stem in front of it: the two refusals overlap here and traversal is
        // the stronger claim about the name.
        assert_eq!(
            validate_path_component_ascii_safe("NUL..")
                .expect_err("a name carrying '..' must be refused"),
            "must not contain '..' (path traversal)"
        );
    }

    #[test]
    fn names_that_only_resemble_a_reserved_device_are_accepted() {
        // `COM0`, `COM10`, and `LPT0` are not devices on Windows, and neither
        // is any name that merely starts with a device name.
        for name in [
            "COM0",
            "com0",
            "COM10",
            "com10",
            "LPT0",
            "lpt0",
            "connect",
            "prolog",
            "auxiliary",
            "nullify",
            "combo",
            "laptop",
            "com1x",
            "nul-1",
            "console.toml",
            "nul x",
            "x nul",
        ] {
            assert!(
                validate_path_component_ascii_safe(name).is_ok(),
                "'{name}' is not a Windows device and must stay a valid profile name"
            );
        }
    }

    // ── validate_path_component_ascii_safe: console device names ─────────────

    #[test]
    fn the_console_device_names_are_rejected_in_any_letter_case() {
        // A profile name reaches the filesystem unprefixed as the
        // counterparty-cache directory component, which is the shape the
        // console layer resolves.
        for (name, device) in [
            ("CONIN$", "CONIN$"),
            ("conin$", "CONIN$"),
            ("CoNiN$", "CONIN$"),
            ("CONOUT$", "CONOUT$"),
            ("conout$", "CONOUT$"),
        ] {
            let reason = validate_path_component_ascii_safe(name)
                .expect_err("a console device name must be refused in any letter case");
            assert_eq!(
                reason,
                format!("must not be the Windows console device name '{device}'")
            );
        }
    }

    #[test]
    fn only_the_exact_console_device_name_is_rejected() {
        // The console layer matches the whole name — no truncation at `.`, no
        // trailing-space trim — so each of these is an ordinary file on Windows.
        // They pass only if the console check is exact rather than stem-matched.
        for name in ["conin$.toml", "conin$ ", "myconin$", "conin$x", "conout$.x"] {
            assert!(
                validate_path_component_ascii_safe(name).is_ok(),
                "'{name}' is not the console device and must stay a valid profile name"
            );
        }
    }

    #[test]
    fn a_leading_dot_does_not_make_the_extension_the_stem() {
        // NT truncates at the first `.`, so `.nul` reduces to the empty name and
        // resolves to no device: the device has to be what precedes the dot.
        assert!(validate_path_component_ascii_safe(".nul").is_ok());
    }

    // ── validate_path_component_ascii_safe: leading '-' ──────────────────────

    #[test]
    fn a_leading_dash_is_rejected() {
        for name in ["-x", "-", "--profile", "-rf"] {
            let reason = validate_path_component_ascii_safe(name)
                .expect_err("a name beginning with '-' must be refused");
            assert_eq!(reason, "must not begin with '-'");
        }
    }

    #[test]
    fn dashes_anywhere_but_the_first_character_are_accepted() {
        for name in ["x-", "a-b", "smoke-fp2", "alice-prod", "a--b"] {
            assert!(
                validate_path_component_ascii_safe(name).is_ok(),
                "'{name}' carries a dash away from the first character and must be accepted"
            );
        }
    }

    // ── windows_reserved_device_refusal / windows_console_device_refusal ─────

    #[test]
    fn the_console_device_table_holds_exactly_the_two_console_names() {
        let devices: Vec<&str> = WINDOWS_CONSOLE_DEVICES
            .iter()
            .map(|&(device, _)| device)
            .collect();
        assert_eq!(devices, vec!["CONIN$", "CONOUT$"]);
    }

    #[test]
    fn the_path_builders_never_see_a_console_device_name() {
        // `audit_log_file_stem` maps `$` to `_`, so `CONIN$` reaches the path
        // builders as `CONIN_`. The console check is therefore the validator's
        // alone, and the sanitising consumers cannot be affected by it.
        assert!(windows_console_device_refusal("CONIN$").is_some());
        assert!(windows_console_device_refusal("CONIN_").is_none());
        assert!(windows_reserved_device_refusal("CONIN$").is_none());
        assert!(windows_reserved_device_refusal("CONIN_").is_none());
    }

    #[test]
    fn the_reserved_device_table_holds_exactly_the_windows_devices() {
        let devices: Vec<&str> = WINDOWS_RESERVED_DEVICES
            .iter()
            .map(|&(device, _)| device)
            .collect();
        assert_eq!(
            devices,
            vec![
                "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
                "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8",
                "LPT9",
            ]
        );
    }

    #[test]
    fn the_sanitised_stem_shape_the_path_builders_pass_is_answered_identically() {
        // `audit_log_file_stem` maps every character outside `[A-Za-z0-9_-]` to
        // `_` before consulting this table, so its input can carry neither a
        // `.` nor a trailing space. Pinning both shapes keeps the shared table
        // from changing the path builders' answers.
        assert!(windows_reserved_device_refusal("CON").is_some());
        assert!(windows_reserved_device_refusal("_CON").is_none());
        assert!(windows_reserved_device_refusal("CON_toml").is_none());
        assert!(windows_reserved_device_refusal("connect").is_none());
    }

    #[test]
    fn the_predicate_truncates_at_a_colon_the_way_nt_does() {
        // NT truncates at `:` as well as `.`, so an alternate-data-stream name
        // resolves to the device in front of it. The validator refuses `:` under
        // its path-separator rule before this runs, so the parity is pinned on
        // the predicate itself — the surface the path builders share.
        assert!(windows_reserved_device_refusal("nul:stream").is_some());
        assert!(windows_reserved_device_refusal("nul :stream").is_some());
        assert!(windows_reserved_device_refusal("connect:stream").is_none());
        assert!(
            validate_path_component_ascii_safe("nul:stream")
                .expect_err("a name carrying ':' must be refused")
                .contains("':'"),
            "the validator refuses ':' before the device table is reached"
        );
    }

    // ── resolve_profile_name ─────────────────────────────────────────────────

    #[test]
    fn arg_wins_and_reports_flag() {
        let resolved = resolve_from_parts(Some("myprofile"), None);
        assert_eq!(resolved.name, "myprofile");
        assert_eq!(resolved.source, ProfileNameSource::Flag);
    }

    #[test]
    fn env_is_used_when_no_arg() {
        let resolved = resolve_from_parts(None, Some("from-env".to_owned()));
        assert_eq!(resolved.name, "from-env");
        assert_eq!(resolved.source, ProfileNameSource::Env);
    }

    #[test]
    fn arg_beats_env() {
        let resolved = resolve_from_parts(Some("explicit"), Some("from-env".to_owned()));
        assert_eq!(resolved.name, "explicit");
        assert_eq!(resolved.source, ProfileNameSource::Flag);
    }

    #[test]
    fn neither_input_falls_back_to_default() {
        let resolved = resolve_from_parts(None, None);
        assert_eq!(resolved.name, "default");
        assert_eq!(resolved.source, ProfileNameSource::Default);
    }

    #[test]
    fn explicit_default_name_is_not_the_default_source() {
        // The distinction the MCP server's no-fallback rule depends on: an
        // explicitly-named `default` is a named profile, not an absent name.
        // Both explicit inputs must report an explicit source even though the
        // resolved string is identical to the fallback.
        let from_flag = resolve_from_parts(Some("default"), None);
        assert_eq!(from_flag.name, "default");
        assert_eq!(from_flag.source, ProfileNameSource::Flag);
        assert!(from_flag.source.is_explicit());

        let from_env = resolve_from_parts(None, Some("default".to_owned()));
        assert_eq!(from_env.name, "default");
        assert_eq!(from_env.source, ProfileNameSource::Env);
        assert!(from_env.source.is_explicit());
    }

    #[test]
    fn public_entry_point_honours_the_arg_without_reading_the_environment() {
        // Covers the wiring from `resolve_profile_name` into the table above
        // for the one arm that is independent of ambient environment state.
        let resolved = resolve_profile_name(Some("acme"));
        assert_eq!(resolved.name, "acme");
        assert_eq!(resolved.source, ProfileNameSource::Flag);
    }

    #[test]
    fn source_tokens_are_stable() {
        assert_eq!(ProfileNameSource::Flag.as_str(), "flag");
        assert_eq!(ProfileNameSource::Env.as_str(), "env");
        assert_eq!(ProfileNameSource::Default.as_str(), "default");
        assert!(!ProfileNameSource::Default.is_explicit());
    }

    // ── profile_name_mismatch_refusal ────────────────────────────────────────

    /// Builds a profile whose per-profile keyring coordinates are derived from
    /// `name`, as `profile init --profile <name>` writes them.
    fn named_profile(name: &str) -> Profile {
        Profile::builder_testnet("svc", "acct", "nonce-svc", "nonce-acct")
            .with_profile_name(name)
            .build()
    }

    #[test]
    fn matching_names_produce_no_refusal() {
        let profile = named_profile("alice");
        assert_eq!(profile_name_mismatch_refusal(&profile, "alice"), None);
    }

    #[test]
    fn copied_profile_file_refuses_and_names_the_field() {
        // The realistic path: `default.toml` copied to `alice.toml` without
        // re-deriving its keyring coordinates.
        let profile = named_profile("default");
        let refusal = profile_name_mismatch_refusal(&profile, "alice")
            .expect("a profile naming 'default' must not serve as 'alice'");

        assert!(refusal.names_another_profile());

        for message in [
            refusal.message(ProfileStateLayout::DerivedThroughout),
            refusal.message(ProfileStateLayout::PolicyDerivedStateRequested),
        ] {
            assert!(
                message.contains("policy_owner_key_id.service names a different profile"),
                "refusal must name the offending field: {message}"
            );
            assert!(
                message.contains("profile init --profile <name>"),
                "refusal must name the recovery command: {message}"
            );
            assert!(
                message.contains(
                    "policy_owner_key_id.service corrected to 'stellar-agent-owner-<name>'"
                ),
                "refusal must name the field-edit recovery path: {message}"
            );
            for value in ["'alice'", "'default'", "stellar-agent-owner-default"] {
                assert!(
                    !message.contains(value),
                    "refusal must not repeat a name or the stored service: {message}"
                );
            }
        }
    }

    /// A seed pasted into the owner-key coordinate or typed as the profile
    /// name never reaches the refusal, its `Debug`, or either layout's text.
    #[test]
    fn a_mismatch_never_repeats_the_service_or_the_name() {
        use stellar_agent_test_support::rejected_value::{assert_no_marker_in_text, seed_marker};
        let seed = seed_marker();
        let mut profile = named_profile("alice");
        let named_by_seed = format!("{OWNER_KEY_SERVICE_PREFIX}{seed}");
        let named_alice = format!("{OWNER_KEY_SERVICE_PREFIX}alice");
        for (service, requested) in [
            (named_by_seed.as_str(), "alice"),
            (seed.as_str(), "alice"),
            (seed.as_str(), seed.as_str()),
            (named_alice.as_str(), seed.as_str()),
        ] {
            profile.policy_owner_key_id =
                crate::profile::schema::KeyringEntryRef::new(service, "default");
            let refusal = profile_name_mismatch_refusal(&profile, requested)
                .expect("the coordinate names another profile or none");
            assert_no_marker_in_text(&format!("{refusal} {refusal:?}"), &seed);
            for layout in [
                ProfileStateLayout::DerivedThroughout,
                ProfileStateLayout::PolicyDerivedStateRequested,
            ] {
                assert_no_marker_in_text(&refusal.message(layout), &seed);
            }
        }
    }

    #[test]
    fn each_layout_states_its_own_state_placement() {
        // The two surfaces do not key their per-profile state the same way, so
        // one message cannot be truthful for both. The MCP reads and writes all
        // of it under the derived name; the CLI keys the approval store and
        // window state on the SELECTED name while the signed policy and owner
        // key follow the derived one.
        let profile = named_profile("default");
        let refusal =
            profile_name_mismatch_refusal(&profile, "alice").expect("mismatch must be reported");

        let derived_throughout = refusal.message(ProfileStateLayout::DerivedThroughout);
        assert!(
            derived_throughout.contains("read and written under the name that field derives"),
            "the derived-throughout layout must say all state moves: {derived_throughout}"
        );
        assert!(
            !derived_throughout.contains("stay keyed on"),
            "the derived-throughout layout must not claim a split: {derived_throughout}"
        );

        let split = refusal.message(ProfileStateLayout::PolicyDerivedStateRequested);
        assert!(
            split.contains("stay keyed on the selected name"),
            "the split layout must name the state that follows the selected name: {split}"
        );
        assert!(
            !split.contains("read and written under the name that field derives"),
            "the split layout must not repeat the derived-throughout claim: {split}"
        );
    }

    #[test]
    fn noop_engine_profile_is_checked_too() {
        // The check must not be attached to the V1 policy-engine derivation:
        // Noop profiles never reach it, yet the approval-store derivation —
        // which resolves a mismatch to `default` — runs for every engine.
        let mut profile = named_profile("default");
        profile.policy.engine = crate::profile::schema::PolicyEngineKind::Noop;
        let refusal = profile_name_mismatch_refusal(&profile, "alice")
            .expect("a Noop-engine profile must be reconciled exactly like a V1 one");
        assert!(
            refusal
                .message(ProfileStateLayout::PolicyDerivedStateRequested)
                .contains("policy_owner_key_id.service names a different profile")
        );
    }

    #[test]
    fn absent_owner_key_prefix_is_a_mismatch_not_a_default() {
        let mut profile = named_profile("alice");
        profile.policy_owner_key_id =
            crate::profile::schema::KeyringEntryRef::new("hand-written", "default");

        assert_eq!(
            derive_profile_name_from_owner_key(&profile),
            None,
            "a coordinate without the prefix yields no name at all"
        );

        let refusal = profile_name_mismatch_refusal(&profile, "alice")
            .expect("a service field without the owner-key prefix must refuse");
        assert!(!refusal.names_another_profile());

        let message = refusal.message(ProfileStateLayout::DerivedThroughout);
        assert!(
            message.contains("does not carry the 'stellar-agent-owner-' prefix"),
            "refusal must explain the absent prefix: {message}"
        );
        assert!(
            !message.contains("names a different profile"),
            "no profile name can be derived, so none may be claimed: {message}"
        );
    }

    #[test]
    fn a_prefixless_service_never_resolves_to_the_default_profile() {
        // The failure this guards: treating a prefix-less coordinate as
        // `"default"` would let a hand-written profile silently operate on the
        // default profile's state under any requested name.
        let mut profile = named_profile("default");
        profile.policy_owner_key_id =
            crate::profile::schema::KeyringEntryRef::new("hand-written", "default");
        assert!(
            profile_name_mismatch_refusal(&profile, "default").is_some(),
            "a prefix-less coordinate must refuse even when 'default' is requested"
        );
    }

    #[test]
    fn the_synthesised_first_run_profile_reconciles_as_default() {
        // The zero-config startup path loads or synthesises `default`; that
        // profile must pass the reconciliation check unchanged.
        let profile = named_profile("default");
        assert_eq!(profile_name_mismatch_refusal(&profile, "default"), None);
    }

    #[test]
    fn the_display_rendering_carries_no_state_layout_claim() {
        // `Display` is layout-independent by construction: a caller that has
        // not chosen a `ProfileStateLayout` must not emit a claim about where
        // the operator's state lives.
        let profile = named_profile("default");
        let refusal =
            profile_name_mismatch_refusal(&profile, "alice").expect("mismatch must be reported");
        let display = refusal.to_string();
        assert!(display.contains("policy_owner_key_id.service names a different profile"));
        assert!(!display.contains("policy-window state"));
    }

    #[test]
    fn the_derived_name_matches_the_constructor_it_inverts() {
        // The constructor and this inverse are the two halves of one contract;
        // pinning them against each other is what keeps the prefix single.
        let coord = crate::profile::schema::KeyringEntryRef::default_owner_key("acme");
        let mut profile = named_profile("acme");
        profile.policy_owner_key_id = coord;
        assert_eq!(derive_profile_name_from_owner_key(&profile), Some("acme"));
    }

    #[test]
    fn shell_word_quotes_one_argument() {
        for (input, expected) in [
            ("alpha_1./:@-", "alpha_1./:@-"),
            ("", "''"),
            ("two words", "'two words'"),
            ("owner's", r"'owner'\''s'"),
            ("a;b", "'a;b'"),
            ("$name", "'$name'"),
            ("`id`", "'`id`'"),
        ] {
            assert_eq!(shell_word(input), expected);
        }
    }
}
