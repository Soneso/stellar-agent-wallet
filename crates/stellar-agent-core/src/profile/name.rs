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
    /// under this layout, for `requested`.
    fn consequence_clause(self, requested: &str) -> String {
        match self {
            Self::DerivedThroughout => format!(
                "the signed policy file, pending-approval store, and policy-window \
                 state would be read and written under the derived name, not \
                 '{requested}'"
            ),
            Self::PolicyDerivedStateRequested => format!(
                "the signed policy file and the owner-key keyring entry would be \
                 read under the derived name while the pending-approval store \
                 and the policy-window state file stay keyed on '{requested}', \
                 so the run would be governed by one profile's policy and \
                 accounted against another's state"
            ),
        }
    }
}

/// A loaded profile whose owner-key coordinate names a different profile than
/// the one the operator selected.
///
/// Carries both names and the offending field so the refusal can be acted on
/// without opening the TOML. Render it with [`Self::message`] to state the
/// calling surface's own state layout; the [`std::fmt::Display`] rendering is
/// layout-independent and omits that clause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileNameMismatch {
    /// The profile name the operator selected.
    requested: String,
    /// The name derived from `policy_owner_key_id.service`, or `None` when the
    /// field does not carry the expected prefix at all.
    derived: Option<String>,
    /// The `policy_owner_key_id.service` value as stored in the profile.
    service: String,
}

impl ProfileNameMismatch {
    /// The profile name the operator selected.
    ///
    /// Callers that build a structured refusal envelope report this as the
    /// name the operation was asked for.
    #[must_use]
    pub fn requested(&self) -> &str {
        &self.requested
    }

    /// The profile name the loaded file's owner-key coordinate carries, or
    /// `None` when the coordinate does not carry [`OWNER_KEY_SERVICE_PREFIX`]
    /// and no name can be recovered from it.
    #[must_use]
    pub fn derived(&self) -> Option<&str> {
        self.derived.as_deref()
    }

    /// The offending `policy_owner_key_id.service` value, verbatim.
    ///
    /// This is the field the operator edits to repair the profile, so it is
    /// reported unmodified rather than summarised.
    #[must_use]
    pub fn service(&self) -> &str {
        &self.service
    }

    /// Renders the operator-facing refusal for a surface with the given state
    /// layout.
    ///
    /// The text names both profiles, quotes the offending field, states what
    /// the mismatch does to per-profile state under `layout`, and names the
    /// two recovery paths.
    #[must_use]
    pub fn message(&self, layout: ProfileStateLayout) -> String {
        let requested = &self.requested;
        format!(
            "{self}; {}. {}",
            layout.consequence_clause(requested),
            self.recovery_clause()
        )
    }

    /// The layout-independent recovery sentence, shared by every surface.
    fn recovery_clause(&self) -> String {
        let requested = &self.requested;
        format!(
            "A profile file renamed or copied from another profile must be \
             re-created with `stellar-agent profile init --profile {requested}`, \
             or its policy_owner_key_id.service corrected to \
             '{OWNER_KEY_SERVICE_PREFIX}{requested}'"
        )
    }
}

impl std::fmt::Display for ProfileNameMismatch {
    /// Renders the layout-independent half of the refusal: which profile was
    /// selected, what its owner coordinate says, and which profile that names.
    ///
    /// The consequence clause is layout-dependent and therefore omitted here;
    /// use [`ProfileNameMismatch::message`] to render it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            requested,
            derived,
            service,
        } = self;
        match derived {
            Some(derived) => write!(
                f,
                "profile '{requested}' was selected, but its \
                 policy_owner_key_id.service is '{service}', which names profile \
                 '{derived}'"
            ),
            None => write!(
                f,
                "profile '{requested}' was selected, but its \
                 policy_owner_key_id.service is '{service}', which does not carry \
                 the '{OWNER_KEY_SERVICE_PREFIX}' prefix a profile name is derived \
                 from"
            ),
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
/// assert_eq!(refusal.requested(), "alice");
/// assert_eq!(refusal.derived(), Some("default"));
/// assert!(
///     refusal
///         .message(ProfileStateLayout::DerivedThroughout)
///         .contains("profile init --profile alice")
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
        requested: requested_name.to_owned(),
        derived: derived.map(ToOwned::to_owned),
        service: profile.policy_owner_key_id.service.clone(),
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
    fn copied_profile_file_refuses_and_names_both_profiles() {
        // The realistic path: `default.toml` copied to `alice.toml` without
        // re-deriving its keyring coordinates.
        let profile = named_profile("default");
        let refusal = profile_name_mismatch_refusal(&profile, "alice")
            .expect("a profile naming 'default' must not serve as 'alice'");

        assert_eq!(refusal.requested(), "alice");
        assert_eq!(refusal.derived(), Some("default"));
        assert_eq!(refusal.service(), "stellar-agent-owner-default");

        for message in [
            refusal.message(ProfileStateLayout::DerivedThroughout),
            refusal.message(ProfileStateLayout::PolicyDerivedStateRequested),
        ] {
            assert!(
                message.contains("'alice'") && message.contains("'default'"),
                "refusal must name both profiles: {message}"
            );
            assert!(
                message.contains("stellar-agent-owner-default"),
                "refusal must quote the offending policy_owner_key_id.service: {message}"
            );
            assert!(
                message.contains("profile init --profile alice"),
                "refusal must name the recovery command: {message}"
            );
            assert!(
                message.contains(
                    "policy_owner_key_id.service corrected to \
                                  'stellar-agent-owner-alice'"
                ),
                "refusal must name the field-edit recovery path: {message}"
            );
        }
    }

    #[test]
    fn each_layout_states_its_own_state_placement() {
        // The two surfaces do not key their per-profile state the same way, so
        // one message cannot be truthful for both. The MCP reads and writes all
        // of it under the derived name; the CLI keys the approval store, audit
        // log, and window state on the REQUESTED name while the signed policy
        // and owner key follow the derived one.
        let profile = named_profile("default");
        let refusal =
            profile_name_mismatch_refusal(&profile, "alice").expect("mismatch must be reported");

        let derived_throughout = refusal.message(ProfileStateLayout::DerivedThroughout);
        assert!(
            derived_throughout.contains("read and written under the derived name"),
            "the derived-throughout layout must say all state moves: {derived_throughout}"
        );
        assert!(
            !derived_throughout.contains("stay keyed on"),
            "the derived-throughout layout must not claim a split: {derived_throughout}"
        );

        let split = refusal.message(ProfileStateLayout::PolicyDerivedStateRequested);
        assert!(
            split.contains("stay keyed on 'alice'"),
            "the split layout must name the state that follows the requested name: {split}"
        );
        assert!(
            !split.contains("read and written under the derived name"),
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
                .contains("'alice'")
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
        assert_eq!(refusal.derived(), None);

        let message = refusal.message(ProfileStateLayout::DerivedThroughout);
        assert!(
            message.contains("does not carry the 'stellar-agent-owner-' prefix"),
            "refusal must explain the absent prefix: {message}"
        );
        assert!(
            !message.contains("names profile"),
            "no profile name can be derived, so none may be reported: {message}"
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
        assert!(display.contains("which names profile 'default'"));
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
}
