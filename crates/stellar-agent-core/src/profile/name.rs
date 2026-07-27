//! Profile-name resolution and path-component validation.
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
    Ok(())
}

#[cfg(test)]
mod tests {
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
}
