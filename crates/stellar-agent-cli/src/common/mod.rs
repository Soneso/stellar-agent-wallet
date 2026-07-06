//! Shared CLI-layer helpers used across all subcommands.
//!
//! # Modules
//!
//! - [`network`] — `TargetNetwork` enum unifying the network selector across
//!   write subcommands.  Carries passphrase constants and implements
//!   `FromStr` / `Display` for clap.
//! - [`render`] — `render_json` and `sanitize_for_table` output helpers
//!   shared by `pay` and `accounts create`.
//! - [`signer_ceremony`] — `resolve_software_signer_from_env`, the single
//!   mlock-protected secret-env signer ceremony shared by every write
//!   subcommand that accepts a `--*-secret-env <VAR>` flag.
//!
//! # Free helpers
//!
//! - [`display_available`] — whether a graphical display is available for a
//!   browser auto-launch, shared by every subcommand that offers one.
//! - [`resolve_profile_name`] — resolve the effective profile name from an
//!   explicit CLI arg, `STELLAR_AGENT_PROFILE` env var, or `"default"`.
//! - [`validate_path_component_ascii_safe`] — validates that a string is safe
//!   to use as a path component (no path traversal, no special characters).

pub mod network;
pub mod render;
pub mod signer_ceremony;

/// Returns `true` when a graphical display is available for a browser launch.
///
/// On Linux, requires `DISPLAY` or `WAYLAND_DISPLAY`; a headless host must not
/// spawn a browser (which could also leak a URL-embedded one-time token into
/// another process's argv). Other platforms are assumed to have a display.
///
/// Shared by every subcommand that offers to auto-launch a browser
/// (`approve serve`, `approve operator enroll --interactive`) so the
/// headless-detection rule cannot drift between them.
#[must_use]
pub fn display_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some()
    }
    #[cfg(not(target_os = "linux"))]
    {
        true
    }
}

/// Resolves the effective profile name from the CLI arg or
/// `STELLAR_AGENT_PROFILE` environment variable, falling back to `"default"`.
///
/// Resolution order:
/// 1. `arg` if `Some`.
/// 2. `STELLAR_AGENT_PROFILE` environment variable.
/// 3. `"default"`.
///
/// # Examples
///
/// ```text
/// // Resolution order: explicit arg > STELLAR_AGENT_PROFILE env var > "default"
/// let name = resolve_profile_name(Some("alice")); // → "alice"
/// let name = resolve_profile_name(None);          // → env var or "default"
/// ```
#[must_use]
pub fn resolve_profile_name(arg: Option<&str>) -> String {
    if let Some(name) = arg {
        return name.to_owned();
    }
    std::env::var("STELLAR_AGENT_PROFILE").unwrap_or_else(|_| "default".to_owned())
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
}
