//! Shared CLI-layer helpers used across all subcommands.
//!
//! # Modules
//!
//! - [`network`] — `TargetNetwork` enum unifying the network selector across
//!   write subcommands.  Carries passphrase constants and implements
//!   `FromStr` / `Display` for clap.
//! - [`profile_access`] — the profile-access choke point: the one place that
//!   decides whether a missing profile file may be replaced by the synthesised
//!   zero-config profile, keyed on the resolved name's provenance.
//! - [`render`] — `render_json` and `sanitize_for_table` output helpers
//!   shared by `pay` and `accounts create`.
//! - [`served_pages`] — the profile's `[served_pages]` block turned into the
//!   identity every operator-facing HTTP listener renders.
//! - [`signer_ceremony`] — `resolve_software_signer_from_env`, the single
//!   mlock-protected secret-env signer ceremony shared by every write
//!   subcommand that accepts a `--*-secret-env <VAR>` flag.
//!
//! # Free helpers
//!
//! - [`display_available`] — whether a graphical display is available for a
//!   browser auto-launch, shared by every subcommand that offers one.
//!
//! # Re-exports
//!
//! - [`resolve_profile_name`] — resolve the effective profile name from an
//!   explicit CLI arg, `STELLAR_AGENT_PROFILE` env var, or `"default"`, with
//!   the provenance of the result.
//! - [`validate_path_component_ascii_safe`] — validates that a string is safe
//!   to use as a path component (no path traversal, no special characters).

pub mod network;
pub mod profile_access;
pub mod render;
pub mod served_pages;
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

/// Profile-name resolution and path-component validation, re-exported from
/// `stellar-agent-core` so the CLI and the MCP server cannot drift apart on
/// either rule.
///
/// [`resolve_profile_name`] returns the name together with its provenance;
/// CLI call sites that treat every profile name alike take `.name`. Sites
/// that decide whether a missing profile file may be synthesised take the
/// whole [`ResolvedProfileName`] — see [`profile_access`].
pub use stellar_agent_core::profile::name::{
    ResolvedProfileName, resolve_profile_name, validate_path_component_ascii_safe,
};
