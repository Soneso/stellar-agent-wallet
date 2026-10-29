//! Shared CLI-layer helpers used across all subcommands.
//!
//! # Modules
//!
//! - [`network`] — `TargetNetwork` enum unifying the network selector across
//!   write subcommands.  Carries passphrase constants and implements
//!   `FromStr` / `Display` for clap.
//! - `private_open`: opens a bearer URL in the browser through a private
//!   redirect file, so no launcher argument ever carries the secret.
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
//! - `interrupted`: resolves when the operator interrupts a ceremony wait,
//!   shared by every subcommand that holds a browser handoff while it waits.
//!
//! # Re-exports
//!
//! - [`resolve_profile_name`] — resolve the effective profile name from an
//!   explicit CLI arg, `STELLAR_AGENT_PROFILE` env var, or `"default"`, with
//!   the provenance of the result.
//! - [`validate_path_component_ascii_safe`] — validates that a string is safe
//!   to use as a path component (no path traversal, no special characters).

pub(crate) mod consent;
#[cfg(test)]
pub(crate) mod installation_key_fixture;
pub(crate) mod mainnet_confirm;
pub(crate) mod mainnet_write;
#[cfg(all(test, feature = "mainnet-write"))]
pub(crate) mod mainnet_write_fixture;
pub mod network;
pub(crate) mod private_open;
pub mod profile_access;
pub mod render;
pub mod served_pages;
pub mod signer_ceremony;
pub(crate) mod tty;

/// Returns `true` when a graphical display is available for a browser launch.
///
/// On Linux, requires `DISPLAY` or `WAYLAND_DISPLAY`; a headless host must not
/// spawn a browser. Other platforms are assumed to have a display. A browser
/// that is spawned receives only a private redirect file's URL (see
/// `private_open`), never the one-time token.
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

/// Resolves once `signal` reports an operator interrupt (Ctrl-C).
///
/// A command races this against its ceremony wait, so an interrupt ends the
/// wait and the command still runs its shutdown and removes its browser
/// handoff file. When the interrupt listener cannot be installed, `signal`
/// returns an error and this never resolves: the wait continues to its own
/// end rather than being cut short.
pub(crate) async fn interrupted(signal: impl Future<Output = std::io::Result<()>>) {
    if let Err(error) = signal.await {
        tracing::debug!(
            error = %error,
            "interrupt listener unavailable; the wait continues without it"
        );
        std::future::pending::<()>().await;
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

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use std::time::Duration;

    use super::interrupted;

    /// A delivered interrupt resolves the wait.
    #[tokio::test(flavor = "current_thread")]
    async fn interrupted_resolves_on_the_signal() {
        tokio::time::timeout(Duration::from_secs(5), interrupted(async { Ok(()) }))
            .await
            .expect("a delivered interrupt resolves");
    }

    /// A listener that could not be installed never cuts the wait short.
    #[tokio::test(flavor = "current_thread")]
    async fn interrupted_without_a_listener_never_resolves() {
        let outcome = tokio::time::timeout(
            Duration::from_millis(200),
            interrupted(async { Err(std::io::Error::other("no signal listener")) }),
        )
        .await;
        assert!(outcome.is_err(), "a failed listener must not end the wait");
    }
}
