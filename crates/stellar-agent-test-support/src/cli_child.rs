//! Isolated ordinary wallet children with caller-owned storage.

use std::path::Path;
use std::process::Command;

/// Removes ambient wallet configuration while retaining the process environment.
/// Explicit fixture overlays must be applied after this filter.
pub fn filter_wallet_environment(command: &mut Command) {
    command
        .env_clear()
        .envs(std::env::vars_os().filter(|(key, _)| {
            !key.to_string_lossy()
                .trim()
                .to_ascii_uppercase()
                .starts_with("STELLAR_AGENT_")
        }));
}

/// Constructs an ordinary isolated CLI child using the supplied executable and home.
/// The caller retains the sandbox owner until the child has stopped. This entry
/// never grants native storage access, including when a live permit is inherited.
///
/// # Errors
/// Returns an I/O error for an unmarked home or an executable without isolation.
pub fn cli_command(executable: impl AsRef<Path>, home: &Path) -> std::io::Result<Command> {
    crate::sandbox::require_isolated_executable(executable.as_ref())?;
    if !home.is_absolute() || !home.join(crate::sandbox::MARKER).is_file() {
        return Err(std::io::Error::other(
            "CLI child requires a caller-owned marked sandbox",
        ));
    }
    let mut command = Command::new(executable.as_ref());
    filter_wallet_environment(&mut command);
    command.env("STELLAR_AGENT_HOME", home);
    Ok(command)
}

#[cfg(all(test, feature = "test-helpers"))]
mod tests {
    #![allow(clippy::unwrap_used, reason = "fixture assertions")]
    use super::*;
    use crate::env_guard::ScopedEnvVar;
    use crate::sandbox::StateSandbox;
    use std::ffi::OsStr;

    #[test]
    #[serial_test::serial]
    fn cli_child_uses_only_fixture_wallet_environment() {
        let _profile = ScopedEnvVar::new("STELLAR_AGENT_PROFILE", Some(OsStr::new("poison")));
        let _permit = ScopedEnvVar::new(
            "STELLAR_AGENT_TEST_LIVE_PLATFORM_KEYRING",
            Some(OsStr::new("real-platform-keyring")),
        );
        let _backend =
            ScopedEnvVar::new("STELLAR_AGENT_KEYRING_BACKEND", Some(OsStr::new("poison")));
        let _unrelated = ScopedEnvVar::new("CLI_CHILD_KEPT", Some(OsStr::new("kept")));
        let home = StateSandbox::new().unwrap();
        let mut command = cli_command(std::env::current_exe().unwrap(), home.path()).unwrap();
        let value = |name: &str| {
            command
                .get_envs()
                .find(|(key, _)| *key == name)
                .and_then(|(_, value)| value)
        };
        assert_eq!(value("STELLAR_AGENT_HOME"), Some(home.path().as_os_str()));
        assert_eq!(value("STELLAR_AGENT_PROFILE"), None);
        assert_eq!(value("STELLAR_AGENT_KEYRING_BACKEND"), None);
        assert_eq!(value("STELLAR_AGENT_TEST_LIVE_PLATFORM_KEYRING"), None);
        assert_eq!(value("CLI_CHILD_KEPT"), Some(OsStr::new("kept")));
        assert_eq!(command.get_args().count(), 0);
        command.env("STELLAR_AGENT_PROFILE", "explicit-fixture");
        assert!(
            command
                .get_envs()
                .any(|(key, value)| key == "STELLAR_AGENT_PROFILE"
                    && value == Some(OsStr::new("explicit-fixture")))
        );
    }

    #[test]
    #[serial_test::serial]
    fn cli_child_refuses_markerless_executable_before_execution() {
        let home = StateSandbox::new().unwrap();
        let executable = home.path().join("markerless");
        std::fs::write(&executable, b"not executable").unwrap();
        assert!(cli_command(&executable, home.path()).is_err());
    }

    #[test]
    #[serial_test::serial]
    fn cli_child_refuses_an_unmarked_home() {
        let home = StateSandbox::new().unwrap();
        let unmarked = home.path().join("unmarked-child-home");
        std::fs::create_dir(&unmarked).unwrap();
        assert!(cli_command(std::env::current_exe().unwrap(), &unmarked).is_err());
    }
}
