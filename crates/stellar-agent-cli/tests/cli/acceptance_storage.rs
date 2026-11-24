//! Shared storage selection for declared native-capable acceptance suites.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "fixture construction and assertions"
)]

#[path = "../../src/acceptance_storage.rs"]
pub(crate) mod route;

use std::path::Path;
use std::process::Command;

/// Initializes the suite's selected storage route.
///
/// # Panics
/// Panics when the requested acceptance route lacks its feature or permit.
#[allow(
    dead_code,
    reason = "only the three suites with in-process storage use this entry"
)]
pub fn dispatch<T>(headless: impl FnOnce() -> T, platform: impl FnOnce() -> T) -> T {
    route::dispatch(
        true,
        cfg!(feature = "live-platform-keyring"),
        std::env::var("STELLAR_AGENT_TEST_KEYRING").ok().as_deref(),
        std::env::var("STELLAR_AGENT_TEST_LIVE_PLATFORM_KEYRING")
            .ok()
            .as_deref(),
        headless,
        platform,
    )
    .expect("acceptance storage selection")
}

/// Constructs an isolated child with the suite's selected storage route.
/// A supplied fixture key applies only to the headless route.
///
/// # Panics
/// Panics when the route, executable or owned home fails validation.
#[allow(dead_code, reason = "integration suites call the public wrapper")]
pub fn command(executable: impl AsRef<Path>, home: &Path, headless_key: Option<&str>) -> Command {
    command_for_selection(
        executable,
        home,
        cfg!(feature = "live-platform-keyring"),
        std::env::var("STELLAR_AGENT_TEST_KEYRING").ok().as_deref(),
        std::env::var("STELLAR_AGENT_TEST_LIVE_PLATFORM_KEYRING")
            .ok()
            .as_deref(),
        headless_key,
    )
}

fn command_for_selection(
    executable: impl AsRef<Path>,
    home: &Path,
    live_feature: bool,
    selection: Option<&str>,
    permit: Option<&str>,
    headless_key: Option<&str>,
) -> Command {
    let argument = route::child_argument(live_feature, selection, permit)
        .expect("acceptance child storage selection");
    let mut command = stellar_agent_test_support::cli_child::cli_command(executable, home)
        .expect("isolated acceptance child");
    if let Some(argument) = argument {
        command
            .arg(argument)
            .env("STELLAR_AGENT_TEST_KEYRING", "platform")
            .env(
                "STELLAR_AGENT_TEST_LIVE_PLATFORM_KEYRING",
                "real-platform-keyring",
            );
    } else {
        for key in [
            "STELLAR_AGENT_KEYRING_BACKEND",
            "STELLAR_AGENT_HEADLESS_KEYRING_KEY",
        ] {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
        if let Some(key) = headless_key {
            command
                .env("STELLAR_AGENT_KEYRING_BACKEND", "headless-env")
                .env("STELLAR_AGENT_HEADLESS_KEYRING_KEY", key);
        }
    }
    command
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[serial_test::serial]
    fn child_command_grants_only_the_selected_platform_entry() {
        let home = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let executable = std::env::current_exe().unwrap();
        for (selection, expected) in [
            ("headless", None),
            ("platform", Some("--test-live-platform-keyring")),
        ] {
            let command = command_for_selection(
                &executable,
                home.path(),
                true,
                Some(selection),
                Some("real-platform-keyring"),
                Some("fixture-headless-key"),
            );
            assert_eq!(
                command.get_args().collect::<Vec<_>>(),
                expected.into_iter().collect::<Vec<_>>(),
                "selected child entry argument"
            );
            let permit = command
                .get_envs()
                .find(|(key, _)| *key == "STELLAR_AGENT_TEST_LIVE_PLATFORM_KEYRING")
                .and_then(|(_, value)| value);
            assert_eq!(
                permit,
                expected.map(|_| std::ffi::OsStr::new("real-platform-keyring")),
                "selected child permit"
            );
            let environment: std::collections::HashMap<_, _> = command.get_envs().collect();
            for (name, value) in [
                ("STELLAR_AGENT_KEYRING_BACKEND", "headless-env"),
                ("STELLAR_AGENT_HEADLESS_KEYRING_KEY", "fixture-headless-key"),
            ] {
                assert_eq!(
                    environment
                        .get(std::ffi::OsStr::new(name))
                        .copied()
                        .flatten(),
                    expected.is_none().then_some(std::ffi::OsStr::new(value)),
                    "selected child headless setting {name}"
                );
            }
        }
    }
}
