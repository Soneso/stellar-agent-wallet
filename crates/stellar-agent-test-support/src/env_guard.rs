//! RAII guards for the two process-global environment variables the wallet's
//! profile resolution reads: `STELLAR_AGENT_HOME` (home-directory resolution —
//! profile loader, audit-log path, keyring backend selection) and
//! `STELLAR_AGENT_PROFILE` (the profile name when no flag supplies one).

use std::ffi::OsString;
use std::path::Path;

/// Overrides `STELLAR_AGENT_HOME` for the lifetime of the guard, restoring
/// the previous value (or clearing the variable if it was unset) on drop.
///
/// # Concurrency
///
/// Environment-variable mutation is process-global. Callers MUST serialise
/// with `#[serial]` (the `serial_test` crate) or an equivalent lock; a
/// sibling test that reads or sets `STELLAR_AGENT_HOME` concurrently would
/// race with this guard.
pub struct StellarAgentHomeGuard {
    previous: Option<OsString>,
}

impl StellarAgentHomeGuard {
    /// Sets `STELLAR_AGENT_HOME` to `value` for the duration of the guard.
    #[must_use]
    pub fn new(value: &Path) -> Self {
        let previous = std::env::var_os("STELLAR_AGENT_HOME");
        #[allow(
            unsafe_code,
            reason = "test-only process environment override; callers serialise with #[serial]"
        )]
        // SAFETY: serialised by the caller's #[serial]; mutated only by this
        // guard and unwound on Drop.
        unsafe {
            std::env::set_var("STELLAR_AGENT_HOME", value);
        }
        Self { previous }
    }
}

impl Drop for StellarAgentHomeGuard {
    fn drop(&mut self) {
        #[allow(
            unsafe_code,
            reason = "test-only process environment restore; panic-safe via Drop"
        )]
        // SAFETY: same as `new`; serialised by the caller's #[serial],
        // restores pre-guard state regardless of panic.
        unsafe {
            if let Some(value) = self.previous.take() {
                std::env::set_var("STELLAR_AGENT_HOME", value);
            } else {
                std::env::remove_var("STELLAR_AGENT_HOME");
            }
        }
    }
}

/// Clears `STELLAR_AGENT_PROFILE` for the lifetime of the guard, restoring the
/// previous value (or leaving it unset) on drop.
///
/// In-process tests that exercise the "no profile was named" branch resolve
/// through `resolve_profile_name`, which reads this variable. An exported
/// value in the shell running `cargo test` would make the resolved name
/// explicit and turn those tests red for a reason that has nothing to do with
/// the code under test — the in-process counterpart of the `env_remove` every
/// subprocess test already applies to its child.
///
/// # Concurrency
///
/// Environment-variable mutation is process-global. Callers MUST serialise
/// with `#[serial]` (the `serial_test` crate) or an equivalent lock.
pub struct ProfileEnvVarGuard {
    previous: Option<OsString>,
}

impl ProfileEnvVarGuard {
    /// Removes `STELLAR_AGENT_PROFILE` for the duration of the guard.
    #[must_use]
    pub fn cleared() -> Self {
        let previous = std::env::var_os("STELLAR_AGENT_PROFILE");
        #[allow(
            unsafe_code,
            reason = "test-only process environment override; callers serialise with #[serial]"
        )]
        // SAFETY: serialised by the caller's #[serial]; mutated only by this
        // guard and unwound on Drop.
        unsafe {
            std::env::remove_var("STELLAR_AGENT_PROFILE");
        }
        Self { previous }
    }
}

impl Drop for ProfileEnvVarGuard {
    fn drop(&mut self) {
        #[allow(
            unsafe_code,
            reason = "test-only process environment restore; panic-safe via Drop"
        )]
        // SAFETY: same as `cleared`; serialised by the caller's #[serial],
        // restores pre-guard state regardless of panic.
        unsafe {
            if let Some(value) = self.previous.take() {
                std::env::set_var("STELLAR_AGENT_PROFILE", value);
            } else {
                std::env::remove_var("STELLAR_AGENT_PROFILE");
            }
        }
    }
}
