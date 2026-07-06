//! RAII guard for overriding `STELLAR_AGENT_HOME` in tests that exercise the
//! wallet's home-directory resolution (profile loader, audit-log path,
//! keyring backend selection).

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
