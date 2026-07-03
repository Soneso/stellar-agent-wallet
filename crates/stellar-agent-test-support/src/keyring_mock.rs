//! In-memory mock keyring store for unit tests.
//!
//! # What this module does
//!
//! Installs `keyring_core`'s built-in in-memory `mock::Store` as the
//! process-global default credential store.  Once installed, every
//! `keyring_core::Entry::new` call in the same process resolves to the
//! in-memory store instead of the platform keyring (macOS Keychain, Linux
//! Secret Service, Windows Credential Manager).  This eliminates OS-level
//! password-dialog prompts and makes keyring-touching tests repeatable,
//! deterministic, and non-interactive.
//!
//! # When to call
//!
//! Call [`install`] at the start of each unit test that creates a
//! `keyring_core::Entry`.  Because `set_default_store` is process-global,
//! tests that share a process must not race on it — use `#[serial]` from
//! the `serial_test` crate when multiple tests in the same binary touch the
//! keyring.  Each call to [`install`] replaces any previously registered
//! store (including a prior mock) with a fresh in-memory store, so test
//! isolation is maintained per-call.
//!
//! # Per-test call vs process-wide setup
//!
//! A per-test call (rather than a `#[ctor]` hook or `Once`-guarded global) is
//! the recommended pattern here for two reasons:
//!
//! 1. **Isolation**: each test gets a fresh, empty store.  Credentials written
//!    by one test do not bleed into another.
//! 2. **Explicit contract**: the test function body makes the mock dependency
//!    visible at the call site.  A hidden process-wide hook would silently affect
//!    tests that never call [`install`], making debugging harder when a test
//!    unexpectedly finds a credential left by a different test.
//!
//! # Why `keyring-core`'s mock store
//!
//! `keyring-core`'s `mock` module is always compiled (no feature flag) and is
//! byte-compatible with the real `keyring_core::Entry` API, so reusing it keeps
//! tests faithful to production behaviour without a hand-rolled stub.

use std::sync::Arc;

/// Installs the in-memory mock keyring store as the process-global default.
///
/// After this call, every subsequent `keyring_core::Entry::new` in the same
/// process resolves to the mock store instead of the platform keyring.  The
/// mock store is not persisted; credentials exist only for the lifetime of the
/// `Arc<CredentialStore>` held internally by `keyring_core`'s global state.
///
/// Safe to call multiple times.  Each call replaces the previously registered
/// store (including a prior mock from an earlier test run) with a fresh,
/// empty in-memory store, ensuring test isolation.
///
/// # Errors
///
/// Returns `Err(keyring_core::Error)` if `keyring_core::mock::Store::new()`
/// fails.  The current upstream mock implementation is infallible; the
/// `Result` is propagated for forward compatibility in case future
/// `keyring-core` versions introduce fallible mock construction.
///
/// # Panics
///
/// Never panics.
///
/// # Examples
///
/// ```rust,no_run
/// use stellar_agent_test_support::keyring_mock;
/// use keyring_core::Entry;
///
/// keyring_mock::install().expect("mock store init");
///
/// let entry = Entry::new("my-service", "my-user").unwrap();
/// entry.set_password("hunter2").unwrap();
/// assert_eq!(entry.get_password().unwrap(), "hunter2");
/// ```
pub fn install() -> Result<(), keyring_core::Error> {
    // The annotation forces the `Arc<mock::Store>` returned by `mock::Store::new()`
    // to coerce to `Arc<dyn CredentialStoreApi + Send + Sync>` (the type alias
    // `keyring_core::CredentialStore` resolves to that trait object), which is the
    // signature `set_default_store` expects.
    let store: Arc<keyring_core::CredentialStore> = keyring_core::mock::Store::new()?;
    keyring_core::set_default_store(store);
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]
    use serial_test::serial;

    #[test]
    #[serial]
    fn install_redirects_entries_to_in_memory_store() {
        super::install().expect("mock store install");
        let entry = keyring_core::Entry::new("test-service", "test-user").expect("entry creation");
        entry.set_password("test-value").expect("set");
        assert_eq!(entry.get_password().expect("get"), "test-value");
    }

    #[test]
    #[serial]
    fn reinstall_resets_to_empty_store() {
        super::install().expect("install 1");
        let e1 = keyring_core::Entry::new("svc", "user").expect("entry");
        e1.set_password("first").expect("set");
        super::install().expect("install 2 (fresh store)");
        let e2 = keyring_core::Entry::new("svc", "user").expect("entry");
        assert!(
            e2.get_password().is_err(),
            "a fresh store must not carry a credential from before reinstall"
        );
    }
}
