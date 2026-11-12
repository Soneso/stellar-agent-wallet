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
//! `keyring_core::Entry`.  `set_default_store` is process-global: each call
//! to [`install`] or [`install_with_read_hooks`] replaces the process-global
//! store and discards every credential already seeded in this process.  A
//! test that installs or reads the mock keyring store therefore holds the
//! same `serial_test` key as every other test in its binary that touches the
//! store or the process environment (`STELLAR_AGENT_HOME`).
//!
//! A test that supplies a store of its own, such as a file-backed one, installs
//! it through [`DefaultStoreGuard`], which restores the previous default store
//! when it drops.
//!
//! # Per-test call vs process-wide setup
//!
//! A per-test call (rather than a `#[ctor]` hook or `Once`-guarded global) is
//! the recommended pattern here for two reasons:
//!
//! 1. **Isolation**: each test that holds its binary's serial key gets a
//!    fresh, empty store.  Credentials written by one test do not bleed into
//!    another.
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
/// Each call replaces the process-global store and discards every credential
/// already seeded in this process, so a test that installs or reads the mock
/// keyring store holds the same `serial_test` key as every other test in its
/// binary that touches the store or the process environment
/// (`STELLAR_AGENT_HOME`).
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

/// Makes a supplied store the process-global default for the guard's
/// lifetime.
///
/// [`DefaultStoreGuard::install`] saves the current default store, or its
/// absence, and installs the supplied one. Dropping the guard restores the
/// saved store, or clears the default when none was set, including during an
/// unwind. Guards nest: each restores the store that was the default when it
/// was created, so they drop in reverse creation order.
///
/// The guard changes process-global state, as [`install`] does. A test that
/// holds it holds the same `serial_test` key as every other test in its
/// binary that touches the store.
#[must_use = "dropping the guard restores the previous default store at once"]
pub struct DefaultStoreGuard {
    previous: Option<Arc<keyring_core::CredentialStore>>,
}

impl DefaultStoreGuard {
    /// Installs `store` as the process-global default and returns the guard
    /// that restores the previous default.
    pub fn install(store: Arc<keyring_core::CredentialStore>) -> Self {
        let previous = keyring_core::unset_default_store();
        keyring_core::set_default_store(store);
        Self { previous }
    }
}

impl std::fmt::Debug for DefaultStoreGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DefaultStoreGuard")
            .field("restores_a_store", &self.previous.is_some())
            .finish()
    }
}

impl Drop for DefaultStoreGuard {
    fn drop(&mut self) {
        keyring_core::unset_default_store();
        if let Some(previous) = self.previous.take() {
            keyring_core::set_default_store(previous);
        }
    }
}

/// A callback the hooked mock store runs before a secret read at one keyring
/// coordinate.
///
/// Lets a test act at the exact moment code under test reads a key, for
/// example to observe the audit log when a signing key loads.
#[derive(Clone)]
pub struct ReadHook {
    service: String,
    account: String,
    hook: Arc<dyn Fn() + Send + Sync>,
}

impl ReadHook {
    /// A hook that runs `hook` before every secret read at `service`/`account`.
    #[must_use]
    pub fn new(service: &str, account: &str, hook: Arc<dyn Fn() + Send + Sync>) -> Self {
        Self {
            service: service.to_owned(),
            account: account.to_owned(),
            hook,
        }
    }
}

impl std::fmt::Debug for ReadHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReadHook")
            .field("service", &self.service)
            .field("account", &self.account)
            .finish_non_exhaustive()
    }
}

/// Installs a fresh in-memory mock store, as [`install`] does, whose secret
/// reads at each hook's coordinate run that hook first.
///
/// Writes, deletes, and reads at every other coordinate behave exactly as the
/// plain mock store. A hook runs on every read at its coordinate, including
/// the reads a test performs itself.
///
/// Each call replaces the process-global store and discards every credential
/// already seeded in this process, so a test that installs or reads the mock
/// keyring store holds the same `serial_test` key as every other test in its
/// binary that touches the store or the process environment
/// (`STELLAR_AGENT_HOME`).
///
/// # Errors
///
/// Returns `Err(keyring_core::Error)` if `keyring_core::mock::Store::new()`
/// fails.
pub fn install_with_read_hooks(hooks: Vec<ReadHook>) -> Result<(), keyring_core::Error> {
    let store: Arc<keyring_core::CredentialStore> = Arc::new(HookedStore {
        inner: keyring_core::mock::Store::new()?,
        hooks,
    });
    keyring_core::set_default_store(store);
    Ok(())
}

/// The mock store with read hooks; see [`install_with_read_hooks`].
struct HookedStore {
    inner: Arc<keyring_core::mock::Store>,
    hooks: Vec<ReadHook>,
}

impl std::fmt::Debug for HookedStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HookedStore")
            .field("hooks", &self.hooks)
            .finish_non_exhaustive()
    }
}

impl keyring_core::api::CredentialStoreApi for HookedStore {
    fn vendor(&self) -> String {
        "stellar-agent-test-support hooked mock store".to_owned()
    }

    fn id(&self) -> String {
        keyring_core::api::CredentialStoreApi::id(self.inner.as_ref())
    }

    fn build(
        &self,
        service: &str,
        user: &str,
        modifiers: Option<&std::collections::HashMap<&str, &str>>,
    ) -> keyring_core::Result<keyring_core::Entry> {
        let entry = keyring_core::api::CredentialStoreApi::build(
            self.inner.as_ref(),
            service,
            user,
            modifiers,
        )?;
        let hooks = self
            .hooks
            .iter()
            .filter(|hook| hook.service == service && hook.account == user)
            .map(|hook| Arc::clone(&hook.hook))
            .collect::<Vec<_>>();
        if hooks.is_empty() {
            return Ok(entry);
        }
        Ok(keyring_core::Entry::new_with_credential(Arc::new(
            HookedCred { entry, hooks },
        )))
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// A mock credential whose secret reads run hooks first.
struct HookedCred {
    entry: keyring_core::Entry,
    hooks: Vec<Arc<dyn Fn() + Send + Sync>>,
}

impl std::fmt::Debug for HookedCred {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HookedCred").finish_non_exhaustive()
    }
}

impl keyring_core::api::CredentialApi for HookedCred {
    fn set_secret(&self, secret: &[u8]) -> keyring_core::Result<()> {
        self.entry.set_secret(secret)
    }

    fn get_secret(&self) -> keyring_core::Result<Vec<u8>> {
        for hook in &self.hooks {
            hook();
        }
        self.entry.get_secret()
    }

    fn delete_credential(&self) -> keyring_core::Result<()> {
        self.entry.delete_credential()
    }

    fn get_credential(&self) -> keyring_core::Result<Option<Arc<keyring_core::api::Credential>>> {
        Ok(None)
    }

    fn get_specifiers(&self) -> Option<(String, String)> {
        self.entry.get_specifiers()
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// One keyring write, deletion or attribute update in a [`MutationLog`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyringMutation {
    /// `set`, `delete` or `update_attributes`.
    pub operation: &'static str,
    /// The service of the entry.
    pub service: String,
    /// The account of the entry.
    pub account: String,
}

/// The keyring mutations made through entries built after
/// [`record_mutations`].
#[derive(Clone, Debug, Default)]
pub struct MutationLog(Arc<std::sync::Mutex<Vec<KeyringMutation>>>);

impl MutationLog {
    /// Every mutation recorded so far, in order.
    ///
    /// # Panics
    ///
    /// Panics when the log is poisoned by a panic in a recording thread.
    #[must_use]
    pub fn mutations(&self) -> Vec<KeyringMutation> {
        #[allow(
            clippy::expect_used,
            reason = "test support; a poisoned log is a test failure"
        )]
        self.0.lock().expect("mutation log").clone()
    }

    fn push(&self, operation: &'static str, service: &str, account: &str) {
        if let Ok(mut log) = self.0.lock() {
            log.push(KeyringMutation {
                operation,
                service: service.to_owned(),
                account: account.to_owned(),
            });
        }
    }
}

/// Wraps the installed default store so that every write, deletion and
/// attribute update through an entry built from now on is recorded.
///
/// The credentials already in the store stay; reads behave as before. A test
/// calls this after its fixture setup and asserts on the log it returns.
///
/// # Errors
///
/// Returns [`keyring_core::Error::NoDefaultStore`] when no store is
/// installed.
pub fn record_mutations() -> Result<MutationLog, keyring_core::Error> {
    let inner = keyring_core::get_default_store().ok_or(keyring_core::Error::NoDefaultStore)?;
    let log = MutationLog::default();
    let store: Arc<keyring_core::CredentialStore> = Arc::new(RecordingStore {
        inner,
        log: log.clone(),
    });
    keyring_core::set_default_store(store);
    Ok(log)
}

/// The store [`record_mutations`] installs.
struct RecordingStore {
    inner: Arc<keyring_core::CredentialStore>,
    log: MutationLog,
}

impl std::fmt::Debug for RecordingStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordingStore").finish_non_exhaustive()
    }
}

impl keyring_core::api::CredentialStoreApi for RecordingStore {
    fn vendor(&self) -> String {
        "stellar-agent-test-support recording mock store".to_owned()
    }

    fn id(&self) -> String {
        self.inner.id()
    }

    fn build(
        &self,
        service: &str,
        user: &str,
        modifiers: Option<&std::collections::HashMap<&str, &str>>,
    ) -> keyring_core::Result<keyring_core::Entry> {
        let entry = self.inner.build(service, user, modifiers)?;
        Ok(keyring_core::Entry::new_with_credential(Arc::new(
            RecordingCred {
                entry,
                service: service.to_owned(),
                account: user.to_owned(),
                log: self.log.clone(),
            },
        )))
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// A credential whose mutations land in a [`MutationLog`].
struct RecordingCred {
    entry: keyring_core::Entry,
    service: String,
    account: String,
    log: MutationLog,
}

impl std::fmt::Debug for RecordingCred {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordingCred").finish_non_exhaustive()
    }
}

impl keyring_core::api::CredentialApi for RecordingCred {
    fn set_secret(&self, secret: &[u8]) -> keyring_core::Result<()> {
        self.log.push("set", &self.service, &self.account);
        self.entry.set_secret(secret)
    }

    fn get_secret(&self) -> keyring_core::Result<Vec<u8>> {
        self.entry.get_secret()
    }

    fn update_attributes(
        &self,
        attributes: &std::collections::HashMap<&str, &str>,
    ) -> keyring_core::Result<()> {
        self.log
            .push("update_attributes", &self.service, &self.account);
        self.entry.update_attributes(attributes)
    }

    fn delete_credential(&self) -> keyring_core::Result<()> {
        self.log.push("delete", &self.service, &self.account);
        self.entry.delete_credential()
    }

    fn get_credential(&self) -> keyring_core::Result<Option<Arc<keyring_core::api::Credential>>> {
        Ok(None)
    }

    fn get_specifiers(&self) -> Option<(String, String)> {
        self.entry.get_specifiers()
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Canonical `Display` text of the `windows-native-keyring-store` platform
/// error for Win32 `ERROR_NO_SUCH_LOGON_SESSION` (1312), as rendered inside
/// `keyring_core::Error::NoStorageAccess`.
///
/// Tests inject this text to exercise the non-interactive-session
/// classification on every platform; the production detector matches on the
/// `Display` text because the platform crate's concrete error type is
/// private.
pub const WINDOWS_NO_LOGON_SESSION_TEXT: &str = "Windows ERROR_NO_SUCH_LOGON_SESSION";

/// Injects a single-shot error into the mock credential at the given
/// coordinates, creating the credential if absent.
///
/// The next keyring operation performed through ANY `keyring_core::Entry`
/// resolving to `service`/`account` returns `err`; operations after that
/// behave normally (the mock removes an injected error once it has been
/// returned). The mock store reuses one credential per coordinate pair, so
/// an injection placed here reaches entries constructed later by production
/// code under test.
///
/// Under [`install_with_read_hooks`] the injection reaches the mock
/// credential behind a hooked coordinate too; a read there runs its hooks
/// and then returns the injected error.
///
/// # Errors
///
/// - Any error from `keyring_core::Entry::new`.
/// - `keyring_core::Error::NotSupportedByStore` when the process-global
///   default store is not the keyring-core mock — call [`install`] first.
pub fn inject_error(
    service: &str,
    account: &str,
    err: keyring_core::Error,
) -> Result<(), keyring_core::Error> {
    let entry = keyring_core::Entry::new(service, account)?;
    let hooked = entry.as_any().downcast_ref::<HookedCred>();
    let credential = hooked.map_or(&entry, |hooked| &hooked.entry);
    let Some(cred) = credential
        .as_any()
        .downcast_ref::<keyring_core::mock::Cred>()
    else {
        return Err(keyring_core::Error::NotSupportedByStore(
            "keyring_mock::inject_error requires the keyring-core mock store; \
             call keyring_mock::install() first"
                .to_owned(),
        ));
    };
    cred.set_error(err);
    Ok(())
}

/// Installs a fresh in-memory mock store whose credential at
/// `service`/`account` holds `initial` and fails its next WRITE with `err`.
///
/// [`inject_error`] fails the next operation of any kind, so a read that
/// precedes a write consumes it. This store leaves reads, deletions, and every
/// other coordinate as [`install`] does and fails only the first write at the
/// named coordinate, so a test can drive a read-then-write sequence to the
/// write. `initial`, when given, is stored before the failure is armed.
/// [`inject_error`] does not reach the named coordinate under this store.
///
/// # Errors
///
/// Returns `Err(keyring_core::Error)` if `keyring_core::mock::Store::new()`
/// fails or `initial` cannot be stored.
pub fn install_with_write_error(
    service: &str,
    account: &str,
    initial: Option<&str>,
    err: keyring_core::Error,
) -> Result<(), keyring_core::Error> {
    use keyring_core::api::CredentialStoreApi as _;
    let inner = keyring_core::mock::Store::new()?;
    if let Some(initial) = initial {
        inner.build(service, account, None)?.set_password(initial)?;
    }
    let store: Arc<keyring_core::CredentialStore> = Arc::new(WriteErrorStore {
        inner,
        target: (service.to_owned(), account.to_owned()),
        error: Arc::new(std::sync::Mutex::new(Some(err))),
        failing: Arc::new(std::sync::atomic::AtomicBool::new(false)),
    });
    keyring_core::set_default_store(store);
    Ok(())
}

/// Installs a mock whose writes at one coordinate fail while the returned switch is set.
///
/// # Errors
/// Returns the error from creating the mock store.
pub fn install_with_write_failure_switch(
    service: &str,
    account: &str,
) -> Result<Arc<std::sync::atomic::AtomicBool>, keyring_core::Error> {
    let failing = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let store = WriteErrorStore {
        inner: keyring_core::mock::Store::new()?,
        target: (service.to_owned(), account.to_owned()),
        error: Arc::new(std::sync::Mutex::new(None)),
        failing: Arc::clone(&failing),
    };
    keyring_core::set_default_store(Arc::new(store));
    Ok(failing)
}

/// The mock store of [`install_with_write_error`].
struct WriteErrorStore {
    inner: Arc<keyring_core::mock::Store>,
    target: (String, String),
    error: Arc<std::sync::Mutex<Option<keyring_core::Error>>>,
    failing: Arc<std::sync::atomic::AtomicBool>,
}

impl keyring_core::api::CredentialStoreApi for WriteErrorStore {
    fn vendor(&self) -> String {
        "stellar-agent-test-support write-error mock".to_owned()
    }

    fn id(&self) -> String {
        "stellar-agent-test-support/write-error-mock".to_owned()
    }

    fn build(
        &self,
        service: &str,
        user: &str,
        modifiers: Option<&std::collections::HashMap<&str, &str>>,
    ) -> keyring_core::Result<keyring_core::Entry> {
        let entry = self.inner.build(service, user, modifiers)?;
        if self.target.0 == service && self.target.1 == user {
            return Ok(keyring_core::Entry::new_with_credential(Arc::new(
                WriteErrorCred {
                    inner: entry,
                    error: Arc::clone(&self.error),
                    failing: Arc::clone(&self.failing),
                },
            )));
        }
        Ok(entry)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// A mock credential that fails its first write with the store's error.
struct WriteErrorCred {
    inner: keyring_core::Entry,
    error: Arc<std::sync::Mutex<Option<keyring_core::Error>>>,
    failing: Arc<std::sync::atomic::AtomicBool>,
}

impl keyring_core::api::CredentialApi for WriteErrorCred {
    fn set_secret(&self, secret: &[u8]) -> keyring_core::Result<()> {
        if self.failing.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(keyring_core::Error::NoEntry);
        }
        let pending = match self.error.lock() {
            Ok(mut guard) => guard.take(),
            Err(poisoned) => poisoned.into_inner().take(),
        };
        if let Some(err) = pending {
            return Err(err);
        }
        self.inner.set_secret(secret)
    }

    fn get_secret(&self) -> keyring_core::Result<Vec<u8>> {
        self.inner.get_secret()
    }

    fn delete_credential(&self) -> keyring_core::Result<()> {
        self.inner.delete_credential()
    }

    fn get_credential(&self) -> keyring_core::Result<Option<Arc<keyring_core::api::Credential>>> {
        self.inner.get_secret()?;
        Ok(None)
    }

    fn get_specifiers(&self) -> Option<(String, String)> {
        self.inner.get_specifiers()
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Injects the Windows no-logon-session failure shape at the given
/// coordinates: `keyring_core::Error::NoStorageAccess` wrapping
/// [`WINDOWS_NO_LOGON_SESSION_TEXT`].
///
/// This is the error a `windows-native-keyring-store` backend returns for
/// every Credential Manager operation (read or write) in a non-interactive
/// Windows session (service, SSH, scheduled task).
///
/// # Errors
///
/// See [`inject_error`].
pub fn inject_no_logon_session(service: &str, account: &str) -> Result<(), keyring_core::Error> {
    inject_error(
        service,
        account,
        keyring_core::Error::NoStorageAccess(Box::new(std::io::Error::other(
            WINDOWS_NO_LOGON_SESSION_TEXT,
        ))),
    )
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

    /// An injected error surfaces on the next operation of an Entry
    /// constructed AFTER the injection (the mock store shares one credential
    /// per coordinate pair), and is single-shot: the operation after it
    /// succeeds.
    #[test]
    #[serial]
    fn injected_error_reaches_a_later_entry_and_is_single_shot() {
        super::install().expect("mock store install");
        super::inject_no_logon_session("inject-svc", "inject-user").expect("inject");

        let entry = keyring_core::Entry::new("inject-svc", "inject-user").expect("entry");
        let err = entry.set_password("value").expect_err("injected failure");
        assert!(
            matches!(err, keyring_core::Error::NoStorageAccess(ref inner)
                if inner.to_string().contains(super::WINDOWS_NO_LOGON_SESSION_TEXT)),
            "expected the injected no-logon-session shape, got {err:?}"
        );

        entry
            .set_password("value")
            .expect("the injection is single-shot; the retry must succeed");
    }

    /// An injection at a hooked coordinate fails the next read after its
    /// hook runs, once.
    #[test]
    #[serial]
    fn injected_error_reaches_a_hooked_coordinate() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};
        let reads = Arc::new(AtomicU32::new(0));
        let counted = Arc::clone(&reads);
        super::install_with_read_hooks(vec![super::ReadHook::new(
            "hooked-svc",
            "hooked-user",
            Arc::new(move || {
                counted.fetch_add(1, Ordering::SeqCst);
            }),
        )])
        .expect("hooked store install");
        let entry = keyring_core::Entry::new("hooked-svc", "hooked-user").expect("entry");
        entry.set_password("value").expect("set");
        super::inject_no_logon_session("hooked-svc", "hooked-user").expect("inject");

        let err = keyring_core::Entry::new("hooked-svc", "hooked-user")
            .expect("entry")
            .get_password()
            .expect_err("injected failure");
        assert!(
            matches!(err, keyring_core::Error::NoStorageAccess(ref inner)
                if inner.to_string().contains(super::WINDOWS_NO_LOGON_SESSION_TEXT)),
            "expected the injected no-logon-session shape, got {err:?}"
        );
        assert_eq!(reads.load(Ordering::SeqCst), 1, "the hook runs first");
        assert_eq!(entry.get_password().expect("single-shot"), "value");
        assert_eq!(reads.load(Ordering::SeqCst), 2);
    }

    /// A fresh mock store as the store type the default holds.
    fn mock_store() -> std::sync::Arc<keyring_core::CredentialStore> {
        keyring_core::mock::Store::new().expect("mock store")
    }

    /// Whether the current default store is `store` itself.
    fn default_is(store: &std::sync::Arc<keyring_core::CredentialStore>) -> bool {
        keyring_core::get_default_store()
            .is_some_and(|current| std::sync::Arc::ptr_eq(&current, store))
    }

    /// The guard restores the store that was the default before it, with the
    /// credentials that store holds, and the supplied store is the default
    /// only while the guard lives.
    #[test]
    #[serial]
    fn default_store_guard_restores_the_previous_store() {
        let original = mock_store();
        keyring_core::set_default_store(std::sync::Arc::clone(&original));
        keyring_core::Entry::new("guard-svc", "guard-user")
            .expect("entry")
            .set_password("kept")
            .expect("set");

        let supplied = mock_store();
        let guard = super::DefaultStoreGuard::install(std::sync::Arc::clone(&supplied));
        assert!(default_is(&supplied), "the supplied store is the default");
        assert!(
            keyring_core::Entry::new("guard-svc", "guard-user")
                .expect("entry")
                .get_password()
                .is_err(),
            "the supplied store does not hold the original credential"
        );
        drop(guard);

        assert!(default_is(&original), "the original store is restored");
        assert_eq!(
            keyring_core::Entry::new("guard-svc", "guard-user")
                .expect("entry")
                .get_password()
                .expect("the restored store keeps its credential"),
            "kept"
        );
        keyring_core::unset_default_store();
    }

    /// With no default store set, the guard clears the default again on drop.
    /// Nested guards restore in reverse order, and an unwind through a guard
    /// restores as a normal drop does.
    #[test]
    #[serial]
    fn default_store_guard_restores_absence_and_unwinds() {
        keyring_core::unset_default_store();
        let outer_store = mock_store();
        let inner_store = mock_store();
        {
            let _outer = super::DefaultStoreGuard::install(std::sync::Arc::clone(&outer_store));
            {
                let _inner = super::DefaultStoreGuard::install(std::sync::Arc::clone(&inner_store));
                assert!(default_is(&inner_store), "the inner store is the default");
            }
            assert!(
                default_is(&outer_store),
                "dropping the inner guard restores the outer store"
            );
        }
        assert!(
            keyring_core::get_default_store().is_none(),
            "dropping the outer guard restores the absence of a default store"
        );

        let unwinding_store = mock_store();
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = super::DefaultStoreGuard::install(std::sync::Arc::clone(&unwinding_store));
            assert!(default_is(&unwinding_store));
            std::panic::resume_unwind(Box::new("unwinding through the guard"));
        }));
        assert!(unwound.is_err(), "the closure unwinds");
        assert!(
            keyring_core::get_default_store().is_none(),
            "an unwind through the guard restores the absence of a default store"
        );
    }

    /// Puts back the default store a test found, also when it panics.
    struct RestoreDefaultStore(Option<std::sync::Arc<keyring_core::CredentialStore>>);

    impl RestoreDefaultStore {
        fn capture() -> Self {
            Self(keyring_core::get_default_store())
        }
    }

    impl Drop for RestoreDefaultStore {
        fn drop(&mut self) {
            match self.0.take() {
                Some(store) => keyring_core::set_default_store(store),
                None => {
                    let _ = keyring_core::unset_default_store();
                }
            }
        }
    }

    fn mutation(operation: &'static str, service: &str, account: &str) -> super::KeyringMutation {
        super::KeyringMutation {
            operation,
            service: service.to_owned(),
            account: account.to_owned(),
        }
    }

    /// Without an installed store there is nothing to wrap.
    #[test]
    #[serial]
    fn record_mutations_requires_an_installed_store() {
        let _restore = RestoreDefaultStore::capture();
        keyring_core::unset_default_store();
        assert!(matches!(
            super::record_mutations(),
            Err(keyring_core::Error::NoDefaultStore)
        ));
    }

    /// A write, an attribute update and a deletion through entries built
    /// after the call each record one mutation with their coordinates, in
    /// order. Reads pass through and record nothing.
    #[test]
    #[serial]
    fn record_mutations_logs_writes_updates_and_deletions_in_order() {
        let _restore = RestoreDefaultStore::capture();
        super::install().expect("mock store install");
        let log = super::record_mutations().expect("recording store");
        assert_eq!(log.mutations(), []);

        let entry = keyring_core::Entry::new("rec-svc", "rec-user").expect("entry");
        entry.set_password("value").expect("set");
        assert_eq!(entry.get_password().expect("read"), "value");
        assert_eq!(entry.get_secret().expect("secret read"), b"value");
        assert_eq!(log.mutations(), [mutation("set", "rec-svc", "rec-user")]);

        let attributes = std::collections::HashMap::from([("label", "laptop")]);
        let _ = entry.update_attributes(&attributes);
        let other = keyring_core::Entry::new("rec-svc", "other-user").expect("entry");
        other.set_password("second").expect("set");
        other.delete_credential().expect("delete");
        assert_eq!(
            log.mutations(),
            [
                mutation("set", "rec-svc", "rec-user"),
                mutation("update_attributes", "rec-svc", "rec-user"),
                mutation("set", "rec-svc", "other-user"),
                mutation("delete", "rec-svc", "other-user"),
            ]
        );
        assert!(
            other.get_password().is_err(),
            "the deletion reaches the store"
        );
        let clone = log.clone();
        assert_eq!(clone.mutations().len(), 4, "clones share one log");
    }

    /// Credentials stored before the call stay readable through entries
    /// built afterwards, and reading them records nothing.
    #[test]
    #[serial]
    fn record_mutations_keeps_earlier_credentials_readable() {
        let _restore = RestoreDefaultStore::capture();
        super::install().expect("mock store install");
        keyring_core::Entry::new("seed-svc", "seed-user")
            .expect("entry")
            .set_password("seeded")
            .expect("seed");
        let log = super::record_mutations().expect("recording store");
        let entry = keyring_core::Entry::new("seed-svc", "seed-user").expect("entry");
        assert_eq!(entry.get_password().expect("read"), "seeded");
        assert_eq!(log.mutations(), []);
    }

    /// The recording store and its credentials name themselves and keep
    /// the inner store's identity and the entry's coordinates.
    #[test]
    #[serial]
    fn record_mutations_store_and_credential_identify_themselves() {
        let _restore = RestoreDefaultStore::capture();
        super::install().expect("mock store install");
        let inner_id = keyring_core::get_default_store().expect("inner store").id();
        let _log = super::record_mutations().expect("recording store");
        let store = keyring_core::get_default_store().expect("recording store");
        assert_eq!(
            store.vendor(),
            "stellar-agent-test-support recording mock store"
        );
        assert_eq!(store.id(), inner_id);
        let recording = store
            .as_any()
            .downcast_ref::<super::RecordingStore>()
            .expect("the default store is the recording store");
        assert_eq!(format!("{recording:?}"), "RecordingStore { .. }");

        let entry = keyring_core::Entry::new("id-svc", "id-user").expect("entry");
        let credential = entry
            .as_any()
            .downcast_ref::<super::RecordingCred>()
            .expect("entries built afterwards wrap a recording credential");
        assert_eq!(format!("{credential:?}"), "RecordingCred { .. }");
        assert_eq!(
            entry.get_specifiers(),
            Some(("id-svc".to_owned(), "id-user".to_owned()))
        );
        assert!(
            entry
                .get_credential()
                .expect("credential")
                .as_any()
                .is::<super::RecordingCred>(),
            "a wrapper credential stands for itself"
        );
    }
}
