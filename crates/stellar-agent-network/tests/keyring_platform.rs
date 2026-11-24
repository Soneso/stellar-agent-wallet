//! Platform keyring round trip through the store the wallet registers.
//!
//! This target is its own test binary, so no other test registers a mock or a
//! headless store in its process. The round trip needs an unlocked platform
//! keyring: the CI `platform-keyring` job runs it inside a private D-Bus
//! session with an unlocked GNOME Keyring. Locally it is built with
//! `--no-run`, because running it writes to the keyring of the person at the
//! machine.

#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; a failed keyring step fails the test"
)]

use keyring_core::Entry;
use stellar_agent_network::keyring::{
    KeyringBackend, active_keyring_backend,
    live::{LivePlatformKeyring, init_platform_keyring_store_live},
};

/// Service of the test entry; no wallet profile uses it.
const SERVICE: &str = "stellar-agent-platform-keyring-check";

/// Deletes the test entry when the test ends, also after a failed assertion,
/// so a failed run leaves nothing in the keyring.
struct EntryCleanup<'a>(&'a Entry);

impl Drop for EntryCleanup<'_> {
    fn drop(&mut self) {
        // A missing entry is the expected state after the test's own delete.
        let _ = self.0.delete_credential();
    }
}

/// Registers the platform store as the binaries do, then writes, reads, and
/// deletes one entry through it, and requires the platform backend.
#[test]
#[ignore = "needs an unlocked platform keyring; CI runs it in the platform-keyring job"]
fn keyring_platform_roundtrip() {
    assert!(
        std::env::var_os("STELLAR_AGENT_KEYRING_BACKEND").is_none(),
        "STELLAR_AGENT_KEYRING_BACKEND selects a headless store; the round trip needs the platform store"
    );
    init_platform_keyring_store_live(LivePlatformKeyring::acknowledge_real_platform_keyring())
        .expect("the platform keyring store registers");
    assert_eq!(
        active_keyring_backend(),
        KeyringBackend::Platform,
        "the registered store is the platform keyring"
    );
    let store = keyring_core::get_default_store().expect("a default store is registered");
    let vendor = store.vendor();
    #[cfg(target_os = "linux")]
    assert!(
        vendor.starts_with("Secret Service store"),
        "the Linux platform store is the Secret Service, not {vendor}"
    );
    #[cfg(target_os = "macos")]
    assert!(
        vendor.starts_with("macOS Keychain Store"),
        "the macOS platform store is the Keychain, not {vendor}"
    );

    let account = format!("round-trip-{}", std::process::id());
    let entry = Entry::new(SERVICE, &account).expect("the test entry opens");
    let _cleanup = EntryCleanup(&entry);
    let value = format!("platform-keyring-value-{account}");
    entry
        .set_password(&value)
        .expect("the platform keyring stores the value");
    let read = entry
        .get_password()
        .expect("the platform keyring returns the value");
    assert_eq!(read, value, "the value read back equals the value written");
    entry
        .delete_credential()
        .expect("the platform keyring deletes the entry");
    match entry.get_password() {
        Err(keyring_core::Error::NoEntry) => {}
        other => panic!("a deleted entry reads as missing, not {other:?}"),
    }
    assert_eq!(
        active_keyring_backend(),
        KeyringBackend::Platform,
        "the backend stays the platform keyring through the round trip"
    );
}
