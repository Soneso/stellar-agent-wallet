//! The first V1 engine build in a process rewrites the older-form owner entry
//! of every other profile in the profile directory.
//!
//! The sweep runs once per process, so this file holds a single test and runs
//! as its own test binary.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test-only; panics and unwraps are acceptable in integration tests"
)]

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use stellar_agent_core::profile::owner_key::encode_owner_public_key;
use stellar_agent_core::profile::schema::{KeyringEntryRef, Profile, default_profile_dir};
use stellar_agent_mcp::server::WalletServer;
use stellar_agent_test_support::{StellarAgentHomeGuard, keyring_mock};

fn put_owner(name: &str, value: &str) {
    let coordinate = KeyringEntryRef::default_owner_key(name);
    keyring_core::Entry::new(&coordinate.service, &coordinate.account)
        .unwrap()
        .set_password(value)
        .unwrap();
}

fn owner(name: &str) -> Option<String> {
    let coordinate = KeyringEntryRef::default_owner_key(name);
    keyring_core::Entry::new(&coordinate.service, &coordinate.account)
        .unwrap()
        .get_password()
        .ok()
}

/// An engine build for profile A rewrites A's older-form owner entry and
/// profile B's. A profile with no owner entry is skipped and the build goes
/// on to its own policy check.
#[test]
fn an_engine_build_for_one_profile_rewrites_another_profiles_older_form_entry() {
    let home = tempfile::tempdir().unwrap();
    let _home = StellarAgentHomeGuard::new(home.path());
    keyring_mock::install().unwrap();
    let profile_dir = default_profile_dir().unwrap();
    std::fs::create_dir_all(&profile_dir).unwrap();
    for name in ["sweep-a", "sweep-b", "sweep-absent"] {
        std::fs::write(profile_dir.join(format!("{name}.toml")), "").unwrap();
    }
    let key_a = [0x71_u8; 32];
    let key_b = [0x72_u8; 32];
    put_owner("sweep-a", &URL_SAFE_NO_PAD.encode(key_a));
    put_owner("sweep-b", &URL_SAFE_NO_PAD.encode(key_b));

    let profile_a = Profile::builder_testnet_named("sweep-a", "s", "a", "n", "a").build();
    // No signed policy exists, so the build itself refuses after the owner read.
    assert!(WalletServer::new(profile_a).is_err());

    assert!(
        owner("sweep-a") == Some(encode_owner_public_key(&key_a)),
        "the built profile's own entry is rewritten"
    );
    assert!(
        owner("sweep-b") == Some(encode_owner_public_key(&key_b)),
        "the first engine build rewrites another profile's older-form entry"
    );
    assert!(
        owner("sweep-absent").is_none(),
        "an absent entry is skipped"
    );
}
