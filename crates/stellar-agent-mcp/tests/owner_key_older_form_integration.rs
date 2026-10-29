//! Engine builds preserve sibling owner entries and refuse older base64.

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

#[test]
#[serial_test::serial]
fn an_engine_build_leaves_another_profiles_older_form_entry() {
    let home = tempfile::tempdir().unwrap();
    let _home = StellarAgentHomeGuard::new(home.path());
    keyring_mock::install().unwrap();
    let profile_dir = default_profile_dir().unwrap();
    std::fs::create_dir_all(&profile_dir).unwrap();
    for name in ["owner-a", "owner-b", "owner-absent"] {
        std::fs::write(profile_dir.join(format!("{name}.toml")), "").unwrap();
    }
    let key_a = [0x71_u8; 32];
    let key_b = [0x72_u8; 32];
    put_owner("owner-a", &encode_owner_public_key(&key_a));
    put_owner("owner-b", &URL_SAFE_NO_PAD.encode(key_b));

    let profile_a = Profile::builder_testnet_named("owner-a", "s", "a", "n", "a").build();
    // No signed policy exists, so the build itself refuses after the owner read.
    assert!(WalletServer::new(profile_a).is_err());

    assert!(
        owner("owner-a") == Some(encode_owner_public_key(&key_a)),
        "the built profile's entry is unchanged"
    );
    assert!(
        owner("owner-b") == Some(URL_SAFE_NO_PAD.encode(key_b)),
        "the sibling entry stays byte-identical"
    );
    assert!(
        owner("owner-absent").is_none(),
        "an absent sibling entry stays absent"
    );
    let profile_b = Profile::builder_testnet_named("owner-b", "s", "b", "n", "b").build();
    let error = WalletServer::new(profile_b).err().unwrap();
    assert!(matches!(
        error,
        stellar_agent_core::policy::BuildRegistryError::OwnerKeyOlderForm { .. }
    ));
    assert_eq!(owner("owner-b"), Some(URL_SAFE_NO_PAD.encode(key_b)));
}
