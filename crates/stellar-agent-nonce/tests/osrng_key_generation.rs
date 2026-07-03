//! Verify that OsRng generates a 32-byte key that is valid base64.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod helpers;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use keyring_core::Entry as KeyringEntry;
use serial_test::serial;
use stellar_agent_nonce::rotate_nonce_key;

use helpers::{init_mock, make_profile};

#[test]
#[serial]
fn osrng_key_is_32_bytes_base64() {
    init_mock();
    let profile = make_profile("osrng-keygen");

    rotate_nonce_key(&profile).expect("rotation ok");

    let entry_ref = &profile.mcp_nonce_key_alias;
    let entry = KeyringEntry::new(&entry_ref.service, &entry_ref.account).unwrap();
    let stored = entry.get_password().unwrap();

    // Must decode successfully.
    let bytes = URL_SAFE_NO_PAD
        .decode(stored.as_bytes())
        .expect("valid URL-safe base64 (no padding)");

    // Must be exactly 32 bytes.
    assert_eq!(bytes.len(), 32, "generated key must be 32 bytes");

    // Stored string must only contain URL-safe base64 characters.
    assert!(
        stored
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "key must use URL-safe base64 alphabet"
    );
}
