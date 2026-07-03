//! Verify that rotation works when no key exists yet (first-run case).

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
fn key_rotation_first_run_creates_key() {
    init_mock();

    // Do NOT pre-seed any key — fresh keyring entry.
    let profile = make_profile("first-run-rotation");

    // Rotation should succeed even when no entry exists yet.
    rotate_nonce_key(&profile).expect("first-run rotation ok");

    // Verify the key is now present and valid.
    let entry_ref = &profile.mcp_nonce_key_alias;
    let entry = KeyringEntry::new(&entry_ref.service, &entry_ref.account).unwrap();
    let stored = entry.get_password().expect("key created by rotation");
    let decoded = URL_SAFE_NO_PAD.decode(stored.as_bytes()).unwrap();
    assert_eq!(decoded.len(), 32, "rotated key must be 32 bytes");
}
