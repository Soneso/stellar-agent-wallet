//! The nonce key loader refuses a key that is, or may be, an owner public key,
//! and accepts exactly 32 decoded bytes.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod helpers;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use keyring_core::Entry as KeyringEntry;
use serial_test::serial;
use stellar_agent_core::profile::schema::{KeyringEntryRef, Profile};
use stellar_agent_nonce::{NonceError, NonceMint};

use helpers::{StaticCatalogue, far_future_expiry, init_mock, make_profile, now_before_expiry};

fn put(entry_ref: &KeyringEntryRef, value: &str) {
    KeyringEntry::new(&entry_ref.service, &entry_ref.account)
        .unwrap()
        .set_password(value)
        .unwrap();
}

fn mint_with(profile: &Profile, profile_name: &str) -> Result<(), NonceError> {
    let mint = NonceMint::from_profile(profile, profile_name).expect("from_profile");
    mint.mint(
        &StaticCatalogue(&["stellar_balances"]),
        b"xdr",
        now_before_expiry(),
        far_future_expiry(),
        "stellar_balances",
        "stellar:testnet",
    )
    .map(|_| ())
}

#[test]
#[serial]
fn thirty_three_bytes_are_refused() {
    init_mock();
    let profile = make_profile("nonce-33");
    put(
        &profile.mcp_nonce_key_alias,
        &URL_SAFE_NO_PAD.encode([7_u8; 33]),
    );
    let err = mint_with(&profile, "nonce-33").expect_err("33 bytes must refuse");
    assert!(
        matches!(err, NonceError::KeyTooLong { actual: 33 }),
        "{err:?}"
    );
}

/// An owner entry in the G-strkey form, relocated to the nonce coordinate,
/// decodes to 42 bytes and is refused.
#[test]
#[serial]
fn a_g_strkey_owner_value_is_refused() {
    init_mock();
    let profile = make_profile("nonce-strkey");
    let strkey = stellar_agent_core::profile::owner_key::encode_owner_public_key(&[9_u8; 32]);
    put(&profile.mcp_nonce_key_alias, &strkey);
    let err = mint_with(&profile, "nonce-strkey").expect_err("a G-strkey must refuse");
    assert!(
        matches!(err, NonceError::KeyTooLong { actual: 42 }),
        "{err:?}"
    );
}

/// A nonce key equal to the profile's own owner public key in the older form
/// is refused with the owner code.
#[test]
#[serial]
fn a_key_equal_to_the_older_form_owner_key_is_refused() {
    init_mock();
    let profile = make_profile("nonce-owner");
    let owner_bytes = [0x44_u8; 32];
    put(
        &KeyringEntryRef::default_owner_key("nonce-owner"),
        &URL_SAFE_NO_PAD.encode(owner_bytes),
    );
    put(
        &profile.mcp_nonce_key_alias,
        &URL_SAFE_NO_PAD.encode(owner_bytes),
    );
    let err = mint_with(&profile, "nonce-owner").expect_err("the owner key must refuse");
    assert!(
        matches!(err, NonceError::KeyMatchesOwnerPublicKey),
        "{err:?}"
    );
    assert_eq!(err.wire_code(), "validation.key_matches_owner_public_key");
    assert!(err.to_string().contains("mcp_nonce_key_alias"), "{err}");

    put(
        &profile.mcp_nonce_key_alias,
        &URL_SAFE_NO_PAD.encode([0x45_u8; 32]),
    );
    mint_with(&profile, "nonce-owner").expect("a key that is not the owner key mints");
}

/// A nonce coordinate in the owner key namespace refuses before any keyring
/// read: an error planted there is still pending afterwards.
#[test]
#[serial]
fn an_owner_namespace_coordinate_is_refused_without_a_read() {
    init_mock();
    let mut profile = make_profile("nonce-coord");
    profile.mcp_nonce_key_alias = KeyringEntryRef::new("stellar-agent-owner-other", "default");
    stellar_agent_test_support::keyring_mock::inject_error(
        "stellar-agent-owner-other",
        "default",
        keyring_core::Error::PlatformFailure(Box::new(std::io::Error::other("planted"))),
    )
    .unwrap();
    let err = mint_with(&profile, "nonce-coord").expect_err("the coordinate must refuse");
    assert!(
        matches!(err, NonceError::KeyMatchesOwnerPublicKey),
        "{err:?}"
    );
    let pending = KeyringEntry::new("stellar-agent-owner-other", "default")
        .unwrap()
        .get_password()
        .unwrap_err();
    assert!(
        matches!(pending, keyring_core::Error::PlatformFailure(_)),
        "{pending:?}"
    );
}
