//! Verify that a keyring entry with < 32 decoded bytes returns KeyTooShort.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod helpers;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use keyring_core::Entry as KeyringEntry;
use serial_test::serial;
use stellar_agent_nonce::{NonceError, NonceMint};

use helpers::{StaticCatalogue, far_future_expiry, init_mock, make_profile, now_before_expiry};

#[test]
#[serial]
fn key_too_short_returns_error() {
    init_mock();

    let profile = make_profile("key-too-short");

    // Manually store a 16-byte key (too short; need ≥ 32).
    let short_key = [0u8; 16];
    let encoded = URL_SAFE_NO_PAD.encode(short_key);
    let entry_ref = &profile.mcp_nonce_key_alias;
    let entry = KeyringEntry::new(&entry_ref.service, &entry_ref.account).unwrap();
    entry.set_password(&encoded).unwrap();

    let mint = NonceMint::from_profile(&profile).expect("from_profile");
    let cat = StaticCatalogue(&["stellar_balances"]);

    let err = mint
        .mint(
            &cat,
            b"xdr",
            now_before_expiry(),
            far_future_expiry(),
            "stellar_balances",
            "stellar:testnet",
        )
        .expect_err("key too short must fail");

    assert!(
        matches!(err, NonceError::KeyTooShort { actual: 16 }),
        "expected KeyTooShort {{ actual: 16 }}, got: {err:?}"
    );
}
