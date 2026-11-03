//! The HMAC tag authenticates the salt.
//!
//! A nonce is `salt(16) || tag(32)` and the replay window keys on all 48
//! bytes.  The tag covers the salt, so a copy of a nonce with any salt byte
//! changed fails verification with `HmacMismatch` on both verify paths and
//! never reaches the replay window as a fresh key.  A tag computed over a
//! preimage without the domain constant and the salt does not verify.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use hmac::{Hmac, KeyInit, Mac};
use serial_test::serial;
use sha2::{Digest, Sha256};
use stellar_agent_nonce::{Nonce, NonceError, NonceMint, NonceVerifyHmacOnlyRequest, ReplayWindow};

use crate::helpers::{
    StaticCatalogue, far_future_expiry, init_mock, make_profile, now_before_expiry, seed_key,
    verify_request,
};

const TOOL: &str = "stellar_pay";
const CHAIN: &str = "stellar:testnet";

/// Returns a copy of `nonce` with one bit of salt byte `index` flipped.
fn with_salt_bit_flipped(nonce: &Nonce, index: usize) -> Nonce {
    let mut raw = nonce.inner_bytes();
    raw[index] ^= 1u8 << (index % 8);
    Nonce::from_raw(raw)
}

#[test]
#[serial]
fn a_changed_salt_byte_fails_verification() {
    init_mock();
    let profile = make_profile("salt-binding-verify");
    seed_key(&profile, &[0x5Au8; 32]);

    let mint = NonceMint::from_profile(&profile, "nonce-test").expect("from_profile");
    let cat = StaticCatalogue(&[TOOL]);
    let expiry = far_future_expiry();
    let now = now_before_expiry();
    let envelope = b"salt_binding_xdr";

    let nonce = mint
        .mint(&cat, envelope, now, expiry, TOOL, CHAIN)
        .expect("mint ok");

    let mut window = ReplayWindow::new();
    mint.verify(verify_request(
        &mut window,
        &nonce,
        envelope,
        expiry,
        TOOL,
        CHAIN,
        now,
    ))
    .expect("the minted nonce verifies once");

    for index in 0..16 {
        let altered = with_salt_bit_flipped(&nonce, index);
        let err = mint
            .verify(verify_request(
                &mut window,
                &altered,
                envelope,
                expiry,
                TOOL,
                CHAIN,
                now,
            ))
            .expect_err("a nonce with a changed salt byte must not verify");
        assert!(
            matches!(err, NonceError::HmacMismatch),
            "salt byte {index}: expected HmacMismatch, got: {err:?}"
        );
    }

    assert_eq!(
        window.len(),
        1,
        "only the minted nonce is recorded; no altered copy reaches the window"
    );
}

#[test]
#[serial]
fn a_changed_salt_byte_fails_the_split_path() {
    init_mock();
    let profile = make_profile("salt-binding-split");
    seed_key(&profile, &[0x5Bu8; 32]);

    let mint = NonceMint::from_profile(&profile, "nonce-test").expect("from_profile");
    let cat = StaticCatalogue(&[TOOL]);
    let expiry = far_future_expiry();
    let now = now_before_expiry();
    let envelope = b"salt_binding_split_xdr";

    let nonce = mint
        .mint(&cat, envelope, now, expiry, TOOL, CHAIN)
        .expect("mint ok");

    let request = |nonce: &Nonce| -> Result<(), NonceError> {
        mint.verify_hmac_only(NonceVerifyHmacOnlyRequest {
            nonce,
            envelope_xdr: envelope,
            expiry_unix_ms: expiry,
            tool_name: TOOL,
            chain_id: CHAIN,
            now_unix_ms: now,
        })
    };

    request(&nonce).expect("the minted nonce passes the HMAC phase");
    let mut window = ReplayWindow::new();
    mint.record_verified_nonce(&mut window, &nonce, expiry)
        .expect("the minted nonce is recorded once");

    for index in 0..16 {
        let altered = with_salt_bit_flipped(&nonce, index);
        let err = request(&altered).expect_err("a nonce with a changed salt byte must not verify");
        assert!(
            matches!(err, NonceError::HmacMismatch),
            "salt byte {index}: expected HmacMismatch, got: {err:?}"
        );
    }

    assert_eq!(window.len(), 1, "only the minted nonce is recorded");
}

#[test]
#[serial]
fn a_tag_over_the_earlier_preimage_is_refused() {
    init_mock();
    let key = [0x5Cu8; 32];
    let profile = make_profile("salt-binding-preimage");
    seed_key(&profile, &key);

    let mint = NonceMint::from_profile(&profile, "nonce-test").expect("from_profile");
    let expiry = far_future_expiry();
    let now = now_before_expiry();
    let envelope = b"salt_binding_preimage_xdr";

    // The preimage without the domain constant and without the salt: boot
    // nonce, envelope hash, expiry, then the length-prefixed tool and chain.
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).expect("32-byte key");
    mac.update(mint.boot_nonce());
    mac.update(&Sha256::digest(envelope));
    mac.update(&expiry.to_be_bytes());
    mac.update(&u32::try_from(TOOL.len()).unwrap().to_be_bytes());
    mac.update(TOOL.as_bytes());
    mac.update(&u32::try_from(CHAIN.len()).unwrap().to_be_bytes());
    mac.update(CHAIN.as_bytes());
    let earlier_tag = mac.finalize().into_bytes();

    let mut raw = [0u8; 48];
    raw[..16].copy_from_slice(&[0xA5u8; 16]);
    raw[16..].copy_from_slice(&earlier_tag);
    let nonce = Nonce::from_raw(raw);

    let mut window = ReplayWindow::new();
    let err = mint
        .verify(verify_request(
            &mut window,
            &nonce,
            envelope,
            expiry,
            TOOL,
            CHAIN,
            now,
        ))
        .expect_err("a tag over the earlier preimage must not verify");
    assert!(
        matches!(err, NonceError::HmacMismatch),
        "expected HmacMismatch, got: {err:?}"
    );
    assert_eq!(window.len(), 0, "a refused nonce is not recorded");

    let err = mint
        .verify_hmac_only(NonceVerifyHmacOnlyRequest {
            nonce: &nonce,
            envelope_xdr: envelope,
            expiry_unix_ms: expiry,
            tool_name: TOOL,
            chain_id: CHAIN,
            now_unix_ms: now,
        })
        .expect_err("verify_hmac_only must not accept a tag over the earlier preimage");
    assert!(
        matches!(err, NonceError::HmacMismatch),
        "verify_hmac_only: expected HmacMismatch, got: {err:?}"
    );
}

#[test]
#[serial]
fn two_genuine_mints_stay_distinct() {
    init_mock();
    let profile = make_profile("salt-binding-distinct");
    seed_key(&profile, &[0x5Du8; 32]);

    let mint = NonceMint::from_profile(&profile, "nonce-test").expect("from_profile");
    let cat = StaticCatalogue(&[TOOL]);
    let expiry = far_future_expiry();
    let now = now_before_expiry();
    let envelope = b"salt_binding_distinct_xdr";

    let first = mint
        .mint(&cat, envelope, now, expiry, TOOL, CHAIN)
        .expect("first mint ok");
    let second = mint
        .mint(&cat, envelope, now, expiry, TOOL, CHAIN)
        .expect("second mint ok");

    assert_ne!(first.salt(), second.salt(), "each mint draws its own salt");
    assert_ne!(
        first.tag(),
        second.tag(),
        "the tag covers the salt, so two mints of one request differ in the tag"
    );

    let mut window = ReplayWindow::new();
    for nonce in [&first, &second] {
        mint.verify(verify_request(
            &mut window,
            nonce,
            envelope,
            expiry,
            TOOL,
            CHAIN,
            now,
        ))
        .expect("each genuine nonce verifies once");
    }
    for nonce in [&first, &second] {
        let err = mint
            .verify(verify_request(
                &mut window,
                nonce,
                envelope,
                expiry,
                TOOL,
                CHAIN,
                now,
            ))
            .expect_err("a consumed nonce must not verify again");
        assert!(
            matches!(err, NonceError::Replayed),
            "expected Replayed, got: {err:?}"
        );
    }
    assert_eq!(window.len(), 2);
}
