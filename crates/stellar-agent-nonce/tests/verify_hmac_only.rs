//! Tests for [`NonceMint::verify_hmac_only`] and the paired
//! [`NonceMint::record_verified_nonce`].
//!
//! `verify_hmac_only` runs the expiry check, chain binding check, and HMAC
//! tag comparison without touching the replay window.  The caller is expected
//! to call `record_verified_nonce` under a replay-window lock after the HMAC
//! phase succeeds.
//!
//! Covered paths:
//! - Happy path: mint → `verify_hmac_only` passes → `record_verified_nonce`
//!   inserts into window.
//! - `Expired`: `now_unix_ms >= expiry_unix_ms`.
//! - `ChainMismatch`: caller-supplied chain_id differs from profile's chain.
//! - `HmacMismatch`: tampered nonce tag / wrong envelope / wrong tool.
//! - `record_verified_nonce` returns `Replayed` on a second call with the same
//!   nonce (TOCTOU duplicate path).
//! - `KeyringError` (get_password failure) propagates as `NonceError::KeyringError`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only"
)]

mod helpers;

use keyring_core::mock;
use serial_test::serial;
use stellar_agent_nonce::{NonceError, NonceMint, NonceVerifyHmacOnlyRequest, ReplayWindow};

use helpers::{
    StaticCatalogue, far_future_expiry, init_mock, make_profile, now_before_expiry, seed_key,
};

// ─── happy path ──────────────────────────────────────────────────────────────

/// Mint a nonce, run `verify_hmac_only`, then `record_verified_nonce`.
///
/// After recording, the nonce appears in the replay window (len == 1) and a
/// second `record_verified_nonce` call returns `Replayed`.
#[test]
#[serial]
fn verify_hmac_only_happy_path_then_record() {
    init_mock();
    let key = [0xA1u8; 32];
    let profile = make_profile("vho-happy");
    seed_key(&profile, &key);

    let mint = NonceMint::from_profile(&profile).expect("from_profile");
    let cat = StaticCatalogue(&["stellar_balances"]);
    let expiry = far_future_expiry();
    let now = now_before_expiry();
    let envelope = b"canonical_xdr";

    let nonce = mint
        .mint(
            &cat,
            envelope,
            now,
            expiry,
            "stellar_balances",
            "stellar:testnet",
        )
        .expect("mint ok");

    // Phase 1: HMAC-only verification (no replay window touched).
    mint.verify_hmac_only(NonceVerifyHmacOnlyRequest {
        nonce: &nonce,
        envelope_xdr: envelope,
        expiry_unix_ms: expiry,
        tool_name: "stellar_balances",
        chain_id: "stellar:testnet",
        now_unix_ms: now,
    })
    .expect("verify_hmac_only must pass for a correctly formed nonce");

    // Phase 2: record under (simulated) replay-window lock.
    let mut window = ReplayWindow::new();
    mint.record_verified_nonce(&mut window, &nonce, expiry)
        .expect("first record must succeed");

    assert_eq!(
        window.len(),
        1,
        "replay window must contain exactly one entry after record"
    );
}

/// `record_verified_nonce` returns `Replayed` when the same nonce is recorded twice.
///
/// This exercises the TOCTOU-bounded duplicate path where two concurrent callers
/// both pass `verify_hmac_only` for the same nonce before either records it.
#[test]
#[serial]
fn record_verified_nonce_returns_replayed_on_duplicate() {
    init_mock();
    let key = [0xA2u8; 32];
    let profile = make_profile("vho-replay");
    seed_key(&profile, &key);

    let mint = NonceMint::from_profile(&profile).expect("from_profile");
    let cat = StaticCatalogue(&["stellar_pay"]);
    let expiry = far_future_expiry();
    let now = now_before_expiry();
    let envelope = b"xdr_payload";

    let nonce = mint
        .mint(
            &cat,
            envelope,
            now,
            expiry,
            "stellar_pay",
            "stellar:testnet",
        )
        .expect("mint ok");

    let mut window = ReplayWindow::new();

    // First record succeeds.
    mint.record_verified_nonce(&mut window, &nonce, expiry)
        .expect("first record ok");

    // Second record of the same nonce must return Replayed.
    let err = mint
        .record_verified_nonce(&mut window, &nonce, expiry)
        .expect_err("second record of the same nonce must fail");

    assert!(
        matches!(err, NonceError::Replayed),
        "expected Replayed, got: {err:?}"
    );
}

// ─── Expired ─────────────────────────────────────────────────────────────────

/// `verify_hmac_only` returns `Expired` when `now_unix_ms >= expiry_unix_ms`.
///
/// The expiry check fires before key load, so no HMAC computation occurs.
#[test]
#[serial]
fn verify_hmac_only_returns_expired_when_now_at_expiry() {
    init_mock();
    let key = [0xA3u8; 32];
    let profile = make_profile("vho-expired");
    seed_key(&profile, &key);

    let mint = NonceMint::from_profile(&profile).expect("from_profile");
    let cat = StaticCatalogue(&["stellar_balances"]);
    let expiry = far_future_expiry();
    let now_at_mint = now_before_expiry();
    let envelope = b"xdr_bytes";

    let nonce = mint
        .mint(
            &cat,
            envelope,
            now_at_mint,
            expiry,
            "stellar_balances",
            "stellar:testnet",
        )
        .expect("mint ok");

    // Advance clock to the expiry boundary (now == expiry → expired).
    let now_expired = expiry;

    let err = mint
        .verify_hmac_only(NonceVerifyHmacOnlyRequest {
            nonce: &nonce,
            envelope_xdr: envelope,
            expiry_unix_ms: expiry,
            tool_name: "stellar_balances",
            chain_id: "stellar:testnet",
            now_unix_ms: now_expired,
        })
        .expect_err("nonce at expiry boundary must return Expired");

    assert!(
        matches!(err, NonceError::Expired),
        "expected Expired, got: {err:?}"
    );
}

/// `verify_hmac_only` returns `Expired` when clock is past the expiry.
#[test]
#[serial]
fn verify_hmac_only_returns_expired_when_now_past_expiry() {
    init_mock();
    let key = [0xA4u8; 32];
    let profile = make_profile("vho-expired-past");
    seed_key(&profile, &key);

    let mint = NonceMint::from_profile(&profile).expect("from_profile");
    let cat = StaticCatalogue(&["stellar_pay"]);
    let expiry = far_future_expiry();
    let now = now_before_expiry();
    let envelope = b"some_xdr";

    let nonce = mint
        .mint(
            &cat,
            envelope,
            now,
            expiry,
            "stellar_pay",
            "stellar:testnet",
        )
        .expect("mint ok");

    let err = mint
        .verify_hmac_only(NonceVerifyHmacOnlyRequest {
            nonce: &nonce,
            envelope_xdr: envelope,
            expiry_unix_ms: expiry,
            tool_name: "stellar_pay",
            chain_id: "stellar:testnet",
            now_unix_ms: expiry + 1, // strictly past expiry
        })
        .expect_err("nonce past expiry must return Expired");

    assert!(
        matches!(err, NonceError::Expired),
        "expected Expired, got: {err:?}"
    );
}

// ─── ChainMismatch ────────────────────────────────────────────────────────────

/// `verify_hmac_only` returns `ChainMismatch` when the supplied `chain_id`
/// differs from the profile's chain.
///
/// This check fires before key load.
#[test]
#[serial]
fn verify_hmac_only_returns_chain_mismatch() {
    init_mock();
    let key = [0xA5u8; 32];
    let profile = make_profile("vho-chain");
    seed_key(&profile, &key);

    let mint = NonceMint::from_profile(&profile).expect("from_profile");
    let cat = StaticCatalogue(&["stellar_balances"]);
    let expiry = far_future_expiry();
    let now = now_before_expiry();
    let envelope = b"xdr";

    let nonce = mint
        .mint(
            &cat,
            envelope,
            now,
            expiry,
            "stellar_balances",
            "stellar:testnet",
        )
        .expect("mint ok");

    let err = mint
        .verify_hmac_only(NonceVerifyHmacOnlyRequest {
            nonce: &nonce,
            envelope_xdr: envelope,
            expiry_unix_ms: expiry,
            tool_name: "stellar_balances",
            chain_id: "stellar:mainnet", // profile is testnet
            now_unix_ms: now,
        })
        .expect_err("wrong chain_id must return ChainMismatch");

    assert!(
        matches!(
            err,
            NonceError::ChainMismatch {
                ref expected,
                ref got,
            } if expected == "stellar:testnet" && got == "stellar:mainnet"
        ),
        "expected ChainMismatch(testnet, mainnet), got: {err:?}"
    );
}

// ─── HmacMismatch ────────────────────────────────────────────────────────────

/// `verify_hmac_only` returns `HmacMismatch` when the nonce tag was minted for
/// a different envelope than the one presented at verify time.
#[test]
#[serial]
fn verify_hmac_only_returns_hmac_mismatch_on_tampered_envelope() {
    init_mock();
    let key = [0xA6u8; 32];
    let profile = make_profile("vho-hmac-env");
    seed_key(&profile, &key);

    let mint = NonceMint::from_profile(&profile).expect("from_profile");
    let cat = StaticCatalogue(&["stellar_pay"]);
    let expiry = far_future_expiry();
    let now = now_before_expiry();
    let original_envelope = b"legitimate_xdr";
    let tampered_envelope = b"tampered_xdr";

    let nonce = mint
        .mint(
            &cat,
            original_envelope,
            now,
            expiry,
            "stellar_pay",
            "stellar:testnet",
        )
        .expect("mint ok");

    let err = mint
        .verify_hmac_only(NonceVerifyHmacOnlyRequest {
            nonce: &nonce,
            envelope_xdr: tampered_envelope,
            expiry_unix_ms: expiry,
            tool_name: "stellar_pay",
            chain_id: "stellar:testnet",
            now_unix_ms: now,
        })
        .expect_err("tampered envelope must return HmacMismatch");

    assert!(
        matches!(err, NonceError::HmacMismatch),
        "expected HmacMismatch, got: {err:?}"
    );
}

/// `verify_hmac_only` returns `HmacMismatch` when the nonce tag was minted for
/// a different tool than the one presented at verify time.
#[test]
#[serial]
fn verify_hmac_only_returns_hmac_mismatch_on_tool_substitution() {
    init_mock();
    let key = [0xA7u8; 32];
    let profile = make_profile("vho-hmac-tool");
    seed_key(&profile, &key);

    let mint = NonceMint::from_profile(&profile).expect("from_profile");
    let cat = StaticCatalogue(&["stellar_pay", "stellar_balances"]);
    let expiry = far_future_expiry();
    let now = now_before_expiry();
    let envelope = b"xdr_bytes";

    // Mint for stellar_pay.
    let nonce = mint
        .mint(
            &cat,
            envelope,
            now,
            expiry,
            "stellar_pay",
            "stellar:testnet",
        )
        .expect("mint ok");

    // Verify with stellar_balances — different tool → HmacMismatch.
    let err = mint
        .verify_hmac_only(NonceVerifyHmacOnlyRequest {
            nonce: &nonce,
            envelope_xdr: envelope,
            expiry_unix_ms: expiry,
            tool_name: "stellar_balances",
            chain_id: "stellar:testnet",
            now_unix_ms: now,
        })
        .expect_err("tool substitution must return HmacMismatch");

    assert!(
        matches!(err, NonceError::HmacMismatch),
        "expected HmacMismatch, got: {err:?}"
    );
}

/// `verify_hmac_only` returns `HmacMismatch` when the nonce tag bytes are
/// manually corrupted (single-byte flip in the tag portion).
#[test]
#[serial]
fn verify_hmac_only_returns_hmac_mismatch_on_corrupted_tag() {
    init_mock();
    let key = [0xA8u8; 32];
    let profile = make_profile("vho-hmac-corrupt");
    seed_key(&profile, &key);

    let mint = NonceMint::from_profile(&profile).expect("from_profile");
    let cat = StaticCatalogue(&["stellar_pay"]);
    let expiry = far_future_expiry();
    let now = now_before_expiry();
    let envelope = b"some_xdr";

    let nonce = mint
        .mint(
            &cat,
            envelope,
            now,
            expiry,
            "stellar_pay",
            "stellar:testnet",
        )
        .expect("mint ok");

    // Flip one byte in the HMAC tag (bytes 16..48) to corrupt it.
    let mut raw = nonce.inner_bytes();
    raw[16] ^= 0xFF;
    let corrupted = stellar_agent_nonce::mint::Nonce::from_raw(raw);

    let err = mint
        .verify_hmac_only(NonceVerifyHmacOnlyRequest {
            nonce: &corrupted,
            envelope_xdr: envelope,
            expiry_unix_ms: expiry,
            tool_name: "stellar_pay",
            chain_id: "stellar:testnet",
            now_unix_ms: now,
        })
        .expect_err("corrupted tag must return HmacMismatch");

    assert!(
        matches!(err, NonceError::HmacMismatch),
        "expected HmacMismatch, got: {err:?}"
    );
}

// ─── KeyringError propagation ─────────────────────────────────────────────────

/// `verify_hmac_only` propagates `NonceError::KeyringError` when `get_password`
/// fails on the mock keyring.
///
/// The error is injected via `mock::Cred::set_error` after the nonce has been
/// minted (so the mock entry exists).  The next `verify_hmac_only` call reaches
/// `load_key` → `get_password` → the armed error fires.
#[test]
#[serial]
fn verify_hmac_only_propagates_keyring_error_on_get_password_failure() {
    init_mock();
    let key = [0xA9u8; 32];
    let profile = make_profile("vho-keyring-err");
    seed_key(&profile, &key);

    let mint = NonceMint::from_profile(&profile).expect("from_profile");
    let cat = StaticCatalogue(&["stellar_pay"]);
    let expiry = far_future_expiry();
    let now = now_before_expiry();
    let envelope = b"xdr";

    // Mint while the keyring is healthy.
    let nonce = mint
        .mint(
            &cat,
            envelope,
            now,
            expiry,
            "stellar_pay",
            "stellar:testnet",
        )
        .expect("mint ok");

    // Arm the mock entry to fail on the next get_password call.
    let entry_ref = &profile.mcp_nonce_key_alias;
    let entry =
        keyring_core::Entry::new(&entry_ref.service, &entry_ref.account).expect("mock entry");
    let cred: &mock::Cred = entry
        .as_any()
        .downcast_ref::<mock::Cred>()
        .expect("credential must downcast to mock::Cred when mock store is active");
    cred.set_error(keyring_core::Error::NoStorageAccess(Box::new(
        std::io::Error::other("mock keyring locked"),
    )));

    // verify_hmac_only must reach load_key, hit get_password, and return KeyringError.
    let err = mint
        .verify_hmac_only(NonceVerifyHmacOnlyRequest {
            nonce: &nonce,
            envelope_xdr: envelope,
            expiry_unix_ms: expiry,
            tool_name: "stellar_pay",
            chain_id: "stellar:testnet",
            now_unix_ms: now,
        })
        .expect_err("get_password failure must propagate as KeyringError");

    assert!(
        matches!(err, NonceError::KeyringError(_)),
        "expected KeyringError, got: {err:?}"
    );
}
