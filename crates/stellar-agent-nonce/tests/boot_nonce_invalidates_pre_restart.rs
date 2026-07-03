//! Verify that the `boot_nonce` is process-scoped and stable within a process.
//!
//! The `boot_nonce` is stored in a `OnceLock` so all `NonceMint` instances in
//! the same process share the same value.  A process restart generates a new
//! `boot_nonce`, causing all pre-restart nonces to fail HMAC verification.
//! The full end-to-end restart test is an OS-level concern; here we verify
//! the process-scoping and HMAC binding properties.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod helpers;

use serial_test::serial;
use stellar_agent_nonce::{NonceMint, ReplayWindow};

use helpers::{
    StaticCatalogue, far_future_expiry, init_mock, make_profile, now_before_expiry, seed_key,
    verify_request,
};

/// Verifies that the `boot_nonce` is stable within a process (not re-generated
/// per `NonceMint` instance).  Because all instances share the same
/// process-scoped `boot_nonce`, a nonce minted by one instance verifies
/// correctly on a second instance constructed in the same process.
#[test]
#[serial]
fn boot_nonce_stable_within_process() {
    init_mock();
    let key = [0x44u8; 32];
    let profile = make_profile("boot-nonce-stable");
    seed_key(&profile, &key);

    let mint1 = NonceMint::from_profile(&profile).expect("mint1");
    let mint2 = NonceMint::from_profile(&profile).expect("mint2");

    // Both mints in the same process must share the same boot_nonce.
    assert_eq!(
        mint1.boot_nonce(),
        mint2.boot_nonce(),
        "boot_nonce must be stable (process-scoped OnceLock) across NonceMint instances"
    );
}

/// Verify that a nonce minted and then verified on the same process works.
/// (Baseline: boot_nonce stability means mint+verify round-trip succeeds.)
#[test]
#[serial]
fn boot_nonce_same_process_round_trip() {
    init_mock();
    let key = [0x44u8; 32];
    let profile = make_profile("boot-nonce-round-trip");
    seed_key(&profile, &key);

    let mint = NonceMint::from_profile(&profile).expect("from_profile");
    let cat = StaticCatalogue(&["stellar_balances"]);
    let expiry = far_future_expiry();
    let now = now_before_expiry();
    let envelope = b"restart_test_xdr";

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

    // Construct a second NonceMint — same boot_nonce since same process.
    let mint2 = NonceMint::from_profile(&profile).expect("mint2");

    let mut window = ReplayWindow::new();
    // Verify on the second mint instance — MUST succeed (shared boot_nonce).
    mint2
        .verify(verify_request(
            &mut window,
            &nonce,
            envelope,
            expiry,
            "stellar_balances",
            "stellar:testnet",
            now,
        ))
        .expect("verify on second mint instance must succeed (same boot_nonce)");
}

/// Asserts that two different `NonceMint` instances expose the same
/// `boot_nonce` (process-scoped `OnceLock` invariant).  A future change
/// making `boot_nonce` per-instance would cause this test to fail, which
/// would break the fail-closed-on-restart invariant.
#[test]
#[serial]
fn boot_nonce_must_be_identical_across_instances() {
    init_mock();
    let key = [0x55u8; 32];
    let profile = make_profile("boot-nonce-identical");
    seed_key(&profile, &key);

    let mint_a = NonceMint::from_profile(&profile).expect("mint_a");
    let mint_b = NonceMint::from_profile(&profile).expect("mint_b");

    assert_eq!(
        mint_a.boot_nonce(),
        mint_b.boot_nonce(),
        "boot_nonce values must be identical across NonceMint instances in the same process \
         (process-scoped OnceLock); a difference would indicate boot_nonce is per-instance \
         rather than per-process, breaking the fail-closed-on-restart invariant"
    );
}

// HMAC-level boot_nonce-binding coverage lives in the unit-test
// `compute_tag_differs_on_boot_nonce` in `src/mint.rs` (called via the private
// `compute_tag` helper, which integration tests cannot reach).  The
// OnceLock-level process-scoping invariant is covered by the two tests above.
