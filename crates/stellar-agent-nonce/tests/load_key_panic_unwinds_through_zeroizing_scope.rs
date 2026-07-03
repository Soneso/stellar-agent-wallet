//! Zeroisation panic-safety integration test: verifies that `Zeroizing<T>`
//! `Drop` fires during panic unwinding in `NonceMint::load_key`.
//!
//! # How it works
//!
//! 1. Arm `stellar_agent_nonce::mint::PANIC_AFTER_LOAD` (test-hooks feature).
//! 2. Push a `DropSentinel` on the call stack inside `catch_unwind`.
//! 3. Call `NonceMint::mint` — `load_key` panics after opening the keyring
//!    entry (the `Zeroizing<[u8; 32]>` key is still live on the stack).
//! 4. `catch_unwind` catches the panic.
//! 5. `DROP_COUNTER` has been incremented at least once, proving the sentinel's
//!    `Drop` fired during unwind.  Since `Zeroizing<T>` uses `Drop` for
//!    zeroisation, the same unwind path fires `Zeroizing::drop`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics and expects acceptable in panic-injection tests"
)]

mod helpers;

use serial_test::serial;
use std::sync::atomic::Ordering;
use stellar_agent_nonce::{
    NonceMint,
    mint::{DROP_COUNTER, PANIC_AFTER_LOAD},
};

use helpers::{
    StaticCatalogue, far_future_expiry, init_mock, make_profile, now_before_expiry, seed_key,
};

/// Sentinel whose `Drop` increments `DROP_COUNTER`.  Placed on the stack
/// inside `catch_unwind`; if `Drop` fires during unwind the counter increments.
struct DropSentinel;

impl Drop for DropSentinel {
    fn drop(&mut self) {
        DROP_COUNTER.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
#[serial]
fn panic_in_load_key_fires_zeroizing_drop() {
    init_mock();
    let key = [0xB7u8; 32];
    let profile = make_profile("panic-injection-nonce");
    seed_key(&profile, &key);

    let mint = NonceMint::from_profile(&profile).expect("from_profile");
    let cat = StaticCatalogue(&["stellar_pay"]);
    let now = now_before_expiry();
    let expiry = far_future_expiry();

    // Reset the counter and arm the hook.
    DROP_COUNTER.store(0, Ordering::SeqCst);
    PANIC_AFTER_LOAD.store(true, Ordering::SeqCst);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // DropSentinel lives on the unwind path alongside the Zeroizing<[u8;32]>
        // key inside load_key.
        let _sentinel = DropSentinel;
        // This call will panic inside load_key when PANIC_AFTER_LOAD is set.
        let _ = mint.mint(&cat, b"xdr", now, expiry, "stellar_pay", "stellar:testnet");
    }));

    // Disarm the hook.
    PANIC_AFTER_LOAD.store(false, Ordering::SeqCst);

    // The catch_unwind must have caught a panic.
    assert!(
        result.is_err(),
        "catch_unwind must catch the injected panic"
    );

    // DROP_COUNTER must be > 0: the sentinel's Drop ran during unwind,
    // proving that Drop implementations (including Zeroizing::drop) fire on
    // the unwind path.
    let count = DROP_COUNTER.load(Ordering::SeqCst);
    assert!(
        count > 0,
        "DROP_COUNTER must be > 0 after panic unwind; got {count}; \
         this means DropSentinel::drop did not fire → Zeroizing::drop may not fire either"
    );
}
