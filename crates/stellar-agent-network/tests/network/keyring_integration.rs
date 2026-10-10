//! Integration tests for the `stellar-agent-network::keyring` module.
//!
//! # Scenarios covered
//!
//! 1. Happy path — store seed, look up via `signer_from_keyring`, sign, verify.
//! 2. Pubkey mismatch — `AuthError::SignerKeyMismatch` before any signing.
//! 3. Missing entry — `AuthError::KeyringNotFound`.
//! 4. Invalid S-strkey stored in the keyring — specific error.
//! 5. Lazy-load timing — delete entry after handle construction, then sign → error.
//! 6. Memory-residue — structural zeroize-on-drop contract (compile-time + type-level).
//! 7. Panic-injected zeroisation — via production-side hook in
//!    `sign_payload_verifying_pubkey`; Drop-sentinel counter proves Drop fired.
//! 8. Signature length — `sign_tx_payload` returns exactly 64 bytes.
//! 9. Cached public key — `public_key()` returns the correct key without keyring re-load.
//! 10. Entry ref accessor — `entry_ref()` returns the stored reference.
//! 11. Host-swap detection — construct handle, swap entry value, sign → `SignerKeyMismatch`.
//!
//! # Test isolation and serialisation
//!
//! All tests share a process-global default keyring store
//! (`keyring_core::set_default_store`).  To prevent races from parallel test
//! execution, every test in this file is annotated `#[serial]` using the
//! `serial_test` crate.  Within a serial run, each test also calls
//! `keyring_mock::install()` and uses a nanosecond-timestamp-namespaced
//! service name to ensure entries from one test do not interfere with another.
//!
//! # Memory-residue test
//!
//! The equivalent test in `signing/software.rs` (`secret_accessible_before_drop`)
//! confirms `SoftwareSigningKey`'s zeroize-on-drop contract at the type level.
//! For the keyring path, the same contract applies: the seed bytes exist only
//! within `sign_payload_verifying_pubkey`'s stack frame.
//! All `Zeroizing<T>` wrappers fire `Drop` on every exit path including panic.
//!
//! Reading freed heap pointers without `unsafe` code is not possible in safe
//! Rust, so the test verifies the structural contract:
//! 1. `SoftwareSigningKey` has an explicit `impl Drop` (auditable anchor).
//! 2. `ed25519_dalek::SigningKey` implements `ZeroizeOnDrop` (compile-time assert).
//! 3. `Zeroizing<T>` from the `zeroize` crate is the established standard for
//!    stack-variable clearing; its correctness is audited by the RustCrypto org.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    unused_variables,
    reason = "test-only; panics and unwraps are acceptable in integration tests"
)]

use ed25519_dalek::Verifier;
use serial_test::serial;
use stellar_agent_core::{
    error::{AuthError, ErrorCategory, WalletError},
    profile::schema::KeyringEntryRef,
};
use stellar_agent_network::keyring::signer_from_keyring;
use stellar_agent_test_support::keyring_mock;

// ─── helpers ─────────────────────────────────────────────────────────────────

/// Derive the G-strkey for a 32-byte seed.
fn gstrkey_for_seed(seed: [u8; 32]) -> String {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let vk = signing_key.verifying_key();
    stellar_strkey::ed25519::PublicKey(vk.to_bytes())
        .to_string()
        .to_string()
}

/// Build the S-strkey for a 32-byte seed.
fn sstrkey_for_seed(seed: [u8; 32]) -> String {
    stellar_strkey::ed25519::PrivateKey(seed)
        .as_unredacted()
        .to_string()
        .to_string()
}

/// Generate a unique `KeyringEntryRef` for the given test name.
///
/// Uses nanosecond timestamp + the test name as the service so parallel tests
/// get distinct entries even with the same prefix.
fn unique_ref(test_name: &str) -> KeyringEntryRef {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    KeyringEntryRef::new(format!("stellar-agent-test-{test_name}-{ts}"), "default")
}

/// Store an S-strkey in the mock keyring for the given `entry_ref`.
fn store_sstrkey(entry_ref: &KeyringEntryRef, sstrkey: &str) {
    let entry = keyring_core::Entry::new(&entry_ref.service, &entry_ref.account)
        .expect("mock entry construction must succeed");
    entry
        .set_password(sstrkey)
        .expect("mock store set_password must succeed");
}

// ─── tests ───────────────────────────────────────────────────────────────────

/// 1. Happy path: store seed → look up → sign → verify.
#[tokio::test]
#[serial]
async fn happy_path_sign_and_verify() {
    keyring_mock::install().expect("mock store init");

    let seed = [0xAA_u8; 32];
    let entry_ref = unique_ref("happy");
    let expected_g = gstrkey_for_seed(seed);
    store_sstrkey(&entry_ref, &sstrkey_for_seed(seed));

    let handle = signer_from_keyring(&entry_ref, &expected_g)
        .await
        .expect("signer_from_keyring must succeed on valid entry");

    // public_key() must return the cached key without touching the keyring.
    let pk = handle.public_key();
    assert_eq!(pk.0, {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        signing_key.verifying_key().to_bytes()
    });

    // sign a known payload and verify the signature.
    let payload = [0x01_u8; 32];
    let sig_bytes = handle
        .sign_tx_payload(&payload)
        .await
        .expect("signing must succeed");
    assert_eq!(sig_bytes.len(), 64);

    let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk.0).expect("valid verifying key");
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    vk.verify(&payload, &sig).expect("signature must verify");
}

/// 2. Pubkey mismatch: stored seed does not match `expected_source_g`.
///    Must fail with `SignerKeyMismatch` BEFORE any signing.
#[tokio::test]
#[serial]
async fn pubkey_mismatch_returns_signer_key_mismatch() {
    keyring_mock::install().expect("mock store init");

    let seed = [0xBB_u8; 32];
    let entry_ref = unique_ref("mismatch");
    store_sstrkey(&entry_ref, &sstrkey_for_seed(seed));

    // Supply an expected G-strkey that is completely unrelated to the seed.
    let wrong_g = "GDUMMYDUMMYDUMMYDUMMYDUMMYDUMMYDUMMYDUMMYDUMMYDUMMYDUMMY";

    let result = signer_from_keyring(&entry_ref, wrong_g).await;
    assert!(result.is_err(), "mismatch must fail");
    let err = match result {
        Err(e) => e,
        Ok(_) => panic!("expected Err for key mismatch"),
    };
    assert_eq!(err.category(), ErrorCategory::Auth);
    assert_eq!(err.code(), "auth.signer_key_mismatch");
    // Verify the error surfaces the expected and got keys (both non-secret).
    if let WalletError::Auth(AuthError::SignerKeyMismatch { expected, got }) = &err {
        assert_eq!(expected, wrong_g);
        assert_eq!(*got, gstrkey_for_seed(seed));
    } else {
        panic!("expected SignerKeyMismatch variant");
    }
}

/// 3. Missing entry: the keyring entry was never stored.
///    Must fail with `KeyringNotFound`.
#[tokio::test]
#[serial]
async fn missing_entry_returns_keyring_not_found() {
    keyring_mock::install().expect("mock store init");

    let entry_ref = unique_ref("missing");
    // Do NOT store anything in the keyring for this entry.

    let result = signer_from_keyring(
        &entry_ref,
        "GDUMMYDUMMYDUMMYDUMMYDUMMYDUMMYDUMMYDUMMYDUMMYDUMMYDUMMY",
    )
    .await;
    assert!(result.is_err(), "missing entry must fail");
    let err = match result {
        Err(e) => e,
        Ok(_) => panic!("expected Err for missing entry"),
    };
    assert_eq!(err.category(), ErrorCategory::Auth);
    assert_eq!(err.code(), "auth.keyring_not_found");
}

/// 4. Invalid S-strkey: garbage stored in the keyring.
///    Must fail with a specific KeyringNotFound error (corrupt entry).
#[tokio::test]
#[serial]
async fn invalid_sstrkey_in_keyring_returns_keyring_not_found() {
    keyring_mock::install().expect("mock store init");

    let entry_ref = unique_ref("invalid");
    store_sstrkey(&entry_ref, "not-a-valid-s-strkey-garbage-value");

    let result = signer_from_keyring(
        &entry_ref,
        "GDUMMYDUMMYDUMMYDUMMYDUMMYDUMMYDUMMYDUMMYDUMMYDUMMYDUMMY",
    )
    .await;
    assert!(result.is_err(), "invalid S-strkey must fail");
    let err = match result {
        Err(e) => e,
        Ok(_) => panic!("expected Err for invalid S-strkey"),
    };
    assert_eq!(err.category(), ErrorCategory::Auth);
    assert_eq!(err.code(), "auth.keyring_not_found");
    // error message must NOT contain the garbage value that was stored.
    // It should only contain the service name or an explanation.
    assert!(
        !err.message().contains("not-a-valid-s-strkey-garbage-value"),
        "error must not echo stored secret-position content"
    );
}

/// 5. Lazy-load timing: construct handle, delete the entry, then sign → error.
///    Proves that `sign_tx_payload` RE-LOADS the secret (lazy, not eager-cached).
#[tokio::test]
#[serial]
async fn lazy_load_delete_then_sign_returns_error() {
    keyring_mock::install().expect("mock store init");

    let seed = [0xCC_u8; 32];
    let entry_ref = unique_ref("lazy");
    let expected_g = gstrkey_for_seed(seed);
    store_sstrkey(&entry_ref, &sstrkey_for_seed(seed));

    // Construct the handle — this succeeds and caches the public key.
    let handle = signer_from_keyring(&entry_ref, &expected_g)
        .await
        .expect("handle construction must succeed");

    // Delete the keyring entry AFTER handle construction.
    let entry = keyring_core::Entry::new(&entry_ref.service, &entry_ref.account)
        .expect("mock entry construction");
    entry
        .delete_credential()
        .expect("delete must succeed on mock store");

    // Now try to sign — must fail because the entry is gone.
    // This proves the secret is NOT cached in the handle.
    let payload = [0xDD_u8; 32];
    let result = handle.sign_tx_payload(&payload).await;
    assert!(result.is_err(), "signing after entry deletion must fail");
    let err = match result {
        Err(e) => e,
        Ok(_) => panic!("expected Err after entry deletion"),
    };
    assert_eq!(err.category(), ErrorCategory::Auth);
    assert_eq!(err.code(), "auth.keyring_not_found");
}

/// 6. Memory-residue structural contract.
///
/// Direct heap scanning is not feasible in safe Rust; the zeroize-on-drop
/// contract is verified through four structural invariants instead.
#[test]
#[serial]
fn memory_residue_structural_contract() {
    // Invariant 1: `SoftwareSigningKey` has an explicit `impl Drop`.
    // This is verified by the existence of the impl in `signing/software.rs`
    // (code review anchor; compile-time enforcement is not possible for
    // user-defined `Drop` impls without a `const fn` or build-time check).

    // Invariant 2: `ed25519_dalek::SigningKey` implements `ZeroizeOnDrop`.
    // The compile-time assertion below catches any future dep update that
    // removes the `zeroize` feature.
    const _: fn() = || {
        fn assert_zod<T: zeroize::ZeroizeOnDrop>() {}
        assert_zod::<ed25519_dalek::SigningKey>();
        // Also assert the Zeroizing wrappers used in the keyring path.
        assert_zod::<zeroize::Zeroizing<[u8; 32]>>();
        assert_zod::<zeroize::Zeroizing<String>>();
    };

    // Invariant 3: `Zeroizing<T>` from `zeroize` zeroes the wrapped value on
    // drop — the RustCrypto-audited guarantee.
    use zeroize::Zeroizing;
    let mut probe = Zeroizing::new([0xFFu8; 32]);
    *probe = [0x00u8; 32]; // mutate to confirm the wrapper is live
    drop(probe); // fires Zeroizing::drop — zeroizes the stack copy

    // Invariant 4: `secrecy::SecretBox<[u8; 32]>` zeroes the heap allocation
    // on drop — the iqlusion-maintained guarantee.
    use secrecy::{ExposeSecret, SecretBox};
    let heap = SecretBox::new(Box::new([0xABu8; 32]));
    // Use boolean equality + plain assert! so the failure message does NOT
    // echo secret bytes (assert_eq! prints left/right payloads on panic).
    let matches = heap.expose_secret() == &[0xABu8; 32];
    assert!(
        matches,
        "SecretBox::expose_secret() did not return expected bytes"
    );
    drop(heap); // fires SecretBox::drop — calls zeroize on the heap allocation
}

/// 7. Panic-injected zeroisation — production-side hook.
///
/// Arms the `PANIC_AFTER_LOAD` hook inside `sign_payload_verifying_pubkey`
/// (compiled only under the `test-hooks` Cargo feature) and calls
/// `KeyringSignHandle::sign_tx_payload` inside `std::panic::catch_unwind`.
///
/// A `DropSentinel` whose `Drop` impl increments `DROP_COUNTER` is placed
/// on the stack inside the catch_unwind closure.  After `catch_unwind` returns:
///
/// - The result is `Err` (panic propagated to the boundary).
/// - `DROP_COUNTER` is >= 2 (hook incremented once + sentinel incremented once).
///
/// This combination proves that `Drop` impls — including `Zeroizing::drop` —
/// fire correctly during stack unwinding through the keyring signing path.
/// It is the only safe-Rust mechanism for asserting Drop fires on an unwind path.
///
/// # Runtime note
///
/// The test is a synchronous `#[test]` (not `#[tokio::test]`) because
/// `std::panic::catch_unwind` cannot be called from inside a Tokio runtime
/// without spawning a blocking task.  A new single-threaded runtime is built
/// explicitly so `block_on(sign_tx_payload(...))` can be called inside the
/// `catch_unwind` closure without "cannot block within async context" issues.
///
/// Requires: `cargo test --features stellar-agent-network/test-hooks`.
/// The test is `#[cfg(feature = "test-hooks")]` and is absent without it.
#[cfg(feature = "test-hooks")]
#[test]
#[serial]
fn panic_unwinds_through_zeroizing_scope() {
    use std::sync::atomic::Ordering;
    use stellar_agent_network::keyring::{DROP_COUNTER, PANIC_AFTER_LOAD};

    // Build an explicit single-threaded runtime so we can call block_on inside
    // the catch_unwind closure without triggering "cannot block from async ctx".
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime build must succeed");

    keyring_mock::install().expect("mock store init");

    let seed = [0xDE_u8; 32];
    let entry_ref = unique_ref("panicb7");
    let expected_g = gstrkey_for_seed(seed);
    store_sstrkey(&entry_ref, &sstrkey_for_seed(seed));

    let handle = rt
        .block_on(signer_from_keyring(&entry_ref, &expected_g))
        .expect("handle construction must succeed");

    // Reset the counter before arming the hook.
    DROP_COUNTER.store(0, Ordering::SeqCst);
    PANIC_AFTER_LOAD.store(true, Ordering::SeqCst);

    // `DropSentinel` increments DROP_COUNTER when it is dropped.
    // Placing it in the closure alongside the `sign_tx_payload` call means
    // it is dropped when the unwind exits the closure scope — during the panic.
    struct DropSentinel;
    impl Drop for DropSentinel {
        fn drop(&mut self) {
            DROP_COUNTER.fetch_add(1, Ordering::SeqCst);
        }
    }

    let payload = [0xBE_u8; 32];
    // Enter the runtime context manually so block_on works inside catch_unwind.
    let _guard = rt.enter();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // The sentinel is on the stack alongside the signing call.
        // When PANIC_AFTER_LOAD fires inside sign_payload_verifying_pubkey,
        // the unwind drops the sentinel and all Zeroizing<T> bindings in scope.
        let _sentinel = DropSentinel;
        // sign_tx_payload is an async fn; we drive it synchronously here.
        // The panic fires inside sign_payload_verifying_pubkey (after
        // drop(s_strkey), with seed_bytes live on the async stack).
        rt.block_on(handle.sign_tx_payload(&payload))
            .expect("unreachable — panic fires before Ok return");
    }));

    // Reset the hook immediately so sibling tests are not affected.
    PANIC_AFTER_LOAD.store(false, Ordering::SeqCst);

    // The closure must have panicked.
    assert!(result.is_err(), "sign_tx_payload must have panicked");

    // DROP_COUNTER >= 2: the hook fired once (inside sign_payload_verifying_pubkey)
    // and the DropSentinel fired once during unwind.
    let count = DROP_COUNTER.load(Ordering::SeqCst);
    assert!(
        count >= 2,
        "DROP_COUNTER must be >= 2 after unwind (hook + sentinel); got {count}"
    );
}

/// 8. `sign_tx_payload` produces the correct 64-byte signature.
///    Separate from happy_path to isolate the signature-length assertion.
#[tokio::test]
#[serial]
async fn sign_tx_payload_returns_64_bytes() {
    keyring_mock::install().expect("mock store init");

    let seed = [0xEE_u8; 32];
    let entry_ref = unique_ref("siglen");
    let expected_g = gstrkey_for_seed(seed);
    store_sstrkey(&entry_ref, &sstrkey_for_seed(seed));

    let handle = signer_from_keyring(&entry_ref, &expected_g)
        .await
        .expect("handle construction");
    let payload = [0x42_u8; 32];
    let sig = handle
        .sign_tx_payload(&payload)
        .await
        .expect("signing must succeed");
    assert_eq!(sig.len(), 64, "ed25519 signature must be 64 bytes");
}

/// 9. `public_key()` returns the correct key without re-loading from keyring.
///    Verifies the cached-pubkey contract.
#[tokio::test]
#[serial]
async fn public_key_is_cached_and_correct() {
    keyring_mock::install().expect("mock store init");

    let seed = [0x07_u8; 32];
    let entry_ref = unique_ref("pubkey");
    let expected_g = gstrkey_for_seed(seed);
    store_sstrkey(&entry_ref, &sstrkey_for_seed(seed));

    let handle = signer_from_keyring(&entry_ref, &expected_g)
        .await
        .expect("handle construction");

    let pk = handle.public_key();
    let pk_g = pk.to_string().to_string();
    assert_eq!(
        pk_g, expected_g,
        "cached pubkey must match expected_source_g"
    );

    // Delete the entry; public_key() must still work (it's cached).
    let entry =
        keyring_core::Entry::new(&entry_ref.service, &entry_ref.account).expect("mock entry");
    entry.delete_credential().expect("delete");

    let pk_after = handle.public_key();
    assert_eq!(
        pk_after.0, pk.0,
        "public_key() must return the same value after entry deletion (cached)"
    );
}

/// 10. `entry_ref()` returns the stored reference.
#[tokio::test]
#[serial]
async fn entry_ref_returns_stored_reference() {
    keyring_mock::install().expect("mock store init");

    let seed = [0x03_u8; 32];
    let entry_ref = unique_ref("entryref");
    let expected_g = gstrkey_for_seed(seed);
    store_sstrkey(&entry_ref, &sstrkey_for_seed(seed));

    let handle = signer_from_keyring(&entry_ref, &expected_g)
        .await
        .expect("handle construction");
    assert_eq!(handle.entry_ref().service, entry_ref.service);
    assert_eq!(handle.entry_ref().account, entry_ref.account);
}

/// 11. Host-swap detection: construct handle, replace the keyring entry with a
///     different seed between construction and signing.  `sign_tx_payload` must
///     return `SignerKeyMismatch` because the freshly-loaded seed's pubkey no
///     longer matches the cached pubkey from construction.
#[tokio::test]
#[serial]
async fn host_swap_detected_as_signer_key_mismatch() {
    keyring_mock::install().expect("mock store init");

    let original_seed = [0x11_u8; 32];
    let entry_ref = unique_ref("hostswap");
    let expected_g = gstrkey_for_seed(original_seed);
    store_sstrkey(&entry_ref, &sstrkey_for_seed(original_seed));

    // Construct the handle with the original seed — caches the original pubkey.
    let handle = signer_from_keyring(&entry_ref, &expected_g)
        .await
        .expect("handle construction must succeed with original seed");

    // Simulate a host-swap: replace the keyring entry with a DIFFERENT seed.
    let swapped_seed = [0x22_u8; 32];
    let entry = keyring_core::Entry::new(&entry_ref.service, &entry_ref.account)
        .expect("mock entry construction");
    entry
        .set_password(&sstrkey_for_seed(swapped_seed))
        .expect("set_password must succeed for swap");

    // Now try to sign — the freshly-loaded seed's pubkey differs from the
    // cached pubkey.  The host-swap defence must catch this.
    let payload = [0x33_u8; 32];
    let result = handle.sign_tx_payload(&payload).await;
    assert!(result.is_err(), "host-swap must be detected");
    let err = match result {
        Err(e) => e,
        Ok(_) => panic!("expected Err for host-swap scenario"),
    };
    assert_eq!(err.category(), ErrorCategory::Auth);
    assert_eq!(
        err.code(),
        "auth.signer_key_mismatch",
        "host-swap must produce SignerKeyMismatch, got: {err:?}"
    );
}
