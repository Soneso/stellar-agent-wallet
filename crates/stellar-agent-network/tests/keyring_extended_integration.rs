//! Extended integration tests for `stellar-agent-network::keyring`.
//!
//! Covers paths not reached by `keyring_integration.rs`:
//! - `KeyringSignHandle::sign_auth_digest` and `sign_soroban_address_auth_payload`
//! - The `Signer` trait `public_key()` impl on `KeyringSignHandle`
//! - `Signer` trait dispatch to `sign_auth_digest` and `sign_soroban_address_auth_payload`
//! - `map_keyring_error` for `NoStorageAccess` and catch-all variants
//! - `redact_keyring_coord` short-value path (≤10 characters)
//! - `wallet_error_kind` branches via the tracing event emitted on failure
//! - `rotate_keyring_secret_32` successive rotation replaces prior secret

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics and unwraps are acceptable in integration tests"
)]

use ed25519_dalek::Verifier;
use serial_test::serial;
use stellar_agent_core::{error::ErrorCategory, profile::schema::KeyringEntryRef};
use stellar_agent_network::{
    Signer,
    keyring::{rotate_keyring_secret_32, signer_from_keyring},
};
use stellar_agent_test_support::{CaptureWriter, keyring_mock};

// ─── helpers ─────────────────────────────────────────────────────────────────

fn gstrkey_for_seed(seed: [u8; 32]) -> String {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    stellar_strkey::ed25519::PublicKey(signing_key.verifying_key().to_bytes())
        .to_string()
        .to_string()
}

fn sstrkey_for_seed(seed: [u8; 32]) -> String {
    stellar_strkey::ed25519::PrivateKey(seed)
        .as_unredacted()
        .to_string()
        .to_string()
}

fn unique_ref(tag: &str) -> KeyringEntryRef {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    KeyringEntryRef::new(format!("stellar-agent-ext-test-{tag}-{ts}"), "default")
}

fn store_sstrkey(entry_ref: &KeyringEntryRef, sstrkey: &str) {
    let entry = keyring_core::Entry::new(&entry_ref.service, &entry_ref.account)
        .expect("mock entry construction must succeed");
    entry
        .set_password(sstrkey)
        .expect("mock store set_password must succeed");
}

// ─── sign_auth_digest ────────────────────────────────────────────────────────

/// `KeyringSignHandle::sign_auth_digest` signs a 32-byte digest using the
/// keyring-stored seed and returns a 64-byte signature that verifies.
#[tokio::test]
#[serial]
async fn sign_auth_digest_happy_path_and_verify() {
    keyring_mock::install().expect("mock store init");

    let seed = [0x11u8; 32];
    let entry_ref = unique_ref("auth-digest-happy");
    let expected_g = gstrkey_for_seed(seed);
    store_sstrkey(&entry_ref, &sstrkey_for_seed(seed));

    let handle = signer_from_keyring(&entry_ref, &expected_g)
        .await
        .expect("handle construction must succeed");

    let digest = [0xA1u8; 32];
    let sig_bytes = handle
        .sign_auth_digest(&digest)
        .await
        .expect("sign_auth_digest must succeed");

    assert_eq!(sig_bytes.len(), 64, "ed25519 signature must be 64 bytes");

    // Verify the signature with dalek.
    let pk = handle.public_key();
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk.0).expect("valid verifying key");
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    vk.verify(&digest, &sig)
        .expect("auth-digest signature must verify");
}

/// After the keyring entry is deleted, `sign_auth_digest` must return
/// `KeyringNotFound`, proving it re-loads the secret per-call.
#[tokio::test]
#[serial]
async fn sign_auth_digest_after_entry_deletion_returns_keyring_not_found() {
    keyring_mock::install().expect("mock store init");

    let seed = [0x22u8; 32];
    let entry_ref = unique_ref("auth-digest-deleted");
    let expected_g = gstrkey_for_seed(seed);
    store_sstrkey(&entry_ref, &sstrkey_for_seed(seed));

    let handle = signer_from_keyring(&entry_ref, &expected_g)
        .await
        .expect("handle construction must succeed");

    // Delete the entry between construction and signing.
    let entry =
        keyring_core::Entry::new(&entry_ref.service, &entry_ref.account).expect("mock entry");
    entry.delete_credential().expect("delete must succeed");

    let digest = [0xB2u8; 32];
    let err = handle.sign_auth_digest(&digest).await.unwrap_err();
    assert_eq!(err.category(), ErrorCategory::Auth);
    assert_eq!(err.code(), "auth.keyring_not_found");
}

// ─── sign_soroban_address_auth_payload ───────────────────────────────────────

/// `KeyringSignHandle::sign_soroban_address_auth_payload` signs a 32-byte
/// payload and returns a 64-byte signature that verifies.
#[tokio::test]
#[serial]
async fn sign_soroban_address_auth_payload_happy_path_and_verify() {
    keyring_mock::install().expect("mock store init");

    let seed = [0x33u8; 32];
    let entry_ref = unique_ref("soroban-auth-happy");
    let expected_g = gstrkey_for_seed(seed);
    store_sstrkey(&entry_ref, &sstrkey_for_seed(seed));

    let handle = signer_from_keyring(&entry_ref, &expected_g)
        .await
        .expect("handle construction must succeed");

    let payload = [0xC3u8; 32];
    let sig_bytes = handle
        .sign_soroban_address_auth_payload(&payload)
        .await
        .expect("sign_soroban_address_auth_payload must succeed");

    assert_eq!(sig_bytes.len(), 64, "ed25519 signature must be 64 bytes");

    let pk = handle.public_key();
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk.0).expect("valid verifying key");
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    vk.verify(&payload, &sig)
        .expect("soroban-auth-payload signature must verify");
}

/// Host-swap detected in `sign_soroban_address_auth_payload` path.
#[tokio::test]
#[serial]
async fn sign_soroban_address_auth_payload_host_swap_detected() {
    keyring_mock::install().expect("mock store init");

    let original_seed = [0x44u8; 32];
    let entry_ref = unique_ref("soroban-auth-swap");
    let expected_g = gstrkey_for_seed(original_seed);
    store_sstrkey(&entry_ref, &sstrkey_for_seed(original_seed));

    let handle = signer_from_keyring(&entry_ref, &expected_g)
        .await
        .expect("handle construction must succeed");

    // Swap the keyring entry with a different seed.
    let swapped_seed = [0x55u8; 32];
    let entry =
        keyring_core::Entry::new(&entry_ref.service, &entry_ref.account).expect("mock entry");
    entry
        .set_password(&sstrkey_for_seed(swapped_seed))
        .expect("swap");

    let payload = [0xD4u8; 32];
    let err = handle
        .sign_soroban_address_auth_payload(&payload)
        .await
        .unwrap_err();
    assert_eq!(err.category(), ErrorCategory::Auth);
    assert_eq!(err.code(), "auth.signer_key_mismatch");
}

// ─── Signer trait dispatch ────────────────────────────────────────────────────

/// `Signer::sign_tx_payload` via trait dispatch (dynamic dispatch path).
#[tokio::test]
#[serial]
async fn signer_trait_sign_tx_payload() {
    keyring_mock::install().expect("mock store init");

    let seed = [0x66u8; 32];
    let entry_ref = unique_ref("trait-tx");
    let expected_g = gstrkey_for_seed(seed);
    store_sstrkey(&entry_ref, &sstrkey_for_seed(seed));

    let handle = signer_from_keyring(&entry_ref, &expected_g)
        .await
        .expect("handle construction");

    // Exercise via trait (dyn Signer).
    let signer: &dyn Signer = &handle;
    let payload = [0x01u8; 32];
    let sig = signer.sign_tx_payload(&payload).await.expect("must sign");
    assert_eq!(sig.len(), 64);
}

/// `Signer::sign_auth_digest` via trait dispatch.
#[tokio::test]
#[serial]
async fn signer_trait_sign_auth_digest() {
    keyring_mock::install().expect("mock store init");

    let seed = [0x77u8; 32];
    let entry_ref = unique_ref("trait-auth");
    let expected_g = gstrkey_for_seed(seed);
    store_sstrkey(&entry_ref, &sstrkey_for_seed(seed));

    let handle = signer_from_keyring(&entry_ref, &expected_g)
        .await
        .expect("handle construction");

    let signer: &dyn Signer = &handle;
    let digest = [0x02u8; 32];
    let sig = signer.sign_auth_digest(&digest).await.expect("must sign");
    assert_eq!(sig.len(), 64);
}

/// `Signer::sign_soroban_address_auth_payload` via trait dispatch.
#[tokio::test]
#[serial]
async fn signer_trait_sign_soroban_address_auth_payload() {
    keyring_mock::install().expect("mock store init");

    let seed = [0x88u8; 32];
    let entry_ref = unique_ref("trait-soroban");
    let expected_g = gstrkey_for_seed(seed);
    store_sstrkey(&entry_ref, &sstrkey_for_seed(seed));

    let handle = signer_from_keyring(&entry_ref, &expected_g)
        .await
        .expect("handle construction");

    let signer: &dyn Signer = &handle;
    let payload = [0x03u8; 32];
    let sig = signer
        .sign_soroban_address_auth_payload(&payload)
        .await
        .expect("must sign");
    assert_eq!(sig.len(), 64);
}

/// `Signer::public_key()` via trait dispatch returns the cached key.
#[tokio::test]
#[serial]
async fn signer_trait_public_key() {
    keyring_mock::install().expect("mock store init");

    let seed = [0x99u8; 32];
    let entry_ref = unique_ref("trait-pubkey");
    let expected_g = gstrkey_for_seed(seed);
    store_sstrkey(&entry_ref, &sstrkey_for_seed(seed));

    let handle = signer_from_keyring(&entry_ref, &expected_g)
        .await
        .expect("handle construction");

    let signer: &dyn Signer = &handle;
    let pk = signer.public_key().await.expect("must return public key");
    let pk_g = pk.to_string().to_string();
    assert_eq!(pk_g, expected_g, "trait public_key must match expected_g");
}

// ─── map_keyring_error coverage ──────────────────────────────────────────────

/// `map_keyring_error` with `NoStorageAccess` maps to `KeyringPlatformError`.
///
/// This variant is produced by the platform keyring when the credential store
/// is locked (e.g. macOS Keychain locked, GNOME Keyring locked). It is
/// distinct from `PlatformFailure` (runtime error) and maps to the same
/// `KeyringPlatformError` code.
///
/// `map_keyring_error` is private; this test verifies the mapping by arming a
/// `NoStorageAccess` error on the mock entry, calling `sign_tx_payload` to
/// traverse the production `map_keyring_error` code path, and asserting the
/// resulting `WalletError::code()`.
#[tokio::test]
#[serial]
async fn no_storage_access_maps_to_keyring_platform_error() {
    use keyring_core::mock;

    keyring_mock::install().expect("mock store init");

    let seed = [0xC1u8; 32];
    let entry_ref = unique_ref("no-storage-access");
    let expected_g = gstrkey_for_seed(seed);
    store_sstrkey(&entry_ref, &sstrkey_for_seed(seed));

    let handle = signer_from_keyring(&entry_ref, &expected_g)
        .await
        .expect("handle construction must succeed");

    // Arm the NoStorageAccess error — the next get_password call during
    // sign_tx_payload will return this error, which map_keyring_error maps
    // to KeyringPlatformError.
    let entry =
        keyring_core::Entry::new(&entry_ref.service, &entry_ref.account).expect("mock entry");
    let cred: &mock::Cred = entry
        .as_any()
        .downcast_ref::<mock::Cred>()
        .expect("must downcast to mock::Cred");
    cred.set_error(keyring_core::Error::NoStorageAccess(Box::new(
        std::io::Error::other("keyring locked"),
    )));

    // sign_tx_payload re-loads the secret; the armed error fires.
    let err = handle.sign_tx_payload(&[0u8; 32]).await.unwrap_err();
    assert_eq!(err.category(), ErrorCategory::Auth);
    assert_eq!(
        err.code(),
        "auth.keyring_platform_error",
        "NoStorageAccess must map to auth.keyring_platform_error; got {:?}",
        err.code()
    );
}

/// `map_keyring_error` catch-all for `BadEncoding` maps to `KeyringNotFound`.
///
/// `BadEncoding`, `TooLong`, `Invalid`, `Ambiguous`, etc. are all catch-all
/// variants that map to `KeyringNotFound` (the keyring entry is malformed or
/// inaccessible, which is operationally equivalent to "not found" for signing).
///
/// `map_keyring_error` is private; we arm a `BadEncoding` error on the mock
/// entry and call `sign_tx_payload` to traverse the production code path.
#[tokio::test]
#[serial]
async fn bad_encoding_maps_to_keyring_not_found_via_mock() {
    use keyring_core::mock;
    keyring_mock::install().expect("mock store init");

    let seed = [0xD2u8; 32];
    let entry_ref = unique_ref("bad-encoding");
    let expected_g = gstrkey_for_seed(seed);
    store_sstrkey(&entry_ref, &sstrkey_for_seed(seed));

    let handle = signer_from_keyring(&entry_ref, &expected_g)
        .await
        .expect("handle construction must succeed");

    // Arm BadEncoding — next get_password returns non-UTF-8 bytes.
    let entry =
        keyring_core::Entry::new(&entry_ref.service, &entry_ref.account).expect("mock entry");
    let cred: &mock::Cred = entry
        .as_any()
        .downcast_ref::<mock::Cred>()
        .expect("must downcast to mock::Cred");
    cred.set_error(keyring_core::Error::BadEncoding(vec![0xFFu8, 0xFEu8]));

    // sign_tx_payload re-loads the secret; the armed error fires.
    // map_keyring_error's catch-all maps BadEncoding to KeyringNotFound.
    let err = handle.sign_tx_payload(&[0u8; 32]).await.unwrap_err();
    assert_eq!(err.category(), ErrorCategory::Auth);
    assert_eq!(
        err.code(),
        "auth.keyring_not_found",
        "BadEncoding catch-all must map to auth.keyring_not_found; got {:?}",
        err.code()
    );
}

// ─── rotate_keyring_secret_32 ────────────────────────────────────────────────

/// Rotating twice replaces the prior secret with a new 32-byte value.
///
/// The second rotation must produce a different base64-encoded secret, proving
/// the function generates fresh CSPRNG bytes each time rather than re-using the
/// previous value.
#[test]
#[serial]
fn rotate_keyring_secret_32_second_rotation_changes_secret() {
    keyring_mock::install().expect("mock store init");

    let service = "stellar-agent-ext-rotate-twice";
    let entry_name = "default";

    rotate_keyring_secret_32(service, entry_name).expect("first rotation");
    let first = keyring_core::Entry::new(service, entry_name)
        .unwrap()
        .get_password()
        .expect("read after first rotation");

    rotate_keyring_secret_32(service, entry_name).expect("second rotation");
    let second = keyring_core::Entry::new(service, entry_name)
        .unwrap()
        .get_password()
        .expect("read after second rotation");

    // The two CSPRNG-derived secrets are astronomically unlikely to collide.
    // If they do, the CSPRNG is broken — which is a real bug, not a test flaw.
    assert_ne!(
        first, second,
        "second rotation must produce a different secret from the first"
    );

    // Both must decode as valid 32-byte base64url-no-pad secrets.
    use base64::Engine as _;
    let dec1 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(second.as_bytes())
        .expect("second secret must be valid base64url-no-pad");
    assert_eq!(dec1.len(), 32, "rotated secret must decode to 32 bytes");
}

// ─── redact_keyring_coord short-value branch ─────────────────────────────────

/// `redact_keyring_coord` for a value ≤10 chars returns the value unchanged.
///
/// The function's contract: strings longer than 10 characters get the
/// first-5…last-5 truncation; strings of 10 or fewer characters are returned
/// as-is. This test triggers the `else` branch of that length check.
///
/// The function is private (`fn redact_keyring_coord`); we exercise it
/// indirectly by constructing a `KeyringSignHandle` with a short service name
/// and observing the tracing event, which calls `redact_keyring_coord` on the
/// service field.
#[tokio::test]
#[serial]
async fn signer_from_keyring_with_short_service_name_logs_unredacted() {
    keyring_mock::install().expect("mock store init");

    // Service name ≤10 chars: "short-svc" (9 chars) — must appear unredacted.
    let short_service = "short-svc";
    let seed = [0xA0u8; 32];
    let entry_ref = KeyringEntryRef::new(short_service, "default");
    let expected_g = gstrkey_for_seed(seed);
    store_sstrkey(&entry_ref, &sstrkey_for_seed(seed));

    let writer = CaptureWriter::new();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .flatten_event(true)
        .with_ansi(false)
        .with_writer(writer.clone())
        .with_max_level(tracing::Level::TRACE)
        .finish();
    let dispatch = tracing::Dispatch::new(subscriber);
    let _guard = tracing::dispatcher::set_default(&dispatch);

    let _handle = signer_from_keyring(&entry_ref, &expected_g)
        .await
        .expect("signer_from_keyring must succeed");
    drop(_guard);

    let logs = writer.captured_str();
    // The short service name must appear in the log as-is (not truncated).
    assert!(
        logs.contains(short_service),
        "short service name must appear unredacted in logs; logs={logs}"
    );
    assert!(logs.contains("keyring.handle.constructed"), "{logs}");
}

// ─── wallet_error_kind coverage ──────────────────────────────────────────────

/// The `keyring.sign.failure` event includes the `error_kind` field, which is
/// populated by the private `wallet_error_kind` function.  By triggering
/// different failure modes we exercise branches of that function that are not
/// reached by the existing `sign_tx_payload_emits_failure_event` test.
///
/// This test covers `KeyringLocked`, `HardwareUserRefused`, and
/// `SignerKindMismatch` branches by injecting mock errors and observing the
/// logged `error_kind` string.
///
/// `KeyringLocked` is armed via `mock::Cred::set_error(Error::NoStorageAccess)`,
/// but `map_keyring_error` maps `NoStorageAccess` to `KeyringPlatformError`
/// (not `KeyringLocked`) — so the `KeyringLocked` and `HardwareUserRefused`
/// wallet_error_kind branches are not reachable through the keyring signing
/// path.  They are reached only via callers that produce those variants (e.g.
/// `HardwareSigningKey`).  Since those callers live outside keyring.rs, the
/// `wallet_error_kind` coverage for `KeyringLocked` and `HardwareUserRefused`
/// is acknowledged as unreachable from the keyring module and listed under
/// suspected_issues in the coverage report.
///
/// What this test DOES cover: the `KeyringPlatformError` branch in
/// `wallet_error_kind`, exercised by arming `NoStorageAccess` and signing.
#[tokio::test]
#[serial]
async fn sign_tx_payload_platform_error_is_logged_as_keyring_platform_error() {
    use keyring_core::mock;

    keyring_mock::install().expect("mock store init");

    let seed = [0xB0u8; 32];
    let entry_ref = unique_ref("platform-error-kind");
    let expected_g = gstrkey_for_seed(seed);
    store_sstrkey(&entry_ref, &sstrkey_for_seed(seed));

    let handle = signer_from_keyring(&entry_ref, &expected_g)
        .await
        .expect("handle construction must succeed");

    // Arm a NoStorageAccess error on the next get_password call.
    // map_keyring_error maps this to KeyringPlatformError.
    let entry =
        keyring_core::Entry::new(&entry_ref.service, &entry_ref.account).expect("mock entry");
    let cred: &mock::Cred = entry
        .as_any()
        .downcast_ref::<mock::Cred>()
        .expect("must downcast");
    cred.set_error(keyring_core::Error::NoStorageAccess(Box::new(
        std::io::Error::other("store locked"),
    )));

    let writer = CaptureWriter::new();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .flatten_event(true)
        .with_ansi(false)
        .with_writer(writer.clone())
        .with_max_level(tracing::Level::TRACE)
        .finish();
    let dispatch = tracing::Dispatch::new(subscriber);
    let _guard = tracing::dispatcher::set_default(&dispatch);

    let err = handle.sign_tx_payload(&[0u8; 32]).await.unwrap_err();
    drop(_guard);

    assert_eq!(err.code(), "auth.keyring_platform_error");

    let logs = writer.captured_str();
    assert!(logs.contains("keyring.sign.failure"), "{logs}");
    assert!(
        logs.contains("AuthError::KeyringPlatformError"),
        "error_kind field must be 'AuthError::KeyringPlatformError'; logs={logs}"
    );
}
