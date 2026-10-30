//! End-to-end integration tests for `CredentialsManager`.
//!
//! These tests exercise the full registration lifecycle using a shared
//! `Arc<tokio::sync::Mutex<PendingApprovalStore>>`. The bridge is NOT started;
//! `prepare_registration` writes to the shared store and the test injects a
//! `RegistrationInput` into the SAME shared store before the poll loop fires.
//! This mirrors the production flow where both the bridge and the manager
//! operate on the same in-process `Arc<Mutex<PendingApprovalStore>>`.
//!
//! # Fixture limitation
//!
//! `make_registration_input` supplies an all-zero 65-byte SEC1 public key
//! (`[0x04, 0, 0, ...]`). This is not a valid P-256 point but satisfies the
//! structural 65-byte / `0x04` marker check required by `RegistrationInput::new`.
//! Tests that assert on `public_key_sec1_b64` check only the structural
//! properties (non-empty, 87 base64url chars for 65 raw bytes, `0x04` prefix
//! after decode) — not elliptic-curve validity.
//!
//! # Coverage (passkey registration path)
//!
//! 1. `list_empty` — `list()` on a new profile returns an empty vec.
//! 2. `is_empty_true_on_new_profile` — `is_empty()` returns `true` before any
//!    registration.
//! 3. `registration_round_trip` — `prepare_registration` → inject
//!    `RegistrationInput` → `poll_registration` returns
//!    `AwaitingConfirmation` with nothing registered → `confirm_registration`
//!    with the page's code → credential persisted in registry → `show` +
//!    `list` reflect the new credential (including `public_key_sec1_b64`).
//! 4. `duplicate_name_rejected` — registering a second credential with the
//!    same name returns `CredentialsError::DuplicateName`.
//! 5. `delete_removes_credential` — after registration, `delete` removes the
//!    entry and `show` returns `NotFound`.
//! 6. `show_not_found` — `show` on a name that does not exist returns
//!    `CredentialsError::NotFound`.
//! 7. `invalid_name_rejected` — names with forbidden characters are rejected
//!    at `prepare_registration` time.
//! 8. `poll_registration_timeout` — when no `RegistrationInput` is injected,
//!    `poll_registration` returns `AddPasskeyOutcome::Timeout` after the
//!    deadline expires.
//! 9. `audit_entry_emitted_on_success`: the poll writes no row; the confirmed
//!    registration writes one `PasskeyRegistered` row with status
//!    `registered`.
//! 10. `audit_entry_emitted_on_timeout` — `poll_registration` writes one JSONL
//!     `PasskeyRegistered` entry with `status: "timeout"` when the deadline
//!     expires.
//! 11. `a_wrong_code_registers_nothing`, `an_expired_confirmation_registers_nothing`,
//!     `a_failed_registered_row_registers_nothing` and
//!     `an_abandoned_registration_records_why`: a recorded registration that
//!     is not confirmed in time with its code, or whose `registered` row
//!     cannot be written, leaves the registry empty.
//!
//! # WebAuthn signer
//!
//! Covers the passkey registration path for the WebAuthn signer.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only"
)]

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use stellar_agent_core::approval::RegistrationInput;
use stellar_agent_core::approval::store::{ApprovalKind, PendingApprovalStore};
use stellar_agent_core::approval::webauthn_registration::{
    ConfirmationCode, PASSKEY_REGISTRATION_CODE_DOMAIN,
};
use stellar_agent_core::audit_log::BindingHistory;
use stellar_agent_core::audit_log::schema::EventKind;
use stellar_agent_core::audit_log::test_helpers::verified_audit_entries_from_path;
use stellar_agent_core::audit_log::tip_anchor::{InMemoryTipAnchorStore, TipAnchorStore};
use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_smart_account::managers::credentials::{
    AddPasskeyOutcome, CredentialMetadata, CredentialsError, CredentialsManager,
    PendingPasskeyRegistration, UnconfirmedEnd,
};
use tempfile::TempDir;
use tokio::sync::Mutex;

// ─────────────────────────────────────────────────────────────────────────────
// Test fixtures
// ─────────────────────────────────────────────────────────────────────────────

/// A synthetic localhost address used as `bridge_addr` in tests.
///
/// No bridge is actually started; the address is only embedded in the
/// registration URL returned by `prepare_registration`.
fn fake_bridge_addr() -> SocketAddr {
    "127.0.0.1:19876".parse().unwrap()
}

/// Constructs a minimal valid `RegistrationInput`.
///
/// `credential_id` — 32 zero bytes (16–64 range, per CTAP2 §4.2).
/// `public_key` — 65-byte uncompressed SEC1 point with `0x04` marker.
/// No attestation blob; transport `"internal"`.
///
/// Note: the all-zero key is NOT a valid P-256 point but satisfies structural
/// validation (`[0] == 0x04`, len == 65).
fn make_registration_input() -> RegistrationInput {
    let mut pubkey = vec![0u8; 65];
    pubkey[0] = 0x04;
    RegistrationInput::new(vec![0u8; 32], pubkey, None, vec!["internal".to_owned()])
        .expect("valid RegistrationInput fixture")
}

/// Opens a `PendingApprovalStore` in `dir/approvals/test-profile.toml`.
fn open_store_in(dir: &TempDir) -> Arc<Mutex<PendingApprovalStore>> {
    let approval_dir = dir.path().join("approvals");
    std::fs::create_dir_all(&approval_dir).unwrap();
    let path = approval_dir.join("test-profile.toml");
    let store = PendingApprovalStore::open(path).expect("test store must open in tempdir");
    Arc::new(Mutex::new(store))
}

/// Constructs a `CredentialsManager` rooted in a `TempDir` with a shared store.
///
/// Returns both the manager and the temp directory (the caller must keep
/// the `TempDir` alive so the directory is not deleted prematurely).
///
/// The RP-ID is `"localhost"` per WebAuthn Level 2 §5.1.2 (IP literals such as
/// `"127.0.0.1"` are forbidden as rpId and are now rejected by the validator).
fn make_manager(dir: &TempDir) -> (CredentialsManager, Arc<Mutex<PendingApprovalStore>>) {
    let passkeys_dir = dir.path().join("passkeys");
    let shared_store = open_store_in(dir);
    let mgr = CredentialsManager::new(
        passkeys_dir,
        "test-profile",
        "localhost",
        Some(Arc::clone(&shared_store)),
    );
    (mgr, shared_store)
}

/// A recorded registration: its nonce and the confirmation code the
/// registration page shows for it.
struct Injected {
    nonce: String,
    code: String,
}

/// Prepares a registration entry, injects a `RegistrationInput` directly into
/// the shared store (simulating the bridge POST handler), and returns the nonce
/// with the code the page computes from the entry's challenge and `reg`.
///
/// Uses the same `Arc<Mutex<PendingApprovalStore>>` as the manager, so
/// `poll_registration` can observe the injected entry without any re-opening.
async fn prepare_and_inject(
    mgr: &CredentialsManager,
    shared_store: &Arc<Mutex<PendingApprovalStore>>,
    credential_name: &str,
    bridge_addr: SocketAddr,
    reg: RegistrationInput,
) -> Injected {
    // prepare_registration acquires the shared mutex, inserts, and releases.
    let handle = mgr
        .prepare_registration(credential_name, bridge_addr, None)
        .await
        .expect("prepare_registration must succeed in test");
    let nonce = handle.nonce.clone();

    // Inject the RegistrationInput via the same shared mutex.
    // This simulates the bridge POST /register/{nonce} handler calling
    // `record_passkey_registration` on the store it shares with the manager.
    let mut guard = shared_store.lock().await;
    let Some(ApprovalKind::RegisterPasskey {
        registration_challenge: Some(challenge),
        ..
    }) = guard.get(&nonce).map(|entry| entry.kind.clone())
    else {
        panic!("a prepared registration entry carries its challenge")
    };
    let key: [u8; 65] = reg.public_key_uncompressed_sec1().try_into().unwrap();
    let code = ConfirmationCode::compute(
        PASSKEY_REGISTRATION_CODE_DOMAIN,
        &challenge,
        reg.credential_id(),
        &key,
    )
    .display();
    guard
        .record_passkey_registration(&nonce, reg)
        .expect("record_passkey_registration must succeed");
    drop(guard);

    Injected { nonce, code }
}

/// Opens an unkeyed writer over `dir/audit.jsonl` and returns it with the path.
fn open_writer(dir: &TempDir) -> (AuditWriter, std::path::PathBuf) {
    let path = dir.path().join("audit.jsonl");
    let writer = AuditWriter::open(path.clone(), None).expect("AuditWriter must open in tempdir");
    (writer, path)
}

/// Polls `injected` to its recorded registration and returns it; the poll
/// registers nothing.
async fn poll_to_pending(
    mgr: &CredentialsManager,
    credential_name: &str,
    injected: &Injected,
    writer: &mut AuditWriter,
) -> PendingPasskeyRegistration {
    let deadline = Instant::now() + Duration::from_secs(5);
    let outcome = mgr
        .poll_registration(credential_name, &injected.nonce, deadline, writer)
        .await
        .expect("poll_registration must not return Err");
    let AddPasskeyOutcome::AwaitingConfirmation { pending } = outcome else {
        panic!("expected AwaitingConfirmation, got {outcome:?}")
    };
    assert_eq!(pending.credential_name(), credential_name);
    assert!(
        mgr.list().unwrap().is_empty(),
        "a recorded registration is not registered before its code is confirmed"
    );
    pending
}

/// Registers `credential_name` end to end: inject, poll, confirm with the
/// page's code.
async fn register(
    mgr: &CredentialsManager,
    shared_store: &Arc<Mutex<PendingApprovalStore>>,
    credential_name: &str,
    writer: &mut AuditWriter,
) -> CredentialMetadata {
    let injected = prepare_and_inject(
        mgr,
        shared_store,
        credential_name,
        fake_bridge_addr(),
        make_registration_input(),
    )
    .await;
    let pending = poll_to_pending(mgr, credential_name, &injected, writer).await;
    mgr.confirm_registration(pending, &injected.code, Instant::now(), writer)
        .expect("the page's code confirms the registration")
}

/// The statuses of the `PasskeyRegistered` rows of the log at `path`.
fn passkey_statuses(path: &Path) -> Vec<String> {
    verified_audit_entries_from_path(path)
        .into_iter()
        .filter_map(|entry| match entry.event_kind {
            EventKind::PasskeyRegistered { status, .. } => Some(status),
            _ => None,
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

// 1. list_empty ─────────────────────────────────────────────────────────────

#[test]
fn list_empty() {
    let dir = TempDir::new().unwrap();
    let (mgr, _store) = make_manager(&dir);
    let creds = mgr.list().expect("list must succeed on empty profile");
    assert!(creds.is_empty(), "expected empty list, got {creds:?}");
}

// 2. is_empty_true_on_new_profile ───────────────────────────────────────────

#[test]
fn is_empty_true_on_new_profile() {
    let dir = TempDir::new().unwrap();
    let (mgr, _store) = make_manager(&dir);
    assert!(
        mgr.is_empty()
            .expect("is_empty must succeed on new profile"),
        "expected is_empty to be true on a new profile"
    );
}

// 3. registration_round_trip ────────────────────────────────────────────────

#[tokio::test]
async fn registration_round_trip() {
    let dir = TempDir::new().unwrap();
    let (mgr, shared_store) = make_manager(&dir);
    let (mut writer, audit_path) = open_writer(&dir);
    let credential_name = "my-yubikey";

    let metadata = register(&mgr, &shared_store, credential_name, &mut writer).await;
    assert_eq!(metadata.credential_name, credential_name);
    assert_eq!(metadata.rp_id, "localhost");
    assert_eq!(metadata.transports, "internal");
    assert!(
        metadata.registered_at_unix_ms > 0,
        "registered_at_unix_ms must be non-zero"
    );
    // credential_id for the fixture: 32 zero bytes → base64url.
    assert_eq!(
        metadata.credential_id_b64url,
        URL_SAFE_NO_PAD.encode([0u8; 32])
    );
    // The fixture pubkey is 65 bytes → 87 base64url chars.
    let decoded = URL_SAFE_NO_PAD
        .decode(&metadata.public_key_sec1_b64)
        .expect("public_key_sec1_b64 must be valid base64url");
    assert_eq!(
        decoded.len(),
        65,
        "decoded public key must be exactly 65 bytes"
    );
    assert_eq!(decoded[0], 0x04, "first byte must be 0x04 (uncompressed)");
    drop(writer);
    assert_eq!(passkey_statuses(&audit_path), ["registered"]);

    // Verify persistence: show + list reflect the new credential.
    let shown = mgr
        .show(credential_name)
        .expect("show must find the newly registered credential");
    assert_eq!(shown.credential_name, credential_name);
    // public_key_sec1_b64 must persist to the registry.
    assert!(
        !shown.public_key_sec1_b64.is_empty(),
        "public_key_sec1_b64 must persist to registry"
    );

    let creds = mgr.list().expect("list must succeed after registration");
    assert_eq!(
        creds.len(),
        1,
        "expected exactly one credential, got {creds:?}"
    );
    assert_eq!(creds[0].credential_name, credential_name);

    // is_empty must now be false.
    assert!(
        !mgr.is_empty().expect("is_empty must succeed"),
        "is_empty must be false after a successful registration"
    );
}

// 4. duplicate_name_rejected ────────────────────────────────────────────────

#[tokio::test]
async fn duplicate_name_rejected() {
    let dir = TempDir::new().unwrap();
    let (mgr, shared_store) = make_manager(&dir);
    let bridge_addr = fake_bridge_addr();
    let credential_name = "my-key";

    let (mut writer, _audit_path) = open_writer(&dir);

    // First registration — complete it so the name is in the registry.
    register(&mgr, &shared_store, credential_name, &mut writer).await;

    // Second attempt with the same name must fail at prepare_registration.
    let err = mgr
        .prepare_registration(credential_name, bridge_addr, None)
        .await
        .expect_err("second registration with same name must fail");
    assert!(
        matches!(err, CredentialsError::DuplicateName { .. }),
        "expected DuplicateName, got {err:?}"
    );
}

// 5. delete_removes_credential ──────────────────────────────────────────────

#[tokio::test]
async fn delete_removes_credential() {
    let dir = TempDir::new().unwrap();
    let (mgr, shared_store) = make_manager(&dir);
    let (mut writer, _audit_path) = open_writer(&dir);
    let credential_name = "to-be-deleted";

    register(&mgr, &shared_store, credential_name, &mut writer).await;

    // Verify it exists.
    mgr.show(credential_name)
        .expect("show must succeed before delete");

    // Delete it.
    mgr.delete(credential_name)
        .expect("delete must succeed for an existing credential");

    // show must now return NotFound.
    let err = mgr
        .show(credential_name)
        .expect_err("show must fail after delete");
    assert!(
        matches!(err, CredentialsError::NotFound { .. }),
        "expected NotFound after delete, got {err:?}"
    );

    // list must be empty again.
    let creds = mgr.list().unwrap();
    assert!(creds.is_empty(), "list must be empty after delete");
}

// 6. show_not_found ─────────────────────────────────────────────────────────

#[test]
fn show_not_found() {
    let dir = TempDir::new().unwrap();
    let (mgr, _store) = make_manager(&dir);
    let err = mgr
        .show("nonexistent")
        .expect_err("show must fail for unknown name");
    assert!(
        matches!(err, CredentialsError::NotFound { ref name } if name == "nonexistent"),
        "expected NotFound {{ name: \"nonexistent\" }}, got {err:?}"
    );
}

// 7. invalid_name_rejected ──────────────────────────────────────────────────

#[tokio::test]
async fn invalid_name_rejected() {
    let dir = TempDir::new().unwrap();
    let (mgr, _store) = make_manager(&dir);
    let bridge_addr = fake_bridge_addr();

    let too_long = "x".repeat(65);
    let bad_names: &[&str] = &[
        "",                // empty
        "a/b",             // slash
        "a\\b",            // backslash
        "a:b",             // colon
        too_long.as_str(), // too long (65 chars)
        "\x01invalid",     // control character
    ];

    for name in bad_names {
        let err = mgr
            .prepare_registration(name, bridge_addr, None)
            .await
            .expect_err(&format!("prepare_registration must reject name {name:?}"));
        assert!(
            matches!(err, CredentialsError::InvalidName { .. }),
            "expected InvalidName for name {name:?}, got {err:?}"
        );
    }
}

// 8. poll_registration_timeout ──────────────────────────────────────────────

#[tokio::test]
async fn poll_registration_timeout() {
    let dir = TempDir::new().unwrap();
    let (mgr, _store) = make_manager(&dir);
    let bridge_addr = fake_bridge_addr();
    let credential_name = "timeout-key";

    // Prepare but do NOT inject a RegistrationInput.
    let handle = mgr
        .prepare_registration(credential_name, bridge_addr, None)
        .await
        .expect("prepare_registration must succeed");
    let nonce = handle.nonce.clone();

    // Set a deadline already in the past (or extremely short).
    let deadline = Instant::now();
    let (mut writer, _audit_path) = open_writer(&dir);

    let outcome = mgr
        .poll_registration(credential_name, &nonce, deadline, &mut writer)
        .await
        .expect("poll_registration must not return Err on timeout");

    assert!(
        matches!(outcome, AddPasskeyOutcome::Timeout),
        "expected Timeout, got {outcome:?}"
    );
}

// 9. audit_entry_emitted_on_success ─────────────────────────────────────────

#[tokio::test]
async fn audit_entry_emitted_on_success() {
    let dir = TempDir::new().unwrap();
    let (mgr, shared_store) = make_manager(&dir);
    let credential_name = "audit-key";
    let (mut writer, audit_path) = open_writer(&dir);

    let injected = prepare_and_inject(
        &mgr,
        &shared_store,
        credential_name,
        fake_bridge_addr(),
        make_registration_input(),
    )
    .await;
    let pending = poll_to_pending(&mgr, credential_name, &injected, &mut writer).await;
    assert!(
        passkey_statuses(&audit_path).is_empty(),
        "the poll writes no row for a recorded registration"
    );

    mgr.confirm_registration(pending, &injected.code, Instant::now(), &mut writer)
        .expect("the page's code confirms the registration");
    assert_eq!(mgr.list().unwrap().len(), 1);
    drop(writer);

    let entries = verified_audit_entries_from_path(&audit_path);
    let [entry] = entries.as_slice() else {
        panic!("expected exactly one audit entry: {entries:?}")
    };
    let EventKind::PasskeyRegistered {
        credential_name: emitted_name,
        credential_id_redacted: redacted,
        rp_id,
        status,
    } = &entry.event_kind
    else {
        panic!("expected PasskeyRegistered entry: {entry:?}")
    };
    assert_eq!(emitted_name, credential_name, "credential_name must match");
    assert_eq!(rp_id, "localhost", "rp_id must match");
    assert_eq!(status, "registered", "status must be registered");

    // credential_id_redacted must be redacted (first-5...last-5 or short passthrough).
    assert!(
        !redacted.is_empty(),
        "credential_id_redacted must not be empty"
    );
    // The full credential_id must NOT appear verbatim (redaction requirement).
    // Our fixture encodes 32 zero-bytes; in base64url that is 43 chars, so
    // the redacted form must be shorter or contain "...".
    assert!(
        redacted.len() < 43 || redacted.contains("..."),
        "credential_id_redacted must be redacted: {redacted}"
    );
}

// 10. audit_entry_emitted_on_timeout ────────────────────────────────────────

#[tokio::test]
async fn audit_entry_emitted_on_timeout() {
    let dir = TempDir::new().unwrap();
    let (mgr, _store) = make_manager(&dir);
    let bridge_addr = fake_bridge_addr();
    let credential_name = "timeout-audit-key";

    let (mut writer, audit_path) = open_writer(&dir);

    // Prepare but do NOT inject; use a past deadline.
    let handle = mgr
        .prepare_registration(credential_name, bridge_addr, None)
        .await
        .expect("prepare_registration must succeed");
    let nonce = handle.nonce.clone();
    let deadline = Instant::now();

    let outcome = mgr
        .poll_registration(credential_name, &nonce, deadline, &mut writer)
        .await
        .expect("poll_registration must not return Err on timeout");

    assert!(
        matches!(outcome, AddPasskeyOutcome::Timeout),
        "expected Timeout, got {outcome:?}"
    );
    drop(writer);

    let entries = verified_audit_entries_from_path(&audit_path);
    let [entry] = entries.as_slice() else {
        panic!("expected exactly one timeout audit entry: {entries:?}")
    };
    let EventKind::PasskeyRegistered {
        credential_name: emitted_name,
        status,
        ..
    } = &entry.event_kind
    else {
        panic!("expected PasskeyRegistered entry: {entry:?}")
    };
    assert_eq!(status, "timeout", "status must be timeout");
    assert_eq!(emitted_name, credential_name);
}

// 11. Unconfirmed registrations ──────────────────────────────────────────────

/// A code for another credential is refused, the refusal is logged with the
/// credential ID, and nothing reaches the registry.
#[tokio::test]
async fn a_wrong_code_registers_nothing() {
    let dir = TempDir::new().unwrap();
    let (mgr, shared_store) = make_manager(&dir);
    let (mut writer, audit_path) = open_writer(&dir);
    let credential_name = "wrong-code-key";

    let injected = prepare_and_inject(
        &mgr,
        &shared_store,
        credential_name,
        fake_bridge_addr(),
        make_registration_input(),
    )
    .await;
    let pending = poll_to_pending(&mgr, credential_name, &injected, &mut writer).await;
    let mut wrong = injected.code.clone();
    let last = if wrong.ends_with('0') { "1" } else { "0" };
    wrong.replace_range(wrong.len() - 1.., last);

    let err = mgr
        .confirm_registration(pending, &wrong, Instant::now(), &mut writer)
        .expect_err("a code for another credential must refuse");
    assert!(
        matches!(err, CredentialsError::RegistrationConfirmationMismatch),
        "expected RegistrationConfirmationMismatch, got {err:?}"
    );
    assert!(mgr.list().unwrap().is_empty(), "nothing is registered");
    drop(writer);

    let entries = verified_audit_entries_from_path(&audit_path);
    let [entry] = entries.as_slice() else {
        panic!("expected exactly one audit entry: {entries:?}")
    };
    let EventKind::PasskeyRegistered {
        credential_id_redacted,
        status,
        ..
    } = &entry.event_kind
    else {
        panic!("expected PasskeyRegistered entry: {entry:?}")
    };
    assert_eq!(status, "confirmation_mismatch");
    assert_ne!(credential_id_redacted, "<no-c...-id>");
}

/// The right code at or after the deadline is refused and nothing reaches
/// the registry.
#[tokio::test]
async fn an_expired_confirmation_registers_nothing() {
    let dir = TempDir::new().unwrap();
    let (mgr, shared_store) = make_manager(&dir);
    let (mut writer, audit_path) = open_writer(&dir);
    let credential_name = "late-key";

    let injected = prepare_and_inject(
        &mgr,
        &shared_store,
        credential_name,
        fake_bridge_addr(),
        make_registration_input(),
    )
    .await;
    let pending = poll_to_pending(&mgr, credential_name, &injected, &mut writer).await;
    let late = pending.deadline() + Duration::from_secs(1);

    let err = mgr
        .confirm_registration(pending, &injected.code, late, &mut writer)
        .expect_err("a code typed after the deadline must refuse");
    assert!(
        matches!(err, CredentialsError::RegistrationConfirmationExpired),
        "expected RegistrationConfirmationExpired, got {err:?}"
    );
    assert!(mgr.list().unwrap().is_empty(), "nothing is registered");
    drop(writer);
    assert_eq!(passkey_statuses(&audit_path), ["confirmation_expired"]);
}

#[tokio::test]
async fn a_confirmation_at_the_deadline_registers_nothing() {
    let dir = TempDir::new().unwrap();
    let (mgr, shared_store) = make_manager(&dir);
    let (mut writer, audit_path) = open_writer(&dir);
    let credential_name = "late-key";

    let injected = prepare_and_inject(
        &mgr,
        &shared_store,
        credential_name,
        fake_bridge_addr(),
        make_registration_input(),
    )
    .await;
    let pending = poll_to_pending(&mgr, credential_name, &injected, &mut writer).await;
    let late = pending.deadline();

    let err = mgr
        .confirm_registration(pending, &injected.code, late, &mut writer)
        .expect_err("a code typed at the deadline must refuse");
    assert!(
        matches!(err, CredentialsError::RegistrationConfirmationExpired),
        "expected RegistrationConfirmationExpired, got {err:?}"
    );
    assert!(mgr.list().unwrap().is_empty(), "nothing is registered");
    drop(writer);
    assert_eq!(passkey_statuses(&audit_path), ["confirmation_expired"]);
}

/// The `registered` row precedes the registry write: when the writer refuses
/// it, the credential is not registered. The writer is anchored, and the log
/// is renamed away under it, which its next append refuses.
#[tokio::test]
async fn a_failed_registered_row_registers_nothing() {
    let dir = TempDir::new().unwrap();
    let (mgr, shared_store) = make_manager(&dir);
    let audit_path = dir.path().join("audit.jsonl");
    let anchor = Arc::new(InMemoryTipAnchorStore::new());
    let mut writer = AuditWriter::open_with_tip_anchor(
        audit_path.clone(),
        None,
        Arc::clone(&anchor) as Arc<dyn TipAnchorStore>,
        BindingHistory::NotRecorded,
    )
    .expect("anchored AuditWriter must open in tempdir");
    let credential_name = "unlogged-key";

    let injected = prepare_and_inject(
        &mgr,
        &shared_store,
        credential_name,
        fake_bridge_addr(),
        make_registration_input(),
    )
    .await;
    let pending = poll_to_pending(&mgr, credential_name, &injected, &mut writer).await;
    let moved = dir.path().join("moved.jsonl");
    std::fs::rename(&audit_path, &moved).unwrap();

    let err = mgr
        .confirm_registration(pending, &injected.code, Instant::now(), &mut writer)
        .expect_err("a registration whose row cannot be written must refuse");
    assert!(
        matches!(err, CredentialsError::AuditWrite { .. }),
        "expected AuditWrite, got {err:?}"
    );
    assert!(
        mgr.list().unwrap().is_empty(),
        "nothing is registered without its row"
    );
    assert!(
        !mgr.registry_path().exists(),
        "the registry file is not written"
    );
}

/// A registration that ends at the prompt without a code logs why, and
/// nothing reaches the registry.
#[tokio::test]
async fn an_abandoned_registration_records_why() {
    for (end, status) in [
        (UnconfirmedEnd::Expired, "confirmation_expired"),
        (UnconfirmedEnd::Canceled, "confirmation_canceled"),
    ] {
        let dir = TempDir::new().unwrap();
        let (mgr, shared_store) = make_manager(&dir);
        let (mut writer, audit_path) = open_writer(&dir);
        let credential_name = "abandoned-key";

        let injected = prepare_and_inject(
            &mgr,
            &shared_store,
            credential_name,
            fake_bridge_addr(),
            make_registration_input(),
        )
        .await;
        let pending = poll_to_pending(&mgr, credential_name, &injected, &mut writer).await;
        mgr.abandon_registration(pending, end, &mut writer);

        assert!(mgr.list().unwrap().is_empty(), "nothing is registered");
        drop(writer);
        assert_eq!(passkey_statuses(&audit_path), [status], "{end:?}");
    }
}
