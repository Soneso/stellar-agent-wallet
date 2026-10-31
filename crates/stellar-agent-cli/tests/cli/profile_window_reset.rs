//! Reset ceremony through the built binary and the persistent headless keyring.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test assertions"
)]

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serial_test::serial;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use stellar_agent_core::audit_log::test_helpers::verified_audit_entries_from_path;
use stellar_agent_core::audit_log::{EventKind, KeyPurpose};
use stellar_agent_core::policy::v1::criteria::state_store::{StateKey, WindowEntry, WindowLimit};
use stellar_agent_core::profile::schema::{KeyringEntryRef, Profile, generation_account};
use stellar_agent_network::policy_state::PersistedWindowStore;
use stellar_agent_test_support::StellarAgentHomeGuard;

const HEADLESS_KEY: [u8; 32] = [0x4b; 32];
const NAME: &str = "reset-ceremony";

struct Fixture {
    _guard: StellarAgentHomeGuard,
    home: tempfile::TempDir,
    profile: Profile,
    path: PathBuf,
}

impl Fixture {
    fn new(existing: bool) -> Self {
        let home = tempfile::tempdir().unwrap();
        let guard = StellarAgentHomeGuard::new(home.path());
        keyring_core::set_default_store(Arc::new(
            stellar_agent_headless_keyring::store::HeadlessStore::new(
                home.path().join("headless-keyring/store.keyring"),
                stellar_agent_headless_keyring::crypto::ProtectionMode::EnvKey(Arc::new(
                    zeroize::Zeroizing::new(HEADLESS_KEY),
                )),
            ),
        ));
        let mut profile = Profile::builder_mainnet_named(
            NAME,
            "https://rpc.example",
            "signer",
            "account",
            "nonce",
            "account",
        )
        .with_noop_engine()
        .audit_log_path(home.path().join("audit/reset.jsonl"))
        .build();
        profile.wallet.mlock_required = stellar_agent_core::wallet::MlockRequired::Warn;
        std::fs::create_dir_all(profile.audit_log_path.parent().unwrap()).unwrap();
        std::fs::write(&profile.audit_log_path, b"").unwrap();
        put(
            &profile.audit_log_hash_chain_key_id,
            &URL_SAFE_NO_PAD.encode([0x2c; 32]),
        );
        stellar_agent_core::profile::loader::save_to_dir(
            NAME,
            &profile,
            &home.path().join("profiles"),
        )
        .unwrap();
        let path = stellar_agent_core::profile::schema::default_policy_window_state_path_for(NAME);
        if existing {
            let now = stellar_agent_core::timefmt::now_unix_ms().unwrap();
            PersistedWindowStore::at_path(path.clone())
                .record_and_persist(
                    &profile,
                    &[WindowEntry::new(
                        StateKey::new(NAME, 3, "native", 86_400),
                        now,
                        99,
                        WindowLimit::Amount {
                            asset: "native".to_owned(),
                            window: "1d".to_owned(),
                            max_stroops: 1_000,
                        },
                    )],
                )
                .unwrap();
        }
        Self {
            _guard: guard,
            home,
            profile,
            path,
        }
    }

    fn run(&self) -> serde_json::Value {
        self.run_owner(None, "repair")
    }

    fn command(&self, reason: &str) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_stellar-agent"));
        command
            .args(["profile", "reset-window-state", NAME, "--reason", reason])
            .env("STELLAR_AGENT_HOME", self.home.path())
            .env("STELLAR_AGENT_KEYRING_BACKEND", "headless-env")
            .env(
                "STELLAR_AGENT_HEADLESS_KEYRING_KEY",
                URL_SAFE_NO_PAD.encode(HEADLESS_KEY),
            )
            .env_remove("STELLAR_AGENT_PROFILE")
            .env_remove("STELLAR_AGENT_RPC_URL");
        command
    }

    fn run_owner(&self, seed: Option<[u8; 32]>, reason: &str) -> serde_json::Value {
        let mut command = self.command(reason);
        if let Some(seed) = seed {
            command
                .args(["--owner-secret-env", "RESET_OWNER_SEED"])
                .env(
                    "RESET_OWNER_SEED",
                    stellar_strkey::ed25519::PrivateKey(seed)
                        .as_unredacted()
                        .to_string()
                        .as_str(),
                );
        }
        Self::output(command)
    }

    fn output(mut command: Command) -> serde_json::Value {
        let output = command.output().unwrap();
        let text = String::from_utf8(output.stdout).unwrap();
        let json: serde_json::Value = serde_json::from_str(text.trim()).unwrap_or_else(|e| {
            panic!(
                "{e}: {text}; stderr={}",
                String::from_utf8_lossy(&output.stderr)
            )
        });
        assert_eq!(
            output.status.code(),
            Some(if json["ok"] == true { 0 } else { 1 })
        );
        json
    }

    fn enable(&self) {
        put(
            &stellar_agent_core::profile::schema::mainnet_enablement_entry_ref(
                &self.profile.policy_window_state_key_id,
            ),
            "test-nonce",
        );
    }

    fn pin(&self, seed: [u8; 32]) {
        use stellar_agent_core::policy::{
            pin::{self, Pin, PinScope},
            state_lock::WindowStoreLock,
        };
        std::fs::create_dir_all(self.path.parent().unwrap()).unwrap();
        let lock =
            WindowStoreLock::acquire_for(&self.path, &self.profile.policy_window_state_key_id)
                .unwrap();
        let owner = ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes();
        pin::write(
            &lock,
            &PinScope::for_profile(&self.path, &self.profile),
            &Pin::new(1, [0x33; 32], owner).unwrap(),
        )
        .unwrap();
    }

    fn assert_refusal(&self, seed: Option<[u8; 32]>, code: &str) {
        let before = self.state();
        let output = self.run_owner(seed, "repair");
        assert_eq!(output["ok"], false, "{output}");
        assert_eq!(output["error"]["code"], code, "{output}");
        assert_eq!(self.state(), before);
        let rows = verified_audit_entries_from_path(&self.profile.audit_log_path);
        assert!(
            !rows
                .iter()
                .any(|row| matches!(row.event_kind, EventKind::PolicyWindowStateReset { .. }))
        );
    }

    fn assert_seed_refusal(&self, value: Option<&str>, code: &str) {
        for (audit, window) in [(false, false), (true, false), (false, true), (true, true)] {
            let before = self.state();
            let _audit = audit.then(|| lock(&sidecar(&self.profile.audit_log_path, ".lock")));
            let _window = window.then(|| lock(&sidecar(&self.path, ".lock")));
            let mut command = self.command("repair");
            command
                .args(["--owner-secret-env", "RESET_OWNER_SEED"])
                .env_remove("RESET_OWNER_SEED");
            if let Some(value) = value {
                command.env("RESET_OWNER_SEED", value);
            }
            let output = Self::output(command);
            assert_eq!(output["ok"], false, "{output}");
            assert_eq!(output["error"]["code"], code, "{output}");
            assert_eq!(self.state(), before);
            let rows = verified_audit_entries_from_path(&self.profile.audit_log_path);
            assert!(
                !rows
                    .iter()
                    .any(|row| matches!(row.event_kind, EventKind::PolicyWindowStateReset { .. }))
            );
        }
    }

    fn state(&self) -> (Option<Vec<u8>>, Option<String>, Option<String>) {
        let key = &self.profile.policy_window_state_key_id;
        let counter = KeyringEntryRef::new(&key.service, generation_account(&key.account));
        (std::fs::read(&self.path).ok(), get(key), get(&counter))
    }
}

fn put(reference: &KeyringEntryRef, value: &str) {
    keyring_core::Entry::new(&reference.service, &reference.account)
        .unwrap()
        .set_password(value)
        .unwrap();
}

fn get(reference: &KeyringEntryRef) -> Option<String> {
    keyring_core::Entry::new(&reference.service, &reference.account)
        .unwrap()
        .get_password()
        .ok()
}

fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut path = path.as_os_str().to_os_string();
    path.push(suffix);
    path.into()
}

fn lock(path: &Path) -> std::fs::File {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(path)
        .unwrap();
    file.try_lock().unwrap();
    file
}

#[test]
#[serial]
fn reset_row_and_output_carry_the_wiped_accrual_and_chain() {
    let f = Fixture::new(true);
    let output = f.run();
    assert_eq!(output["ok"], true, "{output}");
    let rows = verified_audit_entries_from_path(&f.profile.audit_log_path);
    let row = rows
        .iter()
        .find(|row| matches!(row.event_kind, EventKind::PolicyWindowStateReset { .. }))
        .unwrap();
    assert_eq!(row.chain_id.as_deref(), Some("stellar:mainnet"));
    let EventKind::PolicyWindowStateReset {
        wiped: Some(wiped), ..
    } = &row.event_kind
    else {
        panic!("reset snapshot missing")
    };
    assert_eq!(wiped.entry_count, 1);
    assert_eq!(wiped.buckets[0].scope_specificity, 3);
    assert_eq!(wiped.buckets[0].confirmed_total, 99);
    assert_eq!(
        (wiped.generation_before, wiped.generation_after),
        (Some(1), 2)
    );
    assert_eq!(
        output["data"]["wiped"],
        serde_json::to_value(wiped).unwrap()
    );
    let memory = stellar_agent_core::policy::v1::PolicyStateStore::new();
    PersistedWindowStore::at_path(f.path.clone())
        .load_into(NAME, &f.profile, &memory)
        .unwrap();
    let (sum, count) = memory
        .query_window(
            &StateKey::new(NAME, 3, "native", 86_400),
            stellar_agent_core::timefmt::now_unix_ms().unwrap(),
        )
        .unwrap();
    assert_eq!((sum, count), (0, 0));
}

#[test]
#[serial]
fn audit_writer_contention_keeps_window_state_unchanged() {
    let f = Fixture::new(true);
    let before = f.state();
    let _lock = lock(&sidecar(&f.profile.audit_log_path, ".lock"));
    let output = f.run();
    assert_eq!(
        output["error"]["code"], "audit.chain_key_unavailable",
        "{output}"
    );
    assert!(
        output["error"]["message"]
            .as_str()
            .unwrap()
            .contains("audit.writer_locked")
    );
    assert_eq!(f.state(), before);
}

#[test]
#[serial]
fn both_locks_refuse_with_the_audit_code_first() {
    let f = Fixture::new(true);
    let before = f.state();
    let _audit = lock(&sidecar(&f.profile.audit_log_path, ".lock"));
    let _window = lock(&sidecar(&f.path, ".lock"));
    let output = f.run();
    assert_eq!(
        output["error"]["code"], "audit.chain_key_unavailable",
        "{output}"
    );
    assert!(
        output["error"]["message"]
            .as_str()
            .unwrap()
            .contains("audit.writer_locked")
    );
    assert_eq!(f.state(), before);
}

/// An audit append failure refuses the reset with the append's I/O cause and
/// leaves the window state unchanged.
///
/// The keyed writer's first row is its entry-tag boundary row, so the
/// blocked chain-root sidecar fails that row after it is written. The reset
/// then refuses before its own row with that failure, `audit.io_error`, not
/// as growth of the log by another writer.
#[test]
#[serial]
fn append_failure_refuses_without_changing_window_state() {
    let f = Fixture::new(true);
    let before = f.state();
    std::fs::create_dir(sidecar(&f.profile.audit_log_path, ".root_hmac")).unwrap();
    let output = f.run();
    assert_eq!(output["ok"], false, "{output}");
    assert_eq!(
        output["error"]["code"], "audit.chain_key_unavailable",
        "{output}"
    );
    assert!(
        output["error"]["message"]
            .as_str()
            .unwrap()
            .contains("audit.io_error: an append to the audit log failed"),
        "{output}"
    );
    assert_eq!(f.state(), before);
    let kinds: Vec<String> = std::fs::read_to_string(&f.profile.audit_log_path)
        .unwrap()
        .lines()
        .map(|line| {
            serde_json::from_str::<serde_json::Value>(line).unwrap()["kind"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    assert_eq!(
        kinds,
        ["audit_entry_tags_started"],
        "the boundary row is written and the reset row is not"
    );
}

#[test]
#[serial]
fn first_use_mint_is_recorded_after_the_reset_row() {
    let f = Fixture::new(false);
    let output = f.run();
    assert_eq!(output["ok"], true, "{output}");
    let rows = verified_audit_entries_from_path(&f.profile.audit_log_path);
    assert!(matches!(
        rows[0].event_kind,
        EventKind::AuditEntryTagsStarted { .. }
    ));
    assert!(matches!(
        rows[1].event_kind,
        EventKind::PolicyWindowStateReset { .. }
    ));
    assert!(matches!(
        rows[2].event_kind,
        EventKind::KeyringKeyWritten {
            key_purpose: KeyPurpose::PolicyWindowStateHmac,
            ..
        }
    ));
}

#[test]
#[serial]
fn mint_is_recorded_even_when_the_store_write_fails() {
    let f = Fixture::new(false);
    std::fs::create_dir_all(sidecar(&f.path, ".tmp")).unwrap();
    let output = f.run();
    assert_eq!(
        output["error"]["code"], "internal.unexpected_state",
        "{output}"
    );
    assert!(
        output["error"]["message"]
            .as_str()
            .unwrap()
            .starts_with("unexpected internal state: policy_window_state.reset_failed:")
    );
    let rows = verified_audit_entries_from_path(&f.profile.audit_log_path);
    assert!(matches!(
        rows[0].event_kind,
        EventKind::AuditEntryTagsStarted { .. }
    ));
    assert!(matches!(
        rows[1].event_kind,
        EventKind::PolicyWindowStateReset { .. }
    ));
    assert!(matches!(
        rows[2].event_kind,
        EventKind::KeyringKeyWritten {
            key_purpose: KeyPurpose::PolicyWindowStateHmac,
            ..
        }
    ));
    assert!(get(&f.profile.policy_window_state_key_id).is_some());
}

#[test]
#[serial]
fn an_enabled_reset_without_the_owner_seed_refuses() {
    for existing in [false, true] {
        let f = Fixture::new(existing);
        f.enable();
        f.pin([0x51; 32]);
        f.assert_refusal(None, "profile.reset_window_state_owner_required");
    }
}

#[test]
#[serial]
fn an_enabled_reset_with_another_seed_refuses() {
    let f = Fixture::new(true);
    f.enable();
    f.pin([0x51; 32]);
    f.assert_refusal(
        Some([0x52; 32]),
        "profile.reset_window_state_owner_mismatch",
    );
}

#[test]
#[serial]
fn an_owner_seed_without_a_nonce_must_match_the_pin() {
    let f = Fixture::new(true);
    f.pin([0x51; 32]);
    f.assert_refusal(
        Some([0x52; 32]),
        "profile.reset_window_state_owner_mismatch",
    );
}

#[test]
#[serial]
fn an_unset_owner_seed_refuses_before_either_lock() {
    let f = Fixture::new(true);
    f.enable();
    f.pin([0x51; 32]);
    f.assert_seed_refusal(None, "validation.secret_env_not_set");
}

#[test]
#[serial]
fn an_invalid_owner_seed_refuses_before_either_lock() {
    let f = Fixture::new(true);
    f.enable();
    f.pin([0x51; 32]);
    f.assert_seed_refusal(Some("invalid-S-strkey"), "validation.secret_env_invalid");
}

#[test]
#[serial]
fn an_enabled_reset_without_a_pin_refuses() {
    let f = Fixture::new(true);
    f.enable();
    f.assert_refusal(Some([0x51; 32]), "policy.pin_absent");
}

#[test]
#[serial]
fn an_owner_seed_without_a_pin_refuses() {
    let f = Fixture::new(false);
    f.assert_refusal(Some([0x51; 32]), "policy.pin_absent");
}

#[test]
#[serial]
fn a_reset_without_a_nonce_needs_no_seed() {
    let f = Fixture::new(true);
    f.pin([0x51; 32]);
    assert_eq!(f.run()["ok"], true);
    let rows = verified_audit_entries_from_path(&f.profile.audit_log_path);
    let row = rows
        .iter()
        .find(|row| matches!(row.event_kind, EventKind::PolicyWindowStateReset { .. }))
        .unwrap();
    assert!(
        serde_json::to_value(row)
            .unwrap()
            .get("owner_authorization")
            .is_none()
    );
}

#[test]
#[serial]
fn an_enabled_reset_by_the_pinned_owner_records_the_signature() {
    use sha2::{Digest as _, Sha256};
    use stellar_agent_core::policy::v1::signature::{
        WindowResetStatement, verify, window_reset_digest,
    };
    for existing in [false, true] {
        let f = Fixture::new(existing);
        f.enable();
        f.pin([0x51; 32]);
        let hash: Option<[u8; 32]> = f.state().0.map(|bytes| Sha256::digest(bytes).into());
        let reason = "réparation".repeat(30);
        let output = f.run_owner(Some([0x51; 32]), &reason);
        assert_eq!(output["ok"], true, "{output}");
        let rows = verified_audit_entries_from_path(&f.profile.audit_log_path);
        let row = rows
            .iter()
            .find(|row| matches!(row.event_kind, EventKind::PolicyWindowStateReset { .. }))
            .unwrap();
        let EventKind::PolicyWindowStateReset {
            profile,
            reason: recorded,
            wiped: Some(wiped),
            owner_authorization: Some(auth),
        } = &row.event_kind
        else {
            panic!("missing authorization")
        };
        assert_eq!(recorded, &"réparation".repeat(8));
        assert_eq!(
            auth.store_sha256,
            hash.map(|hash| stellar_agent_core::hex::encode(&hash))
        );
        assert_eq!(auth.signature.len(), 128);
        assert!(
            auth.signature
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        );
        let signature: Vec<u8> = auth
            .signature
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        let owner = ed25519_dalek::SigningKey::from_bytes(&[0x51; 32])
            .verifying_key()
            .to_bytes();
        assert_eq!(
            auth.owner_redacted,
            stellar_agent_core::observability::RedactedStrkey::from_full(
                &stellar_agent_core::profile::owner_key::encode_owner_public_key(&owner),
            )
        );
        let digest = window_reset_digest(&WindowResetStatement {
            profile,
            chain_id: row.chain_id.as_deref().unwrap(),
            store_sha256: hash,
            generation_before: wiped.generation_before,
            generation_after: wiped.generation_after,
            reason: recorded,
            request_id: &row.request_id,
        });
        verify(&digest, &signature.try_into().unwrap(), &owner, NAME).unwrap();
        let state = stellar_agent_core::policy::v1::PolicyStateStore::new();
        PersistedWindowStore::at_path(f.path.clone())
            .load_into(NAME, &f.profile, &state)
            .unwrap();
        assert_eq!(
            state
                .query_window(
                    &StateKey::new(NAME, 3, "native", 86_400),
                    stellar_agent_core::timefmt::now_unix_ms().unwrap()
                )
                .unwrap(),
            (0, 0)
        );
        let generation: serde_json::Value = serde_json::from_str(&f.state().2.unwrap()).unwrap();
        assert_eq!(generation["generation"], wiped.generation_after);
    }
}
