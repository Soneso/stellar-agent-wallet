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
        let profile = Profile::builder_mainnet_named(
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
        let output = Command::new(env!("CARGO_BIN_EXE_stellar-agent"))
            .args(["profile", "reset-window-state", NAME, "--reason", "repair"])
            .env("STELLAR_AGENT_HOME", self.home.path())
            .env("STELLAR_AGENT_KEYRING_BACKEND", "headless-env")
            .env(
                "STELLAR_AGENT_HEADLESS_KEYRING_KEY",
                URL_SAFE_NO_PAD.encode(HEADLESS_KEY),
            )
            .env_remove("STELLAR_AGENT_PROFILE")
            .env_remove("STELLAR_AGENT_RPC_URL")
            .output()
            .unwrap();
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
    assert_eq!(f.state(), before);
    assert!(
        !std::fs::read(&f.profile.audit_log_path).unwrap().is_empty(),
        "the failure occurs after append acquisition and the row write"
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
        EventKind::PolicyWindowStateReset { .. }
    ));
    assert!(matches!(
        rows[1].event_kind,
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
        EventKind::PolicyWindowStateReset { .. }
    ));
    assert!(matches!(
        rows[1].event_kind,
        EventKind::KeyringKeyWritten {
            key_purpose: KeyPurpose::PolicyWindowStateHmac,
            ..
        }
    ));
    assert!(get(&f.profile.policy_window_state_key_id).is_some());
}
