//! Reset ceremony through the built binary and the persistent headless keyring.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test assertions"
)]

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit as _, Mac as _};
use serial_test::serial;
use sha2::Sha256;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use stellar_agent_core::audit_log::test_helpers::verified_audit_entries_from_path;
use stellar_agent_core::audit_log::{EventKind, KeyPurpose};
use stellar_agent_core::policy::v1::criteria::state_store::{StateKey, WindowEntry, WindowLimit};
use stellar_agent_core::profile::schema::{KeyringEntryRef, Profile, generation_account};
use stellar_agent_network::policy_state::PersistedWindowStore;
use stellar_agent_test_support::StellarAgentHomeGuard;
use stellar_agent_test_support::rejected_value::assert_no_marker_in_text;

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
        Self::for_chain(existing, true)
    }

    fn for_chain(existing: bool, mainnet: bool) -> Self {
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
        if !mainnet {
            profile.chain_id = stellar_agent_core::profile::caip2::Caip2::Testnet;
            profile.network_passphrase =
                stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE.into();
        }
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

    fn window_lock(&self) -> PathBuf {
        stellar_agent_core::policy::state_lock::window_lock_path(
            &self.path,
            &self.profile.policy_window_state_key_id,
        )
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
        pin::write_for_test(
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
            let _window = window.then(|| lock(&self.window_lock()));
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
    let _window = lock(&f.window_lock());
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

/// An authenticated store whose version this build does not read keeps its
/// stable code, and the version stays out of the envelope and every event.
#[test]
#[serial]
fn an_unsupported_version_stays_out_of_the_reset_refusal() {
    const REFUSED_VERSION: &str = "3141592653";
    let f = Fixture::new(true);
    let key =
        stellar_agent_network::keyring::load_hmac_key_32(&f.profile.policy_window_state_key_id)
            .unwrap();
    let body = format!(r#"{{"version":{REFUSED_VERSION}}}"#);
    // The store authenticates its body under its context label.
    let tag = Hmac::<Sha256>::new_from_slice(key.as_ref())
        .unwrap()
        .chain_update(b"stellar-agent-policy-window/v1/body\x00")
        .chain_update(&body)
        .finalize()
        .into_bytes();
    std::fs::write(&f.path, [tag.as_slice(), body.as_bytes()].concat()).unwrap();
    let before = f.state();

    let mut command = f.command("repair");
    let output = command.env("STELLAR_AGENT_LOG", "trace").output().unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let envelope: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(envelope["ok"], false, "{envelope}");
    assert_eq!(
        envelope["error"]["code"], "profile.reset_window_state_newer_version",
        "{envelope}"
    );
    let message = envelope["error"]["message"].as_str().unwrap();
    assert!(
        message.ends_with(
            "policy window-state version must be supported by this build; use the build that \
             wrote the file"
        ),
        "{message}"
    );
    assert_no_marker_in_text(&stdout, REFUSED_VERSION);
    assert_no_marker_in_text(&stderr, REFUSED_VERSION);
    assert_eq!(f.state(), before);
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
fn mainnet_pinned_reset_without_nonce_requires_signature() {
    for existing in [false, true] {
        let f = Fixture::new(existing);
        f.pin([0x51; 32]);
        f.assert_refusal(None, "profile.reset_window_state_owner_required");
        let output = f.run();
        let message = output["error"]["message"].as_str().unwrap();
        assert!(message.contains("owner's signature"));
        assert!(!message.contains("mainnet enabled"));
    }
}

#[test]
#[serial]
fn owner_reset_without_nonce_requires_signature() {
    for existing in [false, true] {
        for pinned in [false, true] {
            let f = Fixture::for_chain(existing, false);
            let owner = ed25519_dalek::SigningKey::from_bytes(&[0x51; 32])
                .verifying_key()
                .to_bytes();
            put(
                &f.profile.policy_owner_key_id,
                &stellar_agent_core::profile::owner_key::encode_owner_public_key(&owner),
            );
            if pinned {
                f.pin([0x51; 32]);
            }
            f.assert_refusal(None, "profile.reset_window_state_owner_required");
            let output = f.run();
            let message = output["error"]["message"].as_str().unwrap();
            assert!(message.contains("owner's signature"));
            assert!(!message.contains("mainnet enabled"));
        }
    }
}

#[test]
#[serial]
fn owner_reset_without_nonce_records_verified_signature() {
    use sha2::Digest as _;
    use stellar_agent_core::policy::v1::signature::{
        WindowResetStatement, verify, window_reset_digest,
    };
    for mainnet in [false, true] {
        for pinned in [false, true] {
            let f = Fixture::for_chain(true, mainnet);
            let owner = ed25519_dalek::SigningKey::from_bytes(&[0x51; 32])
                .verifying_key()
                .to_bytes();
            put(
                &f.profile.policy_owner_key_id,
                &stellar_agent_core::profile::owner_key::encode_owner_public_key(&owner),
            );
            if pinned {
                f.pin([0x51; 32]);
            }
            let pin_ref = stellar_agent_core::profile::schema::policy_pin_entry_ref(
                &f.profile.policy_window_state_key_id,
            );
            let nonce_ref = stellar_agent_core::profile::schema::mainnet_enablement_entry_ref(
                &f.profile.policy_window_state_key_id,
            );
            let raw = |entry: &KeyringEntryRef| {
                keyring_core::Entry::new(&entry.service, &entry.account)
                    .unwrap()
                    .get_password()
                    .ok()
            };
            let pin = raw(&pin_ref);
            let nonce = raw(&nonce_ref);
            let profile_path = f.home.path().join("profiles").join(format!("{NAME}.toml"));
            let profile_bytes = std::fs::read(&profile_path).unwrap();
            let policy_path = f.home.path().join("policies").join(format!("{NAME}.toml"));
            std::fs::create_dir_all(policy_path.parent().unwrap()).unwrap();
            let policy_body = format!(
                "version = 2\nsequence = 1\nscope = \"profile:{NAME}\"\n[[rules]]\nmatch = {{tool = \"stellar_pay\", chain = \"*\"}}\ncriteria = [{{kind = \"per_tx_cap\", asset = \"native\", max_stroops = \"1\"}}]\ndecision = \"allow\"\n"
            );
            let canonical =
                stellar_agent_core::policy::v1::canonical::canonical_bytes(&policy_body).unwrap();
            let signature = stellar_agent_core::policy::v1::signature::sign(
                &stellar_agent_core::policy::v1::signature::digest(&canonical),
                &ed25519_dalek::SigningKey::from_bytes(&[0x51; 32]),
            );
            let policy = format!(
                "{policy_body}\n[signature]\nowner_id = \"{}\"\nsig = \"{}\"\n",
                stellar_strkey::ed25519::PublicKey(owner),
                stellar_agent_core::hex::encode(&signature)
            )
            .into_bytes();
            std::fs::write(&policy_path, &policy).unwrap();
            let hash = Sha256::digest(f.state().0.unwrap()).into();
            assert_eq!(f.run_owner(Some([0x51; 32]), "repair")["ok"], true);
            let rows = verified_audit_entries_from_path(&f.profile.audit_log_path);
            let row = rows
                .iter()
                .find(|row| matches!(row.event_kind, EventKind::PolicyWindowStateReset { .. }))
                .unwrap();
            let EventKind::PolicyWindowStateReset {
                profile,
                reason,
                wiped: Some(wiped),
                owner_authorization: Some(auth),
            } = &row.event_kind
            else {
                panic!("missing signed reset");
            };
            let decode = |value: &str| {
                value
                    .as_bytes()
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                    .collect::<Vec<_>>()
            };
            let digest = window_reset_digest(&WindowResetStatement {
                profile,
                chain_id: row.chain_id.as_deref().unwrap(),
                store_sha256: Some(hash),
                generation_before: wiped.generation_before,
                generation_after: wiped.generation_after,
                reason,
                request_id: &row.request_id,
                challenge: decode(&auth.challenge).try_into().unwrap(),
            });
            verify(
                &digest,
                &decode(&auth.signature).try_into().unwrap(),
                &owner,
                NAME,
            )
            .unwrap();
            let body: serde_json::Value =
                serde_json::from_slice(&f.state().0.unwrap()[32..]).unwrap();
            assert_eq!(
                body["reset_consent"]["statement_digest"],
                stellar_agent_core::hex::encode(&digest)
            );
            assert_eq!(body["reset_consent"]["request_id"], row.request_id);
            assert_eq!(raw(&pin_ref), pin);
            assert_eq!(raw(&nonce_ref), nonce);
            assert_eq!(std::fs::read(profile_path).unwrap(), profile_bytes);
            assert_eq!(std::fs::read(policy_path).unwrap(), policy);
        }
    }
}

#[test]
#[serial]
fn an_enabled_reset_by_the_pinned_owner_records_the_signature() {
    use sha2::{Digest as _, Sha256};
    use stellar_agent_core::policy::v1::signature::{
        WindowResetStatement, verify, window_reset_digest,
    };
    let mut challenges = Vec::new();
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
        assert_eq!(recorded, &"réparation".repeat(5));
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
        assert_eq!(auth.challenge.len(), 64);
        assert!(
            auth.challenge
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        );
        let challenge: [u8; 32] = auth
            .challenge
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap();
        challenges.push(challenge);
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
            challenge,
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
    assert_ne!(
        challenges[0], challenges[1],
        "each reset draws its own challenge"
    );
}

#[test]
#[serial]
fn owner_seed_engine_ceremony_output_excludes_secrets() {
    let f = Fixture::for_chain(false, false);
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x51; 32]);
    put(
        &f.profile.policy_owner_key_id,
        &stellar_agent_core::profile::owner_key::encode_owner_public_key(
            &key.verifying_key().to_bytes(),
        ),
    );
    let directory = f.home.path().join("policies");
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join(format!("{NAME}.toml"));
    for kind in ["noop", "v1"] {
        let body = format!(
            "version = 2\nsequence = 1\nengine = \"{kind}\"\nscope = \"profile:{NAME}\"\n[[rules]]\nmatch = {{tool = \"stellar_pay\", chain = \"*\"}}\ncriteria = []\ndecision = \"deny\"\n"
        );
        std::fs::write(&path, &body).unwrap();
        for seed in [[0x52; 32], [0x51; 32]] {
            let secret = stellar_strkey::ed25519::PrivateKey(seed)
                .as_unredacted()
                .to_string();
            let output = Command::new(env!("CARGO_BIN_EXE_stellar-agent"))
                .args([
                    "profile",
                    "sign-policy",
                    "--profile",
                    NAME,
                    "--secret-env",
                    "CEREMONY_OWNER",
                ])
                .env("STELLAR_AGENT_HOME", f.home.path())
                .env("STELLAR_AGENT_KEYRING_BACKEND", "headless-env")
                .env(
                    "STELLAR_AGENT_HEADLESS_KEYRING_KEY",
                    URL_SAFE_NO_PAD.encode(HEADLESS_KEY),
                )
                .env("CEREMONY_OWNER", secret.as_str())
                .env_remove("STELLAR_AGENT_PROFILE")
                .env_remove("STELLAR_AGENT_RPC_URL")
                .output()
                .unwrap();
            for bytes in [&output.stdout, &output.stderr] {
                assert!(!String::from_utf8_lossy(bytes).contains(secret.as_str()));
                assert!(
                    !String::from_utf8_lossy(bytes)
                        .contains(&stellar_agent_core::hex::encode(&seed))
                );
            }
            assert_eq!(
                output.status.code(),
                Some(if seed == [0x51; 32] { 0 } else { 1 })
            );
            if seed != [0x51; 32] {
                assert_eq!(std::fs::read_to_string(&path).unwrap(), body);
            }
        }
    }
}
