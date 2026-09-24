//! Adoption and reset exercise the keyed audit writer and the real store lock.
#![allow(
    clippy::expect_used,
    reason = "test fixtures assert setup and outcomes"
)]

use super::*;
use crate::sponsored::tests::prepared_fixture;
use stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE;
use stellar_agent_network::keyring::{load_hmac_key_32, rotate_keyring_secret_32};
use stellar_agent_test_support::keyring_mock;
use tempfile::TempDir;

const NOW: i64 = 1_700_000_000;

struct Fixture {
    _directory: TempDir,
    path: PathBuf,
    name: String,
    profile: Profile,
    key_ref: KeyringEntryRef,
    records: Vec<AuthorizationRecord>,
    snapshot: Vec<u8>,
}

impl Fixture {
    async fn new(name: &str, version: u32, generation: u64) -> Self {
        let directory = TempDir::new().expect("directory");
        let path = directory.path().join("mpp.state");
        let key_ref = KeyringEntryRef::default_mpp_state_key(name);
        rotate_keyring_secret_32(&key_ref.service, &key_ref.account).expect("state key");
        let mut profile = Profile::builder_testnet("signer", "default", "nonce", "default").build();
        profile.audit_log_path = directory.path().join("audit.jsonl");
        profile.audit_log_hash_chain_key_id =
            KeyringEntryRef::new(format!("audit-{name}"), "default");
        let audit_ref = &profile.audit_log_hash_chain_key_id;
        rotate_keyring_secret_32(&audit_ref.service, &audit_ref.account).expect("audit key");
        let (prepared, _signer, _rpc) = prepared_fixture(NOW).await;
        let mut records = Vec::new();
        for (index, status) in [
            AuthorizationStatus::Prepared,
            AuthorizationStatus::Authorized,
            AuthorizationStatus::Indeterminate,
            AuthorizationStatus::Settled,
        ]
        .into_iter()
        .enumerate()
        {
            let mut record = AuthorizationRecord::new(
                &format!("{name}-{index}"),
                TESTNET_PASSPHRASE,
                &prepared,
                NOW,
            )
            .expect("record");
            if status != AuthorizationStatus::Prepared {
                record.allow_commit(NOW).expect("ready");
                record
                    .transition(AuthorizationStatus::Authorizing, NOW)
                    .expect("claim");
                record.set_policy_accounted();
                if status == AuthorizationStatus::Indeterminate {
                    record.transition(status, NOW).expect("indeterminate");
                } else {
                    record.set_credential_digest([3; 32]);
                    record
                        .transition(AuthorizationStatus::DeliveryPending, NOW)
                        .expect("delivery");
                    record
                        .transition(AuthorizationStatus::Authorized, NOW)
                        .expect("authorized");
                    if status == AuthorizationStatus::Settled {
                        record.set_ledger_outcome(LedgerOutcome::Settled {
                            ledger: 7,
                            reconciled_at: NOW,
                        });
                        record.transition(status, NOW).expect("settled");
                    }
                }
            }
            record.validate().expect("valid fixture record");
            records.push(record);
        }
        let mut value = serde_json::json!({"version": version, "records": records});
        if version == STORE_VERSION {
            value["generation"] = generation.into();
        }
        let body = serde_json::to_vec(&value).expect("body");
        let key = load_hmac_key_32(&key_ref).expect("key");
        let tag = compute_tag(&key, &body).expect("tag");
        let snapshot = [tag.as_slice(), body.as_slice()].concat();
        fs::write(&path, &snapshot).expect("snapshot");
        Self {
            _directory: directory,
            path,
            name: name.to_owned(),
            profile,
            key_ref,
            records,
            snapshot,
        }
    }

    fn adopt_row(&self, generation: u64) -> Result<(), MppError> {
        emit_state_audit(
            &self.profile,
            &self.name,
            AuditEntry::new_mpp_state_adopted(
                &self.name,
                generation,
                uuid::Uuid::new_v4().to_string(),
            ),
        )
    }

    fn open(&self) -> Result<MppAuthorizationStore, MppError> {
        MppAuthorizationStore::open_for_read_audited_at(
            self.path.clone(),
            &self.key_ref,
            |generation| self.adopt_row(generation),
        )?
        .ok_or_else(state_error)
    }

    fn reset(&self) -> Result<Option<u64>, MppError> {
        MppAuthorizationStore::reset_at(self.path.clone(), &self.key_ref, |generation| {
            emit_state_audit(
                &self.profile,
                &self.name,
                AuditEntry::new_mpp_state_reset(
                    &self.name,
                    generation,
                    "operator recovery",
                    uuid::Uuid::new_v4().to_string(),
                ),
            )
        })
    }

    fn rows(&self, kind: &str) -> Vec<serde_json::Value> {
        fs::read_to_string(&self.profile.audit_log_path)
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("audit row"))
            .filter(|value| value["kind"] == kind)
            .collect()
    }

    fn generation(&self) -> Option<u64> {
        load_generation(&generation_entry_ref(&self.key_ref)).expect("counter")
    }
}

#[tokio::test]
#[serial_test::serial]
async fn adoption_preserves_history_once_and_enforces_rollback() {
    keyring_mock::install().expect("keyring");
    let fx = Fixture::new("adopt-history", 1, 0).await;
    let expected = 1;
    let store = fx.open().expect("adopt verified history");
    assert_eq!(fx.generation(), Some(expected));
    for record in &fx.records {
        assert_eq!(
            serde_json::to_value(store.load(record.authorization_id()).expect("record"))
                .expect("value"),
            serde_json::to_value(record).expect("value")
        );
    }
    let settled = fx.records.last().expect("settled").authorization_id();
    assert_eq!(
        store
            .claim_ready(settled, NOW)
            .expect_err("settled replay")
            .code(),
        "mpp.authorization_replayed"
    );
    fx.open().expect("second read");
    let rows = fx.rows("mpp_state_adopted");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["profile"], fx.name);
    assert_eq!(rows[0]["generation"], expected);
    store.prune(NOW).expect("advance");
    fs::write(&fx.path, &fx.snapshot).expect("restore stale snapshot");
    assert!(
        fx.open()
            .expect_err("rollback")
            .message()
            .contains("rolled back")
    );
    fs::remove_file(&fx.path).expect("delete state");
    assert!(
        fx.open()
            .expect_err("deletion")
            .message()
            .contains("profile reset-mpp-state")
    );
    assert_eq!(fx.rows("mpp_state_adopted").len(), 1);
}

#[tokio::test]
#[serial_test::serial]
async fn a_protected_snapshot_without_its_anchor_is_not_adopted() {
    keyring_mock::install().expect("keyring");
    let fx = Fixture::new("adopt-refusal-anchored-format", STORE_VERSION, 7).await;
    assert!(
        fx.open()
            .expect_err("anchor removed")
            .message()
            .contains("profile reset-mpp-state")
    );
    assert_eq!(fx.generation(), None);
    assert!(fx.rows("mpp_state_adopted").is_empty());
    assert_eq!(fs::read(&fx.path).expect("snapshot"), fx.snapshot);
}

#[tokio::test]
#[serial_test::serial]
async fn adoption_refuses_bad_hmac_invalid_records_and_anchor_access_failure() {
    keyring_mock::install().expect("keyring");
    for fault in ["hmac", "records", "keyring"] {
        let fx = Fixture::new(&format!("adopt-refusal-{fault}"), 1, 0).await;
        if fault == "hmac" {
            let mut bytes = fx.snapshot.clone();
            bytes[0] ^= 1;
            fs::write(&fx.path, bytes).expect("tamper");
        } else if fault == "records" {
            let body = serde_json::to_vec(
                &serde_json::json!({"version":1,"records":[fx.records[0],fx.records[0]]}),
            )
            .expect("duplicate body");
            let key = load_hmac_key_32(&fx.key_ref).expect("key");
            let tag = compute_tag(&key, &body).expect("tag");
            fs::write(&fx.path, [tag.as_slice(), body.as_slice()].concat())
                .expect("duplicate snapshot");
        } else {
            let entry = generation_entry_ref(&fx.key_ref);
            keyring_mock::inject_no_logon_session(&entry.service, &entry.account)
                .expect("access error");
        }
        let before = fs::read(&fx.path).expect("snapshot");
        assert_eq!(
            fx.open().expect_err("unverified history").code(),
            "mpp.state_unavailable"
        );
        assert_eq!(fx.generation(), None);
        assert_eq!(fx.rows("mpp_state_adopted").len(), 0);
        assert_eq!(fs::read(&fx.path).expect("snapshot"), before);
    }
}

#[tokio::test]
#[serial_test::serial]
async fn adoption_and_reset_require_a_durable_audit_row() {
    keyring_mock::install().expect("keyring");
    let fx = Fixture::new("mpp-audit-required", 1, 0).await;
    let coord = &fx.profile.audit_log_hash_chain_key_id;
    keyring_core::Entry::new(&coord.service, &coord.account)
        .expect("entry")
        .delete_credential()
        .expect("missing audit key");
    let key = load_hmac_key_32(&fx.key_ref).expect("state key");
    assert!(
        fx.open()
            .expect_err("audit required for adoption")
            .message()
            .contains("audit")
    );
    assert!(
        fx.reset()
            .expect_err("audit required for reset")
            .message()
            .contains("audit")
    );
    assert_eq!(fx.generation(), None);
    assert_eq!(fs::read(&fx.path).expect("state"), fx.snapshot);
    assert_eq!(*load_hmac_key_32(&fx.key_ref).expect("state key"), *key);
    assert!(fx.rows("mpp_state_adopted").is_empty());
    assert!(fx.rows("mpp_state_reset").is_empty());
}

#[tokio::test]
#[serial_test::serial]
async fn adoption_and_reset_share_the_prepare_lock() {
    keyring_mock::install().expect("keyring");
    let fx = Fixture::new("mpp-maintenance-lock", 1, 0).await;
    let handle =
        MppAuthorizationStore::at_path(fx.path.clone(), [0; 32], generation_entry_ref(&fx.key_ref));
    let lock = handle.acquire_lock().expect("prepare lock");
    assert!(fx.open().is_err());
    assert!(fx.reset().is_err());
    assert_eq!(fx.generation(), None);
    assert!(fx.rows("mpp_state_adopted").is_empty());
    assert!(fx.rows("mpp_state_reset").is_empty());
    drop(lock);
    let barrier = std::sync::Barrier::new(2);
    std::thread::scope(|scope| {
        let first = scope.spawn(|| {
            barrier.wait();
            fx.open().is_ok()
        });
        let second = scope.spawn(|| {
            barrier.wait();
            fx.open().is_ok()
        });
        let outcomes = [first.join().expect("first"), second.join().expect("second")];
        assert!(outcomes.into_iter().any(|ok| ok));
    });
    fx.open().expect("read after contenders");
    assert_eq!(fx.rows("mpp_state_adopted").len(), 1);
    assert_eq!(fx.generation(), Some(1));
}

#[tokio::test]
#[serial_test::serial]
async fn reset_recovers_a_counter_gap_and_invalidates_snapshots_and_handles() {
    keyring_mock::install().expect("keyring");
    let fx = Fixture::new("mpp-reset-gap", 1, 0).await;
    let stale_handle = fx.open().expect("adopt");
    write_generation(&generation_entry_ref(&fx.key_ref), 2).expect("counter-only commit");
    assert!(
        fx.open()
            .expect_err("counter gap")
            .message()
            .contains("profile reset-mpp-state")
    );
    assert_eq!(fx.reset().expect("reset"), Some(2));
    assert_eq!(fx.generation(), Some(0));
    assert!(!fx.path.exists());
    assert!(
        stale_handle.prune(NOW).is_err(),
        "an old handle must not publish with the discarded key"
    );
    let clean = MppAuthorizationStore::open_for_prepare_audited_at(
        fx.path.clone(),
        &fx.key_ref,
        |generation| fx.adopt_row(generation),
    )
    .expect("clean prepare");
    assert_eq!(
        clean
            .load(fx.records[0].authorization_id())
            .expect_err("empty")
            .code(),
        "mpp.authorization_not_found"
    );
    clean
        .insert_prepared(fx.records[0].clone(), NOW)
        .expect("first prepare proceeds");
    assert_eq!(fx.generation(), Some(1));
    let rows = fx.rows("mpp_state_reset");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["profile"], fx.name);
    assert_eq!(rows[0]["discarded_generation"], 2);
    assert_eq!(rows[0]["reason"], "operator recovery");
    fs::write(&fx.path, &fx.snapshot).expect("restore old generation one");
    assert!(
        fx.open().is_err(),
        "reset must invalidate old snapshots at reused generations"
    );
}

#[tokio::test]
#[serial_test::serial]
async fn reset_recovers_a_malformed_anchor_and_missing_state_key() {
    keyring_mock::install().expect("keyring");
    let fx = Fixture::new("mpp-reset-malformed", 1, 0).await;
    let anchor = generation_entry_ref(&fx.key_ref);
    keyring_core::Entry::new(&anchor.service, &anchor.account)
        .expect("anchor")
        .set_password("bad-counter")
        .expect("counter");
    keyring_core::Entry::new(&fx.key_ref.service, &fx.key_ref.account)
        .expect("key")
        .delete_credential()
        .expect("remove key");
    assert!(
        fx.open()
            .expect_err("invalid anchor")
            .message()
            .contains("profile reset-mpp-state")
    );
    assert_eq!(fx.reset().expect("reset"), None);
    assert_eq!(fx.generation(), Some(0));
    assert!(!fx.path.exists());
    assert!(load_hmac_key_32(&fx.key_ref).is_ok());
    assert_eq!(fx.rows("mpp_state_reset").len(), 1);
    assert!(fx.rows("mpp_state_reset")[0]["discarded_generation"].is_null());
    fx.open().expect("clean state");
}
