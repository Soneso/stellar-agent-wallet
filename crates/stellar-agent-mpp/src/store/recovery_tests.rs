//! Adoption and reset exercise the keyed audit writer and the real store lock.
#![allow(
    clippy::expect_used,
    reason = "test fixtures assert setup and outcomes"
)]

use super::*;
use crate::sponsored::tests::prepared_fixture_for_resource;
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
            let (prepared, _, _) = prepared_fixture_for_resource(
                NOW,
                &format!("https://merchant.example/recovery/{index}"),
            )
            .await;
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
            stellar_agent_core::audit_log::BindingCheck::Enforce,
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
            &self.name,
            |generation| self.adopt_row(generation),
        )?
        .ok_or_else(state_error)
    }

    fn reset(&self) -> Result<MppStateReset, MppError> {
        MppAuthorizationStore::reset_at(
            self.path.clone(),
            &self.key_ref,
            &self.name,
            NOW,
            |outcome| {
                emit_state_audit(
                    &self.profile,
                    &self.name,
                    stellar_agent_core::audit_log::BindingCheck::Enforce,
                    AuditEntry::new_mpp_state_reset(
                        &self.name,
                        outcome.discarded_generation,
                        outcome.carried_generation,
                        outcome.stale_carry,
                        "operator recovery",
                        uuid::Uuid::new_v4().to_string(),
                    ),
                )
            },
        )
    }

    fn intent_entry(&self) -> KeyringEntryRef {
        generation_intent_entry_ref(&generation_entry_ref(&self.key_ref))
    }

    fn intent(&self) -> Option<u64> {
        load_intent(&self.intent_entry()).expect("intent")
    }

    fn put(entry_ref: &KeyringEntryRef, value: &str) {
        keyring_core::Entry::new(&entry_ref.service, &entry_ref.account)
            .expect("entry")
            .set_password(value)
            .expect("keyring value");
    }

    fn put_bytes(entry_ref: &KeyringEntryRef, value: &[u8]) {
        keyring_core::Entry::new(&entry_ref.service, &entry_ref.account)
            .expect("entry")
            .set_secret(value)
            .expect("keyring bytes");
    }

    /// The pruned-expiry watermark of the state file on disk.
    fn watermark(&self) -> i64 {
        let bytes = fs::read(&self.path).expect("state");
        let body: serde_json::Value =
            serde_json::from_slice(&bytes[HMAC_TAG_BYTES..]).expect("body");
        body.get("pruned_through")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(0)
    }

    async fn record_for(&self, resource: &str, now: i64) -> AuthorizationRecord {
        let (prepared, _, _) = prepared_fixture_for_resource(now, resource).await;
        AuthorizationRecord::new(&self.name, TESTNET_PASSPHRASE, &prepared, now).expect("record")
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

    /// The operator step a carry refusal names: the state file leaves the
    /// MPP state directory.
    fn move_state_file_out(&self) {
        fs::rename(&self.path, self._directory.path().join("moved-out.state"))
            .expect("move the state file out");
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
    Fixture::put(&generation_entry_ref(&fx.key_ref), "0");
    assert!(
        fx.reset()
            .expect_err("audit required for reset")
            .message()
            .contains("audit")
    );
    assert_eq!(fx.generation(), Some(0));
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

/// Only intent one identifies a resumable adoption beside a version 1 file.
/// Any other intent cannot be told apart from anchor removal, so it refuses.
#[tokio::test]
#[serial_test::serial]
async fn adoption_refuses_a_present_intent() {
    keyring_mock::install().expect("keyring");
    for intent in ["0", "5"] {
        let fx = Fixture::new(&format!("adopt-refusal-intent-{intent}"), 1, 0).await;
        Fixture::put(&fx.intent_entry(), intent);
        let error = fx.open().expect_err("intent without counter");
        assert_eq!(error.message(), anchor_error().message());
        assert_eq!(fx.generation(), None);
        assert_eq!(fs::read(&fx.path).expect("snapshot"), fx.snapshot);
    }
}

/// An adoption at intent one resumes at generation two before publication.
/// A publication under an absent counter completes through its matching intent.
#[tokio::test]
#[serial_test::serial]
async fn an_interrupted_adoption_completes_on_the_next_open() {
    keyring_mock::install().expect("keyring");
    for (index, (hook, published)) in [
        (&tests::AFTER_RESERVATION, false),
        (&tests::BEFORE_PUBLICATION, false),
        (&tests::AFTER_PUBLICATION, true),
        (&tests::BEFORE_GENERATION_WRITE, true),
    ]
    .into_iter()
    .enumerate()
    {
        let fx = Fixture::new(&format!("adopt-interrupted-{index}"), 1, 0).await;
        hook.with(|slot| *slot.borrow_mut() = Some(Box::new(|| Err(state_error()))));
        assert_eq!(
            fx.open().expect_err("interrupted adoption").code(),
            "mpp.state_unavailable"
        );
        assert_eq!(fx.generation(), None);
        assert_eq!(fx.intent(), Some(1));
        let expected = if published { 1 } else { 2 };
        let store = fx.open().expect("the next open completes the adoption");
        assert_eq!(fx.generation(), Some(expected));
        assert_eq!(fx.intent(), Some(expected));
        assert_eq!(
            store.read_for_test().expect("adopted snapshot").generation,
            expected
        );
        for record in &fx.records {
            assert_eq!(
                serde_json::to_value(store.load(record.authorization_id()).expect("record"))
                    .expect("value"),
                serde_json::to_value(record).expect("value")
            );
        }
        let rows = fx.rows("mpp_state_adopted");
        assert_eq!(rows.len(), if published { 1 } else { 2 });
        assert_eq!(rows[rows.len() - 1]["generation"], expected);
    }
}

#[tokio::test]
#[serial_test::serial]
async fn reset_carries_authenticated_records_across_a_counter_gap() {
    keyring_mock::install().expect("keyring");
    let fx = Fixture::new("mpp-reset-gap", 1, 0).await;
    let stale_handle = fx.open().expect("adopt");
    let key = load_hmac_key_32(&fx.key_ref).expect("key");
    let snapshot = fs::read(&fx.path).expect("pre-reset snapshot");
    write_generation(&generation_entry_ref(&fx.key_ref), 2).expect("counter-only commit");
    assert!(
        fx.open()
            .expect_err("counter gap")
            .message()
            .contains("profile reset-mpp-state")
    );
    let outcome = fx.reset().expect("reset");
    assert_eq!(outcome.discarded_generation, Some(2));
    assert_eq!(outcome.carried_records, 4);
    assert_eq!(outcome.carried_generation, Some(1));
    assert!(
        !outcome.stale_carry,
        "a gap of one is an interrupted commit"
    );
    assert_eq!(fx.generation(), Some(3));
    assert_eq!(fx.watermark(), 0, "a current carry keeps the watermark");
    assert_eq!(*load_hmac_key_32(&fx.key_ref).expect("key"), *key);
    let carried = fx.open().expect("carried history");
    for (index, record) in fx.records.iter().enumerate() {
        let expected = if index == 0 {
            AuthorizationStatus::ExpiredUnresolved
        } else {
            record.status()
        };
        assert_eq!(
            carried
                .load(record.authorization_id())
                .expect("carried record")
                .status(),
            expected
        );
        assert_eq!(
            stale_handle
                .load(record.authorization_id())
                .expect("old handle reads carried record")
                .status(),
            expected
        );
    }
    assert_eq!(
        carried
            .insert_prepared(fx.records[0].clone(), NOW)
            .expect_err("replay")
            .code(),
        "mpp.authorization_replayed"
    );
    let rows = fx.rows("mpp_state_reset");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["profile"], fx.name);
    assert_eq!(rows[0]["discarded_generation"], 2);
    assert_eq!(rows[0]["carried_generation"], 1);
    assert!(rows[0].get("stale_carry").is_none());
    assert_eq!(rows[0]["reason"], "operator recovery");
    fs::write(&fx.path, snapshot).expect("restore pre-reset snapshot");
    assert!(
        fx.open()
            .expect_err("rollback")
            .message()
            .contains("rolled back")
    );
}

/// A file more than one generation below the committed counter was rolled
/// back. The reset carries it, reports it as stale, and refuses challenges
/// expiring within the challenge lifetime cap, whose markers it may have lost.
#[tokio::test]
#[serial_test::serial]
async fn reset_reports_a_stale_carry_and_refuses_challenges_it_may_have_lost() {
    keyring_mock::install().expect("keyring");
    let fx = Fixture::new("mpp-reset-stale", STORE_VERSION, 1).await;
    write_generation(&generation_entry_ref(&fx.key_ref), 1).expect("anchor");
    let store = fx.open().expect("anchored store");
    store.prune(NOW).expect("generation 2");
    store.prune(NOW).expect("generation 3");
    fs::write(&fx.path, &fx.snapshot).expect("roll back to generation 1");
    let outcome = fx.reset().expect("reset");
    assert_eq!(outcome.discarded_generation, Some(3));
    assert_eq!(outcome.carried_generation, Some(1));
    assert!(outcome.stale_carry);
    assert_eq!(outcome.carried_records, 4);
    assert_eq!(fx.generation(), Some(4));
    assert_eq!(fx.watermark(), NOW + MAX_CHALLENGE_LIFETIME_SECS);
    let rows = fx.rows("mpp_state_reset");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["carried_generation"], 1);
    assert_eq!(rows[0]["stale_carry"], true);
    let carried = fx.open().expect("carried store");
    let lost = fx
        .record_for("https://merchant.example/recovery/lost", NOW)
        .await;
    let refused = carried
        .insert_prepared(lost, NOW)
        .expect_err("a lost marker's challenge is refused");
    assert_eq!(refused.code(), "mpp.challenge_expired");
    let fresh = fx
        .record_for("https://merchant.example/recovery/fresh", NOW + 1)
        .await;
    carried
        .insert_prepared(fresh, NOW + 1)
        .expect("a challenge expiring past the cap prepares");
}

/// A malformed counter cannot bound the generations the retained key sealed,
/// so a carry refuses before audit, key rotation, or publication. Once the
/// state file is moved out, the reset discards: the fresh key leaves no
/// earlier snapshot that authenticates, and the guarded writes replace the
/// malformed value above every valid counter.
#[tokio::test]
#[serial_test::serial]
async fn malformed_counters_refuse_a_carry_and_recover_by_discarding() {
    keyring_mock::install().expect("keyring");
    check_malformed_counter_recovery("text-committed", b"bad-counter", b"3", None).await;
    check_malformed_counter_recovery("text-intent", b"3", b"bad-intent", Some(3)).await;
}

#[tokio::test]
#[serial_test::serial]
async fn non_utf8_committed_counter_recovers_by_discarding() {
    keyring_mock::install().expect("keyring");
    check_malformed_counter_recovery("bytes-committed", &[0xff, 0xfe], b"3", None).await;
}

#[tokio::test]
#[serial_test::serial]
async fn non_utf8_intent_counter_recovers_by_discarding() {
    keyring_mock::install().expect("keyring");
    check_malformed_counter_recovery("bytes-intent", b"3", &[0xff, 0xfe], Some(3)).await;
}

async fn check_malformed_counter_recovery(
    label: &str,
    counter: &[u8],
    intent: &[u8],
    discarded: Option<u64>,
) {
    let fx = Fixture::new(&format!("mpp-reset-{label}"), STORE_VERSION, 3).await;
    let anchor = generation_entry_ref(&fx.key_ref);
    Fixture::put_bytes(&anchor, counter);
    Fixture::put_bytes(&fx.intent_entry(), intent);
    let key = load_hmac_key_32(&fx.key_ref).expect("key");
    if discarded.is_none() {
        assert_eq!(
            fx.open().expect_err("invalid anchor").message(),
            anchor_error().message()
        );
    } else {
        assert_eq!(
            fx.open()
                .expect("committed snapshot reads")
                .prune(NOW)
                .expect_err("invalid intent refuses mutation")
                .message(),
            anchor_error().message()
        );
    }
    assert_eq!(
        fx.reset().expect_err("invalid counter").message(),
        carry_anchor_error().message()
    );
    for (entry_ref, expected) in [(&anchor, counter), (&fx.intent_entry(), intent)] {
        assert_eq!(
            keyring_core::Entry::new(&entry_ref.service, &entry_ref.account)
                .expect("entry")
                .get_secret()
                .expect("counter bytes"),
            expected
        );
    }
    assert_eq!(fs::read(&fx.path).expect("snapshot"), fx.snapshot);
    assert_eq!(*load_hmac_key_32(&fx.key_ref).expect("key"), *key);
    assert!(fx.rows("mpp_state_reset").is_empty());
    fx.move_state_file_out();
    let outcome = fx.reset().expect("discarding reset");
    assert_eq!(outcome.discarded_generation, discarded);
    assert_eq!(outcome.carried_records, 0);
    assert_eq!(outcome.carried_generation, None);
    assert_eq!(fx.generation(), Some(4));
    assert_eq!(fx.intent(), Some(4));
    assert_ne!(*load_hmac_key_32(&fx.key_ref).expect("rotated key"), *key);
    assert_eq!(fx.watermark(), NOW + MAX_CHALLENGE_LIFETIME_SECS);
    let rows = fx.rows("mpp_state_reset");
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0]["discarded_generation"],
        discarded.map_or(serde_json::Value::Null, Into::into)
    );
    assert!(
        fx.open()
            .expect("discarded store")
            .read_for_test()
            .expect("snapshot")
            .records
            .is_empty()
    );
}

/// The floor includes a burned intent above the counter, so the reset
/// publishes above every generation a failed write gave out.
#[tokio::test]
#[serial_test::serial]
async fn reset_publishes_above_a_burned_intent() {
    keyring_mock::install().expect("keyring");
    let fx = Fixture::new("mpp-reset-floor-intent", STORE_VERSION, 3).await;
    write_generation(&generation_entry_ref(&fx.key_ref), 3).expect("counter");
    write_intent(&fx.intent_entry(), 6).expect("burned intent");
    let outcome = fx.reset().expect("reset");
    assert_eq!(outcome.discarded_generation, Some(3));
    assert!(!outcome.stale_carry);
    assert_eq!(fx.generation(), Some(7));
    assert_eq!(fx.intent(), Some(7));
}

/// A state key equal to the owner public key never authenticates a carry:
/// the reset discards the history and rotates the key.
#[tokio::test]
#[serial_test::serial]
async fn reset_discards_history_under_an_owner_state_key() {
    use base64::Engine as _;
    keyring_mock::install().expect("keyring");
    let fx = Fixture::new("mpp-reset-owner-key", STORE_VERSION, 1).await;
    write_generation(&generation_entry_ref(&fx.key_ref), 1).expect("anchor");
    let key = load_hmac_key_32(&fx.key_ref).expect("key");
    Fixture::put(
        &KeyringEntryRef::default_owner_key(&fx.name),
        &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(*key),
    );
    let outcome = fx.reset().expect("reset");
    assert_eq!(outcome.carried_records, 0);
    assert_eq!(outcome.carried_generation, None);
    assert_ne!(*load_hmac_key_32(&fx.key_ref).expect("rotated key"), *key);
    assert!(
        fx.open()
            .expect("fresh store")
            .read_for_test()
            .expect("snapshot")
            .records
            .is_empty()
    );
}

/// A present key with a file that does not authenticate takes the discard
/// path: the key rotates and an empty snapshot carries the watermark.
#[tokio::test]
#[serial_test::serial]
async fn reset_discards_a_file_that_does_not_authenticate() {
    keyring_mock::install().expect("keyring");
    let fx = Fixture::new("mpp-reset-tampered", STORE_VERSION, 1).await;
    write_generation(&generation_entry_ref(&fx.key_ref), 1).expect("anchor");
    let key = load_hmac_key_32(&fx.key_ref).expect("key");
    let mut tampered = fx.snapshot.clone();
    tampered[HMAC_TAG_BYTES] ^= 1;
    fs::write(&fx.path, tampered).expect("tamper");
    let outcome = fx.reset().expect("reset");
    assert_eq!(outcome.discarded_generation, Some(1));
    assert_eq!(outcome.carried_records, 0);
    assert_eq!(outcome.carried_generation, None);
    assert!(!outcome.stale_carry);
    assert_ne!(*load_hmac_key_32(&fx.key_ref).expect("rotated key"), *key);
    assert_eq!(fx.generation(), Some(2));
    assert_eq!(fx.intent(), Some(2));
    assert_eq!(fx.watermark(), NOW + MAX_CHALLENGE_LIFETIME_SECS);
    assert!(
        fx.open()
            .expect("fresh store")
            .read_for_test()
            .expect("snapshot")
            .records
            .is_empty()
    );
}

/// A keyring access error on the state key, or a state path the reset cannot
/// read as a file, refuses before the audit row and changes nothing, also
/// when the state key is missing.
#[tokio::test]
#[serial_test::serial]
async fn reset_refuses_read_errors_without_changing_state() {
    keyring_mock::install().expect("keyring");
    for fault in ["directory", "directory-without-key", "keyring"] {
        let fx = Fixture::new(&format!("mpp-reset-read-error-{fault}"), STORE_VERSION, 1).await;
        write_generation(&generation_entry_ref(&fx.key_ref), 1).expect("anchor");
        let key = load_hmac_key_32(&fx.key_ref).expect("key");
        if fault != "keyring" {
            fs::remove_file(&fx.path).expect("remove file");
            fs::create_dir(&fx.path).expect("directory at the state path");
        }
        match fault {
            "directory-without-key" => {
                keyring_core::Entry::new(&fx.key_ref.service, &fx.key_ref.account)
                    .expect("key")
                    .delete_credential()
                    .expect("remove key");
            }
            "keyring" => {
                keyring_mock::inject_no_logon_session(&fx.key_ref.service, &fx.key_ref.account)
                    .expect("access error");
            }
            _ => {}
        }
        assert_eq!(
            fx.reset().expect_err("read error").code(),
            "mpp.state_unavailable"
        );
        if fault == "directory-without-key" {
            assert!(key_is_absent(&fx.key_ref).expect("key lookup"));
        } else {
            assert_eq!(*load_hmac_key_32(&fx.key_ref).expect("key"), *key);
        }
        assert_eq!(fx.generation(), Some(1));
        assert_eq!(fx.intent(), None);
        assert!(fx.rows("mpp_state_reset").is_empty());
        if fault == "keyring" {
            assert_eq!(fs::read(&fx.path).expect("snapshot"), fx.snapshot);
        } else {
            assert!(fx.path.is_dir());
        }
    }
}

#[tokio::test]
#[serial_test::serial]
async fn reset_closes_a_ready_record() {
    keyring_mock::install().expect("keyring");
    let fx = Fixture::new("mpp-reset-ready", 1, 0).await;
    let store = fx.open().expect("adopt");
    let id = fx.records[0].authorization_id();
    store
        .mutate(|wire| {
            wire.records.truncate(1);
            Ok(())
        })
        .expect("one record");
    store.mark_ready(id, NOW + 10).expect("ready");
    write_generation(&generation_entry_ref(&fx.key_ref), 4).expect("counter-only commit");
    assert_eq!(fx.reset().expect("reset").carried_records, 1);
    assert_eq!(
        store
            .claim_ready(id, NOW + 10)
            .expect_err("closed record")
            .code(),
        "mpp.authorization_replayed"
    );
    let record = store.load(id).expect("record");
    assert_eq!(record.status(), AuthorizationStatus::ExpiredUnresolved);
    assert_eq!(record.updated_at(), NOW + 10);
}

/// An absent counter cannot bound the generations the retained key sealed,
/// so a carry refuses and names the discarding reset, which then recovers
/// the profile by initializing the counter through the guarded writes.
#[tokio::test]
#[serial_test::serial]
async fn an_absent_anchor_refuses_a_carry_and_recovers_by_discarding() {
    keyring_mock::install().expect("keyring");
    let fx = Fixture::new("mpp-reset-absent", STORE_VERSION, 3).await;
    let key = load_hmac_key_32(&fx.key_ref).expect("key");
    assert_eq!(
        fx.open().expect_err("absent anchor").message(),
        anchor_error().message()
    );
    assert_eq!(
        fx.reset().expect_err("absent anchor").message(),
        carry_anchor_error().message()
    );
    assert_eq!(fx.generation(), None);
    assert_eq!(fx.intent(), None);
    assert_eq!(fs::read(&fx.path).expect("snapshot"), fx.snapshot);
    assert_eq!(*load_hmac_key_32(&fx.key_ref).expect("key"), *key);
    assert!(fx.rows("mpp_state_reset").is_empty());
    fx.move_state_file_out();
    let outcome = fx.reset().expect("discarding reset");
    assert_eq!(outcome.discarded_generation, None);
    assert_eq!(outcome.carried_records, 0);
    assert_eq!(outcome.carried_generation, None);
    assert!(!outcome.stale_carry);
    assert_eq!(fx.generation(), Some(1));
    assert_eq!(fx.intent(), Some(1));
    assert_ne!(*load_hmac_key_32(&fx.key_ref).expect("rotated key"), *key);
    let rows = fx.rows("mpp_state_reset");
    assert_eq!(rows.len(), 1);
    assert!(rows[0]["discarded_generation"].is_null());
    assert!(
        fx.open()
            .expect("discarded store")
            .read_for_test()
            .expect("snapshot")
            .records
            .is_empty()
    );
}

/// A state key with neither a counter nor a state file holds no history the
/// reset could carry, so the reset discards without operator file moves.
#[tokio::test]
#[serial_test::serial]
async fn reset_recovers_a_state_key_without_counter_or_file() {
    keyring_mock::install().expect("keyring");
    let fx = Fixture::new("mpp-reset-keyonly", STORE_VERSION, 3).await;
    fs::remove_file(&fx.path).expect("remove state file");
    assert_eq!(
        fx.open().expect_err("absent anchor").message(),
        anchor_error().message()
    );
    let outcome = fx.reset().expect("discarding reset");
    assert_eq!(outcome.discarded_generation, None);
    assert_eq!(outcome.carried_generation, None);
    assert_eq!(fx.generation(), Some(1));
    assert_eq!(fx.intent(), Some(1));
    assert!(
        fx.open()
            .expect("discarded store")
            .read_for_test()
            .expect("snapshot")
            .records
            .is_empty()
    );
}

/// Without a state key no snapshot authenticates, so a malformed counter
/// does not block the discard. It publishes above the valid burned intent,
/// and a challenge whose marker the discard dropped refuses while it can
/// still be live.
#[tokio::test]
#[serial_test::serial]
async fn reset_discards_under_a_malformed_anchor_and_missing_state_key() {
    keyring_mock::install().expect("keyring");
    let fx = Fixture::new("mpp-reset-malformed", 1, 0).await;
    let anchor = generation_entry_ref(&fx.key_ref);
    Fixture::put(&anchor, "bad-counter");
    Fixture::put(&fx.intent_entry(), "9");
    keyring_core::Entry::new(&fx.key_ref.service, &fx.key_ref.account)
        .expect("key")
        .delete_credential()
        .expect("remove key");
    assert_eq!(
        fx.open().expect_err("invalid anchor").message(),
        anchor_error().message()
    );
    let outcome = fx.reset().expect("discarding reset");
    assert_eq!(outcome.discarded_generation, None);
    assert_eq!(outcome.carried_records, 0);
    assert_eq!(outcome.carried_generation, None);
    assert!(!outcome.stale_carry);
    assert_eq!(fx.generation(), Some(10));
    assert_eq!(fx.intent(), Some(10));
    assert_eq!(fx.watermark(), NOW + MAX_CHALLENGE_LIFETIME_SECS);
    assert!(load_hmac_key_32(&fx.key_ref).is_ok());
    let rows = fx.rows("mpp_state_reset");
    assert_eq!(rows.len(), 1);
    assert!(rows[0]["discarded_generation"].is_null());
    assert!(rows[0].get("carried_generation").is_none());
    let clean = fx.open().expect("clean state");
    assert!(
        clean
            .read_for_test()
            .expect("empty snapshot")
            .records
            .is_empty()
    );
    let lost = fx
        .record_for("https://merchant.example/recovery/0", NOW)
        .await;
    assert_eq!(
        clean
            .insert_prepared(lost, NOW)
            .expect_err("a discarded marker's challenge is refused")
            .code(),
        "mpp.challenge_expired"
    );
}

/// Every committed-counter state has a recovery at each discard boundary.
#[tokio::test]
#[serial_test::serial]
async fn discard_crash_boundaries_have_documented_recovery() {
    keyring_mock::install().expect("keyring");
    for (label, committed) in [
        ("absent", None),
        ("text", Some(b"bad".as_slice())),
        ("bytes", Some([0xff, 0xfe].as_slice())),
        ("valid", Some(b"3".as_slice())),
    ] {
        for (phase, hook, published, reserved) in [
            ("rotation", &tests::AFTER_KEY_ROTATION, false, false),
            ("publication", &tests::BEFORE_PUBLICATION, false, true),
            ("commit", &tests::AFTER_PUBLICATION, true, true),
        ] {
            let fx =
                Fixture::new(&format!("discard-crash-{label}-{phase}"), STORE_VERSION, 3).await;
            let anchor = generation_entry_ref(&fx.key_ref);
            if let Some(bytes) = committed {
                Fixture::put_bytes(&anchor, bytes);
            }
            Fixture::put(&fx.intent_entry(), "5");
            keyring_core::Entry::new(&fx.key_ref.service, &fx.key_ref.account)
                .expect("key entry")
                .delete_credential()
                .expect("absent key");
            let observed = Counter::read(&anchor).expect("observed counter");
            hook.with(|slot| *slot.borrow_mut() = Some(Box::new(|| Err(state_error()))));
            assert_eq!(
                fx.reset().expect_err("interrupted discard").message(),
                state_error().message()
            );
            assert_eq!(
                Counter::read(&anchor).expect("uncommitted counter"),
                observed
            );
            assert_eq!(fx.intent(), Some(if reserved { 6 } else { 5 }));
            assert_eq!(fx.rows("mpp_state_reset").len(), 1);
            let malformed = matches!(observed, Counter::Malformed(_));
            let expected = if published && !malformed {
                fx.open().expect("matching publication completes");
                6
            } else {
                assert_eq!(
                    fx.open().expect_err("incomplete discard refuses").message(),
                    if malformed {
                        anchor_error().message()
                    } else {
                        state_error().message()
                    }
                );
                if published {
                    let snapshot = fs::read(&fx.path).expect("publication");
                    assert_eq!(
                        fx.reset()
                            .expect_err("malformed counter refuses a carry")
                            .message(),
                        carry_anchor_error().message()
                    );
                    assert_eq!(fs::read(&fx.path).expect("publication"), snapshot);
                    assert_eq!(fx.rows("mpp_state_reset").len(), 1);
                    fx.move_state_file_out();
                } else {
                    assert_eq!(
                        fs::read(&fx.path).expect("unpublished snapshot survives"),
                        fx.snapshot
                    );
                }
                let outcome = fx.reset().expect("discard recovery");
                assert_eq!(outcome.carried_generation, None);
                assert_eq!(outcome.carried_records, 0);
                if reserved { 7 } else { 6 }
            };
            assert_eq!(fx.generation(), Some(expected), "{label} at {phase}");
            assert_eq!(fx.intent(), Some(expected), "{label} at {phase}");
            let store = fx.open().expect("recovered store opens");
            let wire = store.read_for_test().expect("recovered snapshot");
            assert!(wire.records.is_empty());
            assert_eq!(wire.pruned_through, NOW + MAX_CHALLENGE_LIFETIME_SECS);
        }
    }
}

/// Intent two beside a version 1 file refuses, and a discarding reset
/// publishes above that reservation after the operator moves the file out.
#[tokio::test]
#[serial_test::serial]
async fn a_resumed_adoption_interrupted_before_publication_requires_discard() {
    keyring_mock::install().expect("keyring");
    let fx = Fixture::new("adopt-resume-interrupted", 1, 0).await;
    Fixture::put(&fx.intent_entry(), "1");
    tests::BEFORE_PUBLICATION
        .with(|slot| *slot.borrow_mut() = Some(Box::new(|| Err(state_error()))));
    assert_eq!(
        fx.open()
            .expect_err("interrupted resumed adoption")
            .message(),
        state_error().message()
    );
    assert_eq!(fx.generation(), None);
    assert_eq!(fx.intent(), Some(2));
    assert_eq!(fs::read(&fx.path).expect("version 1 snapshot"), fx.snapshot);
    assert_eq!(
        fx.open().expect_err("ambiguous intent refuses").message(),
        anchor_error().message()
    );
    assert_eq!(
        fx.reset().expect_err("carry refuses").message(),
        carry_anchor_error().message()
    );
    assert!(fx.rows("mpp_state_reset").is_empty());
    assert_eq!(fx.rows("mpp_state_adopted").len(), 1);
    fx.move_state_file_out();
    assert_eq!(
        fx.reset().expect("discard recovery").carried_generation,
        None
    );
    assert_eq!(fx.generation(), Some(3));
    assert_eq!(fx.intent(), Some(3));
    assert!(
        fx.open()
            .expect("recovered store")
            .read_for_test()
            .expect("snapshot")
            .records
            .is_empty()
    );
}
