//! Locked, HMAC-authenticated, atomic MPP authorization persistence.

use std::{
    collections::HashSet,
    fmt,
    fs::{self, File, OpenOptions},
    io::Write as _,
    path::{Path, PathBuf},
};

use hmac::{Hmac, KeyInit as _, Mac as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use stellar_agent_core::profile::schema::canonical_data_root;
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::{
    error::{MppError, MppErrorCode},
    receipt::PaymentReceipt,
    state::{AuthorizationRecord, AuthorizationStatus, HostObservation, LedgerOutcome},
};

type HmacSha256 = Hmac<Sha256>;

const HMAC_TAG_BYTES: usize = 32;
const HMAC_DOMAIN: &[u8] = b"stellar-agent-mpp-state:v1\0";
const STORE_VERSION: u32 = 1;
const MAX_STORE_BYTES: usize = 8 * 1024 * 1024;
const MAX_ACTIVE_RECORDS: usize = 1_000;
const MAX_TOTAL_RECORDS: usize = MAX_ACTIVE_RECORDS * 2;
const TERMINAL_RETENTION_SECS: i64 = 30 * 24 * 60 * 60;

#[derive(Default, Deserialize, Serialize)]
struct WireStore {
    version: u32,
    records: Vec<AuthorizationRecord>,
}

struct StoreLock {
    _file: File,
}

/// Per-profile durable MPP authorization store.
pub struct MppAuthorizationStore {
    path: PathBuf,
    key: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for MppAuthorizationStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MppAuthorizationStore")
            .field("path", &self.path)
            .field("key", &"[redacted]")
            .finish()
    }
}

impl MppAuthorizationStore {
    /// Creates a store handle at an explicit path with an injected HMAC key.
    #[must_use]
    pub fn at_path(path: PathBuf, key: [u8; 32]) -> Self {
        Self {
            path,
            key: Zeroizing::new(key),
        }
    }

    /// Creates a store handle under the canonical wallet data root. The file
    /// name is a hash of the profile name, so hostile profile characters never
    /// become path components.
    ///
    /// # Errors
    ///
    /// Returns `mpp.state_unavailable` if the canonical data root is unavailable.
    pub fn for_profile(profile_name: &str, key: [u8; 32]) -> Result<Self, MppError> {
        let stem = hex::encode(Sha256::digest(profile_name.as_bytes()));
        let root = canonical_data_root().map_err(|_error| state_error())?;
        Ok(Self::at_path(
            root.join("mpp").join(format!("{stem}.state")),
            key,
        ))
    }

    /// Opens the canonical per-profile store using its dedicated keyring key.
    ///
    /// When `mint_if_absent` is true, a key is minted only for a genuinely new
    /// store. A missing key for an existing state file fails closed so state
    /// deletion/key rotation cannot silently reset replay protection.
    ///
    /// # Errors
    ///
    /// Returns `mpp.state_unavailable` when the keyring, data root, or existing
    /// key is unavailable.
    pub fn from_profile_keyring(
        profile_name: &str,
        mint_if_absent: bool,
    ) -> Result<Self, MppError> {
        use stellar_agent_core::profile::schema::KeyringEntryRef;
        use stellar_agent_network::keyring::{load_hmac_key_32, rotate_keyring_secret_32};

        let placeholder = Self::for_profile(profile_name, [0; 32])?;
        let entry_ref = KeyringEntryRef::default_mpp_state_key(profile_name);
        let key = match load_hmac_key_32(&entry_ref) {
            Ok(key) => key,
            Err(_) if mint_if_absent && !placeholder.path.exists() => {
                rotate_keyring_secret_32(&entry_ref.service, &entry_ref.account)
                    .map_err(|_error| state_error())?;
                load_hmac_key_32(&entry_ref).map_err(|_error| state_error())?
            }
            Err(_) => return Err(state_error()),
        };
        Ok(Self {
            path: placeholder.path,
            key,
        })
    }

    /// Inserts a newly prepared record or returns the existing identical record.
    ///
    /// # Errors
    ///
    /// Fails closed on replay, capacity, lock, integrity, parse, or I/O errors.
    pub fn insert_prepared(
        &self,
        record: AuthorizationRecord,
        now_unix: i64,
    ) -> Result<AuthorizationRecord, MppError> {
        self.mutate(|wire| {
            if let Some(existing) = wire
                .records
                .iter()
                .find(|existing| existing.fingerprint() == record.fingerprint())
            {
                if matches!(
                    existing.status(),
                    AuthorizationStatus::Prepared
                        | AuthorizationStatus::ApprovalPending
                        | AuthorizationStatus::Ready
                ) && existing.expires_at() >= now_unix
                {
                    return Ok(existing.clone());
                }
                return Err(replay_error());
            }
            let active = wire
                .records
                .iter()
                .filter(|existing| !existing.status().is_terminal())
                .count();
            if active >= MAX_ACTIVE_RECORDS {
                return Err(state_error());
            }
            if wire.records.len() >= MAX_TOTAL_RECORDS {
                return Err(state_error());
            }
            wire.records.push(record.clone());
            Ok(record)
        })
    }

    /// Loads one fully verified record.
    ///
    /// # Errors
    ///
    /// Fails closed if the store or record is unavailable.
    pub fn load(&self, authorization_id: &str) -> Result<AuthorizationRecord, MppError> {
        validate_authorization_id(authorization_id)?;
        let _lock = self.acquire_lock()?;
        let wire = self.read_verified()?;
        wire.records
            .into_iter()
            .find(|record| record.authorization_id() == authorization_id)
            .ok_or_else(state_error)
    }

    /// Loads the unique authorization attached to a pending approval nonce.
    ///
    /// # Errors
    ///
    /// Fails closed if the store is unavailable or no unique record matches.
    pub fn load_by_approval_nonce(
        &self,
        approval_nonce: &str,
    ) -> Result<AuthorizationRecord, MppError> {
        if approval_nonce.len() != 22
            || !approval_nonce
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(state_error());
        }
        let _lock = self.acquire_lock()?;
        let wire = self.read_verified()?;
        let mut matching = wire
            .records
            .into_iter()
            .filter(|record| record.approval_nonce() == Some(approval_nonce));
        let record = matching.next().ok_or_else(state_error)?;
        if matching.next().is_some() {
            return Err(state_error());
        }
        Ok(record)
    }

    /// Moves a prepared or approval-pending record to ready.
    ///
    /// # Errors
    ///
    /// Returns a replay/state error for an invalid transition.
    pub fn mark_ready(
        &self,
        authorization_id: &str,
        now_unix: i64,
    ) -> Result<AuthorizationRecord, MppError> {
        self.transition(authorization_id, AuthorizationStatus::Ready, now_unix)
    }

    /// Marks a prepared authorization as awaiting approval.
    ///
    /// # Errors
    ///
    /// Returns a replay/state error for an invalid transition.
    pub fn mark_approval_pending(
        &self,
        authorization_id: &str,
        approval_nonce: String,
        now_unix: i64,
    ) -> Result<AuthorizationRecord, MppError> {
        self.update_record(authorization_id, |record| {
            record.set_approval_nonce(approval_nonce);
            record.transition(AuthorizationStatus::ApprovalPending, now_unix)
        })
    }

    /// Atomically claims a ready record before policy accounting or key access.
    ///
    /// # Errors
    ///
    /// Returns replay/expiry/state errors when commit cannot safely proceed.
    pub fn claim_ready(
        &self,
        authorization_id: &str,
        now_unix: i64,
    ) -> Result<AuthorizationRecord, MppError> {
        self.update_record(authorization_id, |record| {
            if record.expires_at().saturating_sub(now_unix)
                < crate::limits::MIN_CHALLENGE_LIFETIME_SECS
            {
                return Err(MppError::new(
                    MppErrorCode::ChallengeExpired,
                    "challenge is expired or too close to expiry",
                ));
            }
            record.transition(AuthorizationStatus::Authorizing, now_unix)
        })
    }

    /// Records conservative policy-window accounting before signing.
    ///
    /// # Errors
    ///
    /// Fails unless the record is currently authorizing.
    pub fn mark_policy_accounted(
        &self,
        authorization_id: &str,
    ) -> Result<AuthorizationRecord, MppError> {
        self.update_record(authorization_id, |record| {
            if record.status() != AuthorizationStatus::Authorizing {
                return Err(replay_error());
            }
            record.set_policy_accounted();
            Ok(())
        })
    }

    /// Records credential construction without storing the credential.
    ///
    /// # Errors
    ///
    /// Returns a replay/state error for an invalid transition.
    pub fn mark_delivery_pending(
        &self,
        authorization_id: &str,
        credential_digest: [u8; 32],
        now_unix: i64,
    ) -> Result<AuthorizationRecord, MppError> {
        self.update_record(authorization_id, |record| {
            record.set_credential_digest(credential_digest);
            record.transition(AuthorizationStatus::DeliveryPending, now_unix)
        })
    }

    /// Marks successful delivery gates before the one-shot result return.
    ///
    /// # Errors
    ///
    /// Returns a replay/state error for an invalid transition.
    pub fn mark_authorized(
        &self,
        authorization_id: &str,
        now_unix: i64,
    ) -> Result<AuthorizationRecord, MppError> {
        self.transition(authorization_id, AuthorizationStatus::Authorized, now_unix)
    }

    /// Marks an ambiguous post-key-access failure that must never be retried.
    ///
    /// # Errors
    ///
    /// Returns a replay/state error for an invalid transition.
    pub fn mark_indeterminate(
        &self,
        authorization_id: &str,
        now_unix: i64,
    ) -> Result<AuthorizationRecord, MppError> {
        self.transition(
            authorization_id,
            AuthorizationStatus::Indeterminate,
            now_unix,
        )
    }

    /// Marks a claimed authorization as failed before signer access.
    ///
    /// # Errors
    ///
    /// Returns a replay/state error for an invalid transition.
    pub fn mark_failed(
        &self,
        authorization_id: &str,
        now_unix: i64,
    ) -> Result<AuthorizationRecord, MppError> {
        self.transition(authorization_id, AuthorizationStatus::Failed, now_unix)
    }

    /// Marks a post-credential delivery-gate failure.
    ///
    /// # Errors
    ///
    /// Returns a replay/state error for an invalid transition.
    pub fn mark_authorized_withheld(
        &self,
        authorization_id: &str,
        now_unix: i64,
    ) -> Result<AuthorizationRecord, MppError> {
        self.transition(
            authorization_id,
            AuthorizationStatus::AuthorizedWithheld,
            now_unix,
        )
    }

    /// Records a host receipt digest idempotently without claiming settlement.
    ///
    /// # Errors
    ///
    /// Returns `mpp.receipt_conflict` if a different receipt was already stored.
    pub fn record_receipt(
        &self,
        authorization_id: &str,
        receipt: &PaymentReceipt,
        now_unix: i64,
    ) -> Result<AuthorizationRecord, MppError> {
        self.update_record(authorization_id, |record| {
            if let Some(existing) = record.host_observation() {
                if existing.receipt_digest == *receipt.digest() {
                    return Ok(());
                }
                return Err(MppError::new(
                    MppErrorCode::ReceiptConflict,
                    "receipt conflicts with the recorded observation",
                ));
            }
            if record.status() != AuthorizationStatus::Authorized {
                return Err(replay_error());
            }
            let prepared = record.prepared_charge()?;
            if let Some(receipt_challenge_id) = receipt.challenge_id()
                && prepared.selected().echo().id() != Some(receipt_challenge_id)
            {
                return Err(MppError::new(
                    MppErrorCode::ReceiptConflict,
                    "receipt challenge identifier does not match the authorization",
                ));
            }
            record.set_host_observation(HostObservation {
                receipt_digest: *receipt.digest(),
                reference_digest: Sha256::digest(receipt.reference().as_bytes()).into(),
                observed_at: now_unix,
            });
            record.transition(AuthorizationStatus::ReceiptObserved, now_unix)
        })
    }

    /// Records a verified ledger outcome.
    ///
    /// # Errors
    ///
    /// Returns a conflict when a contradictory verified outcome already exists.
    pub fn record_ledger_outcome(
        &self,
        authorization_id: &str,
        outcome: LedgerOutcome,
        now_unix: i64,
    ) -> Result<AuthorizationRecord, MppError> {
        self.update_record(authorization_id, |record| {
            if !matches!(record.ledger_outcome(), LedgerOutcome::Unknown) {
                let same = matches!(
                    (record.ledger_outcome(), &outcome),
                    (
                        LedgerOutcome::Settled { ledger: left, .. },
                        LedgerOutcome::Settled { ledger: right, .. }
                    ) | (
                        LedgerOutcome::Failed { ledger: left, .. },
                        LedgerOutcome::Failed { ledger: right, .. }
                    ) if left == right
                );
                if same {
                    return Ok(());
                }
                return Err(MppError::new(
                    MppErrorCode::ReceiptConflict,
                    "ledger outcome conflicts with the recorded result",
                ));
            }
            let next = match outcome {
                LedgerOutcome::Unknown => return Ok(()),
                LedgerOutcome::Settled { .. } => AuthorizationStatus::Settled,
                LedgerOutcome::Failed { .. } => AuthorizationStatus::Failed,
            };
            record.set_ledger_outcome(outcome);
            record.transition(next, now_unix)
        })
    }

    /// Prunes only expired terminal records older than the retention window.
    /// Indeterminate records are retained for operator diagnosis.
    ///
    /// # Errors
    ///
    /// Fails closed on lock, integrity, or write errors.
    pub fn prune(&self, now_unix: i64) -> Result<usize, MppError> {
        self.mutate(|wire| {
            for record in &mut wire.records {
                if record.expires_at() <= now_unix
                    && matches!(
                        record.status(),
                        AuthorizationStatus::Prepared
                            | AuthorizationStatus::ApprovalPending
                            | AuthorizationStatus::Ready
                            | AuthorizationStatus::Authorized
                            | AuthorizationStatus::ReceiptObserved
                    )
                {
                    record.transition(AuthorizationStatus::ExpiredUnresolved, now_unix)?;
                }
            }
            let before = wire.records.len();
            wire.records.retain(|record| {
                record.status() == AuthorizationStatus::Indeterminate
                    || !record.status().is_terminal()
                    || record.expires_at().saturating_add(TERMINAL_RETENTION_SECS) >= now_unix
            });
            Ok(before.saturating_sub(wire.records.len()))
        })
    }

    fn transition(
        &self,
        authorization_id: &str,
        status: AuthorizationStatus,
        now_unix: i64,
    ) -> Result<AuthorizationRecord, MppError> {
        self.update_record(authorization_id, |record| {
            record.transition(status, now_unix)
        })
    }

    fn update_record<F>(
        &self,
        authorization_id: &str,
        update: F,
    ) -> Result<AuthorizationRecord, MppError>
    where
        F: FnOnce(&mut AuthorizationRecord) -> Result<(), MppError>,
    {
        validate_authorization_id(authorization_id)?;
        self.mutate(|wire| {
            let record = wire
                .records
                .iter_mut()
                .find(|record| record.authorization_id() == authorization_id)
                .ok_or_else(state_error)?;
            update(record)?;
            Ok(record.clone())
        })
    }

    fn mutate<T, F>(&self, update: F) -> Result<T, MppError>
    where
        F: FnOnce(&mut WireStore) -> Result<T, MppError>,
    {
        self.ensure_parent()?;
        let _lock = self.acquire_lock()?;
        let mut wire = self.read_verified()?;
        let result = update(&mut wire)?;
        self.write_atomic(&wire)?;
        Ok(result)
    }

    fn ensure_parent(&self) -> Result<(), MppError> {
        let parent = self.path.parent().ok_or_else(state_error)?;
        fs::create_dir_all(parent).map_err(|_error| state_error())?;
        reject_symlink(parent)?;
        Ok(())
    }

    fn acquire_lock(&self) -> Result<StoreLock, MppError> {
        let path = sibling_path(&self.path, ".lock");
        if path.exists() {
            reject_symlink(&path)?;
        }
        #[cfg(unix)]
        let file = {
            use std::os::unix::fs::OpenOptionsExt as _;
            OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(false)
                .mode(0o600)
                .open(path)
                .map_err(|_error| state_error())?
        };
        #[cfg(not(unix))]
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(path)
            .map_err(|_error| state_error())?;
        file.try_lock().map_err(|_error| state_error())?;
        Ok(StoreLock { _file: file })
    }

    fn read_verified(&self) -> Result<WireStore, MppError> {
        if !self.path.exists() {
            return Ok(WireStore {
                version: STORE_VERSION,
                records: Vec::new(),
            });
        }
        reject_symlink(&self.path)?;
        let metadata = fs::metadata(&self.path).map_err(|_error| state_error())?;
        if !metadata.is_file()
            || usize::try_from(metadata.len()).unwrap_or(usize::MAX) > MAX_STORE_BYTES
        {
            return Err(state_error());
        }
        let bytes = fs::read(&self.path).map_err(|_error| state_error())?;
        if bytes.len() < HMAC_TAG_BYTES {
            return Err(state_error());
        }
        let (tag, body) = bytes.split_at(HMAC_TAG_BYTES);
        let expected = compute_tag(&self.key, body)?;
        if !bool::from(tag.ct_eq(&expected)) {
            return Err(state_error());
        }
        let wire: WireStore = serde_json::from_slice(body).map_err(|_error| state_error())?;
        if wire.version != STORE_VERSION || wire.records.len() > MAX_TOTAL_RECORDS {
            return Err(state_error());
        }
        let mut authorization_ids = HashSet::with_capacity(wire.records.len());
        let mut fingerprints = HashSet::with_capacity(wire.records.len());
        let mut approval_nonces = HashSet::with_capacity(wire.records.len());
        for record in &wire.records {
            record.validate()?;
            if !authorization_ids.insert(record.authorization_id())
                || !fingerprints.insert(*record.fingerprint())
                || record
                    .approval_nonce()
                    .is_some_and(|nonce| !approval_nonces.insert(nonce))
            {
                return Err(state_error());
            }
        }
        Ok(wire)
    }

    fn write_atomic(&self, wire: &WireStore) -> Result<(), MppError> {
        let body = serde_json::to_vec(wire).map_err(|_error| state_error())?;
        if body.len() > MAX_STORE_BYTES {
            return Err(state_error());
        }
        let tag = compute_tag(&self.key, &body)?;
        let parent = self.path.parent().ok_or_else(state_error)?;
        let mut temporary =
            tempfile::NamedTempFile::new_in(parent).map_err(|_error| state_error())?;
        temporary.write_all(&tag).map_err(|_error| state_error())?;
        temporary.write_all(&body).map_err(|_error| state_error())?;
        temporary
            .as_file()
            .sync_data()
            .map_err(|_error| state_error())?;
        temporary
            .persist(&self.path)
            .map_err(|_error| state_error())?;
        #[cfg(unix)]
        if let Some(parent) = self.path.parent() {
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|_error| state_error())?;
        }
        Ok(())
    }
}

fn compute_tag(key: &[u8; 32], body: &[u8]) -> Result<[u8; 32], MppError> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_error| state_error())?;
    mac.update(HMAC_DOMAIN);
    mac.update(body);
    Ok(mac.finalize().into_bytes().into())
}

fn sibling_path(path: &Path, suffix: &str) -> PathBuf {
    let mut result = path.to_path_buf();
    let name = result
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("mpp.state");
    result.set_file_name(format!("{name}{suffix}"));
    result
}

fn reject_symlink(path: &Path) -> Result<(), MppError> {
    let metadata = fs::symlink_metadata(path).map_err(|_error| state_error())?;
    if metadata.file_type().is_symlink() {
        return Err(state_error());
    }
    Ok(())
}

fn validate_authorization_id(value: &str) -> Result<(), MppError> {
    if value.len() != 36
        || !value.starts_with("mpp_")
        || !value[4..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(state_error());
    }
    Ok(())
}

const fn state_error() -> MppError {
    MppError::new(
        MppErrorCode::StateUnavailable,
        "MPP authorization state is unavailable",
    )
}

const fn replay_error() -> MppError {
    MppError::new(
        MppErrorCode::AuthorizationReplayed,
        "MPP authorization has already been consumed",
    )
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        reason = "test fixtures use expect for concise setup"
    )]

    use super::*;
    use crate::sponsored::tests::prepared_fixture;
    use crate::{ReceiptInput, parse_receipt};
    use serde_json::Value;
    use stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE;
    use tempfile::TempDir;

    #[test]
    fn empty_store_is_lazy_until_mutation() {
        let directory = TempDir::new().expect("tempdir");
        let path = directory.path().join("state");
        let store = MppAuthorizationStore::at_path(path.clone(), [7; 32]);
        assert!(store.load("mpp_00000000000000000000000000000000").is_err());
        assert!(!path.exists());
    }

    #[test]
    fn hmac_tamper_fails_closed() {
        let directory = TempDir::new().expect("tempdir");
        let path = directory.path().join("state");
        let store = MppAuthorizationStore::at_path(path.clone(), [7; 32]);
        let wire = WireStore {
            version: STORE_VERSION,
            records: Vec::new(),
        };
        store.ensure_parent().expect("parent");
        store.write_atomic(&wire).expect("write");
        let mut bytes = fs::read(&path).expect("read");
        bytes[HMAC_TAG_BYTES] ^= 1;
        fs::write(&path, bytes).expect("tamper");
        assert!(store.read_verified().is_err());
    }

    #[test]
    fn wrong_key_fails_closed() {
        let directory = TempDir::new().expect("tempdir");
        let path = directory.path().join("state");
        let first = MppAuthorizationStore::at_path(path.clone(), [7; 32]);
        first.ensure_parent().expect("parent");
        first
            .write_atomic(&WireStore {
                version: STORE_VERSION,
                records: Vec::new(),
            })
            .expect("write");
        let second = MppAuthorizationStore::at_path(path, [8; 32]);
        assert!(second.read_verified().is_err());
    }

    #[test]
    fn truncated_authenticated_store_fails_closed() {
        let directory = TempDir::new().expect("tempdir");
        let path = directory.path().join("state");
        let store = MppAuthorizationStore::at_path(path.clone(), [7; 32]);
        store.ensure_parent().expect("parent");
        fs::write(path, [0_u8; HMAC_TAG_BYTES - 1]).expect("truncated file");
        assert!(store.read_verified().is_err());
    }

    #[test]
    fn lock_contention_fails_without_mutation() {
        let directory = TempDir::new().expect("tempdir");
        let path = directory.path().join("state");
        let store = MppAuthorizationStore::at_path(path.clone(), [7; 32]);
        store.ensure_parent().expect("parent");
        let lock = store.acquire_lock().expect("first lock");
        let contender = MppAuthorizationStore::at_path(path.clone(), [7; 32]);
        assert!(contender.acquire_lock().is_err());
        assert!(!path.exists());
        drop(lock);
        assert!(contender.acquire_lock().is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_state_file_fails_closed() {
        use std::os::unix::fs::symlink;

        let directory = TempDir::new().expect("tempdir");
        let target = directory.path().join("target");
        let path = directory.path().join("state");
        fs::write(&target, b"not state").expect("target");
        symlink(target, &path).expect("symlink");
        let store = MppAuthorizationStore::at_path(path, [7; 32]);
        assert!(store.read_verified().is_err());
    }

    #[tokio::test]
    async fn duplicate_authenticated_records_fail_closed() {
        let directory = TempDir::new().expect("tempdir");
        let path = directory.path().join("state");
        let store = MppAuthorizationStore::at_path(path, [7; 32]);
        let (prepared, _signer, _rpc) = prepared_fixture(1_700_000_000).await;
        let record =
            AuthorizationRecord::new("duplicate", TESTNET_PASSPHRASE, &prepared, 1_700_000_000)
                .expect("record");
        store.ensure_parent().expect("parent");
        store
            .write_atomic(&WireStore {
                version: STORE_VERSION,
                records: vec![record.clone(), record],
            })
            .expect("authenticated duplicate store");
        assert!(store.read_verified().is_err());
    }

    #[tokio::test]
    async fn prune_removes_only_expired_records_past_terminal_retention() {
        let directory = TempDir::new().expect("tempdir");
        let path = directory.path().join("state");
        let store = MppAuthorizationStore::at_path(path, [7; 32]);
        let now = 1_700_000_000;
        let (prepared, _signer, _rpc) = prepared_fixture(now).await;
        let mut record =
            AuthorizationRecord::new("prune", TESTNET_PASSPHRASE, &prepared, now).expect("record");
        record.allow_commit(now).expect("ready");
        let id = record.authorization_id().to_owned();
        store.insert_prepared(record, now).expect("insert");

        assert_eq!(store.prune(now + 301).expect("retain marker"), 0);
        assert_eq!(
            store.load(&id).expect("terminal marker").status(),
            AuthorizationStatus::ExpiredUnresolved
        );
        assert_eq!(
            store
                .prune(now + 301 + TERMINAL_RETENTION_SECS)
                .expect("remove old terminal marker"),
            1
        );
        assert!(store.load(&id).is_err());
    }

    #[tokio::test]
    async fn durable_transition_api_enforces_replay_receipt_and_outcome_rules() {
        let directory = TempDir::new().expect("tempdir");
        let store = MppAuthorizationStore::at_path(directory.path().join("state"), [7; 32]);
        let now = 1_700_000_000;
        let (prepared, _signer, _rpc) = prepared_fixture(now).await;
        let make_record = |profile: &str| {
            AuthorizationRecord::new(profile, TESTNET_PASSPHRASE, &prepared, now).expect("record")
        };
        let insert_ready = |profile: &str| {
            let record = make_record(profile);
            let id = record.authorization_id().to_owned();
            store.insert_prepared(record, now).expect("insert");
            store.mark_ready(&id, now + 1).expect("ready");
            id
        };
        let authorize = |id: &str| {
            store.claim_ready(id, now + 2).expect("claim");
            store.mark_policy_accounted(id).expect("account policy");
            store
                .mark_delivery_pending(id, [3; 32], now + 3)
                .expect("credential");
            store.mark_authorized(id, now + 4).expect("authorized");
        };

        let debug = format!("{store:?}");
        assert!(debug.contains("key: \"[redacted]\""));
        assert!(!debug.contains("07070707"));
        assert!(MppAuthorizationStore::for_profile("../hostile/profile", [8; 32]).is_ok());
        for invalid in ["", "mpp_short", "mpp_G0000000000000000000000000000000"] {
            assert!(store.load(invalid).is_err());
        }

        let pending = make_record("pending");
        let pending_id = pending.authorization_id().to_owned();
        assert_eq!(
            store
                .insert_prepared(pending.clone(), now)
                .expect("insert")
                .authorization_id(),
            pending_id
        );
        assert_eq!(
            store
                .insert_prepared(pending, now)
                .expect("idempotent insert")
                .authorization_id(),
            pending_id
        );
        let nonce = "approval_nonce_value12".to_owned();
        store
            .mark_approval_pending(&pending_id, nonce.clone(), now + 1)
            .expect("approval pending");
        assert_eq!(
            store
                .load_by_approval_nonce(&nonce)
                .expect("nonce lookup")
                .authorization_id(),
            pending_id
        );
        assert!(store.load_by_approval_nonce("short").is_err());
        assert!(
            store
                .load_by_approval_nonce("missing_nonce_value_12")
                .is_err()
        );
        store.mark_ready(&pending_id, now + 2).expect("approved");
        authorize(&pending_id);

        let receipt = |reference: char, challenge_id: Option<&str>| {
            let mut value = serde_json::json!({
                "method": "stellar",
                "reference": reference.to_string().repeat(64),
                "status": "success",
                "timestamp": "2026-07-16T12:00:00Z"
            });
            if let Some(challenge_id) = challenge_id {
                value["challengeId"] = Value::String(challenge_id.to_owned());
            }
            parse_receipt(&ReceiptInput::Mcp { receipt: value }).expect("receipt")
        };
        assert_eq!(
            store
                .record_receipt(&pending_id, &receipt('a', Some("wrong-challenge")), now + 5,)
                .expect_err("challenge mismatch")
                .code(),
            "mpp.receipt_conflict"
        );
        let first = receipt('a', Some("challenge-1"));
        store
            .record_receipt(&pending_id, &first, now + 5)
            .expect("receipt");
        store
            .record_receipt(&pending_id, &first, now + 6)
            .expect("idempotent receipt");
        assert_eq!(
            store
                .record_receipt(&pending_id, &receipt('b', None), now + 7)
                .expect_err("receipt conflict")
                .code(),
            "mpp.receipt_conflict"
        );
        let settled = LedgerOutcome::Settled {
            ledger: 123,
            reconciled_at: now + 8,
        };
        store
            .record_ledger_outcome(&pending_id, settled.clone(), now + 8)
            .expect("settled");
        store
            .record_ledger_outcome(&pending_id, settled, now + 9)
            .expect("idempotent outcome");
        assert_eq!(
            store
                .record_ledger_outcome(
                    &pending_id,
                    LedgerOutcome::Settled {
                        ledger: 124,
                        reconciled_at: now + 9,
                    },
                    now + 9,
                )
                .expect_err("outcome conflict")
                .code(),
            "mpp.receipt_conflict"
        );

        let failed = insert_ready("failed");
        store
            .claim_ready(&failed, now + 2)
            .expect("claim failed path");
        store
            .mark_failed(&failed, now + 3)
            .expect("pre-sign failure");
        let indeterminate = insert_ready("indeterminate");
        store
            .claim_ready(&indeterminate, now + 2)
            .expect("claim indeterminate path");
        store
            .mark_indeterminate(&indeterminate, now + 3)
            .expect("indeterminate");
        let withheld = insert_ready("withheld");
        store
            .claim_ready(&withheld, now + 2)
            .expect("claim withheld");
        store
            .mark_delivery_pending(&withheld, [4; 32], now + 3)
            .expect("delivery");
        store
            .mark_authorized_withheld(&withheld, now + 4)
            .expect("withheld");

        let ledger_failed = insert_ready("ledger-failed");
        authorize(&ledger_failed);
        assert_eq!(
            store
                .record_ledger_outcome(&ledger_failed, LedgerOutcome::Unknown, now + 5)
                .expect("unknown no-op")
                .status(),
            AuthorizationStatus::Authorized
        );
        store
            .record_ledger_outcome(
                &ledger_failed,
                LedgerOutcome::Failed {
                    ledger: 125,
                    reconciled_at: now + 6,
                },
                now + 6,
            )
            .expect("ledger failure");

        let expiring = insert_ready("expiring");
        assert_eq!(
            store
                .claim_ready(&expiring, now + 271)
                .expect_err("too close to expiry")
                .code(),
            "mpp.challenge_expired"
        );
    }
}
