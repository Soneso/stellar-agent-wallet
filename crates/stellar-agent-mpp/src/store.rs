//! Locked, HMAC-authenticated MPP persistence with a keyring generation anchor.

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
use stellar_agent_core::{
    audit_log::{AuditEntry, AuditWriterRegistry},
    profile::schema::{KeyringEntryRef, Profile, canonical_data_root},
};
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
const STORE_VERSION: u32 = 2;
const MAX_STORE_BYTES: usize = 8 * 1024 * 1024;
const MAX_ACTIVE_RECORDS: usize = 1_000;
const MAX_TOTAL_RECORDS: usize = MAX_ACTIVE_RECORDS * 2;
const TERMINAL_RETENTION_SECS: i64 = 30 * 24 * 60 * 60;

#[derive(Default, Deserialize, Serialize)]
struct WireStore {
    version: u32,
    #[serde(default)]
    generation: u64,
    records: Vec<AuthorizationRecord>,
}

struct StoreLock {
    _file: File,
}

/// Per-profile durable MPP authorization store.
pub struct MppAuthorizationStore {
    path: PathBuf,
    key: Zeroizing<[u8; 32]>,
    generation_entry: KeyringEntryRef,
    state_key_entry: Option<KeyringEntryRef>,
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
    /// Creates a store handle with an injected key and a trusted generation entry.
    ///
    /// The caller must provision the entry to `0` only for a new store and retain
    /// it across handles and process restarts. Its contents belong in the keyring,
    /// outside the filesystem containing the state snapshots.
    #[must_use]
    pub fn at_path(path: PathBuf, key: [u8; 32], generation_entry: KeyringEntryRef) -> Self {
        Self {
            path,
            key: Zeroizing::new(key),
            generation_entry,
            state_key_entry: None,
        }
    }

    /// Creates a handle under the canonical root with the profile's generation
    /// entry. The hashed profile name cannot introduce path components.
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
            generation_entry_ref(&KeyringEntryRef::default_mpp_state_key(profile_name)),
        ))
    }

    /// Opens and verifies the prepare store, provisioning a key and initial
    /// generation for a new profile under the store lock.
    ///
    /// An advanced counter survives missing state or key material. Verified
    /// version 1 history is adopted once with a mandatory audit row.
    ///
    /// # Errors
    ///
    /// Returns `mpp.state_unavailable` for inaccessible or unverifiable state,
    /// an invalid anchor, or rollback. Only a proven absent key may be minted.
    pub fn open_for_prepare(profile_name: &str, profile: &Profile) -> Result<Self, MppError> {
        let placeholder = Self::for_profile(profile_name, [0; 32])?;
        let entry_ref = KeyringEntryRef::default_mpp_state_key(profile_name);
        Self::open_for_prepare_audited_at(placeholder.path, &entry_ref, |generation| {
            emit_state_audit(
                profile,
                profile_name,
                AuditEntry::new_mpp_state_adopted(
                    profile_name,
                    generation,
                    uuid::Uuid::new_v4().to_string(),
                ),
            )
        })
    }

    fn open_for_prepare_audited_at(
        path: PathBuf,
        entry_ref: &KeyringEntryRef,
        adopt: impl FnOnce(u64) -> Result<(), MppError>,
    ) -> Result<Self, MppError> {
        use stellar_agent_network::keyring::{load_hmac_key_32, rotate_keyring_secret_32};

        let mut store = Self::at_path(path, [0; 32], generation_entry_ref(entry_ref));
        let _lock = store.acquire_lock()?;
        let generation = load_generation(&store.generation_entry)?;
        if generation.is_some_and(|value| value > 0) && provably_absent(&store.path) {
            return Err(rollback_error());
        }
        if key_is_absent(entry_ref)? {
            if !provably_absent(&store.path) || generation.is_some_and(|value| value > 0) {
                return Err(state_error());
            }
            if generation.is_none() {
                write_generation(&store.generation_entry, 0)?;
            }
            rotate_keyring_secret_32(&entry_ref.service, &entry_ref.account).map_err(|error| {
                tracing::debug!(error = %error, "mpp state key mint failed");
                state_error()
            })?;
        }
        store.key = load_hmac_key_32(entry_ref).map_err(|error| {
            tracing::debug!(error = %error, "mpp state key load failed");
            state_error()
        })?;
        store.state_key_entry = Some(entry_ref.clone());
        store.verify_or_adopt(adopt)?;
        Ok(store)
    }

    /// Opens a read handle, returning `Ok(None)` only for provably absent state
    /// and key material with no advanced generation. Keyring failures refuse.
    ///
    /// # Errors
    ///
    /// Returns `mpp.state_unavailable` for inaccessible or unverifiable state,
    /// or an invalid anchor. A missing file with an advanced anchor is rolled back.
    pub fn open_for_read(profile_name: &str, profile: &Profile) -> Result<Option<Self>, MppError> {
        let placeholder = Self::for_profile(profile_name, [0; 32])?;
        let entry_ref = KeyringEntryRef::default_mpp_state_key(profile_name);
        Self::open_for_read_audited_at(placeholder.path, &entry_ref, |generation| {
            emit_state_audit(
                profile,
                profile_name,
                AuditEntry::new_mpp_state_adopted(
                    profile_name,
                    generation,
                    uuid::Uuid::new_v4().to_string(),
                ),
            )
        })
    }

    /// Tests inject a temporary path so isolated unit runs cannot reach the
    /// operator's data root when core's home override is compiled out.
    fn open_for_read_audited_at(
        path: PathBuf,
        entry_ref: &KeyringEntryRef,
        adopt: impl FnOnce(u64) -> Result<(), MppError>,
    ) -> Result<Option<Self>, MppError> {
        use stellar_agent_network::keyring::load_hmac_key_32;

        let mut store = Self::at_path(path, [0; 32], generation_entry_ref(entry_ref));
        // The lock also serializes first-read adoption and prepare/reset.
        let _lock = store.acquire_lock()?;
        let generation = load_generation(&store.generation_entry)?;
        if generation.is_some_and(|value| value > 0) && provably_absent(&store.path) {
            return Err(rollback_error());
        }
        if key_is_absent(entry_ref)? {
            return if provably_absent(&store.path) {
                Ok(None)
            } else {
                Err(state_error())
            };
        }
        store.key = load_hmac_key_32(entry_ref).map_err(|_error| state_error())?;
        store.state_key_entry = Some(entry_ref.clone());
        store.verify_or_adopt(adopt)?;
        Ok(Some(store))
    }

    #[cfg(test)]
    fn open_for_read_at(
        path: PathBuf,
        entry_ref: &KeyringEntryRef,
    ) -> Result<Option<Self>, MppError> {
        Self::open_for_read_audited_at(path, entry_ref, |_| Err(anchor_error()))
    }

    #[cfg(test)]
    fn open_for_prepare_at(path: PathBuf, entry_ref: &KeyringEntryRef) -> Result<Self, MppError> {
        Self::open_for_prepare_audited_at(path, entry_ref, |_| Err(anchor_error()))
    }

    fn verify_or_adopt(
        &self,
        audit: impl FnOnce(u64) -> Result<(), MppError>,
    ) -> Result<(), MppError> {
        if load_generation(&self.generation_entry)?.is_some() {
            return self.read_verified().map(|_| ());
        }
        if provably_absent(&self.path) {
            return Err(anchor_error());
        }
        let mut wire = self.read_authenticated()?;
        // Every version 2 snapshot is published after its counter, so one with
        // an absent counter proves the anchor was removed and is not adopted.
        if wire.version != 1 {
            return Err(anchor_error());
        }
        // The initial zero counter means no file has been committed. A version
        // 1 snapshot therefore enters the protected format at generation one.
        wire.version = STORE_VERSION;
        wire.generation = 1;
        audit(wire.generation)?;
        self.write_atomic(&wire)
    }

    /// Discards MPP replay history after an operator acknowledgement at the
    /// caller. The reset request is audited under the store lock before mutation.
    /// A fresh HMAC key prevents snapshots from the discarded history matching
    /// generations reused by a clean store.
    ///
    /// # Errors
    ///
    /// Refuses on lock, audit, keyring access, or filesystem errors. A failed
    /// reset can be retried with the same explicit acknowledgement.
    pub fn reset_for_profile(
        profile_name: &str,
        profile: &Profile,
        reason: &str,
    ) -> Result<Option<u64>, MppError> {
        let placeholder = Self::for_profile(profile_name, [0; 32])?;
        let key_ref = KeyringEntryRef::default_mpp_state_key(profile_name);
        Self::reset_at(placeholder.path, &key_ref, |generation| {
            emit_state_audit(
                profile,
                profile_name,
                AuditEntry::new_mpp_state_reset(
                    profile_name,
                    generation,
                    reason,
                    uuid::Uuid::new_v4().to_string(),
                ),
            )
        })
    }

    fn reset_at(
        path: PathBuf,
        key_ref: &KeyringEntryRef,
        audit: impl FnOnce(Option<u64>) -> Result<(), MppError>,
    ) -> Result<Option<u64>, MppError> {
        let store = Self::at_path(path, [0; 32], generation_entry_ref(key_ref));
        let _lock = store.acquire_lock()?;
        let discarded =
            load_generation_value(&store.generation_entry)?.and_then(|value| value.parse().ok());
        audit(discarded)?;
        stellar_agent_network::keyring::rotate_keyring_secret_32(
            &key_ref.service,
            &key_ref.account,
        )
        .map_err(|_error| state_error())?;
        match fs::remove_file(&store.path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(state_error()),
        }
        #[cfg(unix)]
        File::open(store.path.parent().ok_or_else(state_error)?)
            .and_then(|parent| parent.sync_all())
            .map_err(|_error| state_error())?;
        write_generation(&store.generation_entry, 0)?;
        Ok(discarded)
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
    /// Returns `mpp.authorization_not_found` when the store holds no record
    /// under `authorization_id`. Fails closed with `mpp.state_unavailable` for
    /// a malformed identifier or a store that cannot be read and verified.
    pub fn load(&self, authorization_id: &str) -> Result<AuthorizationRecord, MppError> {
        validate_authorization_id(authorization_id)?;
        let _lock = self.acquire_lock()?;
        let wire = self.read_verified()?;
        wire.records
            .into_iter()
            .find(|record| record.authorization_id() == authorization_id)
            .ok_or_else(MppError::authorization_not_found)
    }

    /// Loads the unique authorization attached to a pending approval nonce.
    ///
    /// # Errors
    ///
    /// Returns `mpp.authorization_not_found` when no record carries the nonce.
    /// Fails closed with `mpp.state_unavailable` for a malformed nonce, a store
    /// that cannot be read and verified, or a nonce carried by more than one
    /// record.
    pub fn load_by_approval_nonce(
        &self,
        approval_nonce: &str,
    ) -> Result<AuthorizationRecord, MppError> {
        validate_approval_nonce(approval_nonce)?;
        let _lock = self.acquire_lock()?;
        let wire = self.read_verified()?;
        let mut matching = wire
            .records
            .into_iter()
            .filter(|record| record.approval_nonce() == Some(approval_nonce));
        let record = matching
            .next()
            .ok_or_else(MppError::authorization_not_found)?;
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
        self.update_record(authorization_id, state_error, |record| {
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
        self.update_record(authorization_id, state_error, |record| {
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
        self.update_record(authorization_id, state_error, |record| {
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
        self.update_record(authorization_id, state_error, |record| {
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

    /// Settles a policy refusal that wrote no window usage and constructed no credential.
    ///
    /// # Errors
    ///
    /// Refuses invalid transitions or unavailable durable state.
    pub fn mark_refused(
        &self,
        authorization_id: &str,
        now_unix: i64,
    ) -> Result<AuthorizationRecord, MppError> {
        self.transition(authorization_id, AuthorizationStatus::Refused, now_unix)
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
    /// Returns `mpp.receipt_conflict` if a different receipt was already stored,
    /// and `mpp.authorization_not_found` when the store holds no record under
    /// `authorization_id` — the same answer [`Self::load`] gives, because this
    /// is the one mutating entry point whose identifier comes straight from the
    /// caller rather than from a record this store just loaded.
    pub fn record_receipt(
        &self,
        authorization_id: &str,
        receipt: &PaymentReceipt,
        now_unix: i64,
    ) -> Result<AuthorizationRecord, MppError> {
        self.update_record(
            authorization_id,
            MppError::authorization_not_found,
            |record| {
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
            },
        )
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
        self.update_record(authorization_id, state_error, |record| {
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
        self.update_record(authorization_id, state_error, |record| {
            record.transition(status, now_unix)
        })
    }

    /// Applies `update` to the record under `authorization_id`, refusing with
    /// `on_missing` when the store holds no such record.
    ///
    /// The refusal is a parameter because the two caller families mean
    /// different things by a missing record. A caller acting on an identifier
    /// its user supplied — [`Self::record_receipt`] — is answering a lookup,
    /// and must answer it the same way every other lookup does. The internal
    /// lifecycle transitions loaded the record under this same lock moments
    /// earlier, so a record missing there is corruption, not a caller mistake,
    /// and stays `mpp.state_unavailable`.
    fn update_record<F>(
        &self,
        authorization_id: &str,
        on_missing: fn() -> MppError,
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
                .ok_or_else(on_missing)?;
            update(record)?;
            Ok(record.clone())
        })
    }

    fn mutate<T, F>(&self, update: F) -> Result<T, MppError>
    where
        F: FnOnce(&mut WireStore) -> Result<T, MppError>,
    {
        // The store directory is established by lock acquisition, which every
        // path — read and write — goes through first.
        let _lock = self.acquire_lock()?;
        let mut wire = self.read_verified()?;
        let result = update(&mut wire)?;
        wire.generation = wire.generation.checked_add(1).ok_or_else(state_error)?;
        self.write_atomic(&wire)?;
        Ok(result)
    }

    /// Establishes the store directory, refusing anything at that path that is
    /// not already a real directory.
    ///
    /// The inspection precedes the creation so the refusal is stated here
    /// rather than inherited from `create_dir_all` reporting `EEXIST` for a
    /// path that is a symlink or a regular file. Every read verb reaches this
    /// function, so what it refuses and why should not depend on a platform's
    /// `mkdir` semantics.
    fn ensure_parent(&self) -> Result<(), MppError> {
        let parent = self.path.parent().ok_or_else(state_error)?;
        match fs::symlink_metadata(parent) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(state_error());
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir_all(parent).map_err(|_error| state_error())?;
                reject_symlink(parent)?;
            }
            Err(_error) => return Err(state_error()),
        }
        Ok(())
    }

    /// Takes the exclusive store lock, establishing the store directory first.
    ///
    /// Reads lock too, so the directory has to exist on a read as well: a key
    /// is minted before the first record is written, and a prepare that is
    /// denied after minting leaves exactly that state. Refusing a read there
    /// would report a profile with nothing stored as a store that cannot be
    /// used, which is the distinction this store owes its callers.
    fn acquire_lock(&self) -> Result<StoreLock, MppError> {
        self.ensure_parent()?;
        let path = sibling_path(&self.path, ".lock");
        // Anything but a proven absence is inspected before the open: `create`
        // follows a symlink at the lock path and would otherwise create and
        // lock the file it points at.
        if !provably_absent(&path) {
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
        if let Some(key_ref) = &self.state_key_entry {
            let current = stellar_agent_network::keyring::load_hmac_key_32(key_ref)
                .map_err(|_error| state_error())?;
            if !bool::from(self.key.as_slice().ct_eq(current.as_slice())) {
                return Err(rollback_error());
            }
        }
        // Only a proven absence reads as an empty store. Any other outcome —
        // a dangling symlink at the state path included — falls through to the
        // symlink and metadata checks and fails closed there.
        if provably_absent(&self.path) {
            return match load_generation(&self.generation_entry)? {
                Some(0) => Ok(WireStore {
                    version: STORE_VERSION,
                    generation: 0,
                    records: Vec::new(),
                }),
                Some(_) => Err(rollback_error()),
                None => Err(anchor_error()),
            };
        }
        let wire = self.read_authenticated()?;
        let generation = load_generation(&self.generation_entry)?.ok_or_else(anchor_error)?;
        if wire.version != STORE_VERSION || wire.generation != generation || generation == 0 {
            return Err(rollback_error());
        }
        Ok(wire)
    }

    fn read_authenticated(&self) -> Result<WireStore, MppError> {
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
        if !matches!(
            (wire.version, wire.generation),
            (1, 0) | (STORE_VERSION, 1..)
        ) || wire.records.len() > MAX_TOTAL_RECORDS
        {
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
        // Advance before publishing any authenticated snapshot, including a temp
        // file. An interrupted write leaves a gap that refuses; its generation
        // can never be reused for a different snapshot.
        write_generation(&self.generation_entry, wire.generation)?;
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

fn emit_state_audit(
    profile: &Profile,
    profile_name: &str,
    entry: AuditEntry,
) -> Result<(), MppError> {
    let unavailable = || {
        MppError::new(
            MppErrorCode::StateUnavailable,
            "MPP authorization state audit is unavailable",
        )
    };
    let access =
        stellar_agent_network::keyring::keyed_audit_access(profile).map_err(|_| unavailable())?;
    let writer =
        AuditWriterRegistry::get_or_open_keyed(profile_name, &profile.audit_log_path, access)
            .map_err(|_| unavailable())?;
    writer
        .lock()
        .map_err(|_| unavailable())?
        .write_entry(entry)
        .map_err(|_| unavailable())
}

/// The counter shares the state key's service and uses a distinct account.
fn generation_entry_ref(key: &KeyringEntryRef) -> KeyringEntryRef {
    KeyringEntryRef::new(key.service.clone(), format!("{}-generation", key.account))
}

fn load_generation(entry_ref: &KeyringEntryRef) -> Result<Option<u64>, MppError> {
    load_generation_value(entry_ref)?
        .map(|value| value.parse().map_err(|_| anchor_error()))
        .transpose()
}

fn load_generation_value(entry_ref: &KeyringEntryRef) -> Result<Option<String>, MppError> {
    let entry = keyring_core::Entry::new(&entry_ref.service, &entry_ref.account)
        .map_err(|_error| state_error())?;
    match entry.get_password() {
        Ok(value) => Ok(Some(value)),
        Err(keyring_core::Error::NoEntry) => Ok(None),
        Err(_error) => Err(state_error()),
    }
}

fn write_generation(entry_ref: &KeyringEntryRef, generation: u64) -> Result<(), MppError> {
    keyring_core::Entry::new(&entry_ref.service, &entry_ref.account)
        .and_then(|entry| entry.set_password(&generation.to_string()))
        .map_err(|_error| state_error())
}

fn key_is_absent(entry_ref: &KeyringEntryRef) -> Result<bool, MppError> {
    let entry = keyring_core::Entry::new(&entry_ref.service, &entry_ref.account)
        .map_err(|_error| state_error())?;
    match entry.get_password().map(Zeroizing::new) {
        Ok(_) => Ok(false),
        Err(keyring_core::Error::NoEntry) => Ok(true),
        Err(_error) => Err(state_error()),
    }
}

const fn rollback_error() -> MppError {
    MppError::new(
        MppErrorCode::StateUnavailable,
        "MPP authorization state is rolled back; recover with stellar-agent profile reset-mpp-state <NAME> --acknowledge --reason <REASON>",
    )
}

const fn anchor_error() -> MppError {
    MppError::new(
        MppErrorCode::StateUnavailable,
        "MPP authorization state generation anchor is missing or invalid; recover with stellar-agent profile reset-mpp-state <NAME> --acknowledge --reason <REASON>",
    )
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

/// Whether `path` provably holds nothing.
///
/// True only when the path lookup itself reports `NotFound`. A dangling
/// symlink, a permission failure, or any other I/O error is not proof of
/// absence, so every caller treats it as present: reads refuse rather than
/// report first run or an empty store, and the prepare path refuses to mint a
/// second key over state it cannot see.
fn provably_absent(path: &Path) -> bool {
    matches!(
        fs::symlink_metadata(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    )
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

fn validate_approval_nonce(value: &str) -> Result<(), MppError> {
    if value.len() != 22
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(state_error());
    }
    Ok(())
}

/// Classifies an authorization-identifier lookup against a profile that has no
/// MPP state, for the adapters that must answer without a store handle.
///
/// The identifier is validated first, so a malformed one is refused with the
/// same code it would get from a store that exists. Answering
/// `mpp.authorization_not_found` for input a real store refuses with
/// `mpp.state_unavailable` would turn the refusal into a probe for whether the
/// profile has ever minted MPP state.
#[must_use]
pub fn absent_state_lookup_error(authorization_id: &str) -> MppError {
    validate_authorization_id(authorization_id)
        .err()
        .unwrap_or_else(MppError::authorization_not_found)
}

/// The approval-nonce counterpart of [`absent_state_lookup_error`].
#[must_use]
pub fn absent_state_approval_lookup_error(approval_nonce: &str) -> MppError {
    validate_approval_nonce(approval_nonce)
        .err()
        .unwrap_or_else(MppError::authorization_not_found)
}

/// The uniform state refusal.
///
/// The message stays generic because the code is raised well beyond the store:
/// oversize or non-regular input files, an unusable clock, approval-store
/// failures, capacity ceilings, and malformed identifiers all reach it. The
/// same two lines are defined in `stellar-agent-cli`'s and `stellar-agent-mcp`'s
/// MPP adapters, where the code is raised without a store handle in hand; the
/// three definitions MUST stay byte-identical so one refusal cannot be told
/// from another by its text.
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

/// Store tests.
///
/// # Keyring serialisation
///
/// Every test that installs the mock keyring store mutates process-global
/// state, so all of them are `#[serial_test::serial]`: two running
/// concurrently would decide each other's quadrant by replacing the store
/// mid-test.
///
/// # Why the quadrant tests drive the seam
///
/// They call [`MppAuthorizationStore::open_for_read_at`] with a `TempDir`
/// path rather than [`MppAuthorizationStore::open_for_read`]. Under
/// `cargo test -p stellar-agent-mpp --lib store::tests::` — which is exactly
/// how the `windows-storage` CI job runs them — `stellar-agent-core` is built
/// as a plain dependency, so `canonical_data_root`'s `STELLAR_AGENT_HOME`
/// override is compiled out and the public entry point would read and write
/// the operator's real data root. No feature unification in that invocation
/// changes it.
#[cfg(test)]
pub(crate) mod tests {
    #![allow(
        clippy::expect_used,
        reason = "test fixtures use expect for concise setup"
    )]

    use super::*;
    use crate::sponsored::tests::prepared_fixture;
    use crate::{ReceiptInput, parse_receipt};
    use serde_json::Value;
    use stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE;
    use stellar_agent_core::profile::schema::KeyringEntryRef;
    use stellar_agent_network::keyring::{load_hmac_key_32, rotate_keyring_secret_32};
    use tempfile::TempDir;

    pub(crate) fn test_store(path: PathBuf, key: [u8; 32]) -> MppAuthorizationStore {
        let entry = KeyringEntryRef::new(
            format!(
                "mpp-test-{}",
                hex::encode(Sha256::digest(path.as_os_str().as_encoded_bytes()))
            ),
            "generation",
        );
        if load_generation(&entry)
            .expect("read fixture anchor")
            .is_none()
        {
            write_generation(&entry, 0).expect("initialize fixture anchor");
        }
        MppAuthorizationStore::at_path(path, key, entry)
    }

    /// A well-formed identifier no store in this suite holds.
    const UNKNOWN_ID: &str = "mpp_00000000000000000000000000000000";

    const NOT_FOUND_CODE: &str = "mpp.authorization_not_found";
    const STATE_CODE: &str = "mpp.state_unavailable";

    fn state_key_coordinates(profile_name: &str) -> KeyringEntryRef {
        KeyringEntryRef::default_mpp_state_key(profile_name)
    }

    /// A malformed identifier classifies the same way with and without a store.
    ///
    /// The adapters answer an identifier lookup on a profile with no MPP state
    /// without ever constructing a store, so they must apply the same input
    /// validation the store applies. If they did not, a caller could learn
    /// whether a profile has ever minted MPP state by sending one malformed
    /// identifier and reading which code came back.
    #[test]
    #[serial_test::serial]
    fn a_malformed_identifier_classifies_identically_with_and_without_a_store() {
        stellar_agent_test_support::keyring_mock::install().expect("mock keyring store");
        let directory = TempDir::new().expect("tempdir");
        let store = test_store(directory.path().join("state"), [7; 32]);

        for malformed in ["", "mpp_short", "mpp_G0000000000000000000000000000000"] {
            assert_eq!(
                absent_state_lookup_error(malformed).code(),
                store
                    .load(malformed)
                    .expect_err("a malformed identifier is refused")
                    .code(),
                "the storeless answer for {malformed:?} must match the store's"
            );
            assert_eq!(absent_state_lookup_error(malformed).code(), STATE_CODE);
        }
        for malformed in [
            "",
            "short",
            "way_too_long_approval_nonce",
            "bad nonce value 12345!",
        ] {
            assert_eq!(
                absent_state_approval_lookup_error(malformed).code(),
                store
                    .load_by_approval_nonce(malformed)
                    .expect_err("a malformed nonce is refused")
                    .code(),
                "the storeless answer for {malformed:?} must match the store's"
            );
            assert_eq!(
                absent_state_approval_lookup_error(malformed).code(),
                STATE_CODE
            );
        }

        assert_eq!(absent_state_lookup_error(UNKNOWN_ID).code(), NOT_FOUND_CODE);
        assert_eq!(
            absent_state_approval_lookup_error("approval_nonce_value12").code(),
            NOT_FOUND_CODE
        );
    }

    /// No key and no file is the profile's first run, not a failure: the read
    /// surface answers `Ok(None)` and leaves the path untouched.
    #[test]
    #[serial_test::serial]
    fn open_for_read_reports_first_run_when_neither_key_nor_file_exists() {
        stellar_agent_test_support::keyring_mock::install().expect("mock keyring store");
        let directory = TempDir::new().expect("tempdir");
        let path = directory.path().join("state");
        let entry_ref = state_key_coordinates("mpp-quadrant-first-run");

        let opened = MppAuthorizationStore::open_for_read_at(path.clone(), &entry_ref)
            .expect("a never-minted profile is not a state failure");

        assert!(opened.is_none(), "no key and no file is first run");
        assert!(!path.exists(), "a read must not create the state file");
    }

    /// A state file whose key does not load fails closed, and does so for EVERY
    /// cause a failed key load can have.
    ///
    /// The read surface distinguishes exactly one thing: the provable
    /// never-minted state, no key AND no file. Once a file exists, an absent
    /// key and an environmental keyring failure are indistinguishable — both
    /// are `mpp.state_unavailable` — so deleting the key, rotating it, or
    /// running without an interactive keyring session can never be answered as
    /// "nothing was ever here" and reset replay protection.
    #[test]
    #[serial_test::serial]
    fn open_for_read_fails_closed_when_a_state_file_exists_without_its_key() {
        stellar_agent_test_support::keyring_mock::install().expect("mock keyring store");
        let directory = TempDir::new().expect("tempdir");
        let path = directory.path().join("state");
        fs::write(&path, [0_u8; HMAC_TAG_BYTES]).expect("fabricate a state file");
        let entry_ref = state_key_coordinates("mpp-quadrant-orphan-file");

        let absent_key = MppAuthorizationStore::open_for_read_at(path.clone(), &entry_ref)
            .expect_err("a state file without its key must refuse");
        assert_eq!(absent_key.code(), "mpp.state_unavailable");

        stellar_agent_test_support::keyring_mock::inject_no_logon_session(
            &entry_ref.service,
            &entry_ref.account,
        )
        .expect("inject the no-logon-session failure at the state-key coordinates");
        let environmental = MppAuthorizationStore::open_for_read_at(path, &entry_ref)
            .expect_err("an environmental keyring failure must refuse");
        assert_eq!(
            environmental.code(),
            absent_key.code(),
            "an environmental failure must not be distinguishable from an absent key"
        );
    }

    /// A minted key and initial counter with no file is the legitimate
    /// post-mint, pre-first-write state. A prepare denied after minting leaves
    /// this state, so reading must remain empty and a first prepare must work.
    #[tokio::test]
    #[serial_test::serial]
    async fn open_for_read_opens_a_minted_store_before_its_first_write() {
        stellar_agent_test_support::keyring_mock::install().expect("mock keyring store");
        let directory = TempDir::new().expect("tempdir");
        let path = directory.path().join("mpp").join("state");
        let entry_ref = state_key_coordinates("mpp-quadrant-minted-no-file");
        MppAuthorizationStore::open_for_prepare_at(path.clone(), &entry_ref)
            .expect("mint key and initial counter");
        fs::remove_dir_all(path.parent().expect("store directory"))
            .expect("remove empty store directory");

        let store = MppAuthorizationStore::open_for_read_at(path.clone(), &entry_ref)
            .expect("a minted key opens the store")
            .expect("a minted key is not first run");

        assert_eq!(
            store
                .load(UNKNOWN_ID)
                .expect_err("an empty store holds no record")
                .code(),
            "mpp.authorization_not_found",
            "a store whose first record was never written holds no authorization; \
             it is not a store that cannot be used"
        );
        assert!(!path.exists(), "a read must not create the state file");
        assert_eq!(
            load_generation(&generation_entry_ref(&entry_ref)).expect("test value"),
            Some(0)
        );
        let reopened =
            MppAuthorizationStore::open_for_prepare_at(path, &entry_ref).expect("first prepare");
        let now = 1_700_000_000;
        let (prepared, _signer, _rpc) = prepared_fixture(now).await;
        let record = AuthorizationRecord::new("first", TESTNET_PASSPHRASE, &prepared, now)
            .expect("test value");
        let id = record.authorization_id().to_owned();
        reopened.insert_prepared(record, now).expect("first record");
        assert_eq!(
            reopened.load(&id).expect("test value").authorization_id(),
            id
        );
        let bytes = fs::read(&reopened.path).expect("test value");
        let body: serde_json::Value =
            serde_json::from_slice(&bytes[HMAC_TAG_BYTES..]).expect("test value");
        assert_eq!(body["version"], 2);
        assert_eq!(body["generation"], 1);
        assert_eq!(
            load_generation(&generation_entry_ref(&entry_ref)).expect("test value"),
            Some(1)
        );
    }

    /// The keyring counter preserves history when filesystem state disappears.
    #[tokio::test]
    #[serial_test::serial]
    async fn anti_rollback_deleted_state_refuses_on_existing_and_reopened_handles() {
        stellar_agent_test_support::keyring_mock::install().expect("mock keyring store");
        let directory = TempDir::new().expect("test value");
        let path = directory.path().join("state");
        let key_ref = state_key_coordinates("deleted-state");
        let store =
            MppAuthorizationStore::open_for_prepare_at(path.clone(), &key_ref).expect("test value");
        let now = 1_700_000_000;
        let (prepared, _signer, _rpc) = prepared_fixture(now).await;
        let record = AuthorizationRecord::new("delete", TESTNET_PASSPHRASE, &prepared, now)
            .expect("test value");
        let id = record.authorization_id().to_owned();
        store.insert_prepared(record, now).expect("test value");
        fs::remove_file(&path).expect("test value");
        for error in [
            store.load(&id).expect_err("refusal"),
            store.prune(now).expect_err("refusal"),
            MppAuthorizationStore::open_for_read_at(path.clone(), &key_ref).expect_err("refusal"),
            MppAuthorizationStore::open_for_prepare_at(path.clone(), &key_ref)
                .expect_err("refusal"),
        ] {
            assert_eq!(error.code(), STATE_CODE);
            assert!(error.message().contains("state is rolled back"));
        }
        keyring_core::Entry::new(&key_ref.service, &key_ref.account)
            .expect("test value")
            .delete_credential()
            .expect("test value");
        assert!(
            MppAuthorizationStore::open_for_read_at(path.clone(), &key_ref)
                .expect_err("refusal")
                .message()
                .contains("rolled back")
        );
        assert!(
            MppAuthorizationStore::open_for_prepare_at(path.clone(), &key_ref)
                .expect_err("refusal")
                .message()
                .contains("rolled back")
        );
        assert!(!path.exists());
        assert_eq!(
            load_generation(&generation_entry_ref(&key_ref)).expect("test value"),
            Some(1)
        );
    }

    /// An authentic older snapshot cannot replace the committed generation.
    #[tokio::test]
    #[serial_test::serial]
    async fn anti_rollback_restored_snapshot_refuses_reads_and_mutations() {
        stellar_agent_test_support::keyring_mock::install().expect("mock keyring store");
        let directory = TempDir::new().expect("test value");
        let path = directory.path().join("state");
        let key_ref = state_key_coordinates("restored-state");
        let store =
            MppAuthorizationStore::open_for_prepare_at(path.clone(), &key_ref).expect("test value");
        let now = 1_700_000_000;
        let (prepared, _signer, _rpc) = prepared_fixture(now).await;
        let first = AuthorizationRecord::new("first", TESTNET_PASSPHRASE, &prepared, now)
            .expect("test value");
        let id = first.authorization_id().to_owned();
        store.insert_prepared(first, now).expect("test value");
        let old = fs::read(&path).expect("test value");
        let second = AuthorizationRecord::new("second", TESTNET_PASSPHRASE, &prepared, now)
            .expect("test value");
        store.insert_prepared(second, now).expect("test value");
        assert_eq!(
            load_generation(&generation_entry_ref(&key_ref)).expect("test value"),
            Some(2)
        );
        fs::write(&path, &old).expect("test value");
        assert!(MppAuthorizationStore::open_for_read_at(path.clone(), &key_ref).is_err());
        for error in [
            store.load(&id).expect_err("refusal"),
            store.prune(now).expect_err("refusal"),
            MppAuthorizationStore::open_for_prepare_at(path.clone(), &key_ref)
                .expect_err("refusal"),
        ] {
            assert_eq!(error.code(), STATE_CODE);
            assert!(error.message().contains("state is rolled back"));
        }
        assert_eq!(fs::read(&path).expect("test value"), old);
        assert_eq!(
            load_generation(&generation_entry_ref(&key_ref)).expect("test value"),
            Some(2)
        );
    }

    /// An anchor failure cannot publish a new authenticated snapshot.
    #[test]
    #[serial_test::serial]
    fn anti_rollback_anchor_write_failure_leaves_no_snapshot() {
        stellar_agent_test_support::keyring_mock::install().expect("mock keyring store");
        let directory = TempDir::new().expect("test value");
        let path = directory.path().join("state");
        let store = test_store(path.clone(), [7; 32]);
        store.ensure_parent().expect("test value");
        stellar_agent_test_support::keyring_mock::inject_no_logon_session(
            &store.generation_entry.service,
            &store.generation_entry.account,
        )
        .expect("test value");
        let wire = WireStore {
            version: STORE_VERSION,
            generation: 1,
            records: Vec::new(),
        };
        assert_eq!(
            store.write_atomic(&wire).expect_err("refusal").code(),
            STATE_CODE
        );
        assert!(!path.exists());
        assert_eq!(
            load_generation(&store.generation_entry).expect("test value"),
            Some(0)
        );
    }

    /// A failed filesystem commit consumes its generation before any snapshot
    /// is published, so an abandoned temporary file cannot reuse a generation.
    #[test]
    #[serial_test::serial]
    fn anti_rollback_failed_file_commit_retains_the_advanced_anchor() {
        stellar_agent_test_support::keyring_mock::install().expect("mock keyring store");
        let directory = TempDir::new().expect("test value");
        let path = directory.path().join("state");
        let store = test_store(path.clone(), [7; 32]);
        store
            .mutate(|_wire| {
                fs::create_dir(&path).expect("test value");
                Ok(())
            })
            .expect_err("a directory blocks the atomic file replacement");
        assert_eq!(
            load_generation(&store.generation_entry).expect("test value"),
            Some(1)
        );
        fs::remove_dir(&path).expect("test value");
        assert!(
            store
                .load(UNKNOWN_ID)
                .expect_err("refusal")
                .message()
                .contains("rolled back")
        );
    }

    /// A missing, malformed, or inaccessible anchor never reads as empty state.
    #[test]
    #[serial_test::serial]
    fn anti_rollback_untrusted_anchor_refuses_without_reinitialization() {
        stellar_agent_test_support::keyring_mock::install().expect("mock keyring store");
        let directory = TempDir::new().expect("test value");
        let path = directory.path().join("state");
        let key_ref = state_key_coordinates("untrusted-anchor");
        let store =
            MppAuthorizationStore::open_for_prepare_at(path.clone(), &key_ref).expect("test value");
        let anchor = keyring_core::Entry::new(
            &store.generation_entry.service,
            &store.generation_entry.account,
        )
        .expect("test value");
        anchor.delete_credential().expect("test value");
        assert!(
            store
                .load(UNKNOWN_ID)
                .expect_err("refusal")
                .message()
                .contains("anchor is missing")
        );
        assert!(
            MppAuthorizationStore::open_for_read_at(path.clone(), &key_ref)
                .expect_err("refusal")
                .message()
                .contains("anchor is missing")
        );
        assert!(
            MppAuthorizationStore::open_for_prepare_at(path.clone(), &key_ref)
                .expect_err("refusal")
                .message()
                .contains("anchor is missing")
        );
        assert!(matches!(
            anchor.get_password(),
            Err(keyring_core::Error::NoEntry)
        ));
        anchor.set_password("invalid").expect("test value");
        assert_eq!(
            store.load(UNKNOWN_ID).expect_err("refusal").code(),
            STATE_CODE
        );
        assert_eq!(
            MppAuthorizationStore::open_for_prepare_at(path.clone(), &key_ref)
                .expect_err("refusal")
                .code(),
            STATE_CODE
        );
        assert_eq!(anchor.get_password().expect("test value"), "invalid");
        anchor.set_password("0").expect("test value");
        stellar_agent_test_support::keyring_mock::inject_no_logon_session(
            &store.generation_entry.service,
            &store.generation_entry.account,
        )
        .expect("test value");
        assert_eq!(
            store.load(UNKNOWN_ID).expect_err("refusal").code(),
            STATE_CODE
        );
        assert!(!path.exists());
        anchor.delete_credential().expect("remove fixture anchor");
    }

    /// Generation exhaustion refuses without wrapping or changing the snapshot.
    #[test]
    #[serial_test::serial]
    fn anti_rollback_generation_overflow_refuses_without_writing() {
        stellar_agent_test_support::keyring_mock::install().expect("mock keyring store");
        let directory = TempDir::new().expect("test value");
        let path = directory.path().join("state");
        let store = test_store(path.clone(), [7; 32]);
        store.ensure_parent().expect("test value");
        store
            .write_atomic(&WireStore {
                version: STORE_VERSION,
                generation: u64::MAX,
                records: Vec::new(),
            })
            .expect("test value");
        let snapshot = fs::read(&path).expect("test value");
        assert_eq!(
            store.prune(1_700_000_000).expect_err("refusal").code(),
            STATE_CODE
        );
        assert_eq!(
            load_generation(&store.generation_entry).expect("test value"),
            Some(u64::MAX)
        );
        assert_eq!(fs::read(path).expect("test value"), snapshot);
    }

    /// Keyring outages do not prove absence and cannot authorize key minting.
    #[test]
    #[serial_test::serial]
    fn anti_rollback_initialization_refuses_keyring_access_errors() {
        stellar_agent_test_support::keyring_mock::install().expect("mock keyring store");
        let directory = TempDir::new().expect("test value");
        let path = directory.path().join("state");
        let key_ref = state_key_coordinates("inaccessible-key");
        stellar_agent_test_support::keyring_mock::inject_no_logon_session(
            &key_ref.service,
            &key_ref.account,
        )
        .expect("test value");
        assert_eq!(
            MppAuthorizationStore::open_for_read_at(path.clone(), &key_ref)
                .expect_err("refusal")
                .code(),
            STATE_CODE
        );
        stellar_agent_test_support::keyring_mock::inject_no_logon_session(
            &key_ref.service,
            &key_ref.account,
        )
        .expect("test value");
        assert_eq!(
            MppAuthorizationStore::open_for_prepare_at(path.clone(), &key_ref)
                .expect_err("refusal")
                .code(),
            STATE_CODE
        );
        assert!(key_is_absent(&key_ref).expect("test value"));
        assert_eq!(
            load_generation(&generation_entry_ref(&key_ref)).expect("test value"),
            None
        );
        assert!(!path.exists());
    }

    /// The negative control: a minted key over an existing file opens normally
    /// and returns its records.
    ///
    /// Without it every assertion above would also hold for a build that
    /// reported first run for everything.
    #[tokio::test]
    #[serial_test::serial]
    async fn open_for_read_opens_a_populated_store_and_returns_its_records() {
        stellar_agent_test_support::keyring_mock::install().expect("mock keyring store");
        let directory = TempDir::new().expect("tempdir");
        let path = directory.path().join("state");
        let entry_ref = state_key_coordinates("mpp-quadrant-populated");
        rotate_keyring_secret_32(&entry_ref.service, &entry_ref.account).expect("mint the key");
        let key = load_hmac_key_32(&entry_ref).expect("read the minted key");

        let now = 1_700_000_000;
        let (prepared, _signer, _rpc) = prepared_fixture(now).await;
        let record = AuthorizationRecord::new("quadrant", TESTNET_PASSPHRASE, &prepared, now)
            .expect("record");
        let id = record.authorization_id().to_owned();
        write_generation(&generation_entry_ref(&entry_ref), 0).expect("initial anchor");
        MppAuthorizationStore::at_path(path.clone(), *key, generation_entry_ref(&entry_ref))
            .insert_prepared(record, now)
            .expect("seed one prepared record");
        assert!(path.exists(), "the fixture must have written the file");

        let store = MppAuthorizationStore::open_for_read_at(path, &entry_ref)
            .expect("a populated store opens")
            .expect("a populated store is not first run");

        assert_eq!(
            store.load(&id).expect("stored record").authorization_id(),
            id
        );
        assert_eq!(
            store
                .load(UNKNOWN_ID)
                .expect_err("an identifier the store does not hold")
                .code(),
            "mpp.authorization_not_found",
            "the narrowed contract holds on a populated store too"
        );
    }

    /// `record_receipt` answers an identifier its caller supplied, so a store
    /// holding no such record answers exactly as `load` does — the verb cannot
    /// return two different codes for one user error depending on store state
    /// the caller cannot see.
    ///
    /// The internal lifecycle transitions keep the state refusal: each acts on
    /// a record loaded under this same lock moments earlier, so a record
    /// missing there is corruption, not a caller mistake.
    #[test]
    #[serial_test::serial]
    fn a_caller_supplied_identifier_is_not_found_while_a_lifecycle_transition_is_a_state_failure() {
        stellar_agent_test_support::keyring_mock::install().expect("mock keyring store");
        let directory = TempDir::new().expect("tempdir");
        let store = test_store(directory.path().join("state"), [7; 32]);
        let now = 1_700_000_000;
        let receipt = parse_receipt(&ReceiptInput::Mcp {
            receipt: serde_json::json!({
                "method": "stellar",
                "reference": "a".repeat(64),
                "status": "success",
                "timestamp": "2026-07-16T12:00:00Z",
            }),
        })
        .expect("receipt");

        assert_eq!(
            store
                .record_receipt(UNKNOWN_ID, &receipt, now)
                .expect_err("an identifier the store does not hold")
                .code(),
            NOT_FOUND_CODE
        );
        assert_eq!(
            store
                .record_receipt(UNKNOWN_ID, &receipt, now)
                .expect_err("same verb, same answer")
                .code(),
            store
                .load(UNKNOWN_ID)
                .expect_err("the lookup answer")
                .code(),
        );

        for (label, outcome) in [
            ("mark_ready", store.mark_ready(UNKNOWN_ID, now)),
            ("claim_ready", store.claim_ready(UNKNOWN_ID, now)),
            ("mark_authorized", store.mark_authorized(UNKNOWN_ID, now)),
            (
                "mark_policy_accounted",
                store.mark_policy_accounted(UNKNOWN_ID),
            ),
            (
                "record_ledger_outcome",
                store.record_ledger_outcome(
                    UNKNOWN_ID,
                    LedgerOutcome::Settled {
                        ledger: 1,
                        reconciled_at: now,
                    },
                    now,
                ),
            ),
        ] {
            assert_eq!(
                outcome.expect_err("no record to transition").code(),
                STATE_CODE,
                "{label} acts on a record it loaded under this lock; a vanished one is corruption"
            );
        }
    }

    #[test]
    #[serial_test::serial]
    fn empty_store_is_lazy_until_mutation() {
        stellar_agent_test_support::keyring_mock::install().expect("mock keyring store");
        let directory = TempDir::new().expect("tempdir");
        let path = directory.path().join("state");
        let store = test_store(path.clone(), [7; 32]);
        assert_eq!(
            store
                .load(UNKNOWN_ID)
                .expect_err("an empty store holds no record")
                .code(),
            "mpp.authorization_not_found"
        );
        assert!(!path.exists());
    }

    #[test]
    #[serial_test::serial]
    fn hmac_tamper_fails_closed() {
        stellar_agent_test_support::keyring_mock::install().expect("mock keyring store");
        let directory = TempDir::new().expect("tempdir");
        let path = directory.path().join("state");
        let store = test_store(path.clone(), [7; 32]);
        let wire = WireStore {
            version: STORE_VERSION,
            generation: 1,
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
    #[serial_test::serial]
    fn wrong_key_fails_closed() {
        stellar_agent_test_support::keyring_mock::install().expect("mock keyring store");
        let directory = TempDir::new().expect("tempdir");
        let path = directory.path().join("state");
        let first = test_store(path.clone(), [7; 32]);
        first.ensure_parent().expect("parent");
        first
            .write_atomic(&WireStore {
                version: STORE_VERSION,
                generation: 1,
                records: Vec::new(),
            })
            .expect("write");
        let second = test_store(path, [8; 32]);
        assert!(second.read_verified().is_err());
    }

    #[test]
    #[serial_test::serial]
    fn truncated_authenticated_store_fails_closed() {
        stellar_agent_test_support::keyring_mock::install().expect("mock keyring store");
        let directory = TempDir::new().expect("tempdir");
        let path = directory.path().join("state");
        let store = test_store(path.clone(), [7; 32]);
        store.ensure_parent().expect("parent");
        fs::write(path, [0_u8; HMAC_TAG_BYTES - 1]).expect("truncated file");
        assert!(store.read_verified().is_err());
    }

    #[test]
    #[serial_test::serial]
    fn lock_contention_fails_without_mutation() {
        stellar_agent_test_support::keyring_mock::install().expect("mock keyring store");
        let directory = TempDir::new().expect("tempdir");
        let path = directory.path().join("state");
        let store = test_store(path.clone(), [7; 32]);
        store.ensure_parent().expect("parent");
        let lock = store.acquire_lock().expect("first lock");
        let contender = test_store(path.clone(), [7; 32]);
        assert!(contender.acquire_lock().is_err());
        assert!(!path.exists());
        drop(lock);
        assert!(contender.acquire_lock().is_ok());
    }

    #[cfg(unix)]
    #[test]
    #[serial_test::serial]
    fn symlinked_state_file_fails_closed() {
        stellar_agent_test_support::keyring_mock::install().expect("mock keyring store");
        use std::os::unix::fs::symlink;

        let directory = TempDir::new().expect("tempdir");
        let target = directory.path().join("target");
        let path = directory.path().join("state");
        fs::write(&target, b"not state").expect("target");
        symlink(target, &path).expect("symlink");
        let store = test_store(path, [7; 32]);
        assert!(store.read_verified().is_err());
    }

    /// A symlink whose target does not exist refuses on every store path, and
    /// the refusal creates nothing at that target.
    ///
    /// A dangling link is invisible to an existence test that follows links.
    /// Treating "does not resolve" as "is not there" reads the state path as an
    /// empty store, and skips the lock path's symlink check — after which the
    /// open creates and locks the file the link points at, since `O_CREAT`
    /// follows symlinks. Read verbs reach both paths.
    ///
    /// The store-directory case is here as an invariant rather than as the
    /// discriminator for a particular implementation: `mkdir` refuses a
    /// symlinked path with `EEXIST` and never materialises its target, so the
    /// directory can only ever be refused, whether the inspection runs before
    /// the creation or after it.
    #[cfg(unix)]
    #[test]
    #[serial_test::serial]
    fn a_dangling_symlink_refuses_without_creating_its_target() {
        stellar_agent_test_support::keyring_mock::install().expect("mock keyring store");
        use std::os::unix::fs::symlink;

        let directory = TempDir::new().expect("tempdir");

        let file_target = directory.path().join("state-target");
        let path = directory.path().join("state");
        symlink(&file_target, &path).expect("dangling state symlink");
        let store = test_store(path, [7; 32]);
        assert_eq!(
            store
                .load(UNKNOWN_ID)
                .expect_err("a dangling state link is not an empty store")
                .code(),
            STATE_CODE
        );
        assert!(
            !file_target.exists(),
            "the refusal must not create the state file at the link target"
        );

        let lock_target = directory.path().join("lock-target");
        let locked_path = directory.path().join("locked");
        symlink(&lock_target, sibling_path(&locked_path, ".lock")).expect("dangling lock symlink");
        let store = test_store(locked_path, [7; 32]);
        assert_eq!(
            store
                .load(UNKNOWN_ID)
                .expect_err("a symlinked lock path is refused")
                .code(),
            STATE_CODE
        );
        assert!(
            !lock_target.exists(),
            "the refusal must not create and lock the file the link points at"
        );

        let directory_target = directory.path().join("store-dir-target");
        let store_directory = directory.path().join("mpp");
        symlink(&directory_target, &store_directory).expect("dangling directory symlink");
        let store = test_store(store_directory.join("state"), [7; 32]);
        assert_eq!(
            store
                .load(UNKNOWN_ID)
                .expect_err("a store directory that is a symlink is refused")
                .code(),
            STATE_CODE
        );
        assert!(
            !directory_target.exists(),
            "the refusal must not materialise the store directory at the link target"
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn duplicate_authenticated_records_fail_closed() {
        stellar_agent_test_support::keyring_mock::install().expect("mock keyring store");
        let directory = TempDir::new().expect("tempdir");
        let path = directory.path().join("state");
        let store = test_store(path, [7; 32]);
        let (prepared, _signer, _rpc) = prepared_fixture(1_700_000_000).await;
        let record =
            AuthorizationRecord::new("duplicate", TESTNET_PASSPHRASE, &prepared, 1_700_000_000)
                .expect("record");
        store.ensure_parent().expect("parent");
        store
            .write_atomic(&WireStore {
                version: STORE_VERSION,
                generation: 1,
                records: vec![record.clone(), record],
            })
            .expect("authenticated duplicate store");
        assert!(store.read_verified().is_err());
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn prune_removes_only_expired_records_past_terminal_retention() {
        stellar_agent_test_support::keyring_mock::install().expect("mock keyring store");
        let directory = TempDir::new().expect("tempdir");
        let path = directory.path().join("state");
        let store = test_store(path, [7; 32]);
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
        assert_eq!(
            store
                .load(&id)
                .expect_err("the pruned record is gone")
                .code(),
            "mpp.authorization_not_found"
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn durable_transition_api_enforces_replay_receipt_and_outcome_rules() {
        stellar_agent_test_support::keyring_mock::install().expect("mock keyring store");
        let directory = TempDir::new().expect("tempdir");
        let store = test_store(directory.path().join("state"), [7; 32]);
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
        // A malformed identifier is refused before any lookup: it is an input
        // fault, not an authorization the store happens not to hold.
        for invalid in ["", "mpp_short", "mpp_G0000000000000000000000000000000"] {
            assert_eq!(
                store
                    .load(invalid)
                    .expect_err("a malformed identifier is refused")
                    .code(),
                "mpp.state_unavailable"
            );
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
        assert_eq!(
            store
                .load_by_approval_nonce("short")
                .expect_err("a malformed nonce is refused")
                .code(),
            "mpp.state_unavailable"
        );
        assert_eq!(
            store
                .load_by_approval_nonce("missing_nonce_value_12")
                .expect_err("a well-formed nonce no record carries")
                .code(),
            "mpp.authorization_not_found"
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

#[cfg(test)]
mod recovery_tests;
