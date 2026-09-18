//! [`PersistedWindowStore`]: the HMAC-protected, single-writer, atomic-write
//! per-profile policy window-state file. See the module-level docs in
//! [`super`] for the wire format, integrity, and concurrency design.

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, KeyInit as _, Mac as _};
use sha2::Sha256;
use stellar_agent_core::policy::v1::criteria::state_store::{PolicyStateStore, StateKey};
use stellar_agent_core::profile::receipt::{ReceiptStatus, ReceiptStore};
use stellar_agent_core::profile::schema::{
    KeyringEntryRef, Profile, default_policy_window_state_path_for,
};
use subtle::ConstantTimeEq as _;

use crate::policy_state::WindowStoreError;
use crate::policy_state::lock::WindowStoreLock;

type HmacSha256 = Hmac<Sha256>;

/// HMAC tag length in bytes.
const HMAC_TAG_LEN: usize = 32;

/// HMAC context-separation label for the window-state store's v1 wire
/// format. A tag computed under this label cannot verify under a different
/// context.
const HMAC_CONTEXT_LABEL: &[u8] = b"stellar-agent-policy-window/v1/body\x00";

/// Retention ceiling: the largest window a criterion supports (`"1w"`), in
/// milliseconds. Entries older than `now_ms - RETENTION_MS` are pruned on
/// every write, so the store never grows unbounded even if a criterion's
/// window shrinks or a rule is removed.
const RETENTION_MS: u64 = 604_800 * 1_000;

/// Bounds the chain-time observation independently of the transport timeout.
const LEDGER_OBSERVATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// Chain observations and RPC allowance shared by one reconciliation pass.
struct ReconcilePass {
    remaining: usize,
    spent: usize,
    observed: bool,
    oldest_ledger: Option<u32>,
    chain: Option<(u32, u64)>,
}

impl ReconcilePass {
    fn new(budget: usize) -> Self {
        Self {
            remaining: budget.saturating_mul(3).saturating_add(2),
            spent: 0,
            observed: false,
            oldest_ledger: None,
            chain: None,
        }
    }

    fn charge(&mut self) -> bool {
        if self.remaining == 0 {
            return false;
        }
        self.remaining -= 1;
        self.spent += 1;
        true
    }

    async fn observe(&mut self, client: &crate::client::StellarRpcClient) {
        if self.observed {
            return;
        }
        self.observed = true;
        if !self.charge() {
            return;
        }
        let health = match client.get_health().await {
            Ok(health) => health,
            Err(error) => {
                tracing::debug!(%error, "window reconcile: retention observation unavailable; reservation stands");
                return;
            }
        };
        self.oldest_ledger = Some(health.oldest_ledger);
        if !self.charge() {
            return;
        }
        let answer = tokio::time::timeout(
            LEDGER_OBSERVATION_TIMEOUT,
            client.inner.get_ledgers(
                stellar_rpc_client::LedgerStart::Ledger(health.latest_ledger),
                Some(1),
                None,
            ),
        )
        .await;
        if let Ok(Ok(answer)) = answer
            && answer.latest_ledger_close_time > 0
            && answer.latest_ledger_close_time >= answer.oldest_ledger_close_time
            && answer.latest_ledger >= health.latest_ledger
            && answer.oldest_ledger <= answer.latest_ledger
        {
            self.oldest_ledger = Some(health.oldest_ledger.max(answer.oldest_ledger));
            self.chain = Some((answer.latest_ledger, answer.latest_ledger_close_time as u64));
            return;
        }
        tracing::debug!(
            "window reconcile: valid ledger close time unavailable; time-bound release stays closed"
        );
    }
}

/// Wire-format version this build writes.
const WIRE_VERSION: u32 = 3;

/// Highest wire-format version this build reads.
///
/// A file written by a newer build carries records this one cannot account
/// for, so it is refused rather than read with the fields it happens to
/// recognise.
const WIRE_VERSION_MAX: u32 = 3;

/// How many reservations one reconciliation pass settles.
///
/// A value verb runs a pass before its policy gate, so this bounds the extra
/// round trips it can spend: at most this many reservations, each costing at
/// most three transaction/account reads, plus one shared retention query and
/// one ledger observation. Every RPC consumes that pass's `3 * budget + 2`
/// allowance, including the ledger observation.
pub const RECONCILE_BUDGET: usize = 5;

/// How long a reservation must stand before a reconciliation pass looks at it.
///
/// Below this age no release branch can fire: a transaction whose sequence is
/// not yet consumed and whose time bound has not passed is still applicable,
/// and asking about it only costs round trips.
pub const RECONCILE_MIN_AGE_MS: u64 = 300_000;

// ─────────────────────────────────────────────────────────────────────────────
// Wire format
// ─────────────────────────────────────────────────────────────────────────────

/// Whether a record counts spend the chain has confirmed, or spend a
/// submission has reserved while its outcome is still open.
///
/// Both count against a window criterion: a submission that has been sent may
/// apply, so the operator's cap has to hold against it until the chain says
/// otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum RecordStatus {
    /// The transaction reached a ledger. Version 1 records default to
    /// confirmed spend so their window accounting remains defined.
    #[default]
    Confirmed,
    /// A signed transaction was sent and its outcome is not known yet.
    Pending,
}

/// One `(timestamp_ms, amount)` record within a bucket, plus the identity of
/// the submission that reserved it.
///
/// The identity fields carry defaults so a v1 record deserialises as a
/// confirmed record with no reservation to reconcile.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct WireRecord {
    ts_ms: u64,
    #[serde(with = "i128_decimal_str")]
    amount: i128,
    /// Reservation identity: the envelope hash of the submission that wrote
    /// this record. Every record one submission writes shares it, so one
    /// reconciliation settles them together. Empty on a confirmed record
    /// written by a path that takes no reservation.
    #[serde(default)]
    id: String,
    #[serde(default)]
    status: RecordStatus,
    /// Transaction hash to reconcile the reservation against.
    #[serde(default)]
    tx_hash: String,
    /// The account whose sequence the transaction consumes.
    #[serde(default)]
    source: String,
    /// The sequence number the transaction consumes.
    #[serde(default)]
    sequence: i64,
    /// `TimeBounds.maxTime` in absolute unix seconds; `0` means no time bound.
    #[serde(default)]
    max_time: u64,
    /// When the reservation was taken, in unix milliseconds.
    #[serde(default)]
    pending_since_ms: u64,
    /// The endpoint's latest ledger when the reservation was taken, compared
    /// against the endpoint's retention floor to tell "the endpoint never saw
    /// it" apart from "the endpoint no longer remembers it".
    #[serde(default)]
    submission_ledger: u32,
    /// An orphan beyond retention requires an operator decision.
    #[serde(default)]
    operator_required: bool,
}

impl WireRecord {
    /// The identity fields of a record that carries no reservation.
    ///
    /// Used with struct-update syntax so a confirmed record names only its
    /// timestamp and amount at the call site.
    fn confirmed_defaults() -> Self {
        Self {
            ts_ms: 0,
            amount: 0,
            id: String::new(),
            status: RecordStatus::Confirmed,
            tx_hash: String::new(),
            source: String::new(),
            sequence: 0,
            max_time: 0,
            pending_since_ms: 0,
            submission_ledger: 0,
            operator_required: false,
        }
    }
}

/// The identity of a submission that holds a window reservation.
///
/// Every record one submission writes carries this identity, so a
/// reconciliation pass settles them together from one round trip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowReservation {
    /// The submission's envelope hash, 64 lowercase hex characters.
    pub id: String,
    /// The transaction hash to reconcile against, 64 lowercase hex characters.
    pub tx_hash: String,
    /// The account whose sequence the transaction consumes, a `G...` strkey.
    pub source: String,
    /// The sequence number the transaction consumes.
    pub sequence: i64,
    /// `TimeBounds.maxTime` in absolute unix seconds; `0` means no time bound.
    pub max_time: u64,
    /// When the reservation was taken, in unix milliseconds.
    pub pending_since_ms: u64,
    /// The endpoint's latest ledger when the reservation was taken.
    pub submission_ledger: u32,
    /// The receipt is absent beyond retention; automatic reconciliation skips this hold.
    pub operator_required: bool,
}

/// What one reconciliation pass did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReconcileReport {
    /// Reservations the pass asked the endpoint about.
    pub examined: usize,
    /// RPC calls charged to this pass, including its shared observations.
    pub rpc_calls: usize,
    /// Reservations confirmed by a `SUCCESS` answer.
    pub confirmed: usize,
    /// Reservations released, either by a `FAILED` answer or because the
    /// transaction can no longer apply.
    pub released: usize,
    /// Reservations left standing because the answer settled nothing.
    pub kept_pending: usize,
    /// Reservations whose transaction the endpoint no longer remembers, so
    /// `NOT_FOUND` proves nothing. Their receipts are marked ambiguous and the
    /// reservations stand until an operator resolves them.
    pub retention_expired: usize,
    /// The submissions the pass settled against a definitive answer, in the
    /// order it settled them.
    ///
    /// The pass holds no audit writer of its own, so it reports what it
    /// settled and the caller writes the value-action row each one is owed.
    pub settled: Vec<SettledSubmission>,
}

/// One submission a reconciliation pass settled against a definitive answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettledSubmission {
    /// The envelope hash naming the submission record.
    pub envelope_hash: String,
    /// The transaction the chain answered for, in full.
    pub tx_hash: String,
    /// The status the receipt now holds.
    pub status: ReceiptStatus,
    /// The ledger the transaction confirmed in, when it did.
    pub ledger: Option<u32>,
}

/// One `StateKey` bucket (everything but the profile name, which is implied
/// by the file's identity) and its accumulated records.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct WireBucket {
    scope_specificity: u8,
    bucket: String,
    window_secs: u64,
    records: Vec<WireRecord>,
}

/// The canonical JSON body. `version` is the wire-format version, distinct
/// from any criterion or policy-document version — bumped only if this
/// store's own wire shape changes. `generation` is the anti-rollback counter
/// — see the module docs' "Anti-rollback" section; it MUST equal the
/// keyring-held generation counter for the file to be accepted.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
struct WireFile {
    version: u32,
    generation: u64,
    entries: Vec<WireBucket>,
    /// Prepared next generation, authenticated with the current snapshot.
    /// The keyring counter selects exactly one side of the atomic commit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    prepared: Option<Box<WireFile>>,
}

/// Decimal-string `i128` serde adapter, mirroring
/// `stellar_agent_core::wire_stroops::i128` / `audit_log::schema::i128_decimal_str` —
/// this crate cannot import those (private to their defining modules), and an
/// `i128` on the wire as a bare JSON number risks float round-tripping through
/// a permissive deserializer, so amounts are always decimal strings here too.
mod i128_decimal_str {
    use serde::{Deserialize as _, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(v: &i128, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&v.to_string())
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<i128, D::Error> {
        let s = String::deserialize(d)?;
        s.parse::<i128>()
            .map_err(|e| serde::de::Error::custom(format!("invalid i128 decimal string: {e}")))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PersistedWindowStore
// ─────────────────────────────────────────────────────────────────────────────

/// Whether a store operation minted a fresh HMAC key (the keyring entry did
/// not previously exist).
///
/// Callers use this to decide whether to emit a `keyring_key_written` audit
/// row — the store itself has no audit-writer handle, so minting is reported
/// back rather than logged internally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MintOutcome {
    /// `true` when this call minted the HMAC key (it was absent beforehand).
    pub newly_minted: bool,
}

/// The HMAC-protected, single-writer, atomically-written per-profile policy
/// window-state store. See the [`super`] module docs for the full design.
#[derive(Debug, Clone)]
pub struct PersistedWindowStore {
    path: PathBuf,
}

impl PersistedWindowStore {
    /// Constructs a store handle for the OS-conventional path for
    /// `profile_name` (`<state>/stellar-agent/policy/<profile_name>.window`).
    #[must_use]
    pub fn for_profile(profile_name: &str) -> Self {
        Self {
            path: default_policy_window_state_path_for(profile_name),
        }
    }

    /// Constructs a store handle at an explicit path — used by tests and by
    /// callers that override the OS-conventional state directory.
    #[must_use]
    pub fn at_path(path: PathBuf) -> Self {
        Self { path }
    }

    /// Returns `true` if the store file exists on disk.
    ///
    /// Used before a pre-rotation integrity check: a file that exists but was
    /// signed by a key the keyring never minted (the keyring entry for
    /// `policy_window_state_key_id` is absent) cannot be verified against any
    /// legitimate prior key, and must be treated as suspicious rather than
    /// silently re-signed.
    #[must_use]
    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    fn lock_path(&self) -> PathBuf {
        let mut p = self.path.clone();
        let name = p
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("policy.window")
            .to_owned();
        p.set_file_name(format!("{name}.lock"));
        p
    }

    /// Loads every persisted entry into `dest`, verifying the HMAC tag AND
    /// the anti-rollback generation under `profile.policy_window_state_key_id`.
    ///
    /// `profile_name` is the same profile-name string the caller passes to
    /// `PolicyEngineV1::new(_with_store)` / criterion evaluation — used to
    /// reconstruct each [`StateKey`] so a hydrated entry's key is identical to
    /// the key a criterion derives at `evaluate` time. Read from the profile
    /// struct itself, NOT re-derived from `policy_window_state_key_id`: an
    /// operator-overridden (non-name-derived) keyring coordinate must not
    /// change which profile a hydrated entry's `StateKey` belongs to.
    ///
    /// A missing store file with no keyring generation counter minted is
    /// treated as empty history (`Ok(())`, no entries appended) — a genuine
    /// first run for this profile. A missing file WITH a minted generation
    /// counter is deletion — see [`WindowStoreError::GenerationMismatch`].
    ///
    /// # Errors
    ///
    /// - [`WindowStoreError::HmacMismatch`] — tampering, corruption, or a
    ///   stale key.
    /// - [`WindowStoreError::GenerationMismatch`] — the file's generation does
    ///   not match the keyring's, or one of the two is present without the
    ///   other (deletion or rollback — see the module docs).
    /// - [`WindowStoreError::Invalid`] — the file is truncated or not valid
    ///   JSON in the expected shape.
    /// - [`WindowStoreError::Keyring`] — the HMAC key could not be loaded
    ///   (and the file exists, so a key SHOULD be present — a store file can
    ///   only have been written after the key was minted).
    /// - [`WindowStoreError::Io`] — the file could not be read for a reason
    ///   other than not existing.
    pub fn load_into(
        &self,
        profile_name: &str,
        profile: &Profile,
        dest: &PolicyStateStore,
    ) -> Result<(), WindowStoreError> {
        let entry_ref = &profile.policy_window_state_key_id;
        let gen_entry = generation_entry_ref(profile);

        // Check file existence BEFORE loading the HMAC key: a genuinely
        // fresh profile (no file, no minted key) must not require a key
        // load at all — `load_hmac_key_32` would fail (`NoEntry`) for a
        // profile that has never recorded anything, and that failure must
        // not be conflated with a real integrity error. `read_verified`
        // (used by `record_and_persist`/`reset`) does not have this problem:
        // those callers always hold an already-minted key via
        // `load_or_mint_key`.
        let bytes = match fs::read(&self.path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return match load_generation(&gen_entry)? {
                    None => Ok(()), // genuine first run — no key, no file, no history.
                    Some(_) => Err(WindowStoreError::GenerationMismatch), // deletion detected.
                };
            }
            Err(e) => return Err(WindowStoreError::Io { kind: e.kind() }),
        };

        let key =
            crate::keyring::load_hmac_key_32(entry_ref).map_err(|e| WindowStoreError::Keyring {
                detail: format!("{e}"),
            })?;
        let wire = self.verify_with_key(&key, &bytes)?;
        let wire = select_generation(wire, load_counter(&gen_entry)?)?;

        for entry in wire.entries {
            let key = StateKey::new(
                profile_name,
                entry.scope_specificity,
                &entry.bucket,
                entry.window_secs,
            );
            for record in entry.records {
                let appended = if record.status == RecordStatus::Pending {
                    dest.append_pending(&key, record.ts_ms, record.amount)
                } else {
                    dest.append(&key, record.ts_ms, record.amount)
                };
                appended.map_err(|e| WindowStoreError::Invalid {
                    detail: format!("in-memory store append failed: {e}"),
                })?;
            }
        }
        Ok(())
    }

    /// Locks, re-reads and fully verifies the current on-disk state (HMAC +
    /// generation — the source of truth, correct even if another process
    /// wrote since this process last hydrated), appends `new_entries`, prunes
    /// entries older than the 1-week retention ceiling, bumps the generation
    /// counter, HMAC-signs under the NEW generation, and atomically writes.
    ///
    /// Lazily mints the HMAC key on the first write for a profile (the
    /// caller should emit a `keyring_key_written` audit row when
    /// [`MintOutcome::newly_minted`] is `true`).
    ///
    /// # Errors
    ///
    /// See [`WindowStoreError`]. A tampered, deleted, or rolled-back EXISTING
    /// file fails closed (`HmacMismatch` / `GenerationMismatch` / `Invalid`)
    /// rather than silently overwriting history with only the new entries —
    /// an operator must run `profile reset-window-state` to recover.
    pub fn record_and_persist(
        &self,
        profile: &Profile,
        new_entries: &[(StateKey, u64, i128)],
    ) -> Result<MintOutcome, WindowStoreError> {
        self.ensure_parent_dir()?;
        let _lock = WindowStoreLock::acquire(&self.lock_path())?;

        let (key, mint_outcome) = self.load_or_mint_key(profile)?;
        let gen_entry = generation_entry_ref(profile);

        let mut wire = self.read_verified(&key, &gen_entry)?;

        for (state_key, ts_ms, amount) in new_entries {
            let bucket = find_or_insert_bucket(&mut wire.entries, state_key);
            bucket.records.push(WireRecord {
                ts_ms: *ts_ms,
                amount: *amount,
                ..WireRecord::confirmed_defaults()
            });
        }

        let now_ms = now_ms()?;
        prune_stale(&mut wire, now_ms);
        wire.version = WIRE_VERSION;

        wire.generation = next_generation(&gen_entry)?;
        write_generation(&gen_entry, &wire)?;
        self.write_atomic(&key, &wire)?;
        Ok(mint_outcome)
    }

    /// Records `new_entries` as a reservation held by `reservation`, under the
    /// same lock, pruning and generation discipline as
    /// [`Self::record_and_persist`].
    ///
    /// A reservation counts toward every window criterion exactly as confirmed
    /// spend does: the transaction has been sent and may apply, so the
    /// operator's cap has to hold against it. It is settled by
    /// [`Self::confirm`], [`Self::release`], or a reconciliation pass.
    ///
    /// # Errors
    ///
    /// See [`WindowStoreError`].
    pub fn record_pending(
        &self,
        profile: &Profile,
        new_entries: &[(StateKey, u64, i128)],
        reservation: &WindowReservation,
    ) -> Result<MintOutcome, WindowStoreError> {
        self.ensure_parent_dir()?;
        let _lock = WindowStoreLock::acquire(&self.lock_path())?;

        let (key, mint_outcome) = self.load_or_mint_key(profile)?;
        let gen_entry = generation_entry_ref(profile);
        let mut wire = self.read_verified(&key, &gen_entry)?;

        for (state_key, ts_ms, amount) in new_entries {
            let bucket = find_or_insert_bucket(&mut wire.entries, state_key);
            bucket.records.push(WireRecord {
                ts_ms: *ts_ms,
                amount: *amount,
                id: reservation.id.clone(),
                status: RecordStatus::Pending,
                tx_hash: reservation.tx_hash.clone(),
                source: reservation.source.clone(),
                sequence: reservation.sequence,
                max_time: reservation.max_time,
                pending_since_ms: reservation.pending_since_ms,
                submission_ledger: reservation.submission_ledger,
                operator_required: false,
            });
        }

        prune_stale(&mut wire, now_ms()?);
        wire.version = WIRE_VERSION;
        wire.generation = next_generation(&gen_entry)?;
        write_generation(&gen_entry, &wire)?;
        self.write_atomic(&key, &wire)?;
        Ok(mint_outcome)
    }

    /// Marks every record held by reservation `id` confirmed.
    ///
    /// Confirmed spend ages from the applying ledger's close time. A missing
    /// or invalid close time leaves the hold pending because its age is unknown.
    ///
    /// # Errors
    ///
    /// See [`WindowStoreError`].
    pub fn confirm(
        &self,
        profile: &Profile,
        id: &str,
        created_at: Option<i64>,
    ) -> Result<(), WindowStoreError> {
        let close_ms = created_at
            .and_then(|time| u64::try_from(time).ok())
            .filter(|time| *time > 0)
            .and_then(|time| time.checked_mul(1_000));
        let Some(close_ms) = close_ms else {
            tracing::warn!(
                "window confirm: applying ledger close time unavailable; reservation stays pending"
            );
            return Ok(());
        };
        self.rewrite_records(profile, |wire| {
            let mut touched = false;
            for bucket in &mut wire.entries {
                for record in &mut bucket.records {
                    if record.id == id && record.status == RecordStatus::Pending {
                        record.status = RecordStatus::Confirmed;
                        record.ts_ms = close_ms;
                        touched = true;
                    }
                }
            }
            touched
        })
    }

    /// Removes every record held by reservation `id`.
    ///
    /// Called where the transaction can no longer apply: the network refused
    /// it, it failed on-chain, or reconciliation established that it cannot
    /// land. The reserved amount stops counting against the window.
    ///
    /// # Errors
    ///
    /// See [`WindowStoreError`].
    pub fn release(&self, profile: &Profile, id: &str) -> Result<(), WindowStoreError> {
        self.rewrite_records(profile, |wire| {
            let before: usize = wire.entries.iter().map(|b| b.records.len()).sum();
            for bucket in &mut wire.entries {
                bucket.records.retain(|r| r.id != id);
            }
            wire.entries.retain(|b| !b.records.is_empty());
            let after: usize = wire.entries.iter().map(|b| b.records.len()).sum();
            after != before
        })
    }

    /// Keeps an orphan's authenticated identity and debit while excluding it
    /// from automatic reconciliation until an operator resolves its outcome.
    fn mark_operator_required(&self, profile: &Profile, id: &str) -> Result<(), WindowStoreError> {
        let result = self.rewrite_records(profile, |wire| {
            let mut touched = false;
            for bucket in &mut wire.entries {
                for record in &mut bucket.records {
                    if record.id == id
                        && record.status == RecordStatus::Pending
                        && !record.operator_required
                    {
                        record.operator_required = true;
                        touched = true;
                    }
                }
            }
            touched
        });
        if let Err(error) = &result {
            tracing::warn!(
                ?error,
                "window reconcile: operator marker write failed; reservation remains selectable"
            );
        }
        result
    }

    /// Returns every reservation the file currently holds pending, oldest
    /// first.
    ///
    /// Verifies the file's HMAC tag and generation, like every other read.
    ///
    /// # Errors
    ///
    /// See [`WindowStoreError`].
    pub fn pending_reservations(
        &self,
        profile: &Profile,
    ) -> Result<Vec<WindowReservation>, WindowStoreError> {
        let wire = match self.read_for_inspection(profile)? {
            Some(wire) => wire,
            None => return Ok(Vec::new()),
        };
        Ok(collect_pending(&wire))
    }

    /// Settles up to `budget` reservations that have stood at least
    /// [`RECONCILE_MIN_AGE_MS`], oldest first, against the chain.
    ///
    /// Per reservation, one `getTransaction`:
    ///
    /// - `SUCCESS` confirms the reservation and finalizes the receipt.
    /// - `FAILED` releases the reservation and finalizes the receipt failed.
    /// - `NOT_FOUND` is only evidence when the endpoint would still remember
    ///   the transaction. When the reservation's submission ledger predates
    ///   the endpoint's retention floor it proves nothing, so the reservation
    ///   stands and the receipt is marked ambiguous for an operator to
    ///   resolve. Otherwise the reservation is released when the source
    ///   account's sequence has reached the one the transaction needs, or an
    ///   observed ledger close time is strictly past its nonzero time bound.
    ///   Both arms require a fresh `NOT_FOUND`; a fresh definitive answer
    ///   settles the spend. Missing chain time closes only the time arm.
    ///
    /// An endpoint that cannot answer leaves the reservation standing. Nothing
    /// here releases a reservation on a transport error.
    ///
    /// `now_ms` is the caller's clock, the same seam every other store
    /// operation takes it through.
    ///
    /// # Errors
    ///
    /// See [`WindowStoreError`]. A per-reservation endpoint failure is not an
    /// error: it leaves that reservation standing and the pass continues.
    pub async fn reconcile_due(
        &self,
        profile: &Profile,
        client: &crate::client::StellarRpcClient,
        receipts: Option<&ReceiptStore>,
        now_ms: u64,
        budget: usize,
    ) -> Result<ReconcileReport, WindowStoreError> {
        let Some(wire) = self.read_for_inspection(profile)? else {
            return Ok(ReconcileReport::default());
        };

        // Oldest first, but past a reservation whose receipt already records
        // an unknown outcome. Those are the oldest records in the file and
        // the endpoint can no longer answer for them, so leaving them in the
        // selection would spend the whole budget on the same few every pass
        // and no younger reservation would ever be reached. Only
        // `tx receipt clear` settles them.
        // One read of the receipt file for the whole pass. The filter below
        // consults it per candidate, and re-reading it each time would cost a
        // lock acquisition and a full parse for every reservation in the file.
        //
        // A read failure leaves the map empty, which makes the filter below
        // admit every reservation rather than exclude the ones the endpoint
        // cannot answer for. That is the safe direction — a pass that examines
        // too much settles nothing wrongly — but it is silent, so it is
        // logged: the same unreadable file is what the per-reservation read
        // below reports too.
        let known: HashMap<String, ReceiptStatus> = match receipts.map(ReceiptStore::all) {
            Some(Ok(all)) => all
                .into_iter()
                .map(|r| (r.envelope_hash, r.status))
                .collect(),
            Some(Err(e)) => {
                tracing::debug!(
                    error = %e,
                    "window reconcile: the receipt store could not be read; the starvation \
                     filter admits every reservation this pass"
                );
                HashMap::new()
            }
            None => HashMap::new(),
        };

        let due: Vec<WindowReservation> = collect_pending(&wire)
            .into_iter()
            .filter(|r| now_ms.saturating_sub(r.pending_since_ms) >= RECONCILE_MIN_AGE_MS)
            .filter(|r| !r.operator_required && !outcome_already_unknown(&known, &r.id))
            .take(budget)
            .collect();

        let mut report = ReconcileReport::default();
        let mut pass = ReconcilePass::new(budget);

        for reservation in due {
            report.examined += 1;
            let settlement = self
                .settle_reservation(profile, client, receipts, &reservation, &mut pass)
                .await?;
            record_settlement(&mut report, &reservation, settlement);
        }

        report.rpc_calls = pass.spent;
        Ok(report)
    }

    /// Settles one named submission against the chain, with no budget and no
    /// minimum age.
    ///
    /// The operator or the agent asked about this submission by name, so the
    /// bound a background pass needs does not apply: there is exactly one
    /// round trip's worth of work and it was requested. The release rule is
    /// the same one [`Self::reconcile_due`] applies.
    ///
    /// Works whether or not the submission holds a reservation. An action the
    /// policy engine sized no value for takes none, and its receipt is still
    /// the handle the agent reconciles with, so the identity is taken from the
    /// receipt when the window file holds no record for it. Settling the
    /// window is then a no-op.
    ///
    /// # Errors
    ///
    /// See [`WindowStoreError`].
    pub async fn reconcile_one(
        &self,
        profile: &Profile,
        client: &crate::client::StellarRpcClient,
        receipts: Option<&ReceiptStore>,
        id: &str,
        _now_ms: u64,
    ) -> Result<ReconcileReport, WindowStoreError> {
        let open = match self.read_for_inspection(profile)? {
            Some(wire) => collect_pending(&wire).into_iter().find(|r| r.id == id),
            None => None,
        };
        let reservation =
            match open.or_else(|| receipts.and_then(|s| reservation_from_receipt(s, id))) {
                Some(r) => r,
                None => return Ok(ReconcileReport::default()),
            };

        let mut report = ReconcileReport {
            examined: 1,
            ..ReconcileReport::default()
        };
        let mut pass = ReconcilePass::new(1);
        let settlement = self
            .settle_reservation(profile, client, receipts, &reservation, &mut pass)
            .await?;
        record_settlement(&mut report, &reservation, settlement);
        report.rpc_calls = pass.spent;
        Ok(report)
    }

    /// Re-initialises the store file to empty and bumps the generation
    /// counter past whatever value it last held (re-baselining both), signed
    /// under the (lazily-minted) HMAC key. Does NOT validate the pre-existing
    /// file's HMAC or generation first — this IS the recovery path for a
    /// tampered, deleted, or rolled-back store, so it must succeed
    /// unconditionally rather than requiring the very state it exists to
    /// repair.
    ///
    /// The caller emits the `PolicyWindowStateReset` audit row — BEFORE
    /// calling this method (see the CLI command's rustdoc for the ordering
    /// rationale); this method performs the file + keyring generation
    /// mutation only.
    ///
    /// # Errors
    ///
    /// See [`WindowStoreError`].
    pub fn reset(&self, profile: &Profile) -> Result<MintOutcome, WindowStoreError> {
        self.ensure_parent_dir()?;
        let _lock = WindowStoreLock::acquire(&self.lock_path())?;
        let (key, mint_outcome) = self.load_or_mint_key(profile)?;
        let gen_entry = generation_entry_ref(profile);
        let new_generation = next_generation(&gen_entry)?;
        let empty = WireFile {
            version: WIRE_VERSION,
            generation: new_generation,
            entries: Vec::new(),
            prepared: None,
        };
        write_generation(&gen_entry, &empty)?;
        self.write_atomic(&key, &empty)?;
        Ok(mint_outcome)
    }

    /// Verifies the store file's HMAC tag under `key` WITHOUT checking the
    /// generation counter or parsing the body — a pure content-integrity
    /// check used before a key rotation destroys the OLD key, so a tampered
    /// file cannot be silently re-signed (and thereby laundered) under the
    /// new one. A missing file is `Ok(())` (nothing to verify).
    ///
    /// # Errors
    ///
    /// - [`WindowStoreError::HmacMismatch`] — the file's tag does not match
    ///   `key`.
    /// - [`WindowStoreError::Invalid`] — the file is shorter than the tag
    ///   prefix.
    /// - [`WindowStoreError::Io`] — the file could not be read for a reason
    ///   other than not existing.
    pub fn verify_tag(&self, key: &[u8; 32]) -> Result<(), WindowStoreError> {
        let bytes = match fs::read(&self.path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(WindowStoreError::Io { kind: e.kind() }),
        };
        if bytes.len() < HMAC_TAG_LEN {
            return Err(WindowStoreError::Invalid {
                detail: "store file is shorter than the HMAC tag prefix".to_owned(),
            });
        }
        let (stored_tag, body) = bytes.split_at(HMAC_TAG_LEN);
        let recomputed = compute_tag(key, body)?;
        if !bool::from(stored_tag.ct_eq(&recomputed)) {
            return Err(WindowStoreError::HmacMismatch);
        }
        Ok(())
    }

    /// Re-signs the store file under `new_key`, WITHOUT requiring the old
    /// key: the body bytes (including the unchanged `generation` field) are
    /// read as-is (the same content any reader would see) and a fresh tag is
    /// computed over them with `new_key` — the same "recompute over the
    /// identical body" shape as [`stellar_agent_core::audit_log`]'s
    /// `resign_chain_root_sidecars`. Does NOT touch the generation counter:
    /// rotation is not a write in the anti-rollback sense, so it must not
    /// look like one.
    ///
    /// Callers MUST verify the file's tag under the OLD key via
    /// [`Self::verify_tag`] BEFORE rotating that key (see the `rotate-policy-state-key`
    /// CLI command) — this method itself performs no such check, so calling
    /// it directly on a tampered file would launder the tamper under the new
    /// key.
    ///
    /// A missing store file is a no-op (`Ok(())`) — nothing to re-sign.
    ///
    /// # Errors
    ///
    /// [`WindowStoreError::Io`] / [`WindowStoreError::Invalid`] if the
    /// existing file cannot be read or is shorter than the tag prefix.
    pub fn resign(&self, new_key: &[u8; 32]) -> Result<(), WindowStoreError> {
        self.ensure_parent_dir()?;
        let _lock = WindowStoreLock::acquire(&self.lock_path())?;

        let bytes = match fs::read(&self.path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(WindowStoreError::Io { kind: e.kind() }),
        };
        if bytes.len() < HMAC_TAG_LEN {
            return Err(WindowStoreError::Invalid {
                detail: "store file is shorter than the HMAC tag prefix".to_owned(),
            });
        }
        let body = &bytes[HMAC_TAG_LEN..];
        let tag = compute_tag(new_key, body)?;
        self.write_atomic_raw(&tag, body)
    }

    // ── internals ────────────────────────────────────────────────────────

    /// Applies `mutate` to the verified file under the write lock and writes
    /// the result, bumping the generation counter.
    ///
    /// `mutate` returns whether it changed anything; when it did not, the file
    /// is left exactly as it stands and the generation counter is not bumped,
    /// so a settle call for a reservation another process already settled
    /// costs nothing and cannot look like a write.
    fn rewrite_records(
        &self,
        profile: &Profile,
        mutate: impl FnOnce(&mut WireFile) -> bool,
    ) -> Result<(), WindowStoreError> {
        self.ensure_parent_dir()?;
        let _lock = WindowStoreLock::acquire(&self.lock_path())?;

        let (key, _mint) = self.load_or_mint_key(profile)?;
        let gen_entry = generation_entry_ref(profile);
        let mut wire = self.read_verified(&key, &gen_entry)?;
        let original = wire.clone();

        if !mutate(&mut wire) {
            return Ok(());
        }

        prune_stale(&mut wire, now_ms()?);
        wire.version = WIRE_VERSION;
        self.commit_generation(&key, &gen_entry, original, wire)
    }

    /// Persists both sides before advancing the keyring commit point. A crash
    /// at any write leaves a snapshot matching the counter, while replay of an
    /// older file cannot supply a matching committed generation.
    fn commit_generation(
        &self,
        key: &[u8; 32],
        gen_entry: &KeyringEntryRef,
        mut original: WireFile,
        mut next: WireFile,
    ) -> Result<(), WindowStoreError> {
        next.generation =
            original
                .generation
                .checked_add(1)
                .ok_or_else(|| WindowStoreError::Invalid {
                    detail: "policy window-state generation counter overflow".to_owned(),
                })?;
        next.prepared = None;
        if original.generation == 0 {
            // Initialisation has no prior debit to retain. A missing trusted
            // counter on an existing file must remain a deletion error.
            write_generation(gen_entry, &next)?;
            return self.write_atomic(key, &next);
        }
        original.version = WIRE_VERSION;
        original.prepared = Some(Box::new(next.clone()));
        self.write_atomic(key, &original)?;
        write_generation(gen_entry, &next)?;
        // The committed candidate is already durable. Compaction is optional:
        // readers use it directly if replacing the prepared image fails.
        if let Err(error) = self.write_atomic(key, &next) {
            tracing::warn!(
                ?error,
                "window store: committed prepared generation retained; compaction failed"
            );
        }
        Ok(())
    }

    /// Settles one reservation against the chain. See [`Self::reconcile_due`]
    /// for the rule this implements.
    async fn settle_reservation(
        &self,
        profile: &Profile,
        client: &crate::client::StellarRpcClient,
        receipts: Option<&ReceiptStore>,
        reservation: &WindowReservation,
        pass: &mut ReconcilePass,
    ) -> Result<Settlement, WindowStoreError> {
        // A missing receipt leaves the authenticated reservation as the
        // submission identity. Its chain outcome and retention boundary still
        // govern settlement. An unreadable receipt store keeps the hold.
        if let Some(store) = receipts {
            match store.get(&reservation.id) {
                Ok(_) => {}
                Err(e) => {
                    tracing::debug!(
                        error = %e,
                        "window reconcile: the receipt store could not be read; the \
                         reservation stands"
                    );
                    return Ok(Settlement::KeptPending);
                }
            }
        }

        let Ok(hash_bytes) = stellar_agent_core::hex::decode_hex32(&reservation.tx_hash) else {
            // A reservation with no usable transaction hash cannot be asked
            // about. It stands until an operator resolves it.
            return Ok(Settlement::KeptPending);
        };
        let tx_hash = stellar_xdr::Hash(hash_bytes);

        if !pass.charge() {
            return Ok(Settlement::KeptPending);
        }
        let response = match client.inner.get_transaction(&tx_hash).await {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(
                    tx_hash = %crate::submit::redact_tx_hash(&reservation.tx_hash),
                    error = %crate::retry::truncate_error_display(&e),
                    "window reconcile: getTransaction failed; reservation stands"
                );
                return Ok(Settlement::KeptPending);
            }
        };

        if response.status == "NOT_FOUND" {
            return self
                .settle_not_found(profile, client, receipts, reservation, pass)
                .await;
        }
        self.settle_chain_answer(profile, receipts, reservation, &response)
    }

    /// Applies a definitive transaction answer to the reservation and receipt.
    fn settle_chain_answer(
        &self,
        profile: &Profile,
        receipts: Option<&ReceiptStore>,
        reservation: &WindowReservation,
        response: &stellar_rpc_client::GetTransactionResponse,
    ) -> Result<Settlement, WindowStoreError> {
        match response.status.as_str() {
            "SUCCESS" => {
                self.confirm(profile, &reservation.id, response.created_at)?;
                finalize_receipt(
                    receipts,
                    reservation,
                    ReceiptStatus::Success,
                    response.ledger,
                );
                Ok(Settlement::Confirmed {
                    ledger: response.ledger,
                })
            }
            "FAILED" => {
                self.release(profile, &reservation.id)?;
                let code = crate::submit::map_failed_result(response.result.as_ref())
                    .code()
                    .to_owned();
                finalize_receipt(
                    receipts,
                    reservation,
                    ReceiptStatus::Failed { code: code.clone() },
                    None,
                );
                Ok(Settlement::Released { code: Some(code) })
            }
            _ => Ok(Settlement::KeptPending),
        }
    }

    /// The `NOT_FOUND` half of the release rule.
    ///
    /// A consumed sequence requires one extra bounded transaction query: the
    /// reserved transaction can land between the first query and the account
    /// read. Settling that answer preserves its debit when it consumed its own
    /// sequence. Only a second `NOT_FOUND` permits sequence-based release.
    async fn settle_not_found(
        &self,
        profile: &Profile,
        client: &crate::client::StellarRpcClient,
        receipts: Option<&ReceiptStore>,
        reservation: &WindowReservation,
        pass: &mut ReconcilePass,
    ) -> Result<Settlement, WindowStoreError> {
        // The retention boundary first: an endpoint that no longer holds the
        // ledger range the submission was made in cannot report the
        // transaction whatever happened to it, so its NOT_FOUND carries no
        // information.
        pass.observe(client).await;
        let Some(floor) = pass.oldest_ledger else {
            return Ok(Settlement::KeptPending);
        };
        if reservation.submission_ledger > 0 && reservation.submission_ledger < floor {
            if let Some(receipts) = receipts {
                match receipts.get(&reservation.id) {
                    Ok(None) => self.mark_operator_required(profile, &reservation.id)?,
                    Ok(Some(_)) => finalize_receipt(
                        Some(receipts),
                        reservation,
                        ReceiptStatus::Ambiguous,
                        None,
                    ),
                    Err(error) => {
                        tracing::warn!(%error, "window reconcile: receipt read failed; orphan status unknown");
                        return Ok(Settlement::KeptPending);
                    }
                }
            }
            return Ok(Settlement::RetentionExpired);
        }

        let time_expired = reservation.max_time > 0
            && reservation.submission_ledger >= floor
            && reservation.submission_ledger > 0
            && pass.chain.is_some_and(|(ledger, close_time)| {
                reservation.submission_ledger <= ledger && close_time > reservation.max_time
            });
        if time_expired {
            return self
                .fresh_answer_or_release(profile, client, receipts, reservation, pass)
                .await;
        }

        // A consumed sequence needs a fresh transaction answer to distinguish
        // this submission landing from another submission using the sequence.
        if !pass.charge() {
            return Ok(Settlement::KeptPending);
        }
        let account = match crate::account::fetch_account(client, &reservation.source, &[]).await {
            Ok(a) => a,
            Err(e) => {
                tracing::debug!(
                    error = %e,
                    "window reconcile: source account fetch failed; reservation stands"
                );
                return Ok(Settlement::KeptPending);
            }
        };
        if account.sequence_number >= reservation.sequence {
            return self
                .fresh_answer_or_release(profile, client, receipts, reservation, pass)
                .await;
        }

        Ok(Settlement::KeptPending)
    }

    /// Rechecks the transaction after observing that it cannot apply.
    async fn fresh_answer_or_release(
        &self,
        profile: &Profile,
        client: &crate::client::StellarRpcClient,
        receipts: Option<&ReceiptStore>,
        reservation: &WindowReservation,
        pass: &mut ReconcilePass,
    ) -> Result<Settlement, WindowStoreError> {
        let Ok(hash) = stellar_agent_core::hex::decode_hex32(&reservation.tx_hash) else {
            return Ok(Settlement::KeptPending);
        };
        if !pass.charge() {
            return Ok(Settlement::KeptPending);
        }
        let response = match client.inner.get_transaction(&stellar_xdr::Hash(hash)).await {
            Ok(response) => response,
            Err(e) => {
                tracing::debug!(error = %crate::retry::truncate_error_display(&e),
                    "window reconcile: confirmation query failed; reservation stands");
                return Ok(Settlement::KeptPending);
            }
        };
        if response.status == "NOT_FOUND" {
            return self.release_as_ambiguous(profile, receipts, reservation);
        }
        self.settle_chain_answer(profile, receipts, reservation, &response)
    }

    /// Releases a reservation whose transaction can no longer apply, recording
    /// the receipt as ambiguous.
    ///
    /// The outcome is ambiguous rather than failed because no
    /// `TransactionResult` exists for it: what is established is that the
    /// transaction cannot reach a ledger, which rests on the endpoint's
    /// answers being honest.
    fn release_as_ambiguous(
        &self,
        profile: &Profile,
        receipts: Option<&ReceiptStore>,
        reservation: &WindowReservation,
    ) -> Result<Settlement, WindowStoreError> {
        self.release(profile, &reservation.id)?;
        finalize_receipt(receipts, reservation, ReceiptStatus::Ambiguous, None);
        Ok(Settlement::Released { code: None })
    }

    /// Reads and fully verifies the file for inspection, taking no lock.
    ///
    /// `Ok(None)` means there is nothing recorded yet for this profile.
    fn read_for_inspection(&self, profile: &Profile) -> Result<Option<WireFile>, WindowStoreError> {
        let gen_entry = generation_entry_ref(profile);
        let bytes = match fs::read(&self.path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return match load_generation(&gen_entry)? {
                    None => Ok(None),
                    Some(_) => Err(WindowStoreError::GenerationMismatch),
                };
            }
            Err(e) => return Err(WindowStoreError::Io { kind: e.kind() }),
        };
        let key =
            crate::keyring::load_hmac_key_32(&profile.policy_window_state_key_id).map_err(|e| {
                WindowStoreError::Keyring {
                    detail: format!("{e}"),
                }
            })?;
        let wire = self.verify_with_key(&key, &bytes)?;
        select_generation(wire, load_counter(&gen_entry)?).map(Some)
    }

    fn ensure_parent_dir(&self) -> Result<(), WindowStoreError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|e| WindowStoreError::Io { kind: e.kind() })?;
        }
        Ok(())
    }

    fn load_or_mint_key(
        &self,
        profile: &Profile,
    ) -> Result<(zeroize::Zeroizing<[u8; 32]>, MintOutcome), WindowStoreError> {
        let entry_ref = &profile.policy_window_state_key_id;
        match crate::keyring::load_hmac_key_32(entry_ref) {
            Ok(key) => Ok((
                key,
                MintOutcome {
                    newly_minted: false,
                },
            )),
            Err(_) => {
                // Load failure is treated as "not yet minted" — mint a fresh
                // key. A genuinely different failure (backend unavailable)
                // surfaces again on the mint attempt below and is reported.
                crate::keyring::rotate_keyring_secret_32(&entry_ref.service, &entry_ref.account)
                    .map_err(|e| WindowStoreError::Keyring {
                        detail: format!("mint failed: {e}"),
                    })?;
                let key = crate::keyring::load_hmac_key_32(entry_ref).map_err(|e| {
                    WindowStoreError::Keyring {
                        detail: format!("load-after-mint failed: {e}"),
                    }
                })?;
                Ok((key, MintOutcome { newly_minted: true }))
            }
        }
    }

    /// Reads and fully verifies (HMAC, then anti-rollback generation) the
    /// current file, or establishes the genuine-first-run empty state.
    /// Requires an already-available `key` — used by
    /// [`Self::record_and_persist`] / [`Self::reset`], both of which hold one
    /// via [`Self::load_or_mint_key`] (which mints on first use) before
    /// calling this. NOT used by [`Self::load_into`]: that method must not
    /// force a key load (and thus a `Keyring` error) for a profile that has
    /// never recorded anything — file existence is checked first there,
    /// inline, so the key is only touched when a file is actually present to
    /// verify.
    ///
    /// Reads the FILE before the KEYRING generation (narrows, in the
    /// fail-closed direction, a benign lock-free-read-races-a-write window:
    /// this method takes no lock, by design, so a concurrent writer could
    /// complete between the two reads; the ordering here means a read that
    /// loses that race sees an old file generation against the new keyring
    /// value and reports [`WindowStoreError::GenerationMismatch`] rather than
    /// silently accepting stale data — the caller retries and the very next
    /// read is consistent).
    fn read_verified(
        &self,
        key: &[u8; 32],
        gen_entry: &KeyringEntryRef,
    ) -> Result<WireFile, WindowStoreError> {
        match fs::read(&self.path) {
            Ok(bytes) => {
                let wire = self.verify_with_key(key, &bytes)?;
                select_generation(wire, load_counter(gen_entry)?)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => match load_generation(gen_entry)?
            {
                None => Ok(WireFile {
                    version: WIRE_VERSION,
                    generation: 0,
                    entries: Vec::new(),
                    prepared: None,
                }),
                Some(_) => Err(WindowStoreError::GenerationMismatch),
            },
            Err(e) => Err(WindowStoreError::Io { kind: e.kind() }),
        }
    }

    fn verify_with_key(&self, key: &[u8; 32], bytes: &[u8]) -> Result<WireFile, WindowStoreError> {
        if bytes.len() < HMAC_TAG_LEN {
            return Err(WindowStoreError::Invalid {
                detail: "store file is shorter than the HMAC tag prefix".to_owned(),
            });
        }
        let (stored_tag, body) = bytes.split_at(HMAC_TAG_LEN);
        let recomputed = compute_tag(key, body)?;
        if !bool::from(stored_tag.ct_eq(&recomputed)) {
            return Err(WindowStoreError::HmacMismatch);
        }
        let wire: WireFile =
            serde_json::from_slice(body).map_err(|e| WindowStoreError::Invalid {
                detail: format!("store body is not valid JSON: {e}"),
            })?;
        if wire.version > WIRE_VERSION_MAX {
            return Err(WindowStoreError::Invalid {
                detail: format!(
                    "store file wire version {} is newer than this build reads (max {WIRE_VERSION_MAX})",
                    wire.version
                ),
            });
        }
        Ok(wire)
    }

    fn write_atomic(&self, key: &[u8; 32], wire: &WireFile) -> Result<(), WindowStoreError> {
        let body = serde_json::to_vec(wire).map_err(|e| WindowStoreError::Invalid {
            detail: format!("failed to serialise store body: {e}"),
        })?;
        let tag = compute_tag(key, &body)?;
        self.write_atomic_raw(&tag, &body)
    }

    /// Writes `tag || body` to the store path via temp-file +
    /// `sync_data` + rename + parent-directory fsync — the
    /// `write_sidecar_atomic` precedent
    /// ([`stellar_agent_core::audit_log`] rotation.rs).
    fn write_atomic_raw(
        &self,
        tag: &[u8; HMAC_TAG_LEN],
        body: &[u8],
    ) -> Result<(), WindowStoreError> {
        let mut tmp = self.path.clone();
        let name = tmp
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("policy.window")
            .to_owned();
        tmp.set_file_name(format!("{name}.tmp"));
        {
            #[cfg(unix)]
            let mut f = {
                use std::os::unix::fs::OpenOptionsExt as _;
                OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(&tmp)
                    .map_err(|e| WindowStoreError::Io { kind: e.kind() })?
            };
            #[cfg(not(unix))]
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp)
                .map_err(|e| WindowStoreError::Io { kind: e.kind() })?;
            f.write_all(tag)
                .map_err(|e| WindowStoreError::Io { kind: e.kind() })?;
            f.write_all(body)
                .map_err(|e| WindowStoreError::Io { kind: e.kind() })?;
            f.sync_data()
                .map_err(|e| WindowStoreError::Io { kind: e.kind() })?;
        }
        fs::rename(&tmp, &self.path).map_err(|e| WindowStoreError::Io { kind: e.kind() })?;
        #[cfg(unix)]
        if let Some(parent) = self.path.parent() {
            fs::File::open(parent)
                .and_then(|d| d.sync_all())
                .map_err(|e| WindowStoreError::Io { kind: e.kind() })?;
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Anti-rollback generation counter
// ─────────────────────────────────────────────────────────────────────────────

/// Derives the generation-counter keyring coordinate from the profile's
/// `policy_window_state_key_id`: same `service`, `account` suffixed
/// `-generation`. Derived from the coordinate ITSELF (not re-derived from the
/// profile name) so an operator-overridden HMAC-key coordinate still gets a
/// correctly-associated generation entry.
fn generation_entry_ref(profile: &Profile) -> KeyringEntryRef {
    let base = &profile.policy_window_state_key_id;
    KeyringEntryRef::new(base.service.clone(), format!("{}-generation", base.account))
}

/// The trusted commit binds one generation to exactly one canonical body.
/// An abandoned candidate can reuse a generation number, but cannot replace
/// another body's commitment when that generation is later committed.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GenerationCommitment {
    generation: u64,
    body_sha256: String,
}

struct GenerationState {
    generation: u64,
    body_sha256: Option<String>,
}

/// Numeric entries retain compatibility with files written under versions 1 and 2.
fn load_counter(entry_ref: &KeyringEntryRef) -> Result<Option<GenerationState>, WindowStoreError> {
    let entry = keyring_core::Entry::new(&entry_ref.service, &entry_ref.account).map_err(|e| {
        WindowStoreError::Keyring {
            detail: format!("generation entry open failed: {e}"),
        }
    })?;
    match entry.get_password() {
        Ok(value) => {
            if let Ok(generation) = value.trim().parse::<u64>() {
                return Ok(Some(GenerationState {
                    generation,
                    body_sha256: None,
                }));
            }
            let committed: GenerationCommitment =
                serde_json::from_str(&value).map_err(|e| WindowStoreError::Keyring {
                    detail: format!("generation entry value is not a valid commitment: {e}"),
                })?;
            if committed.body_sha256.len() != 64
                || !committed
                    .body_sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(WindowStoreError::Keyring {
                    detail: "generation commitment digest is invalid".to_owned(),
                });
            }
            Ok(Some(GenerationState {
                generation: committed.generation,
                body_sha256: Some(committed.body_sha256),
            }))
        }
        Err(keyring_core::Error::NoEntry) => Ok(None),
        Err(e) => Err(WindowStoreError::Keyring {
            detail: format!("generation entry read failed: {e}"),
        }),
    }
}

fn load_generation(entry_ref: &KeyringEntryRef) -> Result<Option<u64>, WindowStoreError> {
    Ok(load_counter(entry_ref)?.map(|state| state.generation))
}

fn next_generation(entry_ref: &KeyringEntryRef) -> Result<u64, WindowStoreError> {
    load_generation(entry_ref)?
        .unwrap_or(0)
        .checked_add(1)
        .ok_or_else(|| WindowStoreError::Invalid {
            detail: "policy window-state generation counter overflow".to_owned(),
        })
}

/// Hashes the selected snapshot, whose prepared field is absent. The digest
/// stays identical across the prepared and compacted representations.
fn body_digest(wire: &WireFile) -> Result<String, WindowStoreError> {
    let body = serde_json::to_vec(wire).map_err(|e| WindowStoreError::Invalid {
        detail: format!("failed to serialise committed store body: {e}"),
    })?;
    Ok(stellar_agent_core::hex::encode(
        &<Sha256 as sha2::Digest>::digest(&body),
    ))
}

/// The window lock serialises callers; one keyring write commits both fields.
fn write_generation(entry_ref: &KeyringEntryRef, wire: &WireFile) -> Result<(), WindowStoreError> {
    let committed = GenerationCommitment {
        generation: wire.generation,
        body_sha256: body_digest(wire)?,
    };
    let value = serde_json::to_string(&committed).map_err(|e| WindowStoreError::Invalid {
        detail: format!("failed to serialise generation commitment: {e}"),
    })?;
    let entry = keyring_core::Entry::new(&entry_ref.service, &entry_ref.account).map_err(|e| {
        WindowStoreError::Keyring {
            detail: format!("generation entry open failed: {e}"),
        }
    })?;
    entry
        .set_password(&value)
        .map_err(|e| WindowStoreError::Keyring {
            detail: format!("generation entry write failed: {e}"),
        })
}

#[cfg(test)]
fn bump_generation(entry_ref: &KeyringEntryRef) -> Result<u64, WindowStoreError> {
    let next = next_generation(entry_ref)?;
    keyring_core::Entry::new(&entry_ref.service, &entry_ref.account)
        .and_then(|entry| entry.set_password(&next.to_string()))
        .map_err(|e| WindowStoreError::Keyring {
            detail: format!("generation entry write failed: {e}"),
        })?;
    Ok(next)
}

fn compute_tag(key: &[u8], body: &[u8]) -> Result<[u8; HMAC_TAG_LEN], WindowStoreError> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|e| WindowStoreError::Invalid {
        detail: format!("HMAC key construction failed: {e}"),
    })?;
    mac.update(HMAC_CONTEXT_LABEL);
    mac.update(body);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; HMAC_TAG_LEN];
    out.copy_from_slice(&tag);
    Ok(out)
}

fn now_ms() -> Result<u64, WindowStoreError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .map_err(|e| WindowStoreError::Invalid {
            detail: format!("system clock is before UNIX epoch: {e}"),
        })
}

/// Drops records that have aged out of the retention window.
///
/// A pending reservation is kept whatever its age. It holds the operator's cap
/// for a submission whose outcome is still unknown, and dropping it would stop
/// that spend counting and take the record out of reconciliation's reach while
/// its receipt still reports pending. A reservation that old is resolved by
/// `tx status` or by `tx receipt clear`, not by the clock.
fn prune_stale(wire: &mut WireFile, now_ms: u64) {
    let cutoff = now_ms.saturating_sub(RETENTION_MS);
    for bucket in &mut wire.entries {
        bucket
            .records
            .retain(|r| r.ts_ms >= cutoff || r.status == RecordStatus::Pending);
    }
    wire.entries.retain(|b| !b.records.is_empty());
}

/// Whether the receipt for `envelope_hash` already records an outcome the
/// endpoint cannot resolve.
fn outcome_already_unknown(known: &HashMap<String, ReceiptStatus>, envelope_hash: &str) -> bool {
    matches!(
        known.get(envelope_hash),
        Some(ReceiptStatus::Ambiguous | ReceiptStatus::ClearedByOperator)
    )
}

/// What one reservation's reconciliation established.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Settlement {
    /// The transaction reached a ledger; the reservation became real spend.
    Confirmed {
        /// The ledger the endpoint reported it in.
        ledger: Option<u32>,
    },
    /// The transaction can no longer apply; the reservation was removed.
    ///
    /// `code` is present only when the chain itself reported the failure. A
    /// release the endpoint never confirmed leaves the outcome unknown, and an
    /// unknown outcome is what the pending audit row already records.
    Released {
        /// The wire code of the on-chain failure, when the chain reported one.
        code: Option<String>,
    },
    /// Nothing was established; the reservation stands.
    KeptPending,
    /// The endpoint no longer holds the ledger range the submission was made
    /// in, so it cannot answer; the reservation stands for an operator.
    RetentionExpired,
}

/// Builds the settlement identity of a submission from its receipt, for a
/// submission that holds no window reservation.
///
/// Only a receipt still awaiting an answer is settled this way: one the chain
/// has already answered for needs no round trip.
fn reservation_from_receipt(receipts: &ReceiptStore, id: &str) -> Option<WindowReservation> {
    let receipt = receipts.get(id).ok().flatten()?;
    if receipt.status.is_terminal() || receipt.tx_hash.is_empty() {
        return None;
    }
    Some(WindowReservation {
        id: receipt.envelope_hash,
        tx_hash: receipt.tx_hash,
        source: receipt.source,
        sequence: receipt.sequence,
        max_time: receipt.max_time,
        pending_since_ms: 0,
        submission_ledger: receipt.recorded_at_ledger,
        operator_required: false,
    })
}

/// Records a terminal status on the receipt a reservation belongs to.
///
/// The reservation has already been settled in the window file by the time
/// this runs, so a receipt-store failure is logged and does not undo it: the
/// window file is the accounting record, the receipt the reconciliation
/// handle.
fn finalize_receipt(
    receipts: Option<&ReceiptStore>,
    reservation: &WindowReservation,
    status: ReceiptStatus,
    ledger: Option<u32>,
) {
    let Some(store) = receipts else {
        return;
    };
    let persist = || {
        if store.get(&reservation.id)?.is_none() {
            if !status.is_definitive_outcome() {
                return Ok(());
            }
            store.try_begin(
                &reservation.id,
                &reservation.tx_hash,
                &reservation.source,
                reservation.sequence,
                reservation.max_time,
                reservation.submission_ledger,
            )?;
            store.mark_submitted(&reservation.id)?;
        }
        store.finalize(&reservation.id, status, ledger)
    };
    if let Err(e) = persist() {
        tracing::warn!(
            error = %e,
            "window reconcile: receipt finalize failed; the window file is settled and the \
             receipt still reports the prior status"
        );
    }
}

/// Collects one [`WindowReservation`] per distinct pending reservation id,
/// oldest first by the time the reservation was taken.
/// Counts one settlement into `report`, and records what the caller owes an
/// audit row for.
///
/// Only a definitive answer from the chain settles a submission's value
/// action. A release the endpoint never confirmed leaves the outcome unknown,
/// which is what the pending row already records.
fn record_settlement(
    report: &mut ReconcileReport,
    reservation: &WindowReservation,
    settlement: Settlement,
) {
    match settlement {
        Settlement::Confirmed { ledger } => {
            report.confirmed += 1;
            report.settled.push(SettledSubmission {
                envelope_hash: reservation.id.clone(),
                tx_hash: reservation.tx_hash.clone(),
                status: ReceiptStatus::Success,
                ledger,
            });
        }
        Settlement::Released { code } => {
            report.released += 1;
            if let Some(code) = code {
                report.settled.push(SettledSubmission {
                    envelope_hash: reservation.id.clone(),
                    tx_hash: reservation.tx_hash.clone(),
                    status: ReceiptStatus::Failed { code },
                    ledger: None,
                });
            }
        }
        Settlement::KeptPending => report.kept_pending += 1,
        Settlement::RetentionExpired => report.retention_expired += 1,
    }
}

/// Resolves a verified prepared image against the trusted keyring counter.
///
/// A candidate is adopted only against a commitment that carries a digest.
/// Every commit of a candidate writes one, so a numeric counter has never
/// committed a candidate and a numeric counter equal to a candidate's
/// generation is refused.
fn select_generation(
    mut wire: WireFile,
    counter: Option<GenerationState>,
) -> Result<WireFile, WindowStoreError> {
    if let Some(next) = &wire.prepared
        && (wire.version != WIRE_VERSION
            || next.version != WIRE_VERSION
            || next.prepared.is_some()
            || wire.generation.checked_add(1) != Some(next.generation))
    {
        return Err(WindowStoreError::GenerationMismatch);
    }
    let counter = counter.ok_or(WindowStoreError::GenerationMismatch)?;
    if counter.generation == wire.generation {
        wire.prepared = None;
    } else if counter.body_sha256.is_some()
        && let Some(next) = wire.prepared
        && counter.generation == next.generation
    {
        wire = *next;
    } else {
        return Err(WindowStoreError::GenerationMismatch);
    }
    if let Some(expected) = counter.body_sha256
        && expected != body_digest(&wire)?
    {
        return Err(WindowStoreError::GenerationMismatch);
    }
    Ok(wire)
}

fn collect_pending(wire: &WireFile) -> Vec<WindowReservation> {
    let mut seen: Vec<WindowReservation> = Vec::new();
    for bucket in &wire.entries {
        for record in &bucket.records {
            if record.status != RecordStatus::Pending || record.id.is_empty() {
                continue;
            }
            if seen.iter().any(|r| r.id == record.id) {
                continue;
            }
            seen.push(WindowReservation {
                id: record.id.clone(),
                tx_hash: record.tx_hash.clone(),
                source: record.source.clone(),
                sequence: record.sequence,
                max_time: record.max_time,
                pending_since_ms: record.pending_since_ms,
                submission_ledger: record.submission_ledger,
                operator_required: record.operator_required,
            });
        }
    }
    seen.sort_by(|a, b| {
        a.pending_since_ms
            .cmp(&b.pending_since_ms)
            .then_with(|| a.id.cmp(&b.id))
    });
    seen
}

fn find_or_insert_bucket<'a>(
    entries: &'a mut Vec<WireBucket>,
    key: &StateKey,
) -> &'a mut WireBucket {
    let idx = entries.iter().position(|b| {
        b.scope_specificity == key.scope_specificity()
            && b.bucket == key.bucket()
            && b.window_secs == key.window_secs()
    });
    let idx = idx.unwrap_or_else(|| {
        entries.push(WireBucket {
            scope_specificity: key.scope_specificity(),
            bucket: key.bucket().to_owned(),
            window_secs: key.window_secs(),
            records: Vec::new(),
        });
        entries.len() - 1
    });
    &mut entries[idx]
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use std::path::Path;

    use serial_test::serial;

    use super::*;
    use stellar_agent_test_support::keyring_mock;
    use tempfile::TempDir;

    fn test_profile(dir: &Path, name: &str) -> Profile {
        let mut p = Profile::builder_testnet(name, "acct", "n-svc", "n-acct").build();
        p.policy_window_state_key_id =
            stellar_agent_core::profile::schema::KeyringEntryRef::default_policy_window_state_key(
                name,
            );
        p.audit_log_path = dir.join("audit.jsonl");
        p
    }

    fn key(profile_name: &str, bucket: &str, window_secs: u64) -> StateKey {
        StateKey::new(profile_name, 1, bucket, window_secs)
    }

    // ── round-trip matrix ────────────────────────────────────────────────

    #[test]
    #[serial]
    fn fresh_store_load_into_appends_nothing() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "fresh");
        let store = PersistedWindowStore::at_path(dir.path().join("fresh.window"));
        let dest = PolicyStateStore::new();
        store.load_into("fresh", &profile, &dest).unwrap();
        let (sum, count) = dest
            .query_window(&key("fresh", "native", 86_400), now_ms().unwrap())
            .unwrap();
        assert_eq!((sum, count), (0, 0));
    }

    #[test]
    #[serial]
    fn record_then_load_into_round_trips_accumulated_entries() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "acc");
        let store = PersistedWindowStore::at_path(dir.path().join("acc.window"));
        let k = key("acc", "native", 86_400);
        let now = now_ms().unwrap();
        let outcome = store
            .record_and_persist(&profile, &[(k.clone(), now, 500_000_000)])
            .unwrap();
        assert!(outcome.newly_minted, "first write mints the key");

        let dest = PolicyStateStore::new();
        store.load_into("acc", &profile, &dest).unwrap();
        let (sum, count) = dest.query_window(&k, now + 1_000).unwrap();
        assert_eq!(sum, 500_000_000);
        assert_eq!(count, 1);
    }

    #[test]
    #[serial]
    fn second_record_does_not_re_mint_and_accumulates() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "acc2");
        let store = PersistedWindowStore::at_path(dir.path().join("acc2.window"));
        let k = key("acc2", "native", 86_400);
        let now = now_ms().unwrap();
        store
            .record_and_persist(&profile, &[(k.clone(), now, 100)])
            .unwrap();
        let outcome2 = store
            .record_and_persist(&profile, &[(k.clone(), now, 200)])
            .unwrap();
        assert!(!outcome2.newly_minted, "second write reuses the minted key");

        let dest = PolicyStateStore::new();
        store.load_into("acc2", &profile, &dest).unwrap();
        let (sum, count) = dest.query_window(&k, now + 1_000).unwrap();
        assert_eq!(sum, 300);
        assert_eq!(count, 2);
    }

    /// Above-`i64::MAX` amounts round-trip exactly (`i128` decimal-string
    /// wire form, not a bare JSON number).
    #[test]
    #[serial]
    fn round_trip_amount_above_i64_max_is_exact() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "big");
        let store = PersistedWindowStore::at_path(dir.path().join("big.window"));
        let k = key("big", "native", 86_400);
        let now = now_ms().unwrap();
        let beyond = i128::from(i64::MAX) + 1_000;
        store
            .record_and_persist(&profile, &[(k.clone(), now, beyond)])
            .unwrap();

        let dest = PolicyStateStore::new();
        store.load_into("big", &profile, &dest).unwrap();
        let (sum, _) = dest.query_window(&k, now + 1_000).unwrap();
        assert_eq!(sum, beyond);
    }

    /// Entries older than the 1-week retention ceiling are pruned on write.
    #[test]
    #[serial]
    fn post_prune_old_entries_are_dropped() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "prune");
        let store = PersistedWindowStore::at_path(dir.path().join("prune.window"));
        let k = key("prune", "native", 86_400);
        let now = now_ms().unwrap();
        let ancient = now.saturating_sub(RETENTION_MS + 1_000);
        store
            .record_and_persist(&profile, &[(k.clone(), ancient, 999)])
            .unwrap();
        // A second write triggers pruning against the ancient entry.
        store
            .record_and_persist(&profile, &[(k.clone(), now, 1)])
            .unwrap();

        let dest = PolicyStateStore::new();
        store.load_into("prune", &profile, &dest).unwrap();
        let (sum, count) = dest.query_window(&k, now + 1_000).unwrap();
        assert_eq!(sum, 1, "the ancient entry must be pruned");
        assert_eq!(count, 1);
    }

    // ── HMAC tamper ──────────────────────────────────────────────────────

    #[test]
    #[serial]
    fn tampered_file_fails_closed_on_load() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "tamper");
        let path = dir.path().join("tamper.window");
        let store = PersistedWindowStore::at_path(path.clone());
        let k = key("tamper", "native", 86_400);
        store
            .record_and_persist(&profile, &[(k, now_ms().unwrap(), 500)])
            .unwrap();

        // Flip a byte in the body (past the 32-byte tag prefix).
        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        fs::write(&path, bytes).unwrap();

        let dest = PolicyStateStore::new();
        let result = store.load_into("tamper", &profile, &dest);
        assert!(matches!(result, Err(WindowStoreError::HmacMismatch)));
    }

    #[test]
    #[serial]
    fn tampered_file_fails_closed_on_record() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "tamper2");
        let path = dir.path().join("tamper2.window");
        let store = PersistedWindowStore::at_path(path.clone());
        let k = key("tamper2", "native", 86_400);
        store
            .record_and_persist(&profile, &[(k.clone(), now_ms().unwrap(), 500)])
            .unwrap();

        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        fs::write(&path, bytes).unwrap();

        let result = store.record_and_persist(&profile, &[(k, now_ms().unwrap(), 1)]);
        assert!(matches!(result, Err(WindowStoreError::HmacMismatch)));
    }

    // ── lock contention ──────────────────────────────────────────────────

    #[test]
    #[serial]
    fn concurrent_record_calls_are_serialised_not_lost() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "lockt");
        let path = dir.path().join("lockt.window");
        let store = PersistedWindowStore::at_path(path);
        let k = key("lockt", "native", 86_400);
        let now = now_ms().unwrap();

        // Two sequential handles (simulating two dispatches) both succeed and
        // their entries are both present — the lock serialises rather than
        // drops either writer.
        store
            .record_and_persist(&profile, &[(k.clone(), now, 10)])
            .unwrap();
        store
            .record_and_persist(&profile, &[(k.clone(), now, 20)])
            .unwrap();

        let dest = PolicyStateStore::new();
        store.load_into("lockt", &profile, &dest).unwrap();
        let (sum, count) = dest.query_window(&k, now + 1_000).unwrap();
        assert_eq!(sum, 30);
        assert_eq!(count, 2);
    }

    #[test]
    fn held_lock_blocks_a_second_writer() {
        let dir = TempDir::new().unwrap();
        let lock_path = dir.path().join("held.window.lock");
        let _held = WindowStoreLock::acquire(&lock_path).unwrap();
        let result = WindowStoreLock::acquire(&lock_path);
        assert!(matches!(result, Err(WindowStoreError::WriterLocked)));
    }

    // ── atomic-write crash-surface ───────────────────────────────────────

    /// A leftover `.tmp` file from a crashed prior write does not block the
    /// next successful write (the next write creates+truncates its own temp
    /// file and renames over the leftover).
    #[test]
    #[serial]
    fn leftover_temp_file_does_not_block_next_write() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "crash");
        let path = dir.path().join("crash.window");
        fs::write(path.with_file_name("crash.window.tmp"), b"leftover-garbage").unwrap();

        let store = PersistedWindowStore::at_path(path);
        let k = key("crash", "native", 86_400);
        let now = now_ms().unwrap();
        store
            .record_and_persist(&profile, &[(k.clone(), now, 42)])
            .unwrap();

        let dest = PolicyStateStore::new();
        store.load_into("crash", &profile, &dest).unwrap();
        let (sum, _) = dest.query_window(&k, now + 1_000).unwrap();
        assert_eq!(sum, 42);
    }

    // ── reset ────────────────────────────────────────────────────────────

    #[test]
    #[serial]
    fn reset_clears_accumulated_history() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "reset");
        let path = dir.path().join("reset.window");
        let store = PersistedWindowStore::at_path(path);
        let k = key("reset", "native", 86_400);
        let now = now_ms().unwrap();
        store
            .record_and_persist(&profile, &[(k.clone(), now, 999)])
            .unwrap();

        let outcome = store.reset(&profile).unwrap();
        assert!(
            !outcome.newly_minted,
            "the key was already minted by record_and_persist"
        );

        let dest = PolicyStateStore::new();
        store.load_into("reset", &profile, &dest).unwrap();
        let (sum, count) = dest.query_window(&k, now + 1_000).unwrap();
        assert_eq!((sum, count), (0, 0), "reset must clear all history");
    }

    // ── resign ───────────────────────────────────────────────────────────

    #[test]
    #[serial]
    fn resign_then_load_with_new_key_reads_green() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let mut profile = test_profile(dir.path(), "resign");
        let path = dir.path().join("resign.window");
        let store = PersistedWindowStore::at_path(path);
        let k = key("resign", "native", 86_400);
        let now = now_ms().unwrap();
        store
            .record_and_persist(&profile, &[(k.clone(), now, 777)])
            .unwrap();

        // Rotate: mint a NEW key at the same keyring coordinate, then re-sign.
        let entry_ref = &profile.policy_window_state_key_id;
        crate::keyring::rotate_keyring_secret_32(&entry_ref.service, &entry_ref.account).unwrap();
        let new_key = crate::keyring::load_hmac_key_32(entry_ref).unwrap();
        store.resign(&new_key).unwrap();

        // load_into re-reads the (now-current) keyring key internally.
        let dest = PolicyStateStore::new();
        store.load_into("resign", &profile, &dest).unwrap();
        let (sum, _) = dest.query_window(&k, now + 1_000).unwrap();
        assert_eq!(
            sum, 777,
            "re-signed store must read green under the new key"
        );

        // Silence an unused-mut warning if the profile is never mutated
        // beyond construction in this test.
        let _ = &mut profile;
    }

    // ── anti-rollback generation counter ────────────────────────────────

    /// No file, no keyring generation entry: `load_into` initializes cleanly
    /// (empty history, no error), and the subsequent first write mints both
    /// the HMAC key and generation=1.
    #[test]
    #[serial]
    fn first_run_initializes_cleanly_with_no_prior_state() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "firstrun");
        let store = PersistedWindowStore::at_path(dir.path().join("firstrun.window"));

        let dest = PolicyStateStore::new();
        store.load_into("firstrun", &profile, &dest).unwrap();
        let (sum, count) = dest
            .query_window(&key("firstrun", "native", 86_400), now_ms().unwrap())
            .unwrap();
        assert_eq!((sum, count), (0, 0));

        let k = key("firstrun", "native", 86_400);
        let now = now_ms().unwrap();
        let outcome = store
            .record_and_persist(&profile, &[(k.clone(), now, 111)])
            .unwrap();
        assert!(outcome.newly_minted);

        let dest2 = PolicyStateStore::new();
        store.load_into("firstrun", &profile, &dest2).unwrap();
        let (sum, _) = dest2.query_window(&k, now + 1_000).unwrap();
        assert_eq!(sum, 111);
    }

    /// Deleting the store file after it has been used (the keyring
    /// generation is minted and non-zero) is detected as a deletion:
    /// `load_into` fails closed instead of silently treating the missing
    /// file as a fresh first run.
    #[test]
    #[serial]
    fn deletion_after_use_fails_closed() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "deleted");
        let path = dir.path().join("deleted.window");
        let store = PersistedWindowStore::at_path(path.clone());
        let k = key("deleted", "native", 86_400);
        store
            .record_and_persist(&profile, &[(k, now_ms().unwrap(), 500)])
            .unwrap();

        fs::remove_file(&path).unwrap();

        let dest = PolicyStateStore::new();
        let result = store.load_into("deleted", &profile, &dest);
        assert!(
            matches!(result, Err(WindowStoreError::GenerationMismatch)),
            "a missing file with a minted keyring generation must fail closed, got {result:?}"
        );
    }

    /// Restoring an OLDER, validly-HMAC-signed snapshot of the store file
    /// (e.g. from a stale backup) after the generation has moved on is a
    /// rollback attempt. The HMAC alone would verify — it was genuinely
    /// signed under the same key when written — so only the generation
    /// check catches this.
    #[test]
    #[serial]
    fn rollback_to_older_valid_file_fails_closed() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "rollback");
        let path = dir.path().join("rollback.window");
        let store = PersistedWindowStore::at_path(path.clone());
        let k = key("rollback", "native", 86_400);
        let now = now_ms().unwrap();

        store
            .record_and_persist(&profile, &[(k.clone(), now, 100)])
            .unwrap();
        // Snapshot the validly-signed generation=1 file bytes before the
        // second write bumps the generation to 2.
        let old_bytes = fs::read(&path).unwrap();

        store
            .record_and_persist(&profile, &[(k.clone(), now, 200)])
            .unwrap();

        // Restore the older (generation=1) snapshot: still a valid HMAC tag
        // under the current key, but behind the keyring's generation=2.
        fs::write(&path, &old_bytes).unwrap();

        let dest = PolicyStateStore::new();
        let result = store.load_into("rollback", &profile, &dest);
        assert!(
            matches!(result, Err(WindowStoreError::GenerationMismatch)),
            "a validly-signed but stale-generation file must fail closed, got {result:?}"
        );
    }

    /// Simulates a crash between the keyring generation bump and the
    /// following file write completing (the keyring-first ordering
    /// `record_and_persist` documents): the keyring is ahead of the file.
    /// `load_into` fails closed, and `reset` recovers by re-baselining both
    /// to a new, consistent generation.
    #[test]
    #[serial]
    fn crash_ordering_keyring_ahead_of_file_fails_closed_and_reset_recovers() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "crashgen");
        let path = dir.path().join("crashgen.window");
        let store = PersistedWindowStore::at_path(path);
        let k = key("crashgen", "native", 86_400);
        let now = now_ms().unwrap();

        store
            .record_and_persist(&profile, &[(k.clone(), now, 50)])
            .unwrap();

        // Simulate the crash: bump the keyring generation as
        // `record_and_persist` would at its keyring-first step, WITHOUT the
        // file write that should follow it.
        let gen_entry = generation_entry_ref(&profile);
        bump_generation(&gen_entry).unwrap();

        let dest = PolicyStateStore::new();
        let result = store.load_into("crashgen", &profile, &dest);
        assert!(
            matches!(result, Err(WindowStoreError::GenerationMismatch)),
            "keyring ahead of the file must fail closed, got {result:?}"
        );

        // reset re-baselines both — recovery succeeds and the store reads
        // empty (the pre-crash history is unrecoverable, by design: the
        // store cannot know whether the un-persisted write was legitimate).
        store.reset(&profile).unwrap();
        let dest2 = PolicyStateStore::new();
        store.load_into("crashgen", &profile, &dest2).unwrap();
        let (sum, count) = dest2.query_window(&k, now + 1_000).unwrap();
        assert_eq!(
            (sum, count),
            (0, 0),
            "reset must recover to an empty, consistent state"
        );
    }

    // ── end-to-end persist seam ─────────────────────────────────────────

    /// The full persist → fresh-load → fresh-engine round trip: a first
    /// "process" (fresh in-memory store hydrated from an empty file, fresh
    /// `PolicyEngineV1`) evaluates and confirms a payment, persisting the
    /// derived window-state entries to disk. A second, entirely independent
    /// "process" (a NEW `PolicyStateStore` hydrated from that file, a NEW
    /// `PolicyEngineV1` over it) evaluates the identical payment again and
    /// is DENIED — proving the persisted state, not merely in-memory
    /// accumulation within one engine instance, drives the second decision.
    /// (`record_confirmed_per_period_cap_accumulates_then_second_call_denies`
    /// in `stellar-agent-core` covers the in-memory-only case; this test is
    /// the seam that case cannot reach, since `stellar-agent-core` cannot
    /// depend on `stellar-agent-network`.)
    #[test]
    #[serial]
    fn end_to_end_persist_seam_second_process_denies() {
        use stellar_agent_core::policy::ToolValueKind;
        use stellar_agent_core::policy::v1::criteria::per_period_cap::{
            PerPeriodCapCriterion, Window,
        };
        use stellar_agent_core::policy::v1::value::{
            ActionKind, ValueClass, ValueEffects, ValueLeg,
        };
        use stellar_agent_core::{
            Decision, DenyReason, McpToolRegistration, PolicyDocument, PolicyEngine,
            PolicyEngineV1, PolicyRule, RuleMatch, ScopeId, ToolDescriptor,
        };

        fn allow_all_with_per_period_cap() -> PolicyDocument {
            // Cap: 100 XLM. Each call attempts 60 XLM.
            let window = Window::parse("1d").unwrap();
            let criterion = PerPeriodCapCriterion::new("native".into(), window, 1_000_000_000);
            PolicyDocument {
                version: 1,
                scope: ScopeId::AllProfiles,
                rules: vec![PolicyRule {
                    r#match: RuleMatch {
                        tool: "*".into(),
                        chain: "*".into(),
                    },
                    criteria: vec![Box::new(criterion)],
                    decision: Decision::Allow,
                    allow_opaque_signing: false,
                }],
                signature: None,
            }
        }

        fn pay_tool() -> ToolDescriptor {
            let mut td = ToolDescriptor::from_registration(&McpToolRegistration {
                name: "stellar_pay",
                destructive_hint: false,
                read_only_hint: false,
                chain_id_required: false,
                value_kind: ToolValueKind::MovesValue,
            });
            td.chain_id = "stellar:testnet".to_owned();
            td
        }

        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "seam");
        let store = PersistedWindowStore::at_path(dir.path().join("seam.window"));
        let td = pay_tool();
        let value = ValueClass::Value(ValueEffects::single(ValueLeg {
            kind: ActionKind::Payment,
            amount: Some(600_000_000),
            asset: Some("native".to_owned()),
            destination: Some("GAAA".to_owned()),
        }));

        // "Process" 1: fresh store hydrated from disk (empty — genuine first
        // run), evaluate → Allow, record_confirmed → derive entries, persist.
        let fresh1 = PolicyStateStore::new();
        store.load_into("seam", &profile, &fresh1).unwrap();
        let engine1 =
            PolicyEngineV1::new_with_store(allow_all_with_per_period_cap(), "seam".into(), fresh1);
        let d1 = engine1
            .evaluate_with_value(
                &td,
                &serde_json::Value::Null,
                &profile,
                value.clone(),
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();
        assert_eq!(d1, Decision::Allow, "first call must be allowed");
        let recorded = engine1.record_confirmed(&td, &profile, &value).unwrap();
        assert_eq!(recorded.len(), 1, "exactly one debit entry recorded");
        store.record_and_persist(&profile, &recorded).unwrap();

        // "Process" 2: an entirely fresh PolicyStateStore hydrated from the
        // file `store` just wrote, and a fresh PolicyEngineV1 over it. The
        // identical call now DENIES: 60 + 60 = 120 XLM exceeds the 100 XLM
        // cap, and the 60 XLM from "process" 1 is visible ONLY because it
        // was persisted to disk and re-hydrated — this engine instance never
        // saw the first call.
        let fresh2 = PolicyStateStore::new();
        store.load_into("seam", &profile, &fresh2).unwrap();
        let engine2 =
            PolicyEngineV1::new_with_store(allow_all_with_per_period_cap(), "seam".into(), fresh2);
        let d2 = engine2
            .evaluate_with_value(
                &td,
                &serde_json::Value::Null,
                &profile,
                value,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();
        assert!(
            matches!(d2, Decision::Deny(DenyReason::PerPeriodCapExceeded { .. })),
            "second process's identical call must be denied by persisted state, got {d2:?}"
        );
    }

    // ── reservations ────────────────────────────────────────────────────

    fn reservation(
        id: &str,
        source: &str,
        sequence: i64,
        pending_since_ms: u64,
    ) -> WindowReservation {
        WindowReservation {
            id: id.to_owned(),
            tx_hash: "ab".repeat(32),
            source: source.to_owned(),
            sequence,
            max_time: 0,
            pending_since_ms,
            submission_ledger: 1_000,
            operator_required: false,
        }
    }

    /// A reservation counts against a window criterion exactly as confirmed
    /// spend does: the transaction has been sent and may apply.
    #[test]
    #[serial]
    fn a_pending_reservation_counts_toward_the_window_total() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "resv-count");
        let store = PersistedWindowStore::at_path(dir.path().join("resv-count.window"));
        let k = key("resv-count", "native", 86_400);
        let now = now_ms().unwrap();

        store
            .record_pending(
                &profile,
                &[(k.clone(), now, 600_000_000)],
                &reservation("a".repeat(64).as_str(), "GSOURCE", 7, now),
            )
            .unwrap();

        let dest = PolicyStateStore::new();
        store.load_into("resv-count", &profile, &dest).unwrap();
        let (sum, count) = dest.query_window(&k, now + 1_000).unwrap();
        assert_eq!(
            (sum, count),
            (600_000_000, 1),
            "a pending reservation must count against the window like confirmed spend"
        );
    }

    /// Confirming a reservation keeps its records and stops them being
    /// reported as open.
    #[test]
    #[serial]
    fn confirm_keeps_the_records_and_closes_the_reservation() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "resv-confirm");
        let store = PersistedWindowStore::at_path(dir.path().join("resv-confirm.window"));
        let k = key("resv-confirm", "native", 86_400);
        let now = now_ms().unwrap();
        let id = "b".repeat(64);

        store
            .record_pending(
                &profile,
                &[(k.clone(), now, 250)],
                &reservation(&id, "GSOURCE", 7, now),
            )
            .unwrap();
        assert_eq!(store.pending_reservations(&profile).unwrap().len(), 1);

        store
            .confirm(&profile, &id, Some((now / 1_000) as i64))
            .unwrap();

        assert!(
            store.pending_reservations(&profile).unwrap().is_empty(),
            "a confirmed reservation is no longer open"
        );
        let dest = PolicyStateStore::new();
        store.load_into("resv-confirm", &profile, &dest).unwrap();
        let (sum, count) = dest.query_window(&k, now + 1_000).unwrap();
        assert_eq!(
            (sum, count),
            (250, 1),
            "confirming keeps the spend: the transaction reached a ledger"
        );
    }

    /// Releasing a reservation removes its records, so the reserved amount
    /// stops counting against the window.
    #[test]
    #[serial]
    fn release_removes_the_records() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "resv-release");
        let store = PersistedWindowStore::at_path(dir.path().join("resv-release.window"));
        let k = key("resv-release", "native", 86_400);
        let now = now_ms().unwrap();
        let id = "c".repeat(64);

        store
            .record_pending(
                &profile,
                &[(k.clone(), now, 900)],
                &reservation(&id, "GSOURCE", 7, now),
            )
            .unwrap();
        store.release(&profile, &id).unwrap();

        assert!(store.pending_reservations(&profile).unwrap().is_empty());
        let dest = PolicyStateStore::new();
        store.load_into("resv-release", &profile, &dest).unwrap();
        let (sum, count) = dest.query_window(&k, now + 1_000).unwrap();
        assert_eq!(
            (sum, count),
            (0, 0),
            "a released reservation stops counting against the window"
        );
    }

    /// Reservations are reported oldest first, so a bounded reconciliation
    /// pass settles the ones that have stood longest.
    #[test]
    #[serial]
    fn pending_reservations_are_reported_oldest_first() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "resv-order");
        let store = PersistedWindowStore::at_path(dir.path().join("resv-order.window"));
        let k = key("resv-order", "native", 86_400);
        let now = now_ms().unwrap();

        for (index, offset) in [(0_u8, 30_000_u64), (1, 10_000), (2, 20_000)] {
            let id = format!("{index:064}");
            store
                .record_pending(
                    &profile,
                    &[(k.clone(), now, 1)],
                    &reservation(&id, "GSOURCE", i64::from(index), now - offset),
                )
                .unwrap();
        }

        let open = store.pending_reservations(&profile).unwrap();
        let ages: Vec<u64> = open.iter().map(|r| r.pending_since_ms).collect();
        assert_eq!(
            ages,
            vec![now - 30_000, now - 20_000, now - 10_000],
            "reservations must be reported oldest first"
        );
    }

    // ── wire version ────────────────────────────────────────────────────

    /// Rewrites the store file's body with `mutate` applied, re-signing under
    /// the profile's key so the tag stays valid.
    fn rewrite_body_version(store: &PersistedWindowStore, profile: &Profile, version: u32) {
        let key = crate::keyring::load_hmac_key_32(&profile.policy_window_state_key_id).unwrap();
        let bytes = fs::read(&store.path).unwrap();
        let mut wire: serde_json::Value = serde_json::from_slice(&bytes[HMAC_TAG_LEN..]).unwrap();
        wire["version"] = serde_json::json!(version);
        let gen_entry = generation_entry_ref(profile);
        keyring_core::Entry::new(&gen_entry.service, &gen_entry.account)
            .unwrap()
            .set_password(&wire["generation"].as_u64().unwrap().to_string())
            .unwrap();
        if version == 1 {
            for bucket in wire["entries"].as_array_mut().unwrap() {
                for record in bucket["records"].as_array_mut().unwrap() {
                    record
                        .as_object_mut()
                        .unwrap()
                        .retain(|name, _| name == "ts_ms" || name == "amount");
                }
            }
        }
        if version == 2 {
            for bucket in wire["entries"].as_array_mut().unwrap() {
                for record in bucket["records"].as_array_mut().unwrap() {
                    record.as_object_mut().unwrap().remove("operator_required");
                }
            }
        }
        let body = serde_json::to_vec(&wire).unwrap();
        let tag = compute_tag(key.as_slice(), &body).unwrap();
        store.write_atomic_raw(&tag, &body).unwrap();
    }

    /// A v1 file contains confirmed spend and no open reservation identity.
    #[test]
    #[serial]
    fn a_v1_file_reads_as_confirmed() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "v1-read");
        let store = PersistedWindowStore::at_path(dir.path().join("v1-read.window"));
        let k = key("v1-read", "native", 86_400);
        let now = now_ms().unwrap();
        store
            .record_and_persist(&profile, &[(k.clone(), now, 4_200)])
            .unwrap();
        rewrite_body_version(&store, &profile, 1);

        let original = fs::read(&store.path).unwrap();
        let dest = PolicyStateStore::new();
        store.load_into("v1-read", &profile, &dest).unwrap();
        assert_eq!(
            fs::read(&store.path).unwrap(),
            original,
            "hydration leaves v1 bytes unchanged"
        );
        assert_eq!(dest.query_window(&k, now + 1_000).unwrap(), (4_200, 1));
        assert_eq!(dest.query_window(&k, now + 86_400_001).unwrap(), (0, 0));
        assert!(
            store.pending_reservations(&profile).unwrap().is_empty(),
            "a v1 record carries no reservation to reconcile"
        );
    }

    /// A prepared settlement is selected only by its trusted generation;
    /// both crash checkpoints remain readable and a replayed old file is refused.
    #[test]
    #[serial]
    fn prepared_settlement_recovers_both_sides_of_the_commit_point() {
        for release in [false, true] {
            keyring_mock::install().unwrap();
            let dir = TempDir::new().unwrap();
            let profile = test_profile(dir.path(), "prepared-hold");
            let store = PersistedWindowStore::at_path(dir.path().join("prepared-hold.window"));
            let k = key("prepared-hold", "native", 86_400);
            let now = now_ms().unwrap();
            let res = reservation(&"c".repeat(64), "GSOURCE", 7, now);
            store
                .record_pending(&profile, &[(k.clone(), now, 43)], &res)
                .unwrap();
            let old_bytes = fs::read(&store.path).unwrap();
            let mut original = store.read_for_inspection(&profile).unwrap().unwrap();
            let mut next = original.clone();
            next.generation += 1;
            if release {
                next.entries.clear();
            } else {
                next.entries[0].records[0].operator_required = true;
            }
            original.prepared = Some(Box::new(next.clone()));
            let hmac_key =
                crate::keyring::load_hmac_key_32(&profile.policy_window_state_key_id).unwrap();
            store.write_atomic(&hmac_key, &original).unwrap();
            let prepared_bytes = fs::read(&store.path).unwrap();
            let reopened = PersistedWindowStore::at_path(store.path.clone());
            assert_eq!(
                reopened.pending_reservations(&profile).unwrap(),
                vec![res.clone()]
            );
            let memory = PolicyStateStore::new();
            reopened
                .load_into("prepared-hold", &profile, &memory)
                .unwrap();
            assert_eq!(memory.query_window(&k, now).unwrap(), (43, 1));
            write_generation(&generation_entry_ref(&profile), &next).unwrap();
            let held = reopened.pending_reservations(&profile).unwrap();
            assert_eq!(held.len(), usize::from(!release));
            if !release {
                assert!(held[0].operator_required);
            }
            let memory = PolicyStateStore::new();
            reopened
                .load_into("prepared-hold", &profile, &memory)
                .unwrap();
            assert_eq!(
                memory.query_window(&k, now).unwrap(),
                if release { (0, 0) } else { (43, 1) }
            );
            fs::write(&store.path, &old_bytes).unwrap();
            assert!(matches!(
                reopened.pending_reservations(&profile),
                Err(WindowStoreError::GenerationMismatch)
            ));
            fs::write(&store.path, &prepared_bytes).unwrap();
            reopened.release(&profile, &res.id).unwrap();
            assert!(reopened.pending_reservations(&profile).unwrap().is_empty());
        }
    }

    /// An abandoned candidate cannot replace a different committed body that
    /// receives the same generation number after retrying the write.
    #[test]
    #[serial]
    fn abandoned_candidate_cannot_replay_at_a_reused_generation() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "abandoned-candidate");
        let store = PersistedWindowStore::at_path(dir.path().join("abandoned-candidate.window"));
        let k = key("abandoned-candidate", "native", 86_400);
        let now = now_ms().unwrap();
        let res = reservation(&"e".repeat(64), "GSOURCE", 7, now);
        store
            .record_pending(&profile, &[(k.clone(), now, 45)], &res)
            .unwrap();
        let mut original = store.read_for_inspection(&profile).unwrap().unwrap();
        let mut abandoned = original.clone();
        abandoned.generation += 1;
        abandoned.entries.clear();
        original.prepared = Some(Box::new(abandoned));
        let hmac_key =
            crate::keyring::load_hmac_key_32(&profile.policy_window_state_key_id).unwrap();
        store.write_atomic(&hmac_key, &original).unwrap();
        let abandoned_bytes = fs::read(&store.path).unwrap();

        // A new debit commits while the abandoned release remains uncommitted.
        store
            .record_and_persist(&profile, &[(k.clone(), now, 5)])
            .unwrap();
        let committed_bytes = fs::read(&store.path).unwrap();
        assert_eq!(
            load_generation(&generation_entry_ref(&profile)).unwrap(),
            Some(original.generation + 1)
        );
        fs::write(&store.path, abandoned_bytes).unwrap();
        assert!(matches!(
            store.pending_reservations(&profile),
            Err(WindowStoreError::GenerationMismatch)
        ));
        assert!(matches!(
            store.load_into("abandoned-candidate", &profile, &PolicyStateStore::new()),
            Err(WindowStoreError::GenerationMismatch)
        ));
        assert!(matches!(
            store.release(&profile, &res.id),
            Err(WindowStoreError::GenerationMismatch)
        ));
        fs::write(&store.path, committed_bytes).unwrap();
        let memory = PolicyStateStore::new();
        store
            .load_into("abandoned-candidate", &profile, &memory)
            .unwrap();
        assert_eq!(memory.query_window(&k, now).unwrap(), (50, 2));
        assert_eq!(store.pending_reservations(&profile).unwrap(), vec![res]);
    }

    /// A failed prepare write cannot advance the trusted generation or hide a hold.
    #[test]
    #[serial]
    fn failed_prepare_write_keeps_the_authenticated_hold_readable() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "prepare-write-failure");
        let store = PersistedWindowStore::at_path(dir.path().join("prepare-write-failure.window"));
        let k = key("prepare-write-failure", "native", 86_400);
        let now = now_ms().unwrap();
        let res = reservation(&"d".repeat(64), "GSOURCE", 7, now);
        store
            .record_pending(&profile, &[(k.clone(), now, 44)], &res)
            .unwrap();
        let blocker = dir.path().join("prepare-write-failure.window.tmp");
        fs::create_dir(&blocker).unwrap();
        assert!(store.mark_operator_required(&profile, &res.id).is_err());
        assert_eq!(store.pending_reservations(&profile).unwrap(), vec![res]);
        let memory = PolicyStateStore::new();
        store
            .load_into("prepare-write-failure", &profile, &memory)
            .unwrap();
        assert_eq!(memory.query_window(&k, now).unwrap(), (44, 1));
    }

    /// A candidate is committed only by a digest-bearing keyring write, so a
    /// numeric counter equal to a candidate's generation is not a commitment
    /// of it and the file is refused. A numeric counter at the outer
    /// generation still reads the outer, which is the state a crash before
    /// the commit point leaves under a legacy counter.
    #[test]
    #[serial]
    fn a_numeric_counter_never_selects_a_candidate() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "numeric-candidate");
        let store = PersistedWindowStore::at_path(dir.path().join("numeric-candidate.window"));
        let k = key("numeric-candidate", "native", 86_400);
        let now = now_ms().unwrap();
        let res = reservation(&"f".repeat(64), "GSOURCE", 7, now);
        store
            .record_pending(&profile, &[(k.clone(), now, 46)], &res)
            .unwrap();
        let gen_entry = generation_entry_ref(&profile);
        let hmac_key =
            crate::keyring::load_hmac_key_32(&profile.policy_window_state_key_id).unwrap();
        let mut original = store.read_for_inspection(&profile).unwrap().unwrap();
        let mut candidate = original.clone();
        candidate.generation += 1;
        candidate.entries.clear();
        original.prepared = Some(Box::new(candidate.clone()));
        store.write_atomic(&hmac_key, &original).unwrap();
        let counter = keyring_core::Entry::new(&gen_entry.service, &gen_entry.account).unwrap();

        counter
            .set_password(&candidate.generation.to_string())
            .unwrap();
        assert!(matches!(
            store.pending_reservations(&profile),
            Err(WindowStoreError::GenerationMismatch)
        ));
        assert!(matches!(
            store.load_into("numeric-candidate", &profile, &PolicyStateStore::new()),
            Err(WindowStoreError::GenerationMismatch)
        ));
        assert!(matches!(
            store.release(&profile, &res.id),
            Err(WindowStoreError::GenerationMismatch)
        ));

        counter
            .set_password(&original.generation.to_string())
            .unwrap();
        assert_eq!(store.pending_reservations(&profile).unwrap(), vec![res]);
        let memory = PolicyStateStore::new();
        store
            .load_into("numeric-candidate", &profile, &memory)
            .unwrap();
        assert_eq!(memory.query_window(&k, now).unwrap(), (46, 1));
    }

    /// A keyring failure at the commit point, through the production commit:
    /// the prepared image is on disk, the counter is unchanged, the hold is
    /// still reported and counted, and a retry completes and compacts.
    ///
    /// The injected error is single-shot and lands on the commit write
    /// because the commit does not read the counter again after the
    /// verified read.
    #[test]
    #[serial]
    fn a_keyring_failure_at_the_commit_point_keeps_the_hold_and_the_retry_completes() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "commit-point");
        let store = PersistedWindowStore::at_path(dir.path().join("commit-point.window"));
        let k = key("commit-point", "native", 86_400);
        let now = now_ms().unwrap();
        let res = reservation(&"a".repeat(64), "GSOURCE", 7, now);
        store
            .record_pending(&profile, &[(k.clone(), now, 47)], &res)
            .unwrap();
        let gen_entry = generation_entry_ref(&profile);
        let counter = keyring_core::Entry::new(&gen_entry.service, &gen_entry.account).unwrap();
        let committed = counter.get_password().unwrap();
        let hmac_key =
            crate::keyring::load_hmac_key_32(&profile.policy_window_state_key_id).unwrap();
        let original = store.read_for_inspection(&profile).unwrap().unwrap();
        let mut next = original.clone();
        next.entries.clear();
        keyring_mock::inject_error(
            &gen_entry.service,
            &gen_entry.account,
            keyring_core::Error::NoStorageAccess(Box::new(std::io::Error::other(
                "keyring unavailable at the commit point",
            ))),
        )
        .unwrap();

        let result = store.commit_generation(&hmac_key, &gen_entry, original.clone(), next);
        assert!(
            matches!(result, Err(WindowStoreError::Keyring { .. })),
            "the commit must report the keyring failure, got {result:?}"
        );
        assert_eq!(counter.get_password().unwrap(), committed);
        let body: serde_json::Value =
            serde_json::from_slice(&fs::read(&store.path).unwrap()[HMAC_TAG_LEN..]).unwrap();
        assert_eq!(body["generation"], original.generation);
        assert_eq!(body["prepared"]["generation"], original.generation + 1);
        assert_eq!(
            store.pending_reservations(&profile).unwrap(),
            vec![res.clone()]
        );
        let memory = PolicyStateStore::new();
        store.load_into("commit-point", &profile, &memory).unwrap();
        assert_eq!(memory.query_window(&k, now).unwrap(), (47, 1));

        store.release(&profile, &res.id).unwrap();
        assert!(store.pending_reservations(&profile).unwrap().is_empty());
        let body: serde_json::Value =
            serde_json::from_slice(&fs::read(&store.path).unwrap()[HMAC_TAG_LEN..]).unwrap();
        assert!(
            body.get("prepared").is_none(),
            "a completed commit is compacted"
        );
        assert_eq!(body["generation"], original.generation + 1);
        assert_eq!(
            load_generation(&gen_entry).unwrap(),
            Some(original.generation + 1)
        );
    }

    /// Version 2 preserves pending identity and headroom without an operator marker.
    #[test]
    #[serial]
    fn a_v2_pending_file_keeps_its_hold() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "v2-hold");
        let store = PersistedWindowStore::at_path(dir.path().join("v2-hold.window"));
        let k = key("v2-hold", "native", 86_400);
        let now = now_ms().unwrap();
        let old = now - 14 * 86_400_000;
        let res = reservation(&"a".repeat(64), "GSOURCE", 7, old);
        store
            .record_pending(&profile, &[(k.clone(), old, 42)], &res)
            .unwrap();
        rewrite_body_version(&store, &profile, 2);
        let original = fs::read(&store.path).unwrap();
        let dest = PolicyStateStore::new();
        store.load_into("v2-hold", &profile, &dest).unwrap();
        assert_eq!(dest.query_window(&k, now).unwrap(), (42, 1));
        assert_eq!(store.pending_reservations(&profile).unwrap(), vec![res]);
        assert_eq!(fs::read(&store.path).unwrap(), original);
    }

    /// A file written by a newer build carries records this one cannot
    /// account for, so it is refused rather than read with the fields it
    /// happens to recognise.
    #[test]
    #[serial]
    fn a_newer_wire_version_is_refused() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "v3-read");
        let store = PersistedWindowStore::at_path(dir.path().join("v3-read.window"));
        let k = key("v3-read", "native", 86_400);
        let now = now_ms().unwrap();
        store.record_and_persist(&profile, &[(k, now, 1)]).unwrap();
        rewrite_body_version(&store, &profile, 4);

        let dest = PolicyStateStore::new();
        let err = store
            .load_into("v3-read", &profile, &dest)
            .expect_err("a newer wire version must be refused");
        assert!(
            matches!(err, WindowStoreError::Invalid { ref detail } if detail.contains("newer")),
            "the refusal must name the version condition; got {err:?}"
        );
    }

    /// The reconciliation budget and minimum age are the bound a value verb
    /// spends on reconciliation before its policy gate.
    #[test]
    fn reconcile_bounds_are_the_documented_values() {
        assert_eq!(RECONCILE_BUDGET, 5);
        assert_eq!(RECONCILE_MIN_AGE_MS, 300_000);
    }

    /// The window file is owner-read-write only on Unix.
    ///
    /// It holds account identifiers, sequence numbers and spend history, and
    /// the HMAC tag proves integrity, not confidentiality.
    #[cfg(unix)]
    #[test]
    #[serial]
    fn the_window_file_is_owner_only_on_unix() {
        use std::os::unix::fs::PermissionsExt as _;

        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "mode-guard");
        let path = dir.path().join("mode-guard.window");
        let store = PersistedWindowStore::at_path(path.clone());
        let k = key("mode-guard", "native", 86_400);
        let now = now_ms().unwrap();
        store.record_and_persist(&profile, &[(k, now, 1)]).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "the window file must be readable and writable by its owner alone; got {mode:o}"
        );
    }
}
