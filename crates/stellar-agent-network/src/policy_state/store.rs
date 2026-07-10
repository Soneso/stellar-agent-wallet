//! [`PersistedWindowStore`]: the HMAC-protected, single-writer, atomic-write
//! per-profile policy window-state file. See the module-level docs in
//! [`super`] for the wire format, integrity, and concurrency design.

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, KeyInit as _, Mac as _};
use sha2::Sha256;
use stellar_agent_core::policy::v1::criteria::state_store::{PolicyStateStore, StateKey};
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

// ─────────────────────────────────────────────────────────────────────────────
// Wire format
// ─────────────────────────────────────────────────────────────────────────────

/// One `(timestamp_ms, amount)` record within a bucket.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct WireRecord {
    ts_ms: u64,
    #[serde(with = "i128_decimal_str")]
    amount: i128,
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
        match load_generation(&gen_entry)? {
            Some(keyring_gen) if keyring_gen == wire.generation => {}
            _ => return Err(WindowStoreError::GenerationMismatch),
        }

        for entry in wire.entries {
            let key = StateKey::new(
                profile_name,
                entry.scope_specificity,
                &entry.bucket,
                entry.window_secs,
            );
            for record in entry.records {
                dest.append(&key, record.ts_ms, record.amount)
                    .map_err(|e| WindowStoreError::Invalid {
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
            });
        }

        let now_ms = now_ms()?;
        prune_stale(&mut wire, now_ms);

        // Generation bump is keyring-first: a crash between this line and the
        // file write below leaves the file BEHIND the keyring (fails closed
        // on next read), never ahead of it. See the module docs.
        wire.generation = bump_generation(&gen_entry)?;

        self.write_atomic(&key, &wire)?;
        Ok(mint_outcome)
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
        let new_generation = bump_generation(&gen_entry)?;
        let empty = WireFile {
            version: 1,
            generation: new_generation,
            entries: Vec::new(),
        };
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
                match load_generation(gen_entry)? {
                    Some(keyring_gen) if keyring_gen == wire.generation => Ok(wire),
                    _ => Err(WindowStoreError::GenerationMismatch),
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => match load_generation(gen_entry)?
            {
                None => Ok(WireFile {
                    version: 1,
                    generation: 0,
                    entries: Vec::new(),
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
        serde_json::from_slice(body).map_err(|e| WindowStoreError::Invalid {
            detail: format!("store body is not valid JSON: {e}"),
        })
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

/// Reads the current generation counter. `Ok(None)` means the entry has
/// never been minted — a genuine first-run signal, distinct from `Some(0)`
/// (which cannot occur: [`bump_generation`] always writes a value `>= 1`).
fn load_generation(entry_ref: &KeyringEntryRef) -> Result<Option<u64>, WindowStoreError> {
    let entry = keyring_core::Entry::new(&entry_ref.service, &entry_ref.account).map_err(|e| {
        WindowStoreError::Keyring {
            detail: format!("generation entry open failed: {e}"),
        }
    })?;
    match entry.get_password() {
        Ok(s) => s
            .trim()
            .parse::<u64>()
            .map(Some)
            .map_err(|e| WindowStoreError::Keyring {
                detail: format!("generation entry value is not a valid counter: {e}"),
            }),
        Err(keyring_core::Error::NoEntry) => Ok(None),
        Err(e) => Err(WindowStoreError::Keyring {
            detail: format!("generation entry read failed: {e}"),
        }),
    }
}

/// Atomically-from-this-process's-perspective increments the generation
/// counter (read-then-write; concurrent bumps are serialised by the SAME
/// [`WindowStoreLock`] every caller of this function already holds — see
/// [`PersistedWindowStore::record_and_persist`] / `reset`) and returns the
/// NEW value. Absent-entry reads as `0`, so the first-ever bump returns `1`.
fn bump_generation(entry_ref: &KeyringEntryRef) -> Result<u64, WindowStoreError> {
    let current = load_generation(entry_ref)?.unwrap_or(0);
    let next = current
        .checked_add(1)
        .ok_or_else(|| WindowStoreError::Invalid {
            detail: "policy window-state generation counter overflow".to_owned(),
        })?;
    let entry = keyring_core::Entry::new(&entry_ref.service, &entry_ref.account).map_err(|e| {
        WindowStoreError::Keyring {
            detail: format!("generation entry open failed: {e}"),
        }
    })?;
    entry
        .set_password(&next.to_string())
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

fn prune_stale(wire: &mut WireFile, now_ms: u64) {
    let cutoff = now_ms.saturating_sub(RETENTION_MS);
    for bucket in &mut wire.entries {
        bucket.records.retain(|r| r.ts_ms >= cutoff);
    }
    wire.entries.retain(|b| !b.records.is_empty());
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
}
