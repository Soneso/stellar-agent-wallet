//! [`HeadlessStore`] (`CredentialStoreApi`) and [`HeadlessCredential`]
//! (`CredentialApi`) — the file-backed keyring store `keyring_core::Entry`
//! transparently routes to once [`crate::init_headless_store`] registers it
//! as the process default.
//!
//! One JSON file for the host, holding every `(service, account)` entry —
//! the coordinate space is already profile-scoped by the wallet's naming
//! convention, mirroring how the platform keyring is one shared store. Every
//! mutation re-reads, modifies, and atomically re-writes the WHOLE file
//! (temp-file + `sync_data` + rename + parent-directory fsync on Unix — the
//! `PersistedWindowStore` / `stellar_agent_core::audit_log` sidecar-write
//! precedent). Mutations are serialised ACROSS PROCESSES by an exclusive OS
//! lock on a sidecar file (see [`acquire_store_lock`]), so a long-lived MCP
//! server writing (e.g. an HMAC-key rotation) cannot silently discard a
//! concurrent CLI enrollment's write, or vice versa. Reads take no lock: the
//! atomic rename guarantees a reader sees a complete former or current
//! file.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use keyring_core::api::{Credential, CredentialApi, CredentialPersistence, CredentialStoreApi};
use keyring_core::{Entry, Error as KcError, Result as KcResult};
use serde::{Deserialize, Serialize};

use crate::crypto::{self, CryptoError, ProtectionMode, Sealed};

const WIRE_VERSION: u32 = 1;

// ─────────────────────────────────────────────────────────────────────────────
// Wire format
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct WireFile {
    version: u32,
    /// Protection-mode label the file was last written under
    /// (`"headless-env"` / `"headless-dpapi"`), for operator diagnostics
    /// only — never used to select the decrypt path (the LIVE
    /// [`ProtectionMode`] the store was constructed with is always what
    /// decrypts; a file written under one mode read back under the other
    /// simply fails to decrypt, which is the correct fail-closed outcome for
    /// a misconfigured backend switch).
    #[serde(default)]
    backend: String,
    entries: BTreeMap<String, WireEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WireEntry {
    /// Base64 (URL-safe, no padding); absent (`None`) for DPAPI-sealed
    /// entries, present for env-key-sealed entries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    nonce_b64: Option<String>,
    ciphertext_b64: String,
}

/// Coordinate key within [`WireFile::entries`]: `service`, then a NUL byte,
/// then `account`. NUL is not a valid byte in either component in practice
/// (keyring service/account strings are always plain ASCII-ish identifiers
/// throughout this codebase), so this cannot collide.
fn coord_key(service: &str, account: &str) -> String {
    format!("{service}\0{account}")
}

fn aad_bytes(service: &str, account: &str) -> Vec<u8> {
    coord_key(service, account).into_bytes()
}

// ─────────────────────────────────────────────────────────────────────────────
// HeadlessStore — CredentialStoreApi
// ─────────────────────────────────────────────────────────────────────────────

/// The opt-in file-backed keyring store.
///
/// Implements `CredentialStoreApi::build` so `keyring_core::Entry::new`
/// (used unchanged at every existing `KeyringEntryRef`-coordinate call site
/// across the wallet) transparently routes here once this store is
/// registered as the process default via
/// [`crate::init_headless_store`].
#[derive(Debug, Clone)]
pub struct HeadlessStore {
    path: PathBuf,
    mode: ProtectionMode,
}

impl HeadlessStore {
    /// Constructs a store writing to `path` under `mode`.
    #[must_use]
    pub fn new(path: PathBuf, mode: ProtectionMode) -> Self {
        Self { path, mode }
    }
}

impl CredentialStoreApi for HeadlessStore {
    fn vendor(&self) -> String {
        "stellar-agent-headless-keyring".to_owned()
    }

    fn id(&self) -> String {
        format!("stellar-agent-headless-keyring/{}", self.mode.label())
    }

    fn build(
        &self,
        service: &str,
        user: &str,
        _modifiers: Option<&std::collections::HashMap<&str, &str>>,
    ) -> KcResult<Entry> {
        if service.is_empty() || user.is_empty() {
            return Err(KcError::Invalid(
                "service/user".to_owned(),
                "service and account must both be non-empty".to_owned(),
            ));
        }
        // The coordinate key and the AEAD AAD are both NUL-delimited
        // `service\0account`; a control byte inside either component could
        // alias two distinct coordinates onto one key. Enforce the invariant
        // the delimiter relies on instead of assuming it.
        if service.bytes().any(|b| b.is_ascii_control())
            || user.bytes().any(|b| b.is_ascii_control())
        {
            return Err(KcError::Invalid(
                "service/user".to_owned(),
                "service and account must not contain control bytes".to_owned(),
            ));
        }
        let credential = HeadlessCredential {
            path: self.path.clone(),
            mode: self.mode.clone(),
            service: service.to_owned(),
            account: user.to_owned(),
        };
        Ok(Entry::new_with_credential(Arc::new(credential)))
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn persistence(&self) -> CredentialPersistence {
        CredentialPersistence::UntilDelete
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HeadlessCredential — CredentialApi
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct HeadlessCredential {
    path: PathBuf,
    mode: ProtectionMode,
    service: String,
    account: String,
}

impl CredentialApi for HeadlessCredential {
    fn set_secret(&self, secret: &[u8]) -> KcResult<()> {
        let _lock = acquire_store_lock(&self.path)?;
        let mut file = read_wire_file(&self.path)?;
        let sealed = crypto::seal(&self.mode, &aad_bytes(&self.service, &self.account), secret)
            .map_err(map_crypto_error)?;
        file.version = WIRE_VERSION;
        file.entries.insert(
            coord_key(&self.service, &self.account),
            wire_entry_from_sealed(&sealed),
        );
        file.backend = self.mode.label().to_owned();
        write_wire_file(&self.path, &file)?;
        tracing::info!(
            target: "headless_keyring",
            event = "headless_keyring.write",
            backend = self.mode.label(),
            "headless keyring entry written"
        );
        Ok(())
    }

    fn get_secret(&self) -> KcResult<Vec<u8>> {
        let file = read_wire_file(&self.path)?;
        let key = coord_key(&self.service, &self.account);
        let Some(entry) = file.entries.get(&key) else {
            return Err(KcError::NoEntry);
        };
        let sealed = sealed_from_wire_entry(entry)?;
        let plaintext = crypto::open(
            &self.mode,
            &aad_bytes(&self.service, &self.account),
            &sealed,
        )
        .map_err(map_crypto_error)?;
        Ok(plaintext.to_vec())
    }

    fn delete_credential(&self) -> KcResult<()> {
        let _lock = acquire_store_lock(&self.path)?;
        let mut file = read_wire_file(&self.path)?;
        let key = coord_key(&self.service, &self.account);
        if file.entries.remove(&key).is_none() {
            return Err(KcError::NoEntry);
        }
        write_wire_file(&self.path, &file)?;
        Ok(())
    }

    fn get_credential(&self) -> KcResult<Option<Arc<Credential>>> {
        // Existence probe only, matching the platform-store pattern (see
        // apple-native-keyring-store's `Cred::get_credential`): every
        // specifier is also a wrapper here, so `None` hands `self` back.
        self.get_secret()?;
        Ok(None)
    }

    fn get_specifiers(&self) -> Option<(String, String)> {
        Some((self.service.clone(), self.account.clone()))
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

fn wire_entry_from_sealed(sealed: &Sealed) -> WireEntry {
    WireEntry {
        nonce_b64: sealed.nonce.map(|n| URL_SAFE_NO_PAD.encode(n)),
        ciphertext_b64: URL_SAFE_NO_PAD.encode(&sealed.ciphertext),
    }
}

fn sealed_from_wire_entry(entry: &WireEntry) -> KcResult<Sealed> {
    let ciphertext = URL_SAFE_NO_PAD
        .decode(&entry.ciphertext_b64)
        .map_err(|_| corrupt_store_error("entry ciphertext is not valid base64"))?;
    let nonce = match &entry.nonce_b64 {
        Some(n) => {
            let decoded = URL_SAFE_NO_PAD
                .decode(n)
                .map_err(|_| corrupt_store_error("entry nonce is not valid base64"))?;
            let arr: [u8; crypto::NONCE_LEN] = decoded
                .try_into()
                .map_err(|_| corrupt_store_error("entry nonce has the wrong length"))?;
            Some(arr)
        }
        None => None,
    };
    Ok(Sealed { nonce, ciphertext })
}

// ─────────────────────────────────────────────────────────────────────────────
// Atomic file I/O
// ─────────────────────────────────────────────────────────────────────────────

/// Bound on lock-acquisition retries in [`acquire_store_lock`] (40 x 50ms =
/// a nominal 2s), sized for the store's write pattern: enrollments and
/// rotations are one-shot operator actions, so genuine contention is brief.
const STORE_LOCK_RETRY_ATTEMPTS: u32 = 40;

/// Delay between lock-acquisition retries.
const STORE_LOCK_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(50);

/// Serialises every read-modify-write of the store file across processes by
/// holding an exclusive OS lock on a SIDECAR file (`<store>.lock`) — never on
/// the store file itself, where a Windows exclusive lock would block other
/// handles' reads and collide with the atomic rename. Two concurrent writers
/// (a long-lived MCP server rotating a key while an operator runs a CLI
/// enrollment) would otherwise both read the same base file and silently
/// discard one write on the last rename.
///
/// The lock is held by the returned handle and released by the OS on drop or
/// process death; a leftover `.lock` file is inert (the lock lives on the
/// open handle, not on the file's existence). Reads take no lock: the atomic
/// rename guarantees a reader sees a complete former or current file.
fn acquire_store_lock(path: &Path) -> KcResult<fs::File> {
    let mut lock_path = path.to_path_buf();
    let name = lock_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("headless.keyring")
        .to_owned();
    lock_path.set_file_name(format!("{name}.lock"));
    if let Some(parent) = lock_path.parent() {
        fs::create_dir_all(parent).map_err(|e| KcError::PlatformFailure(Box::new(e)))?;
    }
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|e| KcError::PlatformFailure(Box::new(e)))?;
    for attempt in 0..STORE_LOCK_RETRY_ATTEMPTS {
        if attempt > 0 {
            std::thread::sleep(STORE_LOCK_RETRY_DELAY);
        }
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(std::fs::TryLockError::WouldBlock) => {}
            Err(std::fs::TryLockError::Error(e)) => {
                return Err(KcError::PlatformFailure(Box::new(e)));
            }
        }
    }
    Err(corrupt_store_error(
        "headless keyring store is locked by another process; retry once it finishes",
    ))
}

fn read_wire_file(path: &Path) -> KcResult<WireFile> {
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(WireFile::default()),
        Err(e) => {
            return Err(KcError::PlatformFailure(Box::new(e)));
        }
    };
    if bytes.is_empty() {
        return Ok(WireFile::default());
    }
    let file: WireFile = serde_json::from_slice(&bytes)
        .map_err(|_| corrupt_store_error("headless keyring file is not valid JSON"))?;
    if file.version != WIRE_VERSION {
        return Err(corrupt_store_error(
            "headless keyring file version is not supported",
        ));
    }
    Ok(file)
}

fn write_wire_file(path: &Path, file: &WireFile) -> KcResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| KcError::PlatformFailure(Box::new(e)))?;
    }
    let body =
        serde_json::to_vec_pretty(file).map_err(|e| KcError::PlatformFailure(Box::new(e)))?;

    let mut tmp = path.to_path_buf();
    let name = tmp
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("headless.keyring")
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
                .map_err(|e| KcError::PlatformFailure(Box::new(e)))?
        };
        #[cfg(not(unix))]
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)
            .map_err(|e| KcError::PlatformFailure(Box::new(e)))?;
        f.write_all(&body)
            .map_err(|e| KcError::PlatformFailure(Box::new(e)))?;
        f.sync_data()
            .map_err(|e| KcError::PlatformFailure(Box::new(e)))?;
    }
    fs::rename(&tmp, path).map_err(|e| KcError::PlatformFailure(Box::new(e)))?;
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        fs::File::open(parent)
            .and_then(|d| d.sync_all())
            .map_err(|e| KcError::PlatformFailure(Box::new(e)))?;
    }
    // Best-effort on Windows: `set_permissions` restricting to the owning
    // user is not applied here (NTFS ACLs, not POSIX mode bits, govern
    // access; the file already inherits the user profile directory's
    // default ACL, which restricts to the owning user and Administrators).
    Ok(())
}

fn corrupt_store_error(detail: &str) -> KcError {
    KcError::BadStoreFormat(detail.to_owned())
}

fn map_crypto_error(e: CryptoError) -> KcError {
    KcError::BadDataFormat(Vec::new(), Box::new(e))
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
    use std::sync::Arc as StdArc;

    use zeroize::Zeroizing;

    use super::*;

    fn env_key_store(path: PathBuf) -> HeadlessStore {
        HeadlessStore::new(
            path,
            ProtectionMode::EnvKey(StdArc::new(Zeroizing::new([0x77u8; 32]))),
        )
    }

    #[test]
    fn set_get_round_trips_through_the_store_api() {
        let dir = tempfile::tempdir().expect("tmp dir");
        let store = env_key_store(dir.path().join("profile.keyring"));

        let entry = store.build("svc-a", "acct-a", None).expect("build");
        entry.set_password("s3cr3t-value").expect("set");
        let got = entry.get_password().expect("get");
        assert_eq!(got, "s3cr3t-value");
    }

    #[test]
    fn distinct_coordinates_do_not_collide() {
        let dir = tempfile::tempdir().expect("tmp dir");
        let store = env_key_store(dir.path().join("profile.keyring"));

        store
            .build("svc-a", "acct", None)
            .expect("build")
            .set_password("value-a")
            .expect("set a");
        store
            .build("svc-b", "acct", None)
            .expect("build")
            .set_password("value-b")
            .expect("set b");

        assert_eq!(
            store
                .build("svc-a", "acct", None)
                .unwrap()
                .get_password()
                .unwrap(),
            "value-a"
        );
        assert_eq!(
            store
                .build("svc-b", "acct", None)
                .unwrap()
                .get_password()
                .unwrap(),
            "value-b"
        );
    }

    #[test]
    fn get_on_missing_entry_returns_no_entry() {
        let dir = tempfile::tempdir().expect("tmp dir");
        let store = env_key_store(dir.path().join("profile.keyring"));
        let entry = store.build("svc", "acct", None).expect("build");
        assert!(matches!(entry.get_password(), Err(KcError::NoEntry)));
    }

    #[test]
    fn delete_removes_entry_and_is_idempotent_refusal() {
        let dir = tempfile::tempdir().expect("tmp dir");
        let store = env_key_store(dir.path().join("profile.keyring"));
        let entry = store.build("svc", "acct", None).expect("build");
        entry.set_password("value").expect("set");
        entry.delete_credential().expect("delete");
        assert!(matches!(entry.get_password(), Err(KcError::NoEntry)));
        assert!(matches!(entry.delete_credential(), Err(KcError::NoEntry)));
    }

    #[test]
    fn overwriting_an_entry_replaces_its_value() {
        let dir = tempfile::tempdir().expect("tmp dir");
        let store = env_key_store(dir.path().join("profile.keyring"));
        let entry = store.build("svc", "acct", None).expect("build");
        entry.set_password("first").expect("set 1");
        entry.set_password("second").expect("set 2");
        assert_eq!(entry.get_password().unwrap(), "second");
    }

    #[test]
    fn file_on_disk_never_carries_the_plaintext_secret() {
        let dir = tempfile::tempdir().expect("tmp dir");
        let path = dir.path().join("profile.keyring");
        let store = env_key_store(path.clone());
        store
            .build("svc", "acct", None)
            .expect("build")
            .set_password("extremely-secret-owner-seed-material")
            .expect("set");

        let on_disk = fs::read_to_string(&path).expect("read file");
        assert!(!on_disk.contains("extremely-secret-owner-seed-material"));
    }

    #[test]
    fn wrong_key_fails_closed_rather_than_returning_garbage() {
        let dir = tempfile::tempdir().expect("tmp dir");
        let path = dir.path().join("profile.keyring");
        env_key_store(path.clone())
            .build("svc", "acct", None)
            .expect("build")
            .set_password("value")
            .expect("set");

        let wrong_key_store = HeadlessStore::new(
            path,
            ProtectionMode::EnvKey(StdArc::new(Zeroizing::new([0x99u8; 32]))),
        );
        let entry = wrong_key_store.build("svc", "acct", None).expect("build");
        assert!(entry.get_password().is_err());
    }

    #[test]
    fn corrupt_file_fails_closed_on_read() {
        let dir = tempfile::tempdir().expect("tmp dir");
        let path = dir.path().join("profile.keyring");
        fs::write(&path, b"not valid json at all {{{").expect("write garbage");
        let store = env_key_store(path);
        let entry = store.build("svc", "acct", None).expect("build");
        assert!(
            entry.get_password().is_err(),
            "a corrupted store file must fail closed, not silently behave as empty"
        );
    }

    #[test]
    fn empty_service_or_account_is_rejected_at_build_time() {
        let dir = tempfile::tempdir().expect("tmp dir");
        let store = env_key_store(dir.path().join("profile.keyring"));
        assert!(store.build("", "acct", None).is_err());
        assert!(store.build("svc", "", None).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn file_is_written_with_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("tmp dir");
        let path = dir.path().join("profile.keyring");
        env_key_store(path.clone())
            .build("svc", "acct", None)
            .expect("build")
            .set_password("value")
            .expect("set");
        let mode = fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "store file must be owner-read-write only");
    }
}
