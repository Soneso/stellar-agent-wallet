//! Operator-approval credential store — WebAuthn passkeys authorized to
//! consent to pending approvals from a device other than the wallet host.
//!
//! # Trust-role separation
//!
//! This registry is deliberately distinct from the smart-account signer
//! passkey registry (`stellar_agent_smart_account::managers::credentials`).
//! A smart-account signer passkey authorizes on-chain transaction signing; an
//! operator-approval credential only authorizes consenting to (approving or
//! rejecting) a pending wallet-controlled approval over the remote-approval
//! HTTP surface. The two registries never share a record type, a file, or a
//! lookup path — conflating them would let enrolling a passkey for one
//! purpose silently grant the other.
//!
//! Enrollment in this store alone does not authorize anything: the profile's
//! `allowed_credentials` allowlist
//! (`crate::profile::schema::RemoteApprovalConfig::allowed_credentials`) is
//! the authorization gate that
//! `crate::approval::user_id::ApproverIdentity::is_authorized_for_entry`
//! consults. This store supplies the public key (for assertion verification)
//! and the sign counter (for cloned-authenticator detection); it does not
//! itself decide who may attest.
//!
//! # On-disk format
//!
//! Stored as `<dir>/<profile>.toml` with mode `0o600` on Unix, written
//! atomically via a temp-file-then-rename. No private-key bytes are ever
//! stored — only the public metadata produced by a WebAuthn registration
//! ceremony.
//!
//! # Write serialization
//!
//! Every mutation ([`OperatorApprovalCredentialStore::enroll`],
//! [`OperatorApprovalCredentialStore::update_sign_count`] and
//! [`OperatorApprovalCredentialStore::remove`]) holds an exclusive advisory
//! lock on the sidecar `<profile>.toml.lock` file from before it loads the
//! registry until after the replacement file is renamed into place. The
//! sidecar is never deleted and never replaced, so every writer locks the
//! same inode; the TOML file itself is replaced on each write and is never
//! the lock target. Two concurrent writers therefore always see each other's
//! successful writes: an enrollment is never lost, a removal is never
//! undone, and a stored sign counter never decreases. A writer that cannot
//! take the lock within a short bounded retry refuses with
//! [`ApprovalError::WriterLocked`] and changes nothing. Reads take no lock:
//! the rename makes every observed file a complete earlier or later version.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use super::error::{ApprovalError, toml_error_position};
use super::store::{LockHandle, lock_path};
use crate::redact_first5_last5;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Minimum credential ID length in raw bytes (CTAP2 §4.2 / WebAuthn-2 §5.4.7).
const CREDENTIAL_ID_MIN_BYTES: usize = 16;

/// Maximum credential ID length in raw bytes (CTAP2 §4.2 / WebAuthn-2 §5.4.7).
const CREDENTIAL_ID_MAX_BYTES: usize = 64;

/// Length of an uncompressed SEC1 P-256 public key in bytes:
/// `0x04 || X (32 bytes) || Y (32 bytes)`.
const PUBLIC_KEY_UNCOMPRESSED_SEC1_LEN: usize = 65;

/// Attempts at taking the write lock before a mutation refuses with
/// [`ApprovalError::WriterLocked`].
const WRITE_LOCK_ATTEMPTS: u32 = 5;

/// Pause between two attempts at taking the write lock. With
/// [`WRITE_LOCK_ATTEMPTS`] a contended mutation waits at most 80 ms before it
/// refuses; every critical section is one small TOML load, edit and rename.
const WRITE_LOCK_BACKOFF: Duration = Duration::from_millis(20);

// ─────────────────────────────────────────────────────────────────────────────
// OperatorApprovalCredential
// ─────────────────────────────────────────────────────────────────────────────

/// Metadata for one enrolled operator-approval passkey credential.
///
/// # Field stability policy
///
/// `credential_id_b64url`, `public_key_sec1_b64`, `rp_id`, `label`, and
/// `registered_at_unix_ms` are always required for a non-corrupt registry
/// entry. `sign_count` is additive (`#[serde(default)]`): absent in registry
/// entries written before sign-counter tracking existed, treated as "counter
/// unsupported or not yet observed" on load.
///
/// # Debug redaction
///
/// `Debug` is hand-implemented (not derived) to redact `credential_id_b64url`
/// to first-5-last-5 form and omit `public_key_sec1_b64` entirely, matching
/// the redaction discipline used by the smart-account signer passkey
/// registry's `CredentialMetadata`.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperatorApprovalCredential {
    /// Base64url-encoded WebAuthn credential ID (CTAP2 canonical form).
    ///
    /// 16–64 raw bytes → 22–86 base64url characters. This is the value
    /// compared against a profile's `RemoteApprovalConfig::allowed_credentials`
    /// allowlist and against the credential ID an
    /// `ApproverIdentity::PasskeyCredential` carries.
    pub credential_id_b64url: String,

    /// Base64url-no-pad encoded uncompressed SEC1 P-256 public key
    /// (`0x04 || X (32 bytes) || Y (32 bytes)`) — exactly 65 raw bytes, 87
    /// base64url characters. Required for WebAuthn assertion verification.
    pub public_key_sec1_b64: String,

    /// WebAuthn Relying Party ID this credential was registered against.
    ///
    /// Must equal the profile's `RemoteApprovalConfig::rp_id` for an
    /// assertion using this credential to verify — a credential registered
    /// under one RP-ID cannot be used to authenticate against another.
    pub rp_id: String,

    /// Operator-chosen human-readable label (e.g. `"laptop"`, `"phone"`).
    pub label: String,

    /// Unix epoch milliseconds of the registration ceremony completion.
    pub registered_at_unix_ms: u64,

    /// WebAuthn signature counter last observed for this credential, if the
    /// authenticator reports one.
    ///
    /// `None` when no verified assertion has updated this record yet, or
    /// when the record predates sign-counter tracking. A presented counter
    /// of `0` means the authenticator does not support counters and is never
    /// stored here as a comparison baseline — see
    /// [`OperatorApprovalCredentialStore::update_sign_count`].
    ///
    /// # Registration-time seeding is advisory, never authorization-bearing
    ///
    /// A caller may seed this field at enrollment time with the counter of
    /// the registration ceremony. The interactive loopback enrollment server
    /// parses it from the authenticator data of the registration response it
    /// verified; argument import takes the operator's `--sign-count`. Either
    /// value comes from the client and, unlike an assertion-time counter, is
    /// never checked against a signature: nothing stops a caller from
    /// reporting any number here. This is acceptable because the field feeds
    /// only the clone-detection regression check in
    /// [`OperatorApprovalCredentialStore::update_sign_count`]: lying about
    /// the seed weakens that one credential's own clone-detection baseline
    /// and nothing else. Authorization is decided solely by the profile's
    /// `allowed_credentials` allowlist, which this field never influences.
    ///
    /// # Seeded verbatim, never clamped
    ///
    /// The registration-time value is stored as-is because it is the
    /// authenticator's own registration counter — the correct WebAuthn
    /// baseline against which the first subsequent assertion's
    /// strictly-greater check is meant to run. Imposing a fixed upper bound
    /// here would be an arbitrary threshold with no basis in the WebAuthn
    /// spec, and would wrongly reject a legitimate roaming authenticator
    /// whose counter is already high from use with other relying parties. A
    /// client that seeds an implausibly high value only weakens
    /// clone-detection for that one credential going forward; it can never
    /// grant that credential — or any other — authorization, which the
    /// `allowed_credentials` allowlist alone decides.
    ///
    /// # Seeding is best-effort
    ///
    /// An authenticator that reports the same counter value at registration
    /// and at its first subsequent assertion — rather than a strictly
    /// greater one — trips the regression check on that first assertion.
    /// Most platform authenticators report `0` at every ceremony, which is
    /// exempt from the check under the zero-counter rule above, so this
    /// edge is rare in practice; when it does occur the assertion is
    /// refused (never silently accepted), and the operator re-enrolls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sign_count: Option<u32>,
}

impl std::fmt::Debug for OperatorApprovalCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OperatorApprovalCredential")
            .field(
                "credential_id_b64url",
                &redact_first5_last5(&self.credential_id_b64url),
            )
            .field("public_key_sec1_b64", &"[redacted]")
            .field("rp_id", &self.rp_id)
            .field("label", &self.label)
            .field("registered_at_unix_ms", &self.registered_at_unix_ms)
            .field("sign_count", &self.sign_count)
            .finish()
    }
}

/// Validates the field-level invariants for a new
/// [`OperatorApprovalCredential`] before it is written to the store.
///
/// # Errors
///
/// Returns [`ApprovalError::Invalid`] when `credential_id_b64url` decodes to
/// fewer than [`CREDENTIAL_ID_MIN_BYTES`] or more than
/// [`CREDENTIAL_ID_MAX_BYTES`] raw bytes, or fails to decode as base64url at
/// all; or when `public_key_sec1_b64` is not exactly
/// [`PUBLIC_KEY_UNCOMPRESSED_SEC1_LEN`] raw bytes with a leading `0x04`
/// marker.
fn validate_credential_invariants(
    credential_id_b64url: &str,
    public_key_sec1_b64: &str,
) -> Result<(), ApprovalError> {
    let credential_id_bytes =
        URL_SAFE_NO_PAD
            .decode(credential_id_b64url)
            .map_err(|_| ApprovalError::Invalid {
                reason: "credential_id_b64url is not valid base64url".to_owned(),
            })?;
    if credential_id_bytes.len() < CREDENTIAL_ID_MIN_BYTES
        || credential_id_bytes.len() > CREDENTIAL_ID_MAX_BYTES
    {
        return Err(ApprovalError::Invalid {
            reason: format!(
                "credential_id must decode to {CREDENTIAL_ID_MIN_BYTES}\u{2013}\
                 {CREDENTIAL_ID_MAX_BYTES} bytes (CTAP2 \u{a7}4.2 / WebAuthn-2 \u{a7}5.4.7), \
                 got {} bytes",
                credential_id_bytes.len()
            ),
        });
    }

    let pubkey_bytes =
        URL_SAFE_NO_PAD
            .decode(public_key_sec1_b64)
            .map_err(|_| ApprovalError::Invalid {
                reason: "public_key_sec1_b64 is not valid base64url".to_owned(),
            })?;
    if pubkey_bytes.len() != PUBLIC_KEY_UNCOMPRESSED_SEC1_LEN {
        return Err(ApprovalError::Invalid {
            reason: format!(
                "public_key_sec1_b64 must decode to exactly \
                 {PUBLIC_KEY_UNCOMPRESSED_SEC1_LEN} bytes (uncompressed SEC1 P-256), got {} bytes",
                pubkey_bytes.len()
            ),
        });
    }
    if pubkey_bytes[0] != 0x04 {
        return Err(ApprovalError::Invalid {
            reason: format!(
                "public_key_sec1_b64[0] must be 0x04 (uncompressed SEC1 P-256 marker), got 0x{:02x}",
                pubkey_bytes[0]
            ),
        });
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// On-disk schema
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Default, Serialize, Deserialize)]
struct OperatorCredentialStoreFile {
    #[serde(default)]
    credentials: Vec<OperatorApprovalCredential>,
}

// ─────────────────────────────────────────────────────────────────────────────
// OperatorApprovalCredentialStore
// ─────────────────────────────────────────────────────────────────────────────

/// TOML-file-backed store of enrolled operator-approval credentials, one file
/// per profile.
pub struct OperatorApprovalCredentialStore {
    path: PathBuf,
}

impl std::fmt::Debug for OperatorApprovalCredentialStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OperatorApprovalCredentialStore")
            .field("path", &self.path)
            .finish()
    }
}

impl OperatorApprovalCredentialStore {
    /// Opens (without yet reading) the store at `path`.
    ///
    /// Does not touch the filesystem: the file and its sidecar lock file are
    /// created lazily by the first mutation. Reads return an empty registry
    /// when the file does not yet exist.
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Returns the path to this store's TOML file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Loads the registry from disk, returning an empty registry if the file
    /// does not exist yet.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalError::Io`] on read failure or
    /// [`ApprovalError::Toml`] if the file cannot be parsed.
    fn load(&self) -> Result<OperatorCredentialStoreFile, ApprovalError> {
        if !self.path.exists() {
            return Ok(OperatorCredentialStoreFile::default());
        }
        let content = fs::read_to_string(&self.path).map_err(ApprovalError::from_io)?;
        toml::from_str(&content).map_err(|e| ApprovalError::Toml {
            detail: format!(
                "operator_credentials: {}",
                toml_error_position(&content, e.span().map(|s| s.start))
            ),
        })
    }

    /// The directory that holds the registry file and its sidecar lock.
    fn parent_dir(&self) -> &Path {
        self.path.parent().unwrap_or_else(|| Path::new("."))
    }

    /// Creates the registry directory (mode `0o700` on Unix) if it is absent.
    fn ensure_parent_dir(&self) -> Result<(), ApprovalError> {
        let parent = self.parent_dir();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)
                .map_err(ApprovalError::from_io)?;
        }
        #[cfg(not(unix))]
        {
            fs::create_dir_all(parent).map_err(ApprovalError::from_io)?;
        }
        Ok(())
    }

    /// Atomically persists the registry via temp-file + rename.
    ///
    /// Called only with the store's write lock held: by
    /// [`Self::with_write_lock`] and by [`Self::remove`].
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalError::Io`] on I/O failure or [`ApprovalError::Toml`]
    /// on serialisation failure.
    fn persist(&self, file: &OperatorCredentialStoreFile) -> Result<(), ApprovalError> {
        let parent = self.parent_dir();

        let toml_str = toml::to_string_pretty(file).map_err(|e| ApprovalError::Toml {
            detail: format!("operator_credentials: serialise error: {e}"),
        })?;

        let mut tmp = tempfile::NamedTempFile::new_in(parent).map_err(ApprovalError::from_io)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            tmp.as_file()
                .set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(ApprovalError::from_io)?;
        }

        tmp.write_all(toml_str.as_bytes())
            .map_err(ApprovalError::from_io)?;
        tmp.flush().map_err(ApprovalError::from_io)?;

        tmp.persist(&self.path)
            .map_err(|e| ApprovalError::from_io(e.error))?;

        Ok(())
    }

    /// Takes the store's write lock, retrying a held lock a bounded number of
    /// times.
    ///
    /// # Errors
    ///
    /// - [`ApprovalError::WriterLocked`] when every attempt finds the lock
    ///   held by another writer.
    /// - [`ApprovalError::Io`] when the directory or the lock file cannot be
    ///   created or locked.
    fn acquire_write_lock(&self) -> Result<OperatorCredentialWriteLock, ApprovalError> {
        self.ensure_parent_dir()?;
        let lock_file = lock_path(&self.path);
        let mut attempt = 0_u32;
        loop {
            attempt += 1;
            match LockHandle::acquire(&lock_file) {
                Ok(handle) => return Ok(OperatorCredentialWriteLock { _handle: handle }),
                Err(ApprovalError::WriterLocked) if attempt < WRITE_LOCK_ATTEMPTS => {
                    #[cfg(test)]
                    test_hooks::fire(&self.path, test_hooks::Point::Busy);
                    std::thread::sleep(WRITE_LOCK_BACKOFF);
                }
                Err(other) => return Err(other),
            }
        }
    }

    /// Runs one mutation of the registry under the store's write lock.
    ///
    /// The lock is taken before the registry is loaded and released after
    /// the replacement file is renamed into place, so `update` always sees
    /// the latest successful write and no other writer can replace the file
    /// between the load and the rename. Nothing is written when `update`
    /// returns an error. No WebAuthn verification, terminal input, network
    /// operation or `.await` happens inside the critical section.
    ///
    /// # Errors
    ///
    /// - [`ApprovalError::WriterLocked`] when the lock stays held by another
    ///   writer; nothing is loaded or written.
    /// - The error `update` returns; nothing is written.
    /// - [`ApprovalError::Io`] / [`ApprovalError::Toml`] on load or persist
    ///   failure.
    fn with_write_lock<T>(
        &self,
        update: impl FnOnce(&mut OperatorCredentialStoreFile) -> Result<T, ApprovalError>,
    ) -> Result<T, ApprovalError> {
        let lock = self.acquire_write_lock()?;
        let mut file = self.load()?;
        let value = update(&mut file)?;
        #[cfg(test)]
        test_hooks::fire(&self.path, test_hooks::Point::Locked);
        self.persist(&file)?;
        drop(lock);
        Ok(value)
    }

    /// Returns all enrolled operator-approval credentials.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalError`] on registry I/O or parse failure.
    pub fn list(&self) -> Result<Vec<OperatorApprovalCredential>, ApprovalError> {
        Ok(self.load()?.credentials)
    }

    /// Returns the enrolled credential matching `credential_id_b64url`, if
    /// any.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalError`] on registry I/O or parse failure.
    pub fn find_by_credential_id(
        &self,
        credential_id_b64url: &str,
    ) -> Result<Option<OperatorApprovalCredential>, ApprovalError> {
        Ok(self
            .load()?
            .credentials
            .into_iter()
            .find(|c| c.credential_id_b64url == credential_id_b64url))
    }

    /// Enrolls a new operator-approval credential and persists the store.
    ///
    /// Enrollment alone does not authorize anything — the operator must also
    /// add `credential_id_b64url` to the profile's
    /// `RemoteApprovalConfig::allowed_credentials`. Keeping enrollment and
    /// allowlisting as two separate steps means a compromised enrollment
    /// path cannot silently grant approval authority; the profile TOML edit
    /// is the operator-controlled authorization act.
    ///
    /// Runs under the store's write lock (see the module docs), so a
    /// concurrent enrollment or counter update never drops this record.
    ///
    /// The label is shown to the operator, so no label that holds a control
    /// character ([`char::is_control`]: C0, DEL, C1) is ever stored, whatever
    /// path supplies it. Loading a store does not check labels.
    ///
    /// # Errors
    ///
    /// - [`ApprovalError::Invalid`] if `credential.credential_id_b64url` or
    ///   `credential.public_key_sec1_b64` fails format validation, or if
    ///   `credential.label` holds a control character. The check runs before
    ///   the write lock is taken; nothing is created or written.
    /// - [`ApprovalError::DuplicateCredentialId`] if a credential with the
    ///   same `credential_id_b64url` is already enrolled. [`Self::remove`] it
    ///   first to re-enroll under the same ID.
    /// - [`ApprovalError::WriterLocked`] if another writer holds the store's
    ///   write lock; nothing is written.
    /// - [`ApprovalError::Io`] / [`ApprovalError::Toml`] on persistence
    ///   failure.
    pub fn enroll(&self, credential: OperatorApprovalCredential) -> Result<(), ApprovalError> {
        validate_credential_invariants(
            &credential.credential_id_b64url,
            &credential.public_key_sec1_b64,
        )?;
        if credential.label.chars().any(char::is_control) {
            return Err(ApprovalError::Invalid {
                reason: "the label holds a control character".to_owned(),
            });
        }

        self.with_write_lock(|file| {
            if file
                .credentials
                .iter()
                .any(|c| c.credential_id_b64url == credential.credential_id_b64url)
            {
                return Err(ApprovalError::duplicate_credential_id(
                    &credential.credential_id_b64url,
                ));
            }
            file.credentials.push(credential);
            Ok(())
        })
    }

    /// Updates the stored sign counter for `credential_id_b64url` after a
    /// verified WebAuthn assertion, enforcing the WebAuthn Level 2
    /// cloned-authenticator regression check.
    ///
    /// If either the presented counter or the previously stored counter is
    /// non-zero and the presented value does not strictly exceed the stored
    /// value, the update is refused (the credential may have been cloned)
    /// and the stored counter is left unchanged. In particular, a presented
    /// counter of `0` against a non-zero stored counter is refused: an
    /// authenticator that has reported counters must keep advancing, and
    /// accepting `0` there would reset the stored value and permanently
    /// disarm the check. Only when both values are `0` is there no
    /// regression check — the authenticator does not report counters at
    /// all, which is valid under WebAuthn Level 2.
    ///
    /// The check runs against the counter loaded under the store's write
    /// lock, so of two concurrent successful updates the later one always
    /// carries the higher counter.
    ///
    /// # Errors
    ///
    /// - [`ApprovalError::NotFound`] if no credential with
    ///   `credential_id_b64url` is enrolled.
    /// - [`ApprovalError::SignCounterRegression`] if the regression check
    ///   above fails. The stored counter is NOT updated in this case.
    /// - [`ApprovalError::WriterLocked`] if another writer holds the store's
    ///   write lock; nothing is written.
    /// - [`ApprovalError::Io`] / [`ApprovalError::Toml`] on persistence
    ///   failure.
    pub fn update_sign_count(
        &self,
        credential_id_b64url: &str,
        presented_counter: u32,
    ) -> Result<(), ApprovalError> {
        self.with_write_lock(|file| {
            let record = file
                .credentials
                .iter_mut()
                .find(|c| c.credential_id_b64url == credential_id_b64url)
                .ok_or(ApprovalError::NotFound)?;

            if let Some(stored) = record.sign_count
                && (stored != 0 || presented_counter != 0)
                && presented_counter <= stored
            {
                return Err(ApprovalError::sign_counter_regression(
                    credential_id_b64url,
                    presented_counter,
                    stored,
                ));
            }

            record.sign_count = Some(presented_counter);
            Ok(())
        })
    }

    /// Removes the enrolled credential `credential_id_b64url`.
    ///
    /// Returns `true` when a record was removed and `false` when none was
    /// enrolled under that ID, in which case nothing is written. Runs under
    /// the store's write lock, so a concurrent counter update or enrollment
    /// cannot write the removed record back.
    ///
    /// Removal deletes the enrollment only. The profile's
    /// `RemoteApprovalConfig::allowed_credentials` list is a separate file
    /// this method never edits; an allowlisted ID with no enrolled record
    /// authorizes nothing.
    ///
    /// # Errors
    ///
    /// - [`ApprovalError::WriterLocked`] if another writer holds the store's
    ///   write lock; nothing is written.
    /// - [`ApprovalError::Io`] / [`ApprovalError::Toml`] on load or
    ///   persistence failure.
    pub fn remove(&self, credential_id_b64url: &str) -> Result<bool, ApprovalError> {
        let lock = self.acquire_write_lock()?;
        let mut file = self.load()?;
        let before = file.credentials.len();
        file.credentials
            .retain(|c| c.credential_id_b64url != credential_id_b64url);
        if file.credentials.len() == before {
            return Ok(false);
        }
        #[cfg(test)]
        test_hooks::fire(&self.path, test_hooks::Point::Locked);
        self.persist(&file)?;
        drop(lock);
        Ok(true)
    }
}

/// The store's held write lock: an exclusive advisory lock on the sidecar
/// `<profile>.toml.lock` file, released when this value drops.
struct OperatorCredentialWriteLock {
    _handle: LockHandle,
}

/// Returns the default path for a profile's operator-approval credential
/// store: `<dir>/<profile>.toml` under
/// [`crate::profile::schema::default_operator_approval_credentials_dir`].
///
/// The returned path always names a file directly inside that directory:
/// `profile_name` must pass
/// [`crate::profile::name::validate_path_component_ascii_safe`], so an
/// absolute path, a separator or a `..` component never reaches the join.
///
/// # Errors
///
/// - [`ApprovalError::Invalid`] if `profile_name` is not a safe path
///   component; nothing is resolved.
/// - [`ApprovalError::Io`] if the OS-conventional state directory cannot be
///   resolved.
pub fn default_operator_approval_credentials_path(
    profile_name: &str,
) -> Result<PathBuf, ApprovalError> {
    crate::profile::name::validate_path_component_ascii_safe(profile_name).map_err(|reason| {
        ApprovalError::Invalid {
            reason: format!("invalid profile name: {reason}"),
        }
    })?;
    let dir = crate::profile::schema::default_operator_approval_credentials_dir().map_err(|e| {
        ApprovalError::from_io_detail(
            std::io::ErrorKind::Other,
            format!("operator_approval_credentials_path: {e}"),
        )
    })?;
    Ok(dir.join(format!("{profile_name}.toml")))
}

/// Pause points inside the write path, so a test can interleave two writers
/// deterministically.
#[cfg(test)]
pub(crate) mod test_hooks {
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};

    /// Where a writer calls its hook.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Point {
        /// The writer holds the write lock and has applied its change; the
        /// replacement file is not yet renamed into place.
        Locked,
        /// An attempt at the write lock found it held; the writer is about to
        /// wait and retry.
        Busy,
    }

    type Hook = Arc<dyn Fn(Point) + Send + Sync>;

    fn hooks() -> &'static Mutex<HashMap<PathBuf, Hook>> {
        static HOOKS: std::sync::OnceLock<Mutex<HashMap<PathBuf, Hook>>> =
            std::sync::OnceLock::new();
        HOOKS.get_or_init(|| Mutex::new(HashMap::new()))
    }

    /// Installs `hook` for the store at `path`, replacing any earlier one.
    pub(crate) fn install(path: &Path, hook: impl Fn(Point) + Send + Sync + 'static) {
        hooks()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(path.to_path_buf(), Arc::new(hook));
    }

    /// Removes the hook for the store at `path`.
    pub(crate) fn clear(path: &Path) {
        hooks()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(path);
    }

    pub(super) fn fire(path: &Path, point: Point) {
        let hook = hooks()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(path)
            .cloned();
        if let Some(hook) = hook {
            hook(point);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]
    use super::*;

    fn valid_pubkey_b64() -> String {
        let mut bytes = vec![0x04u8; PUBLIC_KEY_UNCOMPRESSED_SEC1_LEN];
        bytes[0] = 0x04;
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn valid_credential_id_b64(seed: u8) -> String {
        let bytes = vec![seed; CREDENTIAL_ID_MIN_BYTES];
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn make_credential(seed: u8, label: &str) -> OperatorApprovalCredential {
        OperatorApprovalCredential {
            credential_id_b64url: valid_credential_id_b64(seed),
            public_key_sec1_b64: valid_pubkey_b64(),
            rp_id: "wallet.internal".to_owned(),
            label: label.to_owned(),
            registered_at_unix_ms: 1_750_000_000_000,
            sign_count: None,
        }
    }

    #[test]
    fn enroll_and_list_round_trip() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = OperatorApprovalCredentialStore::new(dir.path().join("default.toml"));
        assert!(store.list().unwrap().is_empty());

        let cred = make_credential(1, "laptop");
        store.enroll(cred.clone()).unwrap();

        let listed = store.list().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0], cred);
    }

    #[test]
    fn enroll_duplicate_credential_id_fails() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = OperatorApprovalCredentialStore::new(dir.path().join("default.toml"));
        let cred = make_credential(2, "laptop");
        store.enroll(cred.clone()).unwrap();

        let err = store.enroll(cred).unwrap_err();
        assert!(matches!(err, ApprovalError::DuplicateCredentialId { .. }));
    }

    #[test]
    fn enroll_rejects_malformed_public_key() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = OperatorApprovalCredentialStore::new(dir.path().join("default.toml"));
        let mut cred = make_credential(3, "laptop");
        cred.public_key_sec1_b64 = URL_SAFE_NO_PAD.encode([0x04u8; 10]); // too short
        let err = store.enroll(cred).unwrap_err();
        assert!(matches!(err, ApprovalError::Invalid { .. }));
    }

    #[test]
    fn enroll_rejects_wrong_sec1_marker() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = OperatorApprovalCredentialStore::new(dir.path().join("default.toml"));
        let mut cred = make_credential(4, "laptop");
        let mut bytes = vec![0x02u8; PUBLIC_KEY_UNCOMPRESSED_SEC1_LEN]; // compressed marker
        bytes[0] = 0x02;
        cred.public_key_sec1_b64 = URL_SAFE_NO_PAD.encode(bytes);
        let err = store.enroll(cred).unwrap_err();
        assert!(matches!(err, ApprovalError::Invalid { .. }));
    }

    #[test]
    fn enroll_rejects_short_credential_id() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = OperatorApprovalCredentialStore::new(dir.path().join("default.toml"));
        let mut cred = make_credential(5, "laptop");
        cred.credential_id_b64url = URL_SAFE_NO_PAD.encode([0x01u8; 8]); // below 16-byte minimum
        let err = store.enroll(cred).unwrap_err();
        assert!(matches!(err, ApprovalError::Invalid { .. }));
    }

    #[test]
    fn find_by_credential_id_returns_none_when_absent() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = OperatorApprovalCredentialStore::new(dir.path().join("default.toml"));
        assert!(
            store
                .find_by_credential_id("nonexistent")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn update_sign_count_not_found_fails() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = OperatorApprovalCredentialStore::new(dir.path().join("default.toml"));
        let err = store.update_sign_count("nonexistent", 5).unwrap_err();
        assert!(matches!(err, ApprovalError::NotFound));
    }

    #[test]
    fn update_sign_count_advances_normally() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = OperatorApprovalCredentialStore::new(dir.path().join("default.toml"));
        let cred = make_credential(6, "laptop");
        let id = cred.credential_id_b64url.clone();
        store.enroll(cred).unwrap();

        store.update_sign_count(&id, 1).unwrap();
        store.update_sign_count(&id, 2).unwrap();

        let found = store.find_by_credential_id(&id).unwrap().unwrap();
        assert_eq!(found.sign_count, Some(2));
    }

    /// WebAuthn-L2 regression policy: a non-advancing counter (both non-zero)
    /// is refused and the stored counter is left unchanged — the
    /// cloned-authenticator signal this method exists to catch.
    #[test]
    fn update_sign_count_regression_is_refused() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = OperatorApprovalCredentialStore::new(dir.path().join("default.toml"));
        let cred = make_credential(7, "laptop");
        let id = cred.credential_id_b64url.clone();
        store.enroll(cred).unwrap();

        store.update_sign_count(&id, 10).unwrap();
        let err = store.update_sign_count(&id, 10).unwrap_err(); // equal, not strictly greater
        assert!(matches!(err, ApprovalError::SignCounterRegression { .. }));

        let err2 = store.update_sign_count(&id, 5).unwrap_err(); // regressed
        assert!(matches!(err2, ApprovalError::SignCounterRegression { .. }));

        // Stored counter must be unchanged after both refusals.
        let found = store.find_by_credential_id(&id).unwrap().unwrap();
        assert_eq!(found.sign_count, Some(10));
    }

    /// An authenticator that never reports counters (presented `0` against a
    /// stored counter that is absent or `0`) is accepted without a
    /// regression check — the counters-unsupported case WebAuthn Level 2
    /// permits.
    #[test]
    fn update_sign_count_zero_only_authenticator_is_accepted() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = OperatorApprovalCredentialStore::new(dir.path().join("default.toml"));
        let cred = make_credential(8, "laptop");
        let id = cred.credential_id_b64url.clone();
        store.enroll(cred).unwrap();

        store.update_sign_count(&id, 0).unwrap();
        store.update_sign_count(&id, 0).unwrap();
        let found = store.find_by_credential_id(&id).unwrap().unwrap();
        assert_eq!(found.sign_count, Some(0));
    }

    /// A presented counter of `0` against a NON-ZERO stored counter is a
    /// regression: an authenticator that has reported counters must keep
    /// advancing. Accepting `0` there would reset the stored value and
    /// permanently disarm the cloned-authenticator check for that
    /// credential.
    #[test]
    fn update_sign_count_zero_against_nonzero_stored_is_refused() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = OperatorApprovalCredentialStore::new(dir.path().join("default.toml"));
        let cred = make_credential(11, "laptop");
        let id = cred.credential_id_b64url.clone();
        store.enroll(cred).unwrap();

        store.update_sign_count(&id, 10).unwrap();
        let err = store.update_sign_count(&id, 0).unwrap_err();
        assert!(matches!(err, ApprovalError::SignCounterRegression { .. }));

        // The stored counter must be unchanged — never reset to 0.
        let found = store.find_by_credential_id(&id).unwrap().unwrap();
        assert_eq!(found.sign_count, Some(10));
    }

    #[test]
    fn store_persists_across_reopen() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("default.toml");
        let cred = make_credential(9, "phone");
        {
            let store = OperatorApprovalCredentialStore::new(path.clone());
            store.enroll(cred.clone()).unwrap();
        }
        let reopened = OperatorApprovalCredentialStore::new(path);
        let listed = reopened.list().unwrap();
        assert_eq!(listed, vec![cred]);
    }

    #[test]
    fn debug_impl_redacts_credential_id_and_omits_public_key() {
        let cred = make_credential(10, "laptop");
        let debug_str = format!("{cred:?}");
        assert!(
            !debug_str.contains(&cred.credential_id_b64url),
            "full credential_id_b64url must not appear in Debug output: {debug_str}"
        );
        assert!(
            !debug_str.contains(&cred.public_key_sec1_b64),
            "full public_key_sec1_b64 must not appear in Debug output: {debug_str}"
        );
    }

    #[test]
    fn load_parse_error_names_the_position_only() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("default.toml");
        let public_key = valid_pubkey_b64();
        fs::write(
            &path,
            format!(
                "[[credentials]]\nrp_id = \"wallet.internal\"\npublic_key_sec1_b64 = \"{public_key}"
            ),
        )
        .unwrap();
        let err = OperatorApprovalCredentialStore::new(path)
            .list()
            .unwrap_err();
        assert!(matches!(err, ApprovalError::Toml { .. }));
        let rendered = err.to_string();
        assert!(
            rendered.contains("operator_credentials: TOML parse error at line 3, column "),
            "{rendered}"
        );
        assert!(!rendered.contains(&public_key), "{rendered}");
        assert!(!rendered.contains("public_key_sec1_b64"), "{rendered}");
    }

    #[cfg(unix)]
    #[test]
    fn persisted_file_has_0o600_permissions() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("default.toml");
        let store = OperatorApprovalCredentialStore::new(path.clone());
        store.enroll(make_credential(11, "laptop")).unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "registry file must be mode 0o600, got {mode:o}"
        );
    }

    // ── Write serialization ─────────────────────────────────────────────────

    /// How long an interleaving step may take before the test fails instead
    /// of hanging.
    const STEP: std::time::Duration = std::time::Duration::from_secs(20);

    /// Runs two writers against the store at `path` in a fixed order: `first`
    /// runs until it holds the write lock with its change applied and pauses;
    /// `second` then runs until it finds the lock held and pauses; `first`
    /// finishes; `second` finishes. A `second` that never meets the held lock
    /// finishes before `first` resumes. Returns both results.
    fn interleave<A, B>(
        path: &Path,
        first: impl FnOnce() -> A + Send + 'static,
        second: impl FnOnce() -> B + Send + 'static,
    ) -> (A, B)
    where
        A: Send + 'static,
        B: Send + 'static,
    {
        use std::sync::mpsc;
        let (locked_tx, locked_rx) = mpsc::channel::<()>();
        let (release_first_tx, release_first_rx) = mpsc::channel::<()>();
        let (busy_tx, busy_rx) = mpsc::channel::<()>();
        let (release_second_tx, release_second_rx) = mpsc::channel::<()>();
        let release_first_rx = std::sync::Mutex::new(Some(release_first_rx));
        let release_second_rx = std::sync::Mutex::new(Some(release_second_rx));
        test_hooks::install(path, move |point| {
            let name = std::thread::current().name().map(str::to_owned);
            match (name.as_deref(), point) {
                (Some("first-writer"), test_hooks::Point::Locked) => {
                    if let Some(rx) = release_first_rx.lock().unwrap().take() {
                        locked_tx.send(()).unwrap();
                        rx.recv_timeout(STEP).unwrap();
                    }
                }
                (Some("second-writer"), test_hooks::Point::Busy) => {
                    if let Some(rx) = release_second_rx.lock().unwrap().take() {
                        busy_tx.send(()).unwrap();
                        rx.recv_timeout(STEP).unwrap();
                    }
                }
                _ => {}
            }
        });

        let first = std::thread::Builder::new()
            .name("first-writer".to_owned())
            .spawn(first)
            .unwrap();
        locked_rx
            .recv_timeout(STEP)
            .expect("the first writer reaches its critical section");
        let second = std::thread::Builder::new()
            .name("second-writer".to_owned())
            .spawn(second)
            .unwrap();
        let deadline = std::time::Instant::now() + STEP;
        let met_lock = loop {
            if busy_rx.try_recv().is_ok() {
                break true;
            }
            if second.is_finished() {
                break false;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the second writer neither met the lock nor finished"
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        };
        release_first_tx.send(()).unwrap();
        let first_result = first.join().unwrap();
        if met_lock {
            release_second_tx.send(()).unwrap();
        }
        let second_result = second.join().unwrap();
        test_hooks::clear(path);
        (first_result, second_result)
    }

    /// Two enrollments that overlap in time both survive: the second writer
    /// meets the held lock, waits, and then loads the first writer's record.
    #[test]
    fn concurrent_enrollments_preserve_both_entries() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("default.toml");
        let first_store = OperatorApprovalCredentialStore::new(path.clone());
        let second_store = OperatorApprovalCredentialStore::new(path.clone());
        let (first, second) = interleave(
            &path,
            move || first_store.enroll(make_credential(21, "first")),
            move || second_store.enroll(make_credential(22, "second")),
        );
        first.unwrap();
        second.unwrap();
        let ids: Vec<String> = OperatorApprovalCredentialStore::new(path)
            .list()
            .unwrap()
            .into_iter()
            .map(|c| c.credential_id_b64url)
            .collect();
        assert_eq!(
            ids,
            vec![valid_credential_id_b64(21), valid_credential_id_b64(22)]
        );
    }

    /// Of two overlapping counter updates, a lower counter that loses the
    /// race to a higher one is refused and the higher one stays stored; in
    /// the other order both succeed and the higher one is stored last.
    #[test]
    fn concurrent_counter_updates_never_regress() {
        for (first_counter, second_counter) in [(10_u32, 5_u32), (5, 10)] {
            let dir = tempfile::TempDir::new().unwrap();
            let path = dir.path().join("default.toml");
            let cred = make_credential(23, "laptop");
            let id = cred.credential_id_b64url.clone();
            OperatorApprovalCredentialStore::new(path.clone())
                .enroll(cred)
                .unwrap();
            let first_store = OperatorApprovalCredentialStore::new(path.clone());
            let second_store = OperatorApprovalCredentialStore::new(path.clone());
            let (first_id, second_id) = (id.clone(), id.clone());
            let (first, second) = interleave(
                &path,
                move || first_store.update_sign_count(&first_id, first_counter),
                move || second_store.update_sign_count(&second_id, second_counter),
            );
            first.unwrap();
            if second_counter < first_counter {
                assert!(
                    matches!(second, Err(ApprovalError::SignCounterRegression { .. })),
                    "{second:?}"
                );
            } else {
                second.unwrap();
            }
            let stored = OperatorApprovalCredentialStore::new(path)
                .find_by_credential_id(&id)
                .unwrap()
                .unwrap()
                .sign_count;
            assert_eq!(stored, Some(first_counter.max(second_counter)));
        }
    }

    /// A removal that overlaps a paused counter update or enrollment stays
    /// removed: the paused writer cannot write the removed record back, and
    /// a later counter update finds nothing.
    #[test]
    fn removal_cannot_be_undone_by_stale_writer() {
        for paused_enrollment in [false, true] {
            let dir = tempfile::TempDir::new().unwrap();
            let path = dir.path().join("default.toml");
            let cred = make_credential(24, "laptop");
            let id = cred.credential_id_b64url.clone();
            OperatorApprovalCredentialStore::new(path.clone())
                .enroll(cred)
                .unwrap();
            let first_store = OperatorApprovalCredentialStore::new(path.clone());
            let second_store = OperatorApprovalCredentialStore::new(path.clone());
            let (first_id, second_id) = (id.clone(), id.clone());
            let (first, removed) = interleave(
                &path,
                move || {
                    if paused_enrollment {
                        first_store.enroll(make_credential(25, "phone"))
                    } else {
                        first_store.update_sign_count(&first_id, 7)
                    }
                },
                move || second_store.remove(&second_id),
            );
            first.unwrap();
            assert!(removed.unwrap(), "the removal found the record");
            let store = OperatorApprovalCredentialStore::new(path);
            assert!(store.find_by_credential_id(&id).unwrap().is_none());
            assert!(matches!(
                store.update_sign_count(&id, 8),
                Err(ApprovalError::NotFound)
            ));
            assert_eq!(
                store.list().unwrap().len(),
                usize::from(paused_enrollment),
                "the paused enrollment survives the removal"
            );
        }
    }

    /// Removal reports whether a record was removed, leaves other records,
    /// and a second removal reports `false` without writing.
    #[test]
    fn remove_is_idempotent_and_leaves_other_records() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("default.toml");
        let store = OperatorApprovalCredentialStore::new(path.clone());
        let keep = make_credential(26, "keep");
        let gone = make_credential(27, "gone");
        store.enroll(keep.clone()).unwrap();
        store.enroll(gone.clone()).unwrap();

        assert!(store.remove(&gone.credential_id_b64url).unwrap());
        assert_eq!(store.list().unwrap(), vec![keep.clone()]);
        let modified = fs::metadata(&path).unwrap().modified().unwrap();
        assert!(!store.remove(&gone.credential_id_b64url).unwrap());
        assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), modified);
        assert_eq!(store.list().unwrap(), vec![keep]);
        assert!(!store.remove("never-enrolled").unwrap());
    }

    /// A writer that cannot take the lock refuses with `WriterLocked` and
    /// changes nothing; the sidecar lock file stays in place between writes.
    #[test]
    fn held_lock_refuses_every_mutation_without_writing() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("default.toml");
        let store = OperatorApprovalCredentialStore::new(path.clone());
        let cred = make_credential(28, "laptop");
        let id = cred.credential_id_b64url.clone();
        store.enroll(cred).unwrap();
        let sidecar = dir.path().join("default.toml.lock");
        assert!(sidecar.exists(), "the sidecar lock file persists");
        let before = fs::read(&path).unwrap();

        let held = LockHandle::acquire(&sidecar).unwrap();
        assert!(matches!(
            store.enroll(make_credential(29, "other")),
            Err(ApprovalError::WriterLocked)
        ));
        assert!(matches!(
            store.update_sign_count(&id, 3),
            Err(ApprovalError::WriterLocked)
        ));
        assert!(matches!(
            store.remove(&id),
            Err(ApprovalError::WriterLocked)
        ));
        assert_eq!(fs::read(&path).unwrap(), before);
        drop(held);

        assert!(store.remove(&id).unwrap());
        assert!(sidecar.exists(), "release never deletes the sidecar");
    }

    /// A label with a control character anywhere refuses before the write
    /// lock: an absent store stays absent with no lock sidecar, and an
    /// existing store keeps its bytes.
    #[test]
    fn enroll_refuses_a_label_with_a_control_character() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("labels.toml");
        let sidecar = dir.path().join("labels.toml.lock");
        let store = OperatorApprovalCredentialStore::new(path.clone());
        for label in [
            "lap\u{1b}[2Ktop",
            "laptop\r",
            "\u{85}laptop",
            "\tlaptop",
            "lap\u{7f}",
        ] {
            assert!(
                matches!(
                    store.enroll(make_credential(40, label)),
                    Err(ApprovalError::Invalid { .. })
                ),
                "{label:?}"
            );
        }
        assert!(!path.exists());
        assert!(!sidecar.exists(), "refused before the write lock");

        store.enroll(make_credential(41, "laptop")).unwrap();
        let before = fs::read(&path).unwrap();
        assert!(matches!(
            store.enroll(make_credential(42, "phone\u{9b}2J")),
            Err(ApprovalError::Invalid { .. })
        ));
        assert_eq!(fs::read(&path).unwrap(), before);
        assert_eq!(store.list().unwrap(), vec![make_credential(41, "laptop")]);
    }

    /// The default store path never leaves the credential directory: a
    /// profile name that is not a safe path component refuses, and a safe
    /// one names a file directly inside the directory.
    #[test]
    fn default_path_refuses_a_profile_name_that_escapes_the_directory() {
        for name in [
            "../escape",
            "/tmp/escape",
            "nested/escape",
            "..",
            "",
            "a\\b",
        ] {
            assert!(
                matches!(
                    default_operator_approval_credentials_path(name),
                    Err(ApprovalError::Invalid { .. })
                ),
                "{name:?}"
            );
        }
        let path = default_operator_approval_credentials_path("laptop").unwrap();
        assert_eq!(path.file_name().unwrap(), "laptop.toml");
        assert!(
            path.parent()
                .unwrap()
                .ends_with("operator-approval-credentials"),
            "{path:?}"
        );
    }
}
