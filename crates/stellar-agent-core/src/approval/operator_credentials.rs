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

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use super::error::ApprovalError;
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
    /// A caller may seed this field at enrollment time with a counter value
    /// read client-side from the registration ceremony (e.g. the interactive
    /// loopback enrollment server extracts it from
    /// `AuthenticatorAttestationResponse.getAuthenticatorData()`). That value
    /// is client-supplied and, unlike an assertion-time counter, is never
    /// checked against a signature — nothing stops a caller from reporting
    /// any number here. This is acceptable because the field feeds only the
    /// clone-detection regression check in
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
    /// Does not touch the filesystem: the file is created lazily on first
    /// [`Self::enroll`] or [`Self::update_sign_count`] call. Reads return an
    /// empty registry when the file does not yet exist.
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
            detail: format!("operator_credentials: {e}"),
        })
    }

    /// Atomically persists the registry via temp-file + rename.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalError::Io`] on I/O failure or [`ApprovalError::Toml`]
    /// on serialisation failure.
    fn persist(&self, file: &OperatorCredentialStoreFile) -> Result<(), ApprovalError> {
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));

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
    /// # Errors
    ///
    /// - [`ApprovalError::Invalid`] if `credential.credential_id_b64url` or
    ///   `credential.public_key_sec1_b64` fails format validation.
    /// - [`ApprovalError::DuplicateCredentialId`] if a credential with the
    ///   same `credential_id_b64url` is already enrolled. Remove it first
    ///   (via a future explicit removal path) to re-enroll under the same ID.
    /// - [`ApprovalError::Io`] / [`ApprovalError::Toml`] on persistence
    ///   failure.
    pub fn enroll(&self, credential: OperatorApprovalCredential) -> Result<(), ApprovalError> {
        validate_credential_invariants(
            &credential.credential_id_b64url,
            &credential.public_key_sec1_b64,
        )?;

        let mut file = self.load()?;
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
        self.persist(&file)
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
    /// # Errors
    ///
    /// - [`ApprovalError::NotFound`] if no credential with
    ///   `credential_id_b64url` is enrolled.
    /// - [`ApprovalError::SignCounterRegression`] if the regression check
    ///   above fails. The stored counter is NOT updated in this case.
    /// - [`ApprovalError::Io`] / [`ApprovalError::Toml`] on persistence
    ///   failure.
    pub fn update_sign_count(
        &self,
        credential_id_b64url: &str,
        presented_counter: u32,
    ) -> Result<(), ApprovalError> {
        let mut file = self.load()?;
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
        self.persist(&file)
    }
}

/// Returns the default path for a profile's operator-approval credential
/// store: `<dir>/<profile>.toml` under
/// [`crate::profile::schema::default_operator_approval_credentials_dir`].
///
/// # Errors
///
/// Returns [`ApprovalError::Io`] if the OS-conventional state directory
/// cannot be resolved.
pub fn default_operator_approval_credentials_path(
    profile_name: &str,
) -> Result<PathBuf, ApprovalError> {
    let dir = crate::profile::schema::default_operator_approval_credentials_dir().map_err(|e| {
        ApprovalError::from_io_detail(
            std::io::ErrorKind::Other,
            format!("operator_approval_credentials_path: {e}"),
        )
    })?;
    Ok(dir.join(format!("{profile_name}.toml")))
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
}
