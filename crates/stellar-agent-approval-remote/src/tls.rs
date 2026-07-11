//! TLS certificate provisioning for the remote-approval listener.
//!
//! On first `--remote` start for a given profile, generates a self-signed
//! `rcgen` key + certificate for the configured `rp_id` under the profile
//! state directory (private key mode `0600` on Unix; the process refuses to
//! start if an existing key file has looser permissions). Subsequent starts
//! reuse the same key + certificate. The certificate's SAN is the `rp_id`
//! hostname, so the browser origin the WebAuthn ceremony binds to matches
//! the TLS certificate's subject.
//!
//! TLS is mandatory in remote mode: there is no plaintext remote path, and
//! `--remote` without a provisionable certificate is a hard start error.
//!
//! # Certificate lifetime
//!
//! `rcgen::generate_simple_self_signed`'s default validity window
//! (`1975-01-01` to `4096-01-01`) is used as-is: a long fixed validity so a
//! silently-expired cert is not a foreseeable failure mode. Re-provisioning
//! (deleting the stored key + cert files and restarting) is the documented
//! rotation path if the operator ever needs to force a new certificate
//! (e.g. suspected key compromise).

use std::fs;
use std::path::{Path, PathBuf};

use rcgen::{CertifiedKey, generate_simple_self_signed};
use sha2::{Digest as _, Sha256};

/// Errors provisioning or loading the remote-approval TLS certificate.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TlsProvisionError {
    /// An I/O error occurred reading or writing the cert/key files.
    #[error("remote-approval TLS I/O error: {kind:?}")]
    Io {
        /// The I/O error kind.
        kind: std::io::ErrorKind,
        /// The source error (not shown in Display; may embed a path).
        #[source]
        source: std::io::Error,
    },

    /// Certificate generation via `rcgen` failed.
    #[error("remote-approval TLS certificate generation failed: {detail}")]
    Generation {
        /// Non-secret diagnostic detail string.
        detail: String,
    },

    /// The existing private-key file has permissions looser than `0600` on
    /// Unix. The process refuses to start rather than silently trust a
    /// key file other local users may be able to read.
    #[error(
        "remote-approval TLS private key at {path:?} has permissions {mode:o}, \
         which is looser than the required 0600; refusing to start"
    )]
    KeyPermissionsTooOpen {
        /// The offending key file path.
        path: PathBuf,
        /// The actual mode bits observed.
        mode: u32,
    },

    /// The OS-conventional state directory could not be determined.
    #[error("could not determine the remote-approval TLS state directory")]
    StateDirUnavailable,
}

impl TlsProvisionError {
    fn from_io(e: std::io::Error) -> Self {
        Self::Io {
            kind: e.kind(),
            source: e,
        }
    }
}

/// A provisioned (freshly generated or reused) TLS certificate and key, in
/// PEM form, plus the certificate's SHA-256 fingerprint for out-of-band
/// operator verification.
///
/// `Debug` is hand-implemented to redact `cert_pem` and `key_pem` (the key
/// PEM is secret material; the cert PEM is not secret but is long and
/// uninformative in a log line — the fingerprint already carries the useful
/// summary).
pub struct ProvisionedTls {
    /// PEM-encoded certificate chain (single self-signed cert).
    pub cert_pem: Vec<u8>,
    /// PEM-encoded private key.
    pub key_pem: Vec<u8>,
    /// Lowercase-hex SHA-256 fingerprint of the DER certificate bytes, for
    /// the operator to verify out-of-band before trusting the certificate on
    /// the approving device (or to pin if not importing it into a trust
    /// store).
    pub fingerprint_sha256_hex: String,
}

impl std::fmt::Debug for ProvisionedTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProvisionedTls")
            .field("cert_pem", &"[redacted]")
            .field("key_pem", &"[redacted]")
            .field("fingerprint_sha256_hex", &self.fingerprint_sha256_hex)
            .finish()
    }
}

/// Returns `<dir>/<profile>-cert.pem` and `<dir>/<profile>-key.pem` paths
/// under the OS-conventional remote-approval TLS state directory.
///
/// # Errors
///
/// Returns [`TlsProvisionError::StateDirUnavailable`] if the platform
/// directories library cannot determine the state directory.
pub fn tls_file_paths(profile_name: &str) -> Result<(PathBuf, PathBuf), TlsProvisionError> {
    #[cfg(any(test, feature = "test-helpers"))]
    if let Some(home) = std::env::var_os("STELLAR_AGENT_HOME") {
        let dir = PathBuf::from(home).join("remote-approval-tls");
        return Ok((
            dir.join(format!("{profile_name}-cert.pem")),
            dir.join(format!("{profile_name}-key.pem")),
        ));
    }

    let root = stellar_agent_core::profile::schema::canonical_data_root()
        .map_err(|_| TlsProvisionError::StateDirUnavailable)?;
    let dir = root.join("remote-approval-tls");
    Ok((
        dir.join(format!("{profile_name}-cert.pem")),
        dir.join(format!("{profile_name}-key.pem")),
    ))
}

/// Provisions (generating on first use) the TLS certificate and key for
/// `rp_id` under `profile_name`'s state directory.
///
/// # Errors
///
/// - [`TlsProvisionError::KeyPermissionsTooOpen`] if an existing key file is
///   not mode `0600` on Unix.
/// - [`TlsProvisionError::Generation`] if certificate generation fails.
/// - [`TlsProvisionError::Io`] on read/write failure.
/// - [`TlsProvisionError::StateDirUnavailable`] if the state directory
///   cannot be resolved.
pub fn provision_or_load(
    profile_name: &str,
    rp_id: &str,
) -> Result<ProvisionedTls, TlsProvisionError> {
    let (cert_path, key_path) = tls_file_paths(profile_name)?;

    if cert_path.exists() && key_path.exists() {
        enforce_key_permissions(&key_path)?;
        let cert_pem = fs::read(&cert_path).map_err(TlsProvisionError::from_io)?;
        let key_pem = fs::read(&key_path).map_err(TlsProvisionError::from_io)?;
        let fingerprint_sha256_hex = fingerprint_from_pem(&cert_pem)?;
        return Ok(ProvisionedTls {
            cert_pem,
            key_pem,
            fingerprint_sha256_hex,
        });
    }

    let CertifiedKey { cert, signing_key } = generate_simple_self_signed(vec![rp_id.to_owned()])
        .map_err(|e| TlsProvisionError::Generation {
            detail: e.to_string(),
        })?;
    let cert_pem = cert.pem().into_bytes();
    let key_pem = signing_key.serialize_pem().into_bytes();
    let fingerprint_sha256_hex = hex_sha256(cert.der());

    persist_new_cert_and_key(&cert_path, &key_path, &cert_pem, &key_pem)?;

    Ok(ProvisionedTls {
        cert_pem,
        key_pem,
        fingerprint_sha256_hex,
    })
}

/// Writes freshly-generated cert and key files atomically, the key at mode
/// `0600` on Unix.
fn persist_new_cert_and_key(
    cert_path: &Path,
    key_path: &Path,
    cert_pem: &[u8],
    key_pem: &[u8],
) -> Result<(), TlsProvisionError> {
    let parent = cert_path
        .parent()
        .ok_or(TlsProvisionError::StateDirUnavailable)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .map_err(TlsProvisionError::from_io)?;
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(parent).map_err(TlsProvisionError::from_io)?;
    }

    write_atomic(cert_path, cert_pem, 0o644)?;
    write_atomic(key_path, key_pem, 0o600)?;

    Ok(())
}

/// Writes `bytes` to `path` atomically (temp-file + rename), setting Unix
/// mode `mode` before the rename.
fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<(), TlsProvisionError> {
    use std::io::Write as _;

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(parent).map_err(TlsProvisionError::from_io)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        tmp.as_file()
            .set_permissions(fs::Permissions::from_mode(mode))
            .map_err(TlsProvisionError::from_io)?;
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
    }

    tmp.write_all(bytes).map_err(TlsProvisionError::from_io)?;
    tmp.flush().map_err(TlsProvisionError::from_io)?;
    tmp.persist(path)
        .map_err(|e| TlsProvisionError::from_io(e.error))?;
    Ok(())
}

/// Refuses to proceed if `key_path`'s Unix mode is looser than `0600`.
///
/// A no-op on non-Unix platforms — Windows ACL enforcement is out of scope
/// for this check.
fn enforce_key_permissions(key_path: &Path) -> Result<(), TlsProvisionError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let meta = fs::metadata(key_path).map_err(TlsProvisionError::from_io)?;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(TlsProvisionError::KeyPermissionsTooOpen {
                path: key_path.to_path_buf(),
                mode,
            });
        }
    }
    #[cfg(not(unix))]
    {
        let _ = key_path;
    }
    Ok(())
}

/// Computes the SHA-256 fingerprint of a PEM certificate's DER bytes.
fn fingerprint_from_pem(cert_pem: &[u8]) -> Result<String, TlsProvisionError> {
    let pem_str = std::str::from_utf8(cert_pem).map_err(|_| TlsProvisionError::Generation {
        detail: "stored certificate PEM is not valid UTF-8".to_owned(),
    })?;
    let der = pem_decode_first_block(pem_str).ok_or_else(|| TlsProvisionError::Generation {
        detail: "stored certificate PEM has no CERTIFICATE block".to_owned(),
    })?;
    Ok(hex_sha256(&der))
}

/// Minimal single-block PEM decoder (base64 body between `-----BEGIN
/// CERTIFICATE-----` and `-----END CERTIFICATE-----`), avoiding a dependency
/// on a general-purpose PEM crate for this one read path.
fn pem_decode_first_block(pem_str: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    let start = pem_str.find("-----BEGIN CERTIFICATE-----")?;
    let end = pem_str.find("-----END CERTIFICATE-----")?;
    let body_start = start + "-----BEGIN CERTIFICATE-----".len();
    if end <= body_start {
        return None;
    }
    let body: String = pem_str[body_start..end]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    base64::engine::general_purpose::STANDARD.decode(body).ok()
}

/// Lowercase-hex SHA-256 of `bytes`.
fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only"
    )]
    use super::*;
    use serial_test::serial;

    #[allow(
        unsafe_code,
        reason = "test-only, serialised via #[serial]: process-env mutation is race-free with \
                  no concurrent readers of this specific var"
    )]
    fn with_isolated_home<T>(f: impl FnOnce(&std::path::Path) -> T) -> T {
        let dir = tempfile::TempDir::new().unwrap();
        unsafe {
            std::env::set_var("STELLAR_AGENT_HOME", dir.path());
        }
        let result = f(dir.path());
        unsafe {
            std::env::remove_var("STELLAR_AGENT_HOME");
        }
        result
    }

    #[test]
    #[serial]
    fn provisions_fresh_cert_and_key_with_0600_permissions() {
        with_isolated_home(|_home| {
            let provisioned = provision_or_load("test-profile-a", "wallet.internal").unwrap();
            assert!(!provisioned.cert_pem.is_empty());
            assert!(!provisioned.key_pem.is_empty());
            assert_eq!(provisioned.fingerprint_sha256_hex.len(), 64);

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                let (_, key_path) = tls_file_paths("test-profile-a").unwrap();
                let mode = fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
                assert_eq!(mode, 0o600, "key file must be mode 0600, got {mode:o}");
            }
        });
    }

    #[test]
    #[serial]
    fn reuses_existing_cert_and_key_across_calls() {
        with_isolated_home(|_home| {
            let first = provision_or_load("test-profile-b", "wallet.internal").unwrap();
            let second = provision_or_load("test-profile-b", "wallet.internal").unwrap();
            assert_eq!(first.fingerprint_sha256_hex, second.fingerprint_sha256_hex);
            assert_eq!(first.cert_pem, second.cert_pem);
            assert_eq!(first.key_pem, second.key_pem);
        });
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn refuses_to_start_when_existing_key_has_loose_permissions() {
        use std::os::unix::fs::PermissionsExt as _;
        with_isolated_home(|_home| {
            let _ = provision_or_load("test-profile-c", "wallet.internal").unwrap();
            let (_, key_path) = tls_file_paths("test-profile-c").unwrap();
            fs::set_permissions(&key_path, fs::Permissions::from_mode(0o644)).unwrap();

            let err = provision_or_load("test-profile-c", "wallet.internal").unwrap_err();
            assert!(matches!(
                err,
                TlsProvisionError::KeyPermissionsTooOpen { .. }
            ));
        });
    }
}
