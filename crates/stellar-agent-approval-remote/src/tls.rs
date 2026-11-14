//! TLS certificate provisioning for the remote-approval listener.
//!
//! [`provision_or_load`] serves a testnet profile without configured certificate
//! files. [`load_pinned`] serves a certificate pinned by its SubjectPublicKeyInfo
//! hash, as an owner-signed approval origin names it, and never generates
//! one.
//!
//! # Generated certificates
//!
//! On first testnet start without configured TLS paths, generates a self-signed
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
//!
//! # Pinned certificates
//!
//! [`load_pinned`] reads an operator-provided certificate file and key file.
//! The leaf is the first `CERTIFICATE` block of the certificate file, the
//! end-entity certificate a TLS server sends first. A bounded walk over its
//! DER reads `Certificate`, `tbsCertificate`, the optional `[0]` version,
//! `serialNumber`, `signature`, `issuer`, `validity` and `subject`, and stops
//! at `subjectPublicKeyInfo`. SHA-256 over that element's whole encoding must
//! equal the pin, else the load refuses with
//! [`TlsProvisionError::CertPinMismatch`]. The walk accepts definite minimal
//! lengths within their enclosing element and the expected tag at each step,
//! and no byte after the certificate. A missing or unreadable file names its
//! field, and nothing is generated in its place.
//! Mainnet always requires both configured paths, even when default files exist.
//! The SPKI pin differs from a fingerprint of the complete certificate.
//! Browsers separately trust a public CA or an installed private CA.
//! Policy signing and certificate replacement require restart; TLS never reloads in place.
//! Issuance, renewal automation and TLS-terminating proxies are outside this module's scope.

use std::fs;
use std::path::{Path, PathBuf};

use rcgen::{CertifiedKey, generate_simple_self_signed};
use sha2::{Digest as _, Sha256};
use stellar_agent_core::ApprovalFailure;

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

    /// A configured certificate or key file cannot be used.
    /// Nothing is generated in its place.
    #[error("remote-approval TLS {field} {problem}")]
    FileUnavailable {
        /// The configuration field that names the file.
        field: TlsFileField,
        /// What is wrong with the file.
        problem: TlsFileProblem,
    },

    /// The leaf certificate's SubjectPublicKeyInfo does not hash to the
    /// pin. Its approval code is `approval.cert_pin_mismatch`.
    #[error("{}", ApprovalFailure::CertPinMismatch)]
    CertPinMismatch,
}

impl TlsProvisionError {
    /// Renders configuration refusals while retaining the provisioning permission mapping.
    #[must_use]
    pub fn wallet_error(&self) -> stellar_agent_core::WalletError {
        use stellar_agent_core::{WalletError, error::InternalError};
        match self {
            Self::CertPinMismatch => WalletError::Approval(ApprovalFailure::CertPinMismatch),
            Self::FileUnavailable { .. } => {
                WalletError::Approval(ApprovalFailure::RemoteTlsUnavailable {
                    detail: self.to_string(),
                })
            }
            _ => WalletError::Internal(InternalError::UnexpectedState {
                detail: format!("approve.remote_tls_provision_failed: {self}"),
            }),
        }
    }

    fn from_io(e: std::io::Error) -> Self {
        Self::Io {
            kind: e.kind(),
            source: e,
        }
    }

    /// The approval failure this refusal reports, for a refusal that has
    /// an approval code: [`ApprovalFailure::CertPinMismatch`] for
    /// [`Self::CertPinMismatch`].
    #[must_use]
    pub fn approval_failure(&self) -> Option<ApprovalFailure> {
        match self {
            Self::CertPinMismatch => Some(ApprovalFailure::CertPinMismatch),
            _ => None,
        }
    }
}

/// The configuration field that names a TLS file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TlsFileField {
    /// `cert_path`: the PEM certificate file, leaf first.
    CertPath,
    /// `key_path`: the PEM private key file.
    KeyPath,
}

impl TlsFileField {
    /// The field name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CertPath => "cert_path",
            Self::KeyPath => "key_path",
        }
    }
}

impl std::fmt::Display for TlsFileField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a configured TLS file cannot be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TlsFileProblem {
    /// No file exists at the path.
    Missing,
    /// The file exists but cannot be read.
    Unreadable,
    /// The certificate file holds no `CERTIFICATE` block.
    NoCertificate,
    /// The first `CERTIFICATE` block is not a certificate the walk reads.
    MalformedCertificate,
    /// The certificate and key cannot form a TLS server configuration.
    InvalidPair,
}

impl std::fmt::Display for TlsFileProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Missing => "names no file",
            Self::Unreadable => "names a file that cannot be read",
            Self::NoCertificate => "names a file without a CERTIFICATE block",
            Self::MalformedCertificate => "names a file whose first certificate is malformed",
            Self::InvalidPair => "contains malformed PEM or does not match cert_path",
        })
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
    /// PEM-encoded certificate chain, leaf first.
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

/// Loads the certificate at `cert_path` and the key at `key_path`, whose
/// leaf certificate's SubjectPublicKeyInfo must hash to `pin`.
///
/// Never generates a certificate. The leaf is the first `CERTIFICATE` block
/// of the certificate file; the whole file is served as the chain. The key
/// file must pass the same permission check as a generated key. The
/// fingerprint is the SHA-256 of the leaf's whole DER, as
/// [`provision_or_load`] reports it.
///
/// # Errors
///
/// - [`TlsProvisionError::FileUnavailable`] naming `cert_path` or
///   `key_path` for a missing or unreadable file. It names `cert_path` for
///   a missing `CERTIFICATE` block or a first certificate the walk refuses.
/// - [`TlsProvisionError::KeyPermissionsTooOpen`] if the key file is not
///   mode `0600` on Unix.
/// - [`TlsProvisionError::CertPinMismatch`] if the leaf's
///   SubjectPublicKeyInfo does not hash to `pin`.
pub fn load_pinned(
    cert_path: &Path,
    key_path: &Path,
    pin: &[u8; 32],
) -> Result<ProvisionedTls, TlsProvisionError> {
    let tls = load_configured(cert_path, key_path)?;
    verify_pin(&tls, pin)?;
    Ok(tls)
}

/// Loads an explicit PEM pair without generating files.
///
/// # Errors
/// Returns the configured field refusal or private-key permission refusal.
fn load_configured(cert_path: &Path, key_path: &Path) -> Result<ProvisionedTls, TlsProvisionError> {
    let cert_pem = read_configured(cert_path, TlsFileField::CertPath)?;
    let cert_text = std::str::from_utf8(&cert_pem)
        .map_err(|_| file_problem(TlsFileField::CertPath, TlsFileProblem::NoCertificate))?;
    let leaf = pem_decode_first_block(cert_text)
        .ok_or_else(|| file_problem(TlsFileField::CertPath, TlsFileProblem::NoCertificate))?;
    leaf_spki(&leaf).ok_or_else(|| {
        file_problem(TlsFileField::CertPath, TlsFileProblem::MalformedCertificate)
    })?;
    let metadata = fs::metadata(key_path).map_err(|e| file_error(TlsFileField::KeyPath, &e))?;
    if !metadata.is_file() {
        return Err(file_problem(
            TlsFileField::KeyPath,
            TlsFileProblem::Unreadable,
        ));
    }
    enforce_key_permissions(key_path)?;
    let key_pem = read_configured(key_path, TlsFileField::KeyPath)?;
    Ok(ProvisionedTls {
        fingerprint_sha256_hex: hex_sha256(&leaf),
        cert_pem,
        key_pem,
    })
}

/// Checks the actual served leaf against the startup pin.
pub(crate) fn verify_pin(tls: &ProvisionedTls, pin: &[u8; 32]) -> Result<(), TlsProvisionError> {
    let leaf = std::str::from_utf8(&tls.cert_pem)
        .ok()
        .and_then(pem_decode_first_block)
        .ok_or_else(|| file_problem(TlsFileField::CertPath, TlsFileProblem::NoCertificate))?;
    let spki = leaf_spki(&leaf).ok_or_else(|| {
        file_problem(TlsFileField::CertPath, TlsFileProblem::MalformedCertificate)
    })?;
    if Sha256::digest(spki).as_slice() != pin.as_slice() {
        return Err(TlsProvisionError::CertPinMismatch);
    }
    Ok(())
}

/// Selects explicit files, or testnet provisioning when both paths are absent.
///
/// A signed pin requires both paths. An incomplete pair always refuses.
///
/// # Errors
/// Returns missing-field, file, permission, provisioning, or pin refusals.
pub async fn select_tls(
    profile_name: &str,
    config: &stellar_agent_core::profile::schema::RemoteApprovalConfig,
    pin: Option<&[u8; 32]>,
) -> Result<(ProvisionedTls, axum_server::tls_rustls::RustlsConfig), TlsProvisionError> {
    let tls = match (&config.cert_path, &config.key_path) {
        (Some(cert), Some(key)) => match pin {
            Some(pin) => load_pinned(cert, key, pin),
            None => load_configured(cert, key),
        },
        (None, None) if pin.is_none() => provision_or_load(profile_name, &config.rp_id),
        (None, _) => Err(file_problem(
            TlsFileField::CertPath,
            TlsFileProblem::Missing,
        )),
        (_, None) => Err(file_problem(TlsFileField::KeyPath, TlsFileProblem::Missing)),
    }?;
    let server = server_config(&tls).await?;
    Ok((tls, server))
}

pub(crate) async fn server_config(
    tls: &ProvisionedTls,
) -> Result<axum_server::tls_rustls::RustlsConfig, TlsProvisionError> {
    axum_server::tls_rustls::RustlsConfig::from_pem(tls.cert_pem.clone(), tls.key_pem.clone())
        .await
        .map_err(|_| file_problem(TlsFileField::KeyPath, TlsFileProblem::InvalidPair))
}

/// The bytes of the configured file at `path`, refusing with `field`.
fn read_configured(path: &Path, field: TlsFileField) -> Result<Vec<u8>, TlsProvisionError> {
    fs::read(path).map_err(|e| file_error(field, &e))
}

/// The refusal of a file `field` names whose read failed with `error`.
fn file_error(field: TlsFileField, error: &std::io::Error) -> TlsProvisionError {
    let problem = if error.kind() == std::io::ErrorKind::NotFound {
        TlsFileProblem::Missing
    } else {
        TlsFileProblem::Unreadable
    };
    file_problem(field, problem)
}

fn file_problem(field: TlsFileField, problem: TlsFileProblem) -> TlsProvisionError {
    TlsProvisionError::FileUnavailable { field, problem }
}

/// The DER tag of a `SEQUENCE`.
const DER_SEQUENCE: u8 = 0x30;
/// The DER tag of an `INTEGER`.
const DER_INTEGER: u8 = 0x02;
/// The DER tag of the explicit `[0]` version of a `tbsCertificate`.
const DER_VERSION: u8 = 0xa0;
/// The most length octets the walk reads; a four-octet length already
/// exceeds any certificate a listener serves.
const DER_LENGTH_OCTETS_MAX: usize = 4;

/// One DER element: its contents and its whole encoding.
struct DerElement<'a> {
    contents: &'a [u8],
    encoding: &'a [u8],
}

/// Reads the element at the start of `input` when its tag is `tag`, and
/// returns it with the bytes after it.
///
/// The length must be definite and minimal, with the short form below 128.
/// The long form has one to four octets, no leading zero octet and a value
/// of at least 128. The contents must lie within `input`.
fn der_element(input: &[u8], tag: u8) -> Option<(DerElement<'_>, &[u8])> {
    let (&found, rest) = input.split_first()?;
    if found != tag {
        return None;
    }
    let (&first, rest) = rest.split_first()?;
    let (length, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > DER_LENGTH_OCTETS_MAX || rest.len() < count {
            return None;
        }
        let (octets, rest) = rest.split_at(count);
        if octets.first() == Some(&0) {
            return None;
        }
        let length = octets.iter().try_fold(0usize, |acc, &octet| {
            acc.checked_mul(256)?.checked_add(usize::from(octet))
        })?;
        if length < 0x80 {
            return None;
        }
        (length, rest)
    };
    if rest.len() < length {
        return None;
    }
    let (contents, after) = rest.split_at(length);
    let header = input.len() - rest.len();
    Some((
        DerElement {
            contents,
            encoding: &input[..header + length],
        },
        after,
    ))
}

/// The whole encoding of the `subjectPublicKeyInfo` of the certificate
/// `der`, or `None` when the walk refuses its shape.
///
/// The certificate must be the whole input. Within it the walk reads
/// `tbsCertificate`, then the optional `[0]` version, `serialNumber`,
/// `signature`, `issuer`, `validity` and `subject`, each with its own tag,
/// and returns the next `SEQUENCE`. Nothing after `subjectPublicKeyInfo` is
/// read.
fn leaf_spki(der: &[u8]) -> Option<&[u8]> {
    let (certificate, trailing) = der_element(der, DER_SEQUENCE)?;
    if !trailing.is_empty() {
        return None;
    }
    let (tbs, _) = der_element(certificate.contents, DER_SEQUENCE)?;
    let mut fields = tbs.contents;
    if fields.first() == Some(&DER_VERSION) {
        fields = der_element(fields, DER_VERSION)?.1;
    }
    let (_serial, fields) = der_element(fields, DER_INTEGER)?;
    let (_signature, fields) = der_element(fields, DER_SEQUENCE)?;
    let (_issuer, fields) = der_element(fields, DER_SEQUENCE)?;
    let (_validity, fields) = der_element(fields, DER_SEQUENCE)?;
    let (_subject, fields) = der_element(fields, DER_SEQUENCE)?;
    let (spki, _) = der_element(fields, DER_SEQUENCE)?;
    Some(spki.encoding)
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
            stellar_agent_test_support::sandbox::mark_sandbox(dir.path()).unwrap();
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

    /// The pinned load, over certificates from the test generator.
    #[cfg(feature = "test-helpers")]
    mod pinned {
        use super::*;
        use crate::test_helpers::{PinnedLeaf, pinned_leaf};

        const HOST: &str = "approve.example.invalid";

        /// The DER of the first `CERTIFICATE` block of `pem`.
        fn der_of(pem: &str) -> Vec<u8> {
            pem_decode_first_block(pem).unwrap()
        }

        /// Writes `cert` and `key` into `dir`, the key at mode `0600`, and
        /// returns their paths.
        fn write_pair(dir: &Path, cert: &str, key: &str) -> (PathBuf, PathBuf) {
            let cert_path = dir.join("cert.pem");
            let key_path = dir.join("key.pem");
            fs::write(&cert_path, cert).unwrap();
            fs::write(&key_path, key).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();
            }
            (cert_path, key_path)
        }

        fn leaves() -> [(&'static str, PinnedLeaf); 2] {
            [
                ("P-256", pinned_leaf(HOST, &rcgen::PKCS_ECDSA_P256_SHA256)),
                ("Ed25519", pinned_leaf(HOST, &rcgen::PKCS_ED25519)),
            ]
        }

        /// The walked SPKI hashes to the pin rcgen derives from the key pair,
        /// for a single leaf and for a chain file whose leaf comes first.
        /// The load serves the whole file and fingerprints the leaf.
        #[test]
        fn spki_walk_matches_the_independent_spki() {
            for (label, leaf) in leaves() {
                for (form, pem) in [("leaf", leaf.cert_pem.clone()), ("chain", leaf.chain_pem())] {
                    let der = der_of(&pem);
                    let spki = leaf_spki(&der).unwrap();
                    assert_eq!(Sha256::digest(spki).as_slice(), leaf.pin, "{label} {form}");
                    let dir = tempfile::TempDir::new().unwrap();
                    let (cert_path, key_path) = write_pair(dir.path(), &pem, &leaf.key_pem);
                    let tls = load_pinned(&cert_path, &key_path, &leaf.pin).unwrap();
                    assert_eq!(tls.cert_pem, pem.as_bytes(), "{label} {form}");
                    assert_eq!(tls.key_pem, leaf.key_pem.as_bytes(), "{label} {form}");
                    assert_eq!(
                        tls.fingerprint_sha256_hex,
                        hex_sha256(&der),
                        "{label} {form}"
                    );
                }
                let issuer_first = format!("{}{}", leaf.issuer_pem, leaf.cert_pem);
                let issuer_der = der_of(&issuer_first);
                let issuer_spki = leaf_spki(&issuer_der).unwrap();
                assert_ne!(Sha256::digest(issuer_spki).as_slice(), leaf.pin, "{label}");
            }
        }

        /// The minimal DER length octets of `length`.
        fn length_octets(length: usize) -> Vec<u8> {
            if length < 0x80 {
                return vec![u8::try_from(length).unwrap()];
            }
            let octets: Vec<u8> = length
                .to_be_bytes()
                .into_iter()
                .skip_while(|&b| b == 0)
                .collect();
            let mut out = vec![0x80 | u8::try_from(octets.len()).unwrap()];
            out.extend(octets);
            out
        }

        /// The minimal DER encoding of `tag` over `contents`.
        fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
            let mut out = vec![tag];
            out.extend(length_octets(contents.len()));
            out.extend_from_slice(contents);
            out
        }

        /// The header length and contents length of the element at the
        /// start of `der`, read without the walk's checks.
        fn header(der: &[u8]) -> (usize, usize) {
            if der[1] < 0x80 {
                return (2, usize::from(der[1]));
            }
            let count = usize::from(der[1] & 0x7f);
            let length = der[2..2 + count]
                .iter()
                .fold(0usize, |acc, &b| acc * 256 + usize::from(b));
            (2 + count, length)
        }

        /// A certificate taken apart: the whole encodings of the
        /// `tbsCertificate` fields, and the bytes after `tbsCertificate`.
        #[derive(Clone)]
        struct Parts {
            fields: Vec<Vec<u8>>,
            after_tbs: Vec<u8>,
        }

        impl Parts {
            fn of(der: &[u8]) -> Self {
                let (cert_header, cert_length) = header(der);
                let contents = &der[cert_header..cert_header + cert_length];
                let (tbs_header, tbs_length) = header(contents);
                let mut rest = &contents[tbs_header..tbs_header + tbs_length];
                let after_tbs = contents[tbs_header + tbs_length..].to_vec();
                let mut fields = Vec::new();
                while !rest.is_empty() {
                    let (h, l) = header(rest);
                    fields.push(rest[..h + l].to_vec());
                    rest = &rest[h + l..];
                }
                Self { fields, after_tbs }
            }

            /// The certificate with `tbs_tag` and `cert_tag`, minimal lengths.
            fn build_with(&self, tbs_tag: u8, cert_tag: u8) -> Vec<u8> {
                let mut contents = tlv(tbs_tag, &self.fields.concat());
                contents.extend_from_slice(&self.after_tbs);
                tlv(cert_tag, &contents)
            }

            fn build(&self) -> Vec<u8> {
                self.build_with(0x30, 0x30)
            }
        }

        /// The walk refuses each shape other than a minimal definite
        /// certificate with the expected tags and nothing after it.
        #[test]
        fn spki_walk_refuses_every_other_shape() {
            let leaf = pinned_leaf(HOST, &rcgen::PKCS_ECDSA_P256_SHA256);
            let der = der_of(&leaf.cert_pem);
            let parts = Parts::of(&der);
            assert_eq!(
                parts.build(),
                der,
                "the generated certificate is minimal DER"
            );
            assert_eq!(
                parts.fields[0][0], DER_VERSION,
                "the leaf names its version"
            );
            assert!(parts.fields.len() >= 7);
            assert!(leaf_spki(&der).is_some());

            let mut shapes: Vec<(String, Vec<u8>)> = Vec::new();
            for tag in [0x31, 0x04, 0xa0] {
                let mut certificate = der.clone();
                certificate[0] = tag;
                shapes.push((format!("Certificate tag {tag:#04x}"), certificate));
                shapes.push((
                    format!("tbsCertificate tag {tag:#04x}"),
                    parts.build_with(tag, 0x30),
                ));
            }
            for (index, name) in [
                "version",
                "serialNumber",
                "signature",
                "issuer",
                "validity",
                "subject",
                "subjectPublicKeyInfo",
            ]
            .into_iter()
            .enumerate()
            {
                let mut changed = parts.clone();
                changed.fields[index][0] = 0x04;
                shapes.push((format!("{name} tag"), changed.build()));
            }

            let (cert_header, cert_length) = header(&der);
            let mut indefinite = vec![0x30, 0x80];
            indefinite.extend_from_slice(&der[cert_header..cert_header + cert_length]);
            indefinite.extend_from_slice(&[0, 0]);
            shapes.push(("indefinite Certificate length".to_owned(), indefinite));
            let mut changed = parts.clone();
            let subject = changed.fields[5].clone();
            let (h, l) = header(&subject);
            let mut indefinite_subject = vec![subject[0], 0x80];
            indefinite_subject.extend_from_slice(&subject[h..h + l]);
            indefinite_subject.extend_from_slice(&[0, 0]);
            changed.fields[5] = indefinite_subject;
            shapes.push(("indefinite subject length".to_owned(), changed.build()));

            let mut padded = vec![0x30, 0x80 | u8::try_from(cert_header - 1).unwrap(), 0];
            padded.extend_from_slice(&der[2..]);
            shapes.push(("leading zero length octet".to_owned(), padded));
            let mut changed = parts.clone();
            let serial = changed.fields[1].clone();
            assert!(serial[1] < 0x80, "the serial number has a short length");
            let mut long_serial = vec![serial[0], 0x81, serial[1]];
            long_serial.extend_from_slice(&serial[2..]);
            changed.fields[1] = long_serial;
            shapes.push(("long form of a short length".to_owned(), changed.build()));
            let mut five_octets = vec![0x30, 0x85, 0, 0, 0];
            five_octets.extend_from_slice(&der[2..]);
            shapes.push(("five length octets".to_owned(), five_octets));

            let mut longer = vec![0x30];
            longer.extend(length_octets(cert_length + 1));
            longer.extend_from_slice(&der[cert_header..]);
            shapes.push(("Certificate length past the input".to_owned(), longer));
            let mut changed = parts.clone();
            let spki_index = 6;
            changed.fields.truncate(spki_index + 1);
            let spki = changed.fields[spki_index].clone();
            let mut past = spki.clone();
            assert!(past[1] < 0x7f, "the P-256 key info has a short length");
            past[1] += 1;
            changed.fields[spki_index] = past;
            shapes.push((
                "subjectPublicKeyInfo length past tbsCertificate".to_owned(),
                changed.build(),
            ));

            shapes.push(("truncated".to_owned(), der[..der.len() - 1].to_vec()));
            let mut trailing = der.clone();
            trailing.push(0);
            shapes.push(("one trailing byte".to_owned(), trailing));
            let mut second = der.clone();
            second.extend_from_slice(&der);
            shapes.push(("a second certificate in one block".to_owned(), second));
            shapes.push(("empty".to_owned(), Vec::new()));

            for (label, shape) in shapes {
                assert!(leaf_spki(&shape).is_none(), "{label}");
            }

            let dir = tempfile::TempDir::new().unwrap();
            let (cert_path, key_path) = write_pair(
                dir.path(),
                "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n",
                &leaf.key_pem,
            );
            assert!(matches!(
                load_pinned(&cert_path, &key_path, &leaf.pin),
                Err(TlsProvisionError::FileUnavailable {
                    field: TlsFileField::CertPath,
                    problem: TlsFileProblem::MalformedCertificate,
                })
            ));
        }

        /// A leaf of another key refuses with the pin mismatch code and its
        /// message, and returns no certificate.
        #[test]
        fn signed_origin_refuses_cert_pin_mismatch() {
            let served = pinned_leaf(HOST, &rcgen::PKCS_ECDSA_P256_SHA256);
            let signed = pinned_leaf(HOST, &rcgen::PKCS_ECDSA_P256_SHA256);
            assert_ne!(served.pin, signed.pin);
            let dir = tempfile::TempDir::new().unwrap();
            for pem in [served.cert_pem.clone(), served.chain_pem()] {
                let (cert_path, key_path) = write_pair(dir.path(), &pem, &served.key_pem);
                let error = load_pinned(&cert_path, &key_path, &signed.pin).unwrap_err();
                assert!(matches!(error, TlsProvisionError::CertPinMismatch));
                let failure = error.approval_failure().unwrap();
                assert_eq!(failure.code(), "approval.cert_pin_mismatch");
                assert_eq!(
                    error.to_string(),
                    "The served certificate does not match the owner-signed pin; install the pinned certificate or sign a new pin."
                );
                assert_eq!(error.to_string(), failure.to_string());
            }
            let (cert_path, key_path) = write_pair(dir.path(), &signed.issuer_pem, &signed.key_pem);
            assert!(matches!(
                load_pinned(&cert_path, &key_path, &signed.pin),
                Err(TlsProvisionError::CertPinMismatch)
            ));
        }

        /// Each missing, unreadable or certificate-less file names its field
        /// and refuses; no certificate is generated under the state
        /// directory.
        #[test]
        #[serial]
        fn signed_origin_refuses_missing_pem_without_fallback() {
            with_isolated_home(|home| {
                let leaf = pinned_leaf(HOST, &rcgen::PKCS_ECDSA_P256_SHA256);
                let dir = tempfile::TempDir::new().unwrap();
                let (cert_path, key_path) = write_pair(dir.path(), &leaf.cert_pem, &leaf.key_pem);
                let absent = dir.path().join("absent.pem");
                let directory = dir.path().join("directory.pem");
                std::fs::create_dir(&directory).unwrap();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt as _;
                    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
                }
                let no_block = dir.path().join("no-block.pem");
                fs::write(&no_block, leaf.key_pem.as_bytes()).unwrap();
                let cases = [
                    (
                        &absent,
                        &key_path,
                        TlsFileField::CertPath,
                        TlsFileProblem::Missing,
                    ),
                    (
                        &cert_path,
                        &absent,
                        TlsFileField::KeyPath,
                        TlsFileProblem::Missing,
                    ),
                    (
                        &directory,
                        &key_path,
                        TlsFileField::CertPath,
                        TlsFileProblem::Unreadable,
                    ),
                    (
                        &cert_path,
                        &directory,
                        TlsFileField::KeyPath,
                        TlsFileProblem::Unreadable,
                    ),
                    (
                        &no_block,
                        &key_path,
                        TlsFileField::CertPath,
                        TlsFileProblem::NoCertificate,
                    ),
                ];
                for (cert, key, field, problem) in cases {
                    let error = load_pinned(cert, key, &leaf.pin).unwrap_err();
                    match &error {
                        TlsProvisionError::FileUnavailable {
                            field: named,
                            problem: found,
                        } => assert_eq!((*named, *found), (field, problem), "{error}"),
                        other => panic!("{field} {problem:?}: {other:?}"),
                    }
                    assert!(error.to_string().contains(field.as_str()), "{error}");
                    assert!(error.approval_failure().is_none());
                }
                let (generated_cert, generated_key) = tls_file_paths("default").unwrap();
                assert!(generated_cert.starts_with(home));
                assert!(!home.join("remote-approval-tls").exists());
                assert!(!generated_cert.exists() && !generated_key.exists());
            });
        }

        /// A key file other users can read refuses as a generated key does.
        #[cfg(unix)]
        #[test]
        fn signed_origin_keeps_key_permission_refusal() {
            use std::os::unix::fs::PermissionsExt as _;
            let leaf = pinned_leaf(HOST, &rcgen::PKCS_ECDSA_P256_SHA256);
            let dir = tempfile::TempDir::new().unwrap();
            let (cert_path, key_path) = write_pair(dir.path(), &leaf.cert_pem, &leaf.key_pem);
            assert!(load_pinned(&cert_path, &key_path, &leaf.pin).is_ok());
            fs::set_permissions(&key_path, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(matches!(
                load_pinned(&cert_path, &key_path, &leaf.pin),
                Err(TlsProvisionError::KeyPermissionsTooOpen { mode: 0o644, .. })
            ));
        }
    }
}
