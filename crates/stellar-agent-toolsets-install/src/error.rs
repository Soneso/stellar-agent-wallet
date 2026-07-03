//! Closed-set typed error surface for toolset install and uninstall operations.
//!
//! [`ToolsetInstallError`] is the single error type returned by all public
//! functions in this crate.  Every variant carries enough context to act on
//! the error, with all attacker-influenced strings (paths, I/O details)
//! length-capped and sanitised at render time to prevent terminal-spoof and
//! log-injection.
//!
//! ## Redaction discipline
//!
//! - Publisher public keys (G-strkeys) are redacted to first-5-last-5 in
//!   `Display` output via [`stellar_agent_core::observability::redact::redact_strkey_first5_last5`].
//! - Auditor public keys are redacted to first-5-last-5 (same rule).
//! - I/O error details and paths run through
//!   [`stellar_agent_toolsets::sanitise_display`] (length-cap 256 + control/ANSI
//!   strip) before inclusion in `Display` output.
//! - Attestation signature bytes NEVER appear in any error `Display` or `Debug`
//!   output.
//!
//! ## Closed-set parity test
//!
//! `tests/error_parity.rs` locks the variant count so that an accidental
//! deletion or addition is caught at CI time.

use stellar_agent_toolsets::ToolsetFormatError;

/// Typed closed-set error for toolset install and uninstall operations.
///
/// ## Variant overview
///
/// | Variant | Trigger |
/// |---------|---------|
/// | `Io` | OS-level I/O failure (file open, read, write, rename, remove). |
/// | `PackageTooLarge` | Package bytes exceed [`crate::MAX_PACKAGE_BYTES`]. |
/// | `HashMismatch` | SHA-256 of package bytes ≠ signed `shasum`. |
/// | `SignatureInvalid` | ed25519 publisher signature fails `verify_strict`. |
/// | `UntrustedPublisher` | Signer public key not in the publisher trust set. |
/// | `TrustSetEmpty` | Trust-set file is absent or contains no entries (publisher or auditor). |
/// | `TrustSetMalformed` | Trust-set file contains a malformed or duplicate entry. |
/// | `InvalidVersion` | Version string fails SemVer parse or length cap. |
/// | `InvalidShasum` | `signed_shasum` argument is not exactly 64 lowercase hex chars. |
/// | `InvalidPackageName` | Package name fails the `[a-z0-9-]` validation rule. |
/// | `ArchivePathTraversal` | Archive entry path escapes the package root. |
/// | `ArchiveEntryNameInvalid` | Archive entry name contains NUL, control bytes, non-UTF-8, or non-ASCII. |
/// | `ArchiveDisallowedEntryType` | Archive entry is a symlink, hardlink, device, FIFO, or other disallowed type. |
/// | `ArchiveDuplicateEntry` | Two archive entries normalise to the same ASCII-lowercase key. |
/// | `ArchiveTooManyEntries` | Archive entry count exceeds the cap. |
/// | `ArchiveEntryTooLarge` | A single entry's decompressed size exceeds the per-entry cap. |
/// | `ArchiveTooLarge` | Total decompressed output exceeds the cap. |
/// | `ArchiveTrailingData` | Gzip stream contains trailing data after the first member (multi-member or garbage rejected). |
/// | `ArchiveBadTopLevel` | Archive does not contain exactly one top-level directory named after the package. |
/// | `ToolsetFormat` | `TOOLSET.md` parse/validation failed (wraps [`ToolsetFormatError`]). |
/// | `IdentityMismatch` | Extracted `TOOLSET.md` `name` ≠ signed package `name`. Version is bound by signature. |
/// | `AlreadyInstalled` | Toolset is already installed and `--force` was not supplied. |
/// | `VersionDowngrade` | `--force` reinstall would downgrade the version; requires `--allow-downgrade`. |
/// | `NotInstalled` | Uninstall requested for a toolset that is not installed. |
/// | `PinRecordMalformed` | Stored pin record is invalid (bad name, escaping path, or symlink target) during uninstall. |
/// | `ToolsetsRootInvalid` | The toolsets root directory itself is a symlink leaf (install-time check). |
/// | `AttestationRequired` | Toolset declares a key-touching capability but no attestation was supplied and `override_attestation` is `false`. |
/// | `AttestationInvalid` | Attestation signature fails `verify_strict`, or `auditor_pubkey` is not a valid ed25519 point. |
/// | `AuditorUntrusted` | Auditor public key is not in the auditor trust set. |
/// | `AttestationFieldMismatch` | An attestation field (`package`/`version`/`shasum`/`capabilities`) does not match the verified install values. |
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ToolsetInstallError {
    /// OS-level I/O error.
    ///
    /// The `detail` string is sanitised (length-capped at 256 chars,
    /// control/ANSI stripped) to prevent log-injection.
    #[error("i/o error: {detail}")]
    Io {
        /// Sanitised I/O error detail (std::io::Error Display, capped + stripped).
        detail: String,
    },

    /// Package bytes exceed the maximum allowed size.
    ///
    /// The size limit prevents OOM on untrusted sources; reading is aborted as
    /// soon as the limit is reached.
    #[error("package too large: exceeds {cap} bytes")]
    PackageTooLarge {
        /// Configured cap in bytes.
        cap: usize,
    },

    /// SHA-256 of the package bytes does not match the signed `shasum`.
    ///
    /// This indicates either data corruption or a tampered package.
    #[error("hash mismatch: package bytes do not match the signed shasum")]
    HashMismatch,

    /// ed25519 signature failed `verify_strict`.
    ///
    /// The signature was well-formed but cryptographically invalid for the
    /// signed payload and claimed publisher key.
    #[error("signature invalid: ed25519 verify_strict failed")]
    SignatureInvalid,

    /// The signer public key is not present in the trust set.
    ///
    /// The publisher key is redacted to first-5-last-5 in `Display` output.
    #[error("untrusted publisher: signer {publisher_key_redacted} is not in the trust set")]
    UntrustedPublisher {
        /// Publisher G-strkey, redacted to first-5-last-5.
        publisher_key_redacted: String,
    },

    /// Trust-set file is absent or contains no entries.
    ///
    /// An empty trust set means no toolset can be installed (fail-closed).
    #[error(
        "trust set empty: no publisher keys configured; add at least one G-strkey to the trust set"
    )]
    TrustSetEmpty,

    /// Trust-set file contains a malformed or duplicate entry.
    ///
    /// The entire file is rejected on any single bad entry (ALL-OR-NOTHING
    /// parse contract).
    #[error("trust set malformed: {detail}")]
    TrustSetMalformed {
        /// Sanitised description of the malformed entry.
        detail: String,
    },

    /// Version string fails SemVer parse or exceeds the length cap.
    ///
    /// For package-name failures see [`ToolsetInstallError::InvalidPackageName`].
    /// For shasum format failures see [`ToolsetInstallError::InvalidShasum`].
    #[error("invalid version: {detail}")]
    InvalidVersion {
        /// Sanitised description of the parse failure.
        detail: String,
    },

    /// Shasum argument fails format validation.
    ///
    /// The `signed_shasum` argument must be exactly 64 lowercase hexadecimal
    /// characters (`[0-9a-f]`).  Uppercase hex digits, wrong length, or
    /// non-hex characters all trigger this variant before any hash comparison
    /// or signature verification.
    #[error("invalid shasum: {detail}")]
    InvalidShasum {
        /// Sanitised description of the format failure.
        detail: String,
    },

    /// Package name fails the `[a-z0-9-]` validation rule.
    ///
    /// A package name must be non-empty, ≤ 64 characters, contain only
    /// lowercase ASCII letters, digits, and hyphens, and must not start,
    /// end, or contain consecutive hyphens.
    #[error("invalid package name: {detail}")]
    InvalidPackageName {
        /// Sanitised description of the validation failure.
        detail: String,
    },

    /// Archive entry path escapes the package root.
    ///
    /// Triggered by `..` components, absolute paths, drive prefixes, or
    /// root-only paths.
    #[error("archive path traversal: entry {entry_name} escapes the package root")]
    ArchivePathTraversal {
        /// Sanitised entry name (length-capped, control/ANSI stripped).
        entry_name: String,
    },

    /// Archive entry name contains NUL, control bytes, or non-UTF-8 bytes.
    ///
    /// Entry names are validated before any path comparison.
    #[error("archive entry name invalid: {detail}")]
    ArchiveEntryNameInvalid {
        /// Sanitised description of the invalid name.
        detail: String,
    },

    /// Archive entry is a disallowed type (symlink, hardlink, device, FIFO, etc.).
    ///
    /// Type check is performed FIRST, before any path or body read.
    #[error("archive disallowed entry type: entry type is not Regular or Directory")]
    ArchiveDisallowedEntryType,

    /// Two archive entries normalise to the same ASCII-lowercase key.
    ///
    /// Rejected to prevent APFS/HFS+ case-folding attacks.  ASCII-lowercase
    /// collision detection is used; full Unicode NFC+case-fold is not yet
    /// implemented.
    #[error(
        "archive duplicate entry: {entry_name} collides with an already-seen entry (ASCII-lowercase)"
    )]
    ArchiveDuplicateEntry {
        /// Sanitised entry name that triggered the collision.
        entry_name: String,
    },

    /// Archive entry count exceeds the configured cap.
    #[error("archive too many entries: exceeds the {cap}-entry cap")]
    ArchiveTooManyEntries {
        /// Configured entry count cap.
        cap: usize,
    },

    /// A single entry's decompressed size exceeds the per-entry cap.
    #[error("archive entry too large: a single entry exceeds {cap} bytes decompressed")]
    ArchiveEntryTooLarge {
        /// Per-entry decompressed byte cap.
        cap: usize,
    },

    /// Total decompressed output exceeds the cap.
    #[error("archive too large: total decompressed output exceeds {cap} bytes")]
    ArchiveTooLarge {
        /// Total decompressed byte cap.
        cap: usize,
    },

    /// Gzip stream contains trailing data after the first member.
    ///
    /// Any non-zero byte after the first gzip footer is rejected — whether
    /// it forms a second gzip member (multi-member concatenation) or is
    /// arbitrary garbage.  Only tar end-of-archive zero padding is tolerated.
    #[error("archive trailing data: gzip stream contains trailing bytes after the first member")]
    ArchiveTrailingData,

    /// Archive top-level shape is invalid.
    ///
    /// A valid package must contain exactly one top-level directory whose name
    /// equals the package name.
    #[error(
        "archive bad top-level: expected exactly one directory named after the package; got {detail}"
    )]
    ArchiveBadTopLevel {
        /// Sanitised description of the top-level shape found.
        detail: String,
    },

    /// `TOOLSET.md` parse or validation failed.
    ///
    /// Wraps [`ToolsetFormatError`]; the staging directory is rolled back on
    /// this error.
    #[error("toolset format error: {0}")]
    ToolsetFormat(#[from] ToolsetFormatError),

    /// Extracted `TOOLSET.md` `name` does not match the signed package `name`.
    ///
    /// Version identity is established by the SIGNATURE BINDING — the signed
    /// tuple includes the version string, so a package cannot be relabeled to
    /// a different version without invalidating the signature.  Only the `name`
    /// field is content-cross-checked here because `TOOLSET.md` carries a name
    /// but no version field.
    ///
    /// The `field` is always `"name"` in current code; `"version"` is reserved
    /// for a future format revision that adds a version field to `TOOLSET.md`.
    #[error("identity mismatch: TOOLSET.md {field} '{extracted}' != signed '{expected}'")]
    IdentityMismatch {
        /// Which field mismatched (`"name"`; `"version"` reserved for future use).
        field: &'static str,
        /// The value found in the extracted TOOLSET.md (sanitised).
        extracted: String,
        /// The value from the signed package identity tuple (sanitised).
        expected: String,
    },

    /// Toolset is already installed and `--force` was not supplied.
    #[error(
        "already installed: '{package}' {installed_version} is already installed; use --force to reinstall"
    )]
    AlreadyInstalled {
        /// Package name (validated `[a-z0-9-]`).
        package: String,
        /// Currently installed version string.
        installed_version: String,
    },

    /// `--force` reinstall would downgrade the installed version.
    ///
    /// Downgrade (installing an older version over a newer one) is refused by
    /// default; pass `--allow-downgrade` to override.
    #[error(
        "version downgrade refused: new {new_version} < installed {installed_version}; use --allow-downgrade to override"
    )]
    VersionDowngrade {
        /// New version being installed.
        new_version: String,
        /// Currently installed version.
        installed_version: String,
    },

    /// Uninstall was requested for a toolset that is not installed.
    #[error("not installed: '{package}' is not installed")]
    NotInstalled {
        /// Package name requested for uninstall (validated).
        package: String,
    },

    /// The stored pin record is invalid.
    ///
    /// Triggered during uninstall when the pin record's `package` name fails
    /// validation or the reconstructed path escapes the toolsets root or resolves
    /// to a symlink.  NOT used for install-time toolsets-root checks; see
    /// [`ToolsetInstallError::ToolsetsRootInvalid`] for those.
    #[error("pin record malformed: {detail}")]
    PinRecordMalformed {
        /// Sanitised description of the malformed field.
        detail: String,
    },

    /// The toolsets root directory is invalid at install time.
    ///
    /// Triggered when the toolsets root directory leaf is a symlink
    /// (no-follow discipline).  Distinct from
    /// [`ToolsetInstallError::PinRecordMalformed`] which covers uninstall
    /// pin-record issues.
    #[error("toolsets root invalid: {detail}")]
    ToolsetsRootInvalid {
        /// Sanitised description of the invalid root.
        detail: String,
    },

    /// Toolset declares a key-touching capability but no attestation was supplied
    /// and `override_attestation` is `false`.
    ///
    /// A key-touching toolset (e.g. `sign-payment`) MUST be accompanied by a
    /// valid auditor attestation when `override_attestation` is `false`.
    /// Absent attestation → install is refused before any artefact is written.
    #[error(
        "attestation required: '{package}' declares a key-touching capability \
         but no attestation was supplied; provide an attestation or use --override-attestation"
    )]
    AttestationRequired {
        /// Package name (validated `[a-z0-9-]`).
        package: String,
    },

    /// Attestation signature is cryptographically invalid.
    ///
    /// Covers both cases opaquely:
    /// - `auditor_pubkey` is not a valid compressed ed25519 point.
    /// - ed25519 `verify_strict` fails for the attestation signature over the
    ///   canonical preimage.
    ///
    /// The error is intentionally opaque — no key bytes, no signature bytes,
    /// no oracle for an attacker to distinguish the two cases.
    #[error("attestation invalid: {detail}")]
    AttestationInvalid {
        /// Opaque, non-attacker-influenced description (`&'static str`).
        ///
        /// Uses `&'static str` so no heap allocation occurs and the set of
        /// possible messages is closed at compile time.
        detail: &'static str,
    },

    /// Auditor public key is not in the auditor trust set.
    ///
    /// The auditor key carried in the attestation is not present in
    /// `<toolsets_dir>/auditor-trust.txt`.  Note that the auditor trust set is
    /// DISTINCT from the publisher trust set (`trust.txt`) — placing a key in
    /// `trust.txt` does NOT implicitly grant auditor status.
    ///
    /// The auditor key is redacted to first-5-last-5 in `Display`.
    #[error(
        "auditor untrusted: auditor {auditor_key_redacted} is not in the auditor trust set \
         (auditor-trust.txt); add the key to trust it"
    )]
    AuditorUntrusted {
        /// Auditor G-strkey, redacted to first-5-last-5.
        auditor_key_redacted: String,
    },

    /// An attestation field does not match the verified install values.
    ///
    /// One of `package`, `version`, `shasum`, or `capabilities` in the
    /// `ToolsetAttestation` struct does not equal the value from the verified
    /// install context.  This prevents cross-package / version / capability
    /// replay attacks.
    ///
    /// The `field` is a closed set of `&'static str` values —
    /// `"package"` / `"version"` / `"shasum"` / `"capabilities"` — so no
    /// attacker-controlled string reaches the error.
    #[error(
        "attestation field mismatch: attestation {field} does not match the verified install values"
    )]
    AttestationFieldMismatch {
        /// Which field mismatched: `"package"` / `"version"` / `"shasum"` / `"capabilities"`.
        ///
        /// Closed set of `&'static str` — no attacker-influenced string.
        field: &'static str,
    },
}

impl ToolsetInstallError {
    /// Constructs an [`ToolsetInstallError::Io`] from a [`std::io::Error`].
    ///
    /// The error's `Display` string is sanitised (length-capped at 256 chars,
    /// control/ANSI stripped) to prevent log-injection.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_toolsets_install::error::ToolsetInstallError;
    ///
    /// let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
    /// let err = ToolsetInstallError::from_io(io_err);
    /// assert!(matches!(err, ToolsetInstallError::Io { .. }));
    /// ```
    #[must_use]
    // `err` is taken by value because this function is used as a `map_err`
    // callback (`map_err(ToolsetInstallError::from_io)`) which requires an
    // owned argument.  The value is not further moved after `to_string()`,
    // but changing to a reference would break the callback use site.
    #[allow(clippy::needless_pass_by_value)]
    pub fn from_io(err: std::io::Error) -> Self {
        Self::Io {
            detail: stellar_agent_toolsets::sanitise_display(&err.to_string(), 256),
        }
    }
}
