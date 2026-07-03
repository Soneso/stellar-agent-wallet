//! Pinned install record for toolsets.
//!
//! Each installed toolset has a corresponding pin record stored at
//! `<toolsets_root>/<package>/.stellar-agent-toolset-pin.json`.  The record
//! stores the **package name** (not a deletable path) plus the version,
//! shasum, publisher public key (G-strkey), and install timestamp.
//!
//! ## Atomic write (temp+rename, same-FS)
//!
//! Pin records are written atomically: the content is written to a temporary
//! file inside the toolsets root (same filesystem as the final location), then
//! renamed over the target path.  If the rename fails, the temporary file is
//! removed.  If a pin write fails after the toolset directory has been moved,
//! the toolset directory is rolled back (removed).

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use stellar_agent_toolsets::CapabilitySet;

use crate::{ToolsetInstallError, validate_package_name};

/// File name for the pin record inside the toolset package directory.
pub(crate) const PIN_FILE_NAME: &str = ".stellar-agent-toolset-pin.json";

/// Pinned install record for a toolset.
///
/// Stored as `<toolsets_root>/<package>/.stellar-agent-toolset-pin.json`.
///
/// ## Capability fields
///
/// `capabilities` and `allowed_tools` are persisted at install time from the
/// signature-verified `TOOLSET.md` parse output.  Dispatch reads these fields
/// from the pin rather than re-parsing on-disk `TOOLSET.md` (TOCTOU avoidance).
///
/// ### Legacy pin behaviour
///
/// Both fields use `#[serde(default)]`: a pin record written before this
/// extension will deserialise with `capabilities = CapabilitySet::empty()`
/// and `allowed_tools = vec![]`.  An empty capabilities set means the runtime
/// grants no capability, so every key-touching action is refused (fail-closed)
/// until the toolset is reinstalled with a current binary.
///
/// See also: `tests::legacy_pin_without_capabilities_fails_closed`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ToolsetPinRecord {
    /// Package name (`[a-z0-9-]`).
    ///
    /// This is the VALIDATED name, not a stored path — uninstall
    /// reconstructs the path from this name.
    pub package: String,

    /// Installed version (SemVer string).
    pub version: String,

    /// Lowercase hex SHA-256 of the installed package bytes (64 chars).
    pub shasum: String,

    /// Publisher public key as a Stellar G-strkey.
    ///
    /// Not redacted in the pin record (it is stored, not logged); only
    /// redacted in `Display`/log output.
    pub publisher: String,

    /// ISO-8601 install timestamp (UTC).
    pub installed_at: String,

    /// Capabilities declared by the toolset manifest, persisted at install time.
    ///
    /// Sourced from the signature-verified `TOOLSET.md` parse.
    /// Default: [`CapabilitySet::empty()`] — a legacy pin with no `capabilities`
    /// field deserialises to an empty set, which **refuses every action** until
    /// reinstall (fail-closed).
    ///
    /// ## Integrity provenance
    ///
    /// The capabilities INHERIT install-time provenance (parsed from the
    /// shasum-verified, publisher-signed package) but, once COPIED into the
    /// locally-written unsigned pin JSON, are thereafter protected only by the
    /// toolsets-dir trust boundary — NOT by the shasum (no over-claim).
    /// The signing isolation (no toolset can EVER reach a signing/key tool) is
    /// STRUCTURAL and tamper-proof regardless of pin contents.
    #[serde(default)]
    pub capabilities: CapabilitySet,

    /// Intersective `allowed_tools` from the toolset manifest, persisted at install time.
    ///
    /// When non-empty, narrows the capability grant: only tools present in
    /// BOTH the capability matrix AND this list are reachable.  An empty list
    /// means no narrowing (the full capability grant applies).
    ///
    /// Default: `vec![]` — legacy pins with no `allowed_tools` field
    /// deserialise to an empty list (no narrowing).
    #[serde(default)]
    pub allowed_tools: Vec<String>,

    /// SHA-256 hex digest (64 lowercase hex chars) of the `TOOLSET.md` bytes as
    /// extracted at install time.
    ///
    /// At every dispatch, the toolsets runtime re-reads the on-disk `TOOLSET.md`,
    /// recomputes SHA-256, and compares against this field.  A mismatch refuses
    /// the dispatch.
    ///
    /// ## Legacy behaviour
    ///
    /// `#[serde(default)]` → `None` for pins written before this field was added.
    /// Legacy pins skip the re-verification step at dispatch (no `toolset_md_shasum`
    /// to compare against).  This is intentionally OPEN for legacy pins — the
    /// capability-source invariant (runtime reads capabilities from the pin, not
    /// from the on-disk `TOOLSET.md`) ensures that a tampered `TOOLSET.md` cannot
    /// escalate capabilities even without the digest check.  Reinstalling with a
    /// current binary populates the field and activates the check.
    ///
    /// ## Security scope
    ///
    /// The `TOOLSET.md` digest covers post-install tamper detection of the toolset's
    /// human-readable manifest.  It does NOT re-verify the full package hash
    /// (`pin.shasum` is SHA-256 of the original `.tar.gz` tarball, which is not
    /// retained post-extraction).  The capability-escalation attack path is
    /// already closed by reading capabilities from the pin rather than re-parsing
    /// the on-disk file; this check adds tamper-evidence for the manifest text.
    #[serde(default)]
    pub toolset_md_shasum: Option<String>,
}

impl ToolsetPinRecord {
    /// Returns the path for this pin record relative to `toolsets_root`.
    ///
    /// Path: `<toolsets_root>/<package>/<PIN_FILE_NAME>`.
    #[must_use]
    pub fn pin_path(&self, toolsets_root: &Path) -> PathBuf {
        toolsets_root.join(&self.package).join(PIN_FILE_NAME)
    }

    /// Constructs a `ToolsetPinRecord` for use in tests and integration fixtures.
    ///
    /// This constructor exists because `ToolsetPinRecord` is `#[non_exhaustive]`
    /// — struct expressions are only legal within the defining crate.  External
    /// test code (e.g. sibling runtime-layer unit tests) needs a way to build a
    /// pin without going through the full install pipeline.
    ///
    /// Only available under `#[cfg(any(test, feature = "test-helpers"))]` — not
    /// reachable from production binaries.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// // Available in test builds or with the "test-helpers" feature.
    /// use stellar_agent_toolsets::CapabilitySet;
    /// use stellar_agent_toolsets_install::ToolsetPinRecord;
    ///
    /// let pin = ToolsetPinRecord::build_for_test(
    ///     "my-toolset",
    ///     "1.0.0",
    ///     &"a".repeat(64),
    ///     "GABC...",
    ///     "2026-06-12T00:00:00Z",
    ///     CapabilitySet::empty(),
    ///     vec![],
    ///     None,
    /// );
    /// ```
    #[cfg(any(test, feature = "test-helpers"))]
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn build_for_test(
        package: impl Into<String>,
        version: impl Into<String>,
        shasum: impl Into<String>,
        publisher: impl Into<String>,
        installed_at: impl Into<String>,
        capabilities: stellar_agent_toolsets::CapabilitySet,
        allowed_tools: Vec<String>,
        toolset_md_shasum: Option<String>,
    ) -> Self {
        Self {
            package: package.into(),
            version: version.into(),
            shasum: shasum.into(),
            publisher: publisher.into(),
            installed_at: installed_at.into(),
            capabilities,
            allowed_tools,
            toolset_md_shasum,
        }
    }
}

/// Writes a pin record atomically (temp+rename, same filesystem).
///
/// Steps:
/// 1. Serialise `record` to JSON.
/// 2. Write to a temp file inside `toolsets_root` (same FS → rename is atomic).
/// 3. Rename temp → `record.pin_path(toolsets_root)`.
///
/// If the rename fails, the temp file is removed and the error is returned.
///
/// # Errors
///
/// - [`ToolsetInstallError::Io`] — serialisation, write, or rename fails.
pub(crate) fn write_pin_atomic(
    record: &ToolsetPinRecord,
    toolsets_root: &Path,
) -> Result<(), ToolsetInstallError> {
    let json = serde_json::to_string_pretty(record)
        .map_err(|e| ToolsetInstallError::from_io(std::io::Error::other(e.to_string())))?;

    let target_path = record.pin_path(toolsets_root);

    // Write to a temp file inside toolsets_root (same FS).
    let tmp =
        tempfile::NamedTempFile::new_in(toolsets_root).map_err(ToolsetInstallError::from_io)?;
    {
        let mut writer = std::io::BufWriter::new(tmp.as_file());
        writer
            .write_all(json.as_bytes())
            .map_err(ToolsetInstallError::from_io)?;
        writer.flush().map_err(ToolsetInstallError::from_io)?;
    }

    // Atomic rename.
    tmp.persist(&target_path).map_err(|e| {
        // persist returns a PersistError; extract the io::Error.
        ToolsetInstallError::from_io(e.error)
    })?;

    Ok(())
}

/// Reads and parses the pin record for `package` from `toolsets_root`.
///
/// Validates `package` against the `[a-z0-9-]` charset BEFORE constructing
/// any filesystem path: a `package` value containing `/`, `\`, `.`, `..`, or
/// any character outside `[a-z0-9-]` is rejected immediately with
/// [`ToolsetInstallError::InvalidPackageName`] and produces NO filesystem path
/// join.
///
/// Returns `None` if the pin file does not exist (toolset not installed).
///
/// # Errors
///
/// - [`ToolsetInstallError::InvalidPackageName`] — `package` fails the
///   `[a-z0-9-]` charset validation.
/// - [`ToolsetInstallError::PinRecordMalformed`] — pin file exists but cannot
///   be parsed or contains an invalid package name.
/// - [`ToolsetInstallError::Io`] — unexpected I/O error (not NotFound).
pub fn read_pin(
    package: &str,
    toolsets_root: &Path,
) -> Result<Option<ToolsetPinRecord>, ToolsetInstallError> {
    // Validate before ANY path join.
    validate_package_name(package)
        .map_err(|detail| ToolsetInstallError::InvalidPackageName { detail })?;

    let pin_path = toolsets_root.join(package).join(PIN_FILE_NAME);

    let content = match std::fs::read_to_string(&pin_path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(ToolsetInstallError::from_io(e)),
    };

    let record: ToolsetPinRecord =
        serde_json::from_str(&content).map_err(|_| ToolsetInstallError::PinRecordMalformed {
            detail: format!("pin record for '{package}' is not valid JSON"),
        })?;

    // Validate the stored package name.
    if let Err(reason) = validate_package_name(&record.package) {
        return Err(ToolsetInstallError::PinRecordMalformed {
            detail: format!(
                "pin record package name '{}' is invalid: {reason}",
                stellar_agent_toolsets::sanitise_display(&record.package, 64),
            ),
        });
    }

    Ok(Some(record))
}

/// Removes the pin record for `package` from `toolsets_root`.
///
/// Returns `Ok(())` if the file was removed successfully or did not exist.
///
/// # Errors
///
/// - [`ToolsetInstallError::Io`] — unexpected removal error.
pub(crate) fn remove_pin(package: &str, toolsets_root: &Path) -> Result<(), ToolsetInstallError> {
    let pin_path = toolsets_root.join(package).join(PIN_FILE_NAME);
    match std::fs::remove_file(&pin_path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(ToolsetInstallError::from_io(e)),
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use tempfile::TempDir;

    use super::*;

    fn test_record() -> ToolsetPinRecord {
        ToolsetPinRecord {
            package: "my-toolset".to_owned(),
            version: "1.0.0".to_owned(),
            shasum: "a".repeat(64),
            publisher: "GABC...XYZ".to_owned(),
            installed_at: "2026-06-01T00:00:00Z".to_owned(),
            capabilities: stellar_agent_toolsets::CapabilitySet::empty(),
            allowed_tools: vec![],
            toolset_md_shasum: None,
        }
    }

    #[test]
    fn write_and_read_pin_roundtrip() {
        let dir = TempDir::new().unwrap();
        let toolsets_root = dir.path();

        // Create the package directory (normally done by extraction).
        let pkg_dir = toolsets_root.join("my-toolset");
        std::fs::create_dir_all(&pkg_dir).unwrap();

        let record = test_record();
        write_pin_atomic(&record, toolsets_root).unwrap();

        let loaded = read_pin("my-toolset", toolsets_root).unwrap().unwrap();
        assert_eq!(loaded, record);
    }

    #[test]
    fn missing_pin_returns_none() {
        let dir = TempDir::new().unwrap();
        let result = read_pin("nonexistent", dir.path()).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn malformed_pin_returns_error() {
        let dir = TempDir::new().unwrap();
        let toolsets_root = dir.path();
        let pkg_dir = toolsets_root.join("bad-toolset");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        let pin_path = pkg_dir.join(PIN_FILE_NAME);
        std::fs::write(&pin_path, b"not json").unwrap();

        let err = read_pin("bad-toolset", toolsets_root).unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::PinRecordMalformed { .. }),
            "expected PinRecordMalformed, got: {err:?}"
        );
    }

    #[test]
    fn remove_pin_nonexistent_is_ok() {
        let dir = TempDir::new().unwrap();
        remove_pin("nonexistent", dir.path()).unwrap();
    }

    // A pin record written before the `capabilities` / `allowed_tools` fields
    // were added MUST deserialise with `capabilities = CapabilitySet::empty()`
    // and `allowed_tools = vec![]` — producing fail-closed behaviour at dispatch
    // time (every action refused until reinstall).
    #[test]
    fn legacy_pin_without_capabilities_fails_closed() {
        let dir = TempDir::new().unwrap();
        let toolsets_root = dir.path();
        let pkg_dir = toolsets_root.join("legacy-toolset");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        let pin_path = pkg_dir.join(PIN_FILE_NAME);

        // Write a legacy pin (no capabilities / allowed_tools fields).
        let legacy_json = r#"{
            "package": "legacy-toolset",
            "version": "1.0.0",
            "shasum": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "publisher": "GABC...XYZ",
            "installed_at": "2026-06-01T00:00:00Z"
        }"#;
        std::fs::write(&pin_path, legacy_json).unwrap();

        let pin = read_pin("legacy-toolset", toolsets_root).unwrap().unwrap();

        // capabilities must default to empty (fail-closed).
        assert!(
            pin.capabilities.is_empty(),
            "legacy pin must deserialise with empty capabilities (fail-closed)"
        );
        // allowed_tools must default to empty.
        assert!(
            pin.allowed_tools.is_empty(),
            "legacy pin must deserialise with empty allowed_tools"
        );
    }

    // Verify that read_pin rejects attacker-controlled package names containing
    // path traversal sequences BEFORE constructing any filesystem path.
    #[test]
    fn read_pin_dotdot_slash_rejected() {
        let dir = TempDir::new().unwrap();
        let err = read_pin("../foo", dir.path()).unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::InvalidPackageName { .. }),
            "expected InvalidPackageName for '../foo', got: {err:?}"
        );
    }

    #[test]
    fn read_pin_slash_in_name_rejected() {
        let dir = TempDir::new().unwrap();
        let err = read_pin("a/b", dir.path()).unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::InvalidPackageName { .. }),
            "expected InvalidPackageName for 'a/b', got: {err:?}"
        );
    }

    #[test]
    fn read_pin_backslash_in_name_rejected() {
        let dir = TempDir::new().unwrap();
        let err = read_pin("..\\foo", dir.path()).unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::InvalidPackageName { .. }),
            "expected InvalidPackageName for '..\\\\foo', got: {err:?}"
        );
    }

    // `build_for_test` is only compiled in test mode; exercise all arguments.
    #[test]
    fn build_for_test_constructs_matching_record() {
        use stellar_agent_toolsets::parse_capability_value_pub;

        let caps = parse_capability_value_pub("sign-payment").unwrap();
        let record = ToolsetPinRecord::build_for_test(
            "test-toolset",
            "1.2.3",
            "a".repeat(64),
            "GABC...XYZ",
            "2026-06-22T00:00:00Z",
            caps.clone(),
            vec!["stellar_pay".to_owned()],
            Some("dead".repeat(16)),
        );

        assert_eq!(record.package, "test-toolset");
        assert_eq!(record.version, "1.2.3");
        assert_eq!(record.shasum, "a".repeat(64));
        assert_eq!(record.publisher, "GABC...XYZ");
        assert_eq!(record.installed_at, "2026-06-22T00:00:00Z");
        assert_eq!(record.capabilities, caps);
        assert_eq!(record.allowed_tools, vec!["stellar_pay"]);
        assert_eq!(record.toolset_md_shasum, Some("dead".repeat(16)));
    }

    // Pin records where the stored `package` name fails validate_package_name
    // must be detected during read_pin and returned as PinRecordMalformed.
    #[test]
    fn read_pin_rejects_invalid_stored_package_name_in_json() {
        let dir = TempDir::new().unwrap();
        let toolsets_root = dir.path();
        // Create a package directory with a valid name.
        let pkg_dir = toolsets_root.join("good-name");
        std::fs::create_dir_all(&pkg_dir).unwrap();

        // Write a pin JSON where the inner `package` field has an invalid value.
        let invalid_pin_json = r#"{
            "package": "BADNAME!@#",
            "version": "1.0.0",
            "shasum": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "publisher": "GABC...XYZ",
            "installed_at": "2026-06-01T00:00:00Z"
        }"#;
        std::fs::write(pkg_dir.join(PIN_FILE_NAME), invalid_pin_json).unwrap();

        let err = read_pin("good-name", toolsets_root).unwrap_err();
        assert!(
            matches!(err, crate::ToolsetInstallError::PinRecordMalformed { .. }),
            "expected PinRecordMalformed for invalid stored name, got: {err:?}"
        );
    }

    #[test]
    fn pin_with_capabilities_roundtrip() {
        let dir = TempDir::new().unwrap();
        let toolsets_root = dir.path();
        let pkg_dir = toolsets_root.join("rich-toolset");
        std::fs::create_dir_all(&pkg_dir).unwrap();

        // Build a pin with capabilities.
        let caps =
            stellar_agent_toolsets::parse_capability_value_pub("read-balance propose-transaction")
                .unwrap();
        let record = ToolsetPinRecord {
            package: "rich-toolset".to_owned(),
            version: "2.0.0".to_owned(),
            shasum: "b".repeat(64),
            publisher: "GDEF...UVW".to_owned(),
            installed_at: "2026-06-01T12:00:00Z".to_owned(),
            capabilities: caps,
            allowed_tools: vec!["stellar_balances".to_owned(), "stellar_pay".to_owned()],
            toolset_md_shasum: None,
        };

        write_pin_atomic(&record, toolsets_root).unwrap();
        let loaded = read_pin("rich-toolset", toolsets_root).unwrap().unwrap();

        assert!(
            loaded
                .capabilities
                .contains(stellar_agent_toolsets::Capability::ReadBalance)
        );
        assert!(
            loaded
                .capabilities
                .contains(stellar_agent_toolsets::Capability::ProposeTransaction)
        );
        assert!(
            !loaded
                .capabilities
                .contains(stellar_agent_toolsets::Capability::SuggestDestination)
        );
        assert_eq!(
            loaded.allowed_tools,
            vec!["stellar_balances", "stellar_pay"]
        );
    }
}
