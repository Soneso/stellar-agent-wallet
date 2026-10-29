//! Pinned install record for toolsets.
//!
//! Each installed toolset has a corresponding pin record stored at
//! `<toolsets_root>/<package>/.stellar-agent-toolset-pin.json`.  The record
//! stores the **package name** (not a deletable path) plus the version,
//! shasum, publisher public key (G-strkey), install timestamp, the capability
//! grant, the `allowed_tools` narrowing, and the `TOOLSET.md` digest.
//!
//! ## Authentication
//!
//! The record is authenticated by an HMAC-SHA256 tag under the installation's
//! [`PinKey`], a 32-byte secret held in the platform keyring.  The stored JSON
//! is `{"v":2, <record fields>, "tag":"<64 lowercase hex>"}`.  The tag covers
//! the domain label `stellar-agent-toolset-pin:v2` followed by every record
//! field in declaration order: each string is prefixed by its byte length as
//! a big-endian `u32`, and each list by its element count as a big-endian
//! `u32` (capabilities as their display tokens in set order, `allowed_tools`
//! in stored order).
//!
//! [`read_pin`] returns a record only when its tag verifies under the key, it
//! names the package it is stored under, and it carries a `TOOLSET.md` digest.
//! A record without a tag, under another key, or with any field edited after
//! the install is [`ToolsetInstallError::PinRecordUnverifiable`].
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

use hmac::{Hmac, KeyInit as _, Mac as _};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use stellar_agent_toolsets::CapabilitySet;
use zeroize::Zeroizing;

use crate::{ToolsetInstallError, validate_package_name};

/// File name for the pin record inside the toolset package directory.
pub(crate) const PIN_FILE_NAME: &str = ".stellar-agent-toolset-pin.json";

/// The record format version the tag authenticates.
const PIN_RECORD_VERSION: u32 = 2;

/// Domain label that starts every tag preimage.
const PIN_TAG_DOMAIN: &[u8] = b"stellar-agent-toolset-pin:v2";

type HmacSha256 = Hmac<Sha256>;

/// The installation key that authenticates every toolset pin record.
///
/// One 32-byte secret per installation, held in the platform keyring.  The
/// toolsets directory is shared by every profile, so the key is too.  The
/// bytes are wiped on drop and never printed: `Debug` renders a fixed
/// placeholder.
///
/// # Examples
///
/// ```
/// use stellar_agent_toolsets_install::PinKey;
/// use zeroize::Zeroizing;
///
/// let key = PinKey::from_bytes(Zeroizing::new([7u8; 32]));
/// assert_eq!(format!("{key:?}"), "PinKey([REDACTED])");
/// ```
#[derive(Clone)]
pub struct PinKey(Zeroizing<[u8; 32]>);

impl PinKey {
    /// Wraps the 32 key bytes read from the keyring.
    #[must_use]
    pub fn from_bytes(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self(bytes)
    }
}

impl std::fmt::Debug for PinKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PinKey([REDACTED])")
    }
}

/// Pinned install record for a toolset.
///
/// Stored as `<toolsets_root>/<package>/.stellar-agent-toolset-pin.json`
/// under an HMAC tag (see the module documentation).  A record is only ever
/// obtained through [`read_pin`], which verifies the tag, so every field of a
/// returned record is the value the install wrote.
///
/// ## Capability fields
///
/// `capabilities` and `allowed_tools` are persisted at install time from the
/// signature-verified `TOOLSET.md` parse output.  Dispatch reads these fields
/// from the pin rather than re-parsing on-disk `TOOLSET.md` (TOCTOU avoidance).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct ToolsetPinRecord {
    /// Package name (`[a-z0-9-]`).
    ///
    /// This is the VALIDATED name, not a stored path. [`read_pin`] refuses a
    /// record whose name differs from the name it is stored under.
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
    ///
    /// The first-invoke gate honors only grants issued after this time, so
    /// the tag covers it like every other field.
    pub installed_at: String,

    /// Capabilities declared by the toolset manifest, persisted at install time.
    ///
    /// Sourced from the signature-verified `TOOLSET.md` parse.  The tag binds
    /// them to the installation key, so a capability added to the stored JSON
    /// makes the record unverifiable rather than granted.
    pub capabilities: CapabilitySet,

    /// Intersective `allowed_tools` from the toolset manifest, persisted at install time.
    ///
    /// When non-empty, narrows the capability grant: only tools present in
    /// BOTH the capability matrix AND this list are reachable.  An empty list
    /// means no narrowing (the full capability grant applies).
    pub allowed_tools: Vec<String>,

    /// SHA-256 hex digest (64 lowercase hex chars) of the `TOOLSET.md` bytes as
    /// extracted at install time.
    ///
    /// Mandatory: every record carries it, and both runtime resolvers re-read
    /// the on-disk `TOOLSET.md` at every dispatch, recompute SHA-256, and refuse
    /// the dispatch on a mismatch or an unreadable file.
    ///
    /// ## Security scope
    ///
    /// The digest covers post-install tamper detection of the toolset's
    /// human-readable manifest.  It does NOT re-verify the full package hash
    /// (`shasum` is SHA-256 of the original `.tar.gz` tarball, which is not
    /// retained post-extraction).  Capabilities are read from this record,
    /// never from the on-disk file, so an edited manifest grants nothing; the
    /// digest makes the edit visible and refuses dispatch.
    pub toolset_md_shasum: String,
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
    ///     "b".repeat(64),
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
        toolset_md_shasum: impl Into<String>,
    ) -> Self {
        Self {
            package: package.into(),
            version: version.into(),
            shasum: shasum.into(),
            publisher: publisher.into(),
            installed_at: installed_at.into(),
            capabilities,
            allowed_tools,
            toolset_md_shasum: toolset_md_shasum.into(),
        }
    }
}

/// The stored form of a pin record: the version, the record, and its tag.
#[derive(Serialize)]
struct StoredPinOut<'a> {
    v: u32,
    #[serde(flatten)]
    record: &'a ToolsetPinRecord,
    tag: String,
}

/// The parse target of a stored pin record.
///
/// Every field is optional or defaulted so that a record of an earlier format
/// parses and is then refused as unverifiable, while an unknown field is a
/// malformed record.
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct StoredPin {
    v: Option<u32>,
    package: String,
    version: String,
    shasum: String,
    publisher: String,
    installed_at: String,
    capabilities: CapabilitySet,
    allowed_tools: Vec<String>,
    toolset_md_shasum: Option<String>,
    tag: Option<String>,
}

/// Feeds `bytes` to `mac` behind its length as a big-endian `u32`.
///
/// Returns `None` when the length does not fit a `u32`; no record field the
/// install writes comes near that bound.
fn put_bytes(mac: &mut HmacSha256, bytes: &[u8]) -> Option<()> {
    let len = u32::try_from(bytes.len()).ok()?;
    mac.update(&len.to_be_bytes());
    mac.update(bytes);
    Some(())
}

/// Feeds a list's element count to `mac` as a big-endian `u32`.
fn put_count(mac: &mut HmacSha256, count: usize) -> Option<()> {
    let count = u32::try_from(count).ok()?;
    mac.update(&count.to_be_bytes());
    Some(())
}

/// The HMAC over the tag preimage of `record` under `key`, ready to finalize
/// or to verify a tag.
///
/// Returns `None` when a field length or a list count does not fit a `u32`.
fn tag_mac(record: &ToolsetPinRecord, key: &PinKey) -> Option<HmacSha256> {
    let mut mac = HmacSha256::new_from_slice(key.0.as_ref()).ok()?;
    mac.update(PIN_TAG_DOMAIN);
    put_bytes(&mut mac, record.package.as_bytes())?;
    put_bytes(&mut mac, record.version.as_bytes())?;
    put_bytes(&mut mac, record.shasum.as_bytes())?;
    put_bytes(&mut mac, record.publisher.as_bytes())?;
    put_bytes(&mut mac, record.installed_at.as_bytes())?;
    put_count(&mut mac, record.capabilities.len())?;
    for capability in record.capabilities.iter() {
        put_bytes(&mut mac, capability.to_string().as_bytes())?;
    }
    put_count(&mut mac, record.allowed_tools.len())?;
    for tool in &record.allowed_tools {
        put_bytes(&mut mac, tool.as_bytes())?;
    }
    put_bytes(&mut mac, record.toolset_md_shasum.as_bytes())?;
    Some(mac)
}

/// Whether `s` is exactly 64 lowercase hex characters.
fn is_lower_hex_64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Serialises `record` in its stored form, tagged under `key`.
///
/// # Errors
///
/// - [`ToolsetInstallError::Io`]: a field is too long to encode, or the JSON
///   serialisation fails.
fn encode_pin(record: &ToolsetPinRecord, key: &PinKey) -> Result<String, ToolsetInstallError> {
    let tag = tag_mac(record, key)
        .ok_or_else(|| {
            ToolsetInstallError::from_io(std::io::Error::other(
                "pin record field exceeds the encodable length",
            ))
        })?
        .finalize()
        .into_bytes();
    let stored = StoredPinOut {
        v: PIN_RECORD_VERSION,
        record,
        tag: hex::encode(tag),
    };
    serde_json::to_string_pretty(&stored)
        .map_err(|e| ToolsetInstallError::from_io(std::io::Error::other(e.to_string())))
}

/// Writes a pin record atomically (temp+rename, same filesystem), tagged
/// under `key`.
///
/// Steps:
/// 1. Serialise `record` with its version and tag to JSON.
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
    key: &PinKey,
) -> Result<(), ToolsetInstallError> {
    let json = encode_pin(record, key)?;

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

/// Writes `record` as an installed toolset's pin record, tagged under `key`,
/// creating `<toolsets_root>/<package>/` first.
///
/// Test fixtures use it to set up an installed toolset without the install
/// pipeline.  Only available under `#[cfg(any(test, feature = "test-helpers"))]`.
///
/// # Errors
///
/// - [`ToolsetInstallError::Io`]: the directory or the record cannot be written.
#[cfg(any(test, feature = "test-helpers"))]
pub fn write_pin_for_test(
    record: &ToolsetPinRecord,
    toolsets_root: &Path,
    key: &PinKey,
) -> Result<(), ToolsetInstallError> {
    std::fs::create_dir_all(toolsets_root.join(&record.package))
        .map_err(ToolsetInstallError::from_io)?;
    write_pin_atomic(record, toolsets_root, key)
}

/// Writes an installed toolset as an install leaves it: a `TOOLSET.md` for
/// `package` declaring `capabilities`, and a version `1.0.0` record of
/// `package` declaring the same capabilities and `allowed_tools`, carrying the
/// manifest's digest and tagged under `key`.  Returns the record.
///
/// `capabilities` are display tokens such as `"sign-payment"`; a token the
/// capability set does not know is dropped, as the record parse drops it.
/// Only available under `#[cfg(any(test, feature = "test-helpers"))]`.
///
/// # Errors
///
/// - [`ToolsetInstallError::Io`]: the directory, the manifest or the record
///   cannot be written.
#[cfg(any(test, feature = "test-helpers"))]
pub fn write_toolset_for_test(
    toolsets_root: &Path,
    package: &str,
    capabilities: &[&str],
    allowed_tools: &[&str],
    installed_at: &str,
    key: &PinKey,
) -> Result<ToolsetPinRecord, ToolsetInstallError> {
    let manifest = format!(
        "---\nname: {package}\ndescription: test toolset.\nmetadata:\n  \
         stellar-agent-capabilities: {}\n---\n\nBody.\n",
        capabilities.join(" ")
    );
    let toolset_dir = toolsets_root.join(package);
    std::fs::create_dir_all(&toolset_dir).map_err(ToolsetInstallError::from_io)?;
    std::fs::write(toolset_dir.join("TOOLSET.md"), &manifest)
        .map_err(ToolsetInstallError::from_io)?;
    let capability_set: CapabilitySet = serde_json::from_value(serde_json::json!(capabilities))
        .map_err(|e| ToolsetInstallError::Io {
            detail: format!("capability tokens: {e}"),
        })?;
    let record = ToolsetPinRecord::build_for_test(
        package,
        "1.0.0",
        "0".repeat(64),
        "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN",
        installed_at,
        capability_set,
        allowed_tools
            .iter()
            .map(|tool| (*tool).to_owned())
            .collect(),
        crate::hash::sha256_hex_of(manifest.as_bytes()),
    );
    write_pin_atomic(&record, toolsets_root, key)?;
    Ok(record)
}

/// Reads and verifies the pin record for `package` from `toolsets_root`.
///
/// Validates `package` against the `[a-z0-9-]` charset BEFORE constructing
/// any filesystem path: a `package` value containing `/`, `\`, `.`, `..`, or
/// any character outside `[a-z0-9-]` is rejected immediately with
/// [`ToolsetInstallError::InvalidPackageName`] and produces NO filesystem path
/// join.
///
/// Returns `None` if the pin file does not exist (toolset not installed).
/// Otherwise the record is returned only when its tag verifies under `key`,
/// it names `package`, and its `TOOLSET.md` digest is 64 lowercase hex
/// characters.  The tag is compared in constant time.
///
/// # Errors
///
/// - [`ToolsetInstallError::InvalidPackageName`]: `package` fails the
///   `[a-z0-9-]` charset validation.
/// - [`ToolsetInstallError::PinRecordMalformed`]: the pin file exists but is
///   not a pin record, names another package, or carries a digest that is not
///   64 lowercase hex characters.
/// - [`ToolsetInstallError::PinRecordUnverifiable`]: `key` is `None`, the
///   record is not version 2, its tag or digest is missing, or its tag does
///   not verify under `key`.
/// - [`ToolsetInstallError::Io`]: unexpected I/O error (not NotFound).
pub fn read_pin(
    package: &str,
    toolsets_root: &Path,
    key: Option<&PinKey>,
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

    let stored: StoredPin =
        serde_json::from_str(&content).map_err(|_| ToolsetInstallError::PinRecordMalformed {
            detail: format!("pin record for '{package}' is not a valid pin record"),
        })?;

    let unverifiable = || ToolsetInstallError::PinRecordUnverifiable {
        package: package.to_owned(),
    };
    let key = key.ok_or_else(unverifiable)?;
    if stored.v != Some(PIN_RECORD_VERSION) {
        return Err(unverifiable());
    }
    let (Some(tag_hex), Some(toolset_md_shasum)) = (stored.tag, stored.toolset_md_shasum) else {
        return Err(unverifiable());
    };
    if !is_lower_hex_64(&tag_hex) {
        return Err(unverifiable());
    }
    let tag = hex::decode(&tag_hex).map_err(|_| unverifiable())?;

    let record = ToolsetPinRecord {
        package: stored.package,
        version: stored.version,
        shasum: stored.shasum,
        publisher: stored.publisher,
        installed_at: stored.installed_at,
        capabilities: stored.capabilities,
        allowed_tools: stored.allowed_tools,
        toolset_md_shasum,
    };

    let mac = tag_mac(&record, key).ok_or_else(unverifiable)?;
    mac.verify_slice(&tag).map_err(|_| unverifiable())?;

    if record.package != package {
        return Err(ToolsetInstallError::PinRecordMalformed {
            detail: format!(
                "pin record names package '{}', stored under '{package}'",
                stellar_agent_toolsets::sanitise_display(&record.package, 64),
            ),
        });
    }

    if !is_lower_hex_64(&record.toolset_md_shasum) {
        return Err(ToolsetInstallError::PinRecordMalformed {
            detail: format!(
                "pin record for '{package}' carries a TOOLSET.md digest that is not \
                 64 lowercase hex characters"
            ),
        });
    }

    Ok(Some(record))
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

    fn key(byte: u8) -> PinKey {
        PinKey::from_bytes(Zeroizing::new([byte; 32]))
    }

    fn test_record() -> ToolsetPinRecord {
        ToolsetPinRecord {
            package: "my-toolset".to_owned(),
            version: "1.0.0".to_owned(),
            shasum: "a".repeat(64),
            publisher: "GABC...XYZ".to_owned(),
            installed_at: "2026-06-01T00:00:00Z".to_owned(),
            capabilities: stellar_agent_toolsets::CapabilitySet::empty(),
            allowed_tools: vec![],
            toolset_md_shasum: "c".repeat(64),
        }
    }

    fn tag_hex(record: &ToolsetPinRecord, key: &PinKey) -> String {
        hex::encode(tag_mac(record, key).unwrap().finalize().into_bytes())
    }

    /// Reads the stored JSON of `package`, applies `edit`, and writes it back.
    fn edit_stored(toolsets_root: &Path, package: &str, edit: impl FnOnce(&mut serde_json::Value)) {
        let path = toolsets_root.join(package).join(PIN_FILE_NAME);
        let mut value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        edit(&mut value);
        std::fs::write(&path, serde_json::to_string(&value).unwrap()).unwrap();
    }

    fn assert_unverifiable(result: Result<Option<ToolsetPinRecord>, ToolsetInstallError>) {
        let err = result.unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::PinRecordUnverifiable { .. }),
            "expected PinRecordUnverifiable, got: {err:?}"
        );
    }

    #[test]
    fn a_tagged_pin_round_trips() {
        let dir = TempDir::new().unwrap();
        let record = test_record();
        write_pin_for_test(&record, dir.path(), &key(1)).unwrap();

        let loaded = read_pin("my-toolset", dir.path(), Some(&key(1)))
            .unwrap()
            .unwrap();
        assert_eq!(loaded, record);

        let stored: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(record.pin_path(dir.path())).unwrap())
                .unwrap();
        assert_eq!(stored["v"], 2);
        assert_eq!(stored["tag"], tag_hex(&record, &key(1)));
    }

    #[test]
    fn missing_pin_returns_none() {
        let dir = TempDir::new().unwrap();
        let result = read_pin("nonexistent", dir.path(), Some(&key(1))).unwrap();
        assert!(result.is_none());
        let result = read_pin("nonexistent", dir.path(), None).unwrap();
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

        let err = read_pin("bad-toolset", toolsets_root, Some(&key(1))).unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::PinRecordMalformed { .. }),
            "expected PinRecordMalformed, got: {err:?}"
        );
    }

    /// The expected tag comes from an independent calculation of the documented preimage.
    /// The test covers eight record fields plus the allowed-tool order.
    #[test]
    fn the_tag_covers_every_field() {
        let base = ToolsetPinRecord {
            package: "vector-toolset".to_owned(),
            version: "1.2.3".to_owned(),
            shasum: "a".repeat(64),
            publisher: "GABC".to_owned(),
            installed_at: "2026-06-01T00:00:00Z".to_owned(),
            capabilities: stellar_agent_toolsets::parse_capability_value_pub(
                "sign-payment read-balance",
            )
            .unwrap(),
            allowed_tools: vec![
                "stellar_pay_commit".to_owned(),
                "stellar_balances".to_owned(),
            ],
            toolset_md_shasum: "b".repeat(64),
        };
        let vector_key = key(0x42);
        let expected = "8fa792e3db0e65cdff5cf0e95dbc437014fca6a597b9621b40fe4b72e9ce3fd4";
        assert_eq!(tag_hex(&base, &vector_key), expected);

        fn prefixed(preimage: &mut Vec<u8>, bytes: &[u8]) {
            preimage.extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_be_bytes());
            preimage.extend_from_slice(bytes);
        }
        let mut preimage = PIN_TAG_DOMAIN.to_vec();
        prefixed(&mut preimage, b"vector-toolset");
        prefixed(&mut preimage, b"1.2.3");
        prefixed(&mut preimage, "a".repeat(64).as_bytes());
        prefixed(&mut preimage, b"GABC");
        prefixed(&mut preimage, b"2026-06-01T00:00:00Z");
        preimage.extend_from_slice(&2u32.to_be_bytes());
        prefixed(&mut preimage, b"read-balance");
        prefixed(&mut preimage, b"sign-payment");
        preimage.extend_from_slice(&2u32.to_be_bytes());
        prefixed(&mut preimage, b"stellar_pay_commit");
        prefixed(&mut preimage, b"stellar_balances");
        prefixed(&mut preimage, "b".repeat(64).as_bytes());
        let mut mac = HmacSha256::new_from_slice(&[0x42; 32]).unwrap();
        mac.update(&preimage);
        assert_eq!(hex::encode(mac.finalize().into_bytes()), expected);

        let mut variants: Vec<(&str, ToolsetPinRecord)> = Vec::new();
        let mut v = base.clone();
        v.package = "vector-toolsets".to_owned();
        variants.push(("package", v));
        let mut v = base.clone();
        v.version = "1.2.4".to_owned();
        variants.push(("version", v));
        let mut v = base.clone();
        v.shasum = "d".repeat(64);
        variants.push(("shasum", v));
        let mut v = base.clone();
        v.publisher = "GABD".to_owned();
        variants.push(("publisher", v));
        let mut v = base.clone();
        v.installed_at = "2026-05-01T00:00:00Z".to_owned();
        variants.push(("installed_at", v));
        let mut v = base.clone();
        v.capabilities =
            stellar_agent_toolsets::parse_capability_value_pub("read-balance").unwrap();
        variants.push(("capabilities", v));
        let mut v = base.clone();
        v.allowed_tools = vec!["stellar_pay_commit".to_owned()];
        variants.push(("allowed_tools", v));
        let mut v = base.clone();
        v.allowed_tools.reverse();
        variants.push(("allowed_tools order", v));
        let mut v = base.clone();
        v.toolset_md_shasum = "e".repeat(64);
        variants.push(("toolset_md_shasum", v));
        assert_eq!(variants.len(), 9);
        for (field, variant) in &variants {
            assert_ne!(
                tag_hex(variant, &vector_key),
                expected,
                "a record differing only in {field} must carry a different tag"
            );
        }
        assert_ne!(
            tag_hex(&base, &key(0x43)),
            expected,
            "the tag depends on the key"
        );
    }

    #[test]
    fn an_edited_capability_fails_verification() {
        let dir = TempDir::new().unwrap();
        let mut record = test_record();
        record.capabilities =
            stellar_agent_toolsets::parse_capability_value_pub("read-balance").unwrap();
        write_pin_for_test(&record, dir.path(), &key(1)).unwrap();
        edit_stored(dir.path(), "my-toolset", |value| {
            value["capabilities"] = serde_json::json!(["read-balance", "sign-payment"]);
        });

        assert_unverifiable(read_pin("my-toolset", dir.path(), Some(&key(1))));
    }

    #[test]
    fn a_pin_without_a_tag_is_unverifiable() {
        let dir = TempDir::new().unwrap();
        let pkg_dir = dir.path().join("legacy-toolset");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        let without_digest = r#"{
            "package": "legacy-toolset",
            "version": "1.0.0",
            "shasum": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "publisher": "GABC...XYZ",
            "installed_at": "2026-06-01T00:00:00Z",
            "capabilities": ["sign-payment"],
            "allowed_tools": []
        }"#;
        let with_digest = r#"{
            "package": "legacy-toolset",
            "version": "1.0.0",
            "shasum": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "publisher": "GABC...XYZ",
            "installed_at": "2026-06-01T00:00:00Z",
            "capabilities": ["sign-payment"],
            "allowed_tools": [],
            "toolset_md_shasum": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        }"#;
        for json in [without_digest, with_digest] {
            std::fs::write(pkg_dir.join(PIN_FILE_NAME), json).unwrap();
            assert_unverifiable(read_pin("legacy-toolset", dir.path(), Some(&key(1))));
        }
    }

    #[test]
    fn a_pin_of_another_format_version_is_unverifiable() {
        let dir = TempDir::new().unwrap();
        write_pin_for_test(&test_record(), dir.path(), &key(1)).unwrap();
        edit_stored(dir.path(), "my-toolset", |value| {
            value["v"] = serde_json::json!(3);
        });
        assert_unverifiable(read_pin("my-toolset", dir.path(), Some(&key(1))));
    }

    #[test]
    fn a_pin_without_a_digest_is_unverifiable() {
        let dir = TempDir::new().unwrap();
        write_pin_for_test(&test_record(), dir.path(), &key(1)).unwrap();
        edit_stored(dir.path(), "my-toolset", |value| {
            value.as_object_mut().unwrap().remove("toolset_md_shasum");
        });
        assert_unverifiable(read_pin("my-toolset", dir.path(), Some(&key(1))));
    }

    #[test]
    fn a_pin_under_another_key_is_unverifiable() {
        let dir = TempDir::new().unwrap();
        write_pin_for_test(&test_record(), dir.path(), &key(1)).unwrap();
        assert_unverifiable(read_pin("my-toolset", dir.path(), Some(&key(2))));
        assert_unverifiable(read_pin("my-toolset", dir.path(), None));
    }

    #[test]
    fn a_pin_copied_under_another_name_is_refused() {
        let dir = TempDir::new().unwrap();
        let mut alpha = test_record();
        alpha.package = "alpha".to_owned();
        write_pin_for_test(&alpha, dir.path(), &key(1)).unwrap();
        std::fs::create_dir_all(dir.path().join("beta")).unwrap();
        std::fs::copy(
            alpha.pin_path(dir.path()),
            dir.path().join("beta").join(PIN_FILE_NAME),
        )
        .unwrap();

        let err = read_pin("beta", dir.path(), Some(&key(1))).unwrap_err();
        assert!(
            matches!(
                &err,
                ToolsetInstallError::PinRecordMalformed { detail }
                    if detail.contains("'alpha'") && detail.contains("'beta'")
            ),
            "the refusal must be PinRecordMalformed naming both packages, got: {err:?}"
        );
    }

    #[test]
    fn a_tagged_pin_naming_an_invalid_package_is_refused() {
        let dir = TempDir::new().unwrap();
        let pkg_dir = dir.path().join("good-name");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        let mut record = test_record();
        record.package = "BADNAME!@#".to_owned();
        std::fs::write(
            pkg_dir.join(PIN_FILE_NAME),
            encode_pin(&record, &key(1)).unwrap(),
        )
        .unwrap();

        let err = read_pin("good-name", dir.path(), Some(&key(1))).unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::PinRecordMalformed { .. }),
            "expected PinRecordMalformed for a stored name other than the requested one, got: {err:?}"
        );
    }

    #[test]
    fn a_pin_with_a_malformed_digest_is_refused() {
        let dir = TempDir::new().unwrap();
        let mut record = test_record();
        record.toolset_md_shasum = "C".repeat(64);
        write_pin_for_test(&record, dir.path(), &key(1)).unwrap();

        let err = read_pin("my-toolset", dir.path(), Some(&key(1))).unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::PinRecordMalformed { .. }),
            "expected PinRecordMalformed for an uppercase digest, got: {err:?}"
        );
    }

    #[test]
    fn an_unknown_field_is_refused() {
        let dir = TempDir::new().unwrap();
        write_pin_for_test(&test_record(), dir.path(), &key(1)).unwrap();
        edit_stored(dir.path(), "my-toolset", |value| {
            value["extra"] = serde_json::json!("x");
        });

        let err = read_pin("my-toolset", dir.path(), Some(&key(1))).unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::PinRecordMalformed { .. }),
            "expected PinRecordMalformed for an unknown field, got: {err:?}"
        );
    }

    // Verify that read_pin rejects attacker-controlled package names containing
    // path traversal sequences BEFORE constructing any filesystem path.
    #[test]
    fn read_pin_dotdot_slash_rejected() {
        let dir = TempDir::new().unwrap();
        let err = read_pin("../foo", dir.path(), Some(&key(1))).unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::InvalidPackageName { .. }),
            "expected InvalidPackageName for '../foo', got: {err:?}"
        );
    }

    #[test]
    fn read_pin_slash_in_name_rejected() {
        let dir = TempDir::new().unwrap();
        let err = read_pin("a/b", dir.path(), Some(&key(1))).unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::InvalidPackageName { .. }),
            "expected InvalidPackageName for 'a/b', got: {err:?}"
        );
    }

    #[test]
    fn read_pin_backslash_in_name_rejected() {
        let dir = TempDir::new().unwrap();
        let err = read_pin("..\\foo", dir.path(), Some(&key(1))).unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::InvalidPackageName { .. }),
            "expected InvalidPackageName for '..\\\\foo', got: {err:?}"
        );
    }

    #[test]
    fn pin_key_debug_prints_no_key_bytes() {
        let rendered = format!("{:?}", key(0xab));
        assert_eq!(rendered, "PinKey([REDACTED])");
        assert!(!rendered.contains("171"), "{rendered}");
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
            "dead".repeat(16),
        );

        assert_eq!(record.package, "test-toolset");
        assert_eq!(record.version, "1.2.3");
        assert_eq!(record.shasum, "a".repeat(64));
        assert_eq!(record.publisher, "GABC...XYZ");
        assert_eq!(record.installed_at, "2026-06-22T00:00:00Z");
        assert_eq!(record.capabilities, caps);
        assert_eq!(record.allowed_tools, vec!["stellar_pay"]);
        assert_eq!(record.toolset_md_shasum, "dead".repeat(16));
    }

    #[test]
    fn pin_with_capabilities_roundtrip() {
        let dir = TempDir::new().unwrap();
        let toolsets_root = dir.path();

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
            toolset_md_shasum: "c".repeat(64),
        };

        write_pin_for_test(&record, toolsets_root, &key(3)).unwrap();
        let loaded = read_pin("rich-toolset", toolsets_root, Some(&key(3)))
            .unwrap()
            .unwrap();

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
