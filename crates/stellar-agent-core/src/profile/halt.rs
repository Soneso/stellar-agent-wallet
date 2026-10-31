//! Per-profile emergency stop: the halt marker.
//!
//! A halted profile refuses every agent action that signs or submits, on the
//! CLI and on the MCP server, and every MCP tool that is not read-only, until
//! the operator lifts the halt. The CLI verbs that only record or reconcile
//! local state (`mpp receipt record`, `mpp settlement reconcile`,
//! `mpp state prune`, `tx status`) stay usable for the operator. The halt is
//! a marker file beside the profile file:
//!
//! ```text
//! <data_root>/profiles/<name>.halt
//! ```
//!
//! `<data_root>` is [`canonical_data_root`], so the marker sits in the same
//! directory as [`default_profile_dir`](crate::profile::schema::default_profile_dir)
//! places `<name>.toml`. The content is TOML:
//!
//! ```toml
//! halted_at = "2026-10-31T12:00:00Z"
//! reason = "suspected prompt injection"
//! ```
//!
//! `halted_at` is an RFC 3339 UTC timestamp with second precision, a date
//! that exists in the calendar, from 1970 to 2099. `reason` is optional, at most [`HALT_REASON_MAX_CHARS`] characters, and holds no
//! control character.
//!
//! # Fail-closed reads
//!
//! [`read_halt`] maps an absent file to `Ok(None)`. Every other outcome that
//! is not a valid marker, an I/O error, a directory at the path, an unreadable
//! file, or content that does not parse or validate, is `Err`. Every caller
//! treats `Err` as a refusal, so a marker that cannot be read stops the
//! profile the same way a valid marker does.
//!
//! # Writes
//!
//! [`write_halt`] writes a temporary file in the profile directory and renames
//! it over the marker path, the way [`crate::profile::loader::save_to_dir`]
//! writes a profile file, so a reader sees either the previous marker or the
//! new one. No handle on the marker stays open after a write, a read, or a
//! removal returns, which keeps the rename and the removal free of sharing
//! violations on Windows.
//!
//! # Trust boundary
//!
//! The marker carries no MAC. A process that can write the data root can
//! remove it, as it can remove or replace the profile file itself. The halt
//! stops the agent surfaces of this wallet; it does not defend against a
//! process that already writes the operator's data directory.

use std::io::{ErrorKind, Read as _};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{ValidationError, WalletError};
use crate::profile::name::validate_path_component_ascii_safe;
use crate::profile::schema::canonical_data_root;

/// Wire code of the refusal a halted profile returns.
pub const HALTED_CODE: &str = "profile.halted";

/// Wire code of the refusal a profile with an unreadable halt marker returns.
pub const HALT_UNREADABLE_CODE: &str = "profile.halt_unreadable";

/// Maximum number of characters in a halt reason.
///
/// Equal to the audit log's bound on recorded operator text, so the reason
/// in the marker and the reason in the audit row are the same string.
pub const HALT_REASON_MAX_CHARS: usize = crate::audit_log::schema::RECORDED_STR_MAX;

/// Upper bound on the size of a marker file a read accepts.
///
/// A valid marker is well under this size; a larger file is refused as
/// unreadable without reading it whole.
const HALT_MARKER_MAX_BYTES: u64 = 4096;

/// File extension of the halt marker.
const HALT_EXTENSION: &str = "halt";

/// The content of a halt marker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct HaltMarker {
    /// When the halt was set, RFC 3339 UTC with second precision.
    pub halted_at: String,
    /// The operator's reason, when one was given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl HaltMarker {
    /// Builds a marker stamped with the current time.
    ///
    /// # Errors
    ///
    /// [`HaltError::InvalidReason`] when `reason` is empty after trimming,
    /// longer than [`HALT_REASON_MAX_CHARS`] characters, or holds a control
    /// character.
    pub fn now(reason: Option<String>) -> Result<Self, HaltError> {
        Self::new(
            crate::timefmt::format_rfc3339_utc(std::time::SystemTime::now()),
            reason,
        )
    }

    /// Builds a marker from its parts, validating both.
    ///
    /// # Errors
    ///
    /// [`HaltError::InvalidTimestamp`] when `halted_at` is not an RFC 3339
    /// UTC timestamp of the form `YYYY-MM-DDTHH:MM:SSZ` naming a date that
    /// exists, and
    /// [`HaltError::InvalidReason`] as for [`Self::now`].
    pub fn new(halted_at: String, reason: Option<String>) -> Result<Self, HaltError> {
        let marker = Self { halted_at, reason };
        marker.validate()?;
        Ok(marker)
    }

    fn validate(&self) -> Result<(), HaltError> {
        if crate::audit_log::verify::parse_rfc3339_utc_seconds(&self.halted_at).is_err() {
            return Err(HaltError::InvalidTimestamp);
        }
        if let Some(reason) = &self.reason {
            validate_halt_reason(reason)?;
        }
        Ok(())
    }
}

/// Failure to locate, read, write, or remove a halt marker.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HaltError {
    /// The profile name is not safe as a path component.
    #[error("profile name `{name}` {reason}")]
    InvalidName {
        /// The refused name.
        name: String,
        /// Why the name was refused.
        reason: &'static str,
    },
    /// The data root could not be determined.
    #[error("the wallet data directory cannot be determined")]
    NoDataRoot,
    /// An I/O operation on the marker path failed.
    #[error("halt marker {}: {source}", path.display())]
    Io {
        /// The marker path.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
    /// The marker file is larger than any valid marker.
    #[error("halt marker {} exceeds {HALT_MARKER_MAX_BYTES} bytes", path.display())]
    TooLarge {
        /// The marker path.
        path: PathBuf,
    },
    /// The marker content is not a valid halt marker.
    #[error("halt marker {} does not parse: {detail}", path.display())]
    Malformed {
        /// The marker path.
        path: PathBuf,
        /// The parse or validation failure.
        detail: String,
    },
    /// `halted_at` is not an RFC 3339 UTC timestamp with second precision
    /// naming a date that exists.
    #[error(
        "halted_at must be an RFC 3339 UTC timestamp of the form YYYY-MM-DDTHH:MM:SSZ naming a date that exists"
    )]
    InvalidTimestamp,
    /// The reason is empty, too long, or holds a control character. The
    /// field holds the rule the reason breaks.
    #[error("reason {0}")]
    InvalidReason(String),
    /// The marker could not be serialized.
    #[error("halt marker serialization failed: {0}")]
    Serialize(#[from] toml::ser::Error),
}

/// Validates an operator-supplied halt reason.
///
/// # Errors
///
/// [`HaltError::InvalidReason`] when `reason` is empty after trimming, longer
/// than [`HALT_REASON_MAX_CHARS`] characters, or holds a control character.
pub fn validate_halt_reason(reason: &str) -> Result<(), HaltError> {
    if reason.trim().is_empty() {
        return Err(HaltError::InvalidReason(
            "must contain non-whitespace text".to_owned(),
        ));
    }
    if reason.chars().count() > HALT_REASON_MAX_CHARS {
        return Err(HaltError::InvalidReason(format!(
            "must be at most {HALT_REASON_MAX_CHARS} characters"
        )));
    }
    if reason.chars().any(char::is_control) {
        return Err(HaltError::InvalidReason(
            "must not contain control characters".to_owned(),
        ));
    }
    Ok(())
}

/// Returns the marker path for `name` under `data_root`:
/// `<data_root>/profiles/<name>.halt`.
///
/// # Errors
///
/// [`HaltError::InvalidName`] when `name` is not safe as a path component.
pub fn halt_path(data_root: &Path, name: &str) -> Result<PathBuf, HaltError> {
    validate_path_component_ascii_safe(name).map_err(|reason| HaltError::InvalidName {
        name: name.to_owned(),
        reason,
    })?;
    Ok(data_root
        .join("profiles")
        .join(format!("{name}.{HALT_EXTENSION}")))
}

/// Reads the halt marker of `name`.
///
/// # Errors
///
/// Every outcome other than a valid marker or an absent file is an error:
/// [`HaltError::InvalidName`], [`HaltError::Io`] (a directory at the path,
/// missing read permission, any other I/O failure), [`HaltError::TooLarge`],
/// and [`HaltError::Malformed`].
pub fn read_halt(data_root: &Path, name: &str) -> Result<Option<HaltMarker>, HaltError> {
    let path = halt_path(data_root, name)?;
    let io = |source| HaltError::Io {
        path: path.clone(),
        source,
    };
    let file = match std::fs::File::open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io(error)),
    };
    let mut bytes = Vec::new();
    // The handle closes when `limited` drops at the end of this block, before
    // parsing.
    {
        let mut limited = file.take(HALT_MARKER_MAX_BYTES + 1);
        limited.read_to_end(&mut bytes).map_err(io)?;
    }
    if bytes.len() as u64 > HALT_MARKER_MAX_BYTES {
        return Err(HaltError::TooLarge { path });
    }
    let text = String::from_utf8(bytes).map_err(|_| HaltError::Malformed {
        path: path.clone(),
        detail: "content is not UTF-8".to_owned(),
    })?;
    let marker: HaltMarker = toml::from_str(&text).map_err(|error| HaltError::Malformed {
        path: path.clone(),
        detail: error.message().to_owned(),
    })?;
    marker.validate().map_err(|error| HaltError::Malformed {
        path,
        detail: error.to_string(),
    })?;
    Ok(Some(marker))
}

/// Writes `marker` as the halt marker of `name`, replacing any marker there.
///
/// Creates the profile directory when it does not exist. Writes a temporary
/// file in that directory and renames it over the marker path.
///
/// # Errors
///
/// [`HaltError::InvalidName`], [`HaltError::Serialize`], and
/// [`HaltError::Io`] on any directory, write, or rename failure.
pub fn write_halt(data_root: &Path, name: &str, marker: &HaltMarker) -> Result<PathBuf, HaltError> {
    let path = halt_path(data_root, name)?;
    marker.validate()?;
    let io = |source| HaltError::Io {
        path: path.clone(),
        source,
    };
    let dir = path
        .parent()
        .ok_or_else(|| io(std::io::Error::other("marker path has no parent")))?;
    std::fs::create_dir_all(dir).map_err(io)?;
    let text = toml::to_string(marker)?;
    let mut tmp = tempfile::NamedTempFile::new_in(dir).map_err(io)?;
    std::io::Write::write_all(&mut tmp, text.as_bytes()).map_err(io)?;
    tmp.as_file().sync_all().map_err(io)?;
    tmp.persist(&path).map_err(|error| io(error.error))?;
    Ok(path)
}

/// Removes the halt marker of `name`.
///
/// Returns `true` when a marker was removed and `false` when none existed.
/// An absent marker is success.
///
/// # Errors
///
/// [`HaltError::InvalidName`], and [`HaltError::Io`] when the path exists and
/// cannot be removed, for example because it is a directory.
pub fn clear_halt(data_root: &Path, name: &str) -> Result<bool, HaltError> {
    let path = halt_path(data_root, name)?;
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(source) => Err(HaltError::Io { path, source }),
    }
}

/// The halt state of a profile as the agent surfaces see it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum HaltState {
    /// No marker exists.
    Running,
    /// A valid marker exists.
    Halted(HaltMarker),
    /// A marker path exists and cannot be read as a valid marker; every
    /// agent action refuses as for a halt.
    Unreadable(String),
}

impl HaltState {
    /// Whether agent actions refuse in this state.
    #[must_use]
    pub fn is_halted(&self) -> bool {
        !matches!(self, Self::Running)
    }

    /// The marker's `halted_at`, when a valid marker exists.
    #[must_use]
    pub fn halted_at(&self) -> Option<&str> {
        match self {
            Self::Halted(marker) => Some(marker.halted_at.as_str()),
            Self::Running | Self::Unreadable(_) => None,
        }
    }

    /// The marker's reason, when a valid marker carries one.
    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Halted(marker) => marker.reason.as_deref(),
            Self::Running | Self::Unreadable(_) => None,
        }
    }
}

/// Reads the halt state of `name` under `data_root`, folding every read
/// failure into [`HaltState::Unreadable`].
#[must_use]
pub fn halt_state_in(data_root: &Path, name: &str) -> HaltState {
    match read_halt(data_root, name) {
        Ok(None) => HaltState::Running,
        Ok(Some(marker)) => HaltState::Halted(marker),
        Err(error) => HaltState::Unreadable(error.to_string()),
    }
}

/// Reads the halt state of `name` under [`canonical_data_root`].
///
/// A data root that cannot be determined reads as
/// [`HaltState::Unreadable`].
#[must_use]
pub fn halt_state(name: &str) -> HaltState {
    match canonical_data_root() {
        Ok(root) => halt_state_in(&root, name),
        Err(_) => HaltState::Unreadable(HaltError::NoDataRoot.to_string()),
    }
}

/// Refuses when `name` is halted or its marker cannot be read.
///
/// The one check every agent surface runs before it touches a signer, a
/// policy engine, a per-profile store, or the network.
///
/// # Errors
///
/// [`ValidationError::ProfileHalted`] (`profile.halted`) for a valid marker
/// and [`ValidationError::ProfileHaltUnreadable`]
/// (`profile.halt_unreadable`) for a marker that cannot be read.
pub fn ensure_not_halted_in(data_root: &Path, name: &str) -> Result<(), WalletError> {
    refusal_for_state(name, halt_state_in(data_root, name))
}

/// [`ensure_not_halted_in`] under [`canonical_data_root`].
///
/// # Errors
///
/// As for [`ensure_not_halted_in`]; a data root that cannot be determined
/// refuses with [`ValidationError::ProfileHaltUnreadable`].
pub fn ensure_not_halted(name: &str) -> Result<(), WalletError> {
    refusal_for_state(name, halt_state(name))
}

fn refusal_for_state(name: &str, state: HaltState) -> Result<(), WalletError> {
    match state {
        HaltState::Running => Ok(()),
        HaltState::Halted(marker) => Err(WalletError::Validation(ValidationError::ProfileHalted {
            profile: name.to_owned(),
            halted_at: marker.halted_at,
            reason: marker.reason,
        })),
        HaltState::Unreadable(detail) => Err(WalletError::Validation(
            ValidationError::ProfileHaltUnreadable {
                profile: name.to_owned(),
                detail,
            },
        )),
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;

    fn marker(reason: Option<&str>) -> HaltMarker {
        HaltMarker::new("2026-10-31T12:00:00Z".to_owned(), reason.map(str::to_owned)).unwrap()
    }

    #[test]
    fn round_trip_write_read_clear() {
        let root = tempfile::tempdir().unwrap();
        let written = marker(Some("suspected prompt injection"));
        let path = write_halt(root.path(), "alice", &written).unwrap();
        assert_eq!(path, root.path().join("profiles").join("alice.halt"));

        assert_eq!(read_halt(root.path(), "alice").unwrap(), Some(written));

        assert!(clear_halt(root.path(), "alice").unwrap());
        assert_eq!(read_halt(root.path(), "alice").unwrap(), None);
        assert!(!path.exists());
    }

    #[test]
    fn rewrite_replaces_the_marker() {
        let root = tempfile::tempdir().unwrap();
        write_halt(root.path(), "alice", &marker(Some("first"))).unwrap();
        let second =
            HaltMarker::new("2026-10-31T13:00:00Z".to_owned(), Some("second".to_owned())).unwrap();
        write_halt(root.path(), "alice", &second).unwrap();
        assert_eq!(read_halt(root.path(), "alice").unwrap(), Some(second));
    }

    #[test]
    fn marker_without_reason_round_trips() {
        let root = tempfile::tempdir().unwrap();
        let written = marker(None);
        write_halt(root.path(), "alice", &written).unwrap();
        let text = std::fs::read_to_string(halt_path(root.path(), "alice").unwrap()).unwrap();
        assert!(!text.contains("reason"), "{text}");
        assert_eq!(read_halt(root.path(), "alice").unwrap(), Some(written));
    }

    #[test]
    fn missing_marker_reads_none_and_the_profile_runs() {
        let root = tempfile::tempdir().unwrap();
        assert_eq!(read_halt(root.path(), "alice").unwrap(), None);
        assert_eq!(halt_state_in(root.path(), "alice"), HaltState::Running);
        ensure_not_halted_in(root.path(), "alice").unwrap();
    }

    #[test]
    fn valid_marker_refuses_with_profile_halted() {
        let root = tempfile::tempdir().unwrap();
        write_halt(root.path(), "alice", &marker(Some("incident"))).unwrap();
        let error = ensure_not_halted_in(root.path(), "alice").unwrap_err();
        assert_eq!(error.code(), HALTED_CODE);
        assert_eq!(
            error.to_string(),
            "profile \"alice\" is halted since 2026-10-31T12:00:00Z: incident; run \
             \"stellar-agent profile resume --profile alice\" to lift it"
        );
    }

    #[test]
    fn valid_marker_without_reason_has_no_reason_suffix() {
        let root = tempfile::tempdir().unwrap();
        write_halt(root.path(), "alice", &marker(None)).unwrap();
        let error = ensure_not_halted_in(root.path(), "alice").unwrap_err();
        assert_eq!(
            error.to_string(),
            "profile \"alice\" is halted since 2026-10-31T12:00:00Z; run \
             \"stellar-agent profile resume --profile alice\" to lift it"
        );
    }

    #[test]
    fn a_directory_at_the_marker_path_reads_err_and_refuses() {
        let root = tempfile::tempdir().unwrap();
        let path = halt_path(root.path(), "alice").unwrap();
        std::fs::create_dir_all(&path).unwrap();
        let error = read_halt(root.path(), "alice").unwrap_err();
        assert!(matches!(error, HaltError::Io { .. }), "{error:?}");
        let refusal = ensure_not_halted_in(root.path(), "alice").unwrap_err();
        assert_eq!(refusal.code(), HALT_UNREADABLE_CODE);
        assert!(clear_halt(root.path(), "alice").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_marker_without_read_permission_reads_err() {
        use std::os::unix::fs::PermissionsExt as _;
        let root = tempfile::tempdir().unwrap();
        let path = write_halt(root.path(), "alice", &marker(None)).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        // A process with CAP_DAC_OVERRIDE opens the file despite its mode. The
        // marker is then readable, and the read returns it.
        let opens_anyway = std::fs::File::open(&path).is_ok();
        let read = read_halt(root.path(), "alice");
        let refusal = ensure_not_halted_in(root.path(), "alice").unwrap_err();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        if opens_anyway {
            assert_eq!(read.unwrap(), Some(marker(None)));
            assert_eq!(refusal.code(), HALTED_CODE);
        } else {
            let error = read.unwrap_err();
            assert!(matches!(error, HaltError::Io { .. }), "{error:?}");
            assert_eq!(refusal.code(), HALT_UNREADABLE_CODE);
        }
    }

    #[test]
    fn malformed_markers_read_err() {
        let root = tempfile::tempdir().unwrap();
        let path = halt_path(root.path(), "alice").unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        for content in [
            "",
            "not toml at all [",
            "reason = \"no timestamp\"\n",
            "halted_at = \"yesterday\"\n",
            "halted_at = \"2026-13-01T00:00:00Z\"\n",
            "halted_at = \"2026-02-29T12:00:00Z\"\n",
            "halted_at = \"2026-04-31T12:00:00Z\"\n",
            "halted_at = \"2026-10-31T12:00:00+01:00\"\n",
            "halted_at = \"2026-10-31T12:00:00Z\"\nreason = \"\"\n",
            "halted_at = \"2026-10-31T12:00:00Z\"\nreason = \"a\\u001bb\"\n",
            "halted_at = \"2026-10-31T12:00:00Z\"\nextra = 1\n",
        ] {
            std::fs::write(&path, content).unwrap();
            let error = read_halt(root.path(), "alice").unwrap_err();
            assert!(
                matches!(error, HaltError::Malformed { .. }),
                "{content:?}: {error:?}"
            );
            assert_eq!(
                ensure_not_halted_in(root.path(), "alice")
                    .unwrap_err()
                    .code(),
                HALT_UNREADABLE_CODE,
                "{content:?}"
            );
        }
    }

    #[test]
    fn non_utf8_and_oversized_markers_read_err() {
        let root = tempfile::tempdir().unwrap();
        let path = halt_path(root.path(), "alice").unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, [0xff_u8, 0xfe, 0x00]).unwrap();
        assert!(matches!(
            read_halt(root.path(), "alice").unwrap_err(),
            HaltError::Malformed { .. }
        ));
        let oversized = vec![b'#'; usize::try_from(HALT_MARKER_MAX_BYTES).unwrap() + 1];
        std::fs::write(&path, oversized).unwrap();
        assert!(matches!(
            read_halt(root.path(), "alice").unwrap_err(),
            HaltError::TooLarge { .. }
        ));
    }

    #[test]
    fn clearing_an_absent_marker_succeeds() {
        let root = tempfile::tempdir().unwrap();
        assert!(!clear_halt(root.path(), "alice").unwrap());
    }

    #[test]
    fn unsafe_names_are_refused_before_any_path_is_built() {
        let root = tempfile::tempdir().unwrap();
        for name in ["", "..", "a/b", "-flag", "a\\b"] {
            assert!(
                matches!(
                    halt_path(root.path(), name),
                    Err(HaltError::InvalidName { .. })
                ),
                "{name:?}"
            );
        }
        assert_eq!(
            ensure_not_halted_in(root.path(), "../x")
                .unwrap_err()
                .code(),
            HALT_UNREADABLE_CODE
        );
    }

    #[test]
    fn reason_validation_bounds() {
        validate_halt_reason("incident 42").unwrap();
        validate_halt_reason(&"x".repeat(HALT_REASON_MAX_CHARS)).unwrap();
        assert!(validate_halt_reason("   ").is_err());
        assert!(validate_halt_reason(&"x".repeat(HALT_REASON_MAX_CHARS + 1)).is_err());
        assert!(validate_halt_reason("line\nbreak").is_err());
        assert!(HaltMarker::now(Some("\u{7}".to_owned())).is_err());
    }

    #[test]
    fn now_stamps_a_valid_timestamp() {
        let marker = HaltMarker::now(None).unwrap();
        crate::audit_log::verify::parse_rfc3339_utc_seconds(&marker.halted_at)
            .unwrap_or_else(|error| panic!("{}: {error}", marker.halted_at));
    }

    #[test]
    fn impossible_calendar_dates_are_refused_and_existing_ones_accepted() {
        for halted_at in ["2026-02-29T12:00:00Z", "2026-04-31T12:00:00Z"] {
            assert!(
                matches!(
                    HaltMarker::new(halted_at.to_owned(), None),
                    Err(HaltError::InvalidTimestamp)
                ),
                "{halted_at}"
            );
        }
        for halted_at in ["2024-02-29T12:00:00Z", "2026-04-30T23:59:59Z"] {
            HaltMarker::new(halted_at.to_owned(), None)
                .unwrap_or_else(|error| panic!("{halted_at}: {error}"));
        }
    }

    #[test]
    fn the_length_refusal_names_the_bound() {
        let error = validate_halt_reason(&"x".repeat(HALT_REASON_MAX_CHARS + 1)).unwrap_err();
        assert_eq!(
            error.to_string(),
            format!("reason must be at most {HALT_REASON_MAX_CHARS} characters")
        );
    }

    #[test]
    fn halt_state_accessors() {
        let halted = HaltState::Halted(marker(Some("r")));
        assert!(halted.is_halted());
        assert_eq!(halted.halted_at(), Some("2026-10-31T12:00:00Z"));
        assert_eq!(halted.reason(), Some("r"));
        let unreadable = HaltState::Unreadable("boom".to_owned());
        assert!(unreadable.is_halted());
        assert_eq!(unreadable.halted_at(), None);
        assert!(!HaltState::Running.is_halted());
    }
}
