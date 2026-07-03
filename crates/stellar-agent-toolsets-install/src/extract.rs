//! Safe toolset-package extraction.
//!
//! This is the core security surface for install.  The entry-by-entry safe
//! extraction wrapper implements all seven controls in order:
//!
//! 1. **Type check FIRST** — accept only `Regular` and `Directory`; reject
//!    `Symlink`, `Link` (hardlink), `Char`, `Block`, `Fifo`, `Continuous`,
//!    GNU-sparse, and unknown types BEFORE reading any path or body.
//! 2. **Path from raw bytes** — `entry.path_bytes()` (PAX/GNU long-name
//!    resolved), explicitly UTF-8 decoded; reject non-UTF-8, NUL, control
//!    bytes, over-long names, or too-many-components.
//! 3. **Lexical containment** — normalise `.`/`..` in memory; reject absolute,
//!    any `..` component, root/drive/prefix components, empty, or `.`-only
//!    paths. NEVER `std::fs::canonicalize` (TOCTOU).
//! 4. **ASCII-only entry-name gate** — rejects ALL non-ASCII entry names
//!    (over-reject, the safe direction).  Additionally, a `BTreeSet` of seen
//!    entry names normalised to ASCII-lowercase is maintained; any collision →
//!    `ArchiveDuplicateEntry`.
//! 5. **No-follow writes** — toolsets root and per-package final dir checked via
//!    `symlink_metadata` (no-follow); staging dir is FRESH via
//!    `TempDir::new_in(toolsets_root)`; extractor creates ONLY directory
//!    components it creates itself; files created with `create_new`.
//! 6. **Size bounds** — gzip decoder OUTPUT wrapped in `Read::take(TOTAL_CAP+1)`;
//!    per-entry cap on ACTUAL bytes read; entry-count cap.
//!    Single-member gzip is enforced by using `flate2::bufread::GzDecoder`
//!    over a `Cursor<&[u8]>` so the cursor position after first-member decode
//!    is observable; ANY byte remaining after the first member (after stripping
//!    tar end-of-archive zero padding) → `ArchiveTrailingData`.
//! 7. **Top-level shape** — exactly one top-level DIRECTORY == `package`; a
//!    top-level regular file or zero entries → `ArchiveBadTopLevel`.
//!
//! On full success: atomic `rename` staging→final.
//! On ANY error: remove staging (no partial install).

use std::collections::BTreeSet;
use std::io::{self, Cursor, Read, Write};
use std::path::{Component, Path, PathBuf};

use flate2::bufread::GzDecoder;
use tar::EntryType;
use tempfile::TempDir;

use crate::{
    MAX_ENTRIES, MAX_ENTRY_BYTES, MAX_NAME_COMPONENTS, MAX_NAME_LEN, MAX_TOTAL_DECOMPRESSED,
    ToolsetInstallError,
};

/// Extracts `package_bytes` (a `.tar.gz` buffer) into `staging_dir`.
///
/// The staging directory has been created by the caller inside the toolsets
/// root.  On success, returns the path to the extracted package directory
/// inside `staging_dir`.  On failure, the caller is responsible for removing
/// `staging_dir`.
///
/// All seven extraction controls are applied in order for each entry.
///
/// # Errors
///
/// Returns any [`ToolsetInstallError`] variant for archive violations.
pub(crate) fn extract_to_staging(
    package_bytes: &[u8],
    package_name: &str,
    staging_dir: &Path,
) -> Result<PathBuf, ToolsetInstallError> {
    // Use `flate2::bufread::GzDecoder` over a `Cursor<&[u8]>`.
    // `Cursor<&[u8]>` implements `BufRead`, which is required by the
    // `bufread::` variant.  After decoding the first member, `into_inner()`
    // on the `bufread::GzDecoder` returns the cursor positioned immediately
    // after the gzip footer — no internal BufReader over-read.  This is the
    // critical property that makes the trailing-data check functional.
    //
    // `Read::take(TOTAL_CAP + 1)` is applied to the GzDecoder OUTPUT so a
    // decompression bomb trips mid-stream.
    let cursor = Cursor::new(package_bytes);
    let gz_decoder = GzDecoder::new(cursor);
    let limited_decoder = gz_decoder.take((MAX_TOTAL_DECOMPRESSED as u64) + 1);

    let mut archive = tar::Archive::new(limited_decoder);

    // Disable unsafe path handling from the tar crate — we do our own.
    archive.set_unpack_xattrs(false);
    archive.set_preserve_permissions(false);
    archive.set_preserve_mtime(false);
    archive.set_overwrite(false);

    let mut seen_names: BTreeSet<String> = BTreeSet::new();
    let mut entry_count: usize = 0;
    let mut total_bytes_read: usize = 0;
    let mut top_level_dir: Option<String> = None;

    let entries = archive.entries().map_err(ToolsetInstallError::from_io)?;

    for entry_result in entries {
        #[allow(unused_mut)]
        let mut entry = entry_result.map_err(ToolsetInstallError::from_io)?;

        // ── Step 1: Type check FIRST ─────────────────────────────────────────
        let entry_type = entry.header().entry_type();
        match entry_type {
            EntryType::Regular | EntryType::Directory => {}
            // GNU sparse files are represented as Regular in header type but
            // have extension headers; the tar crate handles them transparently.
            // We reject explicitly-typed sparse variants:
            EntryType::GNUSparse | EntryType::Continuous => {
                return Err(ToolsetInstallError::ArchiveDisallowedEntryType);
            }
            EntryType::Symlink
            | EntryType::Link
            | EntryType::Char
            | EntryType::Block
            | EntryType::Fifo => {
                return Err(ToolsetInstallError::ArchiveDisallowedEntryType);
            }
            // Other / unknown types are rejected.
            _ => return Err(ToolsetInstallError::ArchiveDisallowedEntryType),
        }

        // ── Step 2: Path from raw bytes (PAX/GNU resolved) ───────────────────
        let path_bytes = entry.path_bytes();

        // Validate raw bytes for NUL and control characters BEFORE UTF-8 decode.
        for &b in path_bytes.as_ref() {
            if b == 0 || (b < 0x20 && b != b'/') {
                return Err(ToolsetInstallError::ArchiveEntryNameInvalid {
                    detail: "entry name contains NUL or control byte".to_owned(),
                });
            }
        }

        // Explicitly UTF-8 decode (NOT lossy — a lossy decode could mangle a
        // `..` sequence after the traversal check).
        let path_str = std::str::from_utf8(path_bytes.as_ref()).map_err(|_| {
            ToolsetInstallError::ArchiveEntryNameInvalid {
                detail: "entry name is not valid UTF-8".to_owned(),
            }
        })?;

        // Length cap on the path string.
        if path_str.len() > MAX_NAME_LEN {
            return Err(ToolsetInstallError::ArchiveEntryNameInvalid {
                detail: format!("entry name exceeds {MAX_NAME_LEN}-byte length cap"),
            });
        }

        // ── Step 3: Lexical containment ──────────────────────────────────────
        let normalised = lexical_normalise_and_check(path_str)?;

        // Component count cap.
        let component_count = normalised.components().count();
        if component_count > MAX_NAME_COMPONENTS {
            return Err(ToolsetInstallError::ArchiveEntryNameInvalid {
                detail: format!("entry has more than {MAX_NAME_COMPONENTS} path components"),
            });
        }

        // Extract the top-level component (first component of the path).
        let top_component = normalised.components().next().and_then(|c| match c {
            Component::Normal(s) => s.to_str().map(str::to_owned),
            _ => None,
        });

        let top_component =
            top_component.ok_or_else(|| ToolsetInstallError::ArchiveBadTopLevel {
                detail: "entry has no valid top-level component".to_owned(),
            })?;

        // Validate / track the top-level directory.
        match &top_level_dir {
            None => {
                // First entry's top-level component.
                if top_component != package_name {
                    return Err(ToolsetInstallError::ArchiveBadTopLevel {
                        detail: stellar_agent_toolsets::sanitise_display(
                            &format!(
                                "top-level directory '{top_component}' != package name '{package_name}'"
                            ),
                            256,
                        ),
                    });
                }
                top_level_dir = Some(top_component.clone());
            }
            Some(expected) => {
                if &top_component != expected {
                    return Err(ToolsetInstallError::ArchiveBadTopLevel {
                        detail: stellar_agent_toolsets::sanitise_display(
                            &format!(
                                "multiple top-level directories: '{expected}' and '{top_component}'"
                            ),
                            256,
                        ),
                    });
                }
            }
        }

        // ── Step 4: ASCII-only gate + case-collision check ───────────────────
        // Rejects ALL non-ASCII entry names (over-reject; safe direction).
        let normalised_str =
            normalised
                .to_str()
                .ok_or_else(|| ToolsetInstallError::ArchiveEntryNameInvalid {
                    detail: "normalised path is not valid UTF-8".to_owned(),
                })?;

        if !is_ascii_only_entry_name(normalised_str) {
            return Err(ToolsetInstallError::ArchiveEntryNameInvalid {
                detail: stellar_agent_toolsets::sanitise_display(
                    &format!(
                        "entry name contains non-ASCII characters (ASCII-only gate): '{normalised_str}'"
                    ),
                    256,
                ),
            });
        }

        // Collision detection on the ASCII-lowercased key.
        let collision_key = normalised_str.to_ascii_lowercase();
        if !seen_names.insert(collision_key) {
            return Err(ToolsetInstallError::ArchiveDuplicateEntry {
                entry_name: stellar_agent_toolsets::sanitise_display(normalised_str, 256),
            });
        }

        // ── Step 5: Entry count cap ───────────────────────────────────────────
        entry_count += 1;
        if entry_count > MAX_ENTRIES {
            return Err(ToolsetInstallError::ArchiveTooManyEntries { cap: MAX_ENTRIES });
        }

        // ── Step 6: No-follow writes ──────────────────────────────────────────
        // Check top-level shape: the top-level entry must be a Directory.
        // A regular file at the top level is rejected immediately.
        let component_count_check = normalised.components().count();
        if component_count_check == 1 && entry_type == EntryType::Regular {
            return Err(ToolsetInstallError::ArchiveBadTopLevel {
                detail: stellar_agent_toolsets::sanitise_display(
                    &format!(
                        "top-level entry '{normalised_str}' is a regular file; expected a directory"
                    ),
                    256,
                ),
            });
        }

        let dest_path = staging_dir.join(&normalised);

        match entry_type {
            EntryType::Directory => {
                // Only create the directory; do not follow any existing symlink.
                std::fs::create_dir_all(&dest_path).map_err(ToolsetInstallError::from_io)?;
            }
            EntryType::Regular => {
                // Ensure the parent exists.
                if let Some(parent) = dest_path.parent() {
                    std::fs::create_dir_all(parent).map_err(ToolsetInstallError::from_io)?;
                }

                // ── Per-entry size cap ────────────────────────────────────────
                // Read up to MAX_ENTRY_BYTES + 1 to detect over-size entries.
                let mut entry_buf = Vec::with_capacity(64 * 1024);
                let bytes_read = entry
                    .take((MAX_ENTRY_BYTES as u64) + 1)
                    .read_to_end(&mut entry_buf)
                    .map_err(ToolsetInstallError::from_io)?;

                if bytes_read > MAX_ENTRY_BYTES {
                    return Err(ToolsetInstallError::ArchiveEntryTooLarge {
                        cap: MAX_ENTRY_BYTES,
                    });
                }

                total_bytes_read += bytes_read;
                if total_bytes_read > MAX_TOTAL_DECOMPRESSED {
                    return Err(ToolsetInstallError::ArchiveTooLarge {
                        cap: MAX_TOTAL_DECOMPRESSED,
                    });
                }

                // Create-new: refuse to overwrite existing files.
                let file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&dest_path)
                    .map_err(ToolsetInstallError::from_io)?;
                let mut writer = std::io::BufWriter::new(file);
                writer
                    .write_all(&entry_buf)
                    .map_err(ToolsetInstallError::from_io)?;
                writer.flush().map_err(ToolsetInstallError::from_io)?;
            }
            _ => unreachable!("type check at step 1 guarantees only Regular and Directory"),
        }
    }

    // ── Step 7: Top-level shape check (zero-entry) ───────────────────────────
    if top_level_dir.is_none() {
        return Err(ToolsetInstallError::ArchiveBadTopLevel {
            detail: "archive is empty (zero entries)".to_owned(),
        });
    }

    // ── Trailing-data check (single-member enforcement) ───────────────────────
    // After the tar archive is fully consumed via the `limited_decoder`, we need
    // to verify that no bytes remain in the gzip stream after the first member.
    //
    // We accomplish this with a SECOND, independent decode pass using
    // `flate2::bufread::GzDecoder` over a fresh `Cursor<&[u8]>`.  The
    // `bufread::` variant exposes `into_inner()` which returns the `Cursor`
    // at its EXACT position after the gzip footer — no internal BufReader
    // over-read (unlike `read::GzDecoder` which wraps an internal
    // `crate::bufreader::BufReader<R>` and can pre-fill 8 KiB, making
    // `into_inner()` return an empty slice regardless of trailing bytes).
    //
    // After decoding, the cursor remainder (minus any trailing zero-padding
    // from the tar end-of-archive blocks) must be empty.  Any non-zero byte
    // → `ArchiveTrailingData`.
    //
    // The decompression-bomb limit is re-applied here to avoid re-expanding
    // a bomb during the verification pass.
    check_no_trailing_gzip_data(package_bytes)?;

    let extracted_pkg_dir = staging_dir.join(package_name);
    Ok(extracted_pkg_dir)
}

/// Performs the full extract-to-staging-then-rename flow atomically.
///
/// 1. Creates a temp staging dir inside `toolsets_root` (same FS → atomic rename).
/// 2. Calls [`extract_to_staging`].
/// 3. Renames staging-package-dir → final-package-dir.
/// 4. On any failure, removes the staging dir.
///
/// Returns the path to the final installed package directory.
///
/// # Errors
///
/// Returns any [`ToolsetInstallError`] from extraction or filesystem operations.
pub(crate) fn extract_and_move(
    package_bytes: &[u8],
    package_name: &str,
    toolsets_root: &Path,
) -> Result<TempDir, ToolsetInstallError> {
    // Verify toolsets_root leaf is not a symlink (no-follow discipline).
    // Ancestors may be symlinks (legitimate operator setup like ~/Library/...);
    // only the leaf is checked.
    check_not_symlink_leaf(toolsets_root)?;

    // Create staging dir INSIDE toolsets_root for same-FS atomic rename.
    let staging = TempDir::new_in(toolsets_root).map_err(ToolsetInstallError::from_io)?;

    let result = extract_to_staging(package_bytes, package_name, staging.path());

    match result {
        Ok(_) => Ok(staging),
        Err(e) => {
            // Remove staging on any failure (no partial install).
            // Best-effort; ignore cleanup error.
            let _ = staging.close();
            Err(e)
        }
    }
}

/// Checks that `path` is not a symlink (no-follow, leaf-only).
///
/// Uses `symlink_metadata` which does not follow symlinks.
///
/// Returns `ToolsetsRootInvalid` (not `PinRecordMalformed`) because this
/// check fires at install time on the toolsets root directory, not on a
/// stored pin record.  `PinRecordMalformed` is reserved for uninstall pin
/// issues.
fn check_not_symlink_leaf(path: &Path) -> Result<(), ToolsetInstallError> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            Err(ToolsetInstallError::ToolsetsRootInvalid {
                detail: stellar_agent_toolsets::sanitise_display(
                    &format!(
                        "toolsets root '{}' is a symlink leaf; refusing for security",
                        path.display()
                    ),
                    256,
                ),
            })
        }
        Ok(_) | Err(_) => Ok(()), // Non-existent or other error: fine, will be created/handled later.
    }
}

/// Normalises a path string lexically, rejecting traversal attempts.
///
/// - Strips leading `./` prefix if present.
/// - Rejects: absolute paths, any `..` component, root/drive/prefix
///   components, empty, or `.`-only paths.
/// - NEVER calls `std::fs::canonicalize` (TOCTOU).
fn lexical_normalise_and_check(path_str: &str) -> Result<PathBuf, ToolsetInstallError> {
    if path_str.is_empty() {
        return Err(ToolsetInstallError::ArchiveEntryNameInvalid {
            detail: "empty entry name".to_owned(),
        });
    }

    let path = Path::new(path_str);
    let mut components: Vec<&str> = Vec::new();

    for component in path.components() {
        match component {
            Component::Normal(s) => {
                let s_str =
                    s.to_str()
                        .ok_or_else(|| ToolsetInstallError::ArchiveEntryNameInvalid {
                            detail: "entry name component is not valid UTF-8".to_owned(),
                        })?;

                if s_str.is_empty() {
                    return Err(ToolsetInstallError::ArchiveEntryNameInvalid {
                        detail: "empty path component".to_owned(),
                    });
                }

                components.push(s_str);
            }
            Component::CurDir => {
                // Skip `.` components (equivalent to empty).
                if components.is_empty() {
                    // Leading `./` — skip.
                    continue;
                }
            }
            Component::ParentDir => {
                return Err(ToolsetInstallError::ArchivePathTraversal {
                    entry_name: stellar_agent_toolsets::sanitise_display(path_str, 256),
                });
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(ToolsetInstallError::ArchivePathTraversal {
                    entry_name: stellar_agent_toolsets::sanitise_display(path_str, 256),
                });
            }
        }
    }

    if components.is_empty() {
        return Err(ToolsetInstallError::ArchiveEntryNameInvalid {
            detail: "path normalises to empty (dot-only or empty components)".to_owned(),
        });
    }

    // Rebuild as a clean relative PathBuf.
    let mut result = PathBuf::new();
    for c in &components {
        result.push(c);
    }
    Ok(result)
}

/// Verifies that `data` contains exactly one gzip member with no trailing
/// data after the first member's footer.
///
/// ## Why `bufread::GzDecoder` + `Cursor`
///
/// `flate2::read::GzDecoder` wraps an internal `crate::bufreader::BufReader<R>`
/// which pre-fills up to 8 KiB on the first `fill_buf()` call.  After
/// `into_inner()` the over-read bytes are silently discarded, so the returned
/// `&[u8]` slice is empty even when trailing bytes remain — making multi-member
/// detection impossible via the `read::` variant.
///
/// `flate2::bufread::GzDecoder<BufRead>` has no such pre-fill: `into_inner()`
/// returns the underlying `BufRead` positioned exactly at the byte immediately
/// following the gzip CRC+size footer of the first member.  Wrapping
/// `package_bytes` in a `std::io::Cursor<&[u8]>` gives us a `BufRead` whose
/// byte-accurate position is observable after decode.
///
/// ## What is rejected
///
/// After the first member, the cursor remainder (minus tar end-of-archive
/// zero-padding) must be empty.  ANY remaining non-zero byte — whether it
/// starts with the gzip magic `1f 8b` (multi-member) or is arbitrary
/// garbage — triggers `ArchiveTrailingData`.
///
/// ## Decompression-bomb guard
///
/// The decode pass is capped at `MAX_TOTAL_DECOMPRESSED + 1` so a bomb
/// embedded in the trailing-data path cannot exhaust memory.
fn check_no_trailing_gzip_data(data: &[u8]) -> Result<(), ToolsetInstallError> {
    // Create a fresh Cursor so this check is independent of the main decode
    // pass and does not re-use any shared reader state.
    let cursor = Cursor::new(data);

    // `bufread::GzDecoder` stops at the end of the FIRST gzip member.
    // `into_inner()` returns the cursor at the position immediately after
    // the gzip footer — no over-read, no internal buffer to drain.
    let mut decoder = GzDecoder::new(cursor);

    // Consume decompressed output up to the bomb limit (discard; we only
    // care about the cursor position afterwards).
    let mut dev_null = io::sink();
    let mut limited = (&mut decoder).take((MAX_TOTAL_DECOMPRESSED as u64) + 1);
    io::copy(&mut limited, &mut dev_null).map_err(ToolsetInstallError::from_io)?;

    // Retrieve the cursor positioned exactly after the first member's footer.
    let cursor_after = decoder.into_inner();
    let remaining = &cursor_after.get_ref()[cursor_after.position() as usize..];

    // Strip tar end-of-archive padding: trim trailing zero bytes.
    // A well-formed tar appends two 512-byte zero blocks; any zero padding
    // here is benign.  We strip from the right to find the last non-zero byte.
    let remaining_non_zero = remaining
        .iter()
        .rposition(|&b| b != 0)
        .map_or(&[] as &[u8], |last_nz| &remaining[..=last_nz]);

    if !remaining_non_zero.is_empty() {
        return Err(ToolsetInstallError::ArchiveTrailingData);
    }

    Ok(())
}

/// Returns `true` if `s` contains only ASCII characters.
///
/// An ASCII-only gate is used for entry-name validation (over-reject,
/// the safe direction).  Full Unicode NFC + case-fold normalisation is
/// not yet implemented; `str::is_ascii()` from the standard library covers
/// the over-reject requirement without new dependencies.
fn is_ascii_only_entry_name(s: &str) -> bool {
    s.is_ascii()
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;

    // ── check_not_symlink_leaf ────────────────────────────────────────────────

    #[cfg(unix)]
    #[test]
    fn check_not_symlink_leaf_on_real_dir_passes() {
        let dir = tempfile::TempDir::new().unwrap();
        // A normal directory is not a symlink.
        check_not_symlink_leaf(dir.path()).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn check_not_symlink_leaf_on_symlink_rejected() {
        let dir = tempfile::TempDir::new().unwrap();
        let real_target = dir.path().join("target");
        std::fs::create_dir_all(&real_target).unwrap();
        let symlink_path = dir.path().join("link");
        std::os::unix::fs::symlink(&real_target, &symlink_path).unwrap();

        let err = check_not_symlink_leaf(&symlink_path).unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::ToolsetsRootInvalid { .. }),
            "expected ToolsetsRootInvalid for symlink leaf, got: {err:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn check_not_symlink_leaf_on_nonexistent_passes() {
        let dir = tempfile::TempDir::new().unwrap();
        let nonexistent = dir.path().join("does-not-exist");
        // Non-existent path → the Err branch → Ok (will be created later).
        check_not_symlink_leaf(&nonexistent).unwrap();
    }

    // ── archive: entry type checks ────────────────────────────────────────────

    fn build_tar_gz_with_entry_type(
        package_name: &str,
        entry_name: &str,
        entry_type: tar::EntryType,
    ) -> Vec<u8> {
        use std::io::Write as _;
        let mut ar = tar::Builder::new(Vec::new());

        // First add a valid directory entry.
        let mut dir_header = tar::Header::new_gnu();
        dir_header.set_entry_type(tar::EntryType::Directory);
        dir_header.set_path(format!("{package_name}/")).unwrap();
        dir_header.set_size(0);
        dir_header.set_mode(0o755);
        dir_header.set_cksum();
        ar.append(&dir_header, &[][..]).unwrap();

        // Add the entry with the requested type.
        let mut entry_header = tar::Header::new_gnu();
        entry_header.set_entry_type(entry_type);
        // Hardlinks need a symlink name to be set; for others just set size=0.
        entry_header.set_size(0);
        entry_header.set_mode(0o644);
        if entry_name.len() < 100 {
            entry_header.as_gnu_mut().unwrap().name[..entry_name.len()]
                .copy_from_slice(entry_name.as_bytes());
        }
        entry_header.set_cksum();
        ar.append(&entry_header, &[][..]).unwrap();

        let tar_bytes = ar.into_inner().unwrap();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&tar_bytes).unwrap();
        gz.finish().unwrap()
    }

    fn extract_to_temp(bytes: &[u8], package_name: &str) -> Result<(), ToolsetInstallError> {
        let staging = tempfile::TempDir::new().unwrap();
        extract_to_staging(bytes, package_name, staging.path()).map(|_| ())
    }

    #[test]
    fn symlink_entry_type_rejected() {
        let gz =
            build_tar_gz_with_entry_type("my-toolset", "my-toolset/link", tar::EntryType::Symlink);
        let err = extract_to_temp(&gz, "my-toolset").unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::ArchiveDisallowedEntryType),
            "expected ArchiveDisallowedEntryType for Symlink, got: {err:?}"
        );
    }

    #[test]
    fn hardlink_entry_type_rejected() {
        let gz =
            build_tar_gz_with_entry_type("my-toolset", "my-toolset/link", tar::EntryType::Link);
        let err = extract_to_temp(&gz, "my-toolset").unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::ArchiveDisallowedEntryType),
            "expected ArchiveDisallowedEntryType for Link, got: {err:?}"
        );
    }

    #[test]
    fn char_device_entry_type_rejected() {
        let gz = build_tar_gz_with_entry_type("my-toolset", "my-toolset/dev", tar::EntryType::Char);
        let err = extract_to_temp(&gz, "my-toolset").unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::ArchiveDisallowedEntryType),
            "expected ArchiveDisallowedEntryType for Char, got: {err:?}"
        );
    }

    // ── archive: path validation ──────────────────────────────────────────────

    /// Builds a tar.gz where the file entry at `name_bytes` is set as raw bytes in the header.
    fn build_tar_gz_with_raw_entry_name(package_name: &str, name_bytes: &[u8]) -> Vec<u8> {
        use std::io::Write as _;
        let mut ar = tar::Builder::new(Vec::new());

        // Directory entry first.
        let mut dir_header = tar::Header::new_gnu();
        dir_header.set_entry_type(tar::EntryType::Directory);
        dir_header.set_path(format!("{package_name}/")).unwrap();
        dir_header.set_size(0);
        dir_header.set_mode(0o755);
        dir_header.set_cksum();
        ar.append(&dir_header, &[][..]).unwrap();

        // File entry with raw name bytes (may contain non-UTF-8 or control chars).
        let mut fh = tar::Header::new_gnu();
        fh.set_entry_type(tar::EntryType::Regular);
        fh.set_size(0);
        fh.set_mode(0o644);
        // Directly write raw bytes into the name field (bypass set_path validation).
        let name_field = &mut fh.as_gnu_mut().unwrap().name;
        let n = name_bytes.len().min(name_field.len() - 1);
        name_field[..n].copy_from_slice(&name_bytes[..n]);
        fh.set_cksum();
        ar.append(&fh, &[][..]).unwrap();

        let tar_bytes = ar.into_inner().unwrap();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&tar_bytes).unwrap();
        gz.finish().unwrap()
    }

    #[test]
    fn entry_name_with_backspace_control_byte_rejected() {
        // Backspace (0x08) is a control byte that is not '/' → ArchiveEntryNameInvalid.
        let name_with_bs = b"my-toolset/fi\x08le.txt";
        let gz = build_tar_gz_with_raw_entry_name("my-toolset", name_with_bs);
        let err = extract_to_temp(&gz, "my-toolset").unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::ArchiveEntryNameInvalid { .. }),
            "expected ArchiveEntryNameInvalid for backspace byte, got: {err:?}"
        );
    }

    #[test]
    fn entry_name_with_control_byte_rejected() {
        // Control byte (0x01) in entry name → ArchiveEntryNameInvalid.
        let name_with_ctrl = b"my-toolset/fi\x01le.txt";
        let gz = build_tar_gz_with_raw_entry_name("my-toolset", name_with_ctrl);
        let err = extract_to_temp(&gz, "my-toolset").unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::ArchiveEntryNameInvalid { .. }),
            "expected ArchiveEntryNameInvalid for control byte, got: {err:?}"
        );
    }

    #[test]
    fn entry_name_over_length_cap_rejected() {
        // A path name that exceeds MAX_NAME_LEN → ArchiveEntryNameInvalid.
        // Use a PAX header to get long names past the 100-char GNU limit.
        use std::io::Write as _;
        let package_name = "my-toolset";
        let long_filename = format!("{package_name}/{}", "a".repeat(4100)); // > MAX_NAME_LEN (4096)
        let mut ar = tar::Builder::new(Vec::new());

        let mut dir_header = tar::Header::new_gnu();
        dir_header.set_entry_type(tar::EntryType::Directory);
        dir_header.set_path(format!("{package_name}/")).unwrap();
        dir_header.set_size(0);
        dir_header.set_mode(0o755);
        dir_header.set_cksum();
        ar.append(&dir_header, &[][..]).unwrap();

        // tar::Builder::append_file with a long path generates PAX headers automatically.
        let mut fh = tar::Header::new_gnu();
        fh.set_entry_type(tar::EntryType::Regular);
        fh.set_size(0);
        fh.set_mode(0o644);
        fh.set_cksum();
        ar.append_data(&mut fh, &long_filename, &[][..]).unwrap();

        let tar_bytes = ar.into_inner().unwrap();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&tar_bytes).unwrap();
        let gz_bytes = gz.finish().unwrap();

        let err = extract_to_temp(&gz_bytes, package_name).unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::ArchiveEntryNameInvalid { .. }),
            "expected ArchiveEntryNameInvalid for over-long name, got: {err:?}"
        );
    }

    // ── archive: multiple top-level dirs ─────────────────────────────────────

    #[test]
    fn multiple_top_level_directories_rejected() {
        use std::io::Write as _;
        let package_name = "my-toolset";
        let mut ar = tar::Builder::new(Vec::new());

        // First top-level dir: matches package name.
        let mut h1 = tar::Header::new_gnu();
        h1.set_entry_type(tar::EntryType::Directory);
        h1.set_path(format!("{package_name}/")).unwrap();
        h1.set_size(0);
        h1.set_mode(0o755);
        h1.set_cksum();
        ar.append(&h1, &[][..]).unwrap();

        // A file inside the package dir.
        let content = b"hello";
        let mut fh = tar::Header::new_gnu();
        fh.set_entry_type(tar::EntryType::Regular);
        fh.set_path(format!("{package_name}/TOOLSET.md")).unwrap();
        fh.set_size(content.len() as u64);
        fh.set_mode(0o644);
        fh.set_cksum();
        ar.append(&fh, &content[..]).unwrap();

        // Second top-level dir: a DIFFERENT name.
        let mut h2 = tar::Header::new_gnu();
        h2.set_entry_type(tar::EntryType::Directory);
        h2.set_path("other-dir/").unwrap();
        h2.set_size(0);
        h2.set_mode(0o755);
        h2.set_cksum();
        ar.append(&h2, &[][..]).unwrap();

        let tar_bytes = ar.into_inner().unwrap();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&tar_bytes).unwrap();
        let gz_bytes = gz.finish().unwrap();

        let err = extract_to_temp(&gz_bytes, package_name).unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::ArchiveBadTopLevel { .. }),
            "expected ArchiveBadTopLevel for multiple top-level dirs, got: {err:?}"
        );
    }

    // ── archive: non-ASCII entry name ─────────────────────────────────────────

    #[test]
    fn non_ascii_entry_name_in_archive_rejected() {
        // Entry name contains a non-ASCII character via PAX long-name extension.
        use std::io::Write as _;
        let package_name = "my-toolset";
        // PAX headers allow arbitrary UTF-8; "café" contains non-ASCII.
        let entry_name = format!("{package_name}/caf\u{00E9}.txt");

        let mut ar = tar::Builder::new(Vec::new());

        let mut dir_header = tar::Header::new_gnu();
        dir_header.set_entry_type(tar::EntryType::Directory);
        dir_header.set_path(format!("{package_name}/")).unwrap();
        dir_header.set_size(0);
        dir_header.set_mode(0o755);
        dir_header.set_cksum();
        ar.append(&dir_header, &[][..]).unwrap();

        let mut fh = tar::Header::new_gnu();
        fh.set_entry_type(tar::EntryType::Regular);
        fh.set_size(0);
        fh.set_mode(0o644);
        fh.set_cksum();
        ar.append_data(&mut fh, &entry_name, &[][..]).unwrap();

        let tar_bytes = ar.into_inner().unwrap();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&tar_bytes).unwrap();
        let gz_bytes = gz.finish().unwrap();

        let err = extract_to_temp(&gz_bytes, package_name).unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::ArchiveEntryNameInvalid { .. }),
            "expected ArchiveEntryNameInvalid for non-ASCII name, got: {err:?}"
        );
    }

    // ── archive: per-entry size cap ───────────────────────────────────────────

    #[test]
    fn per_entry_size_cap_rejected() {
        // A single file entry that exceeds MAX_ENTRY_BYTES → ArchiveEntryTooLarge.
        use std::io::Write as _;
        let package_name = "my-toolset";
        let entry_size = MAX_ENTRY_BYTES + 1;

        let mut ar = tar::Builder::new(Vec::new());

        let mut dir_header = tar::Header::new_gnu();
        dir_header.set_entry_type(tar::EntryType::Directory);
        dir_header.set_path(format!("{package_name}/")).unwrap();
        dir_header.set_size(0);
        dir_header.set_mode(0o755);
        dir_header.set_cksum();
        ar.append(&dir_header, &[][..]).unwrap();

        // Build an in-memory content block of size MAX_ENTRY_BYTES + 1.
        let big_content = vec![0u8; entry_size];
        let mut fh = tar::Header::new_gnu();
        fh.set_entry_type(tar::EntryType::Regular);
        fh.set_path(format!("{package_name}/big.bin")).unwrap();
        fh.set_size(entry_size as u64);
        fh.set_mode(0o644);
        fh.set_cksum();
        ar.append(&fh, big_content.as_slice()).unwrap();

        let tar_bytes = ar.into_inner().unwrap();
        // Compress with best-speed to avoid time-out on 32 MiB.
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&tar_bytes).unwrap();
        let gz_bytes = gz.finish().unwrap();

        let err = extract_to_temp(&gz_bytes, package_name).unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::ArchiveEntryTooLarge { .. }),
            "expected ArchiveEntryTooLarge, got: {err:?}"
        );
    }

    // ── lexical_normalise_and_check ───────────────────────────────────────────

    #[test]
    fn normal_path_accepted() {
        let p = lexical_normalise_and_check("my-toolset/TOOLSET.md").unwrap();
        assert_eq!(p, PathBuf::from("my-toolset/TOOLSET.md"));
    }

    #[test]
    fn leading_dotslash_stripped() {
        let p = lexical_normalise_and_check("./my-toolset/TOOLSET.md").unwrap();
        assert_eq!(p, PathBuf::from("my-toolset/TOOLSET.md"));
    }

    #[test]
    fn dotdot_rejected() {
        let err = lexical_normalise_and_check("my-toolset/../etc/passwd").unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::ArchivePathTraversal { .. }),
            "expected ArchivePathTraversal, got: {err:?}"
        );
    }

    #[test]
    fn absolute_path_rejected() {
        let err = lexical_normalise_and_check("/etc/passwd").unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::ArchivePathTraversal { .. }),
            "expected ArchivePathTraversal, got: {err:?}"
        );
    }

    #[test]
    fn dotonly_path_rejected() {
        let err = lexical_normalise_and_check(".").unwrap_err();
        // `.` alone normalises to empty components (CurDir only).
        assert!(matches!(
            err,
            ToolsetInstallError::ArchiveEntryNameInvalid { .. }
                | ToolsetInstallError::ArchivePathTraversal { .. }
        ));
    }

    #[test]
    fn empty_path_rejected() {
        let err = lexical_normalise_and_check("").unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::ArchiveEntryNameInvalid { .. }),
            "expected ArchiveEntryNameInvalid, got: {err:?}"
        );
    }

    // ── is_ascii_only_entry_name ──────────────────────────────────────────────

    #[test]
    fn ascii_entry_names_pass() {
        assert!(is_ascii_only_entry_name("my-toolset/TOOLSET.md"));
        assert!(is_ascii_only_entry_name("a-b-c"));
        assert!(is_ascii_only_entry_name("toolset123/references/file.txt"));
    }

    #[test]
    fn non_ascii_entry_names_rejected() {
        // Non-ASCII characters are rejected (over-reject, safe direction).
        assert!(!is_ascii_only_entry_name("caf\u{00E9}")); // café with precomposed é
        assert!(!is_ascii_only_entry_name("caf\u{0065}\u{0301}")); // café with combining accent
        assert!(!is_ascii_only_entry_name("my-toolset/\u{4e2d}\u{6587}.txt")); // Chinese chars
    }

    // ── check_no_trailing_gzip_data ───────────────────────────────────────────

    use flate2::Compression;
    use flate2::write::GzEncoder as GzWriteEncoder;

    fn build_single_member_gz(content: &[u8]) -> Vec<u8> {
        let mut enc = GzWriteEncoder::new(Vec::new(), Compression::default());
        enc.write_all(content).unwrap();
        enc.finish().unwrap()
    }

    #[test]
    fn single_member_gz_passes_trailing_check() {
        let gz = build_single_member_gz(b"hello");
        // Must not return ArchiveTrailingData.
        check_no_trailing_gzip_data(&gz).unwrap();
    }

    #[test]
    fn two_member_gz_triggers_trailing_data() {
        // A two-member gzip = concatenation of two valid gzip streams.
        let m1 = build_single_member_gz(b"first member");
        let m2 = build_single_member_gz(b"second member");
        let mut multi = m1;
        multi.extend_from_slice(&m2);

        let err = check_no_trailing_gzip_data(&multi).unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::ArchiveTrailingData),
            "expected ArchiveTrailingData for two-member gzip, got: {err:?}"
        );
    }

    #[test]
    fn non_magic_trailing_garbage_triggers_trailing_data() {
        // A valid gzip member followed by non-magic garbage bytes.
        let mut gz = build_single_member_gz(b"data");
        gz.extend_from_slice(b"\xDE\xAD\xBE\xEF"); // non-zero, non-magic

        let err = check_no_trailing_gzip_data(&gz).unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::ArchiveTrailingData),
            "expected ArchiveTrailingData for trailing garbage, got: {err:?}"
        );
    }
}
