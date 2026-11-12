//! Outbox generation files of a carrier binding.
//!
//! `audit bind-carriers` copies the committed rows of the current outbox
//! generation G into the staged file `<log>.outbox.g<G+1>`, records the
//! carriers, then renames the current outbox to a retired file and the staged
//! file into its place. A holder of generation G keeps its open handle on the
//! retired file. A staged file that still exists marks a binding that has not
//! finished, and every ordinary writer open refuses while one does. A rerun
//! that restages rewrites the stage in place, so the mark stays until the
//! stage is installed.
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use super::outbox::{OutboxState, holds_exactly_committed, outbox_path, sync_parent_dir};
use super::writer::{WriterError, sidecar_path};

/// Result of a carrier binding.
#[derive(Debug, serde::Serialize)]
pub struct CarrierBindingReport {
    /// Outbox generation the binding recorded.
    pub generation: u64,
    /// Committed operator rows carried into this generation.
    pub carried_rows: u64,
    /// File name the previous generation's outbox was retired to, `None` when
    /// the log had no outbox file to retire.
    pub retired_file: Option<String>,
}

/// The staged outbox file of `generation`, `<log>.outbox.g<generation>`.
pub(crate) fn generation_path(log: &Path, generation: u64) -> PathBuf {
    sidecar_path(log, &format!(".outbox.g{generation}"))
}

/// The retired file of `generation`: `<log>.outbox.retired-g<generation>`,
/// and `<log>.outbox.retired-g<generation>.<n>` for the `n`th collision.
fn retired_path(log: &Path, generation: u64, collision: u64) -> PathBuf {
    if collision == 0 {
        sidecar_path(log, &format!(".outbox.retired-g{generation}"))
    } else {
        sidecar_path(log, &format!(".outbox.retired-g{generation}.{collision}"))
    }
}

/// The name the outbox of `generation` is retired to. It is `None` when no
/// outbox file exists. Otherwise it is the first free name across the whole
/// `u64` collision suffix range. An exhaustion error follows when every name
/// is taken. A directory entry of any kind takes its name, a dangling link
/// included.
///
/// A retired name of a generation repeats when a binding restarts at a
/// generation an earlier binding already retired, as after a lost carrier
/// record. The earlier file stays, and the collision suffix keeps both.
///
/// # Errors
///
/// [`WriterError::Io`] when the directory cannot be read, or of kind
/// `AlreadyExists` when every collision suffix is taken.
pub(crate) fn retired_name(log: &Path, generation: u64) -> Result<Option<String>, WriterError> {
    if !outbox_path(log).try_exists()? {
        return Ok(None);
    }
    for collision in 0..=u64::MAX {
        let path = retired_path(log, generation, collision);
        if !entry_exists(&path)? {
            return Ok(Some(file_name(&path)));
        }
    }
    Err(retired_names_exhausted(generation))
}

/// Moves the outbox to the retired file `name` the carrier record already
/// names. The result is `true` when the outbox now sits there or no outbox
/// file exists, and `false` when another entry holds `name`.
///
/// The move never replaces an entry, and the file never has two names.
///
/// # Errors
///
/// [`WriterError::Io`] when the move fails for a reason other than an
/// existing destination.
pub(crate) fn retire_to(log: &Path, name: &str) -> Result<bool, WriterError> {
    let outbox = outbox_path(log);
    if !outbox.try_exists()? {
        return Ok(true);
    }
    match rename_no_replace(&outbox, &log.with_file_name(name)) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(WriterError::Io(e)),
    }
}

/// Renames `from` to `to`, refusing with `AlreadyExists` when an entry of
/// any kind holds `to`. The file is never linked or copied.
///
/// On Linux and Apple platforms the exclusive rename does the move:
/// `renameat2` with `RENAME_NOREPLACE`, or `renameatx_np` with `RENAME_EXCL`.
/// A system that reports it unsupported gets [`checked_rename`].
#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
fn rename_no_replace(from: &Path, to: &Path) -> io::Result<()> {
    use rustix::fs::{CWD, RenameFlags, renameat_with};
    use rustix::io::Errno;

    #[cfg(test)]
    if test_seam::exclusive_rename_unsupported() {
        return checked_rename(from, to);
    }
    match renameat_with(CWD, from, CWD, to, RenameFlags::NOREPLACE) {
        Ok(()) => Ok(()),
        Err(errno)
            if errno == Errno::NOSYS
                || errno == Errno::INVAL
                || errno == Errno::NOTSUP
                || errno == Errno::OPNOTSUPP =>
        {
            checked_rename(from, to)
        }
        Err(errno) => Err(errno.into()),
    }
}

/// Renames `from` to `to` on a Unix system without an exclusive rename.
#[cfg(all(
    unix,
    not(any(target_os = "linux", target_os = "android", target_vendor = "apple"))
))]
fn rename_no_replace(from: &Path, to: &Path) -> io::Result<()> {
    checked_rename(from, to)
}

/// Renames `from` to `to` through `MoveFileExW` without the replace flag.
///
/// The path guard's cleanup is disabled before the move is attempted, so no
/// outcome removes `from`.
#[cfg(windows)]
fn rename_no_replace(from: &Path, to: &Path) -> io::Result<()> {
    let mut source = tempfile::TempPath::try_from_path(from)?;
    source.disable_cleanup(true);
    source
        .persist_noclobber(to)
        .map_err(|refused| refused.error)
}

/// Renames `from` to `to` on a platform without another no-replace rename.
#[cfg(not(any(unix, windows)))]
fn rename_no_replace(from: &Path, to: &Path) -> io::Result<()> {
    checked_rename(from, to)
}

/// Refuses with `AlreadyExists` when an entry of any kind holds `to`, and
/// otherwise renames `from` there.
///
/// The binding holds every carrier, the outbox lock included, so no wallet
/// process creates the name between the check and the rename.
#[cfg_attr(
    windows,
    allow(dead_code, reason = "Windows renames without replacing")
)]
fn checked_rename(from: &Path, to: &Path) -> io::Result<()> {
    if entry_exists(to)? {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "the retired outbox name is taken",
        ));
    }
    std::fs::rename(from, to)
}

/// The file name of a path built beside the log.
fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// The error for a generation whose every retired name is taken.
fn retired_names_exhausted(generation: u64) -> WriterError {
    WriterError::Io(io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!(
            "every retired outbox name of generation {generation} is taken; move the \
             retired files aside and rerun"
        ),
    ))
}

/// Whether a directory entry of any kind exists at `path`.
///
/// Symbolic links are not followed, so a link whose target is missing still
/// occupies its name.
///
/// # Errors
///
/// [`io::Error`] when the entry cannot be inspected for a reason other than
/// its absence.
fn entry_exists(path: &Path) -> io::Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

/// The staged generation files beside `log`: exactly the names
/// `<log>.outbox.g<N>` whose number `N` is written canonically. Any other
/// name, such as an operator's `<log>.outbox.gz` or `<log>.outbox.g1.saved`,
/// is not a stage and is never removed.
///
/// # Errors
///
/// [`WriterError::Io`] when the directory cannot be read, or of kind
/// `InvalidInput` when `log` has no file name or parent directory.
pub(crate) fn staged_files(log: &Path) -> Result<Vec<PathBuf>, WriterError> {
    let prefix_path = sidecar_path(log, ".outbox.g");
    let prefix = prefix_path
        .file_name()
        .ok_or_else(|| invalid_log_path("a file name"))?
        .as_encoded_bytes();
    let parent = log.parent().ok_or_else(|| invalid_log_path("a parent"))?;
    let mut files = Vec::new();
    for entry in std::fs::read_dir(parent)? {
        let entry = entry?;
        let name = entry.file_name();
        let generation = name
            .as_encoded_bytes()
            .strip_prefix(prefix)
            .and_then(|suffix| std::str::from_utf8(suffix).ok())
            .and_then(|suffix| suffix.parse::<u64>().ok());
        if generation.is_some_and(|generation| {
            generation_path(log, generation).file_name() == Some(name.as_os_str())
        }) {
            files.push(entry.path());
        }
    }
    Ok(files)
}

/// Whether the staged file of a generation holds exactly the rows `state`
/// commits: every line complete and the lines chaining to the committed head.
///
/// # Errors
///
/// [`WriterError::Io`] when the staged file cannot be read.
pub(crate) fn stage_holds(staged: &Path, state: &OutboxState) -> Result<bool, WriterError> {
    Ok(holds_exactly_committed(&std::fs::read(staged)?, state))
}

/// Writes `bytes` as the staged file of `generation` and removes every other
/// stage.
///
/// An existing stage of `generation` is truncated and rewritten in place, so
/// the stage that marks an incomplete binding exists at every point of the
/// rewrite. The file and its directory are synced before this returns.
///
/// # Errors
///
/// [`WriterError::Io`] when the stage cannot be written or synced, or another
/// stage cannot be removed.
pub(crate) fn write_stage(log: &Path, generation: u64, bytes: &[u8]) -> Result<(), WriterError> {
    let staged = generation_path(log, generation);
    let mut file = open_stage_0600(&staged)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    for stage in staged_files(log)? {
        if stage != staged {
            std::fs::remove_file(stage)?;
        }
    }
    sync_parent_dir(log)?;
    Ok(())
}

/// Opens the stage at `path` for writing, created with permissions `0600` on
/// POSIX, and truncated when it exists.
fn open_stage_0600(path: &Path) -> io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path)
}

/// Installs the staged file of `generation` as the outbox.
///
/// Renames the current outbox to `retired` unless a directory entry of any
/// kind already holds that name, a dangling link included. A rerun finds its
/// own retired file there and skips the move. The move itself never replaces
/// an entry: a name created after the check refuses it with `AlreadyExists`.
/// Then the staged file takes the outbox's place, and the directory is
/// synced. Each step is skipped or repeated safely, so a rerun converges.
///
/// # Errors
///
/// [`WriterError::Io`] when a rename or the directory sync fails.
pub(crate) fn finish(
    log: &Path,
    generation: u64,
    retired: Option<&str>,
) -> Result<(), WriterError> {
    let outbox = outbox_path(log);
    if let Some(name) = retired {
        let retired = log.with_file_name(name);
        if outbox.try_exists()? && !entry_exists(&retired)? {
            rename_no_replace(&outbox, &retired)?;
        }
    }
    std::fs::rename(generation_path(log, generation), &outbox)?;
    sync_parent_dir(log)?;
    Ok(())
}

/// The `InvalidInput` error for a log path the binding cannot place files
/// beside.
fn invalid_log_path(missing: &str) -> WriterError {
    WriterError::Io(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("the audit log path has no {missing}"),
    ))
}

/// Test-only switch that makes the exclusive rename read as unsupported on
/// the current thread, so the checked fallback runs.
#[cfg(test)]
pub(crate) mod test_seam {
    use std::cell::Cell;

    thread_local! {
        static UNSUPPORTED: Cell<bool> = const { Cell::new(false) };
    }

    /// Makes the exclusive rename read as unsupported on this thread, or not.
    pub(crate) fn set_exclusive_rename_unsupported(unsupported: bool) {
        UNSUPPORTED.with(|cell| cell.set(unsupported));
    }

    #[cfg_attr(
        not(any(target_os = "linux", target_os = "android", target_vendor = "apple")),
        allow(dead_code, reason = "only the exclusive rename reads the switch")
    )]
    pub(super) fn exclusive_rename_unsupported() -> bool {
        UNSUPPORTED.with(Cell::get)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, reason = "test-only")]

    use super::*;
    use crate::audit_log::tip_anchor::{CarrierRecord, RetiredOutbox};
    use crate::file_lock::FileIdentity;

    /// Another process takes the chosen retired name after the search: a
    /// regular file holds it, and on Unix a link whose target is missing holds
    /// the next suffix. Each refused move keeps that entry and leaves the
    /// outbox in place with its bytes. The next free name takes the outbox,
    /// which then has that one name only. Both the exclusive rename and the
    /// checked fallback behave so.
    #[test]
    fn an_occupied_retired_name_is_kept_and_the_next_free_name_is_taken() {
        for unsupported in [false, true] {
            test_seam::set_exclusive_rename_unsupported(unsupported);
            let dir = tempfile::tempdir().unwrap();
            let log = dir.path().join("audit.jsonl");
            std::fs::write(outbox_path(&log), b"current outbox\n").unwrap();
            let mut name = retired_name(&log, 3).unwrap().unwrap();
            assert_eq!(name, "audit.jsonl.outbox.retired-g3");
            std::fs::write(retired_path(&log, 3, 0), b"another process\n").unwrap();
            #[cfg(unix)]
            let (link, expected) = {
                let link = retired_path(&log, 3, 1);
                std::os::unix::fs::symlink("missing-target", &link).unwrap();
                (link, "audit.jsonl.outbox.retired-g3.2")
            };
            #[cfg(not(unix))]
            let expected = "audit.jsonl.outbox.retired-g3.1";

            let mut refused = 0;
            while !retire_to(&log, &name).unwrap() {
                refused += 1;
                assert_eq!(
                    std::fs::read(outbox_path(&log)).unwrap(),
                    b"current outbox\n",
                    "a refused move leaves the outbox with its bytes"
                );
                name = retired_name(&log, 3).unwrap().unwrap();
            }
            // Only the name taken after the search refuses; the next search
            // skips every occupied name, the link included.
            assert_eq!(refused, 1, "the taken name refuses once");
            assert_eq!(name, expected, "fallback {unsupported}");
            assert_eq!(
                std::fs::read(retired_path(&log, 3, 0)).unwrap(),
                b"another process\n",
                "the regular file keeps its bytes"
            );
            #[cfg(unix)]
            assert_eq!(
                std::fs::read_link(&link).unwrap(),
                std::path::Path::new("missing-target"),
                "the dangling link keeps its target"
            );
            assert_eq!(
                std::fs::read(log.with_file_name(&name)).unwrap(),
                b"current outbox\n"
            );
            assert!(
                !outbox_path(&log).exists(),
                "the outbox has one name, not two"
            );

            write_stage(&log, 4, b"staged\n").unwrap();
            finish(&log, 4, Some(&name)).unwrap();
            assert_eq!(std::fs::read(outbox_path(&log)).unwrap(), b"staged\n");
            assert_eq!(
                std::fs::read(log.with_file_name(&name)).unwrap(),
                b"current outbox\n"
            );
        }
        test_seam::set_exclusive_rename_unsupported(false);
    }

    /// Collision suffixes 0 through 1,000 of generation 3 are taken, and on
    /// Unix suffix 1,001 is a link whose target is missing. The binding names
    /// the next suffix, installs its stage, and every earlier retired file
    /// keeps its bytes. The link keeps its target text. The carrier record
    /// keeps its wire form.
    #[test]
    fn retired_names_continue_past_one_thousand_without_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.jsonl");
        std::fs::write(outbox_path(&log), b"current outbox\n").unwrap();
        for collision in 0..=1_000_u64 {
            std::fs::write(
                retired_path(&log, 3, collision),
                format!("retired {collision}\n"),
            )
            .unwrap();
        }
        #[cfg(unix)]
        let (link, expected) = {
            let link = retired_path(&log, 3, 1_001);
            std::os::unix::fs::symlink("missing-target", &link).unwrap();
            (link, "audit.jsonl.outbox.retired-g3.1002")
        };
        #[cfg(not(unix))]
        let expected = "audit.jsonl.outbox.retired-g3.1001";

        // A search that wraps never ends, so the search runs on its own
        // thread under a generous bound.
        let (sent, received) = std::sync::mpsc::channel();
        let search_log = log.clone();
        std::thread::spawn(move || {
            let _ = sent.send(retired_name(&search_log, 3).map_err(|e| e.to_string()));
        });
        let name = received
            .recv_timeout(std::time::Duration::from_secs(60))
            .expect("the search past suffix 1,000 ends")
            .unwrap()
            .unwrap();
        assert_eq!(name, expected);

        write_stage(&log, 4, b"staged\n").unwrap();
        finish(&log, 4, Some(&name)).unwrap();
        #[cfg(unix)]
        assert_eq!(
            std::fs::read_link(&link).unwrap(),
            std::path::Path::new("missing-target"),
            "the dangling link stays in place"
        );
        for collision in 0..=1_000_u64 {
            assert_eq!(
                std::fs::read(retired_path(&log, 3, collision)).unwrap(),
                format!("retired {collision}\n").into_bytes(),
                "retired file {collision} stays unchanged"
            );
        }
        assert_eq!(
            std::fs::read(log.with_file_name(&name)).unwrap(),
            b"current outbox\n"
        );
        assert_eq!(std::fs::read(outbox_path(&log)).unwrap(), b"staged\n");

        let identity = FileIdentity::Unix { dev: 1, ino: 2 };
        let record = CarrierRecord {
            generation: 4,
            writer: identity.clone(),
            drain: identity.clone(),
            outbox_lock: identity,
            retired: Some(RetiredOutbox {
                generation: 3,
                state: String::new(),
                file: Some(name.clone()),
            }),
        };
        let wire = record.to_keyring_value().unwrap();
        assert_eq!(
            wire,
            format!(
                r#"{{"drain":"unix:1:2","generation":4,"outbox_lock":"unix:1:2","retired":{{"file":"{name}","generation":3,"state":""}},"v":1,"writer":"unix:1:2"}}"#
            )
        );
        assert_eq!(CarrierRecord::parse(&wire).unwrap(), record);
    }
}
