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

/// Collision suffixes tried for a retired file name before the binding
/// refuses.
const RETIRED_NAME_ATTEMPTS: u64 = 1_000;

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

/// The name the outbox of `generation` is retired to: `None` when no outbox
/// file exists, otherwise the first free name among at most 1000 candidates,
/// with an exhaustion error when every candidate is taken.
///
/// A retired name of a generation repeats when a binding restarts at a
/// generation an earlier binding already retired, as after a lost carrier
/// record. The earlier file stays, and the collision suffix keeps both.
///
/// # Errors
///
/// [`WriterError::Io`] when the directory cannot be read, or of kind
/// `AlreadyExists` when all 1000 candidates are taken.
pub(crate) fn retired_name(log: &Path, generation: u64) -> Result<Option<String>, WriterError> {
    if !outbox_path(log).try_exists()? {
        return Ok(None);
    }
    for collision in 0..RETIRED_NAME_ATTEMPTS {
        let path = retired_path(log, generation, collision);
        if !path.try_exists()? {
            return Ok(path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned()));
        }
    }
    Err(WriterError::Io(io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!(
            "every retired outbox name of generation {generation} is taken; move the \
             retired files aside and rerun"
        ),
    )))
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
/// Renames the current outbox to `retired` unless that name already holds the
/// retired file, then the staged file into the outbox's place, then syncs the
/// directory. Each rename is skipped or repeated safely, so a rerun after an
/// interruption between them converges.
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
        if outbox.try_exists()? && !retired.try_exists()? {
            std::fs::rename(&outbox, &retired)?;
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
