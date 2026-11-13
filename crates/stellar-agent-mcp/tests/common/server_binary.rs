//! The server child of the integration tests: the unified `stellar-agent`
//! executable, started under its `stellar-agent-mcp` alias.
//!
//! The executable belongs to `stellar-agent-cli`, so a test run builds it only
//! when it selects that package too:
//! `cargo test -p stellar-agent-cli -p stellar-agent-mcp --no-run` with the
//! run's `--target` and feature flags. Building both packages together gives
//! the child the dev-dependency features of both.
//!
//! The canonical file sits in the run's target and profile directory, which
//! [`bin_dir_of`] derives from the test executable's path. Its `--version`
//! marker must match this test build's `mainnet-write` state. The alias is a complete copy below
//! `<bin dir>/../tmp/server-alias-<len>-<mtime_ns>/`. It is published without
//! overwriting an existing file, so concurrent test processes share one
//! alias, and an existing alias is used only when its bytes equal the
//! canonical file. Each process resolves the alias once. The command runs the
//! child under a scratch `STELLAR_AGENT_HOME` unless the caller sets one.

#![allow(dead_code, reason = "shared helper; each suite uses the part it needs")]

use std::fs::File;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::UNIX_EPOCH;

/// File name of the unified executable.
fn canonical_name() -> String {
    format!("stellar-agent{}", std::env::consts::EXE_SUFFIX)
}

/// File name of the server alias.
fn alias_name() -> String {
    format!("stellar-agent-mcp{}", std::env::consts::EXE_SUFFIX)
}

/// A command that starts the server child under its alias.
///
/// The command sets `STELLAR_AGENT_HOME` to a scratch home of this process
/// below `<bin dir>/../tmp`, so a child never reaches the default state
/// directory. A caller that sets its own home replaces it.
///
/// # Panics
///
/// Panics with the reason when the canonical executable is missing, reports
/// the other feature state, the alias cannot be published, or the scratch
/// home cannot be created.
#[must_use]
#[allow(
    clippy::panic,
    reason = "test helper; a child that cannot start fails the calling test with the reason"
)]
pub fn server_command() -> Command {
    static CACHE: AliasCache = AliasCache::new();
    static HOME: AliasCache = AliasCache::new();
    let bin_dir = || {
        let exe = std::env::current_exe().map_err(|err| format!("test executable: {err}"))?;
        bin_dir_of(&exe)
    };
    let path = CACHE.get_with(|| resolve(&bin_dir()?));
    let home = HOME.get_with(|| scratch_home(&bin_dir()?));
    match (path, home) {
        (Ok(path), Ok(home)) => {
            let mut command = Command::new(path);
            command.env("STELLAR_AGENT_HOME", home);
            command
        }
        (Err(reason), _) | (_, Err(reason)) => panic!("{reason}"),
    }
}

/// Creates the scratch home of this process below `<bin dir>/../tmp`. It
/// stays after the process ends, like the alias directory beside it.
fn scratch_home(bin_dir: &Path) -> Result<PathBuf, String> {
    let root = bin_dir.join("..").join("tmp");
    std::fs::create_dir_all(&root).map_err(|err| format!("{}: {err}", root.display()))?;
    tempfile::Builder::new()
        .prefix("server-home-")
        .tempdir_in(&root)
        .map(tempfile::TempDir::keep)
        .map_err(|err| format!("scratch home in {}: {err}", root.display()))
}

/// One alias resolution per process.
struct AliasCache(OnceLock<Result<PathBuf, String>>);

impl AliasCache {
    /// An empty cache.
    #[must_use]
    const fn new() -> Self {
        Self(OnceLock::new())
    }

    /// The cached result, computed by `resolve` on the first call only.
    fn get_with(
        &self,
        resolve: impl FnOnce() -> Result<PathBuf, String>,
    ) -> &Result<PathBuf, String> {
        self.0.get_or_init(resolve)
    }
}

/// The target and profile directory that holds the executables of the run
/// that built the test executable `exe`.
///
/// Cargo places a test executable at `<bin dir>/deps/<name>` or at
/// `<bin dir>/build/<package>/<hash>/out/<name>`.
///
/// # Errors
///
/// Returns the reason when `exe` sits in neither layout.
fn bin_dir_of(exe: &Path) -> Result<PathBuf, String> {
    let up = |count: usize| exe.ancestors().nth(count);
    let named = |count: usize, expected: &str| {
        up(count).and_then(Path::file_name) == Some(std::ffi::OsStr::new(expected))
    };
    let dir = if named(1, "deps") {
        up(2)
    } else if named(1, "out") && named(4, "build") {
        up(5)
    } else {
        None
    };
    dir.map(Path::to_path_buf)
        .ok_or_else(|| format!("{} is in no known Cargo layout", exe.display()))
}

/// Locates the canonical executable in `dir`, checks its feature marker, and
/// returns its published alias.
///
/// # Errors
///
/// Returns the reason when any step refuses.
fn resolve(dir: &Path) -> Result<PathBuf, String> {
    let canonical = locate_in(dir)?;
    verify_marker(&canonical, cfg!(feature = "mainnet-write"))?;
    let alias = alias_path(&canonical)?;
    publish(&canonical, &alias)?;
    Ok(alias)
}

/// The canonical executable in `dir`.
///
/// # Errors
///
/// Returns the build command when no regular file is there.
fn locate_in(dir: &Path) -> Result<PathBuf, String> {
    let path = dir.join(canonical_name());
    if path.is_file() {
        Ok(path)
    } else {
        Err(format!(
            "the unified binary is not built at {}; run cargo test -p stellar-agent-cli -p stellar-agent-mcp --no-run with this run's --target and feature flags",
            path.display()
        ))
    }
}

/// Requires a successful `--version` whose second line is the marker for
/// `mainnet_write`.
///
/// # Errors
///
/// Returns the reason when the run fails or the marker differs.
fn verify_marker(canonical: &Path, mainnet_write: bool) -> Result<(), String> {
    let output = Command::new(canonical)
        .arg("--version")
        .output()
        .map_err(|err| format!("{} --version: {err}", canonical.display()))?;
    if !output.status.success() {
        return Err(format!(
            "{} --version exited with {}",
            canonical.display(),
            output.status
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let state = if mainnet_write { "on" } else { "off" };
    let expected = format!("{}{}{state}", "STELLAR_AGENT_BUILD_", "MAINNET_WRITE=");
    let line = stdout
        .lines()
        .nth(1)
        .map(|line| line.trim_end_matches('\r'));
    if line == Some(expected.as_str()) {
        Ok(())
    } else {
        Err(format!(
            "{} reports {line:?}, this test build expects {expected}; build both packages with this run's feature flags",
            canonical.display()
        ))
    }
}

/// The alias path for `canonical`, keyed by its length and modification time.
///
/// # Errors
///
/// Returns the reason when the metadata is unreadable.
fn alias_path(canonical: &Path) -> Result<PathBuf, String> {
    let meta =
        std::fs::metadata(canonical).map_err(|err| format!("{}: {err}", canonical.display()))?;
    let mtime_ns = meta
        .modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|elapsed| elapsed.as_nanos())
        .ok_or_else(|| format!("{}: no modification time", canonical.display()))?;
    let bin_dir = canonical
        .parent()
        .ok_or_else(|| format!("{} has no directory", canonical.display()))?;
    Ok(bin_dir
        .join("..")
        .join("tmp")
        .join(format!("server-alias-{}-{mtime_ns}", meta.len()))
        .join(alias_name()))
}

/// How [`publish`] obtained the alias.
#[derive(Debug, PartialEq, Eq)]
enum Publication {
    /// This call placed the alias.
    Published,
    /// An equal alias was already there and stays unchanged.
    Existing,
}

/// Places a copy of `canonical` at `alias` unless a file is already there,
/// then requires equal bytes at `alias`.
///
/// The copy is complete, carries the canonical permissions, and has no open
/// handle when it is published. Publication never replaces a file at `alias`.
/// Successful publication may leave a temporary hard link; failed
/// publication drops its temporary path.
///
/// # Errors
///
/// Returns the reason when the copy fails or the alias differs.
fn publish(canonical: &Path, alias: &Path) -> Result<Publication, String> {
    let dir = alias
        .parent()
        .ok_or_else(|| format!("{} has no directory", alias.display()))?;
    std::fs::create_dir_all(dir).map_err(|err| format!("{}: {err}", dir.display()))?;
    let outcome = if alias.symlink_metadata().is_ok() {
        Publication::Existing
    } else {
        let temp = copy_to_temp(canonical, dir)?;
        match temp.persist_noclobber(alias) {
            Ok(()) => Publication::Published,
            Err(err) if err.error.kind() == ErrorKind::AlreadyExists => Publication::Existing,
            Err(err) if alias.symlink_metadata().is_ok() => {
                drop(err.path);
                Publication::Existing
            }
            Err(err) => return Err(format!("publish {}: {}", alias.display(), err.error)),
        }
    };
    require_equal(canonical, alias)?;
    Ok(outcome)
}

/// A complete copy of `canonical` in `dir`, with its handle closed.
fn copy_to_temp(canonical: &Path, dir: &Path) -> Result<tempfile::TempPath, String> {
    let fail =
        |err: std::io::Error| format!("copy {} to {}: {err}", canonical.display(), dir.display());
    let mut source = File::open(canonical).map_err(fail)?;
    let mut temp = tempfile::Builder::new()
        .prefix(".alias-")
        .tempfile_in(dir)
        .map_err(fail)?;
    std::io::copy(&mut source, temp.as_file_mut()).map_err(fail)?;
    let permissions = source.metadata().map_err(fail)?.permissions();
    temp.as_file().set_permissions(permissions).map_err(fail)?;
    temp.as_file().sync_all().map_err(fail)?;
    Ok(temp.into_temp_path())
}

/// Requires a regular file at `alias` with the bytes of `canonical`.
fn require_equal(canonical: &Path, alias: &Path) -> Result<(), String> {
    let meta = alias
        .symlink_metadata()
        .map_err(|err| format!("{}: {err}", alias.display()))?;
    if !meta.is_file() {
        return Err(format!("{} is not a regular file", alias.display()));
    }
    let expected =
        std::fs::read(canonical).map_err(|err| format!("{}: {err}", canonical.display()))?;
    let actual = std::fs::read(alias).map_err(|err| format!("{}: {err}", alias.display()))?;
    if expected == actual {
        Ok(())
    } else {
        Err(format!(
            "{} differs from {}; it is never replaced",
            alias.display(),
            canonical.display()
        ))
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test assertions; a failed expectation fails the test"
)]
mod tests {
    use super::*;
    use std::sync::Barrier;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    const CONTEND_CANONICAL: &str = "SERVER_ALIAS_CONTEND_CANONICAL";
    const CONTEND_ALIAS: &str = "SERVER_ALIAS_CONTEND_ALIAS";
    const CONTEND_GO: &str = "SERVER_ALIAS_CONTEND_GO";

    /// A fixture directory below the run's `target/tmp`.
    fn fixture() -> tempfile::TempDir {
        let exe = std::env::current_exe().unwrap();
        let root = bin_dir_of(&exe).unwrap().join("..").join("tmp");
        std::fs::create_dir_all(&root).unwrap();
        tempfile::Builder::new()
            .prefix("server-binary-")
            .tempdir_in(root)
            .unwrap()
    }

    /// A canonical file with `bytes` in `<fixture>/bin`.
    fn canonical_in(fixture: &Path, bytes: &[u8]) -> PathBuf {
        let bin = fixture.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let path = bin.join(canonical_name());
        std::fs::write(&path, bytes).unwrap();
        path
    }

    #[test]
    fn missing_binary_names_the_command() {
        let fixture = fixture();
        let reason = locate_in(fixture.path()).unwrap_err();
        let expected = fixture.path().join(canonical_name());
        assert!(
            reason.contains(&format!("not built at {}", expected.display())),
            "{reason}"
        );
        assert!(
            reason.contains(
                "run cargo test -p stellar-agent-cli -p stellar-agent-mcp --no-run with this run's --target and feature flags"
            ),
            "{reason}"
        );
    }

    #[test]
    fn both_cargo_layouts_name_the_bin_dir() {
        let bin = Path::new("target")
            .join("x86_64-unknown-linux-gnu")
            .join("debug");
        assert_eq!(bin_dir_of(&bin.join("deps").join("mcp-0a")).unwrap(), bin);
        let nested = bin
            .join("build")
            .join("stellar-agent-mcp")
            .join("0a")
            .join("out")
            .join("mcp-0a");
        assert_eq!(bin_dir_of(&nested).unwrap(), bin);
        let reason = bin_dir_of(&bin.join("other").join("mcp-0a")).unwrap_err();
        assert!(reason.contains("no known Cargo layout"), "{reason}");
    }

    #[test]
    fn a_present_binary_is_located() {
        let fixture = fixture();
        let canonical = canonical_in(fixture.path(), b"canonical");
        assert_eq!(locate_in(&fixture.path().join("bin")).unwrap(), canonical);
    }

    /// A script that prints a version and the marker for `state`.
    #[cfg(unix)]
    fn version_script(fixture: &Path, state: &str, status: i32) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        let marker = format!("{}{}{state}", "STELLAR_AGENT_BUILD_", "MAINNET_WRITE=");
        let path = canonical_in(
            fixture,
            format!("#!/bin/sh\nprintf 'stellar-agent 0.0.0\\n{marker}\\n'\nexit {status}\n")
                .as_bytes(),
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        wait_until_executable(&path);
        path
    }

    /// Waits until `path` can be executed. A child that another test thread
    /// forks while this file is open for writing holds a writable handle
    /// until it execs, and Linux refuses to run the file meanwhile.
    #[cfg(unix)]
    fn wait_until_executable(path: &Path) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match Command::new(path).arg("--version").output() {
                Err(err) if err.kind() == ErrorKind::ExecutableFileBusy => {
                    assert!(Instant::now() < deadline, "{} stays busy", path.display());
                    std::thread::sleep(Duration::from_millis(5));
                }
                _ => return,
            }
        }
    }

    /// The marker state of this test build.
    #[cfg(unix)]
    fn build_state() -> &'static str {
        if cfg!(feature = "mainnet-write") {
            "on"
        } else {
            "off"
        }
    }

    #[cfg(unix)]
    #[test]
    fn resolve_publishes_a_fresh_alias() {
        let fixture = fixture();
        let canonical = version_script(fixture.path(), build_state(), 0);
        let alias = alias_path(&canonical).unwrap();
        assert!(alias.symlink_metadata().is_err(), "the alias starts absent");
        assert_eq!(resolve(&fixture.path().join("bin")).unwrap(), alias);
        assert!(alias.symlink_metadata().unwrap().is_file());
        assert_eq!(
            std::fs::read(&alias).unwrap(),
            std::fs::read(&canonical).unwrap()
        );
    }

    #[cfg(unix)]
    #[test]
    fn resolve_refuses_the_other_marker_before_publication() {
        let fixture = fixture();
        let other = if build_state() == "on" { "off" } else { "on" };
        let canonical = version_script(fixture.path(), other, 0);
        let alias = alias_path(&canonical).unwrap();
        let reason = resolve(&fixture.path().join("bin")).unwrap_err();
        assert!(reason.contains("this test build expects"), "{reason}");
        assert!(
            alias.symlink_metadata().is_err(),
            "a refused build publishes no alias"
        );
    }

    #[cfg(unix)]
    #[test]
    fn resolve_refuses_an_unequal_existing_alias() {
        let fixture = fixture();
        let canonical = version_script(fixture.path(), build_state(), 0);
        let alias = alias_path(&canonical).unwrap();
        std::fs::create_dir_all(alias.parent().unwrap()).unwrap();
        std::fs::write(&alias, b"stale alias").unwrap();
        let reason = resolve(&fixture.path().join("bin")).unwrap_err();
        assert!(reason.contains("never replaced"), "{reason}");
        assert_eq!(std::fs::read(&alias).unwrap(), b"stale alias");
    }

    #[cfg(unix)]
    #[test]
    fn the_marker_must_match_the_test_build() {
        let fixture = fixture();
        let on = version_script(fixture.path(), "on", 0);
        verify_marker(&on, true).unwrap();
        let reason = verify_marker(&on, false).unwrap_err();
        assert!(reason.contains("MAINNET_WRITE=off"), "{reason}");
        let off = version_script(fixture.path(), "off", 0);
        verify_marker(&off, false).unwrap();
        let reason = verify_marker(&off, true).unwrap_err();
        assert!(reason.contains("MAINNET_WRITE=on"), "{reason}");
    }

    #[cfg(unix)]
    #[test]
    fn a_failed_version_run_is_refused() {
        let fixture = fixture();
        let failing = version_script(fixture.path(), "on", 3);
        let reason = verify_marker(&failing, true).unwrap_err();
        assert!(reason.contains("--version exited"), "{reason}");
    }

    #[test]
    fn the_alias_is_keyed_below_the_tmp_directory() {
        let fixture = fixture();
        let canonical = canonical_in(fixture.path(), b"twelve bytes");
        let alias = alias_path(&canonical).unwrap();
        assert_eq!(
            alias.file_name().unwrap().to_str(),
            Some(alias_name().as_str())
        );
        let dir = alias.parent().unwrap();
        assert!(
            dir.file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("server-alias-12-"),
            "{}",
            dir.display()
        );
        assert_eq!(
            dir.parent().unwrap(),
            fixture.path().join("bin").join("..").join("tmp")
        );
    }

    #[test]
    fn a_published_alias_is_an_equal_copy() {
        let fixture = fixture();
        let canonical = canonical_in(fixture.path(), b"canonical bytes");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&canonical, std::fs::Permissions::from_mode(0o751)).unwrap();
        }
        let alias = alias_path(&canonical).unwrap();
        assert_eq!(publish(&canonical, &alias).unwrap(), Publication::Published);
        assert_eq!(std::fs::read(&alias).unwrap(), b"canonical bytes");
        let meta = alias.symlink_metadata().unwrap();
        assert!(meta.is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
            assert_eq!(meta.permissions().mode() & 0o7777, 0o751);
            assert_eq!(meta.nlink(), 1);
        }
    }

    #[test]
    fn eight_threads_share_one_alias() {
        let fixture = fixture();
        let canonical = canonical_in(fixture.path(), b"shared canonical");
        let cache = AliasCache::new();
        let resolutions = AtomicUsize::new(0);
        let barrier = Barrier::new(8);
        let paths: Vec<PathBuf> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        barrier.wait();
                        cache
                            .get_with(|| {
                                resolutions.fetch_add(1, Ordering::SeqCst);
                                let alias = alias_path(&canonical)?;
                                publish(&canonical, &alias)?;
                                Ok(alias)
                            })
                            .clone()
                            .unwrap()
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect()
        });
        assert_eq!(resolutions.load(Ordering::SeqCst), 1);
        assert!(paths.iter().all(|path| *path == paths[0]), "{paths:?}");
        assert_eq!(std::fs::read(&paths[0]).unwrap(), b"shared canonical");
    }

    #[test]
    fn an_equal_existing_alias_is_reused() {
        let fixture = fixture();
        let canonical = canonical_in(fixture.path(), b"canonical");
        let alias = alias_path(&canonical).unwrap();
        std::fs::create_dir_all(alias.parent().unwrap()).unwrap();
        std::fs::write(&alias, b"canonical").unwrap();
        let before = alias.symlink_metadata().unwrap().modified().unwrap();
        assert_eq!(publish(&canonical, &alias).unwrap(), Publication::Existing);
        assert_eq!(
            alias.symlink_metadata().unwrap().modified().unwrap(),
            before
        );
    }

    #[test]
    fn an_unequal_existing_alias_is_refused_unchanged() {
        let fixture = fixture();
        let canonical = canonical_in(fixture.path(), b"canonical");
        let alias = alias_path(&canonical).unwrap();
        std::fs::create_dir_all(alias.parent().unwrap()).unwrap();
        std::fs::write(&alias, b"stale alias").unwrap();
        let reason = publish(&canonical, &alias).unwrap_err();
        assert!(reason.contains("never replaced"), "{reason}");
        assert_eq!(std::fs::read(&alias).unwrap(), b"stale alias");
    }

    /// The test path of [`contender`] for a `--exact` filter.
    fn contender_name() -> String {
        let module = module_path!();
        let module = module.split_once("::").map_or(module, |(_, rest)| rest);
        format!("{module}::contender")
    }

    #[test]
    fn independent_processes_publish_one_alias() {
        const CONTENDERS: usize = 4;
        let fixture = fixture();
        let canonical = canonical_in(fixture.path(), b"contended canonical");
        let alias = alias_path(&canonical).unwrap();
        let go = fixture.path().join("go");
        let exe = std::env::current_exe().unwrap();
        let children: Vec<_> = (0..CONTENDERS)
            .map(|_| {
                Command::new(&exe)
                    .args(["--exact", &contender_name(), "--ignored", "--nocapture"])
                    .args(["--test-threads", "1"])
                    .env(CONTEND_CANONICAL, &canonical)
                    .env(CONTEND_ALIAS, &alias)
                    .env(CONTEND_GO, &go)
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                    .unwrap()
            })
            .collect();
        std::fs::write(&go, b"").unwrap();
        let outputs: Vec<String> = children
            .into_iter()
            .map(|child| {
                let output = child.wait_with_output().unwrap();
                let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
                assert!(
                    output.status.success(),
                    "{stdout}\n{}",
                    String::from_utf8_lossy(&output.stderr)
                );
                stdout
            })
            .collect();
        let count = |word: &str| {
            outputs
                .iter()
                .filter(|stdout| stdout.contains(&format!("contender: {word}\n")))
                .count()
        };
        assert_eq!(count("Published"), 1, "{outputs:?}");
        assert_eq!(count("Existing"), CONTENDERS - 1, "{outputs:?}");
        assert_eq!(std::fs::read(&alias).unwrap(), b"contended canonical");
    }

    /// One contender of [`independent_processes_publish_one_alias`]. It waits
    /// for the start file, publishes, and prints its outcome.
    #[test]
    #[ignore = "a child process of independent_processes_publish_one_alias"]
    #[allow(
        clippy::print_stdout,
        reason = "the parent test reads the outcome from this child's standard output"
    )]
    fn contender() {
        let (Some(canonical), Some(alias), Some(go)) = (
            std::env::var_os(CONTEND_CANONICAL),
            std::env::var_os(CONTEND_ALIAS),
            std::env::var_os(CONTEND_GO),
        ) else {
            return;
        };
        let deadline = Instant::now() + Duration::from_secs(30);
        while !Path::new(&go).exists() {
            assert!(Instant::now() < deadline, "the start file never appeared");
            std::thread::sleep(Duration::from_millis(1));
        }
        let outcome = publish(Path::new(&canonical), Path::new(&alias)).unwrap();
        println!("contender: {outcome:?}");
    }

    #[test]
    fn the_server_command_targets_the_alias() {
        let command = server_command();
        let program = Path::new(command.get_program());
        assert_eq!(
            program.file_name().unwrap().to_str(),
            Some(alias_name().as_str())
        );
        // `<bin dir>/../tmp/<alias dir>/<alias>`: four components up.
        let canonical = program.ancestors().nth(4).unwrap().join(canonical_name());
        assert_eq!(
            std::fs::read(program).unwrap(),
            std::fs::read(canonical).unwrap()
        );
        let home = command
            .get_envs()
            .find(|(name, _)| *name == "STELLAR_AGENT_HOME")
            .and_then(|(_, value)| value)
            .map(PathBuf::from)
            .unwrap();
        assert!(home.is_dir(), "{}", home.display());
        assert_eq!(home.parent(), program.parent().and_then(Path::parent));
    }
}
