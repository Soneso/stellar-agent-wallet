//! Marked directories for isolated wallet storage.

use std::path::Path;

/// Failure to prepare isolated fixture storage.
#[derive(Debug)]
pub enum SandboxError {
    /// The requested directory is outside the permitted fixture roots.
    OutsideAllowedRoot,
    /// The fixture directory or marker could not be prepared.
    Io(std::io::Error),
}

impl std::fmt::Display for SandboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OutsideAllowedRoot => f.write_str(
                "STELLAR_AGENT_TEST_STORAGE_ISOLATED: sandbox requires the temporary or workspace target directory",
            ),
            Self::Io(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for SandboxError {}

impl From<std::io::Error> for SandboxError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<SandboxError> for std::io::Error {
    fn from(error: SandboxError) -> Self {
        Self::other(error)
    }
}

// Resolve existing ancestors before creating anything, including links and `..`.
fn resolved_destination(path: &Path) -> std::io::Result<std::path::PathBuf> {
    match path.canonicalize() {
        Ok(path) => Ok(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = path.parent().ok_or(error)?;
            let resolved = resolved_destination(parent)?;
            Ok(resolved.join(path.file_name().ok_or_else(|| {
                std::io::Error::other("sandbox destination must name a directory")
            })?))
        }
        Err(error) => Err(error),
    }
}

/// The metadata file that identifies an isolated fixture directory.
pub const MARKER: &str = ".stellar-agent-test-sandbox";

/// The documented Linux wallet suffix, for assertions about displayed paths.
pub const LINUX_WALLET_SUFFIX: &str = include_str!("../docs/linux-wallet-suffix.txt");

/// The documented macOS wallet suffix, for assertions about displayed paths.
pub const MACOS_WALLET_SUFFIX: &str = include_str!("../docs/macos-wallet-suffix.txt");

/// The documented wallet directory component, for assertions about displayed paths.
pub const WALLET_DIRECTORY_COMPONENT: &str = include_str!("../docs/wallet-directory-component.txt");

/// Marks a fixture directory as isolated wallet storage.
///
/// # Errors
/// Returns [`SandboxError::OutsideAllowedRoot`] outside the system temporary
/// directory or workspace target directory, or an I/O error during setup.
/// A temporary root at the filesystem root or containing HOME is not permitted.
pub fn mark_sandbox(path: &Path) -> Result<(), SandboxError> {
    if !path.is_absolute() {
        return Err(SandboxError::OutsideAllowedRoot);
    }
    let destination = resolved_destination(path)?;
    let temporary = std::env::temp_dir().canonicalize()?;
    let home = std::env::var_os("HOME")
        .map(|home| resolved_destination(Path::new(&home)))
        .transpose()?;
    let temporary_allowed =
        temporary.parent().is_some() && home.is_none_or(|home| !home.starts_with(&temporary));
    let target = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .canonicalize()?;
    if !(temporary_allowed && destination.starts_with(temporary))
        && !destination.starts_with(target)
    {
        return Err(SandboxError::OutsideAllowedRoot);
    }
    let marker = destination.join(MARKER);
    if std::fs::symlink_metadata(&marker).is_ok_and(|meta| meta.file_type().is_symlink()) {
        return Err(SandboxError::OutsideAllowedRoot);
    }
    std::fs::create_dir_all(&destination)?;
    Ok(std::fs::write(marker, b"")?)
}

/// Refuses an executable without the storage isolation marker.
///
/// # Errors
/// Returns an I/O error when the executable is unreadable or lacks isolation.
pub fn require_isolated_executable(path: &Path) -> std::io::Result<()> {
    let bytes = std::fs::read(path)?;
    let marker = b"STELLAR_AGENT_TEST_STORAGE_ISOLATED";
    if bytes.windows(marker.len()).any(|window| window == marker) {
        Ok(())
    } else {
        Err(std::io::Error::other(
            "Build the child with test-helpers and stellar-agent-core/test-helpers before running acceptance.",
        ))
    }
}

/// A marked directory retained for the lifetime of its owner.
#[cfg(feature = "test-helpers")]
pub struct StateSandbox(tempfile::TempDir);

#[cfg(feature = "test-helpers")]
impl StateSandbox {
    /// Creates a marked directory below the workspace target directory.
    ///
    /// # Errors
    /// Returns an I/O error when the directory or marker cannot be created.
    pub fn new() -> std::io::Result<Self> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/tmp/test-sandboxes");
        std::fs::create_dir_all(&root)?;
        let dir = tempfile::tempdir_in(root.canonicalize()?)?;
        mark_sandbox(dir.path())?;
        Ok(Self(dir))
    }

    /// Returns the fixture directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        self.0.path()
    }
}

#[cfg(all(test, feature = "test-helpers"))]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "fixture assertions"
    )]
    use super::*;
    use crate::env_guard::StellarAgentHomeGuard;

    fn refuse_temporary_root_in_child(temporary: &Path, test: &str) {
        const DESTINATION: &str = "STELLAR_AGENT_TEST_SANDBOX_DESTINATION";
        if let Some(path) = std::env::var_os(DESTINATION) {
            let path = Path::new(&path);
            assert!(!path.exists());
            assert!(matches!(
                mark_sandbox(path),
                Err(SandboxError::OutsideAllowedRoot)
            ));
            assert!(!path.exists());
            return;
        }
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let fixture = tempfile::tempdir_in(workspace).unwrap();
        let home = tempfile::tempdir().unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test])
            .env("TMPDIR", temporary)
            .env("TMP", temporary)
            .env("TEMP", temporary)
            .env("HOME", home.path())
            .env(DESTINATION, fixture.path().join("wallet"))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    #[serial_test::serial]
    fn sandbox_refuses_a_filesystem_temporary_root_before_creating_it() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let root = workspace.ancestors().last().unwrap();
        refuse_temporary_root_in_child(
            root,
            "sandbox::tests::sandbox_refuses_a_filesystem_temporary_root_before_creating_it",
        );
    }

    #[test]
    #[serial_test::serial]
    fn sandbox_refuses_a_temporary_root_containing_home_before_creating_it() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        refuse_temporary_root_in_child(
            &workspace,
            "sandbox::tests::sandbox_refuses_a_temporary_root_containing_home_before_creating_it",
        );
    }

    #[test]
    #[serial_test::serial]
    fn sandbox_accepts_the_system_temporary_root() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("wallet");
        mark_sandbox(&path).unwrap();
        let _home = StellarAgentHomeGuard::new(&path);
        assert!(path.join(MARKER).is_file());
        assert_eq!(
            std::env::var_os("STELLAR_AGENT_HOME").unwrap(),
            path.canonicalize().unwrap()
        );
    }

    #[test]
    #[serial_test::serial]
    fn sandbox_accepts_the_workspace_target_root() {
        let target = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .canonicalize()
            .unwrap();
        let temporary = tempfile::tempdir_in(target).unwrap();
        // Distinguish the target allowance even when TMPDIR is below target.
        let system = tempfile::tempdir().unwrap();
        let _tmp = crate::env_guard::ScopedEnvVar::new("TMPDIR", Some(system.path().as_os_str()));
        mark_sandbox(temporary.path()).unwrap();
        let _home = StellarAgentHomeGuard::new(temporary.path());
        assert!(temporary.path().join(MARKER).is_file());
    }

    #[test]
    #[serial_test::serial]
    fn sandbox_refuses_every_other_root_before_creating_it() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let path = workspace.join("forbidden-sandbox-fixture");
        assert!(!path.exists());
        let error = mark_sandbox(&path).unwrap_err();
        assert!(matches!(error, SandboxError::OutsideAllowedRoot));
        assert!(
            error
                .to_string()
                .contains("STELLAR_AGENT_TEST_STORAGE_ISOLATED")
        );
        let panic = std::panic::catch_unwind(|| StellarAgentHomeGuard::new(&path))
            .err()
            .expect("home guard must refuse");
        let reason = panic
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| panic.downcast_ref::<&str>().copied())
            .unwrap();
        assert!(reason.contains("STELLAR_AGENT_TEST_STORAGE_ISOLATED"));
        assert!(!path.exists());
    }
}
