//! One policy file has one authoring lock across its read and replacement.

use std::{fs::OpenOptions, path::Path};
use stellar_agent_core::{
    file_lock::HeldFileLock,
    policy::{
        PolicyError,
        pin::{self, PinState},
        state_lock::{LOCK_ATTEMPTS, LOCK_RETRY_DELAY},
        v1::verified::read_pin_without_creating,
    },
    profile::schema::Profile,
};

type Failure = (&'static str, String);

pub(super) struct AuthoringGuard {
    _lock: HeldFileLock,
}

/// Holds the policy's sibling lock until the author returns.
pub(super) fn acquire(policy_path: &Path) -> Result<AuthoringGuard, Failure> {
    let mut path = policy_path.as_os_str().to_owned();
    path.push(".authoring.lock");
    let io_failure = |error: std::io::Error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            return (
                "sign_policy.policy_file_unreadable",
                format!("could not read the policy file --file names: {error}"),
            );
        }
        (
            "sign_policy.authoring_lock_io",
            "the policy authoring lock cannot be opened or acquired".into(),
        )
    };
    for attempt in 0..LOCK_ATTEMPTS {
        let mut options = OpenOptions::new();
        options.create(true).write(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let file = options.open(&path).map_err(io_failure)?;
        match HeldFileLock::try_lock(file) {
            Ok(lock) => return Ok(AuthoringGuard { _lock: lock }),
            Err(std::fs::TryLockError::Error(error)) => return Err(io_failure(error)),
            Err(std::fs::TryLockError::WouldBlock) => {
                if attempt + 1 < LOCK_ATTEMPTS {
                    std::thread::sleep(LOCK_RETRY_DELAY);
                }
            }
        }
    }
    Err((
        "sign_policy.authoring_lock_busy",
        "another author holds the policy authoring lock; retry when that author finishes".into(),
    ))
}

/// Reads a pin without allowing a missing lock file to hide its entry.
pub(super) fn read_pin_checked(
    name: &str,
    profile: &Profile,
    window_path: &Path,
) -> Result<PinState, Failure> {
    let state = read_pin_without_creating(window_path, profile)
        .map_err(|error| pin_read_failure(name, error))?;
    if matches!(state, PinState::Absent)
        && pin::entry_present(&profile.policy_window_state_key_id)
            .map_err(|error| pin_read_failure(name, PolicyError::from(error)))?
    {
        return Err((
            PolicyError::PinAbsent.wire_code(),
            missing_pin_lock_detail(name),
        ));
    }
    Ok(state)
}

/// The cause and recovery when a pin entry exists without its lock file.
pub(super) fn missing_pin_lock_detail(name: &str) -> String {
    format!(
        "the policy-state lock file of profile '{name}' is missing, so its policy pin \
         cannot be read; a command that builds the V1 policy engine recreates the lock \
         file, and this command can run after it; nothing was written"
    )
}

/// An unusable pin names its recovery; other failures keep their messages.
pub(super) fn pin_read_failure(name: &str, error: PolicyError) -> Failure {
    let code = error.wire_code();
    match error {
        PolicyError::PinUnusable { detail } => (
            code,
            format!(
                "the policy pin of profile '{name}' cannot be used ({detail}); nothing was \
                 written. Rerun this command once the keyring is reachable if it was \
                 unavailable. No command repairs a malformed pin in this release, since a \
                 replacement could lower its recorded sequence; create a profile under a new \
                 name."
            ),
        ),
        other => (code, other.to_string()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "test-only assertions")]
mod tests {
    use super::*;

    fn busy(path: &Path) -> Failure {
        acquire(path).err().unwrap()
    }

    #[test]
    fn guard_works_without_state_lock() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.toml");
        let _guard = acquire(&path).unwrap();
        assert!(dir.path().join("policy.toml.authoring.lock").exists());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn guard_busy_after_all_attempts() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.toml");
        let _guard = acquire(&path).unwrap();
        let start = std::time::Instant::now();
        assert_eq!(busy(&path).0, "sign_policy.authoring_lock_busy");
        assert!(start.elapsed() >= LOCK_RETRY_DELAY * (LOCK_ATTEMPTS - 1));
    }

    #[test]
    fn guard_lock_io_refuses() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("policy.toml.authoring.lock")).unwrap();
        assert_eq!(
            busy(&dir.path().join("policy.toml")).0,
            "sign_policy.authoring_lock_io"
        );
    }

    #[test]
    fn guard_open_does_not_truncate() {
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join("policy.toml.authoring.lock");
        std::fs::write(&lock, "marker").unwrap();
        let _guard = acquire(&dir.path().join("policy.toml")).unwrap();
        assert_eq!(std::fs::read_to_string(lock).unwrap(), "marker");
    }

    #[test]
    #[cfg(unix)]
    fn guard_lock_file_mode_is_0600() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let _guard = acquire(&dir.path().join("policy.toml")).unwrap();
        assert_eq!(
            std::fs::metadata(dir.path().join("policy.toml.authoring.lock"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}
