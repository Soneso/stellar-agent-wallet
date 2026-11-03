//! Process hardening that runs before the CLI starts its async runtime.
//!
//! On Linux [`harden_process`] marks the process non-dumpable with
//! `PR_SET_DUMPABLE 0` while it is still single-threaded. The kernel then
//! refuses a `ptrace` attach from any process without `CAP_SYS_PTRACE` and
//! gives the owner-only entries of `/proc/<pid>` (`environ`, `mem` and the
//! like) to root, so another process of the same user reads neither the
//! memory nor the environment of the CLI, and no core file of the process is
//! readable by that user. The flag covers the whole run, including the
//! presence wait of a mainnet ceremony and every seed an enrollment or owner
//! ceremony reads from the environment.
//!
//! The process keeps what it needs of its own `/proc` entries:
//! `/proc/self/exe` resolves for the process itself, and `/proc/<pid>` keeps
//! the effective user as its owner, which the approval identity reads.
//!
//! Only `PR_SET_DUMPABLE` is set. `PR_SET_NO_NEW_PRIVS` is inherited across
//! `execve`, and the CLI launches the system browser for its loopback
//! handoffs, whose sandbox helper may need the privileges that flag removes.
//!
//! The flag protects this process only. The shell that exported a variable,
//! and every other process it starts, keeps its own copy of the environment.
//! On macOS and Windows no flag is set and [`harden_process`] returns
//! `Ok(())`.
//!
//! [`guarded_start`] runs the hardening first and runs the command only when
//! it succeeded: a CLI that cannot make itself non-dumpable refuses to run.

use stellar_agent_core::envelope::Envelope;

/// The hardening syscall failed; the command does not run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    not(target_os = "linux"),
    allow(
        dead_code,
        reason = "constructed only by the Linux prctl path and the tests"
    )
)]
pub(crate) struct HardeningError {
    /// The `errno` the syscall reported, or `0` when the platform reported
    /// none.
    pub(crate) errno: i32,
}

/// Marks the process non-dumpable on Linux.
///
/// Call it before the async runtime starts any thread. On every other target
/// it does nothing and returns `Ok(())`.
///
/// # Errors
///
/// [`HardeningError`] with the reported `errno` when `prctl` fails.
#[cfg(target_os = "linux")]
pub(crate) fn harden_process() -> Result<(), HardeningError> {
    let disabled: libc::c_ulong = 0;
    let unused: libc::c_ulong = 0;
    // SAFETY: prctl(2) with PR_SET_DUMPABLE changes only the process's own
    // dumpable attribute in the kernel. The second argument is the new value
    // (0, non-dumpable); the remaining three are unused by this option and
    // passed as zero, as the kernel ABI requires. No pointer is passed, so no
    // memory is read or written through the arguments. The return value is
    // checked and a failure stops the command.
    #[allow(unsafe_code, reason = "raw prctl syscall; see the SAFETY comment")]
    let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, disabled, unused, unused, unused) };
    if rc == 0 {
        Ok(())
    } else {
        Err(HardeningError {
            errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
        })
    }
}

/// Marks the process non-dumpable on Linux; on this target there is no such
/// flag and the function returns `Ok(())`.
///
/// # Errors
///
/// None on this target.
#[cfg(not(target_os = "linux"))]
pub(crate) fn harden_process() -> Result<(), HardeningError> {
    Ok(())
}

/// Runs `harden` and then `start`, returning `start`'s exit code.
///
/// When `harden` fails, `start` never runs: one
/// `wallet.process_hardening_failed` error envelope goes to stdout, as a
/// parse failure's does, and the exit code is `1`.
pub(crate) fn guarded_start(
    harden: impl FnOnce() -> Result<(), HardeningError>,
    start: impl FnOnce() -> i32,
) -> i32 {
    match harden() {
        Ok(()) => start(),
        Err(HardeningError { errno }) => {
            crate::common::render::render_json(&Envelope::<()>::err_raw(
                "wallet.process_hardening_failed",
                format!(
                    "the process could not be made non-dumpable (errno {errno}); the command \
                     did not run"
                ),
            ));
            1
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only assertions"
    )]

    use std::cell::Cell;

    use super::*;

    /// A failed hardening renders the refusal, exits 1 and never starts the
    /// command.
    #[test]
    fn a_hardening_failure_stops_before_the_command() {
        crate::common::render::take_rendered_for_test();
        let started = Cell::new(false);

        let code = guarded_start(
            || Err(HardeningError { errno: 1 }),
            || {
                started.set(true);
                0
            },
        );

        assert_eq!(code, 1);
        assert!(!started.get(), "the command must not run");
        let rendered = crate::common::render::take_rendered_for_test();
        assert_eq!(rendered.len(), 1, "{rendered:?}");
        assert_eq!(
            rendered[0]["error"]["code"], "wallet.process_hardening_failed",
            "{rendered:?}"
        );
        assert_eq!(
            rendered[0]["error"]["message"],
            "the process could not be made non-dumpable (errno 1); the command did not run"
        );
    }

    /// A successful hardening runs the command once and returns its exit
    /// code unchanged, rendering nothing of its own.
    #[test]
    fn a_successful_hardening_runs_the_command() {
        crate::common::render::take_rendered_for_test();
        let starts = Cell::new(0_u32);

        let code = guarded_start(
            || Ok(()),
            || {
                starts.set(starts.get() + 1);
                7
            },
        );

        assert_eq!(code, 7);
        assert_eq!(starts.get(), 1);
        assert!(crate::common::render::take_rendered_for_test().is_empty());
    }

    /// The variable that makes the test binary run the hardening in the
    /// child process instead of spawning one.
    #[cfg(target_os = "linux")]
    const CHILD_SWITCH: &str = "STELLAR_AGENT_HARDENING_TEST_CHILD";

    /// [`harden_process`] leaves the process non-dumpable, with its own
    /// executable path and its approval identity unchanged. The hardening
    /// runs in a child process of the test binary, so the test runner
    /// itself stays dumpable.
    #[cfg(target_os = "linux")]
    #[test]
    fn harden_process_makes_the_test_process_non_dumpable() {
        const NAME: &str =
            "process_hardening::tests::harden_process_makes_the_test_process_non_dumpable";
        if std::env::var_os(CHILD_SWITCH).is_some() {
            let uid = stellar_agent_core::approval::process_uid_for_attestation().unwrap();
            let exe = std::env::current_exe().unwrap();

            harden_process().expect("prctl must succeed");

            // SAFETY: prctl(2) with PR_GET_DUMPABLE reads the process's own
            // dumpable attribute; it takes no pointer argument.
            #[allow(unsafe_code, reason = "raw prctl syscall; see the SAFETY comment")]
            let dumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
            assert_eq!(dumpable, 0, "the process must be non-dumpable");
            assert_eq!(std::env::current_exe().unwrap(), exe);
            assert_eq!(
                stellar_agent_core::approval::process_uid_for_attestation().unwrap(),
                uid,
                "the approval identity must not change"
            );
            return;
        }

        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", NAME, "--nocapture", "--test-threads=1"])
            .env(CHILD_SWITCH, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "child failed:\n{stdout}\n{stderr}");
        assert!(
            stdout.contains("test result: ok. 1 passed"),
            "the child must run exactly this test:\n{stdout}"
        );
    }
}
