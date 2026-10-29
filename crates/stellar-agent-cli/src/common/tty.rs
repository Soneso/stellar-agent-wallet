//! Terminal requirements for interactive operator prompts: mainnet consent
//! and the operator-enrollment confirmation code.

use std::io::IsTerminal as _;
use stellar_agent_core::error::{ValidationError, WalletError};

pub(crate) fn require_tty_for_mainnet() -> Result<(), WalletError> {
    let (stdin, stderr) = terminal_streams();
    require_streams(stdin, stderr)
}

/// Whether stdin and stderr are both terminals, the condition every
/// interactive operator prompt needs.
pub(crate) fn stdin_and_stderr_are_terminals() -> bool {
    let (stdin, stderr) = terminal_streams();
    stdin && stderr
}

/// Whether stdin and stderr are terminals, as the process sees them or as a
/// test reports them.
fn terminal_streams() -> (bool, bool) {
    #[cfg(test)]
    if let Some(streams) = tests::TEST_TTY.get() {
        tests::TEST_TTY_CHECKS.set(tests::TEST_TTY_CHECKS.get() + 1);
        return streams;
    }
    (
        std::io::stdin().is_terminal(),
        std::io::stderr().is_terminal(),
    )
}

fn require_streams(stdin: bool, stderr: bool) -> Result<(), WalletError> {
    if !stdin || !stderr {
        return Err(ValidationError::ConfirmTtyRequired.into());
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    #![allow(clippy::unwrap_used, reason = "test assertions")]
    use super::*;

    thread_local! {
        /// The terminal state of stdin and stderr that
        /// [`require_tty_for_mainnet`] reports in place of the real streams.
        pub(crate) static TEST_TTY: std::cell::Cell<Option<(bool, bool)>> =
            const { std::cell::Cell::new(None) };
        /// How often [`require_tty_for_mainnet`] answered from [`TEST_TTY`] on
        /// this thread.
        pub(crate) static TEST_TTY_CHECKS: std::cell::Cell<u64> =
            const { std::cell::Cell::new(0) };
    }

    /// Restores the previous terminal state when dropped.
    pub(crate) struct TestTty(Option<(bool, bool)>);

    impl Drop for TestTty {
        fn drop(&mut self) {
            TEST_TTY.set(self.0);
        }
    }

    /// Reports `stdin` and `stderr` as the terminal state until the guard
    /// drops.
    pub(crate) fn test_tty(stdin: bool, stderr: bool) -> TestTty {
        TestTty(TEST_TTY.replace(Some((stdin, stderr))))
    }

    /// How often [`require_tty_for_mainnet`] answered from the reported
    /// terminal state on this thread.
    #[cfg(feature = "mainnet-write")]
    pub(crate) fn tty_checks_on_this_thread() -> u64 {
        TEST_TTY_CHECKS.get()
    }

    /// Every check under a reported terminal state is counted, whether it
    /// passes or refuses.
    #[test]
    fn each_reported_check_is_counted() {
        let previous = TEST_TTY.replace(Some((true, false)));
        let before = TEST_TTY_CHECKS.get();
        assert_eq!(
            require_tty_for_mainnet().unwrap_err().code(),
            "confirm.tty_required"
        );
        TEST_TTY.set(Some((true, true)));
        require_tty_for_mainnet().unwrap();
        assert_eq!(TEST_TTY_CHECKS.get() - before, 2);
        TEST_TTY.set(previous);
    }

    #[test]
    fn confirm_refuses_non_tty_stdin() {
        assert_eq!(
            require_streams(false, true).unwrap_err().code(),
            "confirm.tty_required"
        );
    }
    #[test]
    fn confirm_refuses_non_tty_stderr() {
        assert_eq!(
            require_streams(true, false).unwrap_err().code(),
            "confirm.tty_required"
        );
    }
}
