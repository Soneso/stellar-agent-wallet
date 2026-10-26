//! Terminal requirements for interactive mainnet consent.
#![cfg_attr(not(test), expect(dead_code, reason = "wired by the mainnet verbs"))]

use std::io::IsTerminal as _;
use stellar_agent_core::error::{ValidationError, WalletError};

pub(crate) fn require_tty_for_mainnet() -> Result<(), WalletError> {
    #[cfg(test)]
    if let Some((stdin, stderr)) = tests::TEST_TTY.get() {
        return require_streams(stdin, stderr);
    }
    require_streams(
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
    }

    /// Restores the previous terminal state when dropped.
    #[cfg(feature = "mainnet-write")]
    pub(crate) struct TestTty(Option<(bool, bool)>);

    #[cfg(feature = "mainnet-write")]
    impl Drop for TestTty {
        fn drop(&mut self) {
            TEST_TTY.set(self.0);
        }
    }

    /// Reports `stdin` and `stderr` as the terminal state until the guard
    /// drops.
    #[cfg(feature = "mainnet-write")]
    pub(crate) fn test_tty(stdin: bool, stderr: bool) -> TestTty {
        TestTty(TEST_TTY.replace(Some((stdin, stderr))))
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
