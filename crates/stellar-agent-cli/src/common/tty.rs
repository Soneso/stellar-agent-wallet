//! Terminal requirements and the line reader for interactive operator
//! prompts: the confirmation codes of operator enrollment, approval
//! credential enrollment and passkey registration. Mainnet consent reads no
//! terminal.

use std::future::Future;
use std::io::{self, IsTerminal as _};

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

/// Reads one line from the process's stdin on a detached thread named
/// `thread_name`; `Ok(None)` at end of input.
///
/// A blocking read cannot be cancelled, so the thread is not joined: when
/// the caller stops waiting, the line it may read later goes nowhere.
pub(crate) fn read_line_from_terminal(
    thread_name: &'static str,
) -> impl Future<Output = io::Result<Option<String>>> {
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let spawned = std::thread::Builder::new()
        .name(thread_name.to_owned())
        .spawn(move || {
            let mut line = String::new();
            let result = match io::stdin().read_line(&mut line) {
                Ok(0) => Ok(None),
                Ok(_) => Ok(Some(line)),
                Err(error) => Err(error),
            };
            let _ = sender.send(result);
        });
    async move {
        spawned?;
        receiver
            .await
            .map_err(|_| io::Error::other("the terminal reader stopped"))?
    }
}

#[cfg(test)]
pub(crate) mod tests {
    #![allow(clippy::unwrap_used, reason = "test assertions")]
    use super::*;

    thread_local! {
        /// The terminal state of stdin and stderr that
        /// [`stdin_and_stderr_are_terminals`] reports in place of the real
        /// streams.
        pub(crate) static TEST_TTY: std::cell::Cell<Option<(bool, bool)>> =
            const { std::cell::Cell::new(None) };
        /// How often [`stdin_and_stderr_are_terminals`] answered from
        /// [`TEST_TTY`] on this thread.
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

    /// How often [`stdin_and_stderr_are_terminals`] answered from the
    /// reported terminal state on this thread.
    #[cfg(feature = "mainnet-write")]
    pub(crate) fn tty_checks_on_this_thread() -> u64 {
        TEST_TTY_CHECKS.get()
    }

    /// Every check under a reported terminal state is counted, and both
    /// streams must be terminals.
    #[test]
    fn each_reported_check_is_counted() {
        let previous = TEST_TTY.replace(Some((true, false)));
        let before = TEST_TTY_CHECKS.get();
        assert!(!stdin_and_stderr_are_terminals());
        TEST_TTY.set(Some((false, true)));
        assert!(!stdin_and_stderr_are_terminals());
        TEST_TTY.set(Some((true, true)));
        assert!(stdin_and_stderr_are_terminals());
        assert_eq!(TEST_TTY_CHECKS.get() - before, 3);
        TEST_TTY.set(previous);
    }
}
