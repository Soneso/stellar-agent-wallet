//! FIFO fixtures for the audit-log tests.
//!
//! A FIFO at a path the log reads must never stall a reader, so the tests
//! plant one. They live here rather than beside the tests that use them
//! because creating a FIFO runs `mkfifo`, and the writer module stays free of
//! process spawning.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only"
)]

use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;

/// Creates a FIFO at `path`.
pub(super) fn make_fifo(path: &Path) {
    let status = std::process::Command::new("mkfifo")
        .arg(path)
        .status()
        .unwrap();
    assert!(
        status.success(),
        "mkfifo {} failed: {status}",
        path.display()
    );
}

/// Opens the FIFO at `path` for writing without waiting and closes it again,
/// which releases a reader blocked opening or reading it.
///
/// With no reader the nonblocking open fails with `ENXIO`, which is ignored:
/// there is nothing to release. The call never blocks.
pub(super) fn release_fifo(path: &Path) {
    match OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
    {
        Ok(writer) => drop(writer),
        Err(e) if e.raw_os_error() == Some(libc::ENXIO) => {}
        Err(e) => panic!("releasing the FIFO at {} failed: {e}", path.display()),
    }
}
