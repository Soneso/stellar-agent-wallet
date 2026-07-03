//! Start/shutdown error types for the approval-inbox server.

use std::net::SocketAddr;

/// Error returned by [`crate::start_serve`] when the server cannot be started.
///
/// `#[non_exhaustive]`: future bind-time validation may add variants without a
/// breaking change.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum ServeStartError {
    /// The requested bind address is not a loopback address.
    ///
    /// The approval-inbox server binds loopback-only as a defence-in-depth
    /// measure: the pending queue and approve/reject actions must never be
    /// reachable off-host.
    #[error("approval-inbox server refused non-loopback bind address: {addr}")]
    NonLoopbackBind {
        /// The rejected bind address.
        addr: SocketAddr,
    },

    /// Binding the TCP listener failed (port in use, permission, etc.).
    ///
    /// Display exposes only [`std::io::ErrorKind`] so any OS path embedded in
    /// the platform error string does not leak.
    #[error("approval-inbox server failed to bind: {kind:?}")]
    Bind {
        /// The I/O error kind, safe to display without OS detail.
        kind: std::io::ErrorKind,
        /// The original source error, retained for chaining, not shown in Display.
        #[source]
        source: std::io::Error,
    },
}

/// Error returned by [`crate::ServeHandle::shutdown`].
///
/// `#[non_exhaustive]`: future shutdown paths may add variants.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum ServeShutdownError {
    /// A spawned task did not stop within the shutdown deadline.
    #[error("approval-inbox server did not shut down within the deadline")]
    Timeout,

    /// A spawned task panicked before completing.
    #[error("approval-inbox server task failed to join: {detail}")]
    JoinFailed {
        /// Non-secret diagnostic detail derived from the join error.
        detail: String,
    },
}
