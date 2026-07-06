//! Start/await/shutdown error types for the interactive operator-enrollment
//! server.

use std::net::SocketAddr;

/// Error returned by [`super::start_operator_enroll_server`] when the server
/// cannot be started.
///
/// `#[non_exhaustive]`: future bind-time validation may add variants without
/// a breaking change.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum OperatorEnrollStartError {
    /// The requested bind address is not a loopback address.
    ///
    /// A WebAuthn credential created against this server is bound to the
    /// hard-coded rp-id `"localhost"` at creation time — only a loopback
    /// origin can claim it. Binding non-loopback would also expose the
    /// one-shot enrollment ceremony off-host.
    #[error("operator-enroll server refused non-loopback bind address: {addr}")]
    NonLoopbackBind {
        /// The rejected bind address.
        addr: SocketAddr,
    },

    /// Binding the TCP listener failed (port in use, permission, etc.).
    ///
    /// Display exposes only [`std::io::ErrorKind`] so any OS path embedded in
    /// the platform error string does not leak.
    #[error("operator-enroll server failed to bind: {kind:?}")]
    Bind {
        /// The I/O error kind, safe to display without OS detail.
        kind: std::io::ErrorKind,
        /// The original source error, retained for chaining, not shown in Display.
        #[source]
        source: std::io::Error,
    },
}

/// Error returned by [`super::OperatorEnrollHandle::await_completion`].
///
/// `#[non_exhaustive]`: future await-path refinements may add variants.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum OperatorEnrollAwaitError {
    /// `await_completion` was already called once on this handle.
    ///
    /// The completion signal is single-use by construction (a
    /// [`tokio::sync::oneshot::Receiver`] can only be awaited to conclusion
    /// once); a second call has nothing left to wait on.
    #[error("operator-enroll completion was already awaited on this handle")]
    AlreadyAwaited,

    /// The server task exited (or was dropped) without ever completing an
    /// enrollment, so the completion sender was dropped without sending.
    #[error("operator-enroll server exited before an enrollment completed")]
    SenderDropped,

    /// No enrollment completed within the caller-supplied timeout.
    #[error("timed out waiting for the operator-enrollment ceremony to complete")]
    Timeout,
}

/// Error returned by [`super::OperatorEnrollHandle::shutdown`].
///
/// `#[non_exhaustive]`: future shutdown paths may add variants.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum OperatorEnrollShutdownError {
    /// The server task did not stop within the shutdown deadline.
    #[error("operator-enroll server did not shut down within the deadline")]
    Timeout,

    /// The server task panicked before completing.
    #[error("operator-enroll server task failed to join: {detail}")]
    JoinFailed {
        /// Non-secret diagnostic detail derived from the join error.
        detail: String,
    },
}
