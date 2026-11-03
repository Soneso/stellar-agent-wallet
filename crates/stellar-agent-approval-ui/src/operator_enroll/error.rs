//! Start/await/shutdown error types for the interactive operator-enrollment
//! server.

use std::net::SocketAddr;

use stellar_agent_loopback_http::PairBindError;

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

    /// The server could not hold both `127.0.0.1` and `[::1]` on its port.
    /// The enrollment page runs at `http://localhost:<port>`, so the ceremony
    /// does not start with one family.
    ///
    /// Display contains structured refusal details, never OS detail.
    #[error("operator-enroll server cannot hold both loopback addresses: {0}")]
    LoopbackPair(PairBindError),
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
