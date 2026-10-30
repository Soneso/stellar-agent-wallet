//! Start/shutdown error types for the approval-inbox server.

use std::net::SocketAddr;

/// Error returned by [`crate::start_serve`] when the server cannot be started.
///
/// `#[non_exhaustive]`: future bind-time validation may add variants without a
/// breaking change.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum ServeStartError {
    /// A mainnet listener refuses to start: its signed approval policy, its
    /// pending entry or its pending store is not as the command presents it.
    /// Display is the fixed message of the refusal's approval code.
    #[error("{}", .0.failure())]
    Presence(PresenceStartRefusal),
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

impl ServeStartError {
    /// The approval failure a mainnet presence refusal reports, or `None`
    /// for a bind refusal.
    #[must_use]
    pub fn presence_failure(&self) -> Option<stellar_agent_core::ApprovalFailure> {
        match self {
            Self::Presence(refusal) => Some(refusal.failure()),
            _ => None,
        }
    }
}

/// Why a mainnet listener refuses to start, by the approval code it reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PresenceStartRefusal {
    /// The current owner-signed approval policy cannot be verified, or names
    /// another profile or network: `approval.presence_policy_unavailable`.
    PolicyUnavailable,
    /// The stored pending entry differs from the one the command presents:
    /// `approval.presence_changed`.
    Changed,
    /// The pending store or the process identity cannot be read:
    /// `approval.presence_unavailable`.
    Unavailable,
}

impl PresenceStartRefusal {
    /// The approval failure with this refusal's stable code and fixed
    /// message.
    #[must_use]
    pub fn failure(self) -> stellar_agent_core::ApprovalFailure {
        use stellar_agent_core::ApprovalFailure as F;
        match self {
            Self::PolicyUnavailable => F::PresencePolicyUnavailable,
            Self::Changed => F::PresenceChanged,
            Self::Unavailable => F::PresenceUnavailable,
        }
    }
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
