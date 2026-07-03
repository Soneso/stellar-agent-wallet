//! Error types for the WebAuthn bridge lifecycle.
//!
//! Provides [`BridgeStartError`] (returned by [`crate::start_bridge_register_only`] when the
//! listener cannot be created) and [`BridgeShutdownError`] (returned by
//! [`crate::BridgeHandle::shutdown`] when the server task does not stop
//! cleanly).

// ─────────────────────────────────────────────────────────────────────────────
// BridgeStartError
// ─────────────────────────────────────────────────────────────────────────────

/// Error returned by [`crate::start_bridge_register_only`].
///
/// # Variants
///
/// - [`BridgeStartError::NonLoopbackBind`] — the caller supplied a non-loopback
///   address.  The bridge only accepts `127.0.0.1` (IPv4 loopback) or `::1`
///   (IPv6 loopback) as a runtime defence.
/// - [`BridgeStartError::Bind`] — the OS rejected the `TcpListener::bind`
///   call.
///
/// `#[non_exhaustive]`: future failure modes (TLS bind, vendor-asset load,
/// etc.) may be added, and existing match-arm callers must continue to compile
/// under those additions.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum BridgeStartError {
    /// The supplied `bind_addr` is not a loopback address.
    ///
    /// The bridge enforces loopback-only at runtime as a defence-in-depth
    /// measure.
    #[error("non-loopback bind address rejected: {addr}")]
    NonLoopbackBind {
        /// The rejected address.
        addr: std::net::SocketAddr,
    },

    /// The OS rejected the `TcpListener::bind(bind_addr)` call.
    #[error("tcp bind failed: {source}")]
    Bind {
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// BridgeShutdownError
// ─────────────────────────────────────────────────────────────────────────────

/// Error returned by [`crate::BridgeHandle::shutdown`].
///
/// `#[non_exhaustive]`: future shutdown paths (e.g. an in-flight-request drain
/// timeout) may add new variants, and existing match-arm callers must continue
/// to compile.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum BridgeShutdownError {
    /// The server task did not stop within the 5-second shutdown deadline.
    #[error("server task did not stop within shutdown deadline")]
    Timeout,

    /// The server task's join handle returned an error (the task panicked).
    #[error("server task panicked: {detail}")]
    JoinFailed {
        /// Diagnostic detail from the join failure.
        detail: String,
    },
}
