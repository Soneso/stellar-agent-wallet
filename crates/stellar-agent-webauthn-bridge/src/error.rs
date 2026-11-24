//! Error types for the WebAuthn bridge lifecycle.
//!
//! Provides [`BridgeStartError`] (returned by [`crate::start_bridge_register_only`] when the
//! listeners cannot be created) and [`BridgeShutdownError`] (returned by
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
/// - [`BridgeStartError::LoopbackPair`]: `127.0.0.1` and `[::1]` could not
///   both be held on the bridge's port.
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

    /// The bridge could not hold both `127.0.0.1` and `[::1]` on its port.
    /// The browser opens the bridge at `http://localhost:<port>`, so the
    /// bridge does not start with one family.
    ///
    /// Display contains structured refusal details, never OS detail.
    #[error("bridge cannot hold both loopback addresses: {0}")]
    LoopbackPair(stellar_agent_loopback_http::PairBindError),
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
    /// The listener tasks did not stop within the 5-second shutdown
    /// deadline; both are aborted.
    #[error("server task did not stop within shutdown deadline")]
    Timeout,

    /// A listener task panicked or ended with an I/O error.
    #[error("server task failed: {detail}")]
    JoinFailed {
        /// Diagnostic detail from the join failure.
        detail: String,
    },
}
