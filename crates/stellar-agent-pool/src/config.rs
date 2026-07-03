//! Pool configuration type re-exports.
//!
//! `PoolConfig` and `PoolChannelRecord` are defined in
//! `stellar-agent-core::profile::schema` so they are available to both the
//! profile loader (which embeds them in `Profile`) and this crate (which
//! builds and consumes them).  This module re-exports them for consumers of
//! `stellar-agent-pool` so they do not need to reach into `stellar-agent-core`
//! directly.

// Re-export from core so stellar-agent-pool consumers can import from here.
pub use stellar_agent_core::profile::schema::{PoolChannelRecord, PoolConfig};
