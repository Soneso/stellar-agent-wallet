//! Shared counterparty validation façade for network-facing code.
//!
//! The canonical implementation lives in `stellar-agent-core` so the policy
//! loader and network stack cannot drift while preserving the crate dependency
//! direction (`network` depends on `core`, never the reverse).

pub use stellar_agent_core::counterparty::is_valid_ldh_home_domain;
