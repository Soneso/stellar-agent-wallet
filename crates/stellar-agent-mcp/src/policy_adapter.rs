//! Re-exports [`stellar_agent_network::policy_view::AccountViewAdapter`].
//!
//! # Why this is a re-export, not the definition
//!
//! `AccountView` is defined in `stellar-agent-network`, which already
//! depends on `stellar-agent-core` (where `AccountReservesView` /
//! `AccountIdentityView` are defined) — implementing those traits for
//! `AccountView` from within `stellar-agent-network` needs no new dependency
//! edge and is orphan-rule-compliant. `stellar-agent-cli` also depends on
//! `stellar-agent-network` directly, so hosting the adapter there lets the
//! CLI's classic-verb commands (`pay`, `claim`, `accounts create`) populate
//! the same policy views their MCP twins do, without a CLI-to-MCP dependency
//! edge. This module keeps `stellar_agent_mcp::policy_adapter::AccountViewAdapter`
//! resolvable at its established path for existing internal call sites.

pub use stellar_agent_network::policy_view::AccountViewAdapter;
