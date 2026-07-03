//! DeFindex vault evaluation criteria.
//!
//! # What this module provides
//!
//! - [`upgradable`] — the `vault_upgradable` criterion: refuses signing when
//!   the vault is marked upgradable:true.
//!
//! Each sub-module follows the same pattern as
//! `stellar-agent-defi::oracle_staleness`: a typed evaluation
//! function used by the `stellar-agent-mcp` / `stellar-agent-cli` dispatch
//! sites, not a `Criterion` trait object.

pub mod upgradable;
