//! CLI subcommand dispatch module.
//!
//! Each subcommand lives in its own submodule. The `Commands` enum is the
//! `clap` top-level subcommand union dispatched from `main.rs`.

pub mod accounts;
pub mod approve;
pub mod audit;
pub mod balances;
pub mod counterparty;
pub mod credentials;
pub mod fees;
pub mod friendbot;
pub(crate) mod policy_engine;
// Blend lending adapter — lend verb.
pub mod lend;
pub mod pay;
pub mod pool;
pub mod profile;
pub mod smart_account;
pub mod toolsets;
// DeFindex vault adapter — vault verb.
pub mod vault;
// Soroswap DEX swap adapter — trade verb.
pub mod trade;
// Shared value-action audit emission for value-moving CLI verbs.
pub(crate) mod value_audit;
// Stablecoin substrate — trustline verb.
pub mod trustline;
// Claimable-balance substrate — claim verb.
pub mod claim;
