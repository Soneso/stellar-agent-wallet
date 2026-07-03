//! Stablecoin substrate for the Stellar agent wallet.
//!
//! Provides issuer-account pins (USDC/EURC per network), a denomination-explicit
//! resolver (SEP-41 C-address | code+issuer | bare code via pin table), a USDT
//! hard-refusal rule, clawback flag disclosure types, and a typed trustline
//! preview surface.
//!
//! # Primary consumers
//!
//! The `trustline` verb in `stellar-agent-mcp` and `stellar-agent-cli`.
//! This crate provides only the substrate — no MCP tool or CLI verb is wired here.
//!
//! # Non-goals
//!
//! - No MCP tool registration.
//! - No CLI subcommand.
//! - No on-chain submission logic.
//! - No Soroban / smart-account paths (classic G-account trustlines only).
//!
//! # Sibling crates
//!
//! - `stellar-agent-network` — supplies `AccountView` (with `account_flags: Option<AccountFlagsView>`)
//!   and `ClassicOpBuilder` (with `change_trust` + `set_options_flags`).
//! - `stellar-agent-core` — supplies `ApprovalKind::TrustlineClawbackOptIn`
//!   and `decode_authoritative_args` for `stellar_trustline_commit`.

#![deny(missing_docs)]

pub mod deny;
pub mod flags;
pub mod pins;
pub mod preview;
pub mod resolve;
