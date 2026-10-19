//! Rust-native x402 Exact Stellar payment scheme — payer side.
//!
//! Constructs and signs x402 v2 `PAYMENT-SIGNATURE` payloads for the Exact
//! Stellar scheme via a multi-step validate → build → simulate → cross-check →
//! sign → re-simulate → finalize flow, wire-compatible with the published
//! `@x402/stellar` package.
//!
//! # Role
//!
//! This crate produces the signed x402 payment payload via
//! [`exact::create_payment`]. A host integration (for example an MCP `x402`
//! tool) delivers the payload over HTTP; the payee/facilitator settles it
//! on-chain. Every request of one payment goes to the client the host passes,
//! and the first is an endpoint identity check. When the payment's value
//! requires the cross-check witness, the host also passes a prepared oracle
//! client, which simulates the same unsigned transfer before anything is
//! signed; the crate builds no client of its own. The signed authorization first
//! leaves the wallet in the RPC re-simulation, and `create_payment` runs the
//! caller's transmit gate immediately before that request, so a host can
//! record the authorization durably or withhold it.
//!
//! [`exact::validate_requirements`] runs the local checks of a payment without
//! a request, so a host can refuse invalid requirements before it admits the
//! payment against a spending window.
//!
//! # Non-goals
//!
//! - **Payee / facilitator logic** — this crate is payer-only.
//! - **EVM / other chains** — only Stellar Exact scheme.
//! - **`upto` scheme** — only `exact` scheme.
//! - **HTTP retry loop** — the caller produces the signed payload; the host
//!   orchestrates the HTTP exchange.
//! - **x402 v3.x** — targets v2 wire format.
//!
//! # Sibling crates
//!
//! - [`stellar_agent_sep43`] — auth-entry signing (single call site).
//! - [`stellar_agent_network`] — Soroban RPC transport, account fetching.
//! - [`stellar_agent_core`] — profile/CAIP-2 passphrase resolution.

#![deny(missing_docs)]

pub mod constants;
pub mod error;
pub mod exact;
pub mod sac_transfer;
pub mod wire;

pub use error::X402Error;
