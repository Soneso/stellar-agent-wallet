//! SEP-10 counterparty-identity pre-payment gate for x402 Exact Stellar payments.
//!
//! # What this crate does
//!
//! Implements the **wallet-side pre-payment identity gate** for x402 v2 Exact
//! Stellar payments.  Before constructing a `PAYMENT-SIGNATURE` payload, the
//! wallet resolves the server's identity via SEP-10 Stellar Web Authentication
//! and returns a verified JWT Bearer token that accompanies the payment.
//!
//! # Primary consumer
//!
//! `stellar-agent-mcp` — the `stellar_x402_authenticated_payment` MCP tool
//! calls [`gate::resolve_and_verify_counterparty`] and then calls
//! `stellar_agent_x402::exact::create_payment`.
//!
//! # HTTP-layer JWT companion
//!
//! x402 has **no native identity wire field**.  `PaymentRequirements` =
//! `{ scheme, network, asset, amount, payTo, maxTimeoutSeconds, extra }` and
//! `ExactStellarPayloadV2 = { transaction }` — there is no identity slot.
//!
//! The SEP-10 identity is bound as an **HTTP-layer companion**:
//!
//! - `PAYMENT-SIGNATURE` header ← the x402 `PaymentPayload` (from `create_payment`)
//! - `Authorization: Bearer <jwt>` ← [`VerifiedCounterpartySession::jwt`]
//!
//! The Soroban transaction XDR / SAC auth-entry / payment memo is **NEVER
//! mutated** to carry the JWT.  The ephemeral SEP-10 key is UNFUNDED and is
//! NOT the payment's funding-account signer.
//!
//! # Non-goals
//!
//! - SEP-45 (C-account Soroban web auth) — out of scope for this crate.
//! - x402 payee / facilitator logic — this crate is payer-side only.
//! - Caching or session reuse — every call generates a fresh ephemeral key.
//! - On-chain submission — this crate produces a JWT; the payment payload is
//!   produced by `stellar_agent_x402::exact::create_payment`.
//!
//! # Sibling crates
//!
//! - `stellar_agent_x402` — x402 Exact Stellar payment construction.
//! - [`stellar_agent_sep10`] — SEP-10 challenge/response client + ephemeral flow.
//! - [`stellar_agent_network`] — `stellar.toml` fetch + `MinimalSep1` parser.

#![deny(unsafe_code)]

pub mod error;
pub mod gate;

pub use error::IdentityError;
pub use gate::{VerifiedCounterpartySession, resolve_and_verify_counterparty};

/// Test seam: drives the full gate against an explicit base URL.
///
/// Allows wiremock-based tests (plain HTTP on `127.0.0.1:PORT`) to exercise
/// every gate step including SEP-10 challenge/response, bypassing the
/// production LDH home-domain validator.  Only available under
/// `test-helpers` or `#[cfg(test)]`.
///
/// See [`gate::resolve_and_verify_counterparty_at`] for full documentation.
#[cfg(any(test, feature = "test-helpers"))]
pub use gate::resolve_and_verify_counterparty_at;
