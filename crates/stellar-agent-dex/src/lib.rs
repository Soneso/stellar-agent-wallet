//! Soroswap DEX swap adapter for the Stellar agent wallet.
//!
//! # What this crate does
//!
//! Implements the `stellar-agent-defi` `DefiAdapter` trait for the Soroswap
//! ROUTER-DIRECT swap path, performing a real on-chain swap with absolute
//! `amount_out_min` (percent-string rejected).
//!
//! Key properties:
//!
//! - **Explicit slippage** — required absolute `amount_out_min: i128`
//!   (typed field, not `Option`); a free-form percent string is a structural
//!   pre-sign refusal.
//! - **Slippage re-verify** — on-chain `router_get_amounts_out`
//!   re-fetch immediately before signing; absent quote or below the absolute
//!   floor → refuse (fail-closed).  NOTE: this is a sandwich/front-run floor re-check
//!   (same `get_amounts_out` routine the swap uses), NOT an independent price
//!   oracle.
//! - **Token canonicalisation** — SEP-41/SAC canonicalisation; ambiguous
//!   inputs (bare code, non-canonicalising code+issuer) refused pre-sign.
//! - **Bounded deadline** — bounded Unix deadline, default now+300s; missing/
//!   zero/excessively-far refused; enforced on-chain by Soroswap router
//!   `ensure_deadline` (`soroswap-core contracts/router/src/lib.rs`).
//! - **Explicit path** — explicit `Vec<Address>` path in preview and
//!   signed call; never auto-routed.
//! - **Venue allowlist** — Soroswap is the only wired venue; a route
//!   through an un-allowlisted venue is refused.
//! - **Aggregator pin** — Soroswap router address + WASM hash pinned
//!   per network; ordered trust gate pin-verifies the router WASM FIRST.
//! - **Trade tool surface** — `trade` (signing) and `quote` (read-only)
//!   verbs in a `trade` namespace on both MCP and CLI.
//!
//! # Primary consumers
//!
//! - `stellar-agent-mcp` / `stellar-agent-cli` — dispatch the `trade` and
//!   `quote` verbs through the seam.
//!
//! # What this crate does NOT do
//!
//! - The Soroswap AGGREGATOR (multi-venue distribution) path is deferred;
//!   it needs an off-chain route-source and has no on-chain quote.
//! - Aquarius / Phoenix execution wiring is deferred; only the venue
//!   allowlist framework ships here.
//! - `CreatePassiveSellOffer` / classic-SDEX limit orders are out of scope.
//! - Oracle-sanity price-deviation checking is deferred; the
//!   deviation math needs a decimals-aware implementation and the oracle
//!   address is not yet plumbed through `DefiAdapterCtx`.
//! - The quote/preview/submit paths reuse the existing submit and simulate
//!   scaffolds; the multi-auth-entry guard builds its own read-only simulate
//!   envelope because it needs the auth entries the shared scaffold does not
//!   return.
//!
//! # Dependency direction
//!
//! `stellar-agent-dex → stellar-agent-defi` (adapter/preview/pins/dispatch/simulate),
//! `→ stellar-agent-network` (RPC, WASM-hash fetch),
//! `→ stellar-agent-smart-account` (submit path),
//! `→ stellar-agent-core` (ContextRuleId / observability redaction).
//!
//! NEVER `stellar-agent-dex → stellar-agent-blend` or
//! `stellar-agent-dex → stellar-agent-defindex`.
//!
//! # ABI provenance
//!
//! Soroswap router ABI bound from
//! `soroswap-core contracts/router/src/lib.rs`
//! (Apache-2.0 / MIT dual per `soroswap-core/LICENSE` + `package.json:license`;
//! interface-bind only, no source vendored).
//!
//! - `swap_exact_tokens_for_tokens(amount_in, amount_out_min, path, to, deadline)`
//!   — single `to.require_auth()`.
//! - `router_get_amounts_out(amount_in, path)`.
//!
//! # Submit path
//!
//! The swap is submitted ROUTER-DIRECT via `submit_signed_invoke` with
//! `.auth_rule_ids(&[ContextRuleId::new(0)])` — identical to the Blend adapter.
//! The router calls `to.require_auth()` in `soroswap-core contracts/router/src/lib.rs`,
//! and the SAC `transfer(from=wallet)` is a covered sub-invocation.
//! No custom smart-account auth machinery is needed.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod abi;
pub mod adapter;
pub mod auth_guard;
pub mod pins;
pub mod preview;
pub mod quote;
pub mod sac;
pub mod scval;
pub mod value;
pub mod venue;
