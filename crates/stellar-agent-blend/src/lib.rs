//! Blend Protocol lending adapter for the Stellar agent wallet.
//!
//! # What this crate does
//!
//! Implements the `stellar-agent-defi` `DefiAdapter` trait for the Blend
//! lending protocol (v1 and v2), delivering five capabilities:
//!
//! - **Typed submit surface** — typed `Vec<BlendRequest>` preview, no
//!   raw-vector or opaque-calldata signing; unknown discriminants refused
//!   pre-sign.
//! - **Version pin** — pin v1+v2 pool WASM hashes per network;
//!   [`pins::verify_blend_pool_wasm`] (two-RPC, reuses
//!   `fetch_contract_wasm_hash`) against the pinned set before any oracle
//!   read or signing.
//! - **Health guard** — simulate-authoritative fail-closed health
//!   check; predicted post-op HF displayed for information only (never gates
//!   signing).
//! - **Oracle staleness policy** — the `blend_oracle_staleness` criterion kind
//!   behind an ordered pin→allowlist→oracle gate; 600s default; per-invocation
//!   override with an unconditional distinct audit event.  Its evaluation logic
//!   and policy-engine registration live in `stellar-agent-defi`
//!   ([`oracle::OracleStalenessEvalExt`]); this crate declares the kind and
//!   supplies the oracle-staleness snapshot.
//! - **Liquidation verb** — deferred (see below).
//!
//! # Behaviors verified end-to-end
//!
//! - Unattended XLM supply to a Blend v2 testnet pool confirmed on-chain; the
//!   supply-only preview shows no armed health check; typed `Vec<Request>`
//!   preview; Reflector ≤600s.
//! - Reflector-stale block → `oracle.staleness_exceeded`; named
//!   override → distinct `oracle.staleness_overridden` audit event.
//!
//! # Primary consumers
//!
//! - `stellar-agent-mcp` / `stellar-agent-cli` — dispatch the `lend` verb
//!   through the seam.
//!
//! # What this crate does NOT do
//!
//! - The `liquidate` verb is deferred.  The `RequestType` enum and
//!   `BlendRequest` type fully support liquidation discriminants 6, 7, 8, 9
//!   to prevent unknown-discriminant failures; the high-level `liquidate` verb
//!   surface is out of current scope.
//! - Flash-loan / `submit_with_allowance` (v2-only) are out of scope.
//! - No new RPC client, simulate loop, or envelope builder — all reuse the
//!   existing submit and simulate paths.
//!
//! # Dependency direction
//!
//! `stellar-agent-blend → stellar-agent-defi` (adapter/preview/pins/dispatch),
//! `→ stellar-agent-network` (RPC, WASM-hash fetch),
//! `→ stellar-agent-smart-account` (submit path),
//! `→ stellar-agent-core` (Criterion/EvalContext/redaction).
//!
//! Note: `stellar-agent-sep48` is NOT a dependency of this crate.  The typed
//! `Vec<Request>` preview is produced directly from wallet-authored Blend ABI
//! types in [`preview`], not from an SEP-48 on-chain spec render.  The sep48
//! crate renders existing `InvokeHostFunction` XDR from on-chain specs; it
//! cannot construct preview entries from wallet-authored Rust types.
//!
//! NEVER `stellar-agent-defi → stellar-agent-blend` or
//! `stellar-agent-core → stellar-agent-blend`.
//!
//! # Oracle allowlist
//!
//! The oracle allowlist is Reflector-only.
//!
//! # ABI provenance
//!
//! Blend v1 ABI bound from
//! `blend-contracts` (AGPL-3.0, interface only — NO source vendored).
//!
//! Blend v2 ABI confirmed byte-identical from
//! `blend-contracts-v2` (see [`abi`] module for the cited equality proof).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod abi;
pub mod adapter;
pub mod oracle;
pub mod oracle_fetch;
pub mod pins;
pub mod preview;
pub mod scval;
pub mod value;
