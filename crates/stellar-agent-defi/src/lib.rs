//! DeFi adapter substrate for the Stellar agent wallet.
//!
//! # What this crate does
//!
//! Provides the substrate that the five protocol adapter crates
//! (Blend, DeFindex, swaps, bridges, stablecoins) build on:
//!
//! 1. **Contract-pin framework** (`pins`) — per-profile, per-network, versioned
//!    `DefiContractPin` model with a fail-closed sign-time gate and a report-only
//!    inspection surface.  Implements the contract-pin framework
//!    (address-pinned WASM + version-pin disciplines).
//!
//! 2. **Typed-preview surface** (`adapter`) — the `DefiAdapter` trait and
//!    `DefiPreview` type that the protocol crates implement.  No raw-vector or
//!    opaque-calldata signing is representable; the no-opaque-calldata discipline
//!    is a type-level guarantee.
//!
//! 3. **Dispatch-verb seam** (`dispatch`) — the capability-witness registration
//!    and routing types by which a protocol adapter exposes a verb (`lend`,
//!    `trade`, `vault`, `bridge`) to the existing MCP/CLI dispatch.  Skip-the-gate
//!    is structurally unrepresentable: the submit hand-off requires a witness value
//!    constructible only from a `GateOutcome::Allow`.
//!
//! 4. **Shared `ScVal` encoders** (`scval`) — the contract-address and `i128`
//!    encoding primitives common to every protocol crate's own `InvokeContractArgs`
//!    builder.
//!
//! # Primary consumers
//!
//! - `stellar-agent-blend`, `stellar-agent-defindex`,
//!   `stellar-agent-dex`, `stellar-agent-bridge` — the protocol crates that
//!   implement `DefiAdapter` and register verbs.
//! - `stellar-agent-mcp` / `stellar-agent-cli` — the binary crates that depend
//!   on those protocol crates and drive the dispatch seam.
//!
//! # What this crate does NOT do
//!
//! - No live MCP/CLI verb ships in this substrate.  The `dispatch` module is tested
//!   only by an internal mock adapter; the live-verb set is defined here.
//! - No protocol-specific preview fields, criteria, or guards.  Those land with
//!   their respective protocol crates.
//! - No policy-engine modification.  The existing `Criterion` / `EvalContext`
//!   extension pattern is documented for protocol crates to follow; no new engine
//!   code is added here.
//!
//! # Dependency direction
//!
//! `stellar-agent-defi → stellar-agent-core` for:
//! - Strkey redaction (`observability::redact_strkey_first5_last5`)
//!   used in the `pins` module's `Display` surfaces and sign-time gate.
//! - `Criterion`/`EvalContext` extension pattern (reserved for when the
//!   first concrete adapter lands and registers DeFi criteria with the policy
//!   engine).
//!
//! `stellar-agent-defi → stellar-agent-network` for the WASM-hash fetch
//! primitive (`fetch_contract_wasm_hash`, `WasmHashFetch`).
//!
//! NEVER `stellar-agent-core → stellar-agent-defi`.  The DeFi `Criterion` impls
//! live in the protocol crates (or core), wired at the `stellar-agent-mcp`
//! dispatch site via the same circular-dep-break pattern used for other views
//! in `stellar-agent-core`'s policy engine.
//!
//! # Related crates
//!
//! - `stellar-agent-core` — policy engine, `Criterion`, `EvalContext`.
//! - `stellar-agent-network` — `StellarRpcClient`, WASM-hash fetch primitive.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod adapter;
pub mod dispatch;
pub mod network;
pub mod oracle_staleness;
pub mod pins;
pub mod reflector;
pub mod scval;
pub mod simulate;

// Re-export the most-used oracle-staleness surface at crate root so consumers
// do not need the full `stellar_agent_defi::oracle_staleness::` path.
pub use oracle_staleness::{
    DEFAULT_MAX_STALENESS_SECS, OracleStalenessDenialReason, OracleStalenessEvalExt,
    OracleStalenessSnapshot, OracleStalenessView, StalenessCheckResult, StalenessOverrideToken,
    evaluate_staleness, proceed_with_staleness_override,
};
