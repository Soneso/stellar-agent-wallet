//! Re-exports from `stellar-agent-network` used by this crate.
//!
//! Centralises the import path so that if a future version renames or moves the
//! upstream types, only this module needs updating.

pub use stellar_agent_network::{
    FetchContractWasmHashError, StellarRpcClient, WasmHashDivergenceError, WasmHashFetch,
    fetch_contract_wasm_hash,
};
