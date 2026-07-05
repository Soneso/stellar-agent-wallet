//! Smart-account signer-set substrate for atomic signer-threshold updates
//! and verifier wasm-hash pinning.
//!
//! Provides the value types and policy/verifier-identification constants consumed by
//! `managers/signers.rs`.
//!
//! # Module structure
//!
//! - [`policy_identification`] — `THRESHOLD_POLICY_WASM_HASHES` allowlist +
//!   `THRESHOLD_POLICY_WASM` vendored bytes.
//! - [`verifier_identification`] — `VERIFIER_WASM_FIXTURE` vendored bytes +
//!   [`crate::VERIFIER_ALLOWLIST`] typed allowlist entries
//!   (`verifier_allowlist.rs`).
//! - [`types`] — `FrozenChainStateTuple` (TOCTOU anchor), `WasmHashSummary`,
//!   `ThresholdAffectingOp` (`AtomicBundleAlternative` removed — CAP-46).
//!
//! # Re-exports from `stellar-agent-core`
//!
//! For downstream convenience, the four signer-set value types
//! from `stellar_agent_core::audit_log::signer_set` are re-exported here so
//! `managers/signers.rs` can import everything from one path:
//!
//! ```ignore
//! use crate::signers::{
//!     FrozenChainStateTuple, WasmHashSummary, ThresholdAffectingOp,
//!     THRESHOLD_POLICY_WASM_HASHES, THRESHOLD_POLICY_WASM,
//!     ObservedSignerSet, SignerPubkey, SignerSetStatePayload, BaselineReason,
//! };
//! ```
//!
//! # Cross-crate type placement
//!
//! `ObservedSignerSet`, `SignerPubkey`, `SignerSetStatePayload`, and
//! `BaselineReason` live in `stellar_agent_core::audit_log::signer_set` so the
//! audit-log substrate is self-contained (core must not depend on
//! smart-account). Smart-account-specific wrappers live here; the audit-log
//! value types live in core.  See `signer_set.rs` module-level rustdoc
//! for the type-placement rationale.
//!
pub mod policy_identification;
pub mod types;
pub mod verifier_identification;

// ── Re-exports for downstream convenience ─────────────────────────────────────

#[cfg(any(test, feature = "deploy-cli"))]
pub use policy_identification::THRESHOLD_POLICY_WASM;
pub use policy_identification::THRESHOLD_POLICY_WASM_HASHES;

pub use types::{
    FrozenChainStateTuple, PolicyIdentifiedKind, ThresholdAffectingOp, WasmHashSummary,
    WasmHashSummaryError,
};

/// Re-exports of signer-set value types from `stellar-agent-core`.
///
/// These live in `stellar_agent_core::audit_log::signer_set` to keep the
/// audit-log substrate self-contained.  Re-exported here for downstream
/// consumer convenience.
pub use stellar_agent_core::audit_log::signer_set::{
    BaselineReason, ObservedSignerSet, SignerPubkey, SignerSetStatePayload,
};
