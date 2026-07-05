//! Smart-account orchestration layer for the Stellar agent wallet.
//!
//! # What this crate does
//!
//! Wraps the OpenZeppelin `stellar-accounts` v0.7.2 on-chain contract surface
//! into typed off-chain primitives the wallet uses for: smart-account deployment,
//! context-rule install + auth-digest binding, WebAuthn passkey signer, atomic
//! signer-threshold updates, wasm-hash pinning, verifier migration,
//! active-rule enumeration, multicall, and upgrade timelock (configurable on-chain execution delay).
//!
//! # What this crate does NOT do
//!
//! - Submit transactions or connect to a network (that is `stellar-agent-network`).
//! - Evaluate wallet policy rules (that is `stellar-agent-core::policy`).
//! - Manage keypairs, signing keys, or the platform keyring (that is
//!   `stellar-agent-core::wallet` and `stellar-agent-network::signing`).

#![forbid(unsafe_code)]
#![deny(missing_docs)]
// `SaError::SignerSetDiverged` carries two `ObservedSignerSet` structs + two
// forensic-symmetry `String` fields.
// The combined variant size of 164 bytes exceeds the 128-byte default threshold.
// The variant is intentionally rich: operators need the full signer-set state to
// diagnose divergence without a separate audit-log query.  The error is always
// converted to `Box<dyn Error>` or serialised before crossing ABI boundaries.
#![allow(
    clippy::result_large_err,
    reason = "SaError::SignerSetDiverged carries full ObservedSignerSet diagnostic state by design"
)]

pub mod bindings;
pub mod deployment;
pub mod ed25519_verifier;
pub mod error;
pub mod managers;
pub mod multicall;
pub mod signers;
pub mod signing;
pub mod simple_threshold_policy;
pub mod spending_limit_policy;
pub mod submit;
pub mod timelock;
pub(crate) mod timelock_submit;
pub mod verifier_allowlist;
pub mod verifiers;
pub mod webauthn;
pub mod webauthn_verifier;
pub mod weighted_threshold_policy;

pub use error::{AdminOrOwnerKey, SaError};
pub use managers::migration::{
    MigrationPlan, MigrationPlanner, MigrationSubmitResult, RuleMigration, SignerMigrationStep,
    SignerStepSubmitOutcome,
};
pub use submit::{MulticallCheck, ResolvedFeePerOp};
pub use verifier_allowlist::{VERIFIER_ALLOWLIST, VerifierAllowlistEntry, VerifierAuditStatus};

// Full-fidelity OZ `Signer` ScVal decoder — always compiled at `pub` in
// `managers/signers.rs` (with `#[cfg_attr(not(any(test, feature = "test-helpers")), allow(dead_code))]`
// to silence dead-code warnings on the externally-unused fields when the
// feature is off); out-of-crate visibility is gated here so integration tests
// compiled with `features = ["test-helpers"]` can import from the crate root
// without exposing the types in production builds.
//
// Gate visibility at the re-export, not the definition — `#[doc(hidden)] pub fn`
// leaks the symbol into public rustdoc.
#[cfg(any(test, feature = "test-helpers"))]
pub use managers::signers::{DecodedOnChainSigner, decode_signer_scval_full};

// `derive_schedule_salt` in `timelock.rs` is split into a private `_impl`
// (always compiled, used by the production call site) and a feature-gated
// `pub fn` wrapper (only compiled under `test-helpers` or `cfg(test)`).
// Adversarial fixture tests that need to call it directly reach the public
// wrapper via this re-export.
//
// Test-only public helpers MUST be feature-gated; `#[doc(hidden)] pub fn`
// leaks the symbol into public rustdoc.
#[cfg(any(test, feature = "test-helpers"))]
pub use timelock::derive_schedule_salt;
