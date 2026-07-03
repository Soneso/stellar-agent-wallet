//! Smart-account deployment via Soroban `CreateContractV2` host function.
//!
//! Three sub-modules:
//!
//! - [`address`] — deterministic C-strkey derivation from
//!   `(deployer_pubkey, salt, network_passphrase)`. Pure
//!   function; no network access. Implements the canonical
//!   contract-id derivation convention.
//! - [`deploy`] — Soroban `CreateContractV2` host-function builder
//!   (with optional preceding `UploadContractWasm` operation when the
//!   target wasm-hash is not yet on-chain) + submission via
//!   `stellar-agent-network`.
//! - [`mod@deploy_webauthn_verifier`] — deploy-only path for the OZ WebAuthn-verifier
//!   WASM; no `__constructor` args; records result in
//!   `VerifierRegistry` (`~/.config/stellar-agent/networks.toml`).
//! - [`mod@deploy_timelock_controller`] — deploy path for the OZ
//!   `timelock-controller-example` v0.7.1 WASM; takes
//!   `__constructor` args (min_delay, proposers, executors, admin).
//! - re-exports: `derive_smart_account_address`, `deploy_smart_account`,
//!   `DeploymentResult`, `DeploymentArgs`, `DeployerKeypair`,
//!   `MULTISIG_ACCOUNT_WASM`, `MULTISIG_ACCOUNT_WASM_SHA256`,
//!   `deploy_webauthn_verifier`, `WebAuthnVerifierDeployArgs`,
//!   `WebAuthnVerifierDeployResult`, `deploy_timelock_controller`,
//!   `TimelockControllerDeployArgs`, `TimelockControllerDeployResult`.
//! - test-only re-exports (requires `test-helpers` feature or `#[cfg(test)]`):
//!   `INTEROP_DEPLOYER_SEED`, `derive_interop_deployer_seed`,
//!   `interop_deployer_pubkey`, `interop_deployer`.

pub mod address;
pub mod deploy;
pub mod deploy_timelock_controller;
pub mod deploy_webauthn_verifier;

pub use address::{AddressError, derive_smart_account_address};
pub use deploy::{
    DeployerKeypair, DeploymentArgs, DeploymentResult, MULTISIG_ACCOUNT_WASM,
    MULTISIG_ACCOUNT_WASM_SHA256, ResolvedFeePerOp, deploy_smart_account,
};

#[cfg(any(test, feature = "test-helpers"))]
pub use address::{INTEROP_DEPLOYER_SEED, derive_interop_deployer_seed, interop_deployer_pubkey};
#[cfg(any(test, feature = "test-helpers"))]
pub use deploy::interop_deployer;
pub use deploy_timelock_controller::{
    TIMELOCK_CONTROLLER_WASM, TIMELOCK_CONTROLLER_WASM_SHA256, TimelockControllerDeployArgs,
    TimelockControllerDeployResult, deploy_timelock_controller,
};
pub use deploy_webauthn_verifier::{
    WebAuthnVerifierDeployArgs, WebAuthnVerifierDeployResult, deploy_webauthn_verifier,
};

/// Canonical inventory of every `SaError::DeploymentFailed::phase` literal
/// emitted from the `deployment/` module substance code.
///
/// Maintained alongside the substance code as new emit sites land.
/// Cross-checked against the canonical 7-value `KNOWN_PHASES` set in
/// `error.rs::tests::phase_string_constant_set_is_closed`.
///
/// `pub(crate)` + `#[cfg(test)]` because the only consumer is the in-crate
/// `#[cfg(test)]` module in `error.rs`. The test gate keeps the constant
/// visible in `cargo test` builds without triggering a dead-code warning in
/// library builds.
#[cfg(test)]
pub(crate) const ALL_EMITTED_PHASES: &[&str] = &[
    "build", // see deploy_smart_account_body() — account fetch, WASM pre-flight, XDR encode, signing, pre-simulate setup
    "simulate", // see deploy_smart_account_body() — simulate_transaction_envelope + transaction assembly
    "upload", // see deploy_smart_account_body() — upload-tx on-chain rejection + post-submit confirmation
    "deploy", // see deploy_smart_account_body() — CreateContractV2 phase
    "constructor", // see build_signer_delegated_scval() — constructor-arg encoding
    "submit", // see deploy_smart_account_body() — deploy-tx or upload-tx envelope rejection
    "post_deploy_verification", // see verify_post_deploy_wasm_hash() — hash-check phase
];

/// The subset of `ALL_EMITTED_PHASES` that map to `SaInvocationResult::OnChainRejected`.
///
/// Phases in this set reached the network layer (or a post-submission check) before
/// failure; phases NOT in this set are pre-submission client-side refusals.
///
/// `"upload"` is included because, after the two-tx upload/deploy split, the upload
/// transaction is submitted to the network before this phase can fail — a failure here
/// means the upload tx was submitted but did not confirm (or an error was returned by
/// the network). This is distinct from the pre-submission `"simulate"` / `"build"` phases.
///
/// `pub(crate)` + `#[cfg(test)]` for the same reason as `ALL_EMITTED_PHASES`; the
/// only consumer is the `on_chain_rejected_phases_subset_of_all_emitted_phases` test.
#[cfg(test)]
pub(crate) const ON_CHAIN_REJECTED_PHASES: &[&str] =
    &["upload", "deploy", "submit", "post_deploy_verification"];
