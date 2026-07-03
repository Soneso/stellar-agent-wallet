//! Smart-account manager surfaces: signers, rules, policies, credentials, verifiers.
//!
//! Each sub-module wraps the corresponding OZ `stellar-accounts` v0.7.1 on-chain
//! surface with typed off-chain orchestration primitives.
//!
//! # Reference cross-check
//!
//! Consulted at SHA `3f81125`:
//! - `packages/accounts/src/smart_account/mod.rs:495-515` (`ExecutionEntryPoint`
//!   trait — the entry point for smart-account call dispatch).
//! - `packages/accounts/src/policies/simple_threshold.rs:99-101`
//!   (`SimpleThresholdAccountParams { threshold: u32 }` — the policy-installation
//!   param shape that threshold-management and caps surfaces consume).

pub mod auth_entry;
pub mod authorization;
pub mod credentials;
pub mod diversification;
pub mod migration;
pub mod policies;
pub mod rules;
pub mod signers;
pub mod verifiers;
