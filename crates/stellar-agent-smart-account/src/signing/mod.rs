//! Smart-account signing pipeline support.
//!
//! This module hosts the pre-signing refusal gates, the ledger witness and
//! the ed25519 auth-digest signing adapter. The network crate owns the signer
//! primitive; this module owns smart-account auth-entry assembly concerns.

pub mod divergence;
pub mod ledger_witness;

#[cfg(test)]
pub(crate) mod recovery_test_fixtures;

pub mod gate;

/// Checked admission fixtures for signing tests.
#[cfg(any(test, feature = "test-helpers"))]
pub mod intent_test_helpers;
