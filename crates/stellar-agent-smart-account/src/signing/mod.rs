//! Smart-account signing pipeline support.
//!
//! This module hosts the pre-signing refusal gates, the ledger witness and
//! the ed25519 auth-digest signing adapter. The network crate owns the signer
//! primitive; this module owns smart-account auth-entry assembly concerns.

pub mod divergence;
pub mod ledger_witness;
